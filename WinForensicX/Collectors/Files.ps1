# File collector — scans a bounded set of high-signal locations (web roots, user drop folders) and
# produces the normalized file records the File/Ransomware analyzers consume:
#   { Path, Directory, Extension, Length, LastWriteUtc, CreatedUtc, Content, Entropy, SignatureStatus, Zone, InWebRoot, SHA256 }
# Everything is bounded (file count, file size, read size, total content budget) so a triage never walks an
# entire disk or produces a huge bundle. Content is kept only for web-served scripts (for web-shell matching)
# and is secret-scrubbed before it enters the bundle. Reading files may update NTFS last-access times on
# volumes where that is enabled — a documented limitation of any live triage.

$script:WfxWebRoots = @(
    "$env:SystemDrive\inetpub\wwwroot"
    "$env:SystemDrive\inetpub\ftproot"
    "$env:SystemDrive\xampp\htdocs"
    "$env:SystemDrive\wamp\www"
    "$env:SystemDrive\wamp64\www"
    "$env:SystemDrive\Apache24\htdocs"
    "$env:SystemDrive\nginx\html"
    "$env:ProgramFiles\Apache Software Foundation"
    "$env:SystemDrive\laragon\www"
    "$env:ProgramFiles\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy"
    "$env:ProgramFiles\Microsoft\Exchange Server\V15\ClientAccess"
)
$script:WfxWebScriptExt = @('.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.asp', '.aspx', '.ashx', '.asmx', '.jsp', '.jspx', '.cfm', '.cgi', '.pl')

function Get-WfxZoneId {
    <# Reads the Mark-of-the-Web Zone.Identifier stream. Returns @{ Zone; HostUrl; ReferrerUrl } (empty when none). #>
    param([string]$Path)
    $r = @{ Zone = ''; HostUrl = ''; ReferrerUrl = '' }
    if (-not (Test-WfxWindows)) { return $r }
    try {
        $z = (Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -ErrorAction Stop) -join "`n"
        $m = [regex]::Match($z, '(?im)^ZoneId\s*=\s*(\d)'); if ($m.Success) { $r.Zone = $m.Groups[1].Value }
        $m = [regex]::Match($z, '(?im)^HostUrl\s*=\s*(\S+)'); if ($m.Success) { $r.HostUrl = Protect-WfxText $m.Groups[1].Value }
        $m = [regex]::Match($z, '(?im)^ReferrerUrl\s*=\s*(\S+)'); if ($m.Success) { $r.ReferrerUrl = Protect-WfxText $m.Groups[1].Value }
    } catch {}
    return $r
}

function Get-WfxFileBytesEntropy {
    <# Shannon entropy over the first $Max bytes of a file (bounded read). 0 on failure. #>
    param([string]$Path, [int]$Max = 262144)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $len = [int][Math]::Min([int64]$Max, $fs.Length)
            if ($len -le 0) { return 0.0 }
            $buf = New-Object byte[] $len
            $read = $fs.Read($buf, 0, $len)
            if ($read -lt $len) { $buf = $buf[0..($read - 1)] }
            return (Get-WfxEntropy ([byte[]]$buf))
        } finally { $fs.Dispose() }
    } catch { return 0.0 }
}

function Get-WfxFileHash256 {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}

function Get-WfxFileData {
    <#
    .SYNOPSIS Collects file records from web roots and user drop folders for the File analyzer.
    .PARAMETER ExtraPath     Additional folders to scan (e.g. a mounted image or a custom web root).
    .PARAMETER MaxFiles      Hard cap on files examined (default 4000) so a triage stays fast.
    .PARAMETER MaxReadKB     Max bytes read for content/entropy of a single file.
    .PARAMETER MaxContentMB  Total budget of web-script content kept in the bundle (default 32 MB).
    .PARAMETER Hours         Only files modified within this window are considered "recent drops" (default 168 = 7d).
    #>
    param([string[]]$ExtraPath = @(), [int]$MaxFiles = 4000, [int]$MaxReadKB = 256, [int]$MaxContentMB = 32, [int]$Hours = 168)
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $budget = [ref]$MaxFiles
    $contentBudget = [ref]([int64]$MaxContentMB * 1MB)
    $cutoff = (Get-Date).AddHours(-[Math]::Abs($Hours))

    $emit = {
        param($Item, [bool]$InWeb, [bool]$ReadContent)
        if ($budget.Value -le 0) { return }
        $p = $Item.FullName
        if ($seen.ContainsKey($p)) { return }
        $seen[$p] = $true
        $budget.Value--
        $ext = $Item.Extension.ToLowerInvariant()
        $content = ''
        $entropy = 0.0
        $isExe = $ext -in @('.exe', '.dll', '.scr', '.com', '.sys', '.ocx', '.cpl', '.pif')
        if ($ReadContent -and $Item.Length -le ($MaxReadKB * 1024)) {
            if ($contentBudget.Value -ge $Item.Length) {
                try { $content = Get-Content -LiteralPath $p -Raw -ErrorAction Stop } catch { $content = '' }
                # Scrub secrets (e.g. connection strings) before the content enters the bundle.
                if ($content) { $content = Protect-WfxText $content; $contentBudget.Value -= $Item.Length }
            } elseif ($contentBudget.Value -ge 0) {
                Add-WfxGap -Source 'files:webroots' -Reason "Web-script content budget ($MaxContentMB MB) reached; remaining web scripts were hashed but not content-scanned." -Fix 'Re-run Get-WfxFileData with a larger -MaxContentMB on that server.'
                $contentBudget.Value = -1
            }
        }
        if ($isExe) { $entropy = Get-WfxFileBytesEntropy $p (($MaxReadKB * 1024)) }
        $motw = Get-WfxZoneId $p
        $sha = ''
        # Hash only the small set of files most likely to matter (executables / MOTW / web scripts).
        if ($isExe -or $motw.Zone -match '^[34]$' -or $InWeb) { $sha = Get-WfxFileHash256 $p }
        $out.Add([pscustomobject]@{
                Path            = $p
                Directory       = $Item.DirectoryName
                Extension       = $ext
                Length          = $Item.Length
                LastWrite       = ConvertTo-WfxUtcString $Item.LastWriteTimeUtc
                Created         = ConvertTo-WfxUtcString $Item.CreationTimeUtc
                Content         = $content
                Entropy         = $entropy
                SignatureStatus = if ($isExe) { Get-WfxSignature $p } else { '' }
                Zone            = $motw.Zone
                HostUrl         = $motw.HostUrl
                ReferrerUrl     = $motw.ReferrerUrl
                InWebRoot       = $InWeb
                SHA256          = $sha
            })
    }

    # ── Web roots: scan served scripts for web shells ──
    Invoke-WfxStep 'files:webroots' {
        foreach ($root in (@($script:WfxWebRoots) + @($ExtraPath))) {
            if ($budget.Value -le 0) { break }
            if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
            Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLowerInvariant() -in $script:WfxWebScriptExt } |
                Select-Object -First ([Math]::Max(0, $budget.Value)) |
                ForEach-Object { & $emit $_ $true $true }
        }
    } | Out-Null

    # ── User drop folders: recently written executables/scripts (download/exec staging) ──
    Invoke-WfxStep 'files:userdrops' {
        $dirs = New-Object System.Collections.Generic.List[string]
        $dirs.Add("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
        $dirs.Add("$env:PUBLIC\Downloads")
        $dirs.Add("$env:PUBLIC\Documents")
        $dirs.Add("$env:SystemRoot\Temp")
        $dirs.Add("$env:ProgramData")
        foreach ($prof in (Get-WfxUserProfilePath)) {
            foreach ($sub in @('Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp', 'AppData\Roaming')) { $dirs.Add((Join-Path $prof $sub)) }
        }
        $dropExt = @('.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.jar', '.lnk', '.iso', '.img', '.vhd', '.vhdx', '.msi', '.one', '.xll')
        foreach ($d in ($dirs | Sort-Object -Unique)) {
            if ($budget.Value -le 0) { break }
            if (-not (Test-Path -LiteralPath $d)) { continue }
            # NOTE: -Depth always implies recursion. Roaming / ProgramData: files directly inside an app folder (depth 1);
            # other folders: two levels down.
            $depth = if ($d -match '(?i)\\AppData\\Roaming$|^[a-z]:\\ProgramData$') { 1 } else { 2 }
            Get-ChildItem -LiteralPath $d -File -Depth $depth -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLowerInvariant() -in $dropExt -and ($_.LastWriteTime -ge $cutoff -or $_.Extension -in @('.exe', '.scr', '.hta')) } |
                Select-Object -First ([Math]::Max(0, $budget.Value)) |
                ForEach-Object { & $emit $_ $false $false }
        }
        if ($budget.Value -le 0) { Add-WfxGap -Source 'files' -Reason "File cap ($MaxFiles) reached; remaining files were not examined." }
    } | Out-Null

    $out.ToArray()
}

function Get-WfxRansomwareData {
    <#
    .SYNOPSIS Collects ransom-note candidates and recently written encrypted-looking files.
    A note candidate is a small text/html file whose NAME looks like a ransom note, or whose identical name was
    dropped into many folders recently (how ransomware leaves notes). Only one copy per name is read; content is
    secret-scrubbed and truncated. Ordinary recent documents are never read.
    Returns .Note (Path, Name, Copies, Content) and .RecentFile (Path, Extension, Entropy, LastWrite).
    .PARAMETER Hours  Window for "recent" (default 48).
    #>
    param([int]$Hours = 48, [int]$MaxNotes = 50, [int]$MaxRecent = 4000, [int]$MaxScan = 60000, [int]$NoteMinCopies = 5)
    $notes = New-Object System.Collections.Generic.List[object]
    $recent = New-Object System.Collections.Generic.List[object]
    if (-not (Test-WfxWindows)) { return [pscustomobject]@{ Note = @(); RecentFile = @() } }
    $cutoff = (Get-Date).AddHours(-[Math]::Abs($Hours))
    $noteNameRx = '(?i)(?:read[\s_\-]?me|how[\s_\-]?to[\s_\-]?(?:decrypt|recover|restore)|decrypt|recover[\s_\-]?(?:files|instruction)|restore[\s_\-]?(?:my[\s_\-]?)?files|your[\s_\-]?files|unlock|ransom|_readme|help_decrypt|!!!)'
    $roots = @(@("$env:PUBLIC") + @(Get-WfxUserProfilePath)) | Where-Object { $_ } | Sort-Object -Unique

    Invoke-WfxStep 'files:ransomnotes' {
        $byName = @{}
        $scanned = 0
        foreach ($r in $roots) {
            if (-not (Test-Path -LiteralPath $r)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Depth 4 -Include '*.txt', '*.html', '*.htm', '*.hta' -ErrorAction SilentlyContinue)) {
                if (++$scanned -gt $MaxScan) { break }
                if ($f.Length -gt 65536) { continue }
                $named = Test-WfxRxMatch $noteNameRx $f.BaseName
                if (-not $named -and $f.LastWriteTime -lt $cutoff) { continue }
                $k = $f.Name.ToLowerInvariant()
                if (-not $byName.ContainsKey($k)) { $byName[$k] = [pscustomobject]@{ Named = $named; Files = New-Object System.Collections.Generic.List[string] } }
                $byName[$k].Files.Add($f.FullName)
            }
        }
        $cands = @($byName.GetEnumerator() | Where-Object { $_.Value.Named -or $_.Value.Files.Count -ge $NoteMinCopies } |
                Sort-Object { $_.Value.Files.Count } -Descending | Select-Object -First $MaxNotes)
        foreach ($c in $cands) {
            $first = $c.Value.Files[0]
            $txt = ''
            try { $txt = Get-Content -LiteralPath $first -Raw -ErrorAction Stop } catch {}
            if ($txt) {
                if ($txt.Length -gt 16384) { $txt = $txt.Substring(0, 16384) }
                $notes.Add([pscustomobject]@{ Path = $first; Name = $c.Key; Copies = $c.Value.Files.Count; Content = (Protect-WfxText $txt) })
            }
        }
    } | Out-Null

    Invoke-WfxStep 'files:recentencrypted' {
        $count = 0; $scanned = 0
        foreach ($r in $roots) {
            if ($count -ge $MaxRecent -or $scanned -ge $MaxScan) { break }
            if (-not (Test-Path -LiteralPath $r)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Depth 5 -ErrorAction SilentlyContinue)) {
                if (++$scanned -gt $MaxScan) { Add-WfxGap -Source 'files:recentencrypted' -Reason "Scan cap ($MaxScan files) reached."; break }
                if ($f.LastWriteTime -lt $cutoff -or $f.Length -lt 1024 -or $f.Length -gt 52428800) { continue }
                if ($count -ge $MaxRecent) { break }
                $count++
                $e = Get-WfxFileBytesEntropy $f.FullName 65536
                if ($e -ge 7.3) {
                    $recent.Add([pscustomobject]@{ Path = $f.FullName; Directory = $f.DirectoryName; Extension = $f.Extension; Entropy = $e; LastWrite = (ConvertTo-WfxUtcString $f.LastWriteTimeUtc) })
                }
            }
        }
    } | Out-Null

    [pscustomobject]@{ Note = @($notes.ToArray()); RecentFile = @($recent.ToArray()) }
}
