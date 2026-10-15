# File collector — scans a bounded set of high-signal locations (web roots, user drop folders) and
# produces the normalized file records the File/Ransomware analyzers consume:
#   { Path, Directory, Extension, Length, LastWrite, Content, Entropy, SignatureStatus, Zone, InWebRoot, SHA256 }
# Everything is bounded (file count, file size, read size) so a triage never walks an entire disk.
# Content is read only for small text files in web roots / script locations and is never emitted raw by the
# analyzer; here it is used for web-shell signature matching only.

$script:WfxWebRoots = @(
    'C:\inetpub\wwwroot'
    'C:\inetpub\ftproot'
    "$env:SystemDrive\xampp\htdocs"
    "$env:SystemDrive\wamp\www"
    "$env:SystemDrive\wamp64\www"
    "$env:SystemDrive\Apache24\htdocs"
    "$env:SystemDrive\nginx\html"
    "$env:ProgramFiles\Apache Software Foundation"
    "$env:SystemDrive\laragon\www"
)
$script:WfxWebScriptExt = @('.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.asp', '.aspx', '.ashx', '.asmx', '.jsp', '.jspx', '.cfm', '.cgi', '.pl')

function Get-WfxZoneId {
    <# Reads the Mark-of-the-Web ZoneId from a file's Zone.Identifier alternate data stream. '' when none. #>
    param([string]$Path)
    if (-not (Test-WfxWindows)) { return '' }
    try {
        $z = Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -ErrorAction Stop
        $m = [regex]::Match(($z -join "`n"), '(?im)^ZoneId\s*=\s*(\d)')
        if ($m.Success) { return $m.Groups[1].Value }
    } catch {}
    return ''
}

function Get-WfxFileBytesEntropy {
    <# Shannon entropy over the first $Max bytes of a file (bounded read). 0 on failure. #>
    param([string]$Path, [int]$Max = 262144)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $len = [Math]::Min([int]$Max, [int]$fs.Length)
            if ($len -le 0) { return 0.0 }
            $buf = New-Object byte[] $len
            [void]$fs.Read($buf, 0, $len)
            return (Get-WfxEntropy $buf)
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
    .PARAMETER ExtraPath   Additional folders to scan (e.g. a mounted image or a custom web root).
    .PARAMETER MaxFiles    Hard cap on files examined (default 4000) so a triage stays fast.
    .PARAMETER MaxReadKB   Max bytes read for content/entropy of a single file.
    .PARAMETER Hours       Only files modified within this window are considered "recent drops" (default 168 = 7d).
    #>
    param([string[]]$ExtraPath = @(), [int]$MaxFiles = 4000, [int]$MaxReadKB = 256, [int]$Hours = 168)
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $budget = [ref]$MaxFiles
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
            try { $content = Get-Content -LiteralPath $p -Raw -ErrorAction Stop } catch { $content = '' }
            # Scrub secrets (e.g. connection strings in a web.config) before the content enters the bundle.
            # Web-shell code constructs (eval/system/base64) are not secret patterns, so detection is unaffected.
            if ($content) { $content = Protect-WfxText $content }
        }
        if ($isExe) { $entropy = Get-WfxFileBytesEntropy $p (($MaxReadKB * 1024)) }
        $zone = Get-WfxZoneId $p
        $sha = ''
        # Hash only the small set of files most likely to matter (executables / MOTW / web scripts).
        if ($isExe -or $zone -match '3|4' -or $InWeb) { $sha = Get-WfxFileHash256 $p }
        $out.Add([pscustomobject]@{
                Path            = $p
                Directory       = $Item.DirectoryName
                Extension       = $ext
                Length          = $Item.Length
                LastWrite       = $Item.LastWriteTime
                Content         = $content
                Entropy         = $entropy
                SignatureStatus = if ($isExe) { Get-WfxSignature $p } else { '' }
                Zone            = $zone
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
                Select-Object -First ($budget.Value) |
                ForEach-Object { & $emit $_ $true $true }
        }
    } | Out-Null

    # ── User drop folders: recently written executables/scripts (download/exec staging) ──
    Invoke-WfxStep 'files:userdrops' {
        $dirs = New-Object System.Collections.Generic.List[string]
        $dirs.Add("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
        $dirs.Add("$env:PUBLIC\Downloads")
        $dirs.Add($env:TEMP)
        $dirs.Add("$env:SystemRoot\Temp")
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($sub in @('Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp', 'AppData\Roaming')) {
                $dirs.Add((Join-Path $_.FullName $sub))
            }
        }
        $dropExt = @('.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.jar', '.lnk', '.iso', '.img', '.vhd')
        foreach ($d in ($dirs | Sort-Object -Unique)) {
            if ($budget.Value -le 0) { break }
            if (-not (Test-Path -LiteralPath $d)) { continue }
            # One level deep for Roaming (app folders), recurse shallow elsewhere.
            $recurse = $d -notmatch '(?i)\\AppData\\Roaming$'
            Get-ChildItem -LiteralPath $d -File -Recurse:$recurse -Depth 2 -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLowerInvariant() -in $dropExt -and ($_.LastWriteTime -ge $cutoff -or $_.Extension -in @('.exe', '.scr', '.hta')) } |
                Select-Object -First ($budget.Value) |
                ForEach-Object { & $emit $_ $false $false }
        }
    } | Out-Null

    , @($out.ToArray())
}

function Get-WfxRansomwareData {
    <#
    .SYNOPSIS Collects ransom-note candidates and recently written encrypted-looking files.
    Returns a pscustomobject with .Note (Path, Content) and .RecentFile (Path, Extension, Entropy, LastWrite).
    .PARAMETER Hours  Window for "recent" encrypted files (default 48).
    #>
    param([int]$Hours = 48, [int]$MaxNotes = 200, [int]$MaxRecent = 4000)
    $notes = New-Object System.Collections.Generic.List[object]
    $recent = New-Object System.Collections.Generic.List[object]
    if (-not (Test-WfxWindows)) { return [pscustomobject]@{ Note = @(); RecentFile = @() } }
    $cutoff = (Get-Date).AddHours(-[Math]::Abs($Hours))
    $noteNameRx = '(?i)(?:read[\s_\-]?me|how[\s_\-]?to[\s_\-]?(?:decrypt|recover)|decrypt[\s_\-]?(?:instruction|info|files)?|recover[\s_\-]?(?:files|instruction)|restore[\s_\-]?files|your[\s_\-]?files|unlock|ransom|_readme|help_decrypt)'
    $roots = @("$env:PUBLIC", "$env:SystemDrive\Users")

    Invoke-WfxStep 'files:ransomnotes' {
        foreach ($r in $roots) {
            if (-not (Test-Path -LiteralPath $r)) { continue }
            Get-ChildItem -LiteralPath $r -Recurse -File -Depth 4 -Include '*.txt', '*.html', '*.htm', '*.hta' -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -le 65536 -and ($_.BaseName -match $noteNameRx -or $_.LastWriteTime -ge $cutoff) } |
                Select-Object -First $MaxNotes |
                ForEach-Object {
                    $c = ''
                    try { $c = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop } catch {}
                    if ($c) { $notes.Add([pscustomobject]@{ Path = $_.FullName; Content = $c }) }
                }
        }
    } | Out-Null

    Invoke-WfxStep 'files:recentencrypted' {
        $count = 0
        foreach ($r in $roots) {
            if ($count -ge $MaxRecent) { break }
            if (-not (Test-Path -LiteralPath $r)) { continue }
            Get-ChildItem -LiteralPath $r -Recurse -File -Depth 5 -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff -and $_.Length -ge 1024 -and $_.Length -le 52428800 } |
                ForEach-Object {
                    if ($count -ge $MaxRecent) { return }
                    $count++
                    $e = Get-WfxFileBytesEntropy $_.FullName 65536
                    if ($e -ge 7.3) {
                        $recent.Add([pscustomobject]@{ Path = $_.FullName; Extension = $_.Extension; Entropy = $e; LastWrite = $_.LastWriteTime })
                    }
                }
        }
    } | Out-Null

    [pscustomobject]@{ Note = @($notes.ToArray()); RecentFile = @($recent.ToArray()) }
}
