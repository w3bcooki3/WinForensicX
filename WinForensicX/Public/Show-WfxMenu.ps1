# Interactive menu: the main way to use WinForensicX without memorising parameters.
# Structure: main menu → section submenus → actions. Every screen says what each option does, inputs are
# validated, B goes back, Q quits from anywhere. Everything is read-only except the Respond section, where
# every change is shown, confirmed, recorded and (except stopping a process) undoable.

$script:WfxMenu = @{ OutputPath = ''; Hours = 72; Days = 0; Allowlist = ''; RulesPath = ''; LastCase = ''; Sigma = ''; Yara = '' }

function Read-WfxMenuChoice {
    <# Reads one menu choice; repeats until it is one of $Valid (case-insensitive). Returns it upper-cased. #>
    param([string[]]$Valid, [string]$Prompt = 'Choose')
    while ($true) {
        $c = ([string](Read-Host "  $Prompt")).Trim().ToUpperInvariant()
        if ($Valid -contains $c) { return $c }
        if ($c -eq '') { continue }
        Write-WfxConsole "  '$c' is not an option here. Type one of: $($Valid -join ', ')" -Kind Warn
    }
}

function Read-WfxMenuText {
    param([string]$Prompt, [string]$Default = '')
    $hint = if ($Default) { " [$Default]" } else { '' }
    $v = ([string](Read-Host "  $Prompt$hint")).Trim()
    if (-not $v) { return $Default }
    return $v
}

function Read-WfxMenuPath {
    <# Asks for a path; strips quotes, expands ~ and %VARS%, checks it exists. Empty input = cancel ($null). #>
    param([string]$Prompt, [ValidateSet('File', 'Folder', 'Any')][string]$Kind = 'Any', [switch]$AllowMissing, [string]$Default = '')
    while ($true) {
        $v = Read-WfxMenuText -Prompt "$Prompt (Enter = cancel)" -Default $Default
        if (-not $v) { return $null }
        $v = [Environment]::ExpandEnvironmentVariables($v.Trim('"', "'", ' '))
        if ($v -like '~*') { $v = Join-Path $HOME $v.Substring(1).TrimStart('\', '/') }
        if ($AllowMissing) { return $v }
        $type = switch ($Kind) { 'File' { 'Leaf' } 'Folder' { 'Container' } default { 'Any' } }
        if (Test-Path -LiteralPath $v -PathType $type) { return (Resolve-Path -LiteralPath $v).Path }
        Write-WfxConsole "  Not found$(if ($Kind -ne 'Any') { " (expected a $($Kind.ToLower()))" }): $v" -Kind Warn
    }
}

function Wait-WfxMenu { Write-WfxConsole ''; [void](Read-Host '  Press Enter to continue') }

function Get-WfxCaseRoot { if ($script:WfxMenu.OutputPath) { $script:WfxMenu.OutputPath } else { Get-WfxDefaultOutputRoot } }

function Get-WfxRecentCase {
    param([int]$Max = 15)
    $root = Get-WfxCaseRoot
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json') } | Sort-Object LastWriteTime -Descending | Select-Object -First $Max)
}

function Write-WfxMenuHeader {
    param([string]$Crumb = 'Main menu')
    try { Clear-Host } catch {}
    $admin = Test-WfxAdmin
    Write-WfxConsole ''
    Write-WfxConsole '  WinForensicX' -Kind Head -NoNewline
    Write-WfxConsole "  v$script:WfxVersion, DFIR toolkit (read-only unless you choose Respond)" -Kind Dim
    Write-WfxConsole ("  Host {0}, {1}, output {2}" -f [Environment]::MachineName, $(if ($admin) { 'elevated' } else { 'NOT elevated (some views limited)' }), (Get-WfxCaseRoot)) -Kind $(if ($admin) { 'Dim' } else { 'Warn' })
    if ($script:WfxMenu.LastCase) { Write-WfxConsole "  Last case: $($script:WfxMenu.LastCase)" -Kind Dim }
    Write-WfxConsole ''
    Write-WfxConsole "  ── $Crumb $('─' * [Math]::Max(3, 60 - $Crumb.Length))" -Kind Head
    Write-WfxConsole ''
}

function Write-WfxMenuItem {
    param([string]$Key, [string]$Label, [string]$Hint = '')
    Write-WfxConsole ("   {0,-3}" -f $Key) -Kind Info -NoNewline
    Write-WfxConsole ("{0,-44}" -f $Label) -Kind Plain -NoNewline
    Write-WfxConsole $Hint -Kind Dim
}

function Write-WfxMenuFooter { param([switch]$NoBack) Write-WfxConsole ''; if (-not $NoBack) { Write-WfxMenuItem 'B' 'Back' }; Write-WfxMenuItem 'Q' 'Quit'; Write-WfxConsole '' }

function Invoke-WfxMenuAction {
    <# Runs one action, catches errors so the menu never dies, and remembers the newest case. #>
    param([scriptblock]$Action, [switch]$NoPause)
    $before = @(Get-WfxRecentCase -Max 1) | Select-Object -First 1
    try { & $Action }
    catch { Write-WfxConsole ''; Write-WfxConsole "  Error: $($_.Exception.Message)" -Kind Bad; Write-WfxConsole '  (Nothing was changed on this computer.)' -Kind Dim }
    $after = @(Get-WfxRecentCase -Max 1) | Select-Object -First 1
    if ($after -and (-not $before -or $after.FullName -ne $before.FullName)) { $script:WfxMenu.LastCase = $after.FullName }
    if (-not $NoPause) { Wait-WfxMenu }
}

function Get-WfxTriageArgs {
    $a = @{ OutputPath = $script:WfxMenu.OutputPath; Hours = $script:WfxMenu.Hours }
    if ($script:WfxMenu.Allowlist) { $a.AllowlistPath = $script:WfxMenu.Allowlist }
    if ($script:WfxMenu.Sigma) { $a.SigmaPath = @($script:WfxMenu.Sigma) }
    if ($script:WfxMenu.Yara) { $a.YaraRules = @($script:WfxMenu.Yara) }
    $a
}

function Open-WfxPath { param([string]$Path) if ((Test-WfxWindows) -and $Path) { try { Start-Process -FilePath $Path } catch { Write-WfxConsole "  Could not open: $Path" -Kind Warn } } else { Write-WfxConsole "  $Path" -Kind Info } }

# ─────────────────────────── sections ───────────────────────────
function Show-WfxMenuTriage {
    while ($true) {
        Write-WfxMenuHeader 'Investigate this computer'
        Write-WfxMenuItem '1' 'Quick triage' 'processes, network, autostarts, events, posture (~1-5 min)'
        Write-WfxMenuItem '2' 'Full triage' '+ web shells, dropped files, ransomware, config secrets (slower)'
        Write-WfxMenuItem '8' 'Full triage + injected-code scan' 'adds a memory scan for injected code (slower; some EDRs report it)'
        Write-WfxMenuItem '3' 'Collect evidence only' 'hashed snapshot to analyze later or elsewhere'
        Write-WfxConsole ''
        Write-WfxMenuItem '4' 'Remote computer(s) over WinRM' 'collect from other machines, analyze here'
        Write-WfxMenuItem '5' 'Offline event logs (.evtx)' 'analyze exported logs from another machine'
        Write-WfxMenuItem '6' 'Re-analyze a saved case' 're-run detections over old evidence'
        Write-WfxMenuItem '7' 'Collected evidence folder (KAPE, image, CTF)' 'hives, Amcache, Jump Lists, .lnk, browsers, .evtx'
        Write-WfxConsole ''
        Write-WfxMenuItem 'P' 'What will a triage read?' 'the plan for quick and full triage; reads nothing'
        Write-WfxMenuFooter
        $c = Read-WfxMenuChoice -Valid '1', '2', '3', '4', '5', '6', '7', '8', 'P', 'B', 'Q'
        switch ($c) {
            'B' { return }
            'Q' { return 'Q' }
            'P' { $a = Get-WfxTriageArgs; Invoke-WfxMenuAction { Invoke-WfxTriage @a -FileScan -ExposureScan -Plan; Write-WfxConsole '  Quick triage (1) skips the File scan stage and the config-file / SYSVOL part of the exposure audit.' -Kind Dim } }
            '1' { $a = Get-WfxTriageArgs; Invoke-WfxMenuAction { Invoke-WfxTriage @a | Out-Null; Write-WfxMenuOpenReport } }
            '2' { $a = Get-WfxTriageArgs; Invoke-WfxMenuAction { Invoke-WfxTriage @a -FileScan -ExposureScan | Out-Null; Write-WfxMenuOpenReport } }
            '8' { $a = Get-WfxTriageArgs; Invoke-WfxMenuAction { Invoke-WfxTriage @a -FileScan -ExposureScan -DeepScan | Out-Null; Write-WfxMenuOpenReport } }
            '3' { Invoke-WfxMenuAction { Save-WfxEvidence -OutputPath $script:WfxMenu.OutputPath -Hours $script:WfxMenu.Hours -FileScan -ExposureScan | Out-Null } }
            '4' {
                $cn = Read-WfxMenuText 'Computer name(s), comma-separated (Enter = cancel)'
                if ($cn) {
                    $cred = $null
                    if ((Read-WfxMenuText 'Use different credentials? (y/N)') -match '^(?i)y') { $cred = Get-Credential }
                    $a = Get-WfxTriageArgs; $a.ComputerName = @($cn -split '\s*,\s*' | Where-Object { $_ }); if ($cred) { $a.Credential = $cred }
                    Invoke-WfxMenuAction { Invoke-WfxTriage @a | Out-Null }
                }
            }
            '5' { $p = Read-WfxMenuPath 'Folder or .evtx file'; if ($p) { $a = Get-WfxTriageArgs; Invoke-WfxMenuAction { Invoke-WfxTriage @a -EvtxPath $p | Out-Null; Write-WfxMenuOpenReport } } }
            '6' { $p = Select-WfxMenuCase; if ($p) { $a = Get-WfxTriageArgs; $a.Remove('Hours'); Invoke-WfxMenuAction { Invoke-WfxTriage @a -InputPath $p | Out-Null; Write-WfxMenuOpenReport } } }
            '7' {
                Write-WfxConsole '  A folder of files copied from another system: registry hives (SYSTEM, Amcache.hve, NTUSER.DAT, UsrClass.dat), Jump Lists, .lnk, browser History / places.sqlite, Prefetch, PCA and Defender logs, .evtx. Files are only read.' -Kind Dim
                $p = Read-WfxMenuPath 'Evidence folder or file'
                if ($p) { $a = Get-WfxTriageArgs; $a.Remove('Hours'); Invoke-WfxMenuAction { Invoke-WfxTriage @a -ArtifactPath $p | Out-Null; Write-WfxMenuOpenReport } }
            }
        }
    }
}

function Write-WfxMenuOpenReport {
    $c = @(Get-WfxRecentCase -Max 1) | Select-Object -First 1
    if (-not $c) { return }
    $r = Join-Path $c.FullName 'report.html'
    if ((Test-Path -LiteralPath $r) -and (Test-WfxWindows)) {
        if ((Read-WfxMenuText 'Open the HTML report now? (Y/n)') -notmatch '^(?i)n') { Open-WfxPath $r }
    }
}

function Write-WfxMenuNote {
    <# Shows why a view is empty or partial (collection gaps), so absence of rows is never mistaken for absence of activity. #>
    param([object[]]$Note)
    $n = @($Note | Expand-WfxRecord | Sort-Object Source, Reason -Unique)
    if (-not $n.Count) { return }
    Write-WfxConsole ''
    Write-WfxConsole '  Notes (coverage and limits):' -Kind Warn
    foreach ($x in ($n | Select-Object -First 8)) {
        Write-WfxConsole ("   - {0}" -f $x.Reason) -Kind Warn
        if ($x.Fix) { Write-WfxConsole ("     {0}" -f $x.Fix) -Kind Dim }
    }
    if ($n.Count -gt 8) { Write-WfxConsole ("   … and {0} more." -f ($n.Count - 8)) -Kind Dim }
}

function Test-WfxGridView {
    <# Out-GridView needs Microsoft.PowerShell.GraphicalHost (Windows PowerShell with the ISE feature) or the
       Microsoft.PowerShell.GraphicalTools module (PowerShell 7). Windows Sandbox / Server Core / PS7 often have neither. #>
    if ($null -ne $script:WfxGridOk) { return $script:WfxGridOk }
    $ok = $false
    if ((Test-WfxWindows) -and (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
        if ($PSVersionTable.PSVersion.Major -le 5) { try { Add-Type -AssemblyName 'Microsoft.PowerShell.GraphicalHost' -ErrorAction Stop; $ok = $true } catch { $ok = $false } }
        else { $ok = $true }
    }
    $script:WfxGridOk = $ok
    $ok
}

function Write-WfxMenuTable {
    <# Prints rows as a table; rows flagged CRITICAL/HIGH are red, MEDIUM yellow, LOW cyan. Unflagged rows show "-"
       in the Flag column so wrapped continuation lines (which start with spaces) keep the colour of their row. #>
    param([object[]]$Rows)
    # Console only: short reason, no technique column (full text: L = list view, G = browser, E = CSV).
    $disp = foreach ($r in $Rows) {
        if (-not $r.PSObject.Properties['Flag']) { $r; continue }
        $c = $r.PSObject.Copy()
        if (-not $c.Flag) { $c.Flag = '-' }
        $whys = @(([string]$c.Why) -split ' \| ' | Where-Object { $_ })
        $c.Why = if ($whys.Count -gt 1) { (Get-WfxShortText $whys[0] 56) + " (+$($whys.Count - 1))" } elseif ($whys.Count) { Get-WfxShortText $whys[0] 64 } else { '' }
        $c | Select-Object -Property * -ExcludeProperty Technique, Rule
    }
    $text = $disp | Format-Table -AutoSize -Wrap | Out-String -Width 220
    $color = $null
    foreach ($line in ($text -split "\r?\n")) {
        if ($line -match '^(CRITICAL|HIGH)\b') { $color = 'Red' }
        elseif ($line -match '^MEDIUM\b') { $color = 'Yellow' }
        elseif ($line -match '^LOW\b') { $color = 'Cyan' }
        elseif ($line -match '^\S') { $color = $null }
        if ($color) { Write-Host $line -ForegroundColor $color } else { Write-Host $line }
    }
}

function Show-WfxMenuInsightTable {
    <# Shows a result set page-friendly, then offers export / grid / filter. #>
    param([object[]]$Rows, [string]$Title, [string]$Key, [object[]]$Note = @(), [object[]]$Pattern = @())
    $Rows = @($Rows | Expand-WfxRecord)
    $flaggable = [bool]($Rows.Count -and $Rows[0].PSObject.Properties['Flag'])
    $view = $Rows; $page = 40; $q = ''; $suspOnly = $false
    $apply = {
        $v = $Rows
        if ($suspOnly) { $v = @($v | Where-Object { $_.Flag -and $_.Flag -ne 'INFO' }) }
        if ($q) { $v = @($v | Where-Object { ($_.PSObject.Properties.Value -join ' ') -like "*$q*" }) }
        $v
    }
    while ($true) {
        Write-WfxMenuHeader "Explore › $Title"
        if ($flaggable) {
            $sum = Get-WfxFlagSummary $Rows
            if ($sum) { Write-WfxConsole ("  Suspicious: {0}   (S = show only these)" -f $sum) -Kind $(if ($sum -match 'CRITICAL|HIGH') { 'Bad' } else { 'Warn' }) }
            else { Write-WfxConsole '  No row matched a suspicious-activity rule. (Absence of a flag is not proof of absence of compromise.)' -Kind Dim }
        }
        foreach ($p in $Pattern) { Write-WfxConsole ("  PATTERN [{0}] {1} {2}" -f $p.Severity, $p.Text, $(if ($p.Technique) { "($($p.Technique))" })) -Kind Bad }
        if (-not $view.Count) { Write-WfxConsole $(if ($suspOnly) { '  No flagged rows.' } elseif ($Note.Count) { '  No records - see the notes below for why.' } else { '  No records in the selected time window.' }) -Kind Dim }
        else {
            Write-WfxMenuTable -Rows @($view | Select-Object -First $page)
            if ($view.Count -gt $page) { Write-WfxConsole ("  … showing {0} of {1} rows." -f $page, $view.Count) -Kind Dim }
            else { Write-WfxConsole ("  {0} row(s){1}." -f $view.Count, $(if ($view.Count -ne $Rows.Count) { " of $($Rows.Count)" } else { '' })) -Kind Dim }
        }
        Write-WfxMenuNote $Note
        Write-WfxConsole ''
        $opts = New-Object System.Collections.Generic.List[string]
        if ($view.Count -gt $page) { Write-WfxMenuItem 'M' 'Show more rows'; $opts.Add('M') }
        if ($flaggable) { Write-WfxMenuItem 'S' $(if ($suspOnly) { 'Show all rows' } else { 'Show suspicious rows only' }) $(Get-WfxFlagSummary $Rows); $opts.Add('S') }
        Write-WfxMenuItem 'F' 'Filter (text search)' $(if ($q) { "current: '$q'" } else { '' }); $opts.Add('F')
        Write-WfxMenuItem 'L' 'List view (all columns, one row at a time)'; $opts.Add('L')
        if ($view.Count) { Write-WfxMenuItem 'G' 'Open in browser (sort, filter, copy)' 'self-contained page, works everywhere'; $opts.Add('G') }
        if ($view.Count -and (Test-WfxGridView)) { Write-WfxMenuItem 'W' 'Open in Out-GridView window'; $opts.Add('W') }
        Write-WfxMenuItem 'E' 'Export to CSV'; $opts.Add('E')
        Write-WfxMenuItem 'R' 'Refresh'; $opts.Add('R')
        Write-WfxMenuFooter
        $opts.Add('B'); $opts.Add('Q')
        $c = Read-WfxMenuChoice -Valid $opts.ToArray()
        switch ($c) {
            'B' { return }
            'Q' { return 'Q' }
            'M' { $page += 80 }
            'R' { return 'R' }
            'S' { $suspOnly = -not $suspOnly; $view = @(& $apply) }
            'F' {
                $q = Read-WfxMenuText 'Text to find (Enter = clear filter)'
                $view = @(& $apply)
            }
            'L' { $view | Select-Object -First $page | Format-List | Out-String -Width 220 | Write-Host; Wait-WfxMenu }
            'G' {
                try {
                    $pn = @($Pattern | ForEach-Object { [pscustomobject]@{ Reason = "PATTERN [$($_.Severity)] $($_.Text) $(if ($_.Technique) { "($($_.Technique))" })"; Fix = '' } })
                    $f = Save-WfxViewHtml -Rows $view -Title $Title -Key $Key -Note (@($pn) + @($Note))
                    Write-WfxConsole "  Saved: $f" -Kind Ok
                    Open-WfxPath $f
                } catch { Write-WfxConsole "  Could not create the page: $($_.Exception.Message)" -Kind Bad }
                Wait-WfxMenu
            }
            'W' { try { $view | Out-GridView -Title "WinForensicX: $Title" -ErrorAction Stop } catch { Write-WfxConsole "  Out-GridView failed: $($_.Exception.Message) - use G (browser) instead." -Kind Warn; Wait-WfxMenu } }
            'E' {
                $root = Get-WfxCaseRoot
                if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
                $f = Join-Path $root ("{0}_{1}_{2}.csv" -f [Environment]::MachineName, $Key, (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
                $view | Export-Csv -Path $f -NoTypeInformation -Encoding UTF8
                Write-WfxConsole "  Saved: $f" -Kind Ok; Wait-WfxMenu
            }
        }
    }
}

function Show-WfxMenuExplore {
    $groups = @($script:WfxInsightTopics.Values | ForEach-Object { $_.Group } | Select-Object -Unique)
    $gdesc = @{ 'Recent changes' = 'what attackers change: registry, files, installs, executions, connections, config'; System = 'OS, updates, software, users, groups, sessions, shares, USB, drives'; Processes = 'running programs, process tree, unsigned programs, loaded DLLs, named pipes'
        Network = 'listening ports, connections, DNS, adapters, routes, ARP, hosts, proxy, Wi-Fi, firewall, SMB'; Persistence = 'autostarts, services, drivers, scheduled tasks, WMI'
        Events = 'logons, failed logons, RDP, account changes, new services, log clears, reboots, PowerShell, Defender'; Files = 'downloads, new programs, Prefetch, recent files, PS history, Run box'
        Security = 'posture checklist with fixes; memory-capture readiness and incident card'; 'Evidence of execution' = 'Amcache, ShimCache, Prefetch, BAM, ShellBags, Jump Lists, browser downloads, Defender logs' }
    while ($true) {
        Write-WfxMenuHeader 'Explore this computer (live, read-only views)'
        $i = 0; $keys = @()
        foreach ($g in $groups) { $i++; $keys += [string]$i; Write-WfxMenuItem ([string]$i) $g $gdesc[$g] }
        Write-WfxConsole ''
        Write-WfxMenuItem 'A' 'Export EVERYTHING to an inventory report' 'HTML + CSV per view, hashed (1-5 min)'
        Write-WfxMenuFooter
        $c = Read-WfxMenuChoice -Valid ($keys + 'A', 'B', 'Q')
        if ($c -eq 'B') { return }
        if ($c -eq 'Q') { return 'Q' }
        if ($c -eq 'A') { Invoke-WfxMenuAction { Save-WfxInsight -OutputPath $script:WfxMenu.OutputPath | Out-Null }; continue }
        $grp = $groups[[int]$c - 1]
        $r = Show-WfxMenuTopicList -Group $grp
        if ($r -eq 'Q') { return 'Q' }
    }
}

function Show-WfxMenuTopicList {
    param([string]$Group)
    $topics = @($script:WfxInsightTopics.GetEnumerator() | Where-Object { $_.Value.Group -eq $Group })
    $admin = Test-WfxAdmin
    while ($true) {
        Write-WfxMenuHeader "Explore › $Group"
        $i = 0; $keys = @()
        foreach ($t in $topics) {
            $i++; $keys += [string]$i
            $tag = if ($t.Value.Admin -and -not $admin) { ' [needs admin]' } else { '' }
            Write-WfxMenuItem ([string]$i) ($t.Value.Title + $tag) ''
            Write-WfxConsole ("        {0}" -f $t.Value.Desc) -Kind Dim
        }
        Write-WfxMenuFooter
        $c = Read-WfxMenuChoice -Valid ($keys + 'B', 'Q')
        if ($c -eq 'B') { return }
        if ($c -eq 'Q') { return 'Q' }
        $t = $topics[[int]$c - 1]
        do {
            Write-WfxConsole ''
            Write-WfxConsole "  Collecting: $($t.Value.Title) ..." -Kind Info
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $rows = @(); $err = $null
            Clear-WfxGap
            try { $rows = @(Get-WfxInsight -Topic $t.Key -Days $(if ($script:WfxMenu.Days) { $script:WfxMenu.Days } else { [int]$(if ($t.Value.Days) { $t.Value.Days } else { 7 }) }) -WarningAction SilentlyContinue) } catch { $err = $_.Exception.Message }
            $notes = @(Get-WfxGap | Expand-WfxRecord)
            if ($t.Value.Admin -and -not $admin) { $notes = @([pscustomobject]@{ Source = 'privileges'; Reason = 'This view needs administrator rights; results are empty or partial.'; Fix = 'Reopen PowerShell with "Run as administrator".' }) + $notes }
            if ($err) { Write-WfxConsole "  Could not read this view: $err" -Kind Bad; Write-WfxMenuNote $notes; Wait-WfxMenu; $r = 'B' }
            else { Write-WfxConsole ("  done in {0:N1}s" -f $sw.Elapsed.TotalSeconds) -Kind Dim; $r = Show-WfxMenuInsightTable -Rows $rows -Title $t.Value.Title -Key $t.Key -Note $notes -Pattern @(Get-WfxViewPattern) }
        } while ($r -eq 'R')
        if ($r -eq 'Q') { return 'Q' }
    }
}

function Show-WfxMenuHunt {
    while ($true) {
        Write-WfxMenuHeader 'Hunt & analyze'
        Write-WfxMenuItem '1' 'Hunt IOCs on this computer' 'hashes, IPs, domains, names, strings'
        Write-WfxMenuItem '2' 'Hunt IOCs in a saved case' 'no live collection'
        Write-WfxMenuItem '3' 'What is this file? (file triage)' 'hashes, real type, signer, download URL, PE, strings, IOCs'
        Write-WfxMenuItem '4' 'Triage every file in a folder' 'quick table: type mismatch, entropy, signature'
        Write-WfxMenuItem '5' 'Decode a command / Base64 payload' '-EncodedCommand, gzip, nested layers (never executed)'
        Write-WfxConsole ''
        Write-WfxMenuItem '6' 'Take a file-integrity baseline' 'hash folders now, to detect changes later'
        Write-WfxMenuItem '7' 'Compare with a baseline' 'added / deleted / content-changed / timestamp-only files'
        Write-WfxConsole ''
        Write-WfxMenuItem '8' 'Parse artifacts from a folder or file' 'Amcache, ShimCache, ShellBags, Jump Lists, .lnk, browser history... as a flagged table'
        Write-WfxMenuItem '9' 'Hunt IOCs in a collected evidence folder' 'Amcache SHA-1 matches programs that were deleted'
        Write-WfxConsole ''
        Write-WfxMenuItem 'F' 'Find files and folders (fast, all drives)' 'by name, extension or none, size, date; optional hash and real type'
        Write-WfxMenuFooter
        $c = Read-WfxMenuChoice -Valid '1', '2', '3', '4', '5', '6', '7', '8', '9', 'F', 'B', 'Q'
        switch ($c) {
            'B' { return }
            'Q' { return 'Q' }
            { $_ -in '1', '2' } {
                Write-WfxConsole '  Enter IOCs separated by commas (defanged like evil[.]com is fine), or the path of a text file with one per line.' -Kind Dim
                $i = Read-WfxMenuText 'IOCs or IOC file (Enter = cancel)'
                if (-not $i) { break }
                $hp = @{ OutputPath = $script:WfxMenu.OutputPath }
                $iv = $i.Trim('"')
                if (Test-Path -LiteralPath $iv -PathType Leaf) { $hp.IocFile = $iv } else { $hp.Ioc = @($i -split '\s*,\s*' | Where-Object { $_ }) }
                if ($c -eq '2') { $p = Select-WfxMenuCase; if (-not $p) { break }; $hp.InputPath = $p }
                else { $hp.Hours = $script:WfxMenu.Hours; if ((Read-WfxMenuText 'Also scan files and hash running programs? Slower. (y/N)') -match '^(?i)y') { $hp.FileScan = $true; $hp.HashProcesses = $true } }
                Invoke-WfxMenuAction { Invoke-WfxHunt @hp | Out-Null }
            }
            '3' {
                $p = Read-WfxMenuPath 'File to examine' -Kind File
                if ($p) { Invoke-WfxMenuAction {
                        $t = Get-WfxFileTriage -Path $p -Strings
                        $t | Format-List Path, Size, FileType, Extension, ExtensionMismatch, MD5, SHA1, SHA256, Entropy, EntropyHint, CreatedUtc, ModifiedUtc, Zone, HostUrl, ReferrerUrl, AlternateStreams | Out-String -Width 200 | Write-Host
                        if ($t.Signature) { Write-WfxConsole '  Signature' -Kind Head; $t.Signature | Format-List | Out-String | Write-Host }
                        if ($t.PE) { Write-WfxConsole '  PE header' -Kind Head; $t.PE | Format-List | Out-String | Write-Host }
                        if ($t.Iocs) {
                            Write-WfxConsole '  Indicators found in strings' -Kind Head
                            foreach ($n in 'Urls', 'IPv4', 'Domains', 'Emails', 'RegistryPaths') { $v = @($t.Iocs.$n); if ($v.Count) { Write-WfxConsole ("   {0,-14} {1}" -f $n, (($v | Select-Object -First 15) -join '  ')) } }
                        }
                        if ((Read-WfxMenuText "Show the first 100 of $($t.StringCount) strings? (y/N)") -match '^(?i)y') { $t.Strings | Select-Object -First 100 | ForEach-Object { Write-WfxConsole "   $_" -Kind Dim } }
                    } }
            }
            '4' {
                $p = Read-WfxMenuPath 'Folder' -Kind Folder
                if ($p) { Invoke-WfxMenuAction -NoPause {
                        $rows = @(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | Select-Object -First 500 | Get-WfxFileTriage | Select-Object @{ n = 'File'; e = { Split-Path -Leaf $_.Path } }, FileType, ExtensionMismatch, Entropy, Zone, @{ n = 'Signed'; e = { if ($_.Signature) { $_.Signature.Status } else { '' } } }, SHA256)
                        $null = Show-WfxMenuInsightTable -Rows $rows -Title "Files in $p" -Key 'filetriage'
                    } }
            }
            '6' {
                Write-WfxConsole '  Folders to baseline, comma-separated (e.g. C:\inetpub\wwwroot, C:\Windows\System32\drivers\etc).' -Kind Dim
                $t = Read-WfxMenuText 'Folders (Enter = cancel)'
                if ($t) { $paths = @($t -split '\s*,\s*' | ForEach-Object { $_.Trim('"') } | Where-Object { $_ }); Invoke-WfxMenuAction { New-WfxFileBaseline -Path $paths | Out-Null } }
            }
            '8' {
                $p = Read-WfxMenuPath 'Evidence folder or file (hive, Jump List, .lnk, History...)'
                if ($p) { Invoke-WfxMenuAction -NoPause {
                        Clear-WfxGap
                        $rows = @(Get-WfxArtifact -Path $p -Flag -WarningAction SilentlyContinue | Sort-Object @{ e = { -$script:WfxFlagRank[[string]$_.Flag] } }, @{ e = { [string]$_.Time }; Descending = $true } |
                            Select-Object Flag, Why, Technique, Rule, Time, TimeKind, Artifact, Path, User, Sha1, Detail, Source)
                        $null = Show-WfxMenuInsightTable -Rows $rows -Title "Artifacts in $p" -Key 'artifacts' -Note @(Get-WfxGap | Expand-WfxRecord)
                    } }
            }
            '9' {
                $i = Read-WfxMenuText 'IOCs (comma-separated) or IOC file (Enter = cancel)'
                if (-not $i) { break }
                $p = Read-WfxMenuPath 'Evidence folder'
                if ($p) {
                    $hp = @{ OutputPath = $script:WfxMenu.OutputPath; ArtifactPath = $p }
                    $iv = $i.Trim('"'); if (Test-Path -LiteralPath $iv -PathType Leaf) { $hp.IocFile = $iv } else { $hp.Ioc = @($i -split '\s*,\s*' | Where-Object { $_ }) }
                    Invoke-WfxMenuAction { Invoke-WfxHunt @hp | Out-Null }
                }
            }
            'F' {
                Write-WfxConsole '  Leave a question empty to skip it. Names take wildcards: *invoice*, setup?.exe' -Kind Dim
                $fa = @{}
                $n = Read-WfxMenuText 'File or folder name(s), comma-separated'
                if ($n) { $fa.Name = @($n -split '\s*,\s*' | Where-Object { $_ }) }
                $e = Read-WfxMenuText 'Extension(s), e.g. exe,ps1,hta (or "none" for files without one)'
                if ($e -match '^(?i)none$') { $fa.NoExtension = $true } elseif ($e) { $fa.Extension = @($e) }
                $p = Read-WfxMenuPath 'Only in this folder (Enter = every drive)' -Kind Folder
                if ($p) { $fa.Path = @($p) }
                $d = 0; if ([int]::TryParse((Read-WfxMenuText 'Changed in the last N days'), [ref]$d) -and $d -gt 0) { $fa.ModifiedAfter = (Get-Date).AddDays(-$d) }
                if ((Read-WfxMenuText 'Also hash each file and check its real type? (y/N)') -match '^(?i)y') { $fa.Hash = $true; $fa.CheckType = $true }
                if (-not ($fa.Name -or $fa.Extension -or $fa.NoExtension -or $fa.ModifiedAfter)) { Write-WfxConsole '  Nothing to look for.' -Kind Warn; Wait-WfxMenu; break }
                if (-not $fa.Name) { $fa.ItemType = 'File' } else { $fa.ItemType = 'Any' }
                Invoke-WfxMenuAction -NoPause {
                    Write-WfxConsole '  Searching...' -Kind Dim
                    $warn = $null
                    $rows = @(Find-WfxFile @fa -WarningVariable warn -WarningAction SilentlyContinue)
                    $note = @($warn | ForEach-Object { [pscustomobject]@{ Source = 'search'; Reason = [string]$_; Fix = '' } })
                    $null = Show-WfxMenuInsightTable -Rows $rows -Title 'Files found' -Key 'find' -Note $note
                }
            }
            '7' {
                $p = Read-WfxMenuPath 'Baseline .json file' -Kind File
                if ($p) { Invoke-WfxMenuAction -NoPause { $d = @(Compare-WfxFileBaseline -Baseline $p); $null = Show-WfxMenuInsightTable -Rows $d -Title 'File baseline comparison' -Key 'baseline' } }
            }
            '5' {
                $p = Read-WfxMenuText 'Paste the command line or Base64 (Enter = cancel)'
                if ($p) { Invoke-WfxMenuAction {
                        $d = ConvertFrom-WfxEncodedCommand -InputObject $p
                        if ($d) {
                            foreach ($l in $d.Layers) { Write-WfxConsole "  Layer $($l.Layer) ($($l.Source))" -Kind Head; Write-WfxConsole "  $($l.Text)" }
                            if ($d.Rules) { Write-WfxConsole ''; Write-WfxConsole ('  Matched detections: ' + ($d.Rules -join '; ')) -Kind Warn }
                            Write-WfxConsole ''; Write-WfxConsole '  Decoded only — nothing was executed.' -Kind Dim
                        }
                    } }
            }
        }
    }
}

function Select-WfxMenuCase {
    <# Lets the user pick a recent case by number or type a path. Returns the case path or $null. #>
    $cases = Get-WfxRecentCase -Max 12
    if ($cases.Count) {
        Write-WfxConsole '  Recent cases:' -Kind Head
        for ($i = 0; $i -lt $cases.Count; $i++) { Write-WfxConsole ("   {0,-3} {1}   ({2:yyyy-MM-dd HH:mm})" -f ($i + 1), $cases[$i].Name, $cases[$i].LastWriteTime) }
        Write-WfxConsole '   P   type a path instead' -Kind Dim
        $c = Read-WfxMenuChoice -Valid (@(1..$cases.Count | ForEach-Object { [string]$_ }) + 'P', 'B') -Prompt 'Case number, P or B'
        if ($c -eq 'B') { return $null }
        if ($c -ne 'P') { return $cases[[int]$c - 1].FullName }
    }
    Read-WfxMenuPath 'Case folder or bundle.json'
}

function Show-WfxMenuCases {
    while ($true) {
        Write-WfxMenuHeader 'Cases & evidence'
        Write-WfxMenuItem '1' 'Open a case report' 'pick from recent cases'
        Write-WfxMenuItem '2' 'Open the case folder'
        Write-WfxMenuItem '3' 'Verify a case (chain of custody)' 're-hash every file against its manifest'
        Write-WfxMenuItem '4' 'Export a case timeline (CSV)' 'one UTC-sorted list of everything with a time'
        Write-WfxMenuItem '5' 'Compare two cases' 'what is new or gone since a baseline'
        Write-WfxMenuItem '6' 'Export a case for other tools' 'Timesketch CSV, Elastic/Splunk ECS, STIX 2.1, indicator list'
        Write-WfxMenuItem '7' 'Fleet report (many hosts)' 'patient zero, spread, shared indicators across all cases in a folder'
        Write-WfxMenuFooter
        $c = Read-WfxMenuChoice -Valid '1', '2', '3', '4', '5', '6', '7', 'B', 'Q'
        switch ($c) {
            'B' { return }
            'Q' { return 'Q' }
            '1' { $p = Select-WfxMenuCase; if ($p) { $r = Join-Path $p 'report.html'; if (Test-Path -LiteralPath $r) { Open-WfxPath $r } else { Write-WfxConsole '  This case has no HTML report (evidence-only or hunt case).' -Kind Warn; Wait-WfxMenu } } }
            '2' { $p = Select-WfxMenuCase; if ($p) { Open-WfxPath $(if (Test-Path -LiteralPath $p -PathType Leaf) { Split-Path -Parent $p } else { $p }) } }
            '3' { $p = Select-WfxMenuCase; if ($p) { Invoke-WfxMenuAction { Test-WfxCase -Path $p | Out-Null } } }
            '4' { $p = Select-WfxMenuCase; if ($p) { Invoke-WfxMenuAction { Export-WfxTimeline -InputPath $p } } }
            '5' {
                Write-WfxConsole '  First the BASELINE (older / known-good) case:' -Kind Dim; $a = Select-WfxMenuCase
                if (-not $a) { break }
                Write-WfxConsole '  Now the CURRENT case:' -Kind Dim; $b = Select-WfxMenuCase
                if ($b) { Invoke-WfxMenuAction -NoPause { $d = @(Compare-WfxCase -Baseline $a -Current $b); $null = Show-WfxMenuInsightTable -Rows $d -Title 'Case comparison' -Key 'compare' } }
            }
            '6' { $p = Select-WfxMenuCase; if ($p) { Invoke-WfxMenuAction { Export-WfxCase -InputPath $p | Out-Null } } }
            '7' {
                $p = Read-WfxMenuPath "Folder holding the case folders (Enter = $(Get-WfxCaseRoot))" -Kind Folder
                if (-not $p) { $p = Get-WfxCaseRoot }
                Invoke-WfxMenuAction { $f = New-WfxFleetReport -Path $p -PassThru; if ($f) { Open-WfxPath $f } }
            }
        }
    }
}

function Show-WfxMenuSettings {
    while ($true) {
        Write-WfxMenuHeader 'Settings (this session)'
        Write-WfxMenuItem '1' 'Output folder' (Get-WfxCaseRoot)
        Write-WfxMenuItem '2' 'Event look-back for triage (hours)' ([string]$script:WfxMenu.Hours)
        Write-WfxMenuItem '3' 'Look-back for live views (days)' $(if ($script:WfxMenu.Days) { [string]$script:WfxMenu.Days } else { 'per view default' })
        Write-WfxMenuItem '4' 'Allowlist file' $(if ($script:WfxMenu.Allowlist) { $script:WfxMenu.Allowlist } else { '(none)' })
        Write-WfxMenuItem '5' 'Custom rules folder' $(if ($script:WfxMenu.RulesPath) { $script:WfxMenu.RulesPath } else { '(built-in only)' })
        Write-WfxMenuItem '6' 'Sigma rules folder' $(if ($script:WfxMenu.Sigma) { $script:WfxMenu.Sigma } elseif ($env:WFX_SIGMA) { "$env:WFX_SIGMA (WFX_SIGMA)" } else { '(none)' })
        Write-WfxMenuItem '7' 'YARA rules folder' $(if ($script:WfxMenu.Yara) { $script:WfxMenu.Yara } elseif ($env:WFX_YARA) { "$env:WFX_YARA (WFX_YARA)" } else { '(none)' })
        Write-WfxConsole ''
        Write-WfxMenuItem 'V' 'Verify this copy of WinForensicX' 'compare its files with SHA256SUMS.txt'
        Write-WfxMenuFooter
        $c = Read-WfxMenuChoice -Valid '1', '2', '3', '4', '5', '6', '7', 'V', 'B', 'Q'
        switch ($c) {
            'B' { return }
            'Q' { return 'Q' }
            '1' {
                $p = Read-WfxMenuPath 'Folder for cases (created if missing; external drive recommended)' -AllowMissing
                if ($p) { try { New-Item -ItemType Directory -Path $p -Force -ErrorAction Stop | Out-Null; $script:WfxMenu.OutputPath = (Resolve-Path -LiteralPath $p).Path } catch { Write-WfxConsole "  Cannot use that folder: $($_.Exception.Message)" -Kind Bad; Wait-WfxMenu } }
            }
            '2' { $v = 0; if ([int]::TryParse((Read-WfxMenuText 'Hours (1-8760)' ([string]$script:WfxMenu.Hours)), [ref]$v) -and $v -ge 1 -and $v -le 8760) { $script:WfxMenu.Hours = $v } else { Write-WfxConsole '  Enter a number from 1 to 8760.' -Kind Warn; Wait-WfxMenu } }
            '3' { $v = 0; $t = Read-WfxMenuText 'Days (1-3650, 0 = per view default)' ([string]$script:WfxMenu.Days); if ([int]::TryParse($t, [ref]$v) -and $v -ge 0 -and $v -le 3650) { $script:WfxMenu.Days = $v } else { Write-WfxConsole '  Enter a number from 0 to 3650.' -Kind Warn; Wait-WfxMenu } }
            'V' { Invoke-WfxMenuAction { Write-WfxConsole ''; Write-WfxIntegrityLine (Test-WfxIntegrity) -Detail } }
            '4' { $p = Read-WfxMenuPath 'Allowlist JSON (see examples\allowlist.example.json)' -Kind File; $script:WfxMenu.Allowlist = [string]$p }
            '5' { $p = Read-WfxMenuPath 'Folder with <pack>.<name>.json rule files' -Kind Folder; $script:WfxMenu.RulesPath = [string]$p; Set-WfxRulePath ([string]$p) }
            '6' { $p = Read-WfxMenuPath 'Folder of Sigma .yml rules (e.g. sigma\rules\windows)' -Kind Folder; $script:WfxMenu.Sigma = [string]$p }
            '7' {
                $p = Read-WfxMenuPath 'Folder or file of YARA rules (.yar)'; $script:WfxMenu.Yara = [string]$p
                if ($p -and -not (Find-WfxYaraExe)) { Write-WfxConsole '  No yara executable found on PATH. Install YARA or set WFX_YARA_EXE; scans are skipped (and noted) until then.' -Kind Warn; Wait-WfxMenu }
            }
        }
    }
}

function Show-WfxMenuRespond {
    while ($true) {
        Write-WfxMenuHeader 'Respond (changes this computer)'
        Write-WfxConsole '  Every action shows what it will do and asks first. Everything except stopping a process can be undone (U).' -Kind Dim
        Write-WfxConsole '  What is changed is recorded first in Downloads\WinForensicX-Quarantine (administrators only).' -Kind Dim
        if (-not (Test-WfxAdmin)) { Write-WfxConsole '  Needs administrator rights: restart WinForensicX as administrator to use this section.' -Kind Warn }
        Write-WfxConsole ''
        Write-WfxMenuItem '1' 'Act on a triage case' 'the stops, quarantines and blocks the triage suggested'
        Write-WfxMenuItem '2' 'Stop a process' 'by PID; capture memory first if you need it'
        Write-WfxMenuItem '3' 'Quarantine a file' 'moved and encrypted into the quarantine'
        Write-WfxMenuItem '4' 'Disable an autostart' 'Run-key value, scheduled task, service or WMI subscription'
        Write-WfxMenuItem '5' 'Block an address or a program' 'Windows Firewall rules (group WinForensicX)'
        Write-WfxMenuItem '6' 'Disable a local account'
        Write-WfxConsole ''
        Write-WfxMenuItem '7' 'Isolate this computer' 'everything blocked except your session; ends by itself'
        Write-WfxMenuItem '8' 'End the isolation'
        Write-WfxMenuItem '9' 'Defender scan of a file or folder' 'a second opinion'
        Write-WfxConsole ''
        Write-WfxMenuItem 'L' 'Actions taken here'
        Write-WfxMenuItem 'U' 'Undo an action'
        Write-WfxMenuFooter
        $c = Read-WfxMenuChoice -Valid '1', '2', '3', '4', '5', '6', '7', '8', '9', 'L', 'U', 'B', 'Q'
        switch ($c) {
            'B' { return }
            'Q' { return 'Q' }
            '1' {
                $p = Select-WfxMenuCase
                if (-not $p) { break }
                $pf = Join-Path $(if (Test-Path -LiteralPath $p -PathType Leaf) { Split-Path -Parent $p } else { $p }) 'respond-plan.json'
                if (-not (Test-Path -LiteralPath $pf)) { Write-WfxConsole '  This case has no response plan (only live and remote triage write one).' -Kind Warn; Wait-WfxMenu; break }
                $plan = Get-Content -LiteralPath $pf -Raw -Encoding UTF8 | ConvertFrom-Json
                if (-not @($plan.Actions).Count) { Write-WfxConsole '  The triage suggested no action.' -Kind Dim; Wait-WfxMenu; break }
                Write-WfxConsole ''
                foreach ($a in @($plan.Actions)) { Write-WfxConsole ("   {0}  {1} {2,-14} {3}   ({4}: {5})" -f $a.Id, $(if ($a.Selected) { '[x]' } else { '[ ]' }), $a.Type, $a.Target, $a.Severity, (Get-WfxShortText ([string]$a.Reason) 70)) -Kind $(if ($a.Selected) { 'Plain' } else { 'Dim' }) }
                Write-WfxConsole ''
                $ids = Read-WfxMenuText 'Action ids to run, comma-separated (Enter = the ticked ones, A = all, N = none)'
                if ($ids -match '^(?i)n$') { break }
                $ra = @{ PlanPath = $pf }
                if ($ids -match '^(?i)a$') { $ra.All = $true } elseif ($ids) { $ra.ActionId = @($ids -split '\s*,\s*' | Where-Object { $_ }) }
                Invoke-WfxMenuAction { Invoke-WfxRespond @ra | Format-Table Type, Target, Status, Message -AutoSize -Wrap | Out-String -Width 200 | Write-Host }
            }
            '2' { $v = 0; if ([int]::TryParse((Read-WfxMenuText 'PID (Enter = cancel)'), [ref]$v) -and $v -gt 4) { Invoke-WfxMenuAction { Invoke-WfxRespond -KillProcess $v | Format-List Type, Target, Status, Message, Id | Out-String | Write-Host } } }
            '3' { $p = Read-WfxMenuPath 'File to quarantine' -Kind File; if ($p) { Invoke-WfxMenuAction { Invoke-WfxRespond -QuarantineFile $p | Format-List Type, Target, Status, Message, Id | Out-String | Write-Host } } }
            '4' {
                Write-WfxConsole '   R  Run-key value, as <key>\<value name>   T  Scheduled task (\Folder\Name)   S  Service name   W  WMI consumer name' -Kind Dim
                $k = Read-WfxMenuChoice -Valid 'R', 'T', 'S', 'W', 'B' -Prompt 'R, T, S, W or B'
                if ($k -eq 'B') { break }
                $v = Read-WfxMenuText 'Which one (Enter = cancel)'
                if (-not $v) { break }
                $ra = switch ($k) { 'R' { @{ DisableRunKey = @($v) } } 'T' { @{ DisableTask = @($v) } } 'S' { @{ DisableService = @($v) } } 'W' { @{ DisableWmiConsumer = @($v) } } }
                Invoke-WfxMenuAction { Invoke-WfxRespond @ra | Format-List Type, Target, Status, Message, Id | Out-String | Write-Host }
            }
            '5' {
                $v = Read-WfxMenuText 'IP address, or the full path of a program (Enter = cancel)'
                if (-not $v) { break }
                $ip = $null
                $ra = if ([System.Net.IPAddress]::TryParse(($v -split '/')[0], [ref]$ip)) { @{ BlockAddress = @($v) } } else { @{ BlockProgram = @($v.Trim('"')) } }
                Invoke-WfxMenuAction { Invoke-WfxRespond @ra | Format-List Type, Target, Status, Message, Id | Out-String | Write-Host }
            }
            '6' { $v = Read-WfxMenuText 'Local account name (Enter = cancel)'; if ($v) { Invoke-WfxMenuAction { Invoke-WfxRespond -DisableAccount $v | Format-List Type, Target, Status, Message, Id | Out-String | Write-Host } } }
            '7' {
                $m = 30; $t = Read-WfxMenuText 'End by itself after how many minutes (0 = never)' '30'
                if (-not [int]::TryParse($t, [ref]$m) -or $m -lt 0) { Write-WfxConsole '  Enter a number of minutes.' -Kind Warn; Wait-WfxMenu; break }
                $al = Read-WfxMenuText 'Extra addresses to keep reachable, comma-separated (management server, EDR, file server)'
                $ia = @{ Minutes = $m }; if ($al) { $ia.Allow = @($al -split '\s*,\s*' | Where-Object { $_ }) }
                Invoke-WfxMenuAction { Start-WfxIsolation @ia | Format-List Type, Status, Message, Id | Out-String | Write-Host }
            }
            '8' { Invoke-WfxMenuAction { Stop-WfxIsolation } }
            '9' { $p = Read-WfxMenuPath 'File or folder to scan'; if ($p) { Invoke-WfxMenuAction { $r = @(Invoke-WfxDefenderScan -Path $p); if ($r.Count) { $r | Format-List | Out-String | Write-Host } } } }
            'L' { Invoke-WfxMenuAction -NoPause { $rows = @(Get-WfxAction | Select-Object Time, Type, Target, Status, Undone, Id, Message); $null = Show-WfxMenuInsightTable -Rows $rows -Title 'Actions taken' -Key 'actions' } }
            'U' {
                $recent = @(Get-WfxAction | Where-Object { $_.Status -eq 'Done' -and $_.Reversible -and -not $_.Undone } | Select-Object -First 15)
                if (-not $recent.Count) { Write-WfxConsole '  Nothing that can be undone.' -Kind Dim; Wait-WfxMenu; break }
                foreach ($r in $recent) { Write-WfxConsole ("   {0}  {1,-14} {2}" -f $r.Id, $r.Type, $r.Target) }
                $v = Read-WfxMenuText 'Action id to undo (Enter = cancel)'
                if ($v) { Invoke-WfxMenuAction { Undo-WfxAction -Id $v.Trim() | Format-List | Out-String | Write-Host } }
            }
        }
    }
}

function Show-WfxMenu {
    <#
    .SYNOPSIS
        Interactive menu for WinForensicX — the easiest way to use the toolkit. Sections:
        Investigate (triage), Explore (live views of the system), Hunt & analyze, Cases & evidence,
        Live monitor, Settings, Respond and Help. Everything is read-only except Respond, which changes only
        what you confirm.
    .EXAMPLE
        Show-WfxMenu
    .EXAMPLE
        Show-WfxMenu -OutputPath E:\cases
    #>
    [CmdletBinding()]
    param([string]$OutputPath = '')
    $script:WfxQuiet = $false
    if ($OutputPath) { $script:WfxMenu.OutputPath = $OutputPath }
    $missing = @(Test-WfxRulePackSet)
    while ($true) {
        Write-WfxMenuHeader 'Main menu'
        if ($missing.Count) { Write-WfxConsole "  ! Rule pack(s) missing: $($missing -join ', ') — restore them from the release (antivirus may have quarantined them)." -Kind Bad; Write-WfxConsole '' }
        Write-WfxMenuItem '1' 'Investigate this computer' 'triage: find signs of compromise and get a report'
        Write-WfxMenuItem '2' 'Explore this computer' '61 live views: what ran, what changed, users, software, network, USB...'
        Write-WfxMenuItem '3' 'Hunt & analyze' 'IOC hunting, artifact parsing, file triage, decode payloads'
        Write-WfxMenuItem '4' 'Cases & evidence' 'reports, verify, timeline, compare, export, fleet report'
        Write-WfxMenuItem '5' 'Live monitor' 'watch new processes / connections as they happen'
        Write-WfxMenuItem '6' 'Settings' 'output folder, look-back, allowlist, custom / Sigma / YARA rules'
        Write-WfxMenuItem '7' 'Respond (contain a threat)' 'stop, quarantine, disable, block, isolate; every step confirmed and undoable'
        Write-WfxMenuItem 'H' 'Help & guide' 'what everything does, in a browser page'
        Write-WfxMenuFooter -NoBack
        $c = Read-WfxMenuChoice -Valid '1', '2', '3', '4', '5', '6', '7', 'H', 'Q'
        $r = switch ($c) {
            '1' { Show-WfxMenuTriage }
            '2' { Show-WfxMenuExplore }
            '3' { Show-WfxMenuHunt }
            '4' { Show-WfxMenuCases }
            '5' {
                Write-WfxMenuHeader 'Live monitor'
                Write-WfxConsole '  Watches for NEW processes and connections and alerts on suspicious ones. Press Ctrl+C to stop.' -Kind Dim
                $d = 0; [void][int]::TryParse((Read-WfxMenuText 'Run for how many seconds? (Enter = until Ctrl+C)' '0'), [ref]$d)
                Invoke-WfxMenuAction { Start-WfxMonitor -Duration $d -OutputPath $script:WfxMenu.OutputPath }
            }
            '6' { Show-WfxMenuSettings }
            '7' { Show-WfxMenuRespond }
            'H' { Invoke-WfxMenuAction -NoPause { Show-WfxHelp -Html } }
            'Q' { 'Q' }
        }
        if (@($r) -contains 'Q') { Write-WfxConsole ''; Write-WfxConsole '  Bye. Cases are in: ' -Kind Dim -NoNewline; Write-WfxConsole (Get-WfxCaseRoot) -Kind Info; return }
    }
}
