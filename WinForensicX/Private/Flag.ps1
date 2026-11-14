# Row verdicts for Explore views: every row of a flaggable view gets Flag / Why / Technique columns.
#
# Design rules (these views are read by people who will act on them):
#   * Analyzer-backed views run the SAME analyzers as triage, so a view and a triage report never disagree.
#   * A flag always says why, in plain words, and names the ATT&CK technique when there is one.
#   * The triage allowlist ($env:WFX_ALLOWLIST) suppresses the same things here.
#   * A flag is a lead to investigate, not a verdict of compromise. Severity follows the analyzers' scale.

$script:WfxFlagRank = @{ 'CRITICAL' = 5; 'HIGH' = 4; 'MEDIUM' = 3; 'LOW' = 2; 'INFO' = 1; '' = 0 }
$script:WfxFlagColumns = @('Flag', 'Why', 'Technique', 'Rule')   # Rule = triage rule id(s), usable in the allowlist

function Get-WfxSessionAllowlist {
    <# The allowlist that triage uses: the menu setting (Settings › Allowlist file) if set, else $env:WFX_ALLOWLIST.
       Cached per path, so changing the setting takes effect on the next view. #>
    $path = ''
    if ((Test-Path variable:script:WfxMenu) -and $script:WfxMenu -and $script:WfxMenu.Allowlist) { $path = [string]$script:WfxMenu.Allowlist }
    elseif ($env:WFX_ALLOWLIST) { $path = $env:WFX_ALLOWLIST }
    if ($null -ne $script:WfxSessionAllow -and $script:WfxSessionAllowPath -eq $path) { return , $script:WfxSessionAllow }
    $a = @()       # Read-WfxAllowlist already returns an array; wrapping it in @() would nest it
    if ($path) {
        if (Test-Path -LiteralPath $path) {
            try { $a = Read-WfxAllowlist -Path $path } catch { Add-WfxGap -Source 'allowlist' -Reason "Allowlist $path could not be read: $($_.Exception.Message)" }
        } else { Add-WfxGap -Source 'allowlist' -Reason "Allowlist file not found: $path" }
    }
    $script:WfxSessionAllow = $a
    $script:WfxSessionAllowPath = $path
    , $a
}

function Add-WfxVerdict {
    <#
    .SYNOPSIS Adds one reason to a row's verdict. The row keeps the highest severity; reasons and techniques accumulate.
    .PARAMETER Severity Critical | High | Medium | Low | Info
    #>
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Severity, [Parameter(Mandatory)][string]$Why, [string[]]$Technique = @(), [string]$Rule = '')
    $sev = $Severity.ToUpperInvariant()
    if (-not $script:WfxFlagRank.ContainsKey($sev) -or $sev -eq '') { throw "Invalid severity '$Severity'" }
    foreach ($c in $script:WfxFlagColumns) { if (-not $InputObject.PSObject.Properties[$c]) { $InputObject | Add-Member -NotePropertyName $c -NotePropertyValue '' } }
    if ($script:WfxFlagRank[$sev] -gt $script:WfxFlagRank[[string]$InputObject.Flag]) { $InputObject.Flag = $sev }
    $whys = @(([string]$InputObject.Why) -split ' \| ' | Where-Object { $_ })
    if ($whys -notcontains $Why) { $InputObject.Why = (@($whys) + $Why) -join ' | ' }
    $tech = @(([string]$InputObject.Technique) -split ', ' | Where-Object { $_ }) + @($Technique | Where-Object { $_ -match '^T\d{4}(?:\.\d{3})?$' })
    $InputObject.Technique = (@($tech | Select-Object -Unique) -join ', ')
    if ($Rule) { $rules = @(([string]$InputObject.Rule) -split ', ' | Where-Object { $_ }); if ($rules -notcontains $Rule) { $InputObject.Rule = (@($rules) + $Rule) -join ', ' } }
}

function Add-WfxFindingVerdict {
    <# Applies analyzer findings to a row (after the allowlist). #>
    param($InputObject, [object[]]$Finding)
    foreach ($f in $Finding) { Add-WfxVerdict -InputObject $InputObject -Severity $f.Severity -Why $f.Title -Technique @($f.Technique) -Rule $f.Id }
}

function Add-WfxFlag {
    <#
    .SYNOPSIS Pipeline step: runs the triage analyzer for a record type over ALL piped records (so cross-record
    rules like parent/child still work) and attaches Flag / Why / Technique to the records the findings are about.
    .PARAMETER Kind Process | Network | Dns | Autostart | Activity | Artifact
    .PARAMETER DnsMap  IP → names, for network records (connections to tunnels / AI APIs).
    #>
    param(
        [Parameter(Mandatory, Position = 0)][ValidateSet('Process', 'Network', 'Dns', 'Autostart', 'Activity', 'Artifact')][string]$Kind,
        [Parameter(ValueFromPipeline)]$InputObject,
        [hashtable]$DnsMap = @{}
    )
    begin { $all = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $all.Add($InputObject) } }
    end {
        $recs = $all.ToArray()
        foreach ($r in $recs) { foreach ($c in $script:WfxFlagColumns) { if (-not $r.PSObject.Properties[$c]) { $r | Add-Member -NotePropertyName $c -NotePropertyValue '' } } }
        if (-not $recs.Count) { return }
        $findings = @()
        try {
            $findings = switch ($Kind) {
                'Process' { Invoke-WfxProcessAnalyzer -Process $recs }
                'Network' { Invoke-WfxNetworkAnalyzer -Connection $recs -DnsMap $DnsMap }
                'Dns' { Invoke-WfxDnsAnalyzer -DnsEntry $recs }
                'Autostart' { Invoke-WfxPersistenceAnalyzer -Autostart $recs }
                'Activity' { Invoke-WfxActivityAnalyzer -Activity $recs }
                'Artifact' { Invoke-WfxArtifactAnalyzer -Artifacts $recs }
            }
            $findings = @($findings | Expand-WfxRecord)
            $allow = Get-WfxSessionAllowlist
            if (@($allow).Count) { $findings = @((Split-WfxAllowlisted -Finding $findings -Allowlist $allow).Kept) }
        } catch {
            Add-WfxGap -Source "flags:$Kind" -Reason "Suspicious-activity checks could not run: $($_.Exception.Message)" -Fix 'Rows are shown unflagged; run a full triage for the complete analysis.'
            $findings = @()
        }
        # Index findings by the key each record type can be matched on.
        $by = @{}
        $add = { param($k, $f) if (-not $by.ContainsKey($k)) { $by[$k] = New-Object System.Collections.Generic.List[object] }; $by[$k].Add($f) }
        foreach ($f in $findings) {
            $e = [string]$f.Entity
            switch ($Kind) {
                'Process' { if ($e -match '^process:(\d+):') { & $add "pid:$($Matches[1])" $f } }
                'Network' {
                    if ($e -match '^listen:(\d+):') { & $add "listen:$($Matches[1]):$($f.Evidence.Pid)" $f }
                    elseif ($e -match '^conn:(.+):(\d+)$' -and $f.Id -ne 'AI-API-NONBROWSER') { & $add "conn:$($Matches[1]):$($Matches[2])" $f }
                    else { & $add "pid:$($f.Evidence.Pid)" $f }
                }
                'Dns' { if ($e -match '^dns:(.+)$') { & $add "dns:$($Matches[1])" $f } }
                'Autostart' { if ($e -match '^autostart:') { & $add $e.ToLowerInvariant() $f } }
                'Artifact' {
                    $ev = $f.Evidence
                    if ($ev -and $ev.Path) { & $add ('art:' + (ConvertTo-WfxArtifactKey $ev.Path)) $f }
                    if ($ev -and $ev.Source -and $e -match '^shortcut:') { & $add ('src:' + ([string]$ev.Source).ToLowerInvariant()) $f }
                }
                'Activity' {
                    $ev = $f.Evidence
                    # Keyed by action + target (not time): the analyzer dedupes repeats, but every matching row is flagged.
                    if ($f.Source -eq 'activity:burst') { Add-WfxViewPattern -Severity $f.Severity -Text $f.Title -Technique @($f.Technique) }
                    elseif ($ev -and $ev.Action) { & $add ("act:{0}|{1}" -f $ev.Action, [string]$ev.Target) $f }   # Target may be empty (e.g. Defender 5001)
                }
            }
        }
        foreach ($r in $recs) {
            $keys = switch ($Kind) {
                'Process' { "pid:$($r.Pid)" }
                'Network' {
                    if ([string]$r.State -match '^Listen') { "listen:$($r.LocalPort):$($r.Pid)" }
                    else { "conn:$($r.RemoteAddress):$($r.RemotePort)"; "pid:$($r.Pid)" }
                }
                'Dns' { 'dns:' + ([string]$r.Name).Trim('.').ToLowerInvariant() }
                'Autostart' { ("autostart:{0}:{1}" -f $r.Kind, $r.Name).ToLowerInvariant() }
                'Activity' { "act:{0}|{1}" -f $r.Action, [string]$r.Target }
                'Artifact' { 'art:' + (ConvertTo-WfxArtifactKey $r.Path); if ($r.Source) { 'src:' + ([string]$r.Source).ToLowerInvariant() } }
            }
            foreach ($k in @($keys)) { if ($by.ContainsKey($k)) { Add-WfxFindingVerdict -InputObject $r -Finding $by[$k].ToArray() } }
        }
        $recs
    }
}

function ConvertTo-WfxArtifactKey {
    <# Path key that ignores case and the drive / volume prefix, so C:\x, c:\x and (volume)\x match. #>
    param([AllowEmptyString()][string]$Path)
    ([string]$Path).ToLowerInvariant() -replace '^\(volume\)', '' -replace '^[a-z]:', ''
}

function Add-WfxViewPattern {
    <# A finding about many rows at once (e.g. 400 deletions in 10 minutes). Shown above the table. #>
    param([string]$Severity, [string]$Text, [string[]]$Technique = @())
    if ($null -eq $script:WfxViewPatterns) { $script:WfxViewPatterns = New-Object System.Collections.Generic.List[object] }
    $script:WfxViewPatterns.Add([pscustomobject]@{ Severity = $Severity.ToUpperInvariant(); Text = $Text; Technique = (@($Technique) -join ', ') })
}

function Clear-WfxViewPattern { $script:WfxViewPatterns = New-Object System.Collections.Generic.List[object] }
function Get-WfxViewPattern { if ($null -eq $script:WfxViewPatterns) { return } ; $script:WfxViewPatterns.ToArray() }

function Add-WfxCommandVerdict {
    <#
    .SYNOPSIS Flags a row whose command line / script text matches the living-off-the-land rule pack, or whose
    executable sits in a user-writable location. Run on the FULL text, before it is shortened for display.
    .PARAMETER Context  Where the command was found ("scheduled task", "PowerShell history" …) — used in the reason.
    #>
    param([Parameter(Mandatory)]$InputObject, [AllowEmptyString()][string]$Text, [string]$Context = '', [switch]$CheckImagePath)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    $suffix = if ($Context) { " ($Context)" } else { '' }
    try {
        foreach ($r in (Test-WfxCommandLine -CommandLine $Text)) { Add-WfxVerdict -InputObject $InputObject -Severity $r.severity -Why "$($r.title)$suffix" -Technique @(Get-WfxValue $r 'technique' @()) -Rule $r.id }
    } catch { Add-WfxGap -Source 'flags:command' -Reason "Command-line rules unavailable: $($_.Exception.Message)" }
    if ($CheckImagePath) {
        $img = Get-WfxImagePath $Text
        if ($img -and (Test-WfxUserWritablePath $img)) { Add-WfxVerdict -InputObject $InputObject -Severity 'Medium' -Why "Runs a program from a user-writable folder$suffix" -Technique @('T1036.005') }
    }
}

function Test-WfxNameInList {
    <# Executable-name match against a rule-pack list (case-insensitive, with or without .exe). #>
    param([AllowEmptyString()][string]$Name, [object[]]$List)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $n = (Get-WfxLeaf $Name).Trim().ToLowerInvariant(); $nb = $n -replace '\.exe$', ''
    foreach ($x in $List) {
        $l = ([string]$x).Trim().ToLowerInvariant()
        if (-not $l -or $l -match '[\\/]') { continue }
        if ($l -eq $n -or ($l -replace '\.exe$', '') -eq $nb) { return $true }
    }
    $false
}

function Complete-WfxFlagRow {
    <# Ensures Flag / Why / Technique exist on every row and puts them first, so flagged and clean rows line up. #>
    param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.ValueType]) { return $InputObject }
        foreach ($c in $script:WfxFlagColumns) { if (-not $InputObject.PSObject.Properties[$c]) { $InputObject | Add-Member -NotePropertyName $c -NotePropertyValue '' } }
        $o = [ordered]@{ Flag = $InputObject.Flag; Why = $InputObject.Why; Technique = $InputObject.Technique; Rule = $InputObject.Rule }
        foreach ($p in $InputObject.PSObject.Properties) { if ($script:WfxFlagColumns -notcontains $p.Name -and -not $p.Name.StartsWith('_')) { $o[$p.Name] = $p.Value } }
        [pscustomobject]$o
    }
}

function Get-WfxFlagSummary {
    <# "2 HIGH · 1 MEDIUM" for a set of rows ('' when nothing is flagged). #>
    param([object[]]$Rows)
    $g = @($Rows | Where-Object { $_ -and $_.PSObject.Properties['Flag'] -and $_.Flag -and $_.Flag -ne 'INFO' } | Group-Object Flag | Sort-Object { -$script:WfxFlagRank[$_.Name] })
    (@($g | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ' · ')
}
