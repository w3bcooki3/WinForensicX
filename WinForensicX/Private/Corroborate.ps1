# Corroboration: does anything else on the host independently record what a finding is about?
#
# A finding comes from one source (a running process, an event, an Amcache entry). When other, independent
# sources record the same program (Prefetch says it ran, Sysmon logged its start, a service points at it),
# the finding is far less likely to be noise, and the earliest of those records tells the analyst when the
# program first appeared, even for findings that only describe state seen at collection.
#
# Matching is by full path where both sides have one. A bare file name only matches another bare name or a
# path with that name, and never for common Windows programs (cmd.exe, rundll32.exe...), which appear
# everywhere and would corroborate anything. Every match is recorded with its source and time, so the
# report can show exactly why confidence went up.

$script:WfxCorroborateCommon = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'conhost.exe', 'svchost.exe', 'explorer.exe', 'rundll32.exe', 'regsvr32.exe',
    'wscript.exe', 'cscript.exe', 'mshta.exe', 'msiexec.exe', 'dllhost.exe', 'taskhostw.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
    'smss.exe', 'wininit.exe', 'spoolsv.exe', 'searchindexer.exe', 'runtimebroker.exe', 'sihost.exe', 'ctfmon.exe', 'wmiprvse.exe', 'wevtutil.exe',
    'vssadmin.exe', 'net.exe', 'net1.exe', 'reg.exe', 'sc.exe', 'schtasks.exe', 'netsh.exe', 'whoami.exe', 'certutil.exe', 'bitsadmin.exe',
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'notepad.exe', 'taskmgr.exe', 'mmc.exe', 'wmic.exe', 'curl.exe', 'tar.exe', 'ssh.exe')

function ConvertFrom-WfxEnvPath {
    <# Expands the machine-wide folder variables that UserAssist, Jump Lists and shortcuts store
    (%SystemRoot%\System32\x.exe), so they are compared as the real folder. Per-user variables
    (%TEMP%, %APPDATA%) are left alone because the user is not known. #>
    param([AllowEmptyString()][string]$Path)
    if (-not $Path -or $Path.IndexOf('%') -lt 0) { return $Path }
    $Path -replace '(?i)^%(?:systemroot|windir)%', 'C:\Windows' -replace '(?i)^%systemdrive%', 'C:' `
        -replace '(?i)^%programfiles\(x86\)%', 'C:\Program Files (x86)' -replace '(?i)^%programfiles%', 'C:\Program Files' `
        -replace '(?i)^%programdata%', 'C:\ProgramData' -replace '(?i)^%public%', 'C:\Users\Public'
}

function ConvertTo-WfxCorroborationKey {
    <# Normalised full-path key (no drive, lower case, env vars expanded) and leaf for a path-like value. #>
    param([string]$Value)
    $v = [string]$Value
    if (-not $v) { return $null }
    $v = $v.Trim().Trim('"')
    if ($v -match '^(?:process|file):(?:\d+:)?(.+)$') { $v = $Matches[1] }
    $v = ConvertFrom-WfxEnvPath $v
    $v = $v -replace '^\\\\\?\\', '' -replace '^\\\?\?\\', '' -replace '(?i)^\\systemroot\\', 'c:\windows\'
    $leaf = ($v -split '[\\/]')[-1].ToLowerInvariant()
    if ($leaf -notmatch '\.[a-z0-9]{2,4}$') { return $null }
    $full = if ($v -match '[\\/]') { ($v.ToLowerInvariant() -replace '/', '\' -replace '^\(volume\)', '' -replace '^[a-z]:', '') } else { '' }
    [pscustomobject]@{ Full = $full; Leaf = $leaf }
}

function Get-WfxObservation {
    <# Flattens the collected evidence into { Source; Key; Time; Detail } records, one per program sighting. #>
    param($Bundle, [object[]]$Event = @(), [object[]]$Artifact = @())
    $out = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$Source, [string]$Path, $Time, [string]$Detail)
        $k = ConvertTo-WfxCorroborationKey $Path; if (-not $k) { return }
        $out.Add([pscustomobject]@{ Source = $Source; Key = $k; Time = $(if ($Time) { ConvertTo-WfxUtcString $Time } else { '' }); Detail = $(if ($Detail) { $Detail } else { $Path }) })
    }
    foreach ($a in $Artifact) {
        if (-not $a -or $a.Evidence -notin 'Execution', 'Presence', 'Install', 'Download', 'Detection', 'Access') { continue }
        & $add ([string]$a.Artifact) ([string]$a.Path) $a.Time ("{0}: {1}" -f $(if ($a.TimeKind) { $a.TimeKind } else { 'recorded' }), $a.Path)
    }
    foreach ($e in $Event) {
        $id = ConvertTo-WfxInt (Get-WfxValue $e 'Id' 0); $log = [string](Get-WfxValue $e 'Log' ''); $fl = Get-WfxValue $e 'Fields' $null
        if (-not $fl) { continue }
        $t = Get-WfxValue $e 'TimeCreated' (Get-WfxValue $e 'Time' '')
        $g = { param($n) [string](Get-WfxValue $fl $n '') }
        if ($log -match 'Sysmon') {
            switch ($id) {
                1 { & $add 'Sysmon 1 (process start)' (& $g 'Image') $t ("started: " + (& $g 'Image')) }
                11 { & $add 'Sysmon 11 (file created)' (& $g 'TargetFilename') $t ("created: " + (& $g 'TargetFilename')) }
                6 { & $add 'Sysmon 6 (driver loaded)' (& $g 'ImageLoaded') $t ("loaded: " + (& $g 'ImageLoaded')) }
                3 { & $add 'Sysmon 3 (network)' (& $g 'Image') $t ("connected to " + (& $g 'DestinationIp') + ':' + (& $g 'DestinationPort')) }
            }
        } elseif ($log -eq 'Security' -and $id -eq 4688) { & $add 'Security 4688 (process start)' (& $g 'NewProcessName') $t ("started: " + (& $g 'NewProcessName')) }
        elseif ($log -eq 'System' -and $id -eq 7045) { $ip = Get-WfxImagePath (& $g 'ImagePath'); & $add 'System 7045 (service installed)' $ip $t ("service " + (& $g 'ServiceName') + ': ' + (& $g 'ImagePath')) }
        elseif ($log -match 'Defender' -and $id -in 1116, 1117) { & $add 'Defender detection' (& $g 'Path') $t ((& $g 'Threat Name') + ' ' + (& $g 'Path')) }
    }
    foreach ($p in @(Get-WfxValue $Bundle 'Process' @())) { & $add 'Running process' ([string](Get-WfxValue $p 'Path' '')) (Get-WfxValue $p 'CreateTime' (Get-WfxValue $p 'StartTime' '')) ("PID " + (Get-WfxValue $p 'Pid' '') + ': ' + (Get-WfxValue $p 'Path' '')) }
    foreach ($p in @(Get-WfxValue $Bundle 'Persistence' @())) {
        $path = [string](Get-WfxValue $p 'Path' ''); if (-not $path) { $path = Get-WfxImagePath ([string](Get-WfxValue $p 'Command' '')) }
        & $add ('Autostart (' + [string](Get-WfxValue $p 'Kind' 'entry') + ')') $path $null ([string](Get-WfxValue $p 'Location' $path))
    }
    foreach ($a in @(Get-WfxValue $Bundle 'Activity' @())) {
        if ([string]$a.Category -notmatch 'File|Execution|Software|Service|Driver') { continue }
        & $add ('Change (' + [string]$a.Source + ')') ([string]$a.Target) $a.Time ("{0}: {1}" -f $a.Action, $a.Target)
    }
    , $out.ToArray()
}

function Get-WfxFindingFileKey {
    <# The programs / files a finding is about, as corroboration keys. #>
    param($Finding)
    $keys = New-Object System.Collections.Generic.List[object]
    $ev = $Finding.Evidence
    $vals = New-Object System.Collections.Generic.List[string]
    if ($ev) {
        foreach ($n in 'Path', 'Image', 'NewProcessName', 'TargetFilename', 'File', 'Driver', 'ImageLoaded', 'Target', 'Process') {
            $v = Get-WfxValue $ev $n ''; if ($v -is [string] -and $v) { $vals.Add($v) }
        }
    }
    if ($Finding.Entity -match '^(?:process|file):') { $vals.Add([string]$Finding.Entity) }
    foreach ($v in $vals) {
        $k = ConvertTo-WfxCorroborationKey $v
        if ($k -and -not @($keys | Where-Object { $_.Leaf -eq $k.Leaf -and ($_.Full -eq $k.Full -or -not $k.Full) }).Count) { $keys.Add($k) }
    }
    # Prefer full paths: drop bare names that a full path already covers.
    $full = @($keys | Where-Object Full)
    , @($full + @($keys | Where-Object { -not $_.Full -and $_.Leaf -notin @($full | ForEach-Object Leaf) }))
}

function Add-WfxCorroboration {
    <#
    .SYNOPSIS Adds Corroboration (independent sources that record the same program) to each finding and raises
    confidence one level when two or more independent sources agree. Returns the findings.
    #>
    param([object[]]$Finding, $Bundle, [object[]]$Event = @(), [object[]]$Artifact = @())
    $obs = @(Get-WfxObservation -Bundle $Bundle -Event $Event -Artifact $Artifact | Expand-WfxRecord)
    $byFull = @{}; $byLeaf = @{}
    foreach ($o in $obs) {
        if ($o.Key.Full) { if (-not $byFull.ContainsKey($o.Key.Full)) { $byFull[$o.Key.Full] = New-Object System.Collections.Generic.List[object] }; $byFull[$o.Key.Full].Add($o) }
        if (-not $byLeaf.ContainsKey($o.Key.Leaf)) { $byLeaf[$o.Key.Leaf] = New-Object System.Collections.Generic.List[object] }; $byLeaf[$o.Key.Leaf].Add($o)
    }
    $up = @{ Low = 'Medium'; Medium = 'High' }
    foreach ($f in $Finding) {
        if (-not $f -or (Test-WfxPostureFinding $f) -or $f.Severity -eq 'Info') { continue }
        $own = New-Object System.Collections.Generic.HashSet[string]
        $src = [string]$f.Source
        if ($src -eq 'process') { [void]$own.Add('Running process') }
        if ($src -eq 'persistence') { foreach ($o in $obs) { if ($o.Source -like 'Autostart*') { [void]$own.Add($o.Source) } } }
        if ($src -match '^activity:(.+)$') { [void]$own.Add("Change ($($Matches[1]))") }
        if ($src -match '^evt:') { foreach ($o in $obs) { if ($o.Source -match '^(?:Sysmon|Security|System|Defender)') { [void]$own.Add($o.Source) } } }
        $ev = $f.Evidence
        foreach ($n in 'SeenIn', 'Artifact') { $sv = [string](Get-WfxValue $ev $n ''); foreach ($s in ($sv -split ',\s*')) { if ($s) { [void]$own.Add($s) } } }
        $hits = @{}
        foreach ($k in @(Get-WfxFindingFileKey $f | Expand-WfxRecord)) {
            # Full path: same full path, or a source that records only the name (Prefetch, Defender) when the name is distinctive.
            # Bare name: any record of that name, again only when distinctive.
            $distinct = $k.Leaf -notin $script:WfxCorroborateCommon -and $k.Leaf.Length -ge 6 -and $byLeaf.ContainsKey($k.Leaf)
            $cand = @()
            if ($k.Full -and $byFull.ContainsKey($k.Full)) { $cand += $byFull[$k.Full].ToArray() }
            if ($distinct) { $cand += @($byLeaf[$k.Leaf].ToArray() | Where-Object { -not $k.Full -or -not $_.Key.Full }) }
            # Common Windows programs appear everywhere; for them only a record within minutes of the finding counts.
            $common = $k.Leaf -in $script:WfxCorroborateCommon
            $ft = if ($f.Time) { ConvertTo-WfxDateTime $f.Time } else { $null }
            foreach ($o in $cand) {
                if ($own.Contains($o.Source)) { continue }
                if ($common -and -not ($ft -and $o.Time -and [Math]::Abs(((ConvertTo-WfxDateTime $o.Time) - $ft).TotalMinutes) -le 10)) { continue }
                if (-not $hits.ContainsKey($o.Source)) { $hits[$o.Source] = [pscustomobject]@{ Source = $o.Source; First = $o.Time; Last = $o.Time; Detail = $o.Detail; Count = 0 } }
                $h = $hits[$o.Source]; $h.Count++
                if ($o.Time -and (-not $h.First -or $o.Time -lt $h.First)) { $h.First = $o.Time }
                if ($o.Time -and (-not $h.Last -or $o.Time -gt $h.Last)) { $h.Last = $o.Time }
            }
        }
        if (-not $hits.Count) { continue }
        $list = @($hits.Values | Sort-Object @{ e = { if ($_.First) { $_.First } else { '9999' } } } | Select-Object -First 8)
        $f | Add-Member -NotePropertyName Corroboration -NotePropertyValue $list -Force
        if ($list.Count -ge 2 -and $up.ContainsKey([string]$f.Confidence)) {
            $old = $f.Confidence; $f.Confidence = $up[$old]
            $f.Score = [Math]::Round($script:WfxSeverityWeight[$f.Severity] * $script:WfxConfidenceFactor[$f.Confidence], 1)
            $f | Add-Member -NotePropertyName ConfidenceNote -NotePropertyValue ("Confidence raised from {0} to {1}: {2} independent sources record the same program ({3})." -f $old, $f.Confidence, $list.Count, (@($list | ForEach-Object Source) -join ', ')) -Force
        }
    }
    , @($Finding)
}
