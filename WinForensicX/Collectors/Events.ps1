# Event collector — normalizes Windows events from live logs or from exported .evtx files.
# Both paths produce { Log, Provider, Id, TimeCreated (UTC ISO), Computer, RecordId, Message, Fields = @{...} }.

# High-volume IDs get their own query (and cap) so they can't crowd rare, high-value events out of the window.
$script:WfxEventQuery = @(
    @{ Log = 'Security'; Ids = @(4624, 4625, 4648, 4688); Max = 30000 }
    @{ Log = 'Security'; Ids = @(1102, 4697, 4698, 4720, 4728, 4732, 4740, 4756); Max = 5000 }
    @{ Log = 'System'; Ids = @(104, 7030, 7040, 7045); Max = 5000 }
    @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4103, 4104); Max = 20000 }
    @{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 140, 141, 200); Max = 5000 }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116, 1117, 5001, 5007); Max = 5000 }
    @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1, 3, 7, 8, 10, 11, 13, 22, 23); Max = 30000 }
    @{ Log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149); Max = 5000 }
)
# Get-WinEvent rejects FilterHashtable queries with too many Id values; keep each query well under the limit.
$script:WfxMaxIdsPerQuery = 20

function Test-WfxNoEventsError {
    param($ErrorRecord)
    return ([string]$ErrorRecord.FullyQualifiedErrorId -like 'NoMatchingEventsFound*')
}

function Get-WfxEventData {
    <#
    .SYNOPSIS Collects security-relevant events from live logs, or from .evtx files when -EvtxFile is given.
    .PARAMETER EvtxFile  One or more exported .evtx files (offline / dead-box analysis).
    .PARAMETER Hours     Live mode: look back this many hours (default 72).
    .PARAMETER MaxPerLog Cap per .evtx file (offline). Live queries have per-query caps. Hitting a cap is a gap.
    #>
    param([string[]]$EvtxFile = @(), [int]$Hours = 72, [int]$MaxPerLog = 50000)
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]

    if ($EvtxFile.Count) {
        $ids = @($script:WfxEventQuery | ForEach-Object { $_.Ids } | Sort-Object -Unique)
        foreach ($f in $EvtxFile) {
            $leaf = Get-WfxLeaf $f
            Invoke-WfxStep "events:evtx:$leaf" {
                $n = 0
                for ($i = 0; $i -lt $ids.Count; $i += $script:WfxMaxIdsPerQuery) {
                    $chunk = $ids[$i..([Math]::Min($i + $script:WfxMaxIdsPerQuery, $ids.Count) - 1)]
                    try {
                        Get-WinEvent -FilterHashtable @{ Path = $f; Id = $chunk } -MaxEvents ($MaxPerLog - $n) -ErrorAction Stop |
                            ForEach-Object { $out.Add((ConvertTo-WfxEvent $_ '')); $n++ }
                    } catch { if (-not (Test-WfxNoEventsError $_)) { throw } }
                    if ($n -ge $MaxPerLog) { Add-WfxGap -Source "events:evtx:$leaf" -Reason "Capped at $MaxPerLog events; older events in this file were not analyzed."; break }
                }
            } | Out-Null
        }
        return , @($out.ToArray())
    }

    $start = (Get-Date).AddHours(-[Math]::Abs($Hours))
    foreach ($q in $script:WfxEventQuery) {
        Invoke-WfxStep "events:$($q.Log):$($q.Ids -join ',')" {
            $ev = $null
            try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $q.Log; Id = $q.Ids; StartTime = $start } -MaxEvents $q.Max -ErrorAction Stop) }
            catch {
                if (Test-WfxNoEventsError $_) { return }        # log exists, nothing matched: that's a result, not a gap
                throw
            }
            foreach ($e in $ev) { $out.Add((ConvertTo-WfxEvent $e $q.Log)) }
            if ($ev.Count -ge $q.Max) { Add-WfxGap -Source "events:$($q.Log)" -Reason "Capped at $($q.Max) events for IDs $($q.Ids -join ','); the oldest part of the $Hours h window was not collected." -Fix 'Re-run with a smaller -Hours window, or export the log and use -EvtxPath.' }
        } | Out-Null
    }
    , @($out.ToArray())
}

function ConvertTo-WfxEvent {
    param($Record, [string]$Log)
    $fields = @{}
    try {
        $xml = [xml]$Record.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) {
            if ($d -and $d.Name) { $fields[$d.Name] = [string]$d.'#text' }
        }
        foreach ($d in @($xml.Event.UserData.ChildNodes)) {
            foreach ($c in @($d.ChildNodes)) { if ($c.LocalName) { $fields[$c.LocalName] = [string]$c.InnerText } }
        }
    } catch {}
    # Friendly aliases the analyzer uses regardless of schema.
    if (-not $fields.ContainsKey('CommandLine') -and $fields.ContainsKey('ProcessCommandLine')) { $fields['CommandLine'] = $fields['ProcessCommandLine'] }
    if (-not $fields.ContainsKey('ScriptBlockText') -and $Record.Id -eq 4104) { try { $fields['ScriptBlockText'] = [string]$Record.Properties[2].Value } catch {} }
    $msg = ''
    try { $msg = [string]$Record.Message } catch { $msg = '' }
    # Redact secrets in the message and every field value at collection time (4688 command lines and 4104
    # script blocks in particular can carry passwords/keys). Structure and tool names are preserved.
    $msg = Protect-WfxText $msg
    if ($msg.Length -gt 8192) { $msg = $msg.Substring(0, 8192) + ' …[truncated]' }
    foreach ($fk in @($fields.Keys)) { $fields[$fk] = Protect-WfxText ([string]$fields[$fk]) }
    $logName = if ($Record.LogName) { [string]$Record.LogName } else { $Log }
    [pscustomobject]@{
        Log         = $logName
        Provider    = [string]$Record.ProviderName
        Id          = [int]$Record.Id
        RecordId    = [long]$Record.RecordId
        TimeCreated = ConvertTo-WfxUtcString $Record.TimeCreated
        Computer    = [string]$Record.MachineName
        Message     = $msg
        Fields      = $fields
    }
}
