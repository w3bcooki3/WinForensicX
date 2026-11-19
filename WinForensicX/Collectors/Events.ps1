# Event collector — normalizes Windows events from live logs or from exported .evtx files.
# Both paths produce { Log, Provider, Id, TimeCreated (UTC ISO), Computer, RecordId, Message, Fields = @{...} }.

# High-volume IDs get their own query (and cap) so they can't crowd rare, high-value events out of the window.
# Msg = $true only where the rendered message is needed: formatting Message text is by far the slowest part
# of reading events (milliseconds each), and high-volume events carry everything we need in their data fields.
$script:WfxEventQuery = @(
    @{ Log = 'Security'; Ids = @(4624, 4625, 4648, 4688); Max = 15000; Msg = $false }
    @{ Log = 'Security'; Ids = @(1102, 4697, 4698, 4720, 4726, 4728, 4732, 4740, 4756); Max = 3000; Msg = $true }
    @{ Log = 'System'; Ids = @(104, 7030, 7040, 7045); Max = 3000; Msg = $true }
    @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4104); Max = 5000; Msg = $false }
    @{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 140, 141, 200); Max = 3000; Msg = $false }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116, 1117, 5001, 5007); Max = 2000; Msg = $true }
    @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1, 3, 4, 7, 8, 10, 11, 13, 16, 22, 23); Max = 15000; Msg = $false }
    @{ Log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149); Max = 2000; Msg = $false }
    # Identity, AD and lateral-movement events (high volume on domain controllers and file servers: own caps).
    @{ Log = 'Security'; Ids = @(4662, 5136); Max = 3000; Msg = $false }
    @{ Log = 'Security'; Ids = @(5145); Max = 5000; Msg = $false }
    @{ Log = 'Security'; Ids = @(4656, 4663, 4703, 4765, 4766, 4794, 4826); Max = 3000; Msg = $false }
    @{ Log = 'System'; Ids = @(7036); Max = 3000; Msg = $false }
    @{ Log = 'Application'; Ids = @(325, 326, 327, 3001, 15281, 15457, 18456, 33205); Max = 3000; Msg = $false }
    @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(2, 6, 12, 17, 18, 19, 20, 21, 25); Max = 10000; Msg = $false }
    @{ Log = 'Microsoft-Windows-Bits-Client/Operational'; Ids = @(59); Max = 1000; Msg = $false }
    @{ Log = 'Microsoft-Windows-Application-Experience/Program-Telemetry'; Ids = @(500); Max = 1000; Msg = $false }
    @{ Log = 'Microsoft-Windows-Winsock-WS2HELP/Operational'; Ids = @(1); Max = 500; Msg = $false }
    @{ Log = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Ids = @(148); Max = 1000; Msg = $false }
)
# Only fields that can carry free text are secret-scrubbed; names, SIDs, IPs, GUIDs and codes cannot.
$script:WfxEventTextFields = @('CommandLine', 'ProcessCommandLine', 'ParentCommandLine', 'ScriptBlockText', 'Payload', 'ContextInfo', 'ImagePath', 'Details', 'TaskContent', 'Path', 'Detection User', 'Param1', 'Param2', 'Param3', 'Data', 'Message', 'url', 'Url')
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
    $out = [System.Collections.Generic.List[object]]::new()

    if ($EvtxFile.Count) {
        $ids = @(@($script:WfxEventQuery) + @($script:WfxSigmaEventQuery | Where-Object { $_ }) | ForEach-Object { $_.Ids } | Sort-Object -Unique)
        foreach ($f in $EvtxFile) {
            $leaf = Get-WfxLeaf $f
            Invoke-WfxStep "events:evtx:$leaf" {
                # On Windows the event API reads the file (it also renders messages). Elsewhere, or when the API
                # cannot open the file (damaged, partly overwritten, carved), the built-in reader is used.
                $viaApi = $false
                if (Test-WfxWindows) {
                    $got = [System.Collections.Generic.List[object]]::new()
                    try {
                        $n = 0
                        for ($i = 0; $i -lt $ids.Count; $i += $script:WfxMaxIdsPerQuery) {
                            $chunk = $ids[$i..([Math]::Min($i + $script:WfxMaxIdsPerQuery, $ids.Count) - 1)]
                            try {
                                Get-WinEvent -FilterHashtable @{ Path = $f; Id = $chunk } -MaxEvents ($MaxPerLog - $n) -ErrorAction Stop |
                                    ForEach-Object { $got.Add((ConvertTo-WfxEvent $_ '' -WithMessage:($_.Id -in 1102, 104, 7045, 1116, 1117, 5001, 5007))); $n++ }
                            } catch { if (-not (Test-WfxNoEventsError $_)) { throw } }
                            if ($n -ge $MaxPerLog) { Add-WfxGap -Source "events:evtx:$leaf" -Reason "Capped at $MaxPerLog events; older events in this file were not analyzed."; break }
                        }
                        $viaApi = $true
                        foreach ($g in $got) { $out.Add($g) }
                    } catch {
                        Add-WfxGap -Source "events:evtx:$leaf" -Reason "The Windows event API could not read this file ($($_.Exception.Message)); it was read with the built-in parser instead (no rendered messages)."
                    }
                }
                if (-not $viaApi) { foreach ($e in (Get-WfxEvtxFileEvent -Path $f -EventId $ids -MaxPerLog $MaxPerLog)) { $out.Add($e) } }
            } | Out-Null
        }
        return $out.ToArray()
    }
    if (-not (Test-WfxWindows)) { return @() }

    $start = (Get-Date).AddHours(-[Math]::Abs($Hours))
    foreach ($q in @(@($script:WfxEventQuery) + @($script:WfxSigmaEventQuery | Where-Object { $_ }))) {
        Invoke-WfxStep "events:$($q.Log):$($q.Ids -join ',')" {
            $ev = $null
            try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $q.Log; Id = $q.Ids; StartTime = $start } -MaxEvents $q.Max -ErrorAction Stop) }
            catch {
                if (Test-WfxNoEventsError $_) { return }        # log exists, nothing matched: that's a result, not a gap
                throw
            }
            foreach ($e in $ev) { $out.Add((ConvertTo-WfxEvent $e $q.Log -WithMessage:$q.Msg)) }
            if ($ev.Count -ge $q.Max) { Add-WfxGap -Source "events:$($q.Log)" -Reason "Capped at $($q.Max) events for IDs $($q.Ids -join ','); the oldest part of the $Hours h window was not collected." -Fix 'Re-run with a smaller -Hours window, or export the log and use -EvtxPath.' }
        } | Out-Null
    }
    $out.ToArray()
}

function Get-WfxEvtxFileEvent {
    <# Events from one .evtx file through the built-in reader (Private/Evtx.ps1), in the collector's event shape, newest $MaxPerLog kept. #>
    param([string]$Path, [int[]]$EventId, [int]$MaxPerLog = 50000)
    $leaf = Get-WfxLeaf $Path
    $recs = [System.Collections.Generic.List[object]]::new()
    $sum = $null
    foreach ($r in (Read-WfxEvtx -Path $Path -EventId $EventId -Recover)) { if ($r.PSObject.Properties['Summary']) { $sum = $r } else { $recs.Add($r) } }
    if ($sum) {
        if (-not $sum.Chunks) { Add-WfxGap -Source "events:evtx:$leaf" -Reason 'No event log chunks found: the file is empty, not an event log, or too damaged to read.' }
        if ($sum.BadRecords) { Add-WfxGap -Source "events:evtx:$leaf" -Reason "$($sum.BadRecords) damaged record(s) could not be read and were skipped." }
        if ($sum.Recovered) { Add-WfxGap -Source "events:evtx:$leaf" -Reason "$($sum.Recovered) older record(s) were recovered from unused space in the file and are included (marked Recovered)." -Fix '' }
    }
    $list = $recs.ToArray()
    if ($list.Count -gt $MaxPerLog) {
        $list = @($list | Sort-Object RecordId | Select-Object -Last $MaxPerLog)
        Add-WfxGap -Source "events:evtx:$leaf" -Reason "Capped at $MaxPerLog events; older events in this file were not analyzed."
    }
    foreach ($r in $list) {
        $e = ConvertTo-WfxEventRecord -Log $r.Log -Provider $r.Provider -Id $r.Id -RecordId $r.RecordId -Time $r.TimeCreated -Computer $r.Computer -Message '' -Fields $r.Fields
        if ($r.Recovered) { $e | Add-Member -NotePropertyName Recovered -NotePropertyValue $true }
        $e
    }
}

function ConvertTo-WfxEvent {
    param($Record, [string]$Log, [switch]$WithMessage)
    $fields = @{}
    try {
        $xml = [xml]$Record.ToXml()
        $i = 0
        foreach ($d in @($xml.Event.EventData.ChildNodes)) {
            if (-not $d -or $d.NodeType -ne 'Element') { continue }
            if ($d.LocalName -eq 'Data') {
                $i++
                $name = [string]$d.GetAttribute('Name')
                if (-not $name) { $name = "Param$i" }        # classic event log strings have no names
                $fields[$name] = [string]$d.InnerText
            } elseif ($d.InnerText) { $fields[$d.LocalName] = [string]$d.InnerText }
        }
        foreach ($d in @($xml.Event.UserData.ChildNodes)) {
            foreach ($c in @($d.ChildNodes)) { if ($c.LocalName) { $fields[$c.LocalName] = [string]$c.InnerText } }
        }
    } catch {}
    if (-not $fields.ContainsKey('ScriptBlockText') -and $Record.Id -eq 4104) { try { $fields['ScriptBlockText'] = [string]$Record.Properties[2].Value } catch {} }
    $msg = ''
    if ($WithMessage) { try { $msg = [string]$Record.Message } catch { $msg = '' } }
    $logName = if ($Record.LogName) { [string]$Record.LogName } else { $Log }
    ConvertTo-WfxEventRecord -Log $logName -Provider ([string]$Record.ProviderName) -Id ([int]$Record.Id) -RecordId ([long]$Record.RecordId) -Time $Record.TimeCreated -Computer ([string]$Record.MachineName) -Message $msg -Fields $fields
}

function ConvertTo-WfxEventRecord {
    <# The collector's event shape, with field aliases and secrets redacted. Shared by the event API path and the built-in reader. #>
    param([string]$Log, [string]$Provider, [int]$Id, [long]$RecordId, $Time, [string]$Computer, [string]$Message, [hashtable]$Fields)
    if (-not $Fields) { $Fields = @{} }
    $fields = $Fields
    # Friendly aliases the analyzer uses regardless of schema.
    if (-not $fields.ContainsKey('CommandLine') -and $fields.ContainsKey('ProcessCommandLine')) { $fields['CommandLine'] = $fields['ProcessCommandLine'] }
    $msg = $Message
    # Redact secrets in the message and every field value at collection time (4688 command lines and 4104
    # script blocks in particular can carry passwords/keys). Structure and tool names are preserved.
    $msg = Protect-WfxText $msg
    if ($msg.Length -gt 8192) { $msg = $msg.Substring(0, 8192) + ' …[truncated]' }
    foreach ($fk in @($fields.Keys)) {
        $v = [string]$fields[$fk]
        if ($v.Length -gt 12 -and ($script:WfxEventTextFields -contains $fk -or $v.Length -gt 200)) { $fields[$fk] = Protect-WfxText $v }
    }
    [pscustomobject]@{
        Log         = $Log
        Provider    = $Provider
        Id          = $Id
        RecordId    = $RecordId
        TimeCreated = ConvertTo-WfxUtcString $Time
        Computer    = $Computer
        Message     = $msg
        Fields      = $fields
    }
}
