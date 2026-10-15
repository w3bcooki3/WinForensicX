# Event collector — normalizes Windows events from live logs or from .evtx files (offline/image).
# Both paths produce { Log, Id, TimeCreated, Computer, Message, Fields = @{ ... } }.

$script:WfxEventQuery = @(
    @{ Log = 'Security'; Ids = @(4624, 4625, 4648, 4672, 4720, 4728, 4732, 4756, 4697, 4698, 1102) }
    @{ Log = 'System'; Ids = @(7045, 104, 7030, 7040) }
    @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4104, 4103) }
    @{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 140, 141) }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116, 1117, 5001, 5007) }
    @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1, 3, 7, 8, 11, 13, 22, 23) }
)

function Get-WfxEventData {
    <#
    .SYNOPSIS Collects security-relevant events.
    .PARAMETER EvtxPath  Folder or single .evtx file to analyze offline (an exported log or forensic image).
    .PARAMETER Hours     Live mode: look back this many hours (default 72).
    .PARAMETER MaxPerLog Cap events per log to bound memory on busy servers.
    #>
    param([string]$EvtxPath, [int]$Hours = 72, [int]$MaxPerLog = 20000)
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]

    if ($EvtxPath) {
        $files = if (Test-Path -LiteralPath $EvtxPath -PathType Container) { Get-ChildItem -LiteralPath $EvtxPath -Filter *.evtx -Recurse -ErrorAction SilentlyContinue } else { @(Get-Item -LiteralPath $EvtxPath -ErrorAction SilentlyContinue) }
        foreach ($f in @($files | Where-Object { $_ })) {
            $ids = ($script:WfxEventQuery | ForEach-Object { $_.Ids }) | Sort-Object -Unique
            Invoke-WfxStep "events:evtx:$($f.Name)" {
                Get-WinEvent -FilterHashtable @{ Path = $f.FullName; Id = $ids } -ErrorAction Stop |
                    Select-Object -First $MaxPerLog | ForEach-Object { $out.Add((ConvertTo-WfxEvent $_ $f.BaseName)) }
            }
        }
        return , @($out.ToArray())
    }

    $start = (Get-Date).AddHours(-[Math]::Abs($Hours))
    foreach ($q in $script:WfxEventQuery) {
        Invoke-WfxStep "events:$($q.Log)" {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = $q.Log; Id = $q.Ids; StartTime = $start } -MaxEvents $MaxPerLog -ErrorAction Stop
            foreach ($e in $ev) { $out.Add((ConvertTo-WfxEvent $e $q.Log)) }
        } | Out-Null
        # A missing/disabled log is a visibility gap worth recording, not a hard error.
    }
    , @($out.ToArray())
}

function ConvertTo-WfxEvent {
    param($Event, [string]$Log)
    $fields = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $fields[$d.Name] = [string]$d.'#text' }
        }
    } catch {}
    # Friendly aliases the analyzer uses regardless of schema.
    if (-not $fields.ContainsKey('CommandLine') -and $fields.ContainsKey('ProcessCommandLine')) { $fields['CommandLine'] = $fields['ProcessCommandLine'] }
    if (-not $fields.ContainsKey('ScriptBlockText') -and $Event.Id -eq 4104) { try { $fields['ScriptBlockText'] = $Event.Properties[2].Value } catch {} }
    $msg = ''
    try { $msg = $Event.Message } catch { $msg = '' }
    # Redact secrets in the message and every field value at collection time (4688 command lines and 4104
    # script blocks in particular can carry passwords/keys). Structure and tool names are preserved.
    $msg = Protect-WfxText $msg
    foreach ($fk in @($fields.Keys)) { $fields[$fk] = Protect-WfxText ([string]$fields[$fk]) }
    [pscustomobject]@{
        Log         = $Log
        Id          = [int]$Event.Id
        TimeCreated = $Event.TimeCreated
        Computer    = $Event.MachineName
        Message     = $msg
        Fields      = $fields
    }
}
