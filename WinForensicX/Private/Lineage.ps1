# Process trees: rebuilds "who started whom" from Sysmon 1 (process GUIDs), Security 4688 (process IDs and
# times) and the live process list, and attaches the ancestry of each process finding.
#
# Process IDs are reused by Windows, so a parent is only accepted when it was started before its child and
# is the most recent process with that ID at that moment. Sysmon's process GUIDs are unique and are used
# when present. Each step records where it came from, so the chain in the report can be checked.

function ConvertFrom-WfxPidValue {
    <# 4688 writes process IDs as hex (0x1a2c); Sysmon and the process list as decimal. #>
    param($Value)
    $s = ([string]$Value).Trim()
    if (-not $s) { return $null }
    if ($s -match '^0x([0-9a-fA-F]+)$') { return [long][Convert]::ToInt64($Matches[1], 16) }
    if ($s -match '^\d+$') { return [long]$s }
    $null
}

function New-WfxProcessGraph {
    <# Builds an index of process starts. Returns { Nodes (List); ByGuid; ByPid (pid -> nodes sorted by start) }. #>
    param([object[]]$Event = @(), [object[]]$Process = @())
    $nodes = [System.Collections.Generic.List[object]]::new()
    $byGuid = @{}; $byPid = @{}; $byLeaf = @{}; $byPidAny = @{}
    $add = {
        param($n)
        $nodes.Add($n)
        if ($n.Guid) { $byGuid[$n.Guid] = $n }
        $lf = if ($n.Image) { ($n.Image -split '\\')[-1].ToLowerInvariant() } else { '' }
        $n | Add-Member -NotePropertyName Leaf -NotePropertyValue $lf
        if ($lf) { if (-not $byLeaf.ContainsKey($lf)) { $byLeaf[$lf] = [System.Collections.Generic.List[object]]::new() }; $byLeaf[$lf].Add($n) }
        if ($null -ne $n.Pid) { if (-not $byPidAny.ContainsKey($n.Pid)) { $byPidAny[$n.Pid] = [System.Collections.Generic.List[object]]::new() }; $byPidAny[$n.Pid].Add($n) }
        if ($null -ne $n.Pid) { $k = "$($n.Computer)|$($n.Pid)"; if (-not $byPid.ContainsKey($k)) { $byPid[$k] = [System.Collections.Generic.List[object]]::new() }; $byPid[$k].Add($n) }
    }
    foreach ($e in $Event) {
        if (-not $e) { continue }
        $id = ConvertTo-WfxInt (Get-WfxValue $e 'Id' 0); $log = [string](Get-WfxValue $e 'Log' '')
        $fl = Get-WfxValue $e 'Fields' $null; if (-not $fl -or $fl -is [string]) { continue }
        $g = { param($n) [string](Get-WfxValue $fl $n '') }
        $comp = [string](Get-WfxValue $e 'Computer' '')
        $t = ConvertTo-WfxDateTime (Get-WfxValue $e 'TimeCreated' $null)
        if ($log -match 'Sysmon' -and $id -eq 1) {
            $ut = & $g 'UtcTime'; if ($ut) { $tt = ConvertTo-WfxDateTime ($ut -replace ' ', 'T' -replace '(\.\d+)?$', '$1Z'); if ($tt) { $t = $tt } }
            & $add ([pscustomobject]@{ Source = 'Sysmon 1'; Computer = $comp; Time = $t; Guid = (& $g 'ProcessGuid'); ParentGuid = (& $g 'ParentProcessGuid')
                    Pid = (ConvertFrom-WfxPidValue (& $g 'ProcessId')); Ppid = (ConvertFrom-WfxPidValue (& $g 'ParentProcessId')); Image = (& $g 'Image'); CommandLine = (& $g 'CommandLine')
                    User = (& $g 'User'); ParentImage = (& $g 'ParentImage'); ParentCommandLine = (& $g 'ParentCommandLine') })
        } elseif ($log -eq 'Security' -and $id -eq 4688) {
            $user = & $g 'SubjectUserName'; $dom = & $g 'SubjectDomainName'; if ($dom -and $user -and $user -notmatch '\$$') { $user = "$dom\$user" }
            & $add ([pscustomobject]@{ Source = 'Security 4688'; Computer = $comp; Time = $t; Guid = ''; ParentGuid = ''
                    Pid = (ConvertFrom-WfxPidValue (& $g 'NewProcessId')); Ppid = (ConvertFrom-WfxPidValue (& $g 'ProcessId')); Image = (& $g 'NewProcessName'); CommandLine = (& $g 'CommandLine')
                    User = $user; ParentImage = (& $g 'ParentProcessName'); ParentCommandLine = '' })
        }
    }
    foreach ($p in $Process) {
        if (-not $p) { continue }
        $pid0 = ConvertFrom-WfxPidValue (Get-WfxValue $p 'Pid' ''); if ($null -eq $pid0) { continue }
        & $add ([pscustomobject]@{ Source = 'Process list'; Computer = ''; Time = (ConvertTo-WfxDateTime (Get-WfxValue $p 'CreateTime' $null)); Guid = ''; ParentGuid = ''
                Pid = $pid0; Ppid = (ConvertFrom-WfxPidValue (Get-WfxValue $p 'Ppid' '')); Image = [string](Get-WfxValue $p 'Path' (Get-WfxValue $p 'Name' '')); CommandLine = [string](Get-WfxValue $p 'CommandLine' '')
                User = [string](Get-WfxValue $p 'User' (Get-WfxValue $p 'Owner' '')); ParentImage = [string](Get-WfxValue $p 'ParentPath' (Get-WfxValue $p 'ParentName' '')); ParentCommandLine = [string](Get-WfxValue $p 'ParentCommandLine' '') })
    }
    foreach ($k in @($byPid.Keys)) { $byPid[$k] = @($byPid[$k] | Sort-Object { if ($_.Time) { $_.Time } else { [datetime]::MinValue } }) }
    [pscustomobject]@{ Nodes = $nodes; ByGuid = $byGuid; ByPid = $byPid; ByLeaf = $byLeaf; ByPidAny = $byPidAny }
}

function Get-WfxProcessParent {
    <# The node that started $Node, or $null. Same source family only, so a 4688 child never borrows a Sysmon parent with a reused ID. #>
    param($Graph, $Node)
    if ($Node.ParentGuid -and $Graph.ByGuid.ContainsKey($Node.ParentGuid)) { return $Graph.ByGuid[$Node.ParentGuid] }
    if ($null -eq $Node.Ppid) { return $null }
    $k = "$($Node.Computer)|$($Node.Ppid)"
    if (-not $Graph.ByPid.ContainsKey($k)) { return $null }
    $best = $null
    foreach ($c in $Graph.ByPid[$k]) {
        if ($c.Source -ne $Node.Source -or [object]::ReferenceEquals($c, $Node)) { continue }
        # Started before the child (a few seconds of clock slack), most recent such process wins.
        if ($Node.Time -and $c.Time -and $c.Time -gt $Node.Time.AddSeconds(2)) { continue }
        if ($Node.Time -and $c.Time -and ($Node.Time - $c.Time).TotalDays -gt 60) { continue }
        $best = $c
    }
    $best
}

function Get-WfxProcessLineage {
    <# Ancestry of $Node, oldest first, ending with $Node. Adds the parent named by the child's own record when the parent's start was not collected. #>
    param($Graph, $Node, [int]$Max = 12)
    $chain = [System.Collections.Generic.List[object]]::new()
    $seen = New-Object System.Collections.Generic.HashSet[object]
    $cur = $Node
    while ($cur -and $chain.Count -lt $Max -and $seen.Add($cur)) {
        $chain.Insert(0, $cur)
        $par = Get-WfxProcessParent -Graph $Graph -Node $cur
        if (-not $par) {
            if ($cur.ParentImage) { $chain.Insert(0, [pscustomobject]@{ Source = "$($cur.Source) (parent named by child)"; Computer = $cur.Computer; Time = $null; Guid = ''; ParentGuid = ''; Pid = $cur.Ppid; Ppid = $null; Image = $cur.ParentImage; CommandLine = $cur.ParentCommandLine; User = ''; ParentImage = ''; ParentCommandLine = '' }) }
            break
        }
        $cur = $par
    }
    , $chain.ToArray()
}

function Find-WfxProcessNode {
    <# The process start a finding is about: by Sysmon GUID, by PID (+ path), or by image path and time. #>
    param($Graph, $Finding)
    $ev = $Finding.Evidence; if (-not $ev) { return $null }
    $gv = { param($n) $v = Get-WfxValue $ev $n ''; if ($v -is [string] -or $v -is [System.ValueType]) { [string]$v } else { '' } }
    $guid = & $gv 'ProcessGuid'
    if ($guid -and $Graph.ByGuid.ContainsKey($guid)) { return $Graph.ByGuid[$guid] }
    $img = & $gv 'Image'; if (-not $img) { $img = & $gv 'NewProcessName' }; if (-not $img) { $img = & $gv 'Path' }
    $t = ConvertTo-WfxDateTime $(if (& $gv 'Time') { & $gv 'Time' } else { $Finding.Time })
    $pidv = ConvertFrom-WfxPidValue (& $gv 'Pid')
    $leaf = if ($img) { ($img -split '\\')[-1].ToLowerInvariant() } else { '' }
    $near = { param($a, $b) $a -and $b -and [Math]::Abs(($a - $b).TotalSeconds) -le 5 }
    $rank = @{ 'Sysmon 1' = 0; 'Security 4688' = 1; 'Process list' = 2 }
    if ($null -ne $pidv) {
        # A process seen running: the process list entry is the process itself. Prefer an event for the same
        # start (same ID, same program, same start time) because it carries the history further back.
        if (-not $Graph.ByPidAny.ContainsKey($pidv)) { return $null }
        $same = @($Graph.ByPidAny[$pidv] | Where-Object { -not $leaf -or -not $_.Leaf -or $_.Leaf -eq $leaf })
        $live = @($same | Where-Object Source -eq 'Process list' | Select-Object -First 1)
        $anchor = if ($live) { $live[0].Time } else { $t }
        $events = @($same | Where-Object { $_.Source -ne 'Process list' -and (& $near $_.Time $anchor) } | Sort-Object { $rank[$_.Source] })
        if ($events) { return $events[0] }
        if ($live) { return $live[0] }
        return $null
    }
    if (-not $leaf -or -not $t -or -not $Graph.ByLeaf.ContainsKey($leaf)) { return $null }
    $cands = @($Graph.ByLeaf[$leaf] | Where-Object { & $near $_.Time $t })
    if (-not $cands.Count) { return $null }
    @($cands | Sort-Object { $rank[$_.Source] }, { [Math]::Abs(($_.Time - $t).TotalSeconds) })[0]
}

function Add-WfxProcessLineage {
    <# Adds Lineage (oldest ancestor first) to findings about a process start, when at least a parent is known. #>
    param([object[]]$Finding, [object[]]$Event = @(), [object[]]$Process = @())
    $graph = New-WfxProcessGraph -Event $Event -Process $Process
    if (-not $graph.Nodes.Count) { return , @($Finding) }
    foreach ($f in $Finding) {
        if (-not $f -or (Test-WfxPostureFinding $f)) { continue }
        $node = Find-WfxProcessNode -Graph $graph -Finding $f
        if (-not $node) { continue }
        $chain = Get-WfxProcessLineage -Graph $graph -Node $node      # returns one wrapped array
        $chain = @($chain)
        if ($chain.Count -lt 2) { continue }
        $f | Add-Member -NotePropertyName Lineage -NotePropertyValue @($chain | ForEach-Object {
                [pscustomobject]@{ Time = $(if ($_.Time) { ConvertTo-WfxUtcString $_.Time } else { '' }); Image = $_.Image; CommandLine = (Protect-WfxText $(if ($_.CommandLine.Length -gt 1000) { $_.CommandLine.Substring(0, 1000) + ' …' } else { $_.CommandLine })); Pid = $_.Pid; User = $_.User; Source = $_.Source }
            }) -Force
    }
    , @($Finding)
}
