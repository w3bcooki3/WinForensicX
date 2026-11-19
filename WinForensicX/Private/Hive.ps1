# Read-only parser for offline Windows registry hive files (regf): SYSTEM, SOFTWARE, NTUSER.DAT,
# UsrClass.dat, Amcache.hve. Pure byte parsing of a copy held in memory: the file is opened for reading
# with sharing, never loaded into the live registry (no "reg load"), and nothing in it is executed.
#
# A "dirty" hive copied from a running system is brought up to date from its transaction logs (.LOG1/.LOG2,
# Windows 8.1 and later format) in memory. Deleted (unallocated) keys are not recovered.

function Open-WfxHive {
    <#
    .SYNOPSIS Opens a regf hive file (or bytes) and returns a handle for Get-WfxHiveKey / Get-WfxHiveValue.
    Returns $null if the data is not a registry hive.
    #>
    param([string]$Path, [byte[]]$Bytes, [switch]$NoLogs)
    if (-not $Bytes) {
        try {
            $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try { $Bytes = New-Object byte[] $fs.Length; $n = 0; while ($n -lt $Bytes.Length) { $r = $fs.Read($Bytes, $n, $Bytes.Length - $n); if ($r -le 0) { break }; $n += $r } } finally { $fs.Dispose() }
        } catch { Write-Verbose "hive open failed: $Path : $($_.Exception.Message)"; return $null }
    }
    if ($Bytes.Length -lt 0x2000 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -ne 'regf') { return $null }
    $seq1 = [BitConverter]::ToUInt32($Bytes, 4); $seq2 = [BitConverter]::ToUInt32($Bytes, 8)
    $replayed = 0
    if ($seq1 -ne $seq2 -and $Path -and -not $NoLogs) {
        # Dirty hive: replay the transaction logs that sit next to it (NAME.LOG1 / NAME.LOG2), if any.
        $dir = Split-Path -Parent $Path; $leaf = Split-Path -Leaf $Path
        $logs = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match ('^' + [regex]::Escape($leaf) + '\.LOG[12]$') } | ForEach-Object FullName)
        if ($logs.Count) { $r = Invoke-WfxHiveLogReplay -Bytes $Bytes -LogPath $logs; $Bytes = $r.Bytes; $replayed = $r.Entries }
        $seq1 = [BitConverter]::ToUInt32($Bytes, 4); $seq2 = [BitConverter]::ToUInt32($Bytes, 8)
    }
    $root = [BitConverter]::ToUInt32($Bytes, 0x24)
    $h = [pscustomobject]@{ Path = $Path; B = $Bytes; Root = [int]$root; Dirty = ($seq1 -ne $seq2); Replayed = $replayed
        LastWrite = (ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($Bytes, 0x0C))) }
    $h
}

function Invoke-WfxHiveLogReplay {
    <#
    .SYNOPSIS Applies new-format (Windows 8.1+, "HvLE") transaction-log entries to an in-memory copy of a
    dirty hive, so writes Windows had not yet flushed into the hive file are not missed. Entries are applied
    in sequence-number order starting at the hive's last complete write; a gap in the sequence stops the
    replay. The original files are never modified. Old-format ("DIRT") logs are not supported.
    #>
    param([byte[]]$Bytes, [string[]]$LogPath)
    $out = New-Object byte[] $Bytes.Length; [Array]::Copy($Bytes, $out, $Bytes.Length)
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($lp in $LogPath) {
        try { $L = [IO.File]::ReadAllBytes($lp) } catch { continue }
        if ($L.Length -lt 1024 -or [Text.Encoding]::ASCII.GetString($L, 0, 4) -ne 'regf') { continue }
        $p = 512
        while ($p + 40 -le $L.Length -and [Text.Encoding]::ASCII.GetString($L, $p, 4) -eq 'HvLE') {
            $size = [BitConverter]::ToUInt32($L, $p + 4); if ($size -lt 40 -or $p + $size -gt $L.Length) { break }
            $entries.Add([pscustomobject]@{ Seq = [BitConverter]::ToUInt32($L, $p + 12); BinSize = [BitConverter]::ToUInt32($L, $p + 16); Count = [BitConverter]::ToUInt32($L, $p + 20); Data = $L; Offset = $p })
            $p += $size
        }
    }
    $expected = [BitConverter]::ToUInt32($out, 8)          # secondary sequence = last complete write
    $applied = 0
    foreach ($e in @($entries | Sort-Object Seq)) {
        if ($e.Seq -lt $expected) { continue }
        if ($e.Seq -ne $expected) { break }
        $need = 0x1000 + [long]$e.BinSize
        if ($need -gt $out.Length -and $need -lt 2GB) { $bigger = New-Object byte[] $need; [Array]::Copy($out, $bigger, $out.Length); $out = $bigger }
        $ref = $e.Offset + 40; $data = $ref + 8 * $e.Count
        for ($i = 0; $i -lt $e.Count; $i++) {
            $po = [BitConverter]::ToUInt32($e.Data, $ref + 8 * $i); $ps = [BitConverter]::ToUInt32($e.Data, $ref + 8 * $i + 4)
            $dst = 0x1000 + [long]$po
            if ($dst + $ps -le $out.Length -and $data + $ps -le $e.Data.Length) { [Array]::Copy($e.Data, $data, $out, $dst, $ps) }
            $data += $ps
        }
        $expected++; $applied++
    }
    if ($applied) {
        [Array]::Copy([BitConverter]::GetBytes([uint32]$expected), 0, $out, 4, 4); [Array]::Copy([BitConverter]::GetBytes([uint32]$expected), 0, $out, 8, 4)
    }
    [pscustomobject]@{ Bytes = $out; Entries = $applied }
}

function ConvertFrom-WfxFileTime {
    param([long]$Value)
    if ($Value -le 0 -or $Value -gt 2650467743999999999) { return $null }   # 0 or after year 9999
    try { [DateTime]::FromFileTimeUtc($Value) } catch { $null }
}

function Get-WfxHiveCell {
    # Absolute offset of a cell's data (after its 4-byte size), or -1 when the offset is out of range.
    param($Hive, [long]$Offset)
    if ($Offset -lt 0 -or $Offset -eq 0xFFFFFFFFL) { return -1 }
    $abs = 0x1000 + $Offset + 4
    if ($abs + 4 -gt $Hive.B.Length) { return -1 }
    $abs
}

function Get-WfxHiveNode {
    <# Parses the nk (key) cell at a hive offset. #>
    param($Hive, [long]$Offset)
    $b = $Hive.B; $o = Get-WfxHiveCell $Hive $Offset
    if ($o -lt 0 -or $o + 0x4C -gt $b.Length -or $b[$o] -ne 0x6E -or $b[$o + 1] -ne 0x6B) { return $null }   # 'nk'
    $flags = [BitConverter]::ToUInt16($b, $o + 2)
    $nl = [BitConverter]::ToUInt16($b, $o + 0x48)
    if ($o + 0x4C + $nl -gt $b.Length) { return $null }
    $name = if ($flags -band 0x20) { [Text.Encoding]::GetEncoding(28591).GetString($b, $o + 0x4C, $nl) } else { [Text.Encoding]::Unicode.GetString($b, $o + 0x4C, $nl) }
    [pscustomobject]@{
        Offset     = $Offset
        Name       = $name
        LastWrite  = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($b, $o + 4))
        SubCount   = [BitConverter]::ToUInt32($b, $o + 0x14)
        SubList    = [BitConverter]::ToUInt32($b, $o + 0x1C)
        ValueCount = [BitConverter]::ToUInt32($b, $o + 0x24)
        ValueList  = [BitConverter]::ToUInt32($b, $o + 0x28)
    }
}

function Get-WfxHiveSubkeyOffsets {
    param($Hive, [long]$ListOffset, [int]$Depth = 0)
    $b = $Hive.B; $o = Get-WfxHiveCell $Hive $ListOffset
    if ($o -lt 0 -or $Depth -gt 4 -or $o + 4 -gt $b.Length) { return }
    $sig = [Text.Encoding]::ASCII.GetString($b, $o, 2); $n = [BitConverter]::ToUInt16($b, $o + 2)
    switch ($sig) {
        { $_ -in 'lf', 'lh' } { for ($i = 0; $i -lt $n -and $o + 4 + $i * 8 + 4 -le $b.Length; $i++) { [BitConverter]::ToUInt32($b, $o + 4 + $i * 8) } }
        'li' { for ($i = 0; $i -lt $n -and $o + 4 + $i * 4 + 4 -le $b.Length; $i++) { [BitConverter]::ToUInt32($b, $o + 4 + $i * 4) } }
        'ri' { for ($i = 0; $i -lt $n -and $o + 4 + $i * 4 + 4 -le $b.Length; $i++) { Get-WfxHiveSubkeyOffsets $Hive ([BitConverter]::ToUInt32($b, $o + 4 + $i * 4)) ($Depth + 1) } }
    }
}

function Get-WfxHiveSubkey {
    <# Child keys of a node (nk objects). #>
    param($Hive, $Node)
    if (-not $Node -or $Node.SubCount -eq 0) { return }
    foreach ($off in @(Get-WfxHiveSubkeyOffsets $Hive $Node.SubList)) { $k = Get-WfxHiveNode $Hive $off; if ($k) { $k } }
}

function Get-WfxHiveKey {
    <#
    .SYNOPSIS Returns the key node at a backslash path below the hive root (case-insensitive), or $null.
    "" or "\" returns the root. A first segment that names the root key itself is skipped.
    #>
    param($Hive, [string]$KeyPath = '')
    $node = Get-WfxHiveNode $Hive $Hive.Root
    if (-not $node) { return $null }
    foreach ($part in @($KeyPath -split '\\' | Where-Object { $_ })) {
        $next = $null
        foreach ($k in @(Get-WfxHiveSubkey $Hive $node)) { if ($k.Name -ieq $part) { $next = $k; break } }
        if (-not $next) { return $null }
        $node = $next
    }
    $node
}

function Get-WfxHiveValue {
    <#
    .SYNOPSIS Values of a key node: Name, Type (REG_*), Data (string / string[] / int / long / byte[]).
    .PARAMETER Name Return only this value ('' or '(default)' for the default value).
    #>
    param($Hive, $Node, [string]$Name, [switch]$IncludeRaw)
    if (-not $Node -or $Node.ValueCount -eq 0) { return }
    $b = $Hive.B; $lo = Get-WfxHiveCell $Hive $Node.ValueList
    if ($lo -lt 0) { return }
    $want = if ($PSBoundParameters.ContainsKey('Name')) { if ($Name -eq '(default)') { '' } else { $Name } } else { $null }
    for ($i = 0; $i -lt $Node.ValueCount -and $lo + $i * 4 + 4 -le $b.Length; $i++) {
        $vo = Get-WfxHiveCell $Hive ([BitConverter]::ToUInt32($b, $lo + $i * 4))
        if ($vo -lt 0 -or $vo + 0x14 -gt $b.Length -or $b[$vo] -ne 0x76 -or $b[$vo + 1] -ne 0x6B) { continue }   # 'vk'
        $nl = [BitConverter]::ToUInt16($b, $vo + 2); $vflags = [BitConverter]::ToUInt16($b, $vo + 0x10)
        if ($vo + 0x14 + $nl -gt $b.Length) { continue }
        $vname = if ($nl -eq 0) { '' } elseif ($vflags -band 1) { [Text.Encoding]::GetEncoding(28591).GetString($b, $vo + 0x14, $nl) } else { [Text.Encoding]::Unicode.GetString($b, $vo + 0x14, $nl) }
        if ($null -ne $want -and $vname -ine $want) { continue }
        $size = [BitConverter]::ToUInt32($b, $vo + 4); $doff = [BitConverter]::ToUInt32($b, $vo + 8); $type = [BitConverter]::ToUInt32($b, $vo + 0xC)
        $raw = Get-WfxHiveData $Hive $size $doff
        $v = [pscustomobject]@{ Name = $vname; Type = (ConvertTo-WfxRegTypeName $type); Data = (ConvertFrom-WfxRegData $type $raw) }
        if ($IncludeRaw) { $v | Add-Member -NotePropertyName Raw -NotePropertyValue $raw; $v | Add-Member -NotePropertyName TypeId -NotePropertyValue $type }
        $v
        if ($null -ne $want) { return }
    }
}

function Get-WfxHiveData {
    param($Hive, [uint32]$Size, [uint32]$Offset)
    $b = $Hive.B
    if ($Size -band 0x80000000L) {                       # data stored inside the offset field (<= 4 bytes)
        $len = [int]($Size -band 0x7FFFFFFF); if ($len -gt 4) { $len = 4 }
        $out = New-Object byte[] $len; [Array]::Copy([BitConverter]::GetBytes($Offset), 0, $out, 0, $len)
        return , $out
    }
    if ($Size -eq 0) { return , ([byte[]]@()) }
    $o = Get-WfxHiveCell $Hive $Offset
    if ($o -lt 0) { return , ([byte[]]@()) }
    if ($Size -gt 16344 -and $o + 8 -le $b.Length -and $b[$o] -eq 0x64 -and $b[$o + 1] -eq 0x62) {   # 'db' big data
        $segs = [BitConverter]::ToUInt16($b, $o + 2); $lst = Get-WfxHiveCell $Hive ([BitConverter]::ToUInt32($b, $o + 4))
        $ms = New-Object IO.MemoryStream
        for ($i = 0; $i -lt $segs -and $lst -ge 0 -and $lst + $i * 4 + 4 -le $b.Length; $i++) {
            $so = Get-WfxHiveCell $Hive ([BitConverter]::ToUInt32($b, $lst + $i * 4)); if ($so -lt 0) { break }
            $take = [Math]::Min(16344, [int]$Size - [int]$ms.Length); if ($take -le 0) { break }
            $take = [Math]::Min($take, $b.Length - $so); $ms.Write($b, $so, $take)
        }
        return , $ms.ToArray()
    }
    $len = [Math]::Min([int]$Size, $b.Length - $o)
    $out = New-Object byte[] $len; [Array]::Copy($b, $o, $out, 0, $len)
    , $out
}

function ConvertTo-WfxRegTypeName {
    param([uint32]$Type)
    switch ($Type) { 0 { 'REG_NONE' } 1 { 'REG_SZ' } 2 { 'REG_EXPAND_SZ' } 3 { 'REG_BINARY' } 4 { 'REG_DWORD' } 5 { 'REG_DWORD_BIG_ENDIAN' } 7 { 'REG_MULTI_SZ' } 11 { 'REG_QWORD' } default { "REG_$Type" } }
}

function ConvertFrom-WfxRegData {
    param([uint32]$Type, $Raw)
    $r = [byte[]]@($Raw)
    switch ($Type) {
        { $_ -in 1, 2 } {
            # A string ends at its first NUL, as Windows reads it; bytes after that (slack or hidden data) are not part of it.
            $s = [Text.Encoding]::Unicode.GetString($r, 0, $r.Length - ($r.Length % 2)); $z = $s.IndexOf([char]0)
            return $(if ($z -ge 0) { $s.Substring(0, $z) } else { $s })
        }
        7 { return , @(([Text.Encoding]::Unicode.GetString($r, 0, $r.Length - ($r.Length % 2))) -split "`0" | Where-Object { $_ }) }
        4 { if ($r.Length -ge 4) { return [BitConverter]::ToUInt32($r, 0) } else { return $null } }
        11 { if ($r.Length -ge 8) { return [BitConverter]::ToUInt64($r, 0) } else { return $null } }
        default { return , $r }
    }
}

function Get-WfxHiveTree {
    <# Walks keys below a node breadth-first (bounded) and emits @{ Path; Node }. #>
    param($Hive, $Node, [string]$Prefix = '', [int]$MaxKeys = 200000)
    $q = New-Object System.Collections.Generic.Queue[object]; $q.Enqueue(@($Node, $Prefix)); $n = 0
    while ($q.Count -and $n -lt $MaxKeys) {
        $item = $q.Dequeue(); $n++
        [pscustomobject]@{ Path = $item[1]; Node = $item[0] }
        foreach ($k in @(Get-WfxHiveSubkey $Hive $item[0])) { $q.Enqueue(@($k, $(if ($item[1]) { "$($item[1])\$($k.Name)" } else { $k.Name }))) }
    }
}

function Get-WfxHiveKind {
    <# Identifies a hive by its contents: SYSTEM, SOFTWARE, NTUSER, USRCLASS, AMCACHE, SAM, SECURITY or UNKNOWN. #>
    param($Hive)
    $top = @(Get-WfxHiveSubkey $Hive (Get-WfxHiveNode $Hive $Hive.Root) | ForEach-Object Name)
    if ($top -contains 'Select' -and ($top -match '^ControlSet00\d$')) { return 'SYSTEM' }
    if ($top -contains 'Root' -and ((Get-WfxHiveKey $Hive 'Root\InventoryApplicationFile') -or (Get-WfxHiveKey $Hive 'Root\File'))) { return 'AMCACHE' }
    if ($top -contains 'Local Settings') { return 'USRCLASS' }
    if ($top -contains 'Microsoft' -and $top -contains 'Classes' -and $top -contains 'Policies' -and -not ($top -contains 'Environment')) { return 'SOFTWARE' }
    if ($top -contains 'Software' -and ($top -contains 'Environment' -or $top -contains 'Control Panel')) { return 'NTUSER' }
    if ($top -contains 'SAM') { return 'SAM' }
    if ($top -contains 'Policy') { return 'SECURITY' }
    'UNKNOWN'
}
