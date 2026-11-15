# Extensible Storage Engine (ESE / "JET Blue") database reader, from the documented on-disk format: pages,
# page tags, B+ trees, the MSysObjects catalog, the record format (fixed, variable and tagged columns), long
# values and the 7-bit and XPRESS compression ESE uses for small values. Read-only, plain PowerShell; it is
# used for SRUM (SRUDB.dat), and works on any ESE file copied off a system.

function Open-WfxEse {
    <# Opens an ESE database copy. Returns { B; PageSize; Small; Tables (name -> table) }. #>
    param([string]$Path = '', [byte[]]$Bytes = $null)
    # Assigned directly (never returned through the pipeline, which would unroll the array into boxed bytes).
    [byte[]]$b = $Bytes
    if (-not $b) {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            if ($fs.Length -gt 2GB) { throw 'ESE database larger than 2 GB.' }
            $b = New-Object byte[] $fs.Length; $o = 0
            while ($o -lt $b.Length) { $k = $fs.Read($b, $o, $b.Length - $o); if ($k -le 0) { break }; $o += $k }
        } finally { $fs.Dispose() }
    }
    if ($b.Length -lt 4096 -or [BitConverter]::ToUInt32($b, 4) -ne 0x89ABCDEFL) { throw 'Not an ESE database (no 0x89ABCDEF signature).' }
    $ps = [int][BitConverter]::ToUInt32($b, 236)
    if ($ps -notin 2048, 4096, 8192, 16384, 32768) { throw "Unsupported ESE page size: $ps" }
    $db = [pscustomobject]@{ B = $b; PageSize = $ps; Small = ($ps -le 8192); Pages = [int][Math]::Floor($b.Length / $ps) - 1; Tables = @{}; State = [BitConverter]::ToUInt32($b, 52) }
    Read-WfxEseCatalog $db
    $db
}

function Get-WfxEsePage {
    <# Page header and tag reader for page $Pgno. Returns $null if the page is outside the file. #>
    param($Db, [long]$Pgno)
    if ($Pgno -lt 1 -or $Pgno -gt $Db.Pages) { return $null }
    $base = ($Pgno + 1) * $Db.PageSize
    $b = $Db.B
    $hdr = if ($Db.Small) { 40 } else { 80 }
    $state = [BitConverter]::ToUInt16($b, $base + 34)
    [pscustomobject]@{
        Num = $Pgno; Base = $base; Data = $base + $hdr; Prev = [BitConverter]::ToUInt32($b, $base + 16); Next = [BitConverter]::ToUInt32($b, $base + 20)
        Flags = [BitConverter]::ToUInt32($b, $base + 36); TagCount = ($state -band 0x0FFF); Reserved = [Math]::Max(1, ($state -shr 12))
    }
}

function Get-WfxEseTag {
    <# Tag $I of $Page: { Off (absolute); Size; Flags (1 version, 2 deleted, 4 compressed key) }. #>
    param($Db, $Page, [int]$I)
    $b = $Db.B
    $t = $Page.Base + $Db.PageSize - 4 * ($I + 1)
    $cb = [BitConverter]::ToUInt16($b, $t); $ib = [BitConverter]::ToUInt16($b, $t + 2)
    if ($Db.Small) { $size = $cb -band 0x1FFF; $off = $ib -band 0x1FFF; $fl = $ib -shr 13 }
    else { $size = $cb -band 0x7FFF; $off = $ib -band 0x7FFF; $fl = 0 }
    $abs = $Page.Data + $off
    if ($abs + $size -gt $Page.Base + $Db.PageSize) { return $null }
    if (-not $Db.Small -and $size -ge 2) { $fl = $b[$abs + 1] -shr 5 }
    [pscustomobject]@{ Off = $abs; Size = $size; Flags = $fl }
}

function Get-WfxEseNode {
    <# Node (key + data) from tag $I. Keys can share a prefix with the page's tag 0 ("compressed" key). #>
    param($Db, $Page, [int]$I, [byte[]]$Prefix)
    $t = Get-WfxEseTag $Db $Page $I
    if (-not $t -or $t.Size -lt 2) { return $null }
    $b = $Db.B; $o = $t.Off; $end = $t.Off + $t.Size
    $pre = 0
    if ($t.Flags -band 4) { $pre = [BitConverter]::ToUInt16($b, $o) -band 0x1FFF; $o += 2 }
    if ($o + 2 -gt $end) { return $null }
    $ks = [BitConverter]::ToUInt16($b, $o) -band 0x1FFF; $o += 2
    if ($o + $ks -gt $end) { return $null }
    $key = New-Object byte[] ($pre + $ks)
    if ($pre) { [Array]::Copy($Prefix, 0, $key, 0, [Math]::Min($pre, $Prefix.Length)) }
    [Array]::Copy($b, $o, $key, $pre, $ks); $o += $ks
    [pscustomobject]@{ Key = $key; Off = $o; Len = ($end - $o); Deleted = [bool]($t.Flags -band 2) }
}

function Get-WfxEseLeaf {
    <# Every live leaf node of the B+ tree rooted at $Root, in key order. #>
    param($Db, [long]$Root)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[long]
    $stack = New-Object System.Collections.Generic.Stack[long]
    $stack.Push($Root)
    while ($stack.Count) {
        $pg = $stack.Pop()
        if (-not $seen.Add($pg) -or $seen.Count -gt 2000000) { continue }
        $p = Get-WfxEsePage $Db $pg; if (-not $p) { continue }
        $prefix = [byte[]]@()
        $t0 = Get-WfxEseTag $Db $p 0
        if ($t0 -and $t0.Size) { $prefix = New-Object byte[] $t0.Size; [Array]::Copy($Db.B, $t0.Off, $prefix, 0, $t0.Size) }
        $leaf = [bool]($p.Flags -band 2)
        $children = New-Object System.Collections.Generic.List[long]
        for ($i = $p.Reserved; $i -lt $p.TagCount; $i++) {
            $n = Get-WfxEseNode $Db $p $i $prefix
            if (-not $n) { continue }
            if ($leaf) { if (-not $n.Deleted) { $out.Add($n) } }
            elseif ($n.Len -ge 4) { $children.Add([BitConverter]::ToUInt32($Db.B, $n.Off)) }
        }
        for ($i = $children.Count - 1; $i -ge 0; $i--) { $stack.Push($children[$i]) }   # keep key order
    }
    , $out.ToArray()
}

$script:WfxEseFixedSize = @{ 1 = 1; 2 = 1; 3 = 2; 4 = 4; 5 = 8; 6 = 4; 7 = 8; 8 = 8; 14 = 4; 15 = 8; 16 = 16; 17 = 2 }

function Read-WfxEseCatalog {
    <# Reads MSysObjects (root page 4): tables, their columns and long-value trees. #>
    param($Db)
    $cat = [pscustomobject]@{ Name = 'MSysObjects'; Root = 4; Columns = @{}; Fixed = @{}; Lv = 0 }
    $defs = @(@(1, 'ObjidTable', 4), @(2, 'Type', 3), @(3, 'Id', 4), @(4, 'ColtypOrPgnoFDP', 4), @(5, 'SpaceUsage', 4), @(6, 'Flags', 4), @(7, 'PagesOrLocale', 4), @(8, 'RootFlag', 1), @(9, 'RecordOffset', 3), @(10, 'LCMapFlags', 4), @(11, 'KeyMost', 17), @(12, 'LVChunkMax', 4))
    $off = 0
    foreach ($d in $defs) { $sz = $script:WfxEseFixedSize[$d[2]]; $cat.Columns[$d[0]] = [pscustomobject]@{ Id = $d[0]; Name = $d[1]; Type = $d[2]; Size = $sz; Offset = $off; Codepage = 0 }; $off += $sz }
    $cat.Columns[128] = [pscustomobject]@{ Id = 128; Name = 'Name'; Type = 10; Size = 0; Offset = 0; Codepage = 1252 }
    $cur = $null
    foreach ($n in (Get-WfxEseLeaf $Db 4)) {
        $r = ConvertFrom-WfxEseRecord $Db $cat $n
        if (-not $r -or $null -eq $r.Type) { continue }
        switch ([int]$r.Type) {
            1 { $cur = [pscustomobject]@{ Name = [string]$r.Name; Root = [long]$r.ColtypOrPgnoFDP; Columns = @{}; Lv = 0; LvCache = $null; NextFixed = 0 }; $Db.Tables[$cur.Name] = $cur }
            2 {
                if (-not $cur) { break }
                $type = [int]$r.ColtypOrPgnoFDP; $id = [int]$r.Id
                $size = if ($r.SpaceUsage) { [int]$r.SpaceUsage } elseif ($script:WfxEseFixedSize.ContainsKey($type)) { $script:WfxEseFixedSize[$type] } else { 0 }
                $col = [pscustomobject]@{ Id = $id; Name = [string]$r.Name; Type = $type; Size = $size; Offset = 0; Codepage = [int]$r.PagesOrLocale }
                if ($id -le 127) { $col.Offset = $cur.NextFixed; $cur.NextFixed += $size }
                $cur.Columns[$id] = $col
            }
            4 { if ($cur) { $cur.Lv = [long]$r.ColtypOrPgnoFDP } }
        }
    }
}

function ConvertFrom-WfxEseValue {
    <# Typed value from raw column bytes. #>
    param([byte[]]$V, $Col)
    if ($null -eq $V) { return $null }
    $n = $V.Length
    switch ($Col.Type) {
        1 { if ($n) { return [bool]($V[0] -ne 0) } }
        2 { if ($n) { return $V[0] } }
        3 { if ($n -ge 2) { return [BitConverter]::ToInt16($V, 0) } }
        4 { if ($n -ge 4) { return [BitConverter]::ToInt32($V, 0) } }
        5 { if ($n -ge 8) { return [BitConverter]::ToInt64($V, 0) } }
        6 { if ($n -ge 4) { return [BitConverter]::ToSingle($V, 0) } }
        7 { if ($n -ge 8) { return [BitConverter]::ToDouble($V, 0) } }
        8 { if ($n -ge 8) { $d = [BitConverter]::ToDouble($V, 0); if ($d -gt -657435 -and $d -lt 2958466) { return [DateTime]::SpecifyKind([DateTime]::FromOADate($d), 'Utc') } ; return $null } }
        { $_ -in 10, 12 } { if ($Col.Codepage -eq 1200) { return [Text.Encoding]::Unicode.GetString($V, 0, $n - ($n % 2)).TrimEnd([char]0) } else { return [Text.Encoding]::GetEncoding(1252).GetString($V).TrimEnd([char]0) } }
        14 { if ($n -ge 4) { return [BitConverter]::ToUInt32($V, 0) } }
        15 { if ($n -ge 8) { return [BitConverter]::ToInt64($V, 0) } }
        16 { if ($n -ge 16) { $g = New-Object byte[] 16; [Array]::Copy($V, $g, 16); return [guid]::new($g) } }
        17 { if ($n -ge 2) { return [BitConverter]::ToUInt16($V, 0) } }
        default { return , $V }
    }
    $null
}

function Expand-WfxEseCompressed {
    <# ESE value compression: first byte >> 3 = scheme (1 = 7-bit ASCII, 2 = 7-bit UTF-16, 3 = XPRESS). #>
    param([byte[]]$V)
    if (-not $V -or $V.Length -lt 2) { return , $V }
    $scheme = $V[0] -shr 3
    if ($scheme -eq 1 -or $scheme -eq 2) {
        $wide = $scheme -eq 2
        $out = New-Object System.Collections.Generic.List[byte]
        $val = 0; $shift = 0
        for ($i = 1; $i -lt $V.Length; $i++) {
            $val = $val -bor ([int]$V[$i] -shl $shift)
            $out.Add([byte]($val -band 0x7F)); if ($wide) { $out.Add(0) }
            $val = $val -shr 7; $shift++
            if ($shift -eq 7) { $out.Add([byte]($val -band 0x7F)); if ($wide) { $out.Add(0) }; $val = $val -shr 7; $shift = 0 }
        }
        # Padding in the last byte can decode to one extra NUL character; text never contains NULs, so drop it.
        $unit = if ($wide) { 2 } else { 1 }
        while ($out.Count -ge $unit -and $out[$out.Count - 1] -eq 0 -and $out[$out.Count - $unit] -eq 0) { $out.RemoveRange($out.Count - $unit, $unit) }
        return , $out.ToArray()
    }
    if ($scheme -eq 3 -and $V.Length -ge 3) { return , (Expand-WfxXpress -Src $V -Start 3) }
    , $V
}

function Expand-WfxXpress {
    <# Plain LZ77 "LZXPRESS" decompression ([MS-XCA] 2.3). #>
    param([byte[]]$Src, [int]$Start = 0, [int]$Max = 16777216)
    $dst = New-Object System.Collections.Generic.List[byte]
    $i = $Start; $n = $Src.Length; $flags = 0; $count = 0; $half = -1
    while ($i -lt $n -and $dst.Count -lt $Max) {
        if ($count -eq 0) { if ($i + 4 -gt $n) { break }; $flags = [BitConverter]::ToUInt32($Src, $i); $i += 4; $count = 32 }
        $count--
        if (-not ($flags -band ([uint32]1 -shl $count))) { $dst.Add($Src[$i]); $i++; continue }
        if ($i -ge $n) { break }
        if ($i + 2 -gt $n) { break }
        $m = [BitConverter]::ToUInt16($Src, $i); $i += 2
        $len = $m -band 7; $off = ($m -shr 3) + 1
        if ($len -eq 7) {
            if ($half -lt 0) { if ($i -ge $n) { break }; $len = $Src[$i] -band 0x0F; $half = $i; $i++ }
            else { $len = $Src[$half] -shr 4; $half = -1 }
            if ($len -eq 15) {
                if ($i -ge $n) { break }
                $len = $Src[$i]; $i++
                if ($len -eq 255) { if ($i + 2 -gt $n) { break }; $len = [BitConverter]::ToUInt16($Src, $i); $i += 2; if ($len -eq 0) { if ($i + 4 -gt $n) { break }; $len = [BitConverter]::ToUInt32($Src, $i); $i += 4 }; if ($len -lt 22) { break }; $len -= 22 }
                $len += 15
            }
            $len += 7
        }
        $len += 3
        if ($off -gt $dst.Count) { break }
        $from = $dst.Count - $off
        for ($k = 0; $k -lt $len; $k++) { $dst.Add($dst[$from + $k]) }
    }
    , $dst.ToArray()
}

function Get-WfxEseLongValue {
    <# Assembles a long value (stored in the table's separate LV tree) from its 4-byte id. #>
    param($Db, $Table, [byte[]]$Id)
    if (-not $Table.Lv -or $Id.Length -lt 4) { return $null }
    if (-not $Table.LvCache) {
        $cache = @{}
        foreach ($n in (Get-WfxEseLeaf $Db $Table.Lv)) {
            if ($n.Key.Length -lt 4) { continue }
            $lid = [BitConverter]::ToString($n.Key, 0, 4)
            if (-not $cache.ContainsKey($lid)) { $cache[$lid] = [pscustomobject]@{ Size = -1; Chunks = New-Object System.Collections.Generic.List[object] } }
            if ($n.Key.Length -eq 4) { if ($n.Len -ge 8) { $cache[$lid].Size = [BitConverter]::ToUInt32($Db.B, $n.Off + 4) } }
            elseif ($n.Key.Length -ge 8) {
                $o = ([long]$n.Key[4] -shl 24) -bor ([long]$n.Key[5] -shl 16) -bor ([long]$n.Key[6] -shl 8) -bor [long]$n.Key[7]
                $d = New-Object byte[] $n.Len; [Array]::Copy($Db.B, $n.Off, $d, 0, $n.Len)
                $cache[$lid].Chunks.Add([pscustomobject]@{ Offset = $o; Data = $d })
            }
        }
        $Table.LvCache = $cache
    }
    $rid = [byte[]]@($Id[3], $Id[2], $Id[1], $Id[0])
    $k = [BitConverter]::ToString($rid)
    if (-not $Table.LvCache.ContainsKey($k)) { return $null }
    $lv = $Table.LvCache[$k]
    $chunks = @($lv.Chunks | Sort-Object Offset)
    $out = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt $chunks.Count; $i++) {
        $next = if ($i + 1 -lt $chunks.Count) { $chunks[$i + 1].Offset } elseif ($lv.Size -ge 0) { $lv.Size } else { $chunks[$i].Offset + $chunks[$i].Data.Length }
        $d = $chunks[$i].Data
        if ($d.Length -ne ($next - $chunks[$i].Offset)) { $d = Expand-WfxEseCompressed $d }    # a chunk shorter than its span is compressed
        $out.AddRange([byte[]]$d)
    }
    , $out.ToArray()
}

function ConvertFrom-WfxEseRecord {
    <# Decodes one leaf node as a record of $Table. Returns a hashtable column-name -> value. $Want (column-id -> 1) limits decoding to those columns. #>
    param($Db, $Table, $Node, [hashtable]$Want = $null)
    $b = $Db.B; $o = $Node.Off; $len = $Node.Len
    if ($len -lt 4) { return $null }
    $lastFixed = $b[$o]; $lastVar = $b[$o + 1]; $varOff = [BitConverter]::ToUInt16($b, $o + 2)
    if ($varOff -gt $len) { return $null }
    $rec = @{}
    $bitmap = $varOff - [int][Math]::Floor(($lastFixed + 7) / 8)
    foreach ($c in $Table.Columns.Values) {
        if ($c.Id -gt 127 -or $c.Id -gt $lastFixed -or ($Want -and -not $Want.ContainsKey($c.Id))) { continue }
        $bi = $c.Id - 1
        if ($bitmap + [Math]::Floor($bi / 8) -lt $len -and ($b[$o + $bitmap + [Math]::Floor($bi / 8)] -band (1 -shl ($bi % 8)))) { continue }
        $s = 4 + $c.Offset
        if ($s + $c.Size -gt $len -or $c.Size -le 0) { continue }
        $v = New-Object byte[] $c.Size; [Array]::Copy($b, $o + $s, $v, 0, $c.Size)
        $rec[$c.Name] = ConvertFrom-WfxEseValue $v $c
    }
    $nVar = $lastVar - 127
    $varData = $varOff + 2 * [Math]::Max(0, $nVar)
    $tagStart = $varData
    if ($nVar -gt 0 -and $varData -le $len) {
        $prev = 0
        for ($i = 0; $i -lt $nVar; $i++) {
            $e = [BitConverter]::ToUInt16($b, $o + $varOff + 2 * $i)
            $end = $e -band 0x7FFF
            $id = 128 + $i
            if (-not ($e -band 0x8000) -and $Table.Columns.ContainsKey($id) -and (-not $Want -or $Want.ContainsKey($id)) -and $varData + $end -le $len -and $end -ge $prev) {
                $v = New-Object byte[] ($end - $prev); [Array]::Copy($b, $o + $varData + $prev, $v, 0, $end - $prev)
                $rec[$Table.Columns[$id].Name] = ConvertFrom-WfxEseValue $v $Table.Columns[$id]
            }
            $prev = $end
        }
        $tagStart = $varData + $prev
    }
    # Tagged columns: an array of (column id, offset) pairs, then the data.
    if ($tagStart + 4 -le $len) {
        $first = [BitConverter]::ToUInt16($b, $o + $tagStart + 2)
        $cnt = [int][Math]::Floor(($(if ($Db.Small) { $first -band 0x1FFF } else { $first -band 0x7FFF })) / 4)
        $fields = for ($i = 0; $i -lt $cnt -and $tagStart + 4 * $i + 4 -le $len; $i++) {
            $tid = [BitConverter]::ToUInt16($b, $o + $tagStart + 4 * $i); $raw = [BitConverter]::ToUInt16($b, $o + $tagStart + 4 * $i + 2)
            if ($Db.Small) { [pscustomobject]@{ Id = $tid; Off = ($raw -band 0x1FFF); Ext = [bool]($raw -band 0x4000); Null = [bool]($raw -band 0x2000) } }
            else { [pscustomobject]@{ Id = $tid; Off = ($raw -band 0x7FFF); Ext = $true; Null = $false } }
        }
        $fields = @($fields)
        for ($i = 0; $i -lt $fields.Count; $i++) {
            $f = $fields[$i]
            if (-not $Table.Columns.ContainsKey([int]$f.Id) -or $f.Null -or ($Want -and -not $Want.ContainsKey([int]$f.Id))) { continue }
            $col = $Table.Columns[[int]$f.Id]
            $s = $tagStart + $f.Off; $e = if ($i + 1 -lt $fields.Count) { $tagStart + $fields[$i + 1].Off } else { $len }
            if ($s -ge $e -or $e -gt $len) { continue }
            $flags = 0
            if ($f.Ext) { $flags = $b[$o + $s]; $s++ }
            if (-not $Db.Small -and ($flags -band 0x20)) { continue }
            $v = New-Object byte[] ($e - $s); [Array]::Copy($b, $o + $s, $v, 0, $e - $s)
            if ($flags -band 0x08) {
                # multi-value: keep the first value
                if ($flags -band 0x10) { if ($v.Length -gt 1) { $l1 = [Math]::Min($v[0], $v.Length - 1); $t = New-Object byte[] $l1; [Array]::Copy($v, 1, $t, 0, $l1); $v = $t } }
                elseif ($v.Length -ge 2) { $f1 = [BitConverter]::ToUInt16($v, 0) -band 0x7FFF; $e1 = if ($f1 -ge 4) { [BitConverter]::ToUInt16($v, 2) -band 0x7FFF } else { $v.Length }; if ($f1 -le $e1 -and $e1 -le $v.Length) { $t = New-Object byte[] ($e1 - $f1); [Array]::Copy($v, $f1, $t, 0, $e1 - $f1); $v = $t } }
            }
            if ($flags -band 0x04) { $v = Get-WfxEseLongValue $Db $Table $v }
            elseif ($flags -band 0x02) { $v = Expand-WfxEseCompressed $v }
            if ($null -ne $v) { $rec[$col.Name] = ConvertFrom-WfxEseValue ([byte[]]$v) $col }
        }
    }
    $rec
}

function Get-WfxEseTable {
    <# All records of a table, as hashtables. -Column limits decoding to the named columns (faster on big tables). #>
    param($Db, [string]$Name, [int]$Max = 2000000, [string[]]$Column = @())
    if (-not $Db.Tables.ContainsKey($Name)) { return }
    $t = $Db.Tables[$Name]; $k = 0
    $want = $null
    if ($Column.Count) { $want = @{}; foreach ($c in $t.Columns.Values) { if ($Column -contains $c.Name) { $want[[int]$c.Id] = 1 } } }
    foreach ($n in (Get-WfxEseLeaf $Db $t.Root)) {
        if (++$k -gt $Max) { break }
        $r = ConvertFrom-WfxEseRecord $Db $t $n $want
        if ($r) { $r }
    }
}
