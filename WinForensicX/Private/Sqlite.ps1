# Minimal read-only SQLite reader: walks table b-trees in a database file held in memory and returns rows.
# Used for browser download history (Chromium "History", Firefox "places.sqlite"). The database is copied
# into memory with read sharing, so the browser keeps running; no SQLite library is loaded or executed.
#
# Limits: rows still in the write-ahead log (History-wal) are not read; freed pages are not carved.

function Read-WfxSqliteVarint {
    param([byte[]]$B, [int]$O)
    [long]$v = 0
    for ($i = 0; $i -lt 9; $i++) {
        if ($O + $i -ge $B.Length) { break }
        $c = $B[$O + $i]
        if ($i -eq 8) { $v = ($v -shl 8) -bor $c; return @($v, 9) }
        $v = ($v -shl 7) -bor ($c -band 0x7F)
        if (-not ($c -band 0x80)) { return @($v, ($i + 1)) }
    }
    @($v, 9)
}

function Read-WfxBigEndian {
    param([byte[]]$B, [int]$O, [int]$N)
    [long]$v = 0; for ($i = 0; $i -lt $N; $i++) { $v = ($v -shl 8) -bor $B[$O + $i] }
    if ($N -lt 8 -and $N -gt 0 -and ($B[$O] -band 0x80)) { $v -= ([long]1 -shl (8 * $N)) }   # sign-extend
    $v
}

function Open-WfxSqlite {
    <# Returns a database handle, or $null when the bytes are not an SQLite 3 database. #>
    param([string]$Path, [byte[]]$Bytes)
    if (-not $Bytes) {
        try {
            $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try { $Bytes = New-Object byte[] $fs.Length; $n = 0; while ($n -lt $Bytes.Length) { $r = $fs.Read($Bytes, $n, $Bytes.Length - $n); if ($r -le 0) { break }; $n += $r } } finally { $fs.Dispose() }
        } catch { Write-Verbose "sqlite open failed: $Path : $($_.Exception.Message)"; return $null }
    }
    if ($Bytes.Length -lt 512 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 15) -ne 'SQLite format 3') { return $null }
    $ps = ([int]$Bytes[16] -shl 8) -bor $Bytes[17]; if ($ps -eq 1) { $ps = 65536 }
    $enc = [int](Read-WfxBigEndian $Bytes 56 4)
    [pscustomobject]@{ B = $Bytes; PageSize = $ps; Usable = $ps - $Bytes[20]; Encoding = $(if ($enc -eq 2) { [Text.Encoding]::Unicode } elseif ($enc -eq 3) { [Text.Encoding]::BigEndianUnicode } else { [Text.Encoding]::UTF8 }) }
}

function Get-WfxSqlitePayload {
    # Full record payload of a leaf cell, following overflow pages.
    param($Sdb, [int]$O, [long]$P)
    $b = $Sdb.B; $U = $Sdb.Usable; $X = $U - 35
    if ($P -le $X) { $out = New-Object byte[] $P; [Array]::Copy($b, $O, $out, 0, [Math]::Min($P, $b.Length - $O)); return , $out }
    $M = [int][Math]::Floor((($U - 12) * 32 / 255)) - 23
    $K = $M + (($P - $M) % ($U - 4)); $local = if ($K -le $X) { $K } else { $M }
    $ms = New-Object IO.MemoryStream; $ms.Write($b, $O, [Math]::Min($local, $b.Length - $O))
    $next = [long](Read-WfxBigEndian $b ($O + $local) 4) -band 0xFFFFFFFFL; $guard = 0
    while ($next -gt 0 -and $ms.Length -lt $P -and $guard++ -lt 100000) {
        $po = ($next - 1) * $Sdb.PageSize; if ($po + 4 -gt $b.Length) { break }
        $take = [int][Math]::Min($U - 4, $P - $ms.Length); $take = [Math]::Min($take, $b.Length - $po - 4)
        $ms.Write($b, [int]$po + 4, $take)
        $next = [long](Read-WfxBigEndian $b ([int]$po) 4) -band 0xFFFFFFFFL
    }
    , $ms.ToArray()
}

function ConvertFrom-WfxSqliteRecord {
    param($Sdb, [byte[]]$R)
    $h = Read-WfxSqliteVarint $R 0; $hdrLen = [int]$h[0]; $p = [int]$h[1]
    $types = New-Object System.Collections.Generic.List[long]
    while ($p -lt $hdrLen -and $p -lt $R.Length) { $v = Read-WfxSqliteVarint $R $p; $types.Add($v[0]); $p += $v[1] }
    $d = $hdrLen; $vals = New-Object System.Collections.Generic.List[object]
    foreach ($t in $types) {
        $val = $null; $n = 0
        switch ($t) {
            0 { } 8 { $val = 0 } 9 { $val = 1 }
            1 { $n = 1 } 2 { $n = 2 } 3 { $n = 3 } 4 { $n = 4 } 5 { $n = 6 } 6 { $n = 8 }
            7 { $n = 8 }
            default { $n = if ($t -ge 12) { [int][Math]::Floor(($t - 12) / 2) } else { 0 } }
        }
        if ($n -gt 0 -and $d + $n -le $R.Length) {
            if ($t -ge 1 -and $t -le 6) { $val = Read-WfxBigEndian $R $d $n }
            elseif ($t -eq 7) { $tmp = New-Object byte[] 8; [Array]::Copy($R, $d, $tmp, 0, 8); [Array]::Reverse($tmp); $val = [BitConverter]::ToDouble($tmp, 0) }
            elseif ($t -ge 13 -and ($t % 2) -eq 1) { $val = $Sdb.Encoding.GetString($R, $d, $n) }
            else { $tmp = New-Object byte[] $n; [Array]::Copy($R, $d, $tmp, 0, $n); $val = $tmp }
        } elseif ($t -ge 13 -and ($t % 2) -eq 1) { $val = '' }
        $vals.Add($val); $d += $n
    }
    , $vals.ToArray()
}

function Get-WfxSqliteRows {
    <# Every (rowid, values[]) of the table b-tree rooted at a page. Bounded against cycles. #>
    param($Sdb, [long]$RootPage, [int]$Max = 200000)
    $b = $Sdb.B; $out = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[long]; $stack.Push($RootPage); $visited = @{}
    while ($stack.Count -and $out.Count -lt $Max) {
        $pg = $stack.Pop(); if ($visited.ContainsKey($pg) -or $pg -lt 1) { continue }; $visited[$pg] = $true
        $base = ($pg - 1) * $Sdb.PageSize; $h = if ($pg -eq 1) { $base + 100 } else { $base }
        if ($h + 8 -gt $b.Length) { continue }
        $type = $b[$h]; $cells = [int](Read-WfxBigEndian $b ($h + 3) 2) -band 0xFFFF
        if ($type -eq 0x05) {
            $hl = 12; $stack.Push(([long](Read-WfxBigEndian $b ($h + 8) 4) -band 0xFFFFFFFFL))
            for ($i = $cells - 1; $i -ge 0; $i--) { $co = $base + ((Read-WfxBigEndian $b ($h + $hl + 2 * $i) 2) -band 0xFFFF); if ($co + 4 -le $b.Length) { $stack.Push(([long](Read-WfxBigEndian $b ([int]$co) 4) -band 0xFFFFFFFFL)) } }
        } elseif ($type -eq 0x0D) {
            for ($i = 0; $i -lt $cells; $i++) {
                $co = [int]($base + ((Read-WfxBigEndian $b ($h + 8 + 2 * $i) 2) -band 0xFFFF)); if ($co -ge $b.Length) { continue }
                $ps = Read-WfxSqliteVarint $b $co; $rid = Read-WfxSqliteVarint $b ($co + $ps[1])
                $payload = Get-WfxSqlitePayload $Sdb ($co + $ps[1] + $rid[1]) $ps[0]
                $out.Add([pscustomobject]@{ RowId = $rid[0]; Values = (ConvertFrom-WfxSqliteRecord $Sdb $payload) })
            }
        }
    }
    , $out.ToArray()
}

function Find-WfxSqliteRow {
    <# One row of a table b-tree by rowid (B-tree descent, so a large table is not scanned). Returns values[] or $null. #>
    param($Sdb, [long]$RootPage, [long]$RowId)
    $b = $Sdb.B; $pg = $RootPage; $guard = 0
    while ($pg -ge 1 -and $guard++ -lt 64) {
        $base = ($pg - 1) * $Sdb.PageSize; $h = if ($pg -eq 1) { $base + 100 } else { $base }
        if ($h + 8 -gt $b.Length) { return $null }
        $type = $b[$h]; $cells = [int](Read-WfxBigEndian $b ($h + 3) 2) -band 0xFFFF
        if ($type -eq 0x05) {
            $next = [long](Read-WfxBigEndian $b ($h + 8) 4) -band 0xFFFFFFFFL
            for ($i = 0; $i -lt $cells; $i++) {
                $co = [int]($base + ((Read-WfxBigEndian $b ($h + 12 + 2 * $i) 2) -band 0xFFFF))
                $key = (Read-WfxSqliteVarint $b ($co + 4))[0]
                if ($RowId -le $key) { $next = [long](Read-WfxBigEndian $b $co 4) -band 0xFFFFFFFFL; break }
            }
            $pg = $next
        } elseif ($type -eq 0x0D) {
            for ($i = 0; $i -lt $cells; $i++) {
                $co = [int]($base + ((Read-WfxBigEndian $b ($h + 8 + 2 * $i) 2) -band 0xFFFF))
                $ps = Read-WfxSqliteVarint $b $co; $rid = Read-WfxSqliteVarint $b ($co + $ps[1])
                if ($rid[0] -eq $RowId) { return , (ConvertFrom-WfxSqliteRecord $Sdb (Get-WfxSqlitePayload $Sdb ($co + $ps[1] + $rid[1]) $ps[0])) }
            }
            return $null
        } else { return $null }
    }
    $null
}

function Get-WfxSqliteSchema {
    <# Root page and column names (INTEGER PRIMARY KEY index) of a table, from sqlite_master. #>
    param($Sdb, [string]$Table)
    $def = Get-WfxSqliteRows $Sdb 1 | Expand-WfxRecord | Where-Object { $_.Values[0] -eq 'table' -and $_.Values[1] -ieq $Table } | Select-Object -First 1
    if (-not $def) { return $null }
    $sql = [string]$def.Values[4]
    $body = $sql.Substring($sql.IndexOf('(') + 1); $body = $body.Substring(0, $body.LastIndexOf(')'))
    $cols = New-Object System.Collections.Generic.List[string]; $depth = 0; $cur = ''
    foreach ($ch in $body.ToCharArray()) { if ($ch -eq '(') { $depth++ } elseif ($ch -eq ')') { $depth-- }; if ($ch -eq ',' -and $depth -eq 0) { $cols.Add($cur); $cur = '' } else { $cur += $ch } }
    if ($cur) { $cols.Add($cur) }
    $names = @(); $pk = -1
    foreach ($c in $cols) {
        $c = $c.Trim(); if ($c -match '^(?i)(?:PRIMARY|UNIQUE|CHECK|FOREIGN|CONSTRAINT)\b') { continue }
        $nm = ($c -split '\s+')[0].Trim('"', '`', '[', ']')
        if ($c -match '(?i)\bINTEGER\s+PRIMARY\s+KEY\b') { $pk = $names.Count }
        $names += $nm
    }
    [pscustomobject]@{ Root = [long]$def.Values[3]; Names = $names; Pk = $pk }
}

function Get-WfxSqliteTable {
    <# Rows of a named table as objects with column names (INTEGER PRIMARY KEY columns take the rowid). #>
    param($Sdb, [Parameter(Mandatory)][string]$Table, [int]$Max = 200000)
    $sc = Get-WfxSqliteSchema $Sdb $Table
    if (-not $sc) { return }
    $names = $sc.Names; $pk = $sc.Pk
    foreach ($row in (Get-WfxSqliteRows $Sdb $sc.Root $Max)) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = if ($i -eq $pk) { $row.RowId } elseif ($i -lt $row.Values.Count) { $row.Values[$i] } else { $null } }
        [pscustomobject]$o
    }
}
