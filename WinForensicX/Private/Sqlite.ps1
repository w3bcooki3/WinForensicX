# Minimal read-only SQLite reader: walks table b-trees in a database file held in memory and returns rows.
# Used for browser download history (Chromium "History", Firefox "places.sqlite"). The database is copied
# into memory with read sharing, so the browser keeps running; no SQLite library is loaded or executed.
#
# A write-ahead log next to the database (History-wal, places.sqlite-wal) is applied in memory, committed
# transactions only, so rows the browser has not yet checkpointed into the main file are read too.
# Limits: freed pages are not carved.

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
    param([byte[]]$B, [int]$O, [int]$N, [switch]$Unsigned)
    [long]$v = 0; for ($i = 0; $i -lt $N; $i++) { $v = ($v -shl 8) -bor $B[$O + $i] }
    if (-not $Unsigned -and $N -lt 8 -and $N -gt 0 -and ($B[$O] -band 0x80)) { $v -= ([long]1 -shl (8 * $N)) }   # sign-extend
    $v
}

function Read-WfxSharedFile {
    <# All bytes of a file opened with read/write/delete sharing (the owning program keeps running). $null if unreadable. #>
    param([string]$Path)
    try {
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { $b = New-Object byte[] $fs.Length; $n = 0; while ($n -lt $b.Length) { $r = $fs.Read($b, $n, $b.Length - $n); if ($r -le 0) { break }; $n += $r } } finally { $fs.Dispose() }
        , $b
    } catch { Write-Verbose "open failed: $Path : $($_.Exception.Message)"; $null }
}

function Get-WfxWalChecksum {
    <# SQLite WAL checksum: pairs of 32-bit words (big-endian when $BigEndian), accumulated from $S0/$S1. #>
    param([byte[]]$B, [int]$Off, [int]$Len, [uint32]$S0, [uint32]$S1, [bool]$BigEndian)
    [long]$s0 = $S0; [long]$s1 = $S1
    $end = $Off + $Len
    if ($BigEndian) {
        for ($i = $Off; $i -lt $end; $i += 8) {
            $x0 = ([long]$B[$i] -shl 24) -bor ([long]$B[$i + 1] -shl 16) -bor ([long]$B[$i + 2] -shl 8) -bor $B[$i + 3]
            $x1 = ([long]$B[$i + 4] -shl 24) -bor ([long]$B[$i + 5] -shl 16) -bor ([long]$B[$i + 6] -shl 8) -bor $B[$i + 7]
            $s0 = ($s0 + $x0 + $s1) -band 0xFFFFFFFFL; $s1 = ($s1 + $x1 + $s0) -band 0xFFFFFFFFL
        }
    } else {
        for ($i = $Off; $i -lt $end; $i += 8) {
            $s0 = ($s0 + [long][BitConverter]::ToUInt32($B, $i) + $s1) -band 0xFFFFFFFFL
            $s1 = ($s1 + [long][BitConverter]::ToUInt32($B, $i + 4) + $s0) -band 0xFFFFFFFFL
        }
    }
    , @([uint32]$s0, [uint32]$s1)
}

function Merge-WfxSqliteWal {
    <#
    .SYNOPSIS Applies the committed frames of an SQLite write-ahead log to a copy of the database bytes.
    A frame counts when its salts match the log header and its checksum continues the chain; pages are applied
    up to the last commit frame (later frames for a page win), and the database takes the size that commit
    recorded. Frames of an unfinished transaction, or left from an earlier checkpoint, are ignored.
    .OUTPUTS { Bytes; Frames (applied) }
    #>
    param([byte[]]$Db, [byte[]]$Wal, [int]$PageSize)
    $none = [pscustomobject]@{ Bytes = $Db; Frames = 0 }
    if (-not $Wal -or $Wal.Length -lt 32) { return $none }
    $magic = [uint32](Read-WfxBigEndian $Wal 0 4 -Unsigned)
    if ($magic -ne 0x377f0682L -and $magic -ne 0x377f0683L) { return $none }
    $be = $magic -eq 0x377f0683L
    $ps = [int](Read-WfxBigEndian $Wal 8 4 -Unsigned)
    if ($ps -ne $PageSize) { return $none }
    $salt1 = Read-WfxBigEndian $Wal 16 4 -Unsigned; $salt2 = Read-WfxBigEndian $Wal 20 4 -Unsigned
    $ck = Get-WfxWalChecksum $Wal 0 24 0 0 $be
    if ($ck[0] -ne (Read-WfxBigEndian $Wal 24 4 -Unsigned) -or $ck[1] -ne (Read-WfxBigEndian $Wal 28 4 -Unsigned)) { return $none }
    $commits = [System.Collections.Generic.List[object]]::new()
    $pos = 32; $frame = 24 + $ps
    $cur = [System.Collections.Generic.List[object]]::new()
    while ($pos + $frame -le $Wal.Length) {
        if ((Read-WfxBigEndian $Wal ($pos + 8) 4 -Unsigned) -ne $salt1 -or (Read-WfxBigEndian $Wal ($pos + 12) 4 -Unsigned) -ne $salt2) { break }
        $c1 = Get-WfxWalChecksum $Wal $pos 8 $ck[0] $ck[1] $be
        $c2 = Get-WfxWalChecksum $Wal ($pos + 24) $ps $c1[0] $c1[1] $be
        if ($c2[0] -ne (Read-WfxBigEndian $Wal ($pos + 16) 4 -Unsigned) -or $c2[1] -ne (Read-WfxBigEndian $Wal ($pos + 20) 4 -Unsigned)) { break }
        $ck = $c2
        $cur.Add([long]$pos)
        $dbPages = Read-WfxBigEndian $Wal ($pos + 4) 4 -Unsigned
        if ($dbPages -gt 0) { $commits.Add([pscustomobject]@{ Frames = $cur.ToArray(); Pages = $dbPages }); $cur.Clear() }
        $pos += $frame
    }
    if (-not $commits.Count) { return $none }
    $size = [long]$commits[$commits.Count - 1].Pages * $ps
    if ($size -le 0 -or $size -gt 2GB) { return $none }
    $out = New-Object byte[] $size
    [Array]::Copy($Db, $out, [Math]::Min($Db.Length, $size))
    $n = 0
    foreach ($c in $commits) {
        foreach ($f in $c.Frames) {
            $pg = Read-WfxBigEndian $Wal ([int]$f) 4 -Unsigned
            $dst = ($pg - 1) * $ps
            if ($pg -ge 1 -and $dst + $ps -le $size) { [Array]::Copy($Wal, [int]$f + 24, $out, $dst, $ps); $n++ }
        }
    }
    [pscustomobject]@{ Bytes = $out; Frames = $n }
}

function Open-WfxSqlite {
    <#
    Returns a database handle, or $null when the bytes are not an SQLite 3 database. With -Path, a write-ahead
    log beside the file (<name>-wal) is applied unless -NoWal; WalFrames on the handle says how many pages it gave.
    #>
    param([string]$Path, [byte[]]$Bytes, [byte[]]$WalBytes, [switch]$NoWal)
    if (-not $Bytes) { $Bytes = Read-WfxSharedFile $Path; if (-not $Bytes) { return $null } }
    if ($Bytes.Length -lt 512 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 15) -ne 'SQLite format 3') { return $null }
    $ps = ([int]$Bytes[16] -shl 8) -bor $Bytes[17]; if ($ps -eq 1) { $ps = 65536 }
    $frames = 0
    if (-not $NoWal) {
        if (-not $WalBytes -and $Path -and (Test-Path -LiteralPath "$Path-wal" -PathType Leaf)) { $WalBytes = Read-WfxSharedFile "$Path-wal" }
        if ($WalBytes) { $m = Merge-WfxSqliteWal -Db $Bytes -Wal $WalBytes -PageSize $ps; $Bytes = $m.Bytes; $frames = $m.Frames }
    }
    $enc = [int](Read-WfxBigEndian $Bytes 56 4)
    [pscustomobject]@{ B = $Bytes; PageSize = $ps; Usable = $ps - $Bytes[20]; WalFrames = $frames; Encoding = $(if ($enc -eq 2) { [Text.Encoding]::Unicode } elseif ($enc -eq 3) { [Text.Encoding]::BigEndianUnicode } else { [Text.Encoding]::UTF8 }) }
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
    $d = $hdrLen; $vals = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $types) {
        $val = $null; $n = 0
        switch ($t) {
            0 { } 8 { $val = 0L } 9 { $val = 1L }
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
        elseif ($t -ge 12 -and ($t % 2) -eq 0) { $val = [byte[]]@() }
        $vals.Add($val); $d += $n
    }
    , $vals.ToArray()
}

function Get-WfxSqliteRows {
    <# Every (rowid, values[]) of the table b-tree rooted at a page. Bounded against cycles. #>
    param($Sdb, [long]$RootPage, [int]$Max = 200000)
    $b = $Sdb.B; $out = [System.Collections.Generic.List[object]]::new()
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
    <#
    Root page, column names, declared types and the rowid alias of a table, from sqlite_master. A column is the
    rowid alias when its declared type is exactly INTEGER and it is the primary key, written on the column
    ("id INTEGER NOT NULL PRIMARY KEY") or as the table's single-column key ("PRIMARY KEY (id)").
    #>
    param($Sdb, [string]$Table)
    $def = Get-WfxSqliteRows $Sdb 1 | Expand-WfxRecord | Where-Object { $_.Values[0] -eq 'table' -and $_.Values[1] -ieq $Table } | Select-Object -First 1
    if (-not $def) { return $null }
    $sql = [string]$def.Values[4]
    if ($sql -match '(?i)\)\s*WITHOUT\s+ROWID\s*;?\s*$' -or $sql -match '(?i)^\s*CREATE\s+VIRTUAL\b') { return $null }
    $open = $sql.IndexOf('('); $close = $sql.LastIndexOf(')')
    if ($open -lt 0 -or $close -le $open) { return $null }
    $body = $sql.Substring($open + 1, $close - $open - 1)
    # Split on top-level commas, ignoring commas inside brackets and quotes.
    $cols = New-Object System.Collections.Generic.List[string]; $depth = 0; $cur = ''; $q = [char]0
    foreach ($ch in $body.ToCharArray()) {
        if ($q -ne [char]0) { if ($ch -eq $q) { $q = [char]0 }; $cur += $ch; continue }
        if ($ch -eq '"' -or $ch -eq "'" -or $ch -eq '`') { $q = $ch; $cur += $ch; continue }
        if ($ch -eq '[') { $q = ']'; $cur += $ch; continue }
        if ($ch -eq '(') { $depth++ } elseif ($ch -eq ')') { $depth-- }
        if ($ch -eq ',' -and $depth -eq 0) { $cols.Add($cur); $cur = '' } else { $cur += $ch }
    }
    if ($cur.Trim()) { $cols.Add($cur) }
    $names = @(); $types = @(); $defaults = @(); $pk = -1; $tablePk = $null
    foreach ($c in $cols) {
        $c = $c.Trim()
        if ($c -match '^(?i)(?:CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY\s*\(\s*["`\[]?([^"`\]\s,)]+)["`\]]?\s*(?:ASC|DESC)?\s*\)') { $tablePk = $Matches[1]; continue }
        if ($c -match '^(?i)(?:PRIMARY|UNIQUE|CHECK|FOREIGN|CONSTRAINT)\b') { continue }
        if ($c -match '^\s*"((?:[^"]|"")*)"\s*(.*)$' -or $c -match "^\s*'((?:[^']|'')*)'\s*(.*)$" -or $c -match '^\s*`([^`]*)`\s*(.*)$' -or $c -match '^\s*\[([^\]]*)\]\s*(.*)$' -or $c -match '^\s*(\S+)\s*(.*)$') { $nm = $Matches[1]; $rest = $Matches[2] } else { continue }
        $type = ($rest -replace '(?i)\b(?:CONSTRAINT|PRIMARY|NOT|NULL|UNIQUE|CHECK|DEFAULT|COLLATE|REFERENCES|GENERATED|AS)\b.*$', '').Trim()
        # DEFAULT: rows written before ALTER TABLE ADD COLUMN read the column's default.
        $dv = $null
        if ($rest -match "(?i)\bDEFAULT\s+(?:\(\s*)?([+-]?\d+(?:\.\d+)?(?:e[+-]?\d+)?|'(?:[^']|'')*'|NULL|TRUE|FALSE|X'[0-9a-f]*')") {
            $lit = $Matches[1]
            $dv = if ($lit -match "^'") { $lit.Substring(1, $lit.Length - 2).Replace("''", "'") }
            elseif ($lit -match '(?i)^NULL$') { $null } elseif ($lit -match '(?i)^TRUE$') { 1L } elseif ($lit -match '(?i)^FALSE$') { 0L }
            elseif ($lit -match "(?i)^X'") { $hx = $lit.Substring(2, $lit.Length - 3); [byte[]]@(for ($j = 0; $j + 1 -lt $hx.Length; $j += 2) { [Convert]::ToByte($hx.Substring($j, 2), 16) }) }
            elseif ($lit -match '[.eE]') { [double]::Parse($lit, [Globalization.CultureInfo]::InvariantCulture) } else { [long]$lit }
        }
        $defaults += , $dv
        if ($rest -match '(?i)^INTEGER\b(?:(?!\bDESC\b).)*\bPRIMARY\s+KEY\b' -and $rest -notmatch '(?i)\bPRIMARY\s+KEY\s+DESC\b') { $pk = $names.Count }
        $names += $nm; $types += $type
    }
    if ($pk -lt 0 -and $tablePk) {
        for ($i = 0; $i -lt $names.Count; $i++) { if ($names[$i] -ieq $tablePk -and $types[$i] -ieq 'INTEGER') { $pk = $i } }
    }
    [pscustomobject]@{ Root = [long]$def.Values[3]; Names = $names; Types = $types; Defaults = $defaults; Pk = $pk }
}

function Get-WfxSqliteTable {
    <# Rows of a named table as objects with column names (INTEGER PRIMARY KEY columns take the rowid). #>
    param($Sdb, [Parameter(Mandatory)][string]$Table, [int]$Max = 200000)
    $sc = Get-WfxSqliteSchema $Sdb $Table
    if (-not $sc) { return }
    $names = $sc.Names; $pk = $sc.Pk
    # REAL affinity: SQLite stores whole-number REAL values as integers; give them back as numbers with a fraction part.
    $real = @(for ($i = 0; $i -lt $names.Count; $i++) { [bool]($sc.Types[$i] -match '(?i)REAL|FLOA|DOUB') -and -not ($sc.Types[$i] -match '(?i)INT') })
    foreach ($row in (Get-WfxSqliteRows $Sdb $sc.Root $Max)) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $names.Count; $i++) {
            # Plain assignments: an if-expression would unroll a BLOB (byte[]) into an object array.
            if ($i -eq $pk) { $v = $row.RowId } elseif ($i -lt $row.Values.Count) { $v = $row.Values[$i] } else { $v = $sc.Defaults[$i] }
            if ($real[$i] -and ($v -is [long] -or $v -is [int])) { $v = [double]$v }
            $o[$names[$i]] = $v
        }
        [pscustomobject]$o
    }
}
