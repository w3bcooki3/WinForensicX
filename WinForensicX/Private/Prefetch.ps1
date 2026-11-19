# Prefetch (.pf) reader, written from the format documentation (libscca, MS-XCA). Versions 17 (XP, 2003),
# 23 (Vista, 7), 26 (8, 8.1), 30 (10) and 31 (11). Windows 10 and later compress the file ("MAM" header,
# XPRESS Huffman); that is decompressed here in plain PowerShell.
#
# What a prefetch file records: the executable name, how many times it ran, the last run time (the last eight
# from Windows 8 on), the volumes it ran from (device path, serial number, creation time) and the files it
# loaded in its first seconds (DLLs, data files, and often the full path of the executable itself).

function Expand-WfxXpressHuffman {
    <#
    .SYNOPSIS Decompresses LZ77+Huffman data (MS-XCA 2.2, "XPRESS Huffman") into a buffer of $OutSize bytes.
    The input is a sequence of blocks, each a 256-byte table of 4-bit code lengths for 512 symbols followed by
    bit-packed symbols that produce up to 64 KB of output.
    #>
    param([Parameter(Mandatory)][byte[]]$In, [int]$Start = 0, [Parameter(Mandatory)][int]$OutSize)
    if ($OutSize -lt 0 -or $OutSize -gt 64MB) { throw "Implausible uncompressed size $OutSize" }
    $out = New-Object byte[] $OutSize
    $inLen = $In.Length
    $ip = $Start; $op = 0
    $len = New-Object int[] 512
    $table = New-Object int[] 32768
    while ($op -lt $OutSize) {
        if ($ip + 256 + 4 -gt $inLen) { throw "Compressed data ends early (block table at $ip)" }
        for ($i = 0; $i -lt 256; $i++) { $b = $In[$ip + $i]; $len[2 * $i] = $b -band 0x0F; $len[2 * $i + 1] = $b -shr 4 }
        $ip += 256
        # Canonical code: shorter codes first, then by symbol value. Each code of length L fills 2^(15-L) entries.
        $e = 0
        for ($bl = 1; $bl -le 15; $bl++) {
            $cnt = 1 -shl (15 - $bl)
            for ($s = 0; $s -lt 512; $s++) {
                if ($len[$s] -ne $bl) { continue }
                if ($e + $cnt -gt 32768) { throw 'Invalid Huffman table (over-subscribed)' }
                for ($k = 0; $k -lt $cnt; $k++) { $table[$e + $k] = $s }
                $e += $cnt
            }
        }
        if ($e -ne 32768) { throw 'Invalid Huffman table (incomplete)' }
        # Bits are read most significant first from little-endian 16-bit words; 32 bits are kept ready.
        $bits = ([long]([int]$In[$ip] -bor ([int]$In[$ip + 1] -shl 8)) -shl 16) -bor ([int]$In[$ip + 2] -bor ([int]$In[$ip + 3] -shl 8))
        $ip += 4
        $extra = 16
        $blockEnd = [Math]::Min($op + 65536, $OutSize)
        while ($op -lt $blockEnd) {
            $sym = $table[[int]($bits -shr 17)]
            $n = $len[$sym]
            $bits = ($bits -shl $n) -band 0xFFFFFFFFL
            $extra -= $n
            if ($extra -lt 0) {
                if ($ip + 1 -lt $inLen) { $bits = $bits -bor ([long]([int]$In[$ip] -bor ([int]$In[$ip + 1] -shl 8)) -shl (-$extra)) }
                elseif ($ip -gt $inLen + 4) { throw 'Compressed data ends early' }     # a few bytes of read-ahead past the end are normal
                $ip += 2; $extra += 16
            }
            if ($sym -lt 256) { $out[$op++] = [byte]$sym; continue }
            $sym -= 256
            $ml = $sym -band 15
            $ob = $sym -shr 4
            if ($ml -eq 15) {
                if ($ip -ge $inLen) { throw 'Compressed data ends inside a match length' }
                $ml = [int]$In[$ip]; $ip++
                if ($ml -eq 255) {
                    if ($ip + 1 -ge $inLen) { throw 'Compressed data ends inside a match length' }
                    $ml = [int]$In[$ip] -bor ([int]$In[$ip + 1] -shl 8); $ip += 2
                    if ($ml -lt 15) { throw 'Invalid match length' }
                    $ml -= 15
                }
                $ml += 15
            }
            $ml += 3
            if ($ob -gt 0) {
                $off = [int]($bits -shr (32 - $ob)) + (1 -shl $ob)
                $bits = ($bits -shl $ob) -band 0xFFFFFFFFL
                $extra -= $ob
                if ($extra -lt 0) {
                    if ($ip + 1 -lt $inLen) { $bits = $bits -bor ([long]([int]$In[$ip] -bor ([int]$In[$ip + 1] -shl 8)) -shl (-$extra)) }
                    elseif ($ip -gt $inLen + 4) { throw 'Compressed data ends early' }
                    $ip += 2; $extra += 16
                }
            } else { $off = 1 }
            if ($off -gt $op) { throw "Match reaches before the start of the output (offset $off at $op)" }
            $src = $op - $off
            $end = [Math]::Min($op + $ml, $OutSize)
            if ($off -ge $ml) { [Array]::Copy($out, $src, $out, $op, $end - $op); $op = $end }
            else { while ($op -lt $end) { $out[$op++] = $out[$src++] } }       # overlapping copy repeats the pattern
        }
    }
    , $out
}

function Read-WfxPrefetch {
    <#
    .SYNOPSIS Parses a prefetch file. Returns { Version; Name; Hash; RunCount; RunTimes (newest first, UTC);
    Volumes ({ Path; Serial; Created; Directories }); Files (loaded files, in load order); Compressed }.
    #>
    param([string]$Path, [byte[]]$Bytes)
    if (-not $Bytes) { $Bytes = [IO.File]::ReadAllBytes($Path) }
    $B = $Bytes
    $compressed = $false
    if ($B.Length -ge 8 -and $B[0] -eq 0x4D -and $B[1] -eq 0x41 -and $B[2] -eq 0x4D) {
        # MAM: byte 3 low nibble = compression format (4 = XPRESS Huffman); bit 0x80 = a CRC-32 follows the size.
        $fmt = $B[3] -band 0x0F
        if ($fmt -ne 4) { throw "Unsupported prefetch compression format $fmt" }
        $size = [int][BitConverter]::ToUInt32($B, 4)
        $data = if ($B[3] -band 0x80) { 12 } else { 8 }
        $B = Expand-WfxXpressHuffman -In $B -Start $data -OutSize $size
        $compressed = $true
    }
    if ($B.Length -lt 84 -or [Text.Encoding]::ASCII.GetString($B, 4, 4) -ne 'SCCA') { throw 'Not a prefetch file (no SCCA signature)' }
    $ver = [int][BitConverter]::ToUInt32($B, 0)
    if ($ver -notin 17, 23, 26, 30, 31) { throw "Unsupported prefetch version $ver" }
    $name = [Text.Encoding]::Unicode.GetString($B, 16, 60); $z = $name.IndexOf([char]0); if ($z -ge 0) { $name = $name.Substring(0, $z) }
    $hash = [BitConverter]::ToUInt32($B, 76)
    $u32 = { param($o) if ($o + 4 -le $B.Length) { [long][BitConverter]::ToUInt32($B, $o) } else { 0L } }
    $metOff = & $u32 84; $metCnt = & $u32 88
    $strOff = & $u32 100; $strSize = & $u32 104
    $volOff = & $u32 108; $volCnt = & $u32 112; $volSize = & $u32 116
    $times = New-Object System.Collections.Generic.List[datetime]
    $ft = {
        param($o)
        if ($o + 8 -gt $B.Length) { return }
        $v = [BitConverter]::ToInt64($B, $o)
        if ($v -gt 0 -and $v -lt 2650467743999999999) { $times.Add([DateTime]::FromFileTimeUtc($v)) }
    }
    $runCount = 0
    switch ($ver) {
        17 { & $ft 120; $runCount = & $u32 144 }
        23 { & $ft 128; $runCount = & $u32 152 }
        default {
            for ($i = 0; $i -lt 8; $i++) { & $ft (128 + 8 * $i) }
            # Version 30 has two layouts: the older one (file information 224 bytes, metrics at 0x130) keeps the
            # run count at 208 like version 26; the newer one (216 bytes, metrics at 0x128) and version 31 at 200.
            $runCount = if ($ver -eq 31 -or ($ver -eq 30 -and $metOff -eq 0x128)) { & $u32 200 } else { & $u32 208 }
        }
    }
    # Loaded files, from the metrics array (names point into the filename strings block).
    $files = New-Object System.Collections.Generic.List[string]
    $entry = if ($ver -eq 17) { 20 } else { 32 }
    $nameAt = if ($ver -eq 17) { 8 } else { 12 }
    if ($metCnt -gt 100000) { $metCnt = 0 }
    for ($i = 0; $i -lt $metCnt; $i++) {
        $e = $metOff + $i * $entry
        if ($e + $entry -gt $B.Length) { break }
        $so = [long][BitConverter]::ToUInt32($B, $e + $nameAt); $sc = [long][BitConverter]::ToUInt32($B, $e + $nameAt + 4)
        $p = $strOff + $so
        if ($so -ge $strSize -or $p + 2 * $sc -gt $B.Length -or $sc -gt 32767) { continue }
        $files.Add([Text.Encoding]::Unicode.GetString($B, [int]$p, [int](2 * $sc)))
    }
    # Volumes: device path, serial number, creation time and the directories used on it.
    $vols = [System.Collections.Generic.List[object]]::new()
    $vEntry = switch ($ver) { 17 { 40 } 23 { 104 } 26 { 104 } default { 96 } }
    if ($volCnt -gt 64) { $volCnt = 0 }
    for ($i = 0; $i -lt $volCnt; $i++) {
        $v = $volOff + $i * $vEntry
        if ($v + 36 -gt $B.Length) { break }
        $dpo = [long][BitConverter]::ToUInt32($B, $v); $dpc = [long][BitConverter]::ToUInt32($B, $v + 4)
        $dev = ''
        if ($volOff + $dpo + 2 * $dpc -le $B.Length -and $dpc -lt 1024) { $dev = [Text.Encoding]::Unicode.GetString($B, [int]($volOff + $dpo), [int](2 * $dpc)) }
        $ct = [BitConverter]::ToInt64($B, $v + 8)
        $created = if ($ct -gt 0 -and $ct -lt 2650467743999999999) { [DateTime]::FromFileTimeUtc($ct) } else { $null }
        $serial = '{0:X8}' -f [BitConverter]::ToUInt32($B, $v + 16)
        $dso = [long][BitConverter]::ToUInt32($B, $v + 28); $dsn = [long][BitConverter]::ToUInt32($B, $v + 32)
        $dirs = New-Object System.Collections.Generic.List[string]
        $q = $volOff + $dso
        for ($k = 0; $k -lt $dsn -and $k -lt 10000; $k++) {
            if ($q + 2 -gt $B.Length) { break }
            $c = [BitConverter]::ToUInt16($B, [int]$q)
            if ($q + 2 + 2 * $c -gt $B.Length) { break }
            $dirs.Add([Text.Encoding]::Unicode.GetString($B, [int]($q + 2), 2 * $c))
            $q += 2 + 2 * ($c + 1)
        }
        $vols.Add([pscustomobject]@{ Path = $dev; Serial = $serial; Created = $created; Directories = $dirs.ToArray() })
    }
    [pscustomobject]@{
        Version = $ver; Name = $name; Hash = ('{0:X8}' -f $hash); RunCount = [int]$runCount
        RunTimes = @($times | Sort-Object -Descending); Volumes = $vols.ToArray(); Files = $files.ToArray(); Compressed = $compressed
    }
}

function Get-WfxPrefetchExecutable {
    <#
    The full path of the program a prefetch file is about: the loaded file whose name is the executable name
    (the header keeps only the first 29 characters). Volume device paths are shown as "(volume)".
    #>
    param($Pf)
    $n = ([string]$Pf.Name).ToUpperInvariant()
    if (-not $n) { return '' }
    foreach ($f in $Pf.Files) {
        $leaf = ($f -split '\\')[-1].ToUpperInvariant()
        if ($leaf -eq $n -or ($n.Length -ge 29 -and $leaf.StartsWith($n))) { return (ConvertFrom-WfxVolumePath $f) }
    }
    ''
}

function ConvertFrom-WfxVolumePath {
    <# \VOLUME{...}\X or \DEVICE\HARDDISKVOLUME2\X -> (volume)\X. #>
    param([string]$Path)
    $Path -replace '^\\(?:VOLUME\{[^}]*\}|DEVICE\\HARDDISKVOLUME\d+|DEVICE\\[^\\]+)(?=\\)', '(volume)'
}
