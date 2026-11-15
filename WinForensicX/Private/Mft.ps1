# NTFS Master File Table ($MFT) parser, from the published on-disk format (FILE records, update-sequence
# fixups, resident and non-resident attributes). Read-only: it parses a copied $MFT file (KAPE, Velociraptor,
# FTK Imager export) and never touches a live volume.
#
# Each file record carries two sets of timestamps: $STANDARD_INFORMATION, which any program can rewrite
# with one API call, and $FILE_NAME, which only the kernel updates. Comparing them is the classic way to
# spot timestomping: a creation time in $STANDARD_INFORMATION earlier than the one in $FILE_NAME, or times
# with no fraction of a second, which Windows itself practically never writes.


function ConvertFrom-WfxFileTimeTicks {
    param([long]$Ticks)
    if ($Ticks -le 0 -or $Ticks -gt 2650467743999999999L) { return $null }
    try { [DateTime]::FromFileTimeUtc($Ticks) } catch { $null }
}

function Read-WfxMftRecord {
    <#
    .SYNOPSIS Parses one FILE record (already read into $Buf at $Off, $Size bytes). Applies the fixups in place.
    Returns $null for an empty / corrupt record.
    #>
    param([byte[]]$Buf, [int]$Off, [int]$Size, [long]$Number)
    if ($Off + 48 -gt $Buf.Length) { return $null }
    if ([BitConverter]::ToUInt32($Buf, $Off) -ne 0x454C4946) { return $null }       # 'FILE'
    $usaOff = [BitConverter]::ToUInt16($Buf, $Off + 4); $usaCnt = [BitConverter]::ToUInt16($Buf, $Off + 6)
    if ($usaCnt -lt 2 -or $usaOff + 2 * $usaCnt -gt $Size -or ($usaCnt - 1) * 512 -gt $Size) { return $null }
    $usn = [BitConverter]::ToUInt16($Buf, $Off + $usaOff)
    # Each sector ends with the update sequence number; the real two bytes are kept in the array and put
    # back here. Some exports (ntfscat, some imagers) already put them back. A sector that shows neither
    # was torn (partly written, common for deleted records): it is left as is and the record is marked Torn;
    # the attribute bounds checks below keep a damaged record from being misread.
    $torn = $false
    for ($i = 1; $i -lt $usaCnt; $i++) {
        $p = $Off + $i * 512 - 2; $v = [BitConverter]::ToUInt16($Buf, $p); $real = [BitConverter]::ToUInt16($Buf, $Off + $usaOff + 2 * $i)
        if ($v -eq $usn) { $Buf[$p] = $Buf[$Off + $usaOff + 2 * $i]; $Buf[$p + 1] = $Buf[$Off + $usaOff + 2 * $i + 1] }
        elseif ($v -ne $real) { $torn = $true }
    }
    $flags = [BitConverter]::ToUInt16($Buf, $Off + 22)
    $base = [long]([BitConverter]::ToUInt64($Buf, $Off + 32) -band 0xFFFFFFFFFFFFL)
    $r = [ordered]@{ Number = $Number; Seq = [BitConverter]::ToUInt16($Buf, $Off + 16); InUse = [bool]($flags -band 1); IsDir = [bool]($flags -band 2); Base = $base
        SI = $null; FN = $null; FnRank = -1; Size = $null; Ads = $null; Zone = $null; Torn = $torn }
    $a = $Off + [BitConverter]::ToUInt16($Buf, $Off + 20)
    # The 'bytes in use' header field can be stale in deleted records, so walk to the end marker instead.
    $end = $Off + $Size
    $guard = 0
    while ($a + 16 -le $end -and $guard++ -lt 64) {
        $type = [BitConverter]::ToUInt32($Buf, $a)
        if ($type -eq 0xFFFFFFFFL) { break }
        $len = [long][BitConverter]::ToUInt32($Buf, $a + 4)
        if ($len -lt 16 -or $a + $len -gt $end) { break }
        $nonRes = $Buf[$a + 8]; $nameLen = $Buf[$a + 9]; $nameOff = [BitConverter]::ToUInt16($Buf, $a + 10)
        $cLen = 0; $c = 0
        if (-not $nonRes) {
            $cLen = [long][BitConverter]::ToUInt32($Buf, $a + 16); $c = $a + [BitConverter]::ToUInt16($Buf, $a + 20)
            if ($c + $cLen -gt $a + $len) { $a += $len; continue }
        }
        switch ($type) {
            0x10 {
                if (-not $nonRes -and $cLen -ge 32) {
                    $r.SI = @([BitConverter]::ToInt64($Buf, $c), [BitConverter]::ToInt64($Buf, $c + 8), [BitConverter]::ToInt64($Buf, $c + 16), [BitConverter]::ToInt64($Buf, $c + 24))
                }
            }
            0x30 {
                if (-not $nonRes -and $cLen -ge 66) {
                    $nl = $Buf[$c + 64]; $ns = $Buf[$c + 65]
                    if ($c + 66 + 2 * $nl -le $c + $cLen) {
                        # Prefer the Win32 long name over the DOS 8.3 alias; POSIX names are fine too.
                        $rank = switch ($ns) { 1 { 3 } 3 { 3 } 0 { 2 } default { 1 } }
                        if ($rank -gt $r.FnRank) {
                            $pref = [BitConverter]::ToUInt64($Buf, $c)
                            $r.FN = [ordered]@{ Parent = [long]($pref -band 0xFFFFFFFFFFFFL); ParentSeq = [int]($pref -shr 48)
                                Times = @([BitConverter]::ToInt64($Buf, $c + 8), [BitConverter]::ToInt64($Buf, $c + 16), [BitConverter]::ToInt64($Buf, $c + 24), [BitConverter]::ToInt64($Buf, $c + 32))
                                Name = [Text.Encoding]::Unicode.GetString($Buf, $c + 66, 2 * $nl) }
                            $r.FnRank = $rank
                        }
                    }
                }
            }
            0x80 {
                $aname = if ($nameLen -and $a + $nameOff + 2 * $nameLen -le $a + $len) { [Text.Encoding]::Unicode.GetString($Buf, $a + $nameOff, 2 * $nameLen) } else { '' }
                if (-not $aname) {
                    if ($nonRes) { if ($len -ge 56) { $r.Size = [BitConverter]::ToInt64($Buf, $a + 48) } } else { $r.Size = [long]$cLen }
                } else {
                    $r.Ads = if ($r.Ads) { @($r.Ads) + $aname } else { @($aname) }
                    if ($aname -eq 'Zone.Identifier' -and -not $nonRes -and $cLen -gt 0) { $r.Zone = [Text.Encoding]::UTF8.GetString($Buf, $c, [Math]::Min($cLen, 1024)) }
                }
            }
        }
        $a += $len
    }
    [pscustomobject]$r
}

function Read-WfxMft {
    <#
    .SYNOPSIS Parses a $MFT file (path or bytes) into one object per file: Number, Seq, InUse, IsDir, Path, Name,
    Size, SI* and FN* times (UTC), Ads, Zone (Zone.Identifier text), Torn. Extension records are merged.
    .DESCRIPTION Two passes, so memory stays small on multi-gigabyte $MFTs: the first keeps only folders (to
    build paths), the second streams the records and emits those that pass -Where.
    .PARAMETER Where       Optional filter run on each entry; only entries for which it returns true are output.
    .PARAMETER Prefilter   Optional cheaper filter run on the raw record (Name via .FN.Name, .SI / .FN.Times ticks,
                           .Ads, .Zone, .IsDir) before its path and output object are built.
    .PARAMETER MaxRecords  Safety cap (default 8 million records, about 8 GB of $MFT).
    #>
    param([string]$Path = '', [byte[]]$Bytes = $null, [scriptblock]$Where = $null, [scriptblock]$Prefilter = $null, [long]$MaxRecords = 8000000)
    $open = { if ($Bytes) { New-Object IO.MemoryStream (, $Bytes) } else { [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete') } }
    $s0 = & $open
    try {
        $head = New-Object byte[] 64
        if ($s0.Read($head, 0, 64) -lt 48 -or [BitConverter]::ToUInt32($head, 0) -ne 0x454C4946) { throw 'Not an NTFS $MFT (no FILE record at the start).' }
    } finally { $s0.Dispose() }
    $size = [long][BitConverter]::ToUInt32($head, 28)
    if ($size -notin 1024, 2048, 4096) { $size = 1024 }
    # Runs $Body for every parsed record, in order.
    $walk = {
        param([scriptblock]$Body)
        $st = & $open
        try {
            $chunk = 2048; $buf = New-Object byte[] ($size * $chunk); $n = 0L
            while ($n -lt $MaxRecords) {
                $got = 0
                while ($got -lt $buf.Length) { $k = $st.Read($buf, $got, $buf.Length - $got); if ($k -le 0) { break }; $got += $k }
                if ($got -lt $size) { break }
                $cnt = [int][Math]::Floor($got / $size)
                for ($i = 0; $i -lt $cnt; $i++) { $r = Read-WfxMftRecord -Buf $buf -Off ($i * $size) -Size $size -Number ($n + $i); if ($r) { & $Body $r } }
                $n += $cnt
                if ($got -lt $buf.Length) { break }
            }
        } finally { $st.Dispose() }
    }
    # Pass 1: folders (for paths) and extension records (attributes that did not fit in their base record).
    $dirs = New-Object 'System.Collections.Generic.Dictionary[long,object]'
    $ext = @{}
    & $walk {
        param($r)
        if ($r.Base -and $r.Base -ne $r.Number) { if (-not $ext.ContainsKey($r.Base)) { $ext[$r.Base] = New-Object System.Collections.Generic.List[object] }; $ext[$r.Base].Add($r); return }
        if ($r.IsDir) { $dirs[$r.Number] = $r }
    }
    $merge = {
        param($b)
        if (-not $ext.ContainsKey($b.Number)) { return }
        foreach ($x in $ext[$b.Number]) {
            if ($x.FN -and $x.FnRank -gt $b.FnRank) { $b.FN = $x.FN; $b.FnRank = $x.FnRank }
            if ($null -eq $b.Size -and $null -ne $x.Size) { $b.Size = $x.Size }
            if (-not $b.SI -and $x.SI) { $b.SI = $x.SI }
            if ($x.Ads) { $b.Ads = @(@($b.Ads) + @($x.Ads) | Where-Object { $_ } | Select-Object -Unique) }
            if (-not $b.Zone -and $x.Zone) { $b.Zone = $x.Zone }
        }
    }
    foreach ($d in @($dirs.Values)) { & $merge $d }
    # Folder paths, following parent references. A parent must still be that folder: a directory whose
    # sequence number matches the reference (one higher is accepted for a deleted folder, since deleting a
    # record increments it); otherwise the entry is placed under [Orphaned].
    $dpath = New-Object 'System.Collections.Generic.Dictionary[long,string]'
    $parentOk = {
        param($child)
        $par = $child.FN.Parent
        if ($par -eq 5) { return $true }
        if (-not $dirs.ContainsKey($par)) { return $false }
        $pr = $dirs[$par]; $ps = $child.FN.ParentSeq
        (-not $ps) -or $pr.Seq -eq $ps -or (-not $pr.InUse -and $pr.Seq -eq (($ps + 1) -band 0xFFFF))
    }
    $dirPath = {
        param([long]$Num)
        if ($Num -eq 5) { return '' }
        $stack = New-Object System.Collections.Generic.List[long]
        $cur = $Num; $prefix = $null
        while ($null -eq $prefix) {
            if ($cur -eq 5) { $prefix = ''; break }
            if ($dpath.ContainsKey($cur)) { $prefix = $dpath[$cur]; break }
            if (-not $dirs.ContainsKey($cur) -or -not $dirs[$cur].FN -or $stack.Count -gt 255 -or $stack.Contains($cur)) { $prefix = '\[Orphaned]'; break }
            $stack.Add($cur)
            if (-not (& $parentOk $dirs[$cur])) { $prefix = '\[Orphaned]'; break }
            $cur = $dirs[$cur].FN.Parent
        }
        $p = $prefix
        for ($j = $stack.Count - 1; $j -ge 0; $j--) { $p = $p + '\' + $dirs[$stack[$j]].FN.Name; $dpath[$stack[$j]] = $p }
        $p
    }
    # Pass 2: every base record, with its path, through the filter.
    & $walk {
        param($r)
        if ($r.Base -and $r.Base -ne $r.Number) { return }
        $b = if ($r.IsDir -and $dirs.ContainsKey($r.Number)) { $dirs[$r.Number] } else { & $merge $r; $r }
        if (-not $b.FN) { return }
        if ($Prefilter -and -not (& $Prefilter $b)) { return }
        $full = if ($b.Number -eq 5) { '' } elseif ($b.IsDir -and $dirs.ContainsKey($b.Number)) { & $dirPath $b.Number }
        elseif (& $parentOk $b) { (& $dirPath $b.FN.Parent) + '\' + $b.FN.Name } else { '\[Orphaned]\' + $b.FN.Name }
        # Inline FILETIME conversion (a function call per timestamp costs more than the parse itself).
        $si = @($null, $null, $null, $null); $fn = @($null, $null, $null, $null)
        for ($j = 0; $j -lt 4; $j++) {
            if ($b.SI) { $x = $b.SI[$j]; if ($x -gt 0 -and $x -lt 2650467743999999999L) { $si[$j] = [DateTime]::FromFileTimeUtc($x) } }
            $x = $b.FN.Times[$j]; if ($x -gt 0 -and $x -lt 2650467743999999999L) { $fn[$j] = [DateTime]::FromFileTimeUtc($x) }
        }
        $e = [pscustomobject]@{
            Number = $b.Number; Seq = $b.Seq; InUse = $b.InUse; IsDir = $b.IsDir; Name = $b.FN.Name; Path = $full; ParentNumber = $b.FN.Parent; Size = $b.Size
            SICreated = $si[0]; SIModified = $si[1]; SIChanged = $si[2]; SIAccessed = $si[3]
            FNCreated = $fn[0]; FNModified = $fn[1]; FNChanged = $fn[2]; FNAccessed = $fn[3]
            SITicks = @($b.SI); FNTicks = @($b.FN.Times); Ads = $(if ($b.Ads) { @($b.Ads) } else { @() }); Zone = $b.Zone; Torn = $b.Torn
        }
        if (-not $Where -or (& $Where $e)) { $e }
    }
}

function Test-WfxMftTimestomp {
    <#
    .SYNOPSIS Timestomp indicators for one parsed $MFT entry. Returns $null or { Score; Reasons }.
      * SI created earlier than FN created (by more than a second): the creation time was set back.
      * SI created and modified are whole seconds while FN has fractions: written by a tool, not by Windows.
    #>
    param($Entry)
    if (-not $Entry -or -not $Entry.SICreated -or -not $Entry.FNCreated) { return $null }
    $reasons = New-Object System.Collections.Generic.List[string]; $score = 0
    if (($Entry.FNCreated - $Entry.SICreated).TotalSeconds -gt 1) {
        $score += 2; $reasons.Add("created time in `$STANDARD_INFORMATION ($(ConvertTo-WfxUtcString $Entry.SICreated)) is earlier than in `$FILE_NAME ($(ConvertTo-WfxUtcString $Entry.FNCreated))")
    }
    $si = @($Entry.SITicks); $fn = @($Entry.FNTicks)
    if ($si.Count -ge 2 -and $fn.Count -ge 1 -and $si[0] -gt 0 -and ($si[0] % 10000000) -eq 0 -and ($si[1] % 10000000) -eq 0 -and ($fn[0] % 10000000) -ne 0) {
        $score += 1; $reasons.Add('created and modified times in $STANDARD_INFORMATION have no fraction of a second, unlike $FILE_NAME')
    }
    if (-not $score) { return $null }
    [pscustomobject]@{ Score = $score; Reasons = @($reasons) }
}
