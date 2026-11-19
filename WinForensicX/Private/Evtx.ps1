# Windows event log (.evtx) reader, written from the format documentation (libevtx, "Windows XML Event Log
# format"). Used for exported logs when the Windows event API is not available (analysis on Linux or macOS)
# or cannot open a file (damaged or partly overwritten logs, carved files).
#
# Layout: a 4 KB file header, then 64 KB chunks. Each chunk holds event records; each record is binary XML
# that names a template (stored once per chunk) and supplies the values that fill it. Templates are compiled
# once and cached; for each record only the values are decoded, and the event ID is read before anything
# else so unwanted records cost almost nothing.
#
# Damage handling: the file header is not trusted (dirty logs carry stale counts), every chunk position is
# tried, every record is checked (signature, size, trailing size copy, bounds), a bad record is skipped
# rather than ending the chunk, and with -Recover records left in chunk slack space are read and marked.

$script:WfxEvtxTokenNames = @{}
$script:WfxCrc32Table = $null

function Get-WfxCrc32 {
    <# CRC-32 (IEEE) of a byte range. #>
    param([byte[]]$B, [int]$Off, [int]$Len)
    if (-not $script:WfxCrc32Table) {
        $t = New-Object 'uint32[]' 256
        for ($i = 0; $i -lt 256; $i++) {
            $c = [uint32]$i
            for ($k = 0; $k -lt 8; $k++) { if ($c -band 1) { $c = [uint32](0xEDB88320L -bxor ($c -shr 1)) } else { $c = [uint32]($c -shr 1) } }
            $t[$i] = $c
        }
        $script:WfxCrc32Table = $t
    }
    $tb = $script:WfxCrc32Table
    $c = [uint32]::MaxValue
    $end = $Off + $Len
    for ($i = $Off; $i -lt $end; $i++) { $c = [uint32]($tb[($c -bxor $B[$i]) -band 0xFF] -bxor ($c -shr 8)) }
    [uint32]($c -bxor [uint32]::MaxValue)
}

function Get-WfxEvtxName {
    <# Element or attribute name stored in the chunk: next(4) hash(2) chars(2) UTF-16 text, NUL. #>
    param($Ctx, [int]$Off)
    $n = $Ctx.Names[$Off]
    if ($null -ne $n) { return $n }
    $B = $Ctx.B
    if ($Off -lt 0 -or $Off + 8 -gt $B.Length) { throw "name offset $Off outside the chunk" }
    $len = [BitConverter]::ToUInt16($B, $Off + 6)
    if ($Off + 8 + 2 * $len -gt $B.Length) { throw "name at $Off runs past the chunk" }
    $n = [Text.Encoding]::Unicode.GetString($B, $Off + 8, 2 * $len)
    # Names are XML names; anything else means the offset points at overwritten data (records in slack space).
    if ($len -eq 0 -or $len -gt 256 -or $n -notmatch '^[A-Za-z_][\w.\-:]*$') { throw "no valid name at offset $Off" }
    $Ctx.Names[$Off] = $n
    $n
}

function Skip-WfxEvtxInlineName {
    <# A name is written in place the first time a chunk uses it: skip it when its offset is the current position. #>
    param($Ctx, [int]$NameOff, [int]$TokenPos)
    if ($NameOff -gt $TokenPos -and $NameOff -eq $Ctx.P) {
        $len = [BitConverter]::ToUInt16($Ctx.B, $NameOff + 6)
        $Ctx.P = $NameOff + 10 + 2 * $len
    }
}

function Read-WfxEvtxParts {
    <#
    Reads value tokens (text, substitutions, character and entity references, CDATA) up to the next token that is
    not one of them. Returns a list of parts: strings, or @{ S = index; O = optional } placeholders, or instance
    nodes from embedded templates.
    #>
    param($Ctx, [int]$End)
    $B = $Ctx.B
    $parts = [System.Collections.Generic.List[object]]::new()
    while ($Ctx.P -lt $End) {
        $t = $B[$Ctx.P]; $k = $t -band 0x0F
        if ($k -eq 0x05) {
            # Value: type(1) then for strings a char count(2) and UTF-16 text. Other types do not occur here in practice.
            $vt = $B[$Ctx.P + 1]
            if ($vt -ne 1) { throw "value token of type $vt" }
            $len = [BitConverter]::ToUInt16($B, $Ctx.P + 2)
            $parts.Add([Text.Encoding]::Unicode.GetString($B, $Ctx.P + 4, 2 * $len))
            $Ctx.P += 4 + 2 * $len
        } elseif ($k -eq 0x0D -or $k -eq 0x0E) {
            $parts.Add(@{ S = [int][BitConverter]::ToUInt16($B, $Ctx.P + 1); O = ($k -eq 0x0E) })
            $Ctx.P += 4
        } elseif ($k -eq 0x07) {
            $len = [BitConverter]::ToUInt16($B, $Ctx.P + 1)
            $parts.Add([Text.Encoding]::Unicode.GetString($B, $Ctx.P + 3, 2 * $len))
            $Ctx.P += 3 + 2 * $len
        } elseif ($k -eq 0x08) {
            $parts.Add([string][char][BitConverter]::ToUInt16($B, $Ctx.P + 1))
            $Ctx.P += 3
        } elseif ($k -eq 0x09) {
            $tp = $Ctx.P; $no = [int][BitConverter]::ToUInt32($B, $Ctx.P + 1); $Ctx.P += 5
            Skip-WfxEvtxInlineName $Ctx $no $tp
            $nm = Get-WfxEvtxName $Ctx $no
            $parts.Add($(switch ($nm) { 'amp' { '&' } 'lt' { '<' } 'gt' { '>' } 'quot' { '"' } 'apos' { "'" } default { "&$nm;" } }))
        } else { break }
    }
    , $parts
}

function Read-WfxEvtxElement {
    <# One element at the current position (open start element token). Returns @{ N; A (list of @{ N; P }); C (list of children) }. #>
    param($Ctx, [int]$End, [int]$Depth)
    if ($Depth -gt 64) { throw 'elements nested too deeply' }
    $B = $Ctx.B
    $tp = $Ctx.P; $t = $B[$tp]
    # token(1) dependency id(2) data size(4) name offset(4) [name, when written in place] [attribute list size(4)]
    $no = [int][BitConverter]::ToUInt32($B, $tp + 7)
    $Ctx.P = $tp + 11
    Skip-WfxEvtxInlineName $Ctx $no $tp
    if ($t -band 0x40) { $Ctx.P += 4 }
    $el = @{ N = (Get-WfxEvtxName $Ctx $no); A = ([System.Collections.Generic.List[object]]::new()); C = ([System.Collections.Generic.List[object]]::new()) }
    while ($Ctx.P -lt $End -and ($B[$Ctx.P] -band 0x0F) -eq 0x06) {
        $ap = $Ctx.P; $an = [int][BitConverter]::ToUInt32($B, $ap + 1); $Ctx.P = $ap + 5
        Skip-WfxEvtxInlineName $Ctx $an $ap
        $el.A.Add(@{ N = (Get-WfxEvtxName $Ctx $an); P = (Read-WfxEvtxParts $Ctx $End) })
    }
    if ($Ctx.P -ge $End) { throw 'element runs past the end of its data' }
    $k = $B[$Ctx.P] -band 0x0F
    if ($k -eq 0x03) { $Ctx.P++; return $el }
    if ($k -ne 0x02) { throw "unexpected token 0x$('{0:x2}' -f $B[$Ctx.P]) after attributes" }
    $Ctx.P++
    while ($Ctx.P -lt $End) {
        $k = $B[$Ctx.P] -band 0x0F
        if ($k -eq 0x04) { $Ctx.P++; return $el }
        if ($k -eq 0x01) { $el.C.Add((Read-WfxEvtxElement $Ctx $End ($Depth + 1))); continue }
        if ($k -eq 0x0C) { $el.C.Add((Read-WfxEvtxInstance $Ctx)); continue }
        if ($k -eq 0x0A -or $k -eq 0x0B) {
            # Processing instructions: target name offset(4), or data char count(2) + text. Not used by events; skipped.
            if ($k -eq 0x0A) { $p0 = $Ctx.P; $o = [int][BitConverter]::ToUInt32($B, $p0 + 1); $Ctx.P += 5; Skip-WfxEvtxInlineName $Ctx $o $p0 }
            else { $Ctx.P += 3 + 2 * [BitConverter]::ToUInt16($B, $Ctx.P + 1) }
            continue
        }
        $before = $Ctx.P
        foreach ($p in (Read-WfxEvtxParts $Ctx $End)) { $el.C.Add($p) }
        if ($Ctx.P -eq $before) { throw "unexpected token 0x$('{0:x2}' -f $B[$Ctx.P]) in element content" }
    }
    throw 'element not closed'
}

function Read-WfxEvtxFragment {
    <# A binary XML fragment from the current position to $End or the end-of-stream token. Returns its top-level nodes. #>
    param($Ctx, [int]$End)
    $B = $Ctx.B
    $nodes = [System.Collections.Generic.List[object]]::new()
    while ($Ctx.P -lt $End) {
        $k = $B[$Ctx.P] -band 0x0F
        if ($k -eq 0x00) { $Ctx.P++; break }
        if ($k -eq 0x0F) { $Ctx.P += 4; continue }
        if ($k -eq 0x01) { $nodes.Add((Read-WfxEvtxElement $Ctx $End 0)); continue }
        if ($k -eq 0x0C) { $nodes.Add((Read-WfxEvtxInstance $Ctx)); continue }
        throw "unexpected token 0x$('{0:x2}' -f $B[$Ctx.P]) in a fragment"
    }
    , $nodes
}

function Get-WfxEvtxTemplate {
    <#
    Compiled template at chunk offset $Off. Templates are cached per chunk (by offset) and across chunks (by GUID
    and size). The instance names the template by its ID, the first four bytes of its GUID: when the definition
    at $Off is damaged, overwritten or is not that template (records recovered from slack space), a template
    with that ID seen elsewhere in the file is used.
    #>
    param($Ctx, [long]$Off, [uint32]$Id)
    $t = $Ctx.Tpl[$Off]
    if ($t -and $t.Id -eq $Id) { return $t }
    $B = $Ctx.B
    $byId = $Ctx.Shared["id:$Id"]
    $valid = $Off -ge 512 -and $Off + 24 -le $B.Length -and [BitConverter]::ToUInt32($B, [int]$Off + 4) -eq $Id
    $size = if ($valid) { [long][BitConverter]::ToUInt32($B, [int]$Off + 20) } else { 0 }
    if (-not $valid -or $size -le 0 -or $Off + 24 + $size -gt $B.Length) {
        if ($byId) { return $byId }
        throw "template at $Off is missing or damaged"
    }
    $guid = [BitConverter]::ToString($B, [int]$Off + 4, 16)
    $key = "$guid|$size"
    $t = $Ctx.Shared[$key]
    if (-not $t) {
        $save = $Ctx.P
        $Ctx.P = [int]$Off + 24
        try { $nodes = Read-WfxEvtxFragment $Ctx ([int]($Off + 24 + $size)) }
        catch { if ($byId) { return $byId }; throw }
        finally { $Ctx.P = $save }
        $t = @{ Nodes = $nodes; Plan = $null; Id = $Id }
        $t.Plan = Get-WfxEvtxPlan $t
        $Ctx.Shared[$key] = $t
        if (-not $byId) { $Ctx.Shared["id:$Id"] = $t }
    }
    $Ctx.Tpl[$Off] = $t
    $t
}

function Read-WfxEvtxInstance {
    <# Template instance token: template reference (with the definition inline the first time), then the substitution values. #>
    param($Ctx)
    $B = $Ctx.B
    $p = $Ctx.P
    $tid = [BitConverter]::ToUInt32($B, $p + 2)
    $def = [long][BitConverter]::ToUInt32($B, $p + 6)
    $Ctx.P = $p + 10
    if ($def -eq $Ctx.P) { $Ctx.P += 24 + [int][BitConverter]::ToUInt32($B, [int]$def + 20) }
    $tpl = Get-WfxEvtxTemplate $Ctx $def $tid
    $n = [int][BitConverter]::ToUInt32($B, $Ctx.P)
    if ($n -gt 4096 -or $Ctx.P + 4 + 4 * $n -gt $B.Length) { throw "bad substitution count $n" }
    $d = $Ctx.P + 4
    $vp = New-Object 'int[]' $n; $vs = New-Object 'int[]' $n; $vt = New-Object 'int[]' $n
    $q = $d + 4 * $n
    for ($i = 0; $i -lt $n; $i++) {
        $vs[$i] = [BitConverter]::ToUInt16($B, $d + 4 * $i); $vt[$i] = $B[$d + 4 * $i + 2]; $vp[$i] = $q; $q += $vs[$i]
    }
    if ($q -gt $B.Length) { throw 'substitution values run past the chunk' }
    $Ctx.P = $q
    @{ I = $true; T = $tpl; VP = $vp; VS = $vs; VT = $vt; V = @{} }
}

function ConvertFrom-WfxEvtxValue {
    <# One substitution value as text, written the way the Windows event API writes it in event XML. Binary XML values return a node list. #>
    param($Ctx, $Inst, [int]$I)
    if ($I -ge $Inst.VT.Length) { return $null }
    if ($Inst.V.ContainsKey($I)) { return $Inst.V[$I] }
    $B = $Ctx.B; $t = $Inst.VT[$I]; $p = $Inst.VP[$I]; $s = $Inst.VS[$I]
    $v = $null
    if ($s -eq 0 -and $t -ne 0x21) { $v = $null }
    elseif ($t -band 0x80) {
        $et = $t -band 0x7F
        $items = New-Object System.Collections.Generic.List[string]
        if ($et -eq 0x01 -or $et -eq 0x02) {
            # Each string ends with a NUL; drop only the last terminator so empty items are kept.
            $txt = if ($et -eq 0x01) { [Text.Encoding]::Unicode.GetString($B, $p, $s - ($s % 2)) } else { [Text.Encoding]::GetEncoding(28591).GetString($B, $p, $s) }
            if ($txt.EndsWith([string][char]0)) { $txt = $txt.Substring(0, $txt.Length - 1) }
            foreach ($x in ($txt -split "`0")) { $items.Add($x) }
        }
        else {
            $w = @{ 3 = 1; 4 = 1; 5 = 2; 6 = 2; 7 = 4; 8 = 4; 9 = 8; 10 = 8; 11 = 4; 12 = 8; 13 = 4; 15 = 16; 16 = 8; 17 = 8; 18 = 16; 20 = 4; 21 = 8 }[$et]
            if ($w) { for ($o = 0; $o + $w -le $s; $o += $w) { $items.Add((ConvertFrom-WfxEvtxScalar $B $et ($p + $o) $w)) } }
            else { $items.Add(([BitConverter]::ToString($B, $p, $s) -replace '-', '')) }
        }
        # An array fills one element per item (classic event log strings become <Data>%1</Data> repeated).
        $Inst.V["A$I"] = $items.ToArray()
        $v = $items -join ', '
    } elseif ($t -eq 0x21) {
        $save = $Ctx.P; $Ctx.P = $p
        try { $v = , (Read-WfxEvtxFragment $Ctx ($p + $s)) } finally { $Ctx.P = $save }
    } else { $v = ConvertFrom-WfxEvtxScalar $B $t $p $s }
    $Inst.V[$I] = $v
    $v
}

function ConvertFrom-WfxEvtxScalar {
    param([byte[]]$B, [int]$T, [int]$P, [int]$S)
    switch ($T) {
        0x00 { return '' }
        0x01 { return [Text.Encoding]::Unicode.GetString($B, $P, $S - ($S % 2)).TrimEnd([char]0) }
        0x02 { return [Text.Encoding]::GetEncoding(28591).GetString($B, $P, $S).TrimEnd([char]0) }
        0x03 { return ([sbyte]$(if ($B[$P] -gt 127) { $B[$P] - 256 } else { $B[$P] })).ToString() }
        0x04 { return $B[$P].ToString() }
        0x05 { return [BitConverter]::ToInt16($B, $P).ToString() }
        0x06 { return [BitConverter]::ToUInt16($B, $P).ToString() }
        0x07 { return [BitConverter]::ToInt32($B, $P).ToString() }
        0x08 { return [BitConverter]::ToUInt32($B, $P).ToString() }
        0x09 { return [BitConverter]::ToInt64($B, $P).ToString() }
        0x0A { return [BitConverter]::ToUInt64($B, $P).ToString() }
        0x0B { return [BitConverter]::ToSingle($B, $P).ToString('R', [Globalization.CultureInfo]::InvariantCulture) }
        0x0C { return [BitConverter]::ToDouble($B, $P).ToString('R', [Globalization.CultureInfo]::InvariantCulture) }
        0x0D { return $(if ([BitConverter]::ToInt32($B, $P) -ne 0) { 'true' } else { 'false' }) }
        0x0E { return ([BitConverter]::ToString($B, $P, $S) -replace '-', '') }
        0x0F { $g = New-Object byte[] 16; [Array]::Copy($B, $P, $g, 0, 16); return ([guid]$g).ToString('B').ToUpperInvariant() }
        0x10 { if ($S -ge 8) { return '0x' + [BitConverter]::ToUInt64($B, $P).ToString('x') } else { return '0x' + [BitConverter]::ToUInt32($B, $P).ToString('x') } }
        0x11 {
            $ft = [BitConverter]::ToInt64($B, $P)
            if ($ft -lt 0 -or $ft -gt 2650467743999999999) { return '' }
            return [DateTime]::FromFileTimeUtc($ft).ToString('yyyy-MM-ddTHH:mm:ss.fffffff', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
        }
        0x12 {
            try {
                $d = New-Object DateTime ([BitConverter]::ToUInt16($B, $P)), ([BitConverter]::ToUInt16($B, $P + 2)), ([BitConverter]::ToUInt16($B, $P + 6)), ([BitConverter]::ToUInt16($B, $P + 8)), ([BitConverter]::ToUInt16($B, $P + 10)), ([BitConverter]::ToUInt16($B, $P + 12)), ([BitConverter]::ToUInt16($B, $P + 14)), ([DateTimeKind]::Utc)
                return $d.ToString('yyyy-MM-ddTHH:mm:ss.fffffff', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
            } catch { return '' }
        }
        0x13 {
            if ($S -lt 8) { return '' }
            $n = $B[$P + 1]; if ($S -lt 8 + 4 * $n) { return '' }
            $auth = 0L; for ($i = 2; $i -lt 8; $i++) { $auth = ($auth -shl 8) -bor $B[$P + $i] }
            $sid = "S-$($B[$P])-$auth"
            for ($i = 0; $i -lt $n; $i++) { $sid += '-' + [BitConverter]::ToUInt32($B, $P + 8 + 4 * $i) }
            return $sid
        }
        0x14 { return '0x' + [BitConverter]::ToUInt32($B, $P).ToString('x') }
        0x15 { return '0x' + [BitConverter]::ToUInt64($B, $P).ToString('x') }
        0x20 { return '0x' + $(if ($S -ge 8) { [BitConverter]::ToUInt64($B, $P).ToString('x') } else { [BitConverter]::ToUInt32($B, $P).ToString('x') }) }
        0x23 { return [Text.Encoding]::Unicode.GetString($B, $P, $S - ($S % 2)).TrimEnd([char]0) }
        default { return ([BitConverter]::ToString($B, $P, $S) -replace '-', '') }
    }
}

function Get-WfxEvtxPlan {
    <#
    Where an event's fields live in a template: the parts of System/EventID, Provider name, TimeCreated, record id,
    channel and computer; and the EventData / UserData element, read generically per record.
    #>
    param($Tpl)
    $plan = @{ Event = $null; Sys = @{}; Data = $null; User = $null; Dynamic = $false }
    $ev = $null; foreach ($x in $Tpl.Nodes) { if ($x -is [hashtable] -and $x.N -eq 'Event') { $ev = $x; break } }
    if (-not $ev) { return $plan }
    $plan.Event = $ev
    foreach ($c in $ev.C) {
        if ($c -is [hashtable] -and -not $c.N) { $plan.Dynamic = $true }   # a substitution or embedded template supplies a section
        if ($c -isnot [hashtable] -or -not $c.N) { continue }
        if ($c.N -eq 'System') {
            foreach ($s in $c.C) {
                if ($s -isnot [hashtable] -or -not $s.N) { continue }
                switch ($s.N) {
                    'Provider' { foreach ($a in $s.A) { if ($a.N -eq 'Name') { $plan.Sys['Provider'] = $a.P } } }
                    'TimeCreated' { foreach ($a in $s.A) { if ($a.N -eq 'SystemTime') { $plan.Sys['Time'] = $a.P } } }
                    'Security' { foreach ($a in $s.A) { if ($a.N -eq 'UserID') { $plan.Sys['UserID'] = $a.P } } }
                    'Execution' { foreach ($a in $s.A) { if ($a.N -eq 'ProcessID') { $plan.Sys['ProcessID'] = $a.P } } }
                    default { $plan.Sys[$s.N] = $s.C }
                }
            }
        } elseif ($c.N -eq 'EventData') { $plan.Data = $c }
        elseif ($c.N -eq 'UserData') { $plan.User = $c }
    }
    $plan
}

function Get-WfxEvtxText {
    <# Concatenated text of parts for one record; embedded XML values give their text content. #>
    param($Ctx, $Inst, $Parts)
    if ($null -eq $Parts) { return $null }
    $sb = ''
    foreach ($p in $Parts) {
        if ($p -is [string]) { $sb += $p; continue }
        if ($p -is [hashtable] -and $p.ContainsKey('S')) {
            $v = ConvertFrom-WfxEvtxValue $Ctx $Inst $p.S
            if ($null -eq $v) { continue }
            if ($v -is [string]) { $sb += $v } else { $sb += (Get-WfxEvtxInnerText $Ctx $Inst $v) }
            continue
        }
        if ($p -is [hashtable] -and $p.I) { $sb += (Get-WfxEvtxInnerText $Ctx $p $p.T.Nodes) ; continue }
        if ($p -is [hashtable] -and $p.N) { $sb += (Get-WfxEvtxInnerText $Ctx $Inst @(, $p)) }
    }
    $sb
}

function Get-WfxEvtxInnerText {
    param($Ctx, $Inst, $Nodes)
    $sb = ''
    foreach ($n in $Nodes) {
        if ($n -is [string]) { $sb += $n }
        elseif ($n -is [hashtable] -and $n.I) { $sb += Get-WfxEvtxInnerText $Ctx $n $n.T.Nodes }
        elseif ($n -is [hashtable] -and $n.N) { $sb += Get-WfxEvtxInnerText $Ctx $Inst $n.C }
        elseif ($n -is [hashtable] -and $n.ContainsKey('S')) { $sb += Get-WfxEvtxText $Ctx $Inst @(, $n) }
    }
    $sb
}

function Resolve-WfxEvtxChildren {
    <#
    The element children of $El for one record, with embedded templates and XML values expanded into
    @{ El; Inst } pairs (the instance that supplies the element's substitution values).
    #>
    param($Ctx, $Inst, $El)
    $out = [System.Collections.Generic.List[object]]::new()
    $walk = {
        param($items, $inst, $depth)
        if ($depth -gt 16) { return }
        foreach ($c in $items) {
            if ($c -is [hashtable] -and $c.N) { $out.Add(@{ El = $c; Inst = $inst }) }
            elseif ($c -is [hashtable] -and $c.I) { & $walk $c.T.Nodes $c ($depth + 1) }
            elseif ($c -is [hashtable] -and $c.ContainsKey('S')) {
                $v = ConvertFrom-WfxEvtxValue $Ctx $inst $c.S
                if ($null -ne $v -and $v -isnot [string]) { & $walk $v $inst ($depth + 1) }
            }
        }
    }
    & $walk $El.C $Inst 0
    , $out
}

function Get-WfxEvtxFields {
    <#
    EventData as Name -> text (unnamed Data elements as Param1, Param2, ... by position; Binary as Binary), and
    for UserData the leaf elements under it as LocalName -> text. Either section may come from the template or,
    as Sysmon and many manifest providers write it, from an embedded XML value supplied by the record.
    #>
    param($Ctx, $Inst)
    $f = @{}
    $plan = $Inst.T.Plan
    $sections = [System.Collections.Generic.List[object]]::new()
    if ($plan.Data) { $sections.Add(@{ El = $plan.Data; Inst = $Inst }) }
    if ($plan.User) { $sections.Add(@{ El = $plan.User; Inst = $Inst }) }
    if ($plan.Dynamic) {
        foreach ($x in (Resolve-WfxEvtxChildren $Ctx $Inst $plan.Event)) { if ($x.El.N -eq 'EventData' -or $x.El.N -eq 'UserData') { $sections.Add($x) } }
    }
    $leaf = {
        param($pairs, $depth)
        foreach ($x in $pairs) {
            $kids = Resolve-WfxEvtxChildren $Ctx $x.Inst $x.El
            if ($kids.Count -and $depth -lt 8) { & $leaf $kids ($depth + 1) }
            else { $f[($x.El.N)] = [string](Get-WfxEvtxInnerText $Ctx $x.Inst $x.El.C) }
        }
    }
    foreach ($sec in $sections) {
        if ($sec.El.N -eq 'EventData') {
            $i = 0
            foreach ($x in (Resolve-WfxEvtxChildren $Ctx $sec.Inst $sec.El)) {
                $el = $x.El
                if ($el.N -eq 'Data') {
                    if ($el.A.Count -eq 0 -and $el.C.Count -eq 1 -and $el.C[0] -is [hashtable] -and $el.C[0].ContainsKey('S') -and $el.C[0].S -lt $x.Inst.VT.Length -and ($x.Inst.VT[$el.C[0].S] -band 0x80)) {
                        $null = ConvertFrom-WfxEvtxValue $Ctx $x.Inst $el.C[0].S
                        foreach ($item in $x.Inst.V["A$($el.C[0].S)"]) { $i++; $f["Param$i"] = [string]$item }
                        continue
                    }
                    $i++
                    $name = $null
                    foreach ($a in $el.A) { if ($a.N -eq 'Name') { $name = Get-WfxEvtxText $Ctx $x.Inst $a.P } }
                    if (-not $name) { $name = "Param$i" }
                    $f[$name] = [string](Get-WfxEvtxInnerText $Ctx $x.Inst $el.C)
                } else {
                    $txt = [string](Get-WfxEvtxInnerText $Ctx $x.Inst $el.C)
                    if ($el.N -ne 'Binary' -or $txt) { $f[$el.N] = $txt }      # an empty Binary element is not written
                }
            }
        } else {
            foreach ($top in (Resolve-WfxEvtxChildren $Ctx $sec.Inst $sec.El)) { & $leaf (Resolve-WfxEvtxChildren $Ctx $top.Inst $top.El) 0 }
        }
    }
    $f
}

function Read-WfxEvtx {
    <#
    .SYNOPSIS Reads event records from an .evtx file without the Windows event API.
    .PARAMETER EventId Only records with these event IDs (empty: all).
    .PARAMETER Recover Also read records left in chunk slack space (overwritten or deleted records); they are marked Recovered.
    .OUTPUTS Objects { Log; Provider; Id; RecordId; TimeCreated; Computer; UserId; Fields; Recovered }, file order, and
    a summary object last ({ Summary = $true; Chunks; DamagedChunks; Records; BadRecords; Recovered; Unreadable (slack
    records that could not be read); Dirty; Header; Errors }).
    #>
    param([Parameter(Mandatory)][string]$Path, [int[]]$EventId = @(), [switch]$Recover, [int]$Max = 0)
    $want = $null
    if ($EventId.Count) { $want = New-Object 'System.Collections.Generic.HashSet[int]'; foreach ($i in $EventId) { [void]$want.Add($i) } }
    $shared = @{}
    $sum = [pscustomobject]@{ Summary = $true; Chunks = 0; DamagedChunks = 0; Records = 0; BadRecords = 0; Recovered = 0; Unreadable = 0; Dirty = $false; Header = $true; Errors = (New-Object System.Collections.Generic.List[string]) }
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $len = $fs.Length
        $hdr = New-Object byte[] 4096
        $got = $fs.Read($hdr, 0, [int][Math]::Min(4096, $len))
        $starts = New-Object System.Collections.Generic.List[long]
        if ($got -ge 128 -and [Text.Encoding]::ASCII.GetString($hdr, 0, 7) -eq 'ElfFile') {
            $sum.Dirty = [bool]([BitConverter]::ToUInt32($hdr, 120) -band 1)
            for ($o = 4096L; $o + 512 -le $len; $o += 65536) { $starts.Add($o) }
        } else {
            # No file header (carved or truncated): look for chunk signatures on 512-byte boundaries.
            $sum.Header = $false
            $probe = New-Object byte[] 8
            for ($o = 0L; $o + 512 -le $len; $o += 512) {
                [void]$fs.Seek($o, 'Begin'); [void]$fs.Read($probe, 0, 8)
                if ([Text.Encoding]::ASCII.GetString($probe, 0, 8) -eq "ElfChnk`0") { $starts.Add($o); $o += 65536 - 512 }
            }
        }
        $emitted = 0
        $seen = New-Object 'System.Collections.Generic.HashSet[long]'
        # Pass 1 reads the records each chunk declares; pass 2 (with -Recover) reads what is left in slack space,
        # once every template in the file is known.
        foreach ($pass in @(1, 2)) {
            if ($pass -eq 2 -and -not $Recover) { break }
            foreach ($cs in $starts) {
                $B = New-Object byte[] 65536
                [void]$fs.Seek($cs, 'Begin')
                $n = $fs.Read($B, 0, 65536)
                if ($n -lt 512 -or [Text.Encoding]::ASCII.GetString($B, 0, 8) -ne "ElfChnk`0") { continue }
                $free = [long][BitConverter]::ToUInt32($B, 48)
                if ($free -lt 512 -or $free -gt $n) { $free = $n }
                if ($pass -eq 1) {
                    $sum.Chunks++
                    $calc = Get-WfxCrc32 -B ([byte[]]($B[0..119] + $B[128..511])) -Off 0 -Len 504
                    if ([BitConverter]::ToUInt32($B, 124) -ne $calc) { $sum.DamagedChunks++ }
                    $pos = 512; $limit = $free
                } else { $pos = [int]$free; $pos += (8 - $pos % 8) % 8; $limit = $n }
                $ctx = @{ B = $B; P = 0; Names = @{}; Tpl = @{}; Shared = $shared }
                while ($pos + 28 -le $limit) {
                    $ok = $B[$pos] -eq 0x2A -and $B[$pos + 1] -eq 0x2A -and $B[$pos + 2] -eq 0 -and $B[$pos + 3] -eq 0
                    $size = if ($ok) { [long][BitConverter]::ToUInt32($B, $pos + 4) } else { 0 }
                    if (-not $ok -or $size -lt 28 -or $pos + $size -gt $n -or [BitConverter]::ToUInt32($B, [int]($pos + $size - 4)) -ne $size) {
                        if ($ok -and $pass -eq 1) { $sum.BadRecords++ }
                        $pos += 8; continue      # records are 8-byte aligned; look for the next one
                    }
                    $rid = [BitConverter]::ToInt64($B, $pos + 8)
                    $recPos = $pos; $pos += [int]$size
                    if ($pass -eq 2 -and $seen.Contains($rid)) { continue }
                    try {
                        $ctx.P = $recPos + 24
                        $nodes = Read-WfxEvtxFragment $ctx ([int]($recPos + $size - 4))
                        $inst = $null; foreach ($x in $nodes) { if ($x -is [hashtable] -and $x.I) { $inst = $x; break } }
                        if (-not $inst -or -not $inst.T.Plan.Event) { throw 'no event in the record' }
                        $sys = $inst.T.Plan.Sys
                        $idText = Get-WfxEvtxText $ctx $inst $sys['EventID']
                        $id = 0; [void][int]::TryParse(([string]$idText).Trim(), [ref]$id)
                        if ($want -and -not $want.Contains($id)) {
                            if ($pass -eq 1) { $sum.Records++ } else { $sum.Recovered++ }
                            [void]$seen.Add($rid); continue
                        }
                        $t = Get-WfxEvtxText $ctx $inst $sys['Time']
                        if (-not $t) { $t = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($B, $recPos + 16)).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') }
                        if ($pass -eq 2) {
                            # A record from slack space is kept only when it reads as a whole event.
                            $prov = [string](Get-WfxEvtxText $ctx $inst $sys['Provider']); $chan = [string](Get-WfxEvtxText $ctx $inst $sys['Channel'])
                            if (-not $prov -or -not $chan -or $t -notmatch '^(?:199|20[0-9])\d-' -or $id -le 0) { throw 'incomplete record in slack space' }
                        }
                        $rec = [pscustomobject]@{
                            Log = [string](Get-WfxEvtxText $ctx $inst $sys['Channel']); Provider = [string](Get-WfxEvtxText $ctx $inst $sys['Provider'])
                            Id = $id; RecordId = $rid; TimeCreated = $t; Computer = [string](Get-WfxEvtxText $ctx $inst $sys['Computer'])
                            UserId = [string](Get-WfxEvtxText $ctx $inst $sys['UserID']); Fields = (Get-WfxEvtxFields $ctx $inst); Recovered = ($pass -eq 2)
                        }
                        if ($pass -eq 1) { $sum.Records++ } else { $sum.Recovered++ }
                        [void]$seen.Add($rid)
                        $rec
                        $emitted++
                        if ($Max -gt 0 -and $emitted -ge $Max) { $sum; return }
                    } catch {
                        if ($pass -eq 1) { $sum.BadRecords++ } else { $sum.Unreadable++ }
                        if ($sum.Errors.Count -lt 20) { $sum.Errors.Add("chunk at $cs, record at $recPos : $($_.Exception.Message)") }
                    }
                }
            }
        }
    } finally { $fs.Dispose() }
    $sum
}
