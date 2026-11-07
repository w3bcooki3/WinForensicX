# Read-only Windows shortcut (.lnk) parser, per [MS-SHLLINK]. Pure byte parsing: no COM object,
# no shell API, nothing is executed or resolved — the file is only read.

function Get-WfxLnkInfo {
    <#
    .SYNOPSIS Parses a .lnk file (path) or its bytes and returns the target path and the target's
    creation / access / write times (UTC) recorded in the shortcut header. Returns $null if the data is
    not a valid shell link.
    #>
    param([string]$Path, [byte[]]$Bytes)
    if (-not $Bytes) {
        if (-not $Path) { return $null }
        try { $Bytes = [System.IO.File]::ReadAllBytes($Path) } catch { return $null }
    }
    $b = $Bytes
    if ($b.Length -lt 0x4C -or [BitConverter]::ToUInt32($b, 0) -ne 0x4C) { return $null }
    # LinkCLSID must be 00021401-0000-0000-C000-000000000046
    $clsid = [BitConverter]::ToString($b, 4, 16)
    if ($clsid -ne '01-14-02-00-00-00-00-00-C0-00-00-00-00-00-00-46') { return $null }
    $flags = [BitConverter]::ToUInt32($b, 0x14)
    $ft = {
        param($o)
        $v = [BitConverter]::ToInt64($b, $o)
        if ($v -le 0) { return $null }
        try { return [DateTime]::FromFileTimeUtc($v) } catch { return $null }
    }
    $target = ''
    $pos = 0x4C
    try {
        if ($flags -band 0x1) {                                 # HasLinkTargetIDList
            $pos += 2 + [BitConverter]::ToUInt16($b, $pos)
        }
        if (($flags -band 0x2) -and $pos + 0x1C -le $b.Length) {  # HasLinkInfo
            $li = $pos
            $liSize = [BitConverter]::ToUInt32($b, $li)
            $hdr = [BitConverter]::ToUInt32($b, $li + 4)
            $liFlags = [BitConverter]::ToUInt32($b, $li + 8)
            if ($liFlags -band 0x1) {                             # VolumeIDAndLocalBasePath
                $base = ''
                if ($hdr -ge 0x24 -and $li + 0x20 -le $b.Length) {
                    $uo = [BitConverter]::ToUInt32($b, $li + 28)
                    if ($uo) { $base = Read-WfxLnkString $b ($li + $uo) $true }
                }
                if (-not $base) {
                    $o = [BitConverter]::ToUInt32($b, $li + 16)
                    $base = Read-WfxLnkString $b ($li + $o) $false
                }
                $target = $base
            } elseif ($liFlags -band 0x2) {                       # CommonNetworkRelativeLinkAndPathSuffix
                $cn = $li + [BitConverter]::ToUInt32($b, $li + 20)
                $netOff = [BitConverter]::ToUInt32($b, $cn + 8)
                $net = Read-WfxLnkString $b ($cn + $netOff) $false
                $sufOff = [BitConverter]::ToUInt32($b, $li + 24)
                $suf = Read-WfxLnkString $b ($li + $sufOff) $false
                $target = if ($suf) { $net.TrimEnd('\') + '\' + $suf } else { $net }
            }
            $pos += $liSize
        }
        if (-not $target) {
            # Fall back to RelativePath from the StringData section (after NAME_STRING).
            $unicode = [bool]($flags -band 0x80)
            $strings = @()
            foreach ($bit in 0x4, 0x8, 0x10, 0x20, 0x40) {      # Name, RelativePath, WorkingDir, Arguments, IconLocation
                if (-not ($flags -band $bit)) { $strings += ''; continue }
                $n = [BitConverter]::ToUInt16($b, $pos); $pos += 2
                $len = if ($unicode) { $n * 2 } else { $n }
                if ($pos + $len -gt $b.Length) { break }
                $s = if ($unicode) { [Text.Encoding]::Unicode.GetString($b, $pos, $len) } else { [Text.Encoding]::Default.GetString($b, $pos, $len) }
                $strings += $s; $pos += $len
            }
            if ($strings.Count -ge 2 -and $strings[1]) { $target = $strings[1] }
        }
    } catch { }
    [pscustomobject]@{
        Target   = $target
        Created  = & $ft 0x1C
        Accessed = & $ft 0x24
        Written  = & $ft 0x2C
        Size     = [BitConverter]::ToUInt32($b, 0x34)
    }
}

function Read-WfxLnkString {
    <# Reads a NUL-terminated ANSI or UTF-16 string from a byte array, bounded by the array length. #>
    param([byte[]]$Bytes, [int]$Offset, [bool]$Unicode)
    if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) { return '' }
    $end = $Offset
    if ($Unicode) {
        while ($end + 1 -lt $Bytes.Length -and ($Bytes[$end] -ne 0 -or $Bytes[$end + 1] -ne 0)) { $end += 2 }
        return [Text.Encoding]::Unicode.GetString($Bytes, $Offset, $end - $Offset)
    }
    while ($end -lt $Bytes.Length -and $Bytes[$end] -ne 0) { $end++ }
    return [Text.Encoding]::Default.GetString($Bytes, $Offset, $end - $Offset)
}
