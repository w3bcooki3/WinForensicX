# Read-only Windows shortcut (.lnk) parser, per [MS-SHLLINK]. Pure byte parsing: no COM object,
# no shell API, nothing is executed or resolved — the file is only read.
#
# Besides the target, a shortcut records evidence an investigator wants: the command-line arguments
# (malicious .lnk lures hide PowerShell here), the window mode (hidden / minimised), the volume serial
# and label and drive type of the target (USB evidence), the network share, and in the tracker block the
# NetBIOS name and MAC address of the machine the shortcut was created on.

$script:WfxDriveType = @{ 0 = 'Unknown'; 1 = 'No root'; 2 = 'Removable'; 3 = 'Fixed'; 4 = 'Network'; 5 = 'CD-ROM'; 6 = 'RAM disk' }

function Get-WfxLnkInfo {
    <#
    .SYNOPSIS Parses a .lnk file (path) or its bytes. Returns $null if the data is not a valid shell link.
    Output: Target, Arguments, WorkingDir, RelativePath, Description, IconLocation, ShowCommand,
    Created / Accessed / Written (the TARGET's times, UTC), Size, Attributes, DriveType, DriveSerial,
    VolumeLabel, NetName, MachineId, MacAddress, Length (bytes the shortcut occupies).
    #>
    param([string]$Path, [byte[]]$Bytes)
    if (-not $Bytes) {
        if (-not $Path) { return $null }
        try { $Bytes = [System.IO.File]::ReadAllBytes($Path) } catch { return $null }
    }
    $b = $Bytes
    if ($b.Length -lt 0x4C -or [BitConverter]::ToUInt32($b, 0) -ne 0x4C) { return $null }
    if ([BitConverter]::ToString($b, 4, 16) -ne '01-14-02-00-00-00-00-00-C0-00-00-00-00-00-00-46') { return $null }
    $flags = [BitConverter]::ToUInt32($b, 0x14)
    $ft = { param($o) $v = [BitConverter]::ToInt64($b, $o); if ($v -le 0) { return $null }; try { [DateTime]::FromFileTimeUtc($v) } catch { $null } }
    $r = [ordered]@{
        Target = ''; Arguments = ''; WorkingDir = ''; RelativePath = ''; Description = ''; IconLocation = ''
        ShowCommand = switch ([BitConverter]::ToUInt32($b, 0x3C)) { 3 { 'Maximized' } 7 { 'Minimized' } default { 'Normal' } }
        Created = & $ft 0x1C; Accessed = & $ft 0x24; Written = & $ft 0x2C; Size = [BitConverter]::ToUInt32($b, 0x34)
        Attributes = [BitConverter]::ToUInt32($b, 0x18)
        DriveType = ''; DriveSerial = ''; VolumeLabel = ''; NetName = ''; MachineId = ''; MacAddress = ''; IdListPath = ''; EnvTarget = ''; Length = 0
    }
    $pos = 0x4C
    try {
        if ($flags -band 0x1) {                                   # LinkTargetIDList
            $idl = [BitConverter]::ToUInt16($b, $pos)
            if ($pos + 2 + $idl -le $b.Length) {
                $items = New-Object byte[] $idl; [Array]::Copy($b, $pos + 2, $items, 0, $idl)
                if (Get-Command ConvertFrom-WfxIdList -ErrorAction SilentlyContinue) {
                    $p = ''; foreach ($it in @(ConvertFrom-WfxIdList $items)) { $p = Join-WfxShellPath $p $it }; $r.IdListPath = $p
                }
            }
            $pos += 2 + $idl
        }
        if (($flags -band 0x2) -and $pos + 0x1C -le $b.Length) {  # LinkInfo
            $li = $pos
            $liSize = [BitConverter]::ToUInt32($b, $li); $hdr = [BitConverter]::ToUInt32($b, $li + 4); $liFlags = [BitConverter]::ToUInt32($b, $li + 8)
            $suffix = ''
            if ($hdr -ge 0x24 -and $li + 0x24 -le $b.Length) { $so = [BitConverter]::ToUInt32($b, $li + 32); if ($so) { $suffix = Read-WfxLnkString $b ($li + $so) $true } }
            if (-not $suffix) { $so = [BitConverter]::ToUInt32($b, $li + 24); if ($so) { $suffix = Read-WfxLnkString $b ($li + $so) $false } }
            if ($liFlags -band 0x1) {                             # VolumeID + LocalBasePath
                $vo = $li + [BitConverter]::ToUInt32($b, $li + 12)
                if ($vo + 16 -le $b.Length) {
                    $r.DriveType = $script:WfxDriveType[[int][BitConverter]::ToUInt32($b, $vo + 4)]
                    $r.DriveSerial = '{0:X8}' -f [BitConverter]::ToUInt32($b, $vo + 8)
                    $lo = [BitConverter]::ToUInt32($b, $vo + 12)
                    $r.VolumeLabel = if ($lo -eq 0x14 -and $vo + 20 -le $b.Length) { Read-WfxLnkString $b ($vo + [BitConverter]::ToUInt32($b, $vo + 16)) $true } else { Read-WfxLnkString $b ($vo + $lo) $false }
                }
                $base = ''
                if ($hdr -ge 0x24) { $uo = [BitConverter]::ToUInt32($b, $li + 28); if ($uo) { $base = Read-WfxLnkString $b ($li + $uo) $true } }
                if (-not $base) { $base = Read-WfxLnkString $b ($li + [BitConverter]::ToUInt32($b, $li + 16)) $false }
                $r.Target = if ($suffix) { $base.TrimEnd('\') + '\' + $suffix } else { $base }
            }
            if ($liFlags -band 0x2) {                             # CommonNetworkRelativeLink
                $cn = $li + [BitConverter]::ToUInt32($b, $li + 20)
                if ($cn + 0x14 -le $b.Length) {
                    $nno = [BitConverter]::ToUInt32($b, $cn + 8)
                    $net = if ($nno -gt 0x14 -and $cn + 0x1C -le $b.Length) { Read-WfxLnkString $b ($cn + [BitConverter]::ToUInt32($b, $cn + 20)) $true } else { Read-WfxLnkString $b ($cn + $nno) $false }
                    $r.NetName = $net
                    if (-not $r.Target) { $r.Target = if ($suffix) { $net.TrimEnd('\') + '\' + $suffix } else { $net } }
                    if (-not $r.DriveType) { $r.DriveType = 'Network' }
                }
            }
            $pos = $li + $liSize
        }
        $unicode = [bool]($flags -band 0x80)
        foreach ($f in @(@(0x4, 'Description'), @(0x8, 'RelativePath'), @(0x10, 'WorkingDir'), @(0x20, 'Arguments'), @(0x40, 'IconLocation'))) {
            if (-not ($flags -band $f[0])) { continue }
            if ($pos + 2 -gt $b.Length) { break }
            $n = [BitConverter]::ToUInt16($b, $pos); $pos += 2
            $len = if ($unicode) { $n * 2 } else { $n }
            if ($pos + $len -gt $b.Length) { break }
            $r[$f[1]] = if ($unicode) { [Text.Encoding]::Unicode.GetString($b, $pos, $len) } else { [Text.Encoding]::GetEncoding(28591).GetString($b, $pos, $len) }
            $pos += $len
        }
        while ($pos + 8 -le $b.Length) {                          # ExtraData blocks
            $bs = [BitConverter]::ToUInt32($b, $pos); if ($bs -lt 8 -or $pos + $bs -gt $b.Length) { if ($bs -lt 4) { $pos += 4 }; break }
            $sig = [BitConverter]::ToUInt32($b, $pos + 4)
            if ($sig -eq 0xA0000003L -and $bs -ge 0x60) {        # TrackerDataBlock
                $r.MachineId = (Read-WfxLnkString $b ($pos + 16) $false)
                if ($r.MachineId.Length -gt 16) { $r.MachineId = $r.MachineId.Substring(0, 16) }
                $droid = New-Object byte[] 16; [Array]::Copy($b, $pos + 48, $droid, 0, 16)
                if (($droid[7] -shr 4) -eq 1) { $r.MacAddress = (($droid[10..15] | ForEach-Object { '{0:x2}' -f $_ }) -join ':') }   # UUID v1 node = MAC
            } elseif ($sig -eq 0xA0000001L -and $bs -ge 0x314) {   # EnvironmentVariableDataBlock
                $r.EnvTarget = Read-WfxLnkString $b ($pos + 268) $true
                if (-not $r.EnvTarget) { $r.EnvTarget = Read-WfxLnkString $b ($pos + 8) $false }
            }
            $pos += $bs
        }
        $r.Length = [Math]::Min($b.Length, $pos + 4)
    } catch { $r.Length = $b.Length }
    if (-not $r.Target) { $r.Target = if ($r.EnvTarget) { $r.EnvTarget } elseif ($r.IdListPath) { $r.IdListPath } else { $r.RelativePath } }
    [pscustomobject]$r
}

function Read-WfxLnkString {
    <# Reads a NUL-terminated ANSI or UTF-16 string from a byte array, bounded by the array length. #>
    param([byte[]]$Bytes, [long]$Offset, [bool]$Unicode)
    if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) { return '' }
    $end = [int]$Offset
    if ($Unicode) {
        while ($end + 1 -lt $Bytes.Length -and ($Bytes[$end] -ne 0 -or $Bytes[$end + 1] -ne 0)) { $end += 2 }
        return [Text.Encoding]::Unicode.GetString($Bytes, [int]$Offset, $end - [int]$Offset)
    }
    while ($end -lt $Bytes.Length -and $Bytes[$end] -ne 0) { $end++ }
    return [Text.Encoding]::GetEncoding(28591).GetString($Bytes, [int]$Offset, $end - [int]$Offset)
}
