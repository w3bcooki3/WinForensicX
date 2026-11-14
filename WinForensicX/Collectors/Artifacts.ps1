# Evidence-of-execution and user-activity artifacts: ShimCache, Amcache, ShellBags, Jump Lists, shortcut
# files, Program Compatibility Assistant logs, Defender support logs and browser download history.
#
# Every parser works on bytes or text that has already been read, so the same code serves a live host and
# a folder of collected files (KAPE output, a mounted image, CTF evidence). Nothing is executed, loaded
# into the registry, or written back; files are opened read-only with sharing so the system keeps running.
#
# Every record has the same shape (New-WfxArtifact) so analyzers, the timeline, the report and the
# exports treat them alike:
#   Artifact  ShimCache | Amcache | AmcacheProgram | AmcacheDriver | ShellBag | JumpList | Shortcut | PCA | DefenderLog | Download
#   Time      UTC ISO-8601; what the time means is in TimeKind
#   Evidence  Execution | Presence | Access | Download | Detection | Install
#   Path, Name, Sha1, User, Detail, Source (the file or key it came from), Extra (artifact-specific fields)

function New-WfxArtifact {
    param([string]$Artifact, $Time, [string]$TimeKind, [string]$Evidence, [string]$Path, [string]$Name = '',
        [string]$Sha1 = '', [string]$User = '', [string]$Detail = '', [string]$Source = '', $Extra = $null)
    if (-not $Name -and $Path) { $Name = ($Path -split '[\\/]')[-1] }
    [pscustomobject]@{
        Artifact = $Artifact; Time = (ConvertTo-WfxUtcString $Time); TimeKind = $TimeKind; Evidence = $Evidence
        Path = (Protect-WfxText $Path); Name = (Protect-WfxText $Name); Sha1 = $Sha1; User = $User
        Detail = (Protect-WfxText $Detail); Source = $Source; Extra = $Extra
    }
}

# ───────────────────────────── ShimCache (AppCompatCache) ─────────────────────────────
function ConvertFrom-WfxShimCache {
    <#
    .SYNOPSIS Parses the AppCompatCache registry value (Windows 7 / 8 / 8.1 / 10 / 11).
    Each entry is a file the shell checked for compatibility: proof the file EXISTED at that path, not proof
    that it ran. LastModified is the file's own $STANDARD_INFORMATION modification time, not a run time.
    Position 0 is the most recent entry. Windows writes the cache to the registry at shutdown.
    #>
    param([byte[]]$Bytes)
    $b = $Bytes
    if (-not $b -or $b.Length -lt 0x34) { return }
    $sig0 = [BitConverter]::ToUInt32($b, 0)
    $rd = { param($o, $n) if ($o -ge 0 -and $n -gt 0 -and $o + $n -le $b.Length) { [Text.Encoding]::Unicode.GetString($b, $o, $n) } else { '' } }
    $pos = 0
    if ($sig0 -eq 0xBADC0FEEL) {                                        # Windows 7 / 2008 R2
        $count = [BitConverter]::ToUInt32($b, 4)
        $x64 = ($b.Length -ge 0x80 + 0x30) -and ([BitConverter]::ToUInt32($b, 0x80 + 4) -eq 0)
        $sz = if ($x64) { 0x30 } else { 0x20 }
        for ($i = 0; $i -lt $count -and 0x80 + ($i + 1) * $sz -le $b.Length; $i++) {
            $e = 0x80 + $i * $sz; $len = [BitConverter]::ToUInt16($b, $e)
            if ($x64) { $po = [BitConverter]::ToInt64($b, $e + 8); $lm = [BitConverter]::ToInt64($b, $e + 16); $fl = [BitConverter]::ToUInt32($b, $e + 24) }
            else { $po = [BitConverter]::ToUInt32($b, $e + 4); $lm = [BitConverter]::ToInt64($b, $e + 8); $fl = [BitConverter]::ToUInt32($b, $e + 16) }
            [pscustomobject]@{ Position = $i; Path = (& $rd ([int]$po) $len); LastModified = (ConvertFrom-WfxFileTime $lm); Executed = [bool]($fl -band 2); Format = 'Win7' }
        }
        return
    }
    if ($b.Length -ge 0x84 -and $sig0 -eq 0x80) {                       # Windows 8 / 8.1: 128-byte header, '00ts' / '10ts'
        $pos = 0x80; $i = 0
        while ($pos + 14 -le $b.Length) {
            $sig = [Text.Encoding]::ASCII.GetString($b, $pos, 4); if ($sig -notin '00ts', '10ts') { break }
            $esz = [BitConverter]::ToUInt32($b, $pos + 8); $len = [BitConverter]::ToUInt16($b, $pos + 12)
            $p = $pos + 14; $path = & $rd $p $len; $p += $len
            if ($p + 2 -le $b.Length) { $p += 2 + [BitConverter]::ToUInt16($b, $p) }      # package name
            $fl = if ($p + 4 -le $b.Length) { [BitConverter]::ToUInt32($b, $p) } else { 0 }
            $lm = if ($p + 16 -le $b.Length) { [BitConverter]::ToInt64($b, $p + 8) } else { 0 }
            [pscustomobject]@{ Position = $i; Path = $path; LastModified = (ConvertFrom-WfxFileTime $lm); Executed = [bool]($fl -band 2); Format = 'Win8' }
            $i++; $pos += 12 + $esz
        }
        return
    }
    if ($sig0 -in 0x30, 0x34) {                                           # Windows 10 / 11
        $pos = [int]$sig0; $i = 0
        while ($pos + 14 -le $b.Length) {
            if ([Text.Encoding]::ASCII.GetString($b, $pos, 4) -ne '10ts') { break }
            $esz = [BitConverter]::ToUInt32($b, $pos + 8); $len = [BitConverter]::ToUInt16($b, $pos + 12)
            $p = $pos + 14; $path = & $rd $p $len; $p += $len
            $lm = if ($p + 8 -le $b.Length) { [BitConverter]::ToInt64($b, $p) } else { 0 }
            [pscustomobject]@{ Position = $i; Path = $path; LastModified = (ConvertFrom-WfxFileTime $lm); Executed = $null; Format = 'Win10' }
            $i++; $pos += 12 + $esz
        }
        return
    }
    Write-Verbose ("unsupported AppCompatCache format 0x{0:X}" -f $sig0)
}

function Get-WfxShimCacheRecord {
    param([byte[]]$Bytes, [string]$Source)
    foreach ($e in @(ConvertFrom-WfxShimCache $Bytes)) {
        if (-not $e.Path -or $e.Path -match '^[0-9a-f]{8}\t') { continue }     # packaged (Store) app entries carry no file path
        $path = $e.Path -replace '^\\\?\?\\', ''
        $ex = if ($e.Executed) { 'Execution' } else { 'Presence' }
        New-WfxArtifact -Artifact 'ShimCache' -Time $e.LastModified -TimeKind 'File modified' -Evidence $ex -Path $path `
            -Detail ("Cache position {0} ({1}); {2}" -f $e.Position, $e.Format, $(if ($e.Executed) { 'execution flag set' } else { 'shows the file existed; not proof it ran' })) `
            -Source $Source -Extra ([pscustomobject]@{ Position = $e.Position })
    }
}

function Get-WfxSystemHiveShimCache {
    param($Hive, [string]$Source)
    $cur = 1
    $sel = Get-WfxHiveKey $Hive 'Select'
    if ($sel) { $c = (Get-WfxHiveValue $Hive $sel -Name 'Current').Data; if ($c) { $cur = [int]$c } }
    $k = Get-WfxHiveKey $Hive ('ControlSet{0:D3}\Control\Session Manager\AppCompatCache' -f $cur)
    if (-not $k) { $k = Get-WfxHiveKey $Hive ('ControlSet{0:D3}\Control\Session Manager\AppCompatibility' -f $cur) }
    if (-not $k) { return }
    $v = Get-WfxHiveValue $Hive $k -Name 'AppCompatCache'
    if ($v) { Get-WfxShimCacheRecord -Bytes ([byte[]]$v.Data) -Source "$Source\ControlSet$('{0:D3}' -f $cur)\...\AppCompatCache" }
}

# ───────────────────────────── Amcache ─────────────────────────────
function Get-WfxAmcacheRecord {
    <#
    .SYNOPSIS Amcache.hve: programs Windows inventoried, with SHA-1. Windows 10/11 layout
    (Root\InventoryApplicationFile, Root\InventoryApplication) and the older Root\File layout.
    The key's last-write time is when Windows recorded the file, usually near its first run or install.
    #>
    param($Hive, [string]$Source, [int]$Max = 20000)
    $n = 0
    $iaf = Get-WfxHiveKey $Hive 'Root\InventoryApplicationFile'
    if ($iaf) {
        foreach ($k in @(Get-WfxHiveSubkey $Hive $iaf)) {
            if ($n++ -ge $Max) { break }
            $v = @{}; foreach ($x in @(Get-WfxHiveValue $Hive $k)) { $v[$x.Name] = $x.Data }
            $path = [string]$v['LowerCaseLongPath']; if (-not $path) { continue }
            $sha = ([string]$v['FileId']) -replace '^0000', ''
            $link = [string]$v['LinkDate']
            New-WfxArtifact -Artifact 'Amcache' -Time $k.LastWrite -TimeKind 'Recorded' -Evidence 'Execution' -Path $path -Name ([string]$v['Name']) -Sha1 $sha.ToLowerInvariant() `
                -Detail (@(@($v['Publisher'], $v['ProductName'], $v['Version']) | Where-Object { $_ }) -join ' · ') -Source "$Source\Root\InventoryApplicationFile" `
                -Extra ([pscustomobject]@{ Publisher = [string]$v['Publisher']; Product = [string]$v['ProductName']; Version = [string]$v['Version']; LinkDate = $link
                    Size = $v['Size']; OsComponent = ([string]$v['IsOsComponent'] -eq '1'); BinaryType = [string]$v['BinaryType']; ProgramId = [string]$v['ProgramId'] })
        }
    }
    $ia = Get-WfxHiveKey $Hive 'Root\InventoryApplication'
    if ($ia) {
        foreach ($k in @(Get-WfxHiveSubkey $Hive $ia)) {
            $v = @{}; foreach ($x in @(Get-WfxHiveValue $Hive $k)) { $v[$x.Name] = $x.Data }
            $nm = [string]$v['Name']; if (-not $nm) { continue }
            $inst = ConvertTo-WfxDateTime ([string]$v['InstallDate'])
            New-WfxArtifact -Artifact 'AmcacheProgram' -Time $(if ($inst) { $inst } else { $k.LastWrite }) -TimeKind $(if ($inst) { 'Installed' } else { 'Recorded' }) -Evidence 'Install' `
                -Path ([string]$v['RootDirPath']) -Name $nm -Detail (@(@($v['Publisher'], $v['Version'], $v['Source']) | Where-Object { $_ }) -join ' · ') `
                -Source "$Source\Root\InventoryApplication" -Extra ([pscustomobject]@{ Publisher = [string]$v['Publisher']; Version = [string]$v['Version']; InstallSource = [string]$v['Source']; ProgramId = $k.Name; UninstallString = [string]$v['UninstallString'] })
        }
    }
    $file = Get-WfxHiveKey $Hive 'Root\File'                               # Windows 8 / early Windows 10 layout (also carries DLLs)
    if ($file) {
        foreach ($vol in @(Get-WfxHiveSubkey $Hive $file)) {
            foreach ($k in @(Get-WfxHiveSubkey $Hive $vol)) {
                if ($n++ -ge $Max) { break }
                $v = @{}; foreach ($x in @(Get-WfxHiveValue $Hive $k)) { $v[$x.Name] = $x.Data }
                $path = [string]$v['15']; if (-not $path) { continue }
                $mod = if ($v['17']) { ConvertFrom-WfxFileTime ([long]$v['17']) } else { $null }
                New-WfxArtifact -Artifact 'Amcache' -Time $k.LastWrite -TimeKind 'Recorded' -Evidence 'Execution' -Path $path -Sha1 ((([string]$v['101']) -replace '^0000', '').ToLowerInvariant()) `
                    -Detail (@(@($v['1'], $v['0']) | Where-Object { $_ }) -join ' · ') -Source "$Source\Root\File" `
                    -Extra ([pscustomobject]@{ Publisher = [string]$v['1']; Product = [string]$v['0']; Modified = (ConvertTo-WfxUtcString $mod) })
            }
        }
    }
    $drv = Get-WfxHiveKey $Hive 'Root\InventoryDriverBinary'                 # drivers Windows has seen (BYOVD hunting)
    if ($drv) {
        foreach ($k in @(Get-WfxHiveSubkey $Hive $drv)) {
            if ($n++ -ge $Max) { break }
            $v = @{}; foreach ($x in @(Get-WfxHiveValue $Hive $k)) { $v[$x.Name] = $x.Data }
            $path = ($k.Name -replace '/', '\')
            $signed = if ($v.ContainsKey('DriverSigned')) { [string]$v['DriverSigned'] -eq '1' } else { $null }
            New-WfxArtifact -Artifact 'AmcacheDriver' -Time $k.LastWrite -TimeKind 'Recorded' -Evidence 'Presence' -Path $path -Name ([string]$v['DriverName']) `
                -Sha1 ((([string]$v['DriverId']) -replace '^0000', '').ToLowerInvariant()) `
                -Detail (@(@($v['DriverCompany'], $v['Product'], $v['DriverVersion'], $(if ($signed -eq $false) { 'unsigned' })) | Where-Object { $_ }) -join ' · ') -Source "$Source\Root\InventoryDriverBinary" `
                -Extra ([pscustomobject]@{ Company = [string]$v['DriverCompany']; Product = [string]$v['Product']; Version = [string]$v['DriverVersion']; Signed = $signed; Service = [string]$v['Service'] })
        }
    }
}

# ───────────────────────────── shell items (ShellBags, shortcut ID lists) ─────────────────────────────
$script:WfxKnownFolder = @{
    '20D04FE0-3AEA-1069-A2D8-08002B30309D' = 'This PC'; '59031A47-3F72-44A7-89C5-5595FE6B30EE' = '%USERPROFILE%'
    'F02C1A0D-BE21-4350-88B0-7367FC96EF3C' = 'Network'; '208D2C60-3AEA-1069-A2D7-08002B30309D' = 'Network'
    '645FF040-5081-101B-9F08-00AA002F954E' = 'Recycle Bin'; '031E4825-7B94-4DC3-B131-E946B44C8DD5' = 'Libraries'
    '450D8FBA-AD25-11D0-98A8-0800361B1103' = 'Documents'; 'D3162B92-9365-467A-956B-92703ACA08AF' = 'Documents'; 'FDD39AD0-238F-46AF-ADB4-6C85480369C7' = 'Documents'
    '26EE0668-A00A-44D7-9371-BEB064C98683' = 'Control Panel'; '21EC2020-3AEA-1069-A2DD-08002B30309D' = 'Control Panel'
    'B4BFCC3A-DB2C-424C-B029-7FE99A87C641' = 'Desktop'; '374DE290-123F-4565-9164-39C4925E467B' = 'Downloads'; '088E3905-0323-4B02-9826-5D99428E115F' = 'Downloads'
    '3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA' = 'Pictures'; '24AD3AD4-A569-4530-98E1-AB02F9417AA8' = 'Pictures'; '33E28130-4E1E-4676-835A-98395C3BC3BB' = 'Pictures'
    'A0953C92-50DC-43BF-BE83-3742FED03C9C' = 'Videos'; 'F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A' = 'Videos'
    '1CF1260C-4DD0-4EBB-811F-33C572699FDE' = 'Music'; '3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE' = 'Music'
    '5E6C858F-0E22-4760-9AFE-EA3317B67173' = '%USERPROFILE%'; '9E3995AB-1F9C-4F13-B827-48B24B6C7174' = 'User Pinned'
    '018D5C66-4533-4307-9B53-224DE2ED1FE6' = 'OneDrive'; '679F85CB-0220-4080-B29B-5540CC05AAB6' = 'Quick access'
    '22877A6D-37A1-461A-91B0-DBDA5AAEBC99' = 'Recent Places'; '4234D49B-0245-4DF3-B780-3893943456E1' = 'Applications'
    'F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F' = 'Users Files'; 'DFFACDC5-679F-4156-8947-C5C76BC0B67F' = 'Users Libraries'
    'E31EA727-12ED-4702-820C-4B6445F28E1A' = 'Dropbox'; 'BB06C0E4-D293-4F75-8A90-CB05B6477EEE' = 'System'; '7B81BE6A-CE2B-4676-A29E-EB907A5126C5' = 'Programs and Features'
    'D20EA4E1-3957-11D2-A40B-0C5020524153' = 'Administrative Tools'; '2227A280-3AEA-1069-A2DE-08002B30309D' = 'Printers'; 'ED7BA470-8E54-465E-825C-99712043E01C' = 'All Tasks (God Mode)'
}

function ConvertFrom-WfxDosTime {
    param([uint32]$Value)
    if (-not $Value) { return $null }
    $date = $Value -band 0xFFFF; $time = ($Value -shr 16) -band 0xFFFF
    try { [datetime]::new(1980 + ($date -shr 9), ($date -shr 5) -band 0xF, $date -band 0x1F, $time -shr 11, ($time -shr 5) -band 0x3F, ($time -band 0x1F) * 2, [DateTimeKind]::Utc) } catch { $null }
}

function ConvertFrom-WfxShellItem {
    <#
    .SYNOPSIS Decodes one shell item (an entry of an ITEMIDLIST) into a display name and its kind.
    Covers root folders, drives, file/folder entries (with the long name and times from the 0xBEEF0004
    extension block), network locations and URIs; anything else is returned with its type byte.
    #>
    param([byte[]]$B)
    if (-not $B -or $B.Length -lt 3) { return $null }
    $t = $B[2]; $kind = 'Other'; $name = ''; $mod = $null; $created = $null; $accessed = $null; $mft = $null
    $ascii = { param($o) $e = $o; while ($e -lt $B.Length -and $B[$e] -ne 0) { $e++ }; if ($e -gt $o) { [Text.Encoding]::GetEncoding(28591).GetString($B, $o, $e - $o) } else { '' } }
    $uni = { param($o) $e = $o; while ($e + 1 -lt $B.Length -and ($B[$e] -ne 0 -or $B[$e + 1] -ne 0)) { $e += 2 }; if ($e -gt $o) { [Text.Encoding]::Unicode.GetString($B, $o, $e - $o) } else { '' } }
    # Long name and times from a BEEF0004 extension block, wherever it sits in the item.
    $ext = {
        for ($i = 4; $i + 8 -lt $B.Length; $i++) {
            if ($B[$i] -eq 0x04 -and $B[$i + 1] -eq 0x00 -and $B[$i + 2] -eq 0xEF -and $B[$i + 3] -eq 0xBE) {
                $s = $i - 4; $ver = [BitConverter]::ToUInt16($B, $s + 2)
                if ($s -lt 0 -or $s + 0x14 -gt $B.Length) { return $null }
                $off = if ($ver -ge 9) { 0x2E } elseif ($ver -ge 8) { 0x2A } elseif ($ver -ge 7) { 0x26 } else { 0x14 }
                $mftRef = if ($ver -ge 7 -and $s + 0x1C -le $B.Length) { [BitConverter]::ToUInt64($B, $s + 0x14) } else { $null }
                return [pscustomobject]@{ Created = (ConvertFrom-WfxDosTime ([BitConverter]::ToUInt32($B, $s + 8))); Accessed = (ConvertFrom-WfxDosTime ([BitConverter]::ToUInt32($B, $s + 12)))
                    Name = $(if ($s + $off -lt $B.Length) { & $uni ($s + $off) } else { '' }); Mft = $mftRef }
            }
        }
        $null
    }
    switch ($t) {
        0x1F {
            $kind = 'Root'
            $txt = [Text.Encoding]::GetEncoding(28591).GetString($B)
            $dm = [regex]::Match($txt, '[A-Za-z]:\\')
            if ($B.Length -eq 20) { $g = ([guid]::new([byte[]]$B[4..19])).ToString().ToUpperInvariant(); $name = if ($script:WfxKnownFolder[$g]) { $script:WfxKnownFolder[$g] } else { "{$g}" } }
            elseif ($dm.Success) { $kind = 'Drive'; $name = $dm.Value }
            elseif ($B.Length -ge 10 -and [BitConverter]::ToUInt32($B, 6) -eq 0x23A3DFD5) { $name = 'Search Folder' }
            elseif ($B.Length -ge 20) { $g = ([guid]::new([byte[]]$B[4..19])).ToString().ToUpperInvariant(); $name = if ($script:WfxKnownFolder[$g]) { $script:WfxKnownFolder[$g] } else { "{$g}" } }
        }
        { $_ -ge 0x20 -and $_ -le 0x2F } {
            $kind = 'Drive'
            if ($B.Length -ge 6 -and $B[4] -eq 0x3A -and (($B[3] -bor 0x20) -ge 0x61) -and (($B[3] -bor 0x20) -le 0x7A)) { $name = & $ascii 3 }
            elseif ($B.Length -ge 20) {
                $g = ([guid]::new([byte[]]$B[4..19])).ToString().ToUpperInvariant()
                if ($script:WfxKnownFolder[$g]) { $kind = 'Root'; $name = $script:WfxKnownFolder[$g] } else { $name = "{$g}" }
            } else { $name = '{Drive}' }
        }
        0x01 {
            $kind = 'ControlPanel'
            $cats = @('All Control Panel Items', 'Appearance and Personalization', 'Hardware and Sound', 'Network and Internet', 'Sounds, Speech and Audio Devices', 'System and Security', 'Clock and Region', 'Ease of Access', 'Programs', 'User Accounts', 'Security Center', 'Mobile PC')
            $ci = if ($B.Length -ge 12) { [BitConverter]::ToUInt32($B, 8) } else { 99 }
            $name = if ($ci -lt $cats.Count) { $cats[$ci] } else { 'Control Panel category' }
        }
        { $_ -ge 0x30 -and $_ -le 0x3F } {
            $kind = if ($t -band 0x01) { 'Folder' } elseif ($t -band 0x02) { 'File' } else { 'Entry' }
            if ($B.Length -ge 14) {
                $mod = ConvertFrom-WfxDosTime ([BitConverter]::ToUInt32($B, 8))
                $name = if ($t -band 0x04) { & $uni 14 } else { & $ascii 14 }
            }
            $x = & $ext; if ($x) { if ($x.Name) { $name = $x.Name }; $created = $x.Created; $accessed = $x.Accessed; $mft = $x.Mft }
        }
        { $_ -ge 0x40 -and $_ -le 0x4F } {
            $kind = 'Network'; $name = & $ascii 5
        }
        0xC3 { $kind = 'Network'; $name = & $ascii 5 }
        0x61 {
            $kind = 'URI'
            $u = [regex]::Match([Text.Encoding]::Unicode.GetString($B, 0, $B.Length - ($B.Length % 2)), '(?i)(?:https?|ftp|file|ms-[a-z-]+):[^\x00]+')
            if (-not $u.Success) { $u = [regex]::Match([Text.Encoding]::GetEncoding(28591).GetString($B), '(?i)(?:https?|ftp|file):[^\x00]+') }
            if (-not $u.Success -and $B.Length -gt 1) { $u = [regex]::Match([Text.Encoding]::Unicode.GetString($B, 1, $B.Length - 1 - (($B.Length - 1) % 2)), '(?i)(?:https?|ftp|file):[^\x00]+') }
            $name = if ($u.Success) { $u.Value } else { '(URI)' }
        }
        0x71 {
            $kind = 'ControlPanel'
            if ($B.Length -ge 0x1E) { $g = ([guid]::new([byte[]]$B[14..29])).ToString().ToUpperInvariant(); $name = if ($script:WfxKnownFolder[$g]) { $script:WfxKnownFolder[$g] } else { "Control Panel item {$g}" } }
        }
        0x74 {
            $kind = 'Folder'; $x = & $ext
            if ($x) { $name = $x.Name; $created = $x.Created; $accessed = $x.Accessed; $mft = $x.Mft }
            if (-not $name -and $B.Length -gt 0x1A) { $name = & $ascii 0x1A }
        }
        default {
            $x = & $ext
            if ($x -and $x.Name) { $kind = 'Entry'; $name = $x.Name; $created = $x.Created; $accessed = $x.Accessed; $mft = $x.Mft }
            else { $name = ('(shell item 0x{0:X2})' -f $t) }
        }
    }
    [pscustomobject]@{ Kind = $kind; Name = $name; Modified = $mod; Created = $created; Accessed = $accessed; MftEntry = $(if ($mft) { $mft -band 0xFFFFFFFFFFFFL } else { $null }) }
}

function Join-WfxShellPath {
    param([string]$Parent, $Item)
    if (-not $Item) { return $Parent }
    $n = [string]$Item.Name
    if (-not $Parent) { if ($Item.Kind -eq 'Network' -and $n -notmatch '^\\\\') { return "\\$n" }; return $n }
    if ($Parent -in 'This PC', 'Network', 'Libraries', 'Quick access', 'Users Files' -and $Item.Kind -in 'Drive', 'Network') { return $n }
    if ($Item.Kind -in 'Drive', 'URI') { return $n }
    if ($Item.Kind -eq 'Network' -and $n -match '^\\\\') { return $n }
    return ($Parent.TrimEnd('\') + '\' + $n)
}

function ConvertFrom-WfxIdList {
    <# Splits an ITEMIDLIST (u16-size-prefixed items, ending with 0) into decoded shell items. #>
    param([byte[]]$Bytes, [int]$Offset = 0)
    $p = $Offset
    while ($p + 2 -le $Bytes.Length) {
        $sz = [BitConverter]::ToUInt16($Bytes, $p); if ($sz -lt 3 -or $p + $sz -gt $Bytes.Length) { break }
        $item = New-Object byte[] $sz; [Array]::Copy($Bytes, $p, $item, 0, $sz)
        ConvertFrom-WfxShellItem $item
        $p += $sz
    }
}

# ───────────────────────────── ShellBags ─────────────────────────────
function Get-WfxShellBagRecord {
    <#
    .SYNOPSIS Folders a user opened in Explorer (including on USB drives, network shares and deleted
    folders) from the BagMRU tree of UsrClass.dat / NTUSER.DAT. Works on an offline hive handle
    (-Hive) or on a live registry key (-LiveKey). Time = last write of the folder's BagMRU key, which is
    roughly the last time the folder's view was updated.
    #>
    param($Hive, $LiveKey, [string]$KeyPath, [string]$User = '', [string]$Source = '', [int]$Max = 20000)
    $out = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[object]
    if ($Hive) { $root = Get-WfxHiveKey $Hive $KeyPath; if (-not $root) { return }; $stack.Push(@($root, '', 0)) }
    elseif ($LiveKey) { $stack.Push(@($LiveKey, '', 0)) } else { return }
    $seen = 0
    while ($stack.Count -and $seen -lt $Max) {
        $f = $stack.Pop(); $node = $f[0]; $parentPath = $f[1]; $depth = $f[2]
        if ($depth -gt 64) { continue }
        if ($Hive) {
            $vals = @{}; foreach ($v in @(Get-WfxHiveValue $Hive $node)) { if ($v.Name -match '^\d+$') { $vals[$v.Name] = [byte[]]$v.Data } }
            $subs = @{}; foreach ($k in @(Get-WfxHiveSubkey $Hive $node)) { $subs[$k.Name] = $k }
        } else {
            $vals = @{}; foreach ($vn in @($node.GetValueNames())) { if ($vn -match '^\d+$') { $d = $node.GetValue($vn); if ($d -is [byte[]]) { $vals[$vn] = $d } } }
            $subs = @{}; foreach ($sn in @($node.GetSubKeyNames())) { if ($sn -match '^\d+$') { $subs[$sn] = $sn } }
        }
        foreach ($num in $vals.Keys) {
            $seen++
            $item = ConvertFrom-WfxShellItem $vals[$num]
            $path = Join-WfxShellPath $parentPath $item
            $child = $subs[$num]
            $childNode = $null; $lw = $null
            if ($child) {
                if ($Hive) { $childNode = $child; $lw = $child.LastWrite }
                else { try { $childNode = $node.OpenSubKey($child, $false); $lw = Get-WfxRegKeyObjectTime $childNode } catch { } }
            }
            $out.Add((New-WfxArtifact -Artifact 'ShellBag' -Time $lw -TimeKind 'Folder view updated' -Evidence 'Access' -Path $path -Name ([string]$item.Name) -User $User `
                        -Detail ("{0}{1}" -f $item.Kind, $(if ($item.Accessed) { "; folder accessed $(ConvertTo-WfxUtcString $item.Accessed)" })) -Source $Source `
                        -Extra ([pscustomobject]@{ Kind = $item.Kind; Created = (ConvertTo-WfxUtcString $item.Created); Modified = (ConvertTo-WfxUtcString $item.Modified); Accessed = (ConvertTo-WfxUtcString $item.Accessed); MftEntry = $item.MftEntry })))
            if ($childNode) { $stack.Push(@($childNode, $path, $depth + 1)) }
        }
    }
    $out.ToArray()
}

# ───────────────────────────── compound files (Jump Lists) ─────────────────────────────
function Read-WfxCompoundFile {
    <#
    .SYNOPSIS Minimal read-only [MS-CFB] reader. Returns @{ Name; Bytes } for every stream, or $null when
    the data is not a compound file. Bounded: chains are cut at the file size to defeat loops.
    #>
    param([byte[]]$Bytes)
    $b = $Bytes
    if (-not $b -or $b.Length -lt 512 -or [BitConverter]::ToString($b, 0, 8) -ne 'D0-CF-11-E0-A1-B1-1A-E1') { return $null }
    $ss = 1 -shl [BitConverter]::ToUInt16($b, 0x1E); $mss = 1 -shl [BitConverter]::ToUInt16($b, 0x20)
    if ($ss -notin 512, 4096 -or $mss -ne 64) { return $null }
    $cutoff = [BitConverter]::ToUInt32($b, 0x38)
    $maxSec = [int][Math]::Ceiling($b.Length / $ss)
    $secOff = { param([long]$s) ($s + 1) * $ss }
    # FAT sector list from the header DIFAT (109 entries) and any DIFAT sectors.
    $fatSecs = New-Object System.Collections.Generic.List[uint32]
    for ($i = 0; $i -lt 109; $i++) { $s = [BitConverter]::ToUInt32($b, 0x4C + $i * 4); if ($s -lt 0xFFFFFFFAL) { $fatSecs.Add($s) } }
    $dif = [BitConverter]::ToUInt32($b, 0x44); $guard = 0
    while ($dif -lt 0xFFFFFFFAL -and $guard++ -lt $maxSec) {
        $o = & $secOff $dif; if ($o + $ss -gt $b.Length) { break }
        for ($i = 0; $i -lt ($ss / 4) - 1; $i++) { $s = [BitConverter]::ToUInt32($b, $o + $i * 4); if ($s -lt 0xFFFFFFFAL) { $fatSecs.Add($s) } }
        $dif = [BitConverter]::ToUInt32($b, $o + $ss - 4)
    }
    $fat = New-Object System.Collections.Generic.List[uint32]
    foreach ($fs in $fatSecs) { $o = & $secOff $fs; if ($o + $ss -gt $b.Length) { continue }; for ($i = 0; $i -lt $ss / 4; $i++) { $fat.Add([BitConverter]::ToUInt32($b, $o + $i * 4)) } }
    $chain = {
        param([uint32]$Start)
        $list = New-Object System.Collections.Generic.List[uint32]; $s = $Start; $g = 0
        while ($s -lt 0xFFFFFFFAL -and $s -lt $fat.Count -and $g++ -lt $maxSec) { $list.Add($s); $s = $fat[[int]$s] }
        , $list.ToArray()
    }
    $readChain = {
        param([uint32]$Start, [long]$Size)
        $ms = New-Object IO.MemoryStream
        foreach ($s in (& $chain $Start)) { $o = & $secOff $s; if ($o + $ss -gt $b.Length) { break }; $ms.Write($b, [int]$o, $ss); if ($ms.Length -ge $Size) { break } }
        $a = $ms.ToArray(); if ($a.Length -gt $Size) { $t = New-Object byte[] $Size; [Array]::Copy($a, $t, $Size); $a = $t }; , $a
    }
    $dir = & $readChain ([BitConverter]::ToUInt32($b, 0x30)) ([long]$b.Length)
    $entries = New-Object System.Collections.Generic.List[object]
    for ($o = 0; $o + 128 -le $dir.Length; $o += 128) {
        $nl = [BitConverter]::ToUInt16($dir, $o + 0x40); $type = $dir[$o + 0x42]
        if ($type -eq 0 -or $nl -lt 2 -or $nl -gt 64) { continue }
        $size = if ($ss -eq 512) { [long][BitConverter]::ToUInt32($dir, $o + 0x78) } else { [BitConverter]::ToInt64($dir, $o + 0x78) }
        $entries.Add([pscustomobject]@{ Name = [Text.Encoding]::Unicode.GetString($dir, $o, $nl - 2); Type = $type; Start = [BitConverter]::ToUInt32($dir, $o + 0x74); Size = $size })
    }
    $root = $entries | Where-Object Type -eq 5 | Select-Object -First 1
    if (-not $root) { return $null }
    $mini = & $readChain $root.Start $root.Size
    $mfat = New-Object System.Collections.Generic.List[uint32]
    $mfStart = [BitConverter]::ToUInt32($b, 0x3C)
    if ($mfStart -lt 0xFFFFFFFAL) { foreach ($s in (& $chain $mfStart)) { $o = & $secOff $s; if ($o + $ss -gt $b.Length) { break }; for ($i = 0; $i -lt $ss / 4; $i++) { $mfat.Add([BitConverter]::ToUInt32($b, $o + $i * 4)) } } }
    foreach ($e in $entries) {
        if ($e.Type -ne 2 -or $e.Size -le 0 -or $e.Size -gt $b.Length * 4) { continue }
        if ($e.Size -lt $cutoff) {
            $ms = New-Object IO.MemoryStream; $s = $e.Start; $g = 0
            while ($s -lt 0xFFFFFFFAL -and $g++ -lt 1000000 -and $ms.Length -lt $e.Size) {
                $o = [long]$s * 64; if ($o + 64 -gt $mini.Length) { break }
                $ms.Write($mini, [int]$o, 64); if ($s -ge $mfat.Count) { break }; $s = $mfat[[int]$s]
            }
            $a = $ms.ToArray(); if ($a.Length -gt $e.Size) { $t = New-Object byte[] $e.Size; [Array]::Copy($a, $t, $e.Size); $a = $t }
        } else { $a = & $readChain $e.Start $e.Size }
        [pscustomobject]@{ Name = $e.Name; Bytes = $a }
    }
}

function Get-WfxJumpListAppName {
    <# Common AppIDs (the file-name prefix of a Jump List) — CRC-64 of the application path, so they are stable. #>
    param([string]$AppId)
    $known = @{
        '1b4dd67f29cb1962' = 'Windows Explorer'; 'f01b4d95cf55d32a' = 'Windows Explorer'; '5f7b5f1e01b83767' = 'Quick Access'; '9b9cdc69c1c24e2b' = 'Notepad (64-bit)'
        '7e4dca80246863e3' = 'Control Panel'; '5d696d521de238c3' = 'Google Chrome'; '9d1f905ce5044aee' = 'Microsoft Edge'; 'f0275e8685d95486' = 'Microsoft Edge'
        '6824f4a902c78fbd' = 'Mozilla Firefox'; '5c450709f7ae4396' = 'Mozilla Firefox'; 'a7bd71699cd38d1c' = 'Microsoft Word'; 'fb3b0dbfee58fac8' = 'Microsoft Word'
        '12dc1ea8e34b5a6' = 'Microsoft Paint'; 'd00655d2aa12ff6d' = 'Microsoft PowerPoint'; 'b8ab77100df80ab2' = 'Microsoft Excel'; 'f5ac5390b9115fdb' = 'Microsoft PowerPoint'
        '1bc392b8e104a00e' = 'Remote Desktop Connection'; '590aee7bdd69b59b' = 'PowerShell'; '9f5c7755804b850a' = 'Windows Script Host'; '6d2bac8f1edf6668' = 'Microsoft Outlook'
        '69639df789022856' = 'Windows Media Player'; 'b74736c2bd8cc8a5' = 'WinZip'; '290532160612e071' = 'WinRAR'; 'f1a4c04eebef2906' = '7-Zip'; '4b6925efc53a3c08' = 'Microsoft Excel'
        'bc0c37e84e063727' = 'Command Prompt'; '4cb9c5750d51c07f' = 'Movies & TV'; 'ccba5a5986c77e43' = 'Microsoft Teams'; '9839aec31243a928' = 'Microsoft Excel'
        '8e4e81d9adc545b8' = 'Microsoft Teams'; 'cfb56c56fa0f0478' = 'TeamViewer'; '4fd44f9f4ce5ec0d' = 'AnyDesk'; 'e2a593822e01aed3' = 'Adobe Acrobat'; 'ee462c3b81abb6f6' = 'Adobe Reader'
    }
    if ($known[$AppId]) { $known[$AppId] } else { '' }
}

function Get-WfxJumpListRecord {
    <#
    .SYNOPSIS Files and folders an application opened, from *.automaticDestinations-ms (with DestList:
    last-used time, open count, pin state) and *.customDestinations-ms (pinned / task items).
    #>
    param([string]$Path, [byte[]]$Bytes, [string]$User = '')
    if (-not $Bytes) { try { $Bytes = [IO.File]::ReadAllBytes($Path) } catch { return } }
    $file = Split-Path -Leaf $Path
    $appId = ($file -split '\.')[0].ToLowerInvariant()
    $app = Get-WfxJumpListAppName $appId
    $appLabel = if ($app) { "$app ($appId)" } else { "AppID $appId" }
    if ($file -match '(?i)\.customDestinations-ms$') {
        $offs = New-Object System.Collections.Generic.List[int]
        for ($i = 0; $i + 20 -le $Bytes.Length; $i++) { if ($Bytes[$i] -eq 0x4C -and $Bytes[$i + 1] -eq 0 -and $Bytes[$i + 2] -eq 0 -and $Bytes[$i + 3] -eq 0 -and $Bytes[$i + 4] -eq 0x01 -and $Bytes[$i + 5] -eq 0x14 -and $Bytes[$i + 6] -eq 0x02) { $offs.Add($i) } }
        for ($k = 0; $k -lt $offs.Count; $k++) {
            $end = if ($k + 1 -lt $offs.Count) { $offs[$k + 1] } else { $Bytes.Length }
            $seg = New-Object byte[] ($end - $offs[$k]); [Array]::Copy($Bytes, $offs[$k], $seg, 0, $seg.Length)
            $l = Get-WfxLnkInfo -Bytes $seg; if (-not $l -or -not $l.Target) { continue }
            New-WfxArtifact -Artifact 'JumpList' -Time $l.Written -TimeKind 'Target modified' -Evidence 'Access' -Path $l.Target -User $User `
                -Detail ("{0}; custom/pinned item{1}" -f $appLabel, $(if ($l.Arguments) { "; arguments: $($l.Arguments)" })) -Source $Path `
                -Extra ([pscustomobject]@{ App = $app; AppId = $appId; Arguments = $l.Arguments; DriveType = $l.DriveType; VolumeSerial = $l.DriveSerial; VolumeLabel = $l.VolumeLabel; MachineId = $l.MachineId; Pinned = $true; Count = $null })
        }
        return
    }
    $streams = @(Read-WfxCompoundFile $Bytes)
    if (-not $streams.Count) { return }
    $dest = @{}
    $dl = $streams | Where-Object Name -eq 'DestList' | Select-Object -First 1
    if ($dl -and $dl.Bytes.Length -ge 32) {
        $d = $dl.Bytes; $ver = [BitConverter]::ToUInt32($d, 0); $n = [BitConverter]::ToUInt32($d, 4)
        $p = 32
        for ($i = 0; $i -lt $n -and $p + 114 -le $d.Length; $i++) {
            $num = [BitConverter]::ToUInt32($d, $p + 88)
            $host_ = ([Text.Encoding]::ASCII.GetString($d, $p + 72, 16)).TrimEnd([char]0)
            $mod = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($d, $p + 100))
            $pin = [BitConverter]::ToInt32($d, $p + 108)
            if ($ver -ge 2) {
                if ($p + 130 -gt $d.Length) { break }
                $cnt = [BitConverter]::ToInt32($d, $p + 116); $plen = [BitConverter]::ToUInt16($d, $p + 128); $po = $p + 130; $tail = 4
            } else { $cnt = $null; $plen = [BitConverter]::ToUInt16($d, $p + 112); $po = $p + 114; $tail = 0 }
            if ($po + $plen * 2 -gt $d.Length) { break }
            $dpath = [Text.Encoding]::Unicode.GetString($d, $po, $plen * 2)
            $dest['{0:x}' -f $num] = [pscustomobject]@{ Time = $mod; Pinned = ($pin -ge 0); Count = $cnt; Host = $host_; Path = $dpath }
            $p = $po + $plen * 2 + $tail
        }
    }
    foreach ($s in $streams) {
        if ($s.Name -eq 'DestList' -or $s.Name -notmatch '^[0-9a-fA-F]+$') { continue }
        $l = Get-WfxLnkInfo -Bytes $s.Bytes
        $e = $dest[$s.Name.ToLowerInvariant()]
        $target = if ($l -and $l.Target -and -not ($e -and $e.Path -and $e.Path -notmatch '^::' -and $l.Target -eq $l.IdListPath)) { $l.Target } elseif ($e -and $e.Path) { $e.Path } elseif ($l) { $l.Target } else { '' }
        if (-not $target) { continue }
        $time = if ($e -and $e.Time) { $e.Time } elseif ($l) { $l.Written } else { $null }
        $bits = @($appLabel)
        if ($e -and $null -ne $e.Count) { $bits += "opened $($e.Count) time(s)" }
        if ($e -and $e.Pinned) { $bits += 'pinned' }
        if ($l -and $l.DriveType -and $l.DriveType -ne 'Fixed') { $bits += "$($l.DriveType) drive$(if ($l.VolumeLabel) { " '$($l.VolumeLabel)'" })$(if ($l.DriveSerial) { " serial $($l.DriveSerial)" })" }
        if ($l -and $l.Arguments) { $bits += "arguments: $($l.Arguments)" }
        New-WfxArtifact -Artifact 'JumpList' -Time $time -TimeKind $(if ($e -and $e.Time) { 'Last opened' } else { 'Target modified' }) -Evidence 'Access' -Path $target -User $User `
            -Detail ($bits -join '; ') -Source $Path `
            -Extra ([pscustomobject]@{ App = $app; AppId = $appId; Count = $(if ($e) { $e.Count }); Pinned = $(if ($e) { $e.Pinned } else { $false }); Host = $(if ($e) { $e.Host }); Arguments = $(if ($l) { $l.Arguments })
                DriveType = $(if ($l) { $l.DriveType }); VolumeSerial = $(if ($l) { $l.DriveSerial }); VolumeLabel = $(if ($l) { $l.VolumeLabel }); MachineId = $(if ($l) { $l.MachineId }); TargetCreated = $(if ($l) { ConvertTo-WfxUtcString $l.Created }) })
    }
}

function Get-WfxShortcutRecord {
    <# A .lnk file (Recent items, Desktop, Startup): the target, arguments and where the target lived. #>
    param([string]$Path, [byte[]]$Bytes, [string]$User = '', $FileTime = $null)
    $l = Get-WfxLnkInfo -Path $Path -Bytes $Bytes
    if (-not $l -or -not ($l.Target -or $l.Arguments)) { return }
    $bits = @()
    if ($l.Arguments) { $bits += "arguments: $($l.Arguments)" }
    if ($l.DriveType -and $l.DriveType -ne 'Fixed') { $bits += "$($l.DriveType) drive$(if ($l.VolumeLabel) { " '$($l.VolumeLabel)'" })$(if ($l.DriveSerial) { " serial $($l.DriveSerial)" })" }
    if ($l.ShowCommand -ne 'Normal') { $bits += "window: $($l.ShowCommand)" }
    if ($l.MachineId) { $bits += "created on $($l.MachineId)" }
    $time = if ($FileTime) { $FileTime } else { $l.Accessed }
    New-WfxArtifact -Artifact 'Shortcut' -Time $time -TimeKind $(if ($FileTime) { 'Shortcut modified' } else { 'Target accessed' }) -Evidence 'Access' -Path $l.Target -User $User `
        -Detail ($bits -join '; ') -Source $Path `
        -Extra ([pscustomobject]@{ Arguments = $l.Arguments; WorkingDir = $l.WorkingDir; Icon = $l.IconLocation; ShowCommand = $l.ShowCommand; DriveType = $l.DriveType; VolumeSerial = $l.DriveSerial; VolumeLabel = $l.VolumeLabel
            NetName = $l.NetName; MachineId = $l.MachineId; MacAddress = $l.MacAddress; TargetCreated = (ConvertTo-WfxUtcString $l.Created); TargetModified = (ConvertTo-WfxUtcString $l.Written); TargetSize = $l.Size })
}

# ───────────────────────────── browser downloads ─────────────────────────────
function ConvertFrom-WfxWebkitTime {
    param($Value)
    $v = 0L; if (-not [long]::TryParse([string]$Value, [ref]$v) -or $v -le 0) { return $null }
    ConvertFrom-WfxFileTime ($v * 10)
}

function Get-WfxBrowserDownloadRecord {
    <#
    .SYNOPSIS Files downloaded through Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi: the
    "History" database) or Firefox ("places.sqlite"): source URL, referrer, saved path, size, whether the
    browser flagged it as dangerous and whether it was opened.
    #>
    param([string]$Path, [byte[]]$Bytes, [string]$User = '', [string]$Browser = '')
    $db = Open-WfxSqlite -Path $Path -Bytes $Bytes
    if (-not $db) { return }
    if (-not $Browser) { $Browser = if ($Path -match '(?i)\\Edge\\') { 'Edge' } elseif ($Path -match '(?i)Brave') { 'Brave' } elseif ($Path -match '(?i)\\Opera') { 'Opera' } elseif ($Path -match '(?i)Vivaldi') { 'Vivaldi' } elseif ($Path -match '(?i)places\.sqlite$') { 'Firefox' } else { 'Chrome' } }
    $danger = @{ 1 = 'dangerous file'; 2 = 'dangerous URL'; 3 = 'dangerous content'; 4 = 'maybe dangerous'; 5 = 'uncommon'; 6 = 'user accepted a warning'; 7 = 'dangerous host'; 8 = 'potentially unwanted'; 9 = 'allowlisted by policy'; 10 = 'async scanning'; 11 = 'blocked: password-protected'; 12 = 'blocked: too large'; 13 = 'sensitive content warning'; 14 = 'sensitive content blocked'; 15 = 'deep scanned safe'; 16 = 'deep scanned: user opened dangerous'; 17 = 'prompt for scanning'; 18 = 'blocked: unsupported file type'; 19 = 'dangerous account compromise' }
    $dl = @(Get-WfxSqliteTable $db 'downloads')
    if ($dl.Count) {
        $chain = @{}
        foreach ($c in @(Get-WfxSqliteTable $db 'downloads_url_chains')) { if (-not $chain[[long]$c.id]) { $chain[[long]$c.id] = New-Object 'System.Collections.Generic.SortedList[long,string]' }; $chain[[long]$c.id][[long]$c.chain_index] = [string]$c.url }
        foreach ($d in $dl) {
            $urls = @(if ($chain[[long]$d.id]) { $chain[[long]$d.id].Values })
            $final = if ($urls.Count) { $urls[-1] } else { [string]$d.tab_url }
            $state = switch ([int]$d.state) { 1 { 'complete' } 2 { 'cancelled' } 3 { 'interrupted' } 4 { 'interrupted' } default { 'in progress' } }
            $dg = [int]$d.danger_type
            $bits = @("$Browser download ($state)")
            if ($final) { $bits += "from $final" }
            if ($d.referrer) { $bits += "referrer $($d.referrer)" }
            if ($dg -and $danger[$dg]) { $bits += "browser warning: $($danger[$dg])" }
            if ([int]$d.opened) { $bits += 'opened from the browser' }
            New-WfxArtifact -Artifact 'Download' -Time (ConvertFrom-WfxWebkitTime $d.start_time) -TimeKind 'Download started' -Evidence 'Download' -Path ([string]$d.target_path) -User $User `
                -Detail ($bits -join '; ') -Source $Path `
                -Extra ([pscustomobject]@{ Browser = $Browser; Url = $final; FirstUrl = $(if ($urls.Count) { $urls[0] }); Referrer = [string]$d.referrer; TabUrl = [string]$d.tab_url; Mime = [string]$d.mime_type
                    Bytes = $d.received_bytes; TotalBytes = $d.total_bytes; State = $state; Danger = $(if ($dg) { $danger[$dg] }); Opened = [bool][int]$d.opened; Finished = (ConvertTo-WfxUtcString (ConvertFrom-WfxWebkitTime $d.end_time)) })
        }
        return
    }
    $attrs = @{}; foreach ($a in @(Get-WfxSqliteTable $db 'moz_anno_attributes')) { $attrs[[long]$a.id] = [string]$a.name }
    if (-not $attrs.Count) { return }
    $dest = ($attrs.GetEnumerator() | Where-Object Value -eq 'downloads/destinationFileURI' | Select-Object -First 1).Key
    if (-not $dest) { return }
    $meta = ($attrs.GetEnumerator() | Where-Object Value -eq 'downloads/metaData' | Select-Object -First 1).Key
    $annos = @(Get-WfxSqliteTable $db 'moz_annos')
    $need = @{}; foreach ($a in $annos) { if ([long]$a.anno_attribute_id -eq $dest) { $need[[long]$a.place_id] = $a } }
    if (-not $need.Count) { return }
    # moz_places can hold hundreds of thousands of rows: look up only the downloaded ones by rowid.
    $places = @{}; $ps = Get-WfxSqliteSchema $db 'moz_places'
    if ($ps) { $ui = [array]::IndexOf($ps.Names, 'url'); foreach ($id in $need.Keys) { $v = Find-WfxSqliteRow $db $ps.Root ([long]$id); if ($v -and $ui -ge 0) { $places[[long]$id] = [pscustomobject]@{ url = $v[$ui] } } } }
    $metaBy = @{}; if ($meta) { foreach ($a in $annos) { if ([long]$a.anno_attribute_id -eq $meta) { $metaBy[[long]$a.place_id] = [string]$a.content } } }
    foreach ($k in $need.Keys) {
        $a = $need[$k]; $url = [string]$places[$k].url
        $file = [string]$a.content
        try { if ($file -match '^file:') { $file = ([uri]$file).LocalPath } } catch { }
        $state = ''; $size = $null
        if ($metaBy[$k]) { try { $m = $metaBy[$k] | ConvertFrom-Json; $state = switch ([int]$m.state) { 1 { 'complete' } 3 { 'cancelled' } 4 { 'paused' } 8 { 'blocked' } 9 { 'blocked by policy' } 0 { 'in progress' } default { "state $($m.state)" } }; $size = $m.fileSize } catch { } }
        $added = $null; $us = 0L; if ([long]::TryParse([string]$a.dateAdded, [ref]$us) -and $us -gt 0) { $added = [DateTimeOffset]::FromUnixTimeMilliseconds([long]($us / 1000)).UtcDateTime }
        New-WfxArtifact -Artifact 'Download' -Time $added -TimeKind 'Download started' -Evidence 'Download' -Path $file -User $User `
            -Detail ("Firefox download$(if ($state) { " ($state)" }); from $url") -Source $Path `
            -Extra ([pscustomobject]@{ Browser = 'Firefox'; Url = $url; Bytes = $size; State = $state })
    }
}

# ───────────────────────────── Program Compatibility Assistant (Windows 11 22H2+) ─────────────────────────────
function Read-WfxTextFile {
    <# Reads a log file that may be UTF-16 (with or without BOM) or UTF-8 / ANSI, with sharing. #>
    param([string]$Path, [byte[]]$Bytes, [int]$MaxMB = 64)
    if (-not $Bytes) {
        try {
            $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try { $len = [int][Math]::Min($fs.Length, $MaxMB * 1MB); $Bytes = New-Object byte[] $len; $n = 0; while ($n -lt $len) { $r = $fs.Read($Bytes, $n, $len - $n); if ($r -le 0) { break }; $n += $r } } finally { $fs.Dispose() }
        } catch { return '' }
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3) }
    $zeros = 0; $probe = [Math]::Min(400, $Bytes.Length); for ($i = 1; $i -lt $probe; $i += 2) { if ($Bytes[$i] -eq 0) { $zeros++ } }
    if ($probe -gt 10 -and $zeros -gt $probe / 4) { return [Text.Encoding]::Unicode.GetString($Bytes, 0, $Bytes.Length - ($Bytes.Length % 2)) }
    [Text.Encoding]::UTF8.GetString($Bytes)
}

function Get-WfxPcaRecord {
    <#
    .SYNOPSIS Program Compatibility Assistant logs (C:\Windows\appcompat\pca): PcaAppLaunchDic.txt
    (path|last launch, UTC) and PcaGeneralDb0/1.txt (time|status|path|description|vendor|version|...).
    Execution evidence for programs launched from Explorer.
    #>
    param([string]$Path, [string]$Text)
    if (-not $Text) { $Text = Read-WfxTextFile -Path $Path }
    $leaf = Split-Path -Leaf $Path
    foreach ($line in ($Text -split "`r?`n")) {
        $line = $line.Trim([char]0, ' '); if (-not $line) { continue }
        $f = $line -split '\|'
        if ($leaf -match '(?i)AppLaunchDic' -and $f.Count -ge 2) {
            New-WfxArtifact -Artifact 'PCA' -Time (ConvertTo-WfxDateTime ($f[1] + 'Z')) -TimeKind 'Last launched' -Evidence 'Execution' -Path $f[0] -Detail 'Launched from Explorer (PcaAppLaunchDic)' -Source $Path
        } elseif ($f.Count -ge 3 -and $f[0] -match '^\d{4}-\d\d-\d\d') {
            $desc = @(@($f[3], $f[4], $f[5]) | Where-Object { $_ }) -join ' · '
            $status = switch ($f[1]) { '0' { 'installer' } '1' { 'driver blocked' } '2' { 'abnormal process exit' } '3' { 'PCA resolve call' } default { "status $($f[1])" } }
            New-WfxArtifact -Artifact 'PCA' -Time (ConvertTo-WfxDateTime ($f[0] + 'Z')) -TimeKind 'Recorded' -Evidence 'Execution' -Path ([Environment]::ExpandEnvironmentVariables($f[2])) `
                -Detail ("$status$(if ($desc) { "; $desc" }) (PcaGeneralDb)") -Source $Path -Extra ([pscustomobject]@{ Status = $status; Description = $f[3]; Vendor = $f[4]; Version = $f[5]; ExitCode = $(if ($f.Count -gt 7) { $f[7] }) })
        }
    }
}

# ───────────────────────────── Microsoft Defender support logs ─────────────────────────────
function Get-WfxDefenderLogRecord {
    <#
    .SYNOPSIS Microsoft Defender MPLog / MPDetection logs (ProgramData\Microsoft\Windows Defender\Support).
    Keeps detections (threat name + file) and the "EstimatedImpact" lines that name processes Defender saw
    running — useful when the event logs were cleared, because these logs are separate files.
    #>
    param([string]$Path, [string]$Text, [int]$Max = 20000)
    if (-not $Text) { $Text = Read-WfxTextFile -Path $Path }
    $n = 0; $seen = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($n -ge $Max) { break }
        $m = [regex]::Match($line, '^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)\s+(.*)$')
        if (-not $m.Success) { continue }
        $time = ConvertTo-WfxDateTime ($m.Groups[1].Value.TrimEnd('Z') + 'Z'); $rest = $m.Groups[2].Value
        $d = [regex]::Match($rest, '(?i)\b(DETECTION(?:EVENT|_ADD|_CLEAN)?\S*)\s+(?:MPSOURCE_\S+\s+)?([A-Za-z]+:[A-Za-z0-9]+/[^\s;!]+(?:![A-Za-z0-9.]+)?)\s*(?:(file|process|regkey|containerfile|behavior|amsi_script|webfile|startup)\s*:\s*)?([^;]*)')
        if ($d.Success) {
            $n++
            New-WfxArtifact -Artifact 'DefenderLog' -Time $time -TimeKind 'Detected' -Evidence 'Detection' -Path ($d.Groups[4].Value.Trim()) -Name ($d.Groups[2].Value) `
                -Detail ("{0}: {1}{2}" -f $d.Groups[1].Value, $d.Groups[2].Value, $(if ($d.Groups[3].Value) { " ($($d.Groups[3].Value))" })) -Source $Path `
                -Extra ([pscustomobject]@{ Threat = $d.Groups[2].Value; Kind = $d.Groups[3].Value; Action = $d.Groups[1].Value })
            continue
        }
        $p = [regex]::Match($rest, '(?i)ProcessImageName:\s*([^,]+),.*?(?:\bPid:\s*(\d+))?')
        if ($p.Success) {
            $img = $p.Groups[1].Value.Trim(); $key = $img.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true; $n++
            New-WfxArtifact -Artifact 'DefenderLog' -Time $time -TimeKind 'Seen running' -Evidence 'Execution' -Path $img `
                -Detail 'Process named in a Defender performance (EstimatedImpact) line; first sighting in this log' -Source $Path
        }
    }
}

# ───────────────────────────── user registry (offline NTUSER.DAT) and BAM (offline SYSTEM) ─────────────────────────────
function ConvertFrom-WfxRot13 { param([string]$Text) -join ($Text.ToCharArray() | ForEach-Object { $c = [int]$_; if ($c -ge 65 -and $c -le 90) { [char](65 + ($c - 52) % 26) } elseif ($c -ge 97 -and $c -le 122) { [char](97 + ($c - 84) % 26) } else { $_ } }) }

function Get-WfxNtuserRecord {
    <#
    .SYNOPSIS From an offline NTUSER.DAT: UserAssist (GUI program launches with run count), RunMRU (commands
    typed in Win+R), TypedPaths (paths typed in the Explorer address bar) and WordWheelQuery (Explorer searches).
    #>
    param($Hive, [string]$Source, [string]$User = '')
    $exp = 'Software\Microsoft\Windows\CurrentVersion\Explorer'
    $ua = Get-WfxHiveKey $Hive "$exp\UserAssist"
    foreach ($g in @(Get-WfxHiveSubkey $Hive $ua)) {
        $ck = @(Get-WfxHiveSubkey $Hive $g | Where-Object Name -eq 'Count')[0]; if (-not $ck) { continue }
        foreach ($v in @(Get-WfxHiveValue $Hive $ck)) {
            $d = [byte[]]$v.Data; if ($d.Length -lt 68) { continue }
            $ft = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($d, 60)); if (-not $ft) { continue }
            $name = ConvertFrom-WfxRot13 $v.Name
            $name = $name -replace '^\{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7\}', '%SystemRoot%\System32' -replace '^\{6D809377-6AF0-444B-8957-A3773F02200E\}', '%ProgramFiles%' -replace '^\{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E\}', '%ProgramFiles(x86)%' -replace '^\{F38BF404-1D43-42F2-9305-67DE0B28FC23\}', '%SystemRoot%'
            New-WfxArtifact -Artifact 'UserAssist' -Time $ft -TimeKind 'Last run' -Evidence 'Execution' -Path $name -User $User -Detail "run count $([BitConverter]::ToInt32($d, 4)); focus time $([Math]::Round([BitConverter]::ToUInt32($d, 12) / 1000)) s" -Source "$Source\$exp\UserAssist"
        }
    }
    $run = Get-WfxHiveKey $Hive "$exp\RunMRU"
    if ($run) {
        $order = [string](Get-WfxHiveValue $Hive $run -Name 'MRUList').Data
        $vals = @{}; foreach ($v in @(Get-WfxHiveValue $Hive $run)) { if ($v.Name -match '^[a-z]$') { $vals[$v.Name] = ([string]$v.Data) -replace '\\1$', '' } }
        $i = 0
        foreach ($ch in $order.ToCharArray()) {
            $k = [string]$ch; if (-not $vals.ContainsKey($k)) { continue }
            New-WfxArtifact -Artifact 'RunMRU' -Time $(if ($i -eq 0) { $run.LastWrite } else { $null }) -TimeKind $(if ($i -eq 0) { 'Most recent (key write)' } else { 'Earlier' }) -Evidence 'Execution' -Path $vals[$k] -Name $vals[$k] -User $User `
                -Detail "Typed in the Run dialog (Win+R), order $($i + 1) of $($order.Length)" -Source "$Source\$exp\RunMRU"
            $i++
        }
    }
    $tp = Get-WfxHiveKey $Hive 'Software\Microsoft\Internet Explorer\TypedURLs'
    $tp2 = Get-WfxHiveKey $Hive "$exp\TypedPaths"
    foreach ($k in @($tp2) | Where-Object { $_ }) {
        foreach ($v in @(Get-WfxHiveValue $Hive $k | Sort-Object { [int](($_.Name -replace '\D', '0')) })) {
            New-WfxArtifact -Artifact 'TypedPath' -Time $(if ($v.Name -eq 'url1') { $k.LastWrite }) -TimeKind 'Most recent (key write)' -Evidence 'Access' -Path ([string]$v.Data) -User $User -Detail "Typed in the Explorer address bar ($($v.Name))" -Source "$Source\$exp\TypedPaths"
        }
    }
    $ww = Get-WfxHiveKey $Hive "$exp\WordWheelQuery"
    if ($ww) {
        foreach ($v in @(Get-WfxHiveValue $Hive $ww)) {
            if ($v.Name -notmatch '^\d+$') { continue }
            $q = ([Text.Encoding]::Unicode.GetString([byte[]]$v.Data)).TrimEnd([char]0)
            New-WfxArtifact -Artifact 'Search' -Time $null -TimeKind '' -Evidence 'Access' -Path $q -Name $q -User $User -Detail 'Searched for in Explorer (WordWheelQuery)' -Source "$Source\$exp\WordWheelQuery"
        }
    }
    $null = $tp
}

function Get-WfxSystemHiveBam {
    <# BAM/DAM from an offline SYSTEM hive: full path and last execution time per user SID. #>
    param($Hive, [string]$Source)
    $cur = 1; $sel = Get-WfxHiveKey $Hive 'Select'; if ($sel) { $c = (Get-WfxHiveValue $Hive $sel -Name 'Current').Data; if ($c) { $cur = [int]$c } }
    foreach ($rel in 'Services\bam\State\UserSettings', 'Services\bam\UserSettings') {
        $root = Get-WfxHiveKey $Hive ('ControlSet{0:D3}\{1}' -f $cur, $rel); if (-not $root) { continue }
        foreach ($sid in @(Get-WfxHiveSubkey $Hive $root)) {
            foreach ($v in @(Get-WfxHiveValue $Hive $sid)) {
                $d = [byte[]]$v.Data; if ($v.Type -ne 'REG_BINARY' -or $d.Length -lt 8) { continue }
                $t = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($d, 0)); if (-not $t) { continue }
                New-WfxArtifact -Artifact 'BAM' -Time $t -TimeKind 'Last run' -Evidence 'Execution' -Path ($v.Name -replace '^\\Device\\HarddiskVolume\d+', '(volume)') -User $sid.Name -Detail 'Background Activity Moderator' -Source "$Source\...\$rel"
            }
        }
        break
    }
}

# ───────────────────────────── collection: live host ─────────────────────────────
function Get-WfxArtifactData {
    <#
    .SYNOPSIS Collects execution / user-activity artifacts from the live host. Read-only; every source that
    cannot be read is recorded as a gap with the reason.
    #>
    param([int]$MaxPerSource = 5000)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Test-WfxWindows)) { return , $out.ToArray() }
    $add = { param($rows) foreach ($r in @($rows | Select-Object -First $MaxPerSource)) { if ($r) { $out.Add($r) } } }
    # ShimCache from the live registry value.
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache', $false)
        $v = if ($k) { $k.GetValue('AppCompatCache') } else { $null }
        if ($v -is [byte[]]) { & $add (Get-WfxShimCacheRecord -Bytes $v -Source 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache') }
        else { Add-WfxGap -Source 'ShimCache' -Reason 'AppCompatCache value not readable (needs administrator rights).' }
    } catch { Add-WfxGap -Source 'ShimCache' -Reason $_.Exception.Message }
    # Amcache: Windows keeps the hive open without sharing; try, and say how to get it if locked.
    $am = Join-Path $env:SystemRoot 'appcompat\Programs\Amcache.hve'
    if (Test-Path -LiteralPath $am) {
        $h = Open-WfxHive -Path $am
        if ($h) { & $add (Get-WfxAmcacheRecord -Hive $h -Source $am) }
        else { Add-WfxGap -Source 'Amcache' -Reason 'Amcache.hve is locked by Windows. Copy it with a raw-copy tool (KAPE, FTK Imager) and analyze the copy: Invoke-WfxTriage -ArtifactPath <folder>.' }
    }
    # PCA (Windows 11 22H2+)
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'appcompat\pca') -Filter 'Pca*.txt' -File -ErrorAction SilentlyContinue)) { & $add (Get-WfxPcaRecord -Path $f.FullName) }
    # Defender support logs
    $sup = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Support'
    if (Test-Path -LiteralPath $sup) {
        $logs = @(Get-ChildItem -LiteralPath $sup -File -ErrorAction SilentlyContinue | Where-Object Name -match '(?i)^MP(Log|Detection)-.*\.log$')
        if (-not $logs.Count) { Add-WfxGap -Source 'Defender logs' -Reason 'No MPLog files readable (needs administrator rights).' }
        foreach ($f in $logs) { & $add (Get-WfxDefenderLogRecord -Path $f.FullName) }
    }
    # Prefetch file names (full parsing of compressed Prefetch is out of scope; name + times are reliable).
    & $add (Get-WfxPrefetchRecord -Folder (Join-Path $env:SystemRoot 'Prefetch'))
    # Per user: ShellBags, Jump Lists, Recent shortcuts, browser downloads.
    $loaded = @{}
    foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) { $loaded[$h.PSChildName] = $true }
    foreach ($prof in @(Get-WfxUserProfilePath)) {
        $user = Split-Path -Leaf $prof
        $sid = $null
        try { $sid = (New-Object Security.Principal.NTAccount($user)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
        foreach ($bag in @(@('UsrClass', "$prof\AppData\Local\Microsoft\Windows\UsrClass.dat", "${sid}_Classes", 'Local Settings\Software\Microsoft\Windows\Shell\BagMRU'),
                @('NTUSER', "$prof\NTUSER.DAT", $sid, 'Software\Microsoft\Windows\Shell\BagMRU'))) {
            try {
                if ($bag[2] -and $loaded[$bag[2]]) {
                    $rk = [Microsoft.Win32.Registry]::Users.OpenSubKey("$($bag[2])\$($bag[3])", $false)
                    if ($rk) { & $add (Get-WfxShellBagRecord -LiveKey $rk -User $user -Source "HKU\$($bag[2])\$($bag[3])") }
                } elseif (Test-Path -LiteralPath $bag[1]) {
                    $hv = Open-WfxHive -Path $bag[1]
                    if ($hv) {
                        & $add (Get-WfxShellBagRecord -Hive $hv -KeyPath $bag[3] -User $user -Source $bag[1])
                        if ($bag[0] -eq 'NTUSER') { & $add (Get-WfxNtuserRecord -Hive $hv -Source $bag[1] -User $user) }
                    }
                }
            } catch { Add-WfxGap -Source "ShellBags ($user)" -Reason $_.Exception.Message }
        }
        $recent = Join-Path $prof 'AppData\Roaming\Microsoft\Windows\Recent'
        foreach ($sub in 'AutomaticDestinations', 'CustomDestinations') {
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $recent $sub) -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 200)) {
                try { & $add (Get-WfxJumpListRecord -Path $f.FullName -User $user) } catch { Write-Verbose "jumplist: $($f.FullName): $_" }
            }
        }
        foreach ($f in @(Get-ChildItem -LiteralPath $recent -Filter *.lnk -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1000)) {
            & $add (Get-WfxShortcutRecord -Path $f.FullName -User $user -FileTime $f.LastWriteTimeUtc)
        }
        foreach ($db in @(Get-WfxBrowserDatabase -ProfilePath $prof)) {
            try { & $add (Get-WfxBrowserDownloadRecord -Path $db.FullName -User $user) } catch { Add-WfxGap -Source "Browser ($user)" -Reason "$($db.FullName): $($_.Exception.Message)" }
        }
    }
    , $out.ToArray()
}

function Get-WfxBrowserDatabase {
    param([string]$ProfilePath)
    $local = Join-Path $ProfilePath 'AppData\Local'; $roam = Join-Path $ProfilePath 'AppData\Roaming'
    foreach ($root in "$local\Google\Chrome\User Data", "$local\Microsoft\Edge\User Data", "$local\BraveSoftware\Brave-Browser\User Data", "$local\Vivaldi\User Data", "$roam\Opera Software\Opera Stable", "$local\Chromium\User Data") {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Filter History -File -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 512MB }
    }
    $ff = Join-Path $roam 'Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $ff) { Get-ChildItem -LiteralPath $ff -Filter places.sqlite -File -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 512MB } }
}

function Get-WfxPrefetchRecord {
    <# Prefetch: one file per program run from a given path. Name = executable; file times = first / last run. #>
    param([string]$Folder, [object[]]$Files)
    if (-not $Files) { $Files = @(Get-ChildItem -LiteralPath $Folder -Filter *.pf -File -ErrorAction SilentlyContinue) }
    foreach ($f in $Files) {
        $exe = $f.Name -replace '-[0-9A-Fa-f]{8}\.pf$', ''
        New-WfxArtifact -Artifact 'Prefetch' -Time $f.LastWriteTimeUtc -TimeKind 'Last run' -Evidence 'Execution' -Path $exe -Name $exe `
            -Detail "first run about $(ConvertTo-WfxUtcString $f.CreationTimeUtc) (file created); prefetch hash $(($f.BaseName -split '-')[-1])" -Source $f.FullName
    }
}

# ───────────────────────────── collection: files from another system ─────────────────────────────
function Import-WfxArtifact {
    <#
    .SYNOPSIS Parses artifacts from a folder of collected evidence (KAPE / Velociraptor output, a mounted
    image, CTF files) or a single file. Files are recognised by their content and name: registry hives
    (SYSTEM, Amcache.hve, NTUSER.DAT, UsrClass.dat), Jump Lists, .lnk, browser databases, PCA and Defender
    logs, Prefetch. Nothing in the folder is executed or modified.
    .OUTPUTS Artifact records. Event logs (*.evtx) are listed in $script:WfxImportEvtx for the caller.
    #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxFiles = 20000)
    $script:WfxImportEvtx = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path)) { Add-WfxGap -Source 'artifacts' -Reason "Path not found: $Path"; return }
    $files = if (Test-Path -LiteralPath $Path -PathType Leaf) { @(Get-Item -LiteralPath $Path) } else { @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First $MaxFiles) }
    $pf = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        $name = $f.Name; $full = $f.FullName
        $user = if ($full -match '(?i)[\\/]Users[\\/]([^\\/]+)[\\/]') { $Matches[1] } else { '' }
        try {
            if ($name -match '(?i)\.evtx$') { $script:WfxImportEvtx.Add($full); continue }
            if ($name -match '(?i)\.pf$') { $pf.Add($f); continue }
            if ($name -match '(?i)\.(automaticDestinations-ms|customDestinations-ms)$') { Get-WfxJumpListRecord -Path $full -User $user; continue }
            if ($name -match '(?i)\.lnk$') { Get-WfxShortcutRecord -Path $full -User $user -FileTime $f.LastWriteTimeUtc; continue }
            if ($name -match '(?i)^Pca(AppLaunchDic|GeneralDb\d*)\.txt$') { Get-WfxPcaRecord -Path $full; continue }
            if ($name -match '(?i)^MP(Log|Detection)-.*\.log$') { Get-WfxDefenderLogRecord -Path $full; continue }
            if ($name -match '(?i)^(History|places\.sqlite)$') { Get-WfxBrowserDownloadRecord -Path $full -User $user; continue }
            if ($name -match '(?i)\.(log\d?|tmp|bak|blf|regtrans-ms)$' -or $f.Length -lt 8192 -or $f.Length -gt 1GB) { continue }
            $head = New-Object byte[] 4
            $fs = [IO.File]::Open($full, 'Open', 'Read', 'ReadWrite'); try { $null = $fs.Read($head, 0, 4) } finally { $fs.Dispose() }
            if ([Text.Encoding]::ASCII.GetString($head) -ne 'regf') { continue }
            $h = Open-WfxHive -Path $full; if (-not $h) { continue }
            if ($h.Dirty) { Add-WfxGap -Source 'artifacts' -Reason "$name is a 'dirty' hive and no transaction log continues it (copy $name.LOG1 and $name.LOG2 from the same folder at the same time): the newest registry writes may be missing." -Fix 'Collect the hive together with its .LOG1/.LOG2 files.' }
            elseif ($h.Replayed) { Write-Verbose "$full : replayed $($h.Replayed) transaction-log entries" }
            switch (Get-WfxHiveKind $h) {
                'SYSTEM' {
                    Get-WfxSystemHiveShimCache -Hive $h -Source $full; Get-WfxSystemHiveBam -Hive $h -Source $full
                    $cn = Get-WfxHiveKey $h 'ControlSet001\Control\ComputerName\ComputerName'
                    if ($cn) { $v = (Get-WfxHiveValue $h $cn -Name 'ComputerName').Data; if ($v) { $script:WfxImportHost = [string]$v } }
                }
                'SOFTWARE' {
                    $cv = Get-WfxHiveKey $h 'Microsoft\Windows NT\CurrentVersion'
                    if ($cv) { $vals = @{}; foreach ($x in @(Get-WfxHiveValue $h $cv)) { $vals[$x.Name] = $x.Data }; $script:WfxImportOs = (@($vals['ProductName'], $vals['DisplayVersion'], $(if ($vals['CurrentBuild']) { "build $($vals['CurrentBuild'])" })) | Where-Object { $_ }) -join ' ' }
                }
                'AMCACHE' { Get-WfxAmcacheRecord -Hive $h -Source $full }
                'USRCLASS' { Get-WfxShellBagRecord -Hive $h -KeyPath 'Local Settings\Software\Microsoft\Windows\Shell\BagMRU' -User $user -Source $full }
                'NTUSER' { Get-WfxShellBagRecord -Hive $h -KeyPath 'Software\Microsoft\Windows\Shell\BagMRU' -User $user -Source $full; Get-WfxNtuserRecord -Hive $h -Source $full -User $user }
            }
        } catch { Add-WfxGap -Source 'artifacts' -Reason "${full}: $($_.Exception.Message)" }
    }
    if ($pf.Count) { Get-WfxPrefetchRecord -Files $pf.ToArray() }
}
