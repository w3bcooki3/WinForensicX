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

function Get-WfxHiveControlSets {
    <# Control set numbers in a SYSTEM hive, the current one first (Select\Current), then the others (older copies). #>
    param($Hive)
    $cur = 1
    $sel = Get-WfxHiveKey $Hive 'Select'
    if ($sel) { $c = (Get-WfxHiveValue $Hive $sel -Name 'Current').Data; if ($c) { $cur = [int]$c } }
    $all = @(Get-WfxHiveSubkey $Hive (Get-WfxHiveNode $Hive $Hive.Root) | Where-Object { $_.Name -match '^ControlSet(\d{3})$' } | ForEach-Object { [int]$_.Name.Substring(10) })
    @($cur) + @($all | Where-Object { $_ -ne $cur } | Sort-Object)
}

function Get-WfxSystemHiveShimCache {
    <#
    ShimCache from every control set of an offline SYSTEM hive. The current set comes first, in its own order
    (position 0 = most recent). Other sets (LastKnownGood, older copies) add only the entries the current set no
    longer holds, which can include programs that have since been pushed out of the cache.
    #>
    param($Hive, [string]$Source)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $first = $true
    foreach ($n in (Get-WfxHiveControlSets $Hive)) {
        $set = 'ControlSet{0:D3}' -f $n
        $k = Get-WfxHiveKey $Hive "$set\Control\Session Manager\AppCompatCache"
        if (-not $k) { $k = Get-WfxHiveKey $Hive "$set\Control\Session Manager\AppCompatibility" }
        if (-not $k) { continue }
        $v = Get-WfxHiveValue $Hive $k -Name 'AppCompatCache'
        if (-not $v) { continue }
        foreach ($r in (Get-WfxShimCacheRecord -Bytes ([byte[]]$v.Data) -Source "$Source\$set\...\AppCompatCache")) {
            if (-not $seen.Add("$($r.Path)|$($r.Time)".ToLowerInvariant())) { continue }
            if (-not $first) { $r.Detail = (($r.Detail, "only in $set (an older copy of the cache)") | Where-Object { $_ }) -join '; ' }
            $r
        }
        $first = $false
    }
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
                -Detail (@(@($v['Publisher'], $v['ProductName'], $v['Version']) | Where-Object { $_ }) -join '; ') -Source "$Source\Root\InventoryApplicationFile" `
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
                -Path ([string]$v['RootDirPath']) -Name $nm -Detail (@(@($v['Publisher'], $v['Version'], $v['Source']) | Where-Object { $_ }) -join '; ') `
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
                    -Detail (@(@($v['1'], $v['0']) | Where-Object { $_ }) -join '; ') -Source "$Source\Root\File" `
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
                -Detail (@(@($v['DriverCompany'], $v['Product'], $v['DriverVersion'], $(if ($signed -eq $false) { 'unsigned' })) | Where-Object { $_ }) -join '; ') -Source "$Source\Root\InventoryDriverBinary" `
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
    # Known folders (KNOWNFOLDERID)
    '1777F761-68AD-4D8A-87BD-30B759FA33DD' = 'Favorites'; '18989B1D-99B5-455B-841C-AB7C74E4DDFC' = 'Videos'; '2112AB0A-C86A-4FFE-A368-0DE96E47012E' = 'Music Library'
    '491E922F-5643-4AF4-A7EB-4E7A138D8174' = 'Videos Library'; '4BD8D571-6D19-48D3-BE97-422220080E43' = 'Music'; '4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4' = 'Saved Games'
    '56784854-C6CB-462B-8169-88E350ACB882' = 'Contacts'; '7B0DB17D-9CD2-4A93-9733-46CC89022E7C' = 'Documents Library'; '7D1D3A04-DEBB-4115-95CF-2F29DA2920DA' = 'Searches'
    'A990AE9F-A03B-4E80-94BC-9912D7504104' = 'Pictures Library'; 'BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968' = 'Links'; '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7' = 'System32'
    'D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27' = 'SysWOW64'; 'F38BF404-1D43-42F2-9305-67DE0B28FC23' = 'Windows'; '6D809377-6AF0-444B-8957-A3773F02200E' = 'Program Files'
    '7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E' = 'Program Files (x86)'; '905E63B6-C1BF-494E-B29C-65B732D3D21A' = 'Program Files'; '62AB5D82-FDC1-4DC3-A9DD-070D1D495D97' = 'ProgramData'
    '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D' = 'AppData\Roaming'; 'F1B32785-6FBA-4FCF-9D55-7B8E7F157091' = 'AppData\Local'; 'A520A1A4-1780-4FF6-BD18-167343C5AF16' = 'AppData\LocalLow'
    'DFDF76A2-C82A-4D63-906A-5644AC457385' = 'Public'; 'C4AA340D-F20F-4863-AFEF-F87EF2E6BA25' = 'Public Desktop'; 'ED4824AF-DCE4-45A8-81E2-FC7965083634' = 'Public Documents'
    '3D644C9B-1FB8-4F30-9B45-F670235F79C0' = 'Public Downloads'; 'AE50C081-EBD2-438A-8655-8A092E34987A' = 'Recent Items'; 'B97D20BB-F46A-4C97-BA10-5E3608430854' = 'Startup'
    '82A5EA35-D9CD-47C5-9629-E15D2F714E6E' = 'Startup (all users)'; 'A77F5D77-2E2B-44C3-A6A2-ABA601054A51' = 'Start Menu Programs'; '0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8' = 'Start Menu Programs (all users)'
    '625B53C3-AB48-4EC1-BA1F-A1EF4146FC19' = 'Start Menu'; 'A4115719-D62E-491D-AA7C-E74B8BE3B067' = 'Start Menu (all users)'; '8983036C-27C0-404B-8F08-102D10DCFD74' = 'SendTo'
    '52A4F021-7B75-48A9-9F6B-4B87A210BC8F' = 'Quick Launch'; '0AC0837C-BBF8-452A-850D-79D08E667CA7' = 'This PC'; 'C5ABBF53-E17F-4121-8900-86626FC2C973' = 'Network Shortcuts'
    'D9DC8A3B-B784-432E-A781-5A1130A75963' = 'History'; '352481E8-33BE-4251-BA85-6007CAEDCF9D' = 'Temporary Internet Files'; '2B0F765D-C0E9-4171-908E-08A611B84FF6' = 'Cookies'
    '1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE' = 'Libraries'; 'A302545D-DEFF-464B-ABE8-61C8648D939B' = 'Libraries'; '9E52AB10-F80D-49DF-ACB8-4330F5687855' = 'CD Burning'
    '4BFEFB45-347D-4006-A5BE-AC0CB0567192' = 'Conflicts'; '82A74AEB-AEB4-465C-A014-D097EE346D63' = 'Control Panel'; '2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39' = 'Original Images'
    # Shell folders
    '17CD9488-1228-4B2F-88CE-4298E93E0966' = 'Default Programs'; '323CA680-C24D-4099-B94D-446DD2D7249E' = 'Common Places'; '871C5380-42A0-1069-A2EA-08002B30309D' = 'Internet Explorer (Homepage)'
    '9343812E-1C37-4A49-A12E-4B2D810D956B' = 'Search Home'; 'B4FB3F98-C1EA-428D-A78A-D1F5659CBA93' = 'Other Users Folder'; 'ED228FDF-9EA8-4870-83B1-96B02CFE0D52' = 'Games'
    '04731B67-D933-450A-90E6-4ACD2E9408FE' = 'Search Folder'; '9113A02D-00A3-46B9-BC5F-9C04DADDD5D7' = 'Enhanced Storage Data Source'
    # Control Panel items
    '025A5937-A6BE-4686-A844-36FE4BEC8B6D' = 'Power Options'; '05D7B0F4-2121-4EFF-BF6B-ED3F69B894D9' = 'Notification Area Icons'; '1206F5F1-0569-412C-8FEC-3204630DFB70' = 'Credential Manager'
    '1FA9085F-25A2-489B-85D4-86326EEDCD87' = 'Manage Wireless Networks'; '241D7C96-F8BF-4F85-B01F-E2B043341A4B' = 'RemoteApp and Desktop Connections'; '36EEF7DB-88AD-4E81-AD49-0E313F0C35F8' = 'Windows Update'
    '4026492F-2F69-46B8-B9BF-5654FC07E423' = 'Windows Firewall'; '58E3C745-D971-4081-9034-86E34B30836A' = 'Speech Recognition'; '60632754-C523-4B62-B45C-4172DA012619' = 'User Accounts'
    '67CA7650-96E6-4FDD-BB43-A8E774F73A57' = 'HomeGroup'; '7007ACC7-3202-11D1-AAD2-00805FC1270E' = 'Network Connections'; '78F3955E-3B90-4184-BD14-5397C15F1EFC' = 'Performance Information and Tools'
    '8E908FC9-BECC-40F6-915B-F4CA0E70D03D' = 'Network and Sharing Center'; '96AE8D84-A250-4520-95A5-A47A7E3C548B' = 'Parental Controls'; '9C60DE1E-E5FC-40F4-A487-460851A8D915' = 'AutoPlay'
    '9FE63AFD-59CF-4419-9775-ABCC3849F861' = 'Recovery'; 'A8A91A66-3A7D-4424-8D24-04E180695C7A' = 'Devices and Printers'; 'B98A2BEA-7D42-4558-8BD1-832F41BAC6FD' = 'Backup and Restore'
    'BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6' = 'Action Center'; 'C555438B-3C23-4769-A71F-B6D3D9B6053A' = 'Display'; 'C58C4893-3BE0-4B45-ABB5-A63E4B8C8651' = 'Troubleshooting'
    'D555645E-D4F8-4C29-A827-D93C859C4F2A' = 'Ease of Access Center'; 'E211B736-43FD-11D1-9EFB-0000F8757FCD' = 'Scanners and Cameras'; 'E7DE9B1A-7533-4556-9484-B26FB486475E' = 'Network Map'
    'ECDB0924-4208-451E-8EE0-373C0956DE16' = 'Work Folders'; 'ED834ED6-4B5A-4BFE-8F11-A626DCB6A921' = 'Personalization'; 'F6B6E965-E9B2-444B-9286-10C9152EDBC5' = 'File History'
    'F942C606-0914-47AB-BE56-1321B8035096' = 'Storage Spaces'; '0142E4D0-FB7A-11DC-BA4A-000FFE7AB428' = 'Biometric Devices'; '15EAE92E-F17A-4431-9F28-805E482DAFD4' = 'Get Programs'
    '259EF4B1-E6C9-4176-B574-481532C9BCE8' = 'Game Controllers'; '40419485-C444-4567-851A-2DD7BFA1684D' = 'Phone and Modem'; '62D8ED13-C9D0-4CE8-A914-47DD628FB1B0' = 'Region and Language'
    '6DFD7C5C-2451-11D3-A299-00C04F8EF6AF' = 'Folder Options'; '74246BFC-4C96-11D0-ABEF-0020AF6B0B7A' = 'Device Manager'; '93412589-74D4-4E4E-AD0E-E0CB621440FD' = 'Fonts'
    'A3DD4F92-658A-410F-84FD-6FBBBEF2FFFE' = 'Internet Options'; 'A304259D-52B8-4526-8B1A-A1D6CECC8243' = 'iSCSI Initiator'; 'D17D1D6D-CC3F-4815-8FE3-607E7D5D10B3' = 'Text to Speech'
    'D24F75AA-4F2B-4D07-A3C4-469B3D9030C4' = 'Sync Center'; 'F2DDFC82-8F12-4CDD-B7DC-D4FE1425AA4D' = 'Sound'; '6C8EEC18-8D75-41B2-A177-8831D59D2D50' = 'Mouse'
    '725BE8F7-668E-4C7B-8F90-46BDB0936430' = 'Keyboard'; 'E9950154-C418-419E-A90A-20C5287AE24B' = 'Location and Other Sensors'; '37EFD44D-EF8D-41B1-940D-96973A50E9E0' = 'Desktop Gadgets'
}

function Read-WfxPropertyStore {
    <#
    Serialized property store ([MS-PROPSTORE]): storages ("1SPS"), each with numbered or named values. Returns
    @{ Fmt; Id; Value } for string, integer, GUID and FILETIME values; others are skipped. Bounded by $End.
    #>
    param([byte[]]$B, [int]$Off, [int]$End)
    $out = [System.Collections.Generic.List[object]]::new()
    $p = $Off
    while ($p + 24 -le $End) {
        $size = [int][BitConverter]::ToUInt32($B, $p)
        if ($size -lt 24 -or $p + $size -gt $End -or [BitConverter]::ToUInt32($B, $p + 4) -ne 0x53505331) { break }
        $g = New-Object byte[] 16; [Array]::Copy($B, $p + 8, $g, 0, 16); $fmt = ([guid]$g).ToString().ToUpperInvariant()
        $named = $fmt -eq 'D5CDD505-2E9C-101B-9397-08002B2CF9AE'
        $q = $p + 24; $stop = $p + $size
        while ($q + 9 -le $stop) {
            $vs = [int][BitConverter]::ToUInt32($B, $q); if ($vs -lt 9 -or $q + $vs -gt $stop) { break }
            if ($named) { $ns = [int][BitConverter]::ToUInt32($B, $q + 4); if ($q + 9 + $ns -gt $stop) { break }; $id = [Text.Encoding]::Unicode.GetString($B, $q + 9, $ns).TrimEnd([char]0); $tv = $q + 9 + $ns }
            else { $id = [BitConverter]::ToUInt32($B, $q + 4); $tv = $q + 9 }
            $val = $null
            if ($tv + 4 -le $q + $vs) {
                $vt = [BitConverter]::ToUInt16($B, $tv)
                switch ($vt) {
                    0x1F { if ($tv + 8 -le $q + $vs) { $n = [int][BitConverter]::ToUInt32($B, $tv + 4); if ($n -gt 0 -and $tv + 8 + 2 * $n -le $q + $vs) { $val = [Text.Encoding]::Unicode.GetString($B, $tv + 8, 2 * $n).TrimEnd([char]0) } } }
                    0x13 { if ($tv + 8 -le $q + $vs) { $val = [BitConverter]::ToUInt32($B, $tv + 4) } }
                    0x03 { if ($tv + 8 -le $q + $vs) { $val = [BitConverter]::ToInt32($B, $tv + 4) } }
                    0x48 { if ($tv + 20 -le $q + $vs) { $h = New-Object byte[] 16; [Array]::Copy($B, $tv + 4, $h, 0, 16); $val = ([guid]$h).ToString().ToUpperInvariant() } }
                    0x40 { if ($tv + 12 -le $q + $vs) { $val = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($B, $tv + 4)) } }
                }
            }
            if ($null -ne $val) { $out.Add([pscustomobject]@{ Fmt = $fmt; Id = $id; Value = $val }) }
            $q += $vs
        }
        $p += $size
    }
    , $out.ToArray()
}

function ConvertFrom-WfxZipShellItem {
    <#
    A compressed-folder shell item (a file or folder inside a ZIP archive the user browsed in Explorer). Its
    layout is known only from its parent, so the caller asks for it when the parent is a .zip file or another
    compressed-folder item. Windows 10 layout first, then Windows XP's; $null when neither holds a name.
    #>
    param([byte[]]$B)
    foreach ($at in @(@(84, 92), @(60, 68))) {
        if ($B.Length -lt $at[1] + 2) { continue }
        $n = [BitConverter]::ToUInt32($B, $at[0])
        if ($n -lt 1 -or $n -gt 1024 -or $at[1] + 2 * $n + 2 -gt $B.Length) { continue }
        if ($B[$at[1] + 2 * $n] -ne 0 -or $B[$at[1] + 2 * $n + 1] -ne 0) { continue }
        $name = [Text.Encoding]::Unicode.GetString($B, $at[1], 2 * $n)
        if ($name -match '[\x00-\x1F]' -or $name.IndexOfAny([char[]]'<>:"|?*') -ge 0) { continue }
        $dt = $null
        $ds = [Text.Encoding]::Unicode.GetString($B, $(if ($at[0] -eq 84) { 36 } else { 24 }), 40)
        $m = [regex]::Match($ds, '^(\d\d)/(\d\d)/(\d\d(?:\d\d)?)\s+(\d\d):(\d\d)(?::(\d\d))?')
        if ($m.Success) {
            $y = [int]$m.Groups[3].Value; if ($y -lt 100) { $y += $(if ($y -lt 70) { 2000 } else { 1900 }) }
            try { $dt = [datetime]::new($y, [int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[4].Value, [int]$m.Groups[5].Value, $(if ($m.Groups[6].Success) { [int]$m.Groups[6].Value } else { 0 })) } catch { $dt = $null }
        }
        return [pscustomobject]@{ Kind = 'ZipEntry'; Name = $name; Modified = $dt; Created = $null; Accessed = $null; MftEntry = $null }
    }
    $null
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
            elseif ($t -eq 0x00 -and $B.Length -ge 30 -and [BitConverter]::ToUInt32($B, 6) -eq 0x23FEBBEE -and [BitConverter]::ToUInt16($B, 12) -eq 16) {
                # Users property view with a known folder (Downloads, Pictures ... seen from "Users Files" or a library):
                # data size(2) signature(4) property store size(2) identifier size(2) = 16, then the folder's GUID.
                $g = ([guid]::new([byte[]]$B[14..29])).ToString().ToUpperInvariant(); $kind = 'Root'
                $name = if ($script:WfxKnownFolder[$g]) { $script:WfxKnownFolder[$g] } else { "{$g}" }
            } else { $name = ('(shell item 0x{0:X2})' -f $t) }
        }
    }
    # A property store inside the item (settings pages, search results, phones and cameras over MTP) carries the
    # name Explorer shows: System.ItemNameDisplay, else a search's AutolistCacheKey.
    # Users property view items (type 0x00 with a data signature at offset 6) take their name from the store
    # even when they embed the target folder's own shell item.
    $upv = $t -eq 0x00 -and $B.Length -ge 10 -and [BitConverter]::ToUInt32($B, 6) -in 0x10141981L, 0x23A3DFD5L, 0x3B93AFBBL, 0xBEEBEE00L, 0x49505241L
    if ($name -match '^\(shell item 0x' -or $kind -eq 'Other' -or $upv -or ($t -eq 0x1F -and $B.Length -gt 20)) {
        for ($i = 4; $i + 8 -le $B.Length; $i++) {
            if ($B[$i] -eq 0x31 -and $B[$i + 1] -eq 0x53 -and $B[$i + 2] -eq 0x50 -and $B[$i + 3] -eq 0x53 -and $i -ge 4) {
                $props = Read-WfxPropertyStore $B ($i - 4) $B.Length
                $disp = @($props | Where-Object { $_.Fmt -eq 'B725F130-47EF-101A-A5F1-02608C9EEBAC' -and $_.Id -eq 10 -and $_.Value -is [string] } | Select-Object -First 1)
                if (-not $disp) { $disp = @($props | Where-Object { $_.Id -eq 'AutolistCacheKey' -and $_.Value -is [string] } | ForEach-Object { [pscustomobject]@{ Value = ($_.Value -replace '\d+$', '') } } | Select-Object -First 1) }
                if ($disp) { $kind = 'Item'; $name = [string]$disp[0].Value }
                break
            }
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
    $p = $Offset; $inZip = $false
    while ($p + 2 -le $Bytes.Length) {
        $sz = [BitConverter]::ToUInt16($Bytes, $p); if ($sz -lt 3 -or $p + $sz -gt $Bytes.Length) { break }
        $item = New-Object byte[] $sz; [Array]::Copy($Bytes, $p, $item, 0, $sz)
        $it = $null
        if ($inZip) { $it = ConvertFrom-WfxZipShellItem $item }
        if (-not $it) { $it = ConvertFrom-WfxShellItem $item }
        $it
        $inZip = [bool]($it -and ($it.Kind -eq 'ZipEntry' -or ([string]$it.Name -match '(?i)\.zip$')))
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
    $out = [System.Collections.Generic.List[object]]::new()
    $stack = New-Object System.Collections.Generic.Stack[object]
    if ($Hive) { $root = Get-WfxHiveKey $Hive $KeyPath; if (-not $root) { return }; $stack.Push(@($root, '', 0, $false)) }
    elseif ($LiveKey) { $stack.Push(@($LiveKey, '', 0, $false)) } else { return }
    $seen = 0
    while ($stack.Count -and $seen -lt $Max) {
        $f = $stack.Pop(); $node = $f[0]; $parentPath = $f[1]; $depth = $f[2]; $inZip = $f[3]
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
            $item = $null
            if ($inZip) { $item = ConvertFrom-WfxZipShellItem $vals[$num] }      # below a .zip: entries inside the archive
            if (-not $item) { $item = ConvertFrom-WfxShellItem $vals[$num] }
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
            if ($childNode) { $stack.Push(@($childNode, $path, ($depth + 1), [bool]($item -and ($item.Kind -eq 'ZipEntry' -or ([string]$item.Name -match '(?i)\.zip$'))))) }
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
    $entries = [System.Collections.Generic.List[object]]::new()
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
    $v = 0L; if (-not [long]::TryParse([string]$Value, [ref]$v) -or $v -le 0 -or $v -gt 265046774400000000L) { return $null }
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
        foreach ($c in @(Get-WfxSqliteTable $db 'downloads_url_chains')) { if (-not $chain[(ConvertTo-WfxLong $c.id)]) { $chain[(ConvertTo-WfxLong $c.id)] = New-Object 'System.Collections.Generic.SortedList[long,string]' }; $chain[(ConvertTo-WfxLong $c.id)][(ConvertTo-WfxLong $c.chain_index)] = [string]$c.url }
        foreach ($d in $dl) {
            $urls = @(if ($chain[(ConvertTo-WfxLong $d.id)]) { $chain[(ConvertTo-WfxLong $d.id)].Values })
            $final = if ($urls.Count) { $urls[-1] } else { [string]$d.tab_url }
            $state = switch ((ConvertTo-WfxInt $d.state)) { 1 { 'complete' } 2 { 'cancelled' } 3 { 'interrupted' } 4 { 'interrupted' } default { 'in progress' } }
            $dg = (ConvertTo-WfxInt $d.danger_type)
            $bits = @("$Browser download ($state)")
            if ($final) { $bits += "from $final" }
            if ($d.referrer) { $bits += "referrer $($d.referrer)" }
            if ($dg -and $danger[$dg]) { $bits += "browser warning: $($danger[$dg])" }
            if ((ConvertTo-WfxInt $d.opened)) { $bits += 'opened from the browser' }
            New-WfxArtifact -Artifact 'Download' -Time (ConvertFrom-WfxWebkitTime $d.start_time) -TimeKind 'Download started' -Evidence 'Download' -Path ([string]$d.target_path) -User $User `
                -Detail ($bits -join '; ') -Source $Path `
                -Extra ([pscustomobject]@{ Browser = $Browser; Url = $final; FirstUrl = $(if ($urls.Count) { $urls[0] }); Referrer = [string]$d.referrer; TabUrl = [string]$d.tab_url; Mime = [string]$d.mime_type
                    Bytes = $d.received_bytes; TotalBytes = $d.total_bytes; State = $state; Danger = $(if ($dg) { $danger[$dg] }); Opened = [bool](ConvertTo-WfxInt $d.opened); Finished = (ConvertTo-WfxUtcString (ConvertFrom-WfxWebkitTime $d.end_time)) })
        }
        return
    }
    $attrs = @{}; foreach ($a in @(Get-WfxSqliteTable $db 'moz_anno_attributes')) { $attrs[(ConvertTo-WfxLong $a.id)] = [string]$a.name }
    if (-not $attrs.Count) { return }
    $dest = ($attrs.GetEnumerator() | Where-Object Value -eq 'downloads/destinationFileURI' | Select-Object -First 1).Key
    if (-not $dest) { return }
    $meta = ($attrs.GetEnumerator() | Where-Object Value -eq 'downloads/metaData' | Select-Object -First 1).Key
    $annos = @(Get-WfxSqliteTable $db 'moz_annos')
    $need = @{}; foreach ($a in $annos) { if ((ConvertTo-WfxLong $a.anno_attribute_id) -eq $dest) { $need[(ConvertTo-WfxLong $a.place_id)] = $a } }
    if (-not $need.Count) { return }
    # moz_places can hold hundreds of thousands of rows: look up only the downloaded ones by rowid.
    $places = @{}; $ps = Get-WfxSqliteSchema $db 'moz_places'
    if ($ps) { $ui = [array]::IndexOf($ps.Names, 'url'); foreach ($id in $need.Keys) { $v = Find-WfxSqliteRow $db $ps.Root ([long]$id); if ($v -and $ui -ge 0) { $places[[long]$id] = [pscustomobject]@{ url = $v[$ui] } } } }
    $metaBy = @{}; if ($meta) { foreach ($a in $annos) { if ((ConvertTo-WfxLong $a.anno_attribute_id) -eq $meta) { $metaBy[(ConvertTo-WfxLong $a.place_id)] = [string]$a.content } } }
    foreach ($k in $need.Keys) {
        $a = $need[$k]; $url = [string]$places[$k].url
        $file = [string]$a.content
        try { if ($file -match '^file:') { $file = ([uri]$file).LocalPath } } catch { }
        $state = ''; $size = $null
        if ($metaBy[$k]) { try { $m = $metaBy[$k] | ConvertFrom-Json; $state = switch ((ConvertTo-WfxInt $m.state)) { 1 { 'complete' } 3 { 'cancelled' } 4 { 'paused' } 8 { 'blocked' } 9 { 'blocked by policy' } 0 { 'in progress' } default { "state $($m.state)" } }; $size = $m.fileSize } catch { } }
        $added = $null; $us = 0L; if ([long]::TryParse([string]$a.dateAdded, [ref]$us) -and $us -gt 0 -and $us -lt 253402300799000000L) { $added = [DateTimeOffset]::FromUnixTimeMilliseconds([long][Math]::Floor($us / 1000)).UtcDateTime }
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
            $desc = @(@($f[3], $f[4], $f[5]) | Where-Object { $_ }) -join ', '
            $status = switch ($f[1]) { '0' { 'installer' } '1' { 'driver blocked' } '2' { 'abnormal process exit' } '3' { 'PCA resolve call' } default { "status $($f[1])" } }
            New-WfxArtifact -Artifact 'PCA' -Time (ConvertTo-WfxDateTime ($f[0] + 'Z')) -TimeKind 'Recorded' -Evidence 'Execution' -Path (ConvertFrom-WfxEnvPath $f[2]) `
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

function ConvertFrom-WfxKnownFolderPath {
    <#
    A path that starts with a known-folder GUID (as UserAssist stores them) as a readable path: machine folders
    as C:\..., per-user folders as C:\Users\<user>\... when the profile name is known, else %USERPROFILE%\...
    #>
    param([string]$Path, [string]$User = '')
    if ($Path -notmatch '^\{([0-9A-Fa-f-]{36})\}(.*)$') { return $Path }
    $g = $Matches[1].ToUpperInvariant(); $rest = $Matches[2]
    $prof = if ($User -and $User -notmatch '^S-1-' -and $User -notmatch '[\\/]') { "C:\Users\$User" } else { '%USERPROFILE%' }
    $map = @{
        '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7' = 'C:\Windows\System32'; 'D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27' = 'C:\Windows\SysWOW64'; 'F38BF404-1D43-42F2-9305-67DE0B28FC23' = 'C:\Windows'
        '6D809377-6AF0-444B-8957-A3773F02200E' = 'C:\Program Files'; '905E63B6-C1BF-494E-B29C-65B732D3D21A' = 'C:\Program Files'; '7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E' = 'C:\Program Files (x86)'
        'F7F1ED05-9F6D-47A2-AAAE-29D317C6F066' = 'C:\Program Files\Common Files'; 'DE974D24-D9C6-4D3E-BF91-F4455120B917' = 'C:\Program Files (x86)\Common Files'
        '62AB5D82-FDC1-4DC3-A9DD-070D1D495D97' = 'C:\ProgramData'; 'DFDF76A2-C82A-4D63-906A-5644AC457385' = 'C:\Users\Public'
        '0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8' = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'; 'A4115719-D62E-491D-AA7C-E74B8BE3B067' = 'C:\ProgramData\Microsoft\Windows\Start Menu'
        '82A5EA35-D9CD-47C5-9629-E15D2F714E6E' = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'; 'C4AA340D-F20F-4863-AFEF-F87EF2E6BA25' = 'C:\Users\Public\Desktop'
        '5E6C858F-0E22-4760-9AFE-EA3317B67173' = $prof; 'B4BFCC3A-DB2C-424C-B029-7FE99A87C641' = "$prof\Desktop"; '374DE290-123F-4565-9164-39C4925E467B' = "$prof\Downloads"
        'FDD39AD0-238F-46AF-ADB4-6C85480369C7' = "$prof\Documents"; '33E28130-4E1E-4676-835A-98395C3BC3BB' = "$prof\Pictures"; '4BD8D571-6D19-48D3-BE97-422220080E43' = "$prof\Music"
        '18989B1D-99B5-455B-841C-AB7C74E4DDFC' = "$prof\Videos"; '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D' = "$prof\AppData\Roaming"; 'F1B32785-6FBA-4FCF-9D55-7B8E7F157091' = "$prof\AppData\Local"
        'A520A1A4-1780-4FF6-BD18-167343C5AF16' = "$prof\AppData\LocalLow"; 'A77F5D77-2E2B-44C3-A6A2-ABA601054A51' = "$prof\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
        '625B53C3-AB48-4EC1-BA1F-A1EF4146FC19' = "$prof\AppData\Roaming\Microsoft\Windows\Start Menu"; 'B97D20BB-F46A-4C97-BA10-5E3608430854' = "$prof\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        '9E3995AB-1F9C-4F13-B827-48B24B6C7174' = "$prof\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned"; '52A4F021-7B75-48A9-9F6B-4B87A210BC8F' = "$prof\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"
        'AE50C081-EBD2-438A-8655-8A092E34987A' = "$prof\AppData\Roaming\Microsoft\Windows\Recent"; '8983036C-27C0-404B-8F08-102D10DCFD74' = "$prof\AppData\Roaming\Microsoft\Windows\SendTo"
    }
    if ($map.ContainsKey($g)) { return $map[$g] + $rest }
    $Path
}

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
            $d = [byte[]]$v.Data
            $name = ConvertFrom-WfxRot13 $v.Name
            if ($name -match '^UEME_CTL') { continue }                       # session and counter bookkeeping, not programs
            # Windows 7 and later: 72 bytes (run count at 4, focus count 8, focus time 12, last run 60).
            # Windows XP / 2003: 16 bytes (run count at 4, stored 5 higher; last run 8).
            if ($d.Length -eq 72 -or ($d.Length -ge 68 -and $d.Length -lt 72)) {
                $ft = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($d, 60)); if (-not $ft) { continue }
                $det = "run count $([BitConverter]::ToInt32($d, 4)); focus time $([Math]::Round([BitConverter]::ToUInt32($d, 12) / 1000)) s"
            } elseif ($d.Length -eq 16) {
                $ft = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($d, 8)); if (-not $ft) { continue }
                $cnt = [BitConverter]::ToInt32($d, 4); if ($cnt -ge 5) { $cnt -= 5 }
                $det = "run count $cnt"
                $name = $name -replace '^UEME_(?:RUNPATH|RUNPIDL|RUNCPL|RUNWMH|UISCUT|UIQCUT|UIHOTKEY|UITOOLBAR):', ''
            } else { continue }
            $name = ConvertFrom-WfxKnownFolderPath $name $User
            New-WfxArtifact -Artifact 'UserAssist' -Time $ft -TimeKind 'Last run' -Evidence 'Execution' -Path $name -User $User -Detail $det -Source "$Source\$exp\UserAssist"
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
    <#
    BAM/DAM from an offline SYSTEM hive: full path and last execution time per user SID. Both key layouts are read
    (bam\UserSettings before Windows 10 1809, bam\State\UserSettings after; an upgraded system can have both), in
    every control set; identical entries are reported once.
    #>
    param($Hive, [string]$Source)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($n in (Get-WfxHiveControlSets $Hive)) {
        $set = 'ControlSet{0:D3}' -f $n
        foreach ($svc in 'bam', 'dam') {
            foreach ($rel in "Services\$svc\State\UserSettings", "Services\$svc\UserSettings") {
                $root = Get-WfxHiveKey $Hive "$set\$rel"; if (-not $root) { continue }
                foreach ($sid in @(Get-WfxHiveSubkey $Hive $root)) {
                    foreach ($v in @(Get-WfxHiveValue $Hive $sid)) {
                        $d = [byte[]]$v.Data; if ($v.Type -ne 'REG_BINARY' -or $d.Length -lt 8) { continue }
                        $t = ConvertFrom-WfxFileTime ([BitConverter]::ToInt64($d, 0)); if (-not $t) { continue }
                        if (-not $seen.Add("$($sid.Name)|$($v.Name)|$($t.Ticks)".ToLowerInvariant())) { continue }
                        New-WfxArtifact -Artifact 'BAM' -Time $t -TimeKind 'Last run' -Evidence 'Execution' -Path ($v.Name -replace '^\\Device\\HarddiskVolume\d+', '(volume)') -User $sid.Name `
                            -Detail $(if ($svc -eq 'dam') { 'Desktop Activity Moderator' } else { 'Background Activity Moderator' }) -Source "$Source\$set\$rel"
                    }
                }
            }
        }
    }
}

# ───────────────────────────── collection: live host ─────────────────────────────
function Get-WfxArtifactData {
    <#
    .SYNOPSIS Collects execution / user-activity artifacts from the live host. Read-only; every source that
    cannot be read is recorded as a gap with the reason.
    #>
    param([int]$MaxPerSource = 5000)
    $out = [System.Collections.Generic.List[object]]::new()
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
    # SRUM: the SRUM service keeps its database open; try, and say how to get it if locked.
    $sru = Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat'
    if (Test-Path -LiteralPath $sru) {
        try { & $add (Get-WfxSrumRecord -Path $sru) }
        catch { Add-WfxGap -Source 'SRUM' -Reason "SRUDB.dat could not be read ($($_.Exception.Message)). Copy it with a raw-copy tool (KAPE, FTK Imager) and analyze the copy: Invoke-WfxTriage -ArtifactPath <folder>." }
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
    # Prefetch: parsed (including the compressed Windows 10 and 11 format); name and file times only if a file is unreadable.
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
    <#
    Prefetch: one record per prefetch file (one per program and folder it ran from). The file is parsed, including
    the compressed format of Windows 10 and 11: run count, the last run time (the last eight from Windows 8 on),
    the full path of the program and the files it loaded. When a file cannot be parsed, its name and file times
    are used and the reason is recorded; file times are less reliable (a copy can reset them).
    #>
    param([string]$Folder, [object[]]$Files)
    if (-not $Files) { $Files = @(Get-ChildItem -LiteralPath $Folder -Filter *.pf -File -ErrorAction SilentlyContinue) }
    $failed = 0; $why = ''
    foreach ($f in $Files) {
        $exe = $f.Name -replace '-[0-9A-Fa-f]{8}\.pf$', ''
        $pf = $null
        try { $pf = Read-WfxPrefetch -Path $f.FullName } catch { $failed++; if (-not $why) { $why = "$($f.Name): $($_.Exception.Message)" } }
        if (-not $pf) {
            New-WfxArtifact -Artifact 'Prefetch' -Time $f.LastWriteTimeUtc -TimeKind 'Last run (file time)' -Evidence 'Execution' -Path $exe -Name $exe `
                -Detail "contents not readable; first run about $(ConvertTo-WfxUtcString $f.CreationTimeUtc) (file created); prefetch hash $(($f.BaseName -split '-')[-1])" -Source $f.FullName
            continue
        }
        $full = Get-WfxPrefetchExecutable $pf
        $name = if ($pf.Name) { $pf.Name } else { $exe }
        $runs = @($pf.RunTimes)
        $last = if ($runs.Count) { $runs[0] } else { $f.LastWriteTimeUtc }
        $earlier = @($runs | Select-Object -Skip 1 | ForEach-Object { ConvertTo-WfxUtcString $_ })
        $files = @($pf.Files | ForEach-Object { ConvertFrom-WfxVolumePath $_ })
        $detail = "ran $($pf.RunCount) time$(if ($pf.RunCount -ne 1) { 's' })"
        if ($earlier.Count) { $detail += "; earlier runs $($earlier -join ', ')" }
        $detail += "; prefetch hash $($pf.Hash)"
        New-WfxArtifact -Artifact 'Prefetch' -Time $last -TimeKind $(if ($runs.Count) { 'Last run' } else { 'Last run (file time)' }) -Evidence 'Execution' `
            -Path $(if ($full) { $full } else { $name }) -Name $name -Detail $detail -Source $f.FullName -Extra ([pscustomobject]@{
                RunCount = $pf.RunCount; RunTimes = @($runs | ForEach-Object { ConvertTo-WfxUtcString $_ }); Version = $pf.Version; Hash = $pf.Hash
                Volumes = @($pf.Volumes | ForEach-Object { "$($_.Path) serial $($_.Serial)$(if ($_.Created) { ' created ' + (ConvertTo-WfxUtcString $_.Created) })" })
                FileCount = $files.Count; Files = @($files | Select-Object -First 500)
            })
    }
    if ($failed) { Add-WfxGap -Source 'Prefetch' -Reason "$failed prefetch file(s) could not be parsed and were read by name and file times only (first: $why)." }
}

# ───────────────────────────── collection: files from another system ─────────────────────────────
function ConvertFrom-WfxSidBytes {
    <# Binary SID -> S-1-5-21-... text. #>
    param([byte[]]$B)
    if (-not $B -or $B.Length -lt 8) { return '' }
    $n = $B[1]; if ($B.Length -lt 8 + 4 * $n) { return '' }
    $auth = 0L; for ($i = 2; $i -lt 8; $i++) { $auth = ($auth -shl 8) -bor $B[$i] }
    $s = "S-$($B[0])-$auth"
    for ($i = 0; $i -lt $n; $i++) { $s += '-' + [BitConverter]::ToUInt32($B, 8 + 4 * $i) }
    $s
}

function Get-WfxSrumRecord {
    <#
    .SYNOPSIS Artifact records from SRUM (System Resource Usage Monitor, C:\Windows\System32\sru\SRUDB.dat): for
    each program and account, the network bytes sent and received and the disk bytes read and written, as
    Windows recorded them hour by hour for about 30 to 60 days. One row per program, account and table.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $db = Open-WfxEse -Path $Path
    $ids = @{}
    foreach ($r in (Get-WfxEseTable $db 'SruDbIdMapTable' -Column 'IdType', 'IdIndex', 'IdBlob')) {
        $blob = $r['IdBlob']; if ($null -eq $r['IdIndex']) { continue }
        $v = if ($blob -is [byte[]]) {
            if ([int]$r['IdType'] -eq 3) { ConvertFrom-WfxSidBytes $blob } else { [Text.Encoding]::Unicode.GetString($blob, 0, $blob.Length - ($blob.Length % 2)).TrimEnd([char]0) }
        } else { [string]$blob }
        $ids[[int]$r['IdIndex']] = $v
    }
    $app = {
        param($id)
        $s = [string]$ids[[int]$id]
        if (-not $s) { return "(unnamed app $id)" }
        $s -replace '(?i)^\\device\\harddiskvolume\d+\\', '(volume)\'
    }
    $mb = { param([double]$x) if ($x -ge 1GB) { '{0:n1} GB' -f ($x / 1GB) } elseif ($x -ge 1MB) { '{0:n1} MB' -f ($x / 1MB) } else { '{0:n0} KB' -f ($x / 1KB) } }
    $tables = @(
        @{ Guid = '{973F5D5C-1D90-4944-BE8E-24B94231A174}'; Kind = 'Network'; A = 'BytesSent'; B = 'BytesRecvd' },
        @{ Guid = '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'; Kind = 'Resources'; A = 'ForegroundBytesWritten'; A2 = 'BackgroundBytesWritten'; B = 'ForegroundBytesRead'; B2 = 'BackgroundBytesRead' })
    foreach ($tb in $tables) {
        if (-not $db.Tables.ContainsKey($tb.Guid)) { continue }
        $agg = @{}
        $cols = @('AppId', 'UserId', 'TimeStamp', $tb.A, $tb.B) + @(@($tb.A2, $tb.B2) | Where-Object { $_ })
        foreach ($r in (Get-WfxEseTable $db $tb.Guid -Column $cols)) {
            $k = "$($r['AppId'])|$($r['UserId'])"
            if (-not $agg.ContainsKey($k)) { $agg[$k] = [pscustomobject]@{ App = $r['AppId']; User = $r['UserId']; A = 0.0; B = 0.0; First = $null; Last = $null; Hours = 0 } }
            $g = $agg[$k]
            $g.A += [double]$r[$tb.A] + $(if ($tb.A2) { [double]$r[$tb.A2] } else { 0 })
            $g.B += [double]$r[$tb.B] + $(if ($tb.B2) { [double]$r[$tb.B2] } else { 0 })
            $ts = $r['TimeStamp']
            if ($ts -is [datetime]) { if (-not $g.First -or $ts -lt $g.First) { $g.First = $ts }; if (-not $g.Last -or $ts -gt $g.Last) { $g.Last = $ts } }
            $g.Hours++
        }
        foreach ($g in $agg.Values) {
            $path = & $app $g.App
            $user = [string]$ids[[int]$g.User]
            $detail = if ($tb.Kind -eq 'Network') { "network: $(& $mb $g.A) sent, $(& $mb $g.B) received in $($g.Hours) hourly records" } else { "disk: $(& $mb $g.A) written, $(& $mb $g.B) read in $($g.Hours) hourly records" }
            if ($g.First) { $detail += " since $(ConvertTo-WfxUtcString $g.First)" }
            $extra = [ordered]@{ Table = $tb.Kind; FirstSeen = (ConvertTo-WfxUtcString $g.First); Hours = $g.Hours }
            if ($tb.Kind -eq 'Network') { $extra.BytesSent = [long]$g.A; $extra.BytesReceived = [long]$g.B } else { $extra.BytesWritten = [long]$g.A; $extra.BytesRead = [long]$g.B }
            New-WfxArtifact -Artifact 'SRUM' -Time $g.Last -TimeKind 'Last hour recorded' -Evidence 'Execution' -Path $path -User $user -Detail $detail -Source $Path -Extra ([pscustomobject]$extra)
        }
    }
}

function Get-WfxMftArtifactRecord {
    <#
    .SYNOPSIS Artifact records from a copied $MFT: executables, scripts, archives, disk images and shortcuts in
    folders users can write to (including deleted ones), every file with a Zone.Identifier (downloaded),
    and every executable or script whose timestamps look rewritten (timestomped). Not every file, which would
    be millions of rows.
    .PARAMETER Volume  Drive letter to show (default: taken from a KAPE-style ...\C\$MFT path, else "(volume)").
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$Volume = '', [int]$Max = 20000)
    if (-not $Volume) { $Volume = if ($Path -match '(?i)[\\/]([A-Z])[\\/]\$MFT$') { "$($Matches[1].ToUpperInvariant()):" } else { '(volume)' } }
    $exeRx = '(?i)\.(?:exe|dll|sys|scr|com|cpl|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|msi|iso|img|vhdx?|zip|rar|7z|jar)$'
    $userRx = '(?i)^\\(?:Users|ProgramData\\[^\\]+$|ProgramData\\(?!Microsoft\\|Package Cache\\)|PerfLogs|\$Recycle\.Bin|Windows\\Temp|Temp|Intel|Recovery)\\|^\\[^\\]+$|^\\\[Orphaned\]\\'
    $quiet = '(?i)^\\Users\\[^\\]+\\AppData\\Local\\(?:Microsoft\\(?:Windows\\INetCache|OneDrive|Edge|Teams|WindowsApps)|Packages|Google\\Chrome\\User Data\\[^\\]+\\(?:Code Cache|Service Worker))\\'
    $pre = {
        param($b)
        if ($b.IsDir) { return $false }
        if ($b.Zone) { return $true }
        $nm = $b.FN.Name
        if ($nm -notmatch $exeRx) { return $false }
        $true
    }
    $entries = @(Read-WfxMft -Path $Path -Prefilter $pre)
    # Timestomp candidates. Windows Setup, updates and installers legitimately write files with backdated,
    # whole-second times (they keep the times of the build), so this is only checked where attackers drop
    # tools (folders users can write to), never in System Restore copies. An installer unpacks many such
    # files into one folder within a minute; five or more backdated programs in one folder and minute are
    # treated as an installer. A handful (an attacker's toolkit, even with identical copied times) is not.
    $codeRx = '(?i)\.(?:exe|dll|sys|scr|com|cpl|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta)$'
    $tsOf = @{}; $byDirMin = @{}
    $dirMin = { param($e) ($e.Path -replace '\\[^\\]*$', '') + '|' + $e.FNCreated.ToString('yyyyMMddHHmm') }
    foreach ($e in $entries) {
        if ($e.Name -notmatch $codeRx -or -not $e.FNCreated -or $e.Path -notmatch $userRx -or $e.Path -match '(?i)^\\System Volume Information\\') { continue }
        # Boot files at the volume root are written by Setup with build times.
        if ($e.Path -match '(?i)^\\(?:ntldr|ntdetect\.com|bootmgr|io\.sys|msdos\.sys|bootsect\.bak|autoexec\.bat|config\.sys|BOOTNXT)$') { continue }
        $ts = Test-WfxMftTimestomp $e
        if (-not $ts) { continue }
        $tsOf[$e.Number] = $ts
        $dk = & $dirMin $e; $byDirMin[$dk] = 1 + [int]$byDirMin[$dk]
    }
    $n = 0
    foreach ($e in $entries) {
        $ts = $null
        if ($tsOf.ContainsKey($e.Number) -and $byDirMin[(& $dirMin $e)] -lt 5) { $ts = $tsOf[$e.Number] }
        $userPath = $e.Path -match $userRx -and $e.Path -notmatch $quiet -and $e.Path -notmatch '(?i)^\\System Volume Information\\'
        if (-not ($e.Zone -or $ts -or $userPath)) { continue }
        if (++$n -gt $Max) { Add-WfxGap -Source "artifacts:$Path" -Reason "More than $Max interesting `$MFT entries; the rest were not listed." -Fix 'Filter the $MFT with a dedicated tool (MFTECmd) for a full listing.'; break }
        $url = ''; $zoneId = ''
        if ($e.Zone) {
            if ($e.Zone -match '(?im)^\s*ZoneId\s*=\s*(\d)') { $zoneId = $Matches[1] }
            if ($e.Zone -match '(?im)^\s*HostUrl\s*=\s*(\S+)') { $url = $Matches[1] } elseif ($e.Zone -match '(?im)^\s*ReferrerUrl\s*=\s*(\S+)') { $url = $Matches[1] }
        }
        $bits = New-Object System.Collections.Generic.List[string]
        if (-not $e.InUse) { $bits.Add('deleted') }
        if ($null -ne $e.Size) { $bits.Add("$($e.Size) bytes") }
        if ($zoneId) { $bits.Add("downloaded (zone $zoneId)" + $(if ($url) { " from $url" } else { '' })) }
        if ($ts) { $bits.Add('timestamps look rewritten') }
        $extra = [ordered]@{ Record = $e.Number; Deleted = (-not $e.InUse); FNCreated = (ConvertTo-WfxUtcString $e.FNCreated); SIModified = (ConvertTo-WfxUtcString $e.SIModified) }
        if ($url) { $extra.Url = $url }
        if ($zoneId) { $extra.ZoneId = $zoneId }
        if ($ts) { $extra.Timestomp = ($ts.Reasons -join '; '); $extra.TimestompScore = $ts.Score }
        $other = @($e.Ads | Where-Object { $_ -ne 'Zone.Identifier' -and $_ -notmatch '^(?:SmartScreen|\$Kernel\.Purge.*|encryptable|favicon|OECustomProperty)$' })
        if ($other) { $extra.Streams = ($other -join ', ') }
        New-WfxArtifact -Artifact 'MFT' -Time $e.SICreated -TimeKind 'Created ($SI)' -Evidence $(if ($zoneId) { 'Download' } else { 'Presence' }) `
            -Path ($Volume + $e.Path) -Detail ($bits -join '; ') -Source $Path -Extra ([pscustomobject]$extra)
    }
}

function Import-WfxArtifact {
    <#
    .SYNOPSIS Parses artifacts from a folder of collected evidence (KAPE / Velociraptor output, a mounted
    image, CTF files) or a single file. Files are recognised by their content and name: registry hives
    (SYSTEM, Amcache.hve, NTUSER.DAT, UsrClass.dat), Jump Lists, .lnk, browser databases, PCA and Defender
    logs, Prefetch, $MFT, SRUM (SRUDB.dat). Nothing in the folder is executed or modified.
    .OUTPUTS Artifact records. Event logs (*.evtx) are listed in $script:WfxImportEvtx for the caller.
    #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxFiles = 20000)
    $script:WfxImportEvtx = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path)) { Add-WfxGap -Source 'artifacts' -Reason "Path not found: $Path"; return }
    $files = if (Test-Path -LiteralPath $Path -PathType Leaf) { @(Get-Item -LiteralPath $Path) } else { @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First $MaxFiles) }
    $pf = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $files) {
        $name = $f.Name; $full = $f.FullName
        $user = if ($full -match '(?i)[\\/]Users[\\/]([^\\/]+)[\\/]') { $Matches[1] } else { '' }
        try {
            if ($name -match '(?i)\.evtx$') { $script:WfxImportEvtx.Add($full); continue }
            if ($name -match '(?i)^\$MFT$|^MFT$|\.mft$' -and $f.Length -ge 1024) { Get-WfxMftArtifactRecord -Path $full; continue }
            if ($name -match '(?i)^SRUDB\.dat$') { Get-WfxSrumRecord -Path $full; continue }
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
                    $cn = Get-WfxHiveKey $h ('ControlSet{0:D3}\Control\ComputerName\ComputerName' -f @(Get-WfxHiveControlSets $h)[0])
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
