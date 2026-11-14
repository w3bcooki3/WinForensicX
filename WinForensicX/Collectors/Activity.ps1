# Activity collector — "what changed recently?" Reconstructs attacker-relevant change history from artefacts
# Windows already keeps, without any prior monitoring:
#   Registry   key last-write times of persistence / defence / software / task locations
#   Files      NTFS change journal (create, delete, content change, rename, ADS, timestamp change), Recycle Bin
#   Software   MSI install/remove events, driver installs, Uninstall-key write times
#   Execution  Prefetch, BAM, UserAssist
#   Network    Sysmon 3, Security 5156, firewall log, live connection creation times, outbound RDP history
#   Config     service / task / account / audit-policy / firewall-rule / Defender / time / log-clear / BITS / WMI events
# Every record is normalized to:
#   { Time (UTC ISO), Category, Action, Target, Detail, Actor, Source }
# Everything is read-only. Note: reading key timestamps needs one small compiled helper (Add-Type), which in
# Windows PowerShell 5.1 briefly writes compiler temp files to %TEMP%.

$script:WfxRegTimeReady = $false

function Get-WfxEventQuick {
    <# Reads events with their data fields (no slow message formatting unless -Message). #>
    param([string]$Log, [int[]]$Id, [int]$Days = 7, [int]$Max = 5000, [switch]$Message, [string]$Path = '')
    $flt = @{ Id = $Id; StartTime = (Get-Date).AddDays(-[Math]::Abs($Days)) }
    if ($Path) { $flt.Path = $Path } else { $flt.LogName = $Log }
    $ev = @()
    try { $ev = @(Get-WinEvent -FilterHashtable $flt -MaxEvents $Max -ErrorAction Stop) }
    catch { if (-not (Test-WfxNoEventsError $_)) { throw } }
    foreach ($e in $ev) {
        $f = @{}
        try { foreach ($d in @(([xml]$e.ToXml()).Event.EventData.Data)) { if ($d -and $d.Name) { $f[$d.Name] = [string]$d.'#text' } } } catch {}
        try { foreach ($u in @(([xml]$e.ToXml()).Event.UserData.ChildNodes)) { foreach ($c in @($u.ChildNodes)) { if ($c.LocalName) { $f[$c.LocalName] = [string]$c.InnerText } } } } catch {}
        [pscustomobject]@{ Time = $e.TimeCreated; Id = $e.Id; Level = $e.LevelDisplayName; Fields = $f; Message = $(if ($Message) { try { [string]$e.Message } catch { '' } } else { '' }) }
    }
}


function Initialize-WfxRegTime {
    if ($script:WfxRegTimeReady) { return $true }
    if (-not (Test-WfxWindows)) { return $false }
    try {
        if (-not ('WfxRegTime' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WfxRegTime {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegQueryInfoKey(IntPtr hKey, IntPtr cls, IntPtr clsLen, IntPtr reserved, IntPtr subKeys, IntPtr maxSubKey,
        IntPtr maxClass, IntPtr values, IntPtr maxValueName, IntPtr maxValueLen, IntPtr secDesc, out long lastWrite);
    // Returns the key's last-write FILETIME (UTC) or -1. Read-only query.
    public static long LastWrite(IntPtr hKey) { long ft; return RegQueryInfoKey(hKey, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft) == 0 ? ft : -1; }
}
'@ -ErrorAction Stop
        }
        $script:WfxRegTimeReady = $true
    } catch { Add-WfxGap -Source 'activity:registry' -Reason "Key timestamps unavailable: $($_.Exception.Message)" }
    return $script:WfxRegTimeReady
}

function Get-WfxRegKeyTime {
    <# Last-write time (UTC DateTime) of a registry key given as a PowerShell path, or $null. #>
    param([string]$Path)
    if (-not (Initialize-WfxRegTime)) { return $null }
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        $ft = [WfxRegTime]::LastWrite($k.Handle.DangerousGetHandle())
        if ($ft -gt 0) { return [DateTime]::FromFileTimeUtc($ft) }
    } catch {}
    return $null
}

function Get-WfxRegKeyObjectTime {
    <# Last-write time (UTC) of an open Microsoft.Win32.RegistryKey, or $null. #>
    param($Key)
    if (-not $Key -or -not (Initialize-WfxRegTime)) { return $null }
    try { $ft = [WfxRegTime]::LastWrite($Key.Handle.DangerousGetHandle()); if ($ft -gt 0) { return [DateTime]::FromFileTimeUtc($ft) } } catch { }
    $null
}

function New-WfxActivity {
    param($Time, [string]$Category, [string]$Action, [string]$Target, [string]$Detail = '', [string]$Actor = '', [string]$Source = '')
    [pscustomobject]@{ Time = (ConvertTo-WfxUtcString $Time); Category = $Category; Action = $Action; Target = (Protect-WfxText $Target); Detail = (Protect-WfxText $(if ($Detail.Length -gt 600) { $Detail.Substring(0, 600) + ' …' } else { $Detail })); Actor = $Actor; Source = $Source }
}

function Get-WfxRegValueSummary {
    param($Key, [int]$Max = 6)
    try {
        $names = @($Key.GetValueNames() | Select-Object -First $Max)
        (@($names | ForEach-Object { $v = $Key.GetValue($_); if ($v -is [byte[]]) { $v = "<$($v.Length) bytes>" } elseif ($v -is [array]) { $v = $v -join ';' }; "$(if ($_) { $_ } else { '(Default)' })=$(Get-WfxShortText ([string]$v) 120)" }) -join ' | ')
    } catch { '' }
}


# Registry locations attackers change, with how to read them. Sub = also check each direct subkey.
$script:WfxActivityRegKeys = @(
    @{ P = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; C = 'Autostart'; Hive = 'Both' }
    @{ P = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; C = 'Autostart'; Hive = 'Both' }
    @{ P = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; C = 'Autostart'; Hive = 'HKLM' }
    @{ P = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; C = 'Autostart'; Hive = 'Both' }
    @{ P = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; C = 'Autostart'; Hive = 'Both' }
    @{ P = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; C = 'Autostart'; Hive = 'Both' }
    @{ P = 'Environment'; C = 'Autostart'; Hive = 'HKU' }
    @{ P = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; C = 'Hijack'; Hive = 'HKLM'; Sub = $true }
    @{ P = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'; C = 'Hijack'; Hive = 'HKLM'; Sub = $true }
    @{ P = 'SOFTWARE\Classes\ms-settings\Shell\Open\command'; C = 'Hijack'; Hive = 'HKU' }
    @{ P = 'SOFTWARE\Classes\mscfile\Shell\Open\command'; C = 'Hijack'; Hive = 'HKU' }
    @{ P = 'SYSTEM\CurrentControlSet\Control\Lsa'; C = 'Credentials'; Hive = 'HKLM' }
    @{ P = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; C = 'Credentials'; Hive = 'HKLM' }
    @{ P = 'SYSTEM\CurrentControlSet\Control\Terminal Server'; C = 'Remote access'; Hive = 'HKLM' }
    @{ P = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'; C = 'Defence'; Hive = 'HKLM' }
    @{ P = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'; C = 'Defence'; Hive = 'HKLM' }
    @{ P = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions'; C = 'Defence'; Hive = 'HKLM' }
    @{ P = 'SOFTWARE\Policies\Microsoft\Windows Defender'; C = 'Defence'; Hive = 'HKLM'; Sub = $true }
    @{ P = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'; C = 'Defence'; Hive = 'HKLM' }
    @{ P = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell'; C = 'Defence'; Hive = 'HKLM'; Sub = $true }
    @{ P = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; C = 'Software'; Hive = 'Both'; Sub = $true }
    @{ P = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; C = 'Software'; Hive = 'HKLM'; Sub = $true }
    @{ P = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'; C = 'Scheduled task'; Hive = 'HKLM'; Sub = $true }
    @{ P = 'SYSTEM\CurrentControlSet\Services'; C = 'Service'; Hive = 'HKLM'; Sub = $true }
)

function Get-WfxRegistryActivity {
    param([int]$Days = 7)
    if (-not (Test-WfxWindows) -or -not (Initialize-WfxRegTime)) { return @() }
    $cut = (Get-Date).ToUniversalTime().AddDays(-[Math]::Abs($Days))
    $out = New-Object System.Collections.Generic.List[object]
    $users = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-|^S-1-12-1-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object { $_.PSChildName })
    foreach ($k in $script:WfxActivityRegKeys) {
        $roots = switch ($k.Hive) { 'HKLM' { @('HKLM:') } 'HKU' { @($users | ForEach-Object { "Registry::HKEY_USERS\$_" }) } default { @('HKLM:') + @($users | ForEach-Object { "Registry::HKEY_USERS\$_" }) } }
        foreach ($r in $roots) {
            $path = "$r\$($k.P)"
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $paths = @($path)
            if ($k.Sub) { $paths += @(Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object { $_.PSPath }) }
            foreach ($p in $paths) {
                $t = Get-WfxRegKeyTime $p
                if (-not $t -or $t -lt $cut) { continue }
                $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                $disp = ($p -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' -replace '^HKLM:', 'HKEY_LOCAL_MACHINE')
                $detail = if ($item) { Get-WfxRegValueSummary $item } else { '' }
                if ($k.C -eq 'Software' -and $item) { $dn = $item.GetValue('DisplayName'); if ($dn) { $detail = "$dn $($item.GetValue('DisplayVersion')) — $($item.GetValue('Publisher'))" } }
                if ($k.C -eq 'Service' -and $item) { $detail = "ImagePath=$($item.GetValue('ImagePath')) Start=$($item.GetValue('Start'))" }
                $out.Add((New-WfxActivity -Time $t -Category 'Registry' -Action "$($k.C) key written" -Target $disp -Detail $detail -Source 'registry key last-write time'))
            }
        }
    }
    $out.ToArray()
}

# ── NTFS change journal ──────────────────────────────────────────────────────────────────────────────
# USN reason flags ([MS-FSCC] / winioctl.h USN_REASON_*). The English text form is what "fsutil usn readjournal"
# prints on some builds instead of hex, so both are accepted.
$script:WfxUsnReason = @(
    [pscustomobject]@{ Bit = 0x00000001; Name = 'Data Overwrite' }
    [pscustomobject]@{ Bit = 0x00000002; Name = 'Data Extend' }
    [pscustomobject]@{ Bit = 0x00000004; Name = 'Data Truncation' }
    [pscustomobject]@{ Bit = 0x00000010; Name = 'Named Data Overwrite' }
    [pscustomobject]@{ Bit = 0x00000020; Name = 'Named Data Extend' }
    [pscustomobject]@{ Bit = 0x00000040; Name = 'Named Data Truncation' }
    [pscustomobject]@{ Bit = 0x00000100; Name = 'File Create' }
    [pscustomobject]@{ Bit = 0x00000200; Name = 'File Delete' }
    [pscustomobject]@{ Bit = 0x00000400; Name = 'EA Change' }
    [pscustomobject]@{ Bit = 0x00000800; Name = 'Security Change' }
    [pscustomobject]@{ Bit = 0x00001000; Name = 'Rename Old Name' }
    [pscustomobject]@{ Bit = 0x00002000; Name = 'Rename New Name' }
    [pscustomobject]@{ Bit = 0x00004000; Name = 'Indexable Change' }
    [pscustomobject]@{ Bit = 0x00008000; Name = 'Basic Info Change' }
    [pscustomobject]@{ Bit = 0x00010000; Name = 'Hard Link Change' }
    [pscustomobject]@{ Bit = 0x00020000; Name = 'Compression Change' }
    [pscustomobject]@{ Bit = 0x00040000; Name = 'Encryption Change' }
    [pscustomobject]@{ Bit = 0x00080000; Name = 'Object ID Change' }
    [pscustomobject]@{ Bit = 0x00100000; Name = 'Reparse Point Change' }
    [pscustomobject]@{ Bit = 0x00200000; Name = 'Stream Change' }
    [pscustomobject]@{ Bit = 0x00400000; Name = 'Transacted Change' }
    [pscustomobject]@{ Bit = 0x00800000; Name = 'Integrity Change' }
    [pscustomobject]@{ Bit = 0x80000000L; Name = 'Close' }
)
# What an examiner calls each flag, in reporting order. (Arrays, not [ordered] dictionaries: indexing an
# ordered dictionary with an integer reads by POSITION, not by key.)
$script:WfxUsnLabel = @(
    [pscustomobject]@{ Bit = 0x100; Name = 'Created' }
    [pscustomobject]@{ Bit = 0x200; Name = 'Deleted' }
    [pscustomobject]@{ Bit = 0x1; Name = 'Content overwritten' }
    [pscustomobject]@{ Bit = 0x2; Name = 'Content extended' }
    [pscustomobject]@{ Bit = 0x4; Name = 'Content truncated' }
    [pscustomobject]@{ Bit = 0x10; Name = 'Alternate stream written' }
    [pscustomobject]@{ Bit = 0x20; Name = 'Alternate stream written' }
    [pscustomobject]@{ Bit = 0x200000; Name = 'Alternate stream added/removed' }
    [pscustomobject]@{ Bit = 0x8000; Name = 'Timestamps/attributes changed' }
    [pscustomobject]@{ Bit = 0x800; Name = 'Permissions changed' }
    [pscustomobject]@{ Bit = 0x10000; Name = 'Hard link changed' }
    [pscustomobject]@{ Bit = 0x100000; Name = 'Reparse point changed' }
)
$script:WfxUsnInteresting = 0x100 -bor 0x200 -bor 0x1 -bor 0x2 -bor 0x4 -bor 0x10 -bor 0x20 -bor 0x200000 -bor 0x8000 -bor 0x800 -bor 0x10000 -bor 0x100000 -bor 0x2000
# Names that are high-volume system churn, not user or attacker activity.
$script:WfxUsnNoise = '(?i)\.(?:tmp|etl|blf|regtrans-ms|pf|db-wal|db-shm|sqlite-journal|ldb|lock|evtx|dat\.log\d?|log\d?)$|^~\$|^\$(?!R)|^(?:ntuser\.dat|usrclass\.dat)'

function ConvertFrom-WfxUsnReason {
    <# "0x80000200" or "File delete | Close" → integer flags. Returns -1 when unreadable. #>
    param([string]$Text)
    $t = ([string]$Text).Trim().Trim('"')
    $m = [regex]::Match($t, '^0[xX]([0-9a-fA-F]{1,8})$')
    if ($m.Success) { return [Convert]::ToInt64($m.Groups[1].Value, 16) }
    if ($t -match '^[0-9a-fA-F]{8}$') { return [Convert]::ToInt64($t, 16) }      # bare 8-digit hex
    $flags = [int64]0; $known = 0
    foreach ($tok in ($t -split '\|')) {
        $n = ($tok -replace '[^A-Za-z]', '').ToLowerInvariant()
        if (-not $n) { continue }
        foreach ($pair in $script:WfxUsnReason) {
            if (($pair.Name -replace '[^A-Za-z]', '').ToLowerInvariant() -eq $n) { $flags = $flags -bor [int64]$pair.Bit; $known++; break }
        }
    }
    if ($known) { return $flags } else { return -1 }
}

function Split-WfxCsvLine {
    <# Splits one CSV line (RFC 4180 quoting) into fields. #>
    param([string]$Line)
    $f = New-Object System.Collections.Generic.List[string]
    foreach ($m in $script:WfxCsvField.Matches($Line)) {
        $v = $m.Groups[1].Value
        if ($v.Length -ge 2 -and $v[0] -eq '"' -and $v[-1] -eq '"') { $v = $v.Substring(1, $v.Length - 2).Replace('""', '"') }
        $f.Add($v)
    }
    , $f.ToArray()
}
$script:WfxCsvField = New-Object System.Text.RegularExpressions.Regex('(?:^|,)("(?:[^"]|"")*"|[^,]*)', [System.Text.RegularExpressions.RegexOptions]::Compiled)

function ConvertFrom-WfxUsnCsv {
    <#
    .SYNOPSIS Parses "fsutil usn readjournal <vol> csv" output into USN records. Pure; no system access.
    .DESCRIPTION Columns are located by header name when the header is English, otherwise by their documented
    position (Usn, File name, File name length, Reason, Time stamp, File attributes, File ID, Parent file ID).
    Rows before -Since are dropped. Returns objects { Usn, Time (local DateTime), Name, Flags, Attributes, FileId, ParentId }.
    #>
    param([string[]]$Line, [datetime]$Since = [datetime]::MinValue)
    $col = @{ Name = 1; Reason = 3; Time = 4; Attr = 5; Id = 6; Parent = 7 }
    $byName = @{ 'file name' = 'Name'; 'reason' = 'Reason'; 'time stamp' = 'Time'; 'file attributes' = 'Attr'; 'file id' = 'Id'; 'parent file id' = 'Parent' }
    $cultures = @([Globalization.CultureInfo]::CurrentCulture, [Globalization.CultureInfo]::InvariantCulture)
    foreach ($l in $Line) {
        if ([string]::IsNullOrWhiteSpace($l)) { continue }
        $f = Split-WfxCsvLine $l
        if ($f.Count -lt 8) { continue }
        $first = $f[0].Trim()
        if ($first -notmatch '^\d+$') {
            if ($first -match '^(?i)usn$') { for ($i = 0; $i -lt $f.Count; $i++) { $k = $byName[$f[$i].Trim().ToLowerInvariant()]; if ($k) { $col[$k] = $i } } }
            continue
        }
        $flags = ConvertFrom-WfxUsnReason $f[$col.Reason]
        if ($flags -lt 0) { continue }
        $ts = $f[$col.Time].Trim(); $t = $null
        foreach ($c in $cultures) { $tmp = [datetime]::MinValue; if ([datetime]::TryParse($ts, $c, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$tmp)) { $t = $tmp; break } }
        if ($null -eq $t -or $t -lt $Since) { continue }
        $attr = 0; $a = $f[$col.Attr].Trim(); if ($a -match '^(?:0x)?([0-9a-fA-F]+)$') { $attr = [Convert]::ToInt64($Matches[1], 16) }
        [pscustomobject]@{ Usn = [int64]$first; Time = $t; Name = $f[$col.Name]; Flags = $flags; Attributes = $attr
            FileId = ($f[$col.Id].Trim() -replace '^0x', '').ToLowerInvariant(); ParentId = ($f[$col.Parent].Trim() -replace '^0x', '').ToLowerInvariant() }
    }
}

function ConvertTo-WfxUsnActivity {
    <#
    .SYNOPSIS Turns USN records into examiner-level events. Pure, given a path resolver.
    .DESCRIPTION
      - One event per completed change (the record carrying the CLOSE flag), labelled from its reason flags.
      - Renames are paired with their "old name" record by file ID, so a move is reported with both paths.
        A rename into $Recycle.Bin\<SID>\$R… is what Explorer's Delete does; it is reported as
        "Deleted to Recycle Bin" with the original path.
      - Deleting a $R… item is the Recycle Bin being emptied (permanent deletion).
      - Folders are identified from the directory attribute.
    .PARAMETER Resolve  Scriptblock: param($ParentId) → folder path or ''.
    #>
    param([object[]]$Record, [scriptblock]$Resolve, [string]$Volume = 'C:')
    $old = @{}
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($r in ($Record | Sort-Object Usn)) {
        if ($r.Flags -band 0x1000) { $old[$r.FileId] = $r }
        if (-not ($r.Flags -band 0x80000000L)) { continue }
        if (-not ($r.Flags -band $script:WfxUsnInteresting)) { continue }
        $isRecycleItem = $r.Name -match '^\$R[A-Z0-9]{5,}'
        $isRename = [bool]($r.Flags -band 0x2000)
        $prev = if ($isRename) { $old[$r.FileId] } else { $null }
        $evidenceDelete = ($r.Flags -band 0x200) -and $r.Name -match '(?i)\.evtx$'      # deleting event logs is anti-forensics, not churn
        if (-not $isRename -and -not $isRecycleItem -and -not $evidenceDelete -and $r.Name -match $script:WfxUsnNoise) { continue }
        if ($isRename -and -not $isRecycleItem -and $r.Name -match $script:WfxUsnNoise -and (-not $prev -or $prev.Name -match $script:WfxUsnNoise)) { continue }
        $events.Add([pscustomobject]@{ R = $r; Prev = $prev; Rename = $isRename; RecycleItem = $isRecycleItem })
    }
    # Resolve each distinct folder once.
    $cache = @{}
    $dirOf = { param($id) if (-not $id) { return '' }; if (-not $cache.ContainsKey($id)) { $cache[$id] = [string](& $Resolve $id) }; $cache[$id] }
    $full = { param($id, $name) $d = & $dirOf $id; if ($d) { $d.TrimEnd('\') + '\' + $name } else { "$Volume\<folder 0x$id>\$name" } }
    foreach ($e in $events) {
        $r = $e.R
        $kind = if ($r.Attributes -band 0x10) { 'folder' } else { 'file' }
        $target = & $full $r.ParentId $r.Name
        $detail = ''
        if ($e.Rename -and $e.Prev) {
            $from = & $full $e.Prev.ParentId $e.Prev.Name
            if ($e.RecycleItem) { $action = 'Deleted to Recycle Bin'; $detail = "$kind · now $target"; $target = $from }
            elseif ($e.Prev.ParentId -eq $r.ParentId) { $action = 'Renamed'; $detail = "$kind · was: $($e.Prev.Name)" }
            else { $action = 'Moved'; $detail = "$kind · from: $from" }
        } elseif ($e.Rename) {
            $action = 'Renamed/moved (old name outside journal window)'; $detail = $kind
        } else {
            $labels = @($script:WfxUsnLabel | Where-Object { $r.Flags -band $_.Bit } | ForEach-Object { $_.Name } | Select-Object -Unique)
            if ($labels -contains 'Created' -and $labels -contains 'Deleted') { $labels = @('Created and deleted (short-lived)') }
            $action = $labels -join ', '
            if ($e.RecycleItem -and ($r.Flags -band 0x200)) { $action = 'Permanently deleted (Recycle Bin emptied)' }
            $detail = $kind
        }
        $sid = if ($target -match '(?i)\\\$Recycle\.Bin\\(S-1-[0-9-]+)') { $Matches[1] } else { '' }
        [pscustomobject]@{ Time = $r.Time; Action = $action; Target = $target; Detail = $detail; Usn = $r.Usn; Sid = $sid }
    }
}

function Resolve-WfxFileId {
    <# Folder path for an NTFS file ID via "fsutil file queryFileNameById" (read-only). Tries the full 128-bit
       form and the 64-bit file reference number. Returns '' if the folder no longer exists. #>
    param([string]$Volume, [string]$Id)
    $cands = @("0x$Id")
    if ($Id.Length -eq 32 -and $Id.StartsWith('0000000000000000')) { $cands += "0x$($Id.Substring(16))" }
    foreach ($c in $cands) {
        $o = @(fsutil file queryFileNameById "$Volume\" $c 2>$null) -join ' '
        if ($LASTEXITCODE -eq 0 -and $o -match '\\\\\?\\(.+)$') { return $Matches[1].Trim() }
    }
    ''
}

function Get-WfxUsnActivity {
    <#
    .SYNOPSIS File-system changes from the NTFS change journal of a volume (admin; read-only, via fsutil).
    .DESCRIPTION Reads the newest part of the journal ($MaxRecords records; the journal itself only keeps a
    limited history — typically hours to a few days on a busy system drive). Records a gap explaining exactly
    why when nothing can be read, and notes how far back the readable window actually goes.
    #>
    param([int]$Days = 7, [string]$Drive = $env:SystemDrive, [int]$MaxRecords = 150000, [int]$MaxResolve = 400)
    if (-not (Test-WfxWindows)) { return }
    if (-not (Test-WfxAdmin)) { Add-WfxGap -Source 'activity:usn' -Reason 'The NTFS change journal can only be read by an administrator.' -Fix 'Open PowerShell with "Run as administrator" and run WinForensicX again.'; return }
    $vol = $Drive.TrimEnd('\')
    $q = @(fsutil usn queryjournal $vol 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0) { Add-WfxGap -Source 'activity:usn' -Reason "No change journal on $vol ($((($q -join ' ') -replace '\s+', ' ').Trim()))." -Fix 'The journal may be disabled; nothing can be reconstructed from it on this volume.'; return }
    $hexes = @($q | ForEach-Object { if ($_ -match ':\s*0x([0-9a-fA-F]+)') { [Convert]::ToInt64($Matches[1], 16) } })
    $first = $null; $next = $null
    foreach ($l in $q) { if ($l -match '^\s*First Usn\s*:\s*0x([0-9a-fA-F]+)') { $first = [Convert]::ToInt64($Matches[1], 16) } elseif ($l -match '^\s*Next Usn\s*:\s*0x([0-9a-fA-F]+)') { $next = [Convert]::ToInt64($Matches[1], 16) } }
    if ($null -eq $next -and $hexes.Count -ge 3) { $first = $hexes[1]; $next = $hexes[2] }          # documented order: ID, First, Next
    if ($null -eq $next) { Add-WfxGap -Source 'activity:usn' -Reason "Could not read the journal range from fsutil output: $((($q | Select-Object -First 3) -join ' / '))"; return }
    $start = [Math]::Max([int64]$first, [int64]$next - [int64]$MaxRecords * 120)       # ~120 bytes per record
    $raw = @(fsutil usn readjournal $vol "startusn=$start" csv 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0 -or $raw.Count -lt 2) { Add-WfxGap -Source 'activity:usn' -Reason "fsutil usn readjournal $vol csv failed: $((($raw | Select-Object -First 2) -join ' ') -replace '\s+', ' ')" -Fix 'This Windows build''s fsutil may not support CSV output; the other Recent-changes views still work.'; return }
    $cut = (Get-Date).AddDays(-[Math]::Abs($Days))
    $recs = @(ConvertFrom-WfxUsnCsv -Line $raw)
    if (-not $recs.Count) {
        $sample = @($raw | Where-Object { $_ -match '\S' } | Select-Object -First 2) -join ' ⏎ '
        Add-WfxGap -Source 'activity:usn' -Reason "fsutil returned $($raw.Count) lines but none could be parsed as journal records. First lines: $(Get-WfxShortText $sample 300)" -Fix 'Please report this output format (Windows version + these lines) so the parser can support it.'
        return
    }
    $oldest = ($recs | Measure-Object -Property Time -Minimum).Minimum
    if ($oldest -gt $cut) { Add-WfxGap -Source 'activity:usn' -Reason ("The readable journal window on {0} starts at {1} (local time); changes before that are not shown." -f $vol, $oldest.ToString('yyyy-MM-dd HH:mm')) }
    $recent = @($recs | Where-Object { $_.Time -ge $cut -or ($_.Flags -band 0x1000) })
    $script:WfxUsnResolveCount = 0         # each lookup starts fsutil once; bounded so a huge journal stays fast
    $resolver = { param($id) if ($script:WfxUsnResolveCount -ge $MaxResolve) { return '' }; $script:WfxUsnResolveCount++; Resolve-WfxFileId -Volume $vol -Id $id }
    $sids = @{}
    foreach ($e in (ConvertTo-WfxUsnActivity -Record $recent -Resolve $resolver -Volume $vol)) {
        if ($e.Time -lt $cut) { continue }
        $actor = ''
        if ($e.Sid) { if (-not $sids.ContainsKey($e.Sid)) { $sids[$e.Sid] = try { (New-Object Security.Principal.SecurityIdentifier($e.Sid)).Translate([Security.Principal.NTAccount]).Value } catch { $e.Sid } }; $actor = $sids[$e.Sid] }
        New-WfxActivity -Time $e.Time -Category 'File' -Action $e.Action -Target $e.Target -Detail $e.Detail -Actor $actor -Source "NTFS change journal $vol (USN $($e.Usn))"
    }
}

function Get-WfxRecycleBinActivity {
    <# Parses Recycle Bin $I metadata files on every fixed drive: original path, size, deletion time, owner,
       whether the item ($R) is still recoverable and whether it was a file or a folder. #>
    param([int]$Days = 30, [string[]]$Root = @())
    if (-not $Root.Count) {
        if (-not (Test-WfxWindows)) { return }
        $Root = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { Join-Path $_.RootDirectory.FullName '$Recycle.Bin' })
    }
    $cut = (Get-Date).ToUniversalTime().AddDays(-[Math]::Abs($Days))
    foreach ($rb in $Root) {
        if (-not (Test-Path -LiteralPath $rb)) { continue }
        $dirs = @(Get-ChildItem -LiteralPath $rb -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($sidDir in $dirs) {
            $user = try { (New-Object Security.Principal.SecurityIdentifier($sidDir.Name)).Translate([Security.Principal.NTAccount]).Value } catch { $sidDir.Name }
            $items = @(Get-ChildItem -LiteralPath $sidDir.FullName -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -like '$I*' })
            foreach ($i in $items) {
                $info = Read-WfxRecycleInfo -Path $i.FullName
                if (-not $info) { Add-WfxGap -Source 'activity:recyclebin' -Reason "Unrecognised Recycle Bin metadata file $($i.FullName)"; continue }
                if ($info.Deleted -lt $cut) { continue }
                $rPath = Join-Path $sidDir.FullName ('$R' + $i.Name.Substring(2))
                $rItem = Get-Item -LiteralPath $rPath -Force -ErrorAction SilentlyContinue
                $state = if (-not $rItem) { 'content gone (bin emptied or item restored/purged)' } elseif ($rItem.PSIsContainer) { "folder · recoverable at $rPath" } else { "file · recoverable at $rPath" }
                New-WfxActivity -Time $info.Deleted -Category 'File' -Action 'Deleted to Recycle Bin' -Target $info.OriginalPath -Detail ("{0} · {1:N0} bytes" -f $state, $info.Size) -Actor $user -Source "Recycle Bin $($i.Name)"
            }
        }
    }
}

function Read-WfxRecycleInfo {
    <# Parses one $I file (Vista/7/8 version 1, Windows 10+ version 2). Pure apart from reading the file. #>
    param([string]$Path, [byte[]]$Bytes)
    if (-not $Bytes) { try { $Bytes = [IO.File]::ReadAllBytes($Path) } catch { return $null } }
    $b = $Bytes
    if ($b.Length -lt 24) { return $null }
    $ver = [BitConverter]::ToInt64($b, 0)
    $ft = [BitConverter]::ToInt64($b, 16)
    if ($ft -le 0) { return $null }
    $name = $null
    if ($ver -eq 2) {
        if ($b.Length -lt 30) { return $null }
        $len = [BitConverter]::ToInt32($b, 24)
        if ($len -le 0 -or 28 + $len * 2 -gt $b.Length) { return $null }
        $name = [Text.Encoding]::Unicode.GetString($b, 28, $len * 2).TrimEnd([char]0)
    } elseif ($ver -eq 1) {
        $name = [Text.Encoding]::Unicode.GetString($b, 24, [Math]::Min(520, $b.Length - 24)).Split([char]0)[0]
    } else { return $null }
    [pscustomobject]@{ Version = $ver; Size = [BitConverter]::ToInt64($b, 8); Deleted = [DateTime]::FromFileTimeUtc($ft); OriginalPath = $name }
}

function Get-WfxEventActivity {
    <# Change events from the logs, normalized. Only reads data fields (fast). #>
    param([int]$Days = 7)
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $q = {
        param($Log, [int[]]$Id, [int]$Max = 2000)
        try { @(Get-WfxEventQuick -Log $Log -Id $Id -Days $Days -Max $Max) } catch { Add-WfxGap -Source "activity:$Log" -Reason $_.Exception.Message; @() }
    }
    foreach ($e in (& $q 'Application' 11707, 11724, 1033, 1034)) {
        $f = $e.Fields; $txt = (@($f.Values) | Where-Object { $_ }) -join ' '
        $act = if ($e.Id -in 11724, 1034) { 'Software removed' } else { 'Software installed' }
        $out.Add((New-WfxActivity -Time $e.Time -Category 'Software' -Action $act -Target (Get-WfxShortText $txt 200) -Source "Application log $($e.Id) (MsiInstaller)"))
    }
    foreach ($e in (& $q 'System' 7045, 7040, 20001, 6, 1)) {
        $f = $e.Fields
        switch ($e.Id) {
            7045 { $out.Add((New-WfxActivity -Time $e.Time -Category 'Service' -Action 'Service installed' -Target $f.ServiceName -Detail "$($f.ImagePath) · start=$($f.StartType) · account=$($f.AccountName)" -Source 'System 7045')) }
            7040 { $out.Add((New-WfxActivity -Time $e.Time -Category 'Service' -Action 'Service start type changed' -Target $f.param1 -Detail "$($f.param2) → $($f.param3)" -Source 'System 7040')) }
            20001 { $out.Add((New-WfxActivity -Time $e.Time -Category 'Software' -Action 'Device driver installed' -Target ((@($f.Values) | Where-Object { $_ }) -join ' ') -Source 'System 20001 (UserPnp)')) }
            6 { if ($f.ContainsKey('ImageName')) { $out.Add((New-WfxActivity -Time $e.Time -Category 'Software' -Action 'Kernel driver loaded' -Target $f.ImageName -Source 'System 6 (FilterManager)')) } }
            1 { if ($f.ContainsKey('NewTime')) { $out.Add((New-WfxActivity -Time $e.Time -Category 'Logging' -Action 'System time changed' -Target "$($f.OldTime) → $($f.NewTime)" -Source 'System 1 (Kernel-General)')) } }
        }
    }
    $secNames = @{ 4698 = 'Scheduled task created'; 4699 = 'Scheduled task deleted'; 4702 = 'Scheduled task changed'; 4720 = 'User created'; 4722 = 'User enabled'; 4724 = 'Password reset'; 4726 = 'User deleted'; 4728 = 'Added to group'; 4732 = 'Added to group'; 4756 = 'Added to group'; 4738 = 'User changed'; 4719 = 'Audit policy changed'; 1102 = 'Security log cleared'; 4616 = 'System time changed'; 1100 = 'Event logging shut down'; 4657 = 'Registry value modified'; 5136 = 'Directory object changed' }
    foreach ($e in (& $q 'Security' @($secNames.Keys) 3000)) {
        $f = $e.Fields
        $cat = switch ($e.Id) { { $_ -in 4698, 4699, 4702 } { 'Scheduled task' } { $_ -in 4719, 1102, 4616, 1100 } { 'Logging' } 4657 { 'Registry' } default { 'Account' } }
        $target = switch ($e.Id) {
            { $_ -in 4698, 4699, 4702 } { $f.TaskName }
            { $_ -in 4728, 4732, 4756 } { "$($f.MemberName) → $($f.TargetUserName)" }
            4657 { "$($f.ObjectName)\$($f.ObjectValueName)" }
            4616 { "$($f.PreviousTime) → $($f.NewTime)" }
            4719 { "$($f.SubcategoryGuid) $($f.AuditPolicyChanges)" }
            default { $(if ($f.TargetUserName) { "$($f.TargetDomainName)\$($f.TargetUserName)" } else { '' }) }
        }
        $detail = if ($e.Id -in 4698, 4702) { Get-WfxShortText (([string]$f.TaskContent) -replace '(?s).*?<Exec>(.*?)</Exec>.*', '$1' -replace '<[^>]+>', ' ') 300 } elseif ($e.Id -eq 4616) { $f.ProcessName } else { '' }
        $out.Add((New-WfxActivity -Time $e.Time -Category $cat -Action $secNames[[int]$e.Id] -Target $target -Detail $detail -Actor "$($f.SubjectDomainName)\$($f.SubjectUserName)" -Source "Security $($e.Id)"))
    }
    foreach ($e in (& $q 'System' 104)) { $out.Add((New-WfxActivity -Time $e.Time -Category 'Logging' -Action 'Event log cleared' -Target $e.Fields.Channel -Actor "$($e.Fields.SubjectDomainName)\$($e.Fields.SubjectUserName)" -Source 'System 104')) }
    foreach ($e in (& $q 'Microsoft-Windows-TaskScheduler/Operational' 106, 140, 141)) {
        $out.Add((New-WfxActivity -Time $e.Time -Category 'Scheduled task' -Action @{ 106 = 'Scheduled task registered'; 140 = 'Scheduled task updated'; 141 = 'Scheduled task deleted' }[[int]$e.Id] -Target $e.Fields.TaskName -Actor $e.Fields.UserContext -Source "TaskScheduler $($e.Id)"))
    }
    foreach ($e in (& $q 'Microsoft-Windows-Windows Defender/Operational' 5001, 5004, 5007, 5010, 5012, 1116)) {
        $f = $e.Fields
        $a = @{ 5001 = 'Real-time protection disabled'; 5004 = 'Real-time protection config changed'; 5007 = 'Defender configuration changed'; 5010 = 'Spyware scanning disabled'; 5012 = 'Virus scanning disabled'; 1116 = 'Malware detected' }[[int]$e.Id]
        $t = if ($e.Id -eq 5007) { Get-WfxShortText "$($f.'Old Value') → $($f.'New Value')" 300 } elseif ($e.Id -eq 1116) { "$($f.'Threat Name') · $($f.Path)" } else { '' }
        $out.Add((New-WfxActivity -Time $e.Time -Category 'Defender' -Action $a -Target $t -Source "Defender $($e.Id)"))
    }
    foreach ($e in (& $q 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' 2004, 2005, 2006, 2033, 2097, 2099, 2003)) {
        $f = $e.Fields
        $a = @{ 2004 = 'Firewall rule added'; 2097 = 'Firewall rule added'; 2005 = 'Firewall rule changed'; 2099 = 'Firewall rule changed'; 2006 = 'Firewall rule deleted'; 2033 = 'All firewall rules deleted'; 2003 = 'Firewall profile setting changed' }[[int]$e.Id]
        $out.Add((New-WfxActivity -Time $e.Time -Category 'Firewall' -Action $a -Target "$($f.RuleName)" -Detail "app=$($f.ApplicationPath) ports=$($f.LocalPorts) dir=$($f.Direction) action=$($f.Action)" -Actor "$($f.ModifyingApplication)" -Source "Firewall $($e.Id)"))
    }
    foreach ($e in (& $q 'Microsoft-Windows-Bits-Client/Operational' 59, 60)) {
        if ($e.Fields.url) { $out.Add((New-WfxActivity -Time $e.Time -Category 'Download' -Action 'BITS transfer' -Target $e.Fields.url -Detail "job=$($e.Fields.name)" -Source "BITS $($e.Id)")) }
    }
    foreach ($e in (& $q 'Microsoft-Windows-WMI-Activity/Operational' 5861)) {
        $out.Add((New-WfxActivity -Time $e.Time -Category 'WMI' -Action 'Permanent WMI subscription registered' -Target (Get-WfxShortText ((@($e.Fields.Values) | Where-Object { $_ }) -join ' ') 300) -Source 'WMI-Activity 5861'))
    }
    foreach ($e in (& $q 'Microsoft-Windows-TerminalServices-RDPClient/Operational' 1024, 1102)) {
        $out.Add((New-WfxActivity -Time $e.Time -Category 'Network' -Action 'Outbound RDP connection' -Target "$($e.Fields.Value)" -Source "RDPClient $($e.Id)"))
    }
    foreach ($e in (& $q 'Microsoft-Windows-Sysmon/Operational' 2, 11, 12, 13, 14, 23, 26 5000)) {
        $f = $e.Fields
        switch ($e.Id) {
            2 { $out.Add((New-WfxActivity -Time $e.Time -Category 'File' -Action 'File creation time changed (timestomp?)' -Target $f.TargetFilename -Detail "$($f.PreviousCreationUtcTime) → $($f.CreationUtcTime)" -Actor $f.Image -Source 'Sysmon 2')) }
            11 { if ($f.TargetFilename -match '(?i)\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|hta|scr|lnk|msi)$') { $out.Add((New-WfxActivity -Time $e.Time -Category 'File' -Action 'Executable/script created' -Target $f.TargetFilename -Actor $f.Image -Source 'Sysmon 11')) } }
            { $_ -in 12, 13, 14 } { $out.Add((New-WfxActivity -Time $e.Time -Category 'Registry' -Action $(switch ($e.Id) { 12 { "Registry $($f.EventType)" } 13 { 'Registry value set' } 14 { 'Registry key renamed' } }) -Target $f.TargetObject -Detail $f.Details -Actor $f.Image -Source "Sysmon $($e.Id)")) }
            { $_ -in 23, 26 } { $out.Add((New-WfxActivity -Time $e.Time -Category 'File' -Action 'File deleted' -Target $f.TargetFilename -Actor $f.Image -Source "Sysmon $($e.Id)")) }
        }
    }
    $out.ToArray()
}

function Get-WfxExecutionActivity {
    <# Program execution evidence: Prefetch (last run), BAM (last run per user, full path), UserAssist (GUI launches). #>
    param([int]$Days = 7)
    if (-not (Test-WfxWindows)) { return @() }
    $cut = (Get-Date).ToUniversalTime().AddDays(-[Math]::Abs($Days))
    $out = New-Object System.Collections.Generic.List[object]
    Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Prefetch') -Filter *.pf -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -ge $cut } | ForEach-Object {
        $out.Add((New-WfxActivity -Time $_.LastWriteTimeUtc -Category 'Execution' -Action 'Program ran (Prefetch)' -Target ($_.BaseName -replace '-[0-9A-F]{8}$', '') -Detail "first seen $(ConvertTo-WfxUtcString $_.CreationTimeUtc)" -Source 'Prefetch'))
    }
    foreach ($bamRoot in 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings') {
        foreach ($sidKey in (Get-ChildItem -LiteralPath $bamRoot -ErrorAction SilentlyContinue)) {
            $user = try { (New-Object Security.Principal.SecurityIdentifier($sidKey.PSChildName)).Translate([Security.Principal.NTAccount]).Value } catch { $sidKey.PSChildName }
            foreach ($n in $sidKey.GetValueNames()) {
                $v = $sidKey.GetValue($n)
                if ($v -isnot [byte[]] -or $v.Length -lt 8) { continue }
                $t = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($v, 0))
                if ($t -lt $cut) { continue }
                $path = $n -replace '^\\Device\\HarddiskVolume\d+', '(volume)'
                $out.Add((New-WfxActivity -Time $t -Category 'Execution' -Action 'Program ran (BAM)' -Target $path -Actor $user -Source 'BAM registry'))
            }
        }
    }
    foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-|^S-1-12-1-' -and $_.PSChildName -notmatch '_Classes$' })) {
        $ua = "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        foreach ($g in (Get-ChildItem -LiteralPath $ua -ErrorAction SilentlyContinue)) {
            $ck = Get-Item -LiteralPath (Join-Path $g.PSPath 'Count') -ErrorAction SilentlyContinue
            if (-not $ck) { continue }
            foreach ($n in $ck.GetValueNames()) {
                $v = $ck.GetValue($n)
                if ($v -isnot [byte[]] -or $v.Length -lt 68) { continue }
                $ft = [BitConverter]::ToInt64($v, 60); if ($ft -le 0) { continue }
                $t = [DateTime]::FromFileTimeUtc($ft); if ($t -lt $cut) { continue }
                $name = -join ($n.ToCharArray() | ForEach-Object { $c = [int]$_; if ($c -ge 65 -and $c -le 90) { [char](65 + ($c - 52) % 26) } elseif ($c -ge 97 -and $c -le 122) { [char](97 + ($c - 84) % 26) } else { $_ } })
                $out.Add((New-WfxActivity -Time $t -Category 'Execution' -Action 'Program launched by user (UserAssist)' -Target $name -Detail "run count $([BitConverter]::ToInt32($v, 4))" -Actor $h.PSChildName -Source 'UserAssist registry'))
            }
        }
    }
    $out.ToArray()
}

function Get-WfxConnectionActivity {
    <# Connection history from whatever this host records: Sysmon 3, Security 5156, the firewall log,
       live connection creation times, outbound RDP history. #>
    param([int]$Days = 7, [int]$Max = 5000)
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $cut = (Get-Date).AddDays(-[Math]::Abs($Days))
    try {
        foreach ($e in @(Get-WfxEventQuick -Log 'Microsoft-Windows-Sysmon/Operational' -Id 3 -Days $Days -Max $Max)) {
            $f = $e.Fields
            if (Test-WfxPrivateIp $f.DestinationIp) { continue }
            $out.Add((New-WfxActivity -Time $e.Time -Category 'Network' -Action 'Outbound connection' -Target "$($f.DestinationIp):$($f.DestinationPort)" -Detail $(if ($f.DestinationHostname) { $f.DestinationHostname } else { '' }) -Actor $f.Image -Source 'Sysmon 3'))
        }
    } catch {}
    try {
        foreach ($e in @(Get-WfxEventQuick -Log Security -Id 5156 -Days $Days -Max $Max)) {
            $f = $e.Fields
            if ([string]$f.Direction -notmatch '14593|Outbound' -or (Test-WfxPrivateIp $f.DestAddress)) { continue }
            $out.Add((New-WfxActivity -Time $e.Time -Category 'Network' -Action 'Outbound connection allowed' -Target "$($f.DestAddress):$($f.DestPort)" -Actor $f.Application -Source 'Security 5156 (WFP)'))
        }
    } catch {}
    $fwLog = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
    if (Test-Path -LiteralPath $fwLog) {
        try {
            foreach ($l in (Get-Content -LiteralPath $fwLog -Tail 20000 -ErrorAction Stop)) {
                if ($l -notmatch '^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (ALLOW|DROP) (\S+) (\S+) (\S+) (\S+) (\S+)') { continue }
                $t = [datetime]::ParseExact("$($Matches[1]) $($Matches[2])", 'yyyy-MM-dd HH:mm:ss', $null)
                if ($t -lt $cut) { continue }
                $dst = $Matches[6]; $src = $Matches[5]
                if ((Test-WfxPrivateIp $dst) -and (Test-WfxPrivateIp $src)) { continue }
                $out.Add((New-WfxActivity -Time $t -Category 'Network' -Action "Firewall $($Matches[3].ToLower()) ($($Matches[4]))" -Target "$src → ${dst}:$($Matches[8])" -Source 'pfirewall.log'))
            }
        } catch {}
    }
    try {
        $names = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
        Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $_.CreationTime -ge $cut -and -not (Test-WfxPrivateIp $_.RemoteAddress) } | ForEach-Object {
            $out.Add((New-WfxActivity -Time $_.CreationTime -Category 'Network' -Action 'Connection opened (still open)' -Target "$($_.RemoteAddress):$($_.RemotePort)" -Actor $names[[int]$_.OwningProcess] -Source 'live TCP table'))
        }
    } catch {}
    foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-|^S-1-12-1-' -and $_.PSChildName -notmatch '_Classes$' })) {
        $srv = "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Terminal Server Client\Servers"
        foreach ($s in (Get-ChildItem -LiteralPath $srv -ErrorAction SilentlyContinue)) {
            $t = Get-WfxRegKeyTime $s.PSPath
            $out.Add((New-WfxActivity -Time $t -Category 'Network' -Action 'Outbound RDP target (saved)' -Target $s.PSChildName -Detail "user hint: $($s.GetValue('UsernameHint'))" -Actor $h.PSChildName -Source 'Terminal Server Client registry'))
        }
    }
    $out.ToArray()
}

function Get-WfxActivityData {
    <#
    .SYNOPSIS Collects all recent-activity evidence (see file header). Each part degrades to a gap on error.
    .PARAMETER Days       Look-back window.
    .PARAMETER Journal    Also read the NTFS change journal (admin; slower).
    #>
    param([int]$Days = 7, [switch]$Journal)
    if (-not (Test-WfxWindows)) { return @() }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($part in @(
            @{ N = 'activity:registry'; S = { Get-WfxRegistryActivity -Days $Days } }
            @{ N = 'activity:events'; S = { Get-WfxEventActivity -Days $Days } }
            @{ N = 'activity:execution'; S = { Get-WfxExecutionActivity -Days $Days } }
            @{ N = 'activity:network'; S = { Get-WfxConnectionActivity -Days $Days } }
            @{ N = 'activity:recyclebin'; S = { Get-WfxRecycleBinActivity -Days ([Math]::Max($Days, 30)) } }
        )) {
        foreach ($r in @(Invoke-WfxStep $part.N $part.S @())) { if ($r) { $all.Add($r) } }
    }
    if ($Journal) { foreach ($r in @(Invoke-WfxStep 'activity:usn' { Get-WfxUsnActivity -Days $Days } @())) { if ($r) { $all.Add($r) } } }
    $all.ToArray() | Sort-Object Time -Descending
}
