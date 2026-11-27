# Respond mode: containment you choose and confirm, one action at a time, with a record and an undo.
#
#   Invoke-WfxRespond -PlanPath <case>          the actions a triage suggested (respond-plan.json)
#   Invoke-WfxRespond -KillProcess 4242 ...     or name them directly
#   Get-WfxAction / Undo-WfxAction -Id ...      what was done, and putting it back
#
# How it stays safe:
#   * Nothing happens without confirmation: every action asks (PowerShell's -Confirm), -WhatIf shows what
#     would happen, and riskier actions (Windows programs, Microsoft tasks, private addresses) ask a second
#     time unless -Force. The never-touch rules in Private/Respond.ps1 cannot be overridden.
#   * A target is checked again just before acting: a process must still be the same program (name, path,
#     start time, hash) so a reused PID is never killed; a Run-key value must still be there.
#   * Before each change, what is about to be changed is recorded (process details, file hash and times,
#     the registry value, the task XML, the service start type ...) in
#     Downloads\WinForensicX-Quarantine\actions, a folder only administrators and SYSTEM can open.
#   * Everything except stopping a process can be undone with Undo-WfxAction.
#   * Quarantined files are encrypted into that folder (they cannot run and scanners do not re-detect
#     them) and the folder is refused if Downloads is synced to OneDrive, Dropbox or Google Drive.

function Initialize-WfxQuarantineRoot {
    <# Creates the quarantine (files\, actions\) locked to Administrators and SYSTEM. Returns its path. #>
    param([string]$Path = '')
    $root = Get-WfxQuarantineRoot -Path $Path
    $cloud = Test-WfxCloudPath $root
    if ($cloud) { throw "The quarantine folder '$root' is inside $cloud, which would copy quarantined malware off this computer. Use -QuarantinePath with a local folder (for example C:\WinForensicX-Quarantine)." }
    $bad = Test-WfxQuarantineFolder -Path $root
    if ($bad) { throw $bad }
    foreach ($d in $root, (Join-Path $root 'files'), (Join-Path $root 'actions')) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
    $marker = Join-Path $root '.wfx-quarantine'
    if (-not (Test-Path -LiteralPath $marker)) { Set-Content -LiteralPath $marker -Value 'WinForensicX quarantine and action records. Locked to Administrators and SYSTEM. Do not delete while actions may need undoing.' -Encoding UTF8 }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $root -AclObject $acl
    $root
}

function Save-WfxActionRecord {
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Root)
    Save-WfxJson -InputObject $Record -Path (Join-Path (Join-Path $Root 'actions') "$($Record.Id).json") -Depth 8
    try { Add-Content -LiteralPath (Join-Path $Root 'actions.log') -Value ($Record | ConvertTo-Json -Compress -Depth 8) -Encoding UTF8 } catch {}
}

function Get-WfxOwnAddress {
    @(try {
            [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object { $_.GetIPProperties().UnicastAddresses } | ForEach-Object { $_.Address.ToString() -replace '%\d+$', '' }
        } catch { })
}

function Test-WfxMicrosoftSigned {
    <# $true when a file has a valid Microsoft Authenticode signature. #>
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try { $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop; return ($s.Status -eq 'Valid' -and [string]$s.SignerCertificate.Subject -match '(?i)O=Microsoft (?:Corporation|Windows)') } catch { return $false }
}

# ───────────────────────────── one action ─────────────────────────────
function Invoke-WfxResponseAction {
    <# Checks, confirms, records and performs one action. Returns its record (or $null when skipped by -WhatIf / No). #>
    param([Parameter(Mandatory)]$Action, [Parameter(Mandatory)]$Cmdlet, [string]$Root, [switch]$Force)
    $type = [string]$Action.Type
    $p = $Action.Params
    $get = { param($n, $d = '') $v = Get-WfxValue $p $n $d; if ($null -eq $v) { $d } else { $v } }
    $rec = [ordered]@{
        Id = ('{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 6))
        Type = $type; Target = [string]$Action.Target; Reason = [string](Get-WfxValue $Action 'Reason' ''); Findings = @(Get-WfxValue $Action 'Findings' @())
        Status = ''; Message = ''; Time = (Get-WfxUtcNow); Operator = [Environment]::UserName; Host = [Environment]::MachineName
        Reversible = $true; Evidence = $null; Undo = $null; Undone = ''
    }
    $refuse = { param($why) $rec.Status = 'Refused'; $rec.Message = $why; Write-Warning ("Refused {0} {1}: {2}" -f $type, $rec.Target, $why); $rec }
    # The second question for riskier actions. -WhatIf never asks (ShouldProcess then only reports).
    $second = { param($q) if ($Force -or $WhatIfPreference) { return $true }; return $Cmdlet.ShouldContinue($q, 'WinForensicX: are you sure?') }

    try {
        switch ($type) {
            'Kill' {
                $procId = [int](& $get 'Pid' -1)
                $rec.Reversible = $false
                $w = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
                if (-not $w) { $rec.Status = 'NotFound'; $rec.Message = "No process with PID $procId is running."; return $rec }
                $why = Test-WfxRefusedProcess -Name ([string]$w.Name) -ProcessId $procId -Self $PID
                if ($why) { return (& $refuse $why) }
                $myParent = -1; try { $myParent = [int](Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop).ParentProcessId } catch {}
                if ($procId -eq $myParent) { return (& $refuse 'This is the window WinForensicX is running in.') }
                $path = [string]$w.ExecutablePath
                $want = [string](& $get 'Name'); if ($want -and ($want -replace '\.exe$', '') -ne ([string]$w.Name -replace '\.exe$', '')) { return (& $refuse "PID $procId is now $($w.Name), not $want: the process has ended and the number was reused.") }
                $wantPath = [string](& $get 'Path'); if ($wantPath -and $path -and $wantPath -ne $path) { return (& $refuse "PID $procId now runs $path, not $wantPath.") }
                $start = ConvertTo-WfxDateTime $w.CreationDate
                $wantStart = ConvertTo-WfxDateTime (& $get 'StartTime')
                if ($wantStart -and $start -and [Math]::Abs(($start - $wantStart).TotalSeconds) -gt 2) { return (& $refuse "PID $procId started at $(ConvertTo-WfxUtcString $start), not $(ConvertTo-WfxUtcString $wantStart): a different process with the same number.") }
                $sha = Get-WfxBinaryHash $path
                $wantSha = [string](& $get 'Sha256'); if ($wantSha -and $sha -and $wantSha -ne $sha) { return (& $refuse "The program file's SHA-256 changed since triage.") }
                $conns = @(try { Get-NetTCPConnection -OwningProcess $procId -ErrorAction Stop | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) $($_.State)" } } catch { })
                $owner = ''; try { $o = Invoke-CimMethod -InputObject $w -MethodName GetOwner -ErrorAction Stop; if ($o.User) { $owner = "$($o.Domain)\$($o.User)" } } catch {}
                $rec.Target = "$($w.Name) (PID $procId)"
                $rec.Evidence = [ordered]@{ Pid = $procId; Name = [string]$w.Name; Path = $path; CommandLine = (Protect-WfxText ([string]$w.CommandLine)); ParentPid = [int]$w.ParentProcessId; Owner = $owner; Started = (ConvertTo-WfxUtcString $start); Sha256 = $sha; Signature = (Get-WfxSignature $path); Connections = $conns }
                if ($path -and $path -match '(?i)^[a-z]:\\windows\\' -and (Test-WfxMicrosoftSigned $path)) {
                    if (-not (& $second "$($w.Name) is a Microsoft program from the Windows folder (PID $procId). Stopping the wrong one can disrupt Windows. Stop it anyway?")) { return $null }
                }
                if (-not $Cmdlet.ShouldProcess($rec.Target, 'Stop the process (cannot be undone; capture memory first if you need it)')) { return $null }
                Stop-Process -Id $procId -Force -Confirm:$false -ErrorAction Stop
                $gone = $false; for ($i = 0; $i -lt 25; $i++) { if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { $gone = $true; break }; Start-Sleep -Milliseconds 200 }
                $rec.Status = if ($gone) { 'Done' } else { 'Failed' }
                $rec.Message = if ($gone) { 'Stopped.' } else { 'Asked to stop, but it is still running (protected, or restarted by something else).' }
            }
            'Quarantine' {
                $path = [string](& $get 'Path')
                if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { $rec.Status = 'NotFound'; $rec.Message = "No file at $path."; return $rec }
                $fi = Get-Item -LiteralPath $path -Force
                $path = $fi.FullName; $rec.Target = $path
                $sig = $null; try { $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop } catch {}
                $why = Test-WfxRefusedFile -Path $path -QuarantineRoot $Root -Signature $(if ($sig) { [string]$sig.Status } else { '' }) -Signer $(if ($sig -and $sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' })
                if ($why) { return (& $refuse $why) }
                if ($fi.Length -gt 2GB) { return (& $refuse 'Larger than 2 GB; collect it with an imaging tool instead.') }
                if ($env:SystemRoot -and $path.StartsWith((Join-Path $env:SystemRoot 'System32\drivers') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                    $leaf = Split-Path -Leaf $path
                    $boot = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { [string]$_.StartMode -in 'Boot', 'System' -and [string]$_.PathName -match ('(?i)\\' + [regex]::Escape($leaf) + '"?$') })
                    if ($boot.Count) { return (& $refuse "A driver Windows loads at boot ($($boot[0].Name)); removing it can stop Windows from starting. Disable or replace it offline instead.") }
                }
                if ($env:SystemRoot -and $path.StartsWith($env:SystemRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
                    if (-not (& $second "$path is in the Windows folder. Removing the wrong file there can break Windows. Quarantine it anyway?")) { return $null }
                }
                if (-not $Cmdlet.ShouldProcess($path, 'Move the file into the quarantine (encrypted; Undo-WfxAction puts it back)')) { return $null }
                $zone = ''; try { $zone = [string](Get-Content -LiteralPath $path -Stream Zone.Identifier -Raw -ErrorAction Stop) } catch {}
                $blob = Join-Path (Join-Path $Root 'files') "$($rec.Id).wfxq"
                $sha = Write-WfxQuarantineFile -Source $path -Target $blob
                if ((Read-WfxQuarantineFile -Source $blob) -ne $sha) { Remove-Item -LiteralPath $blob -Force -ErrorAction SilentlyContinue; throw 'The quarantined copy did not verify; the original was left in place.' }
                $rec.Evidence = [ordered]@{ Path = $path; Size = $fi.Length; Sha256 = $sha; Created = (ConvertTo-WfxUtcString $fi.CreationTimeUtc); Modified = (ConvertTo-WfxUtcString $fi.LastWriteTimeUtc); Accessed = (ConvertTo-WfxUtcString $fi.LastAccessTimeUtc)
                    Attributes = [string]$fi.Attributes; Signature = $(if ($sig) { [string]$sig.Status } else { '' }); Signer = $(if ($sig -and $sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }); ZoneIdentifier = $zone }
                $rec.Undo = [ordered]@{ Path = $path; Blob = "files\$($rec.Id).wfxq"; Sha256 = $sha; Created = $fi.CreationTimeUtc.Ticks; Modified = $fi.LastWriteTimeUtc.Ticks; Accessed = $fi.LastAccessTimeUtc.Ticks; Attributes = [int]$fi.Attributes; Zone = $zone }
                $attrs = $fi.Attributes
                try {
                    if ($attrs -band [IO.FileAttributes]::ReadOnly) { $fi.Attributes = $attrs -bxor [IO.FileAttributes]::ReadOnly }
                    Remove-Item -LiteralPath $path -Force -Confirm:$false -ErrorAction Stop
                } catch {
                    try { if (Test-Path -LiteralPath $path) { (Get-Item -LiteralPath $path -Force).Attributes = $attrs } } catch {}
                    Remove-Item -LiteralPath $blob -Force -Confirm:$false -ErrorAction SilentlyContinue
                    throw "The file could not be removed ($($_.Exception.Message)). If a program is using it, stop that process first. The original was left in place."
                }
                $rec.Status = 'Done'; $rec.Message = "Quarantined as $($rec.Undo.Blob)."
            }
            'DisableRunKey' {
                $key = [string](& $get 'Key'); $name = [string](& $get 'Name')
                if (-not (Test-WfxRunKeyPath $key)) { return (& $refuse 'Only values in the Run and RunOnce keys can be removed here.') }
                $k = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
                $vn = if ($name -eq '(Default)') { '' } else { $name }
                if (-not $k -or @($k.GetValueNames()) -notcontains $vn) { $rec.Status = 'NotFound'; $rec.Message = 'The value is not there any more.'; return $rec }
                $kind = [string]$k.GetValueKind($vn)
                $val = $k.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
                if ($kind -eq 'Binary') { $val = [Convert]::ToBase64String([byte[]]$val) }
                $rec.Evidence = [ordered]@{ Key = $key; Name = $name; Kind = $kind; Value = (Protect-WfxText ([string](@($val) -join ' '))) }
                if (-not $Cmdlet.ShouldProcess("$key\$name", 'Remove the Run-key value (backed up; Undo-WfxAction restores it)')) { return $null }
                $rec.Undo = [ordered]@{ Key = $key; Name = $vn; Kind = $kind; Value = $val }
                Remove-ItemProperty -LiteralPath $key -Name $vn -Confirm:$false -ErrorAction Stop
                $rec.Status = 'Done'; $rec.Message = 'Removed.'
            }
            'DisableTask' {
                $t = [string](& $get 'Task')
                $i = $t.LastIndexOf('\')
                $tp = if ($i -ge 0) { $t.Substring(0, $i + 1) } else { '\' }; $tn = $t.Substring($i + 1)
                if (-not $tp.StartsWith('\')) { $tp = '\' + $tp }
                $task = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue
                if (-not $task) { $rec.Status = 'NotFound'; $rec.Message = "No scheduled task $tp$tn."; return $rec }
                $rec.Target = "$tp$tn"
                if ($tp -like '\Microsoft\*') { if (-not (& $second "$tp$tn is in the Microsoft task folder (attackers hide there, but Windows needs many of these). Disable it anyway?")) { return $null } }
                $xml = ''; try { $xml = [string](Export-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop) } catch {}
                $rec.Evidence = [ordered]@{ Task = "$tp$tn"; State = [string]$task.State; Actions = @($task.Actions | ForEach-Object { Protect-WfxText ("$($_.Execute) $($_.Arguments)".Trim()) }); RunAs = [string]$task.Principal.UserId; Xml = $xml }
                if (-not $Cmdlet.ShouldProcess("$tp$tn", 'Disable the scheduled task (Undo-WfxAction enables it again)')) { return $null }
                $rec.Undo = [ordered]@{ TaskPath = $tp; TaskName = $tn; WasEnabled = ([string]$task.State -ne 'Disabled') }
                Disable-ScheduledTask -TaskPath $tp -TaskName $tn -Confirm:$false -ErrorAction Stop | Out-Null
                $rec.Status = 'Done'; $rec.Message = 'Disabled.'
            }
            'DisableService' {
                $name = [string](& $get 'Name')
                if ($name -notmatch '^[\w .\-\$]+$') { return (& $refuse 'Not a valid service name.') }
                $why = Test-WfxRefusedService $name; if ($why) { return (& $refuse $why) }
                $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ($name -replace "'", "''")) -ErrorAction SilentlyContinue
                if (-not $svc) { $rec.Status = 'NotFound'; $rec.Message = "No service named $name."; return $rec }
                if ([string]$svc.StartMode -in 'Boot', 'System') { return (& $refuse 'A boot or system driver; disabling it can stop Windows from starting.') }
                $img = Get-WfxImagePath $svc.PathName
                if ($img -and $img -match '(?i)\\system32\\svchost\.exe$' -or (Test-WfxMicrosoftSigned $img)) {
                    if (-not (& $second "$name runs a Microsoft-signed Windows program. Malware can register a service this way, but so does Windows. Disable it anyway?")) { return $null }
                }
                $delayed = $null; try { $delayed = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name DelayedAutostart -ErrorAction Stop).DelayedAutostart } catch {}
                $rec.Target = $name
                $rec.Evidence = [ordered]@{ Name = $name; DisplayName = [string]$svc.DisplayName; Command = (Protect-WfxText ([string]$svc.PathName)); StartMode = [string]$svc.StartMode; State = [string]$svc.State; RunAs = [string]$svc.StartName; Signature = (Get-WfxSignature $img) }
                if (-not $Cmdlet.ShouldProcess($name, 'Set the service to Disabled and stop it (Undo-WfxAction restores the start type)')) { return $null }
                $rec.Undo = [ordered]@{ Name = $name; StartMode = [string]$svc.StartMode; Delayed = $delayed; WasRunning = ([string]$svc.State -eq 'Running') }
                Set-Service -Name $name -StartupType Disabled -Confirm:$false -ErrorAction Stop
                $rec.Status = 'Done'; $rec.Message = 'Disabled.'
                if ([string]$svc.State -eq 'Running') {
                    try { Stop-Service -Name $name -Confirm:$false -ErrorAction Stop -WarningAction SilentlyContinue; $rec.Message = 'Disabled and stopped.' }
                    catch { $rec.Message = "Disabled, but not stopped ($($_.Exception.Message)); other services may depend on it. It will not start again." }
                }
            }
            'DisableWmi' {
                $consumer = [string](& $get 'Consumer')
                $binds = @(Get-CimInstance -Namespace 'root\subscription' -ClassName __FilterToConsumerBinding -ErrorAction Stop | Where-Object { [string]$_.Consumer.Name -eq $consumer })
                if (-not $binds.Count) { $rec.Status = 'NotFound'; $rec.Message = "No WMI binding to a consumer named $consumer."; return $rec }
                $saved = @($binds | ForEach-Object { [ordered]@{ Filter = [string]$_.Filter.Name; ConsumerClass = [string]$_.Consumer.CimClass.CimClassName; Consumer = [string]$_.Consumer.Name } })
                if (-not $saved[0].ConsumerClass) { $saved = @($binds | ForEach-Object { [ordered]@{ Filter = [string]$_.Filter.Name; ConsumerClass = [string]$_.Consumer.CimSystemProperties.ClassName; Consumer = [string]$_.Consumer.Name } }) }
                $rec.Evidence = [ordered]@{ Consumer = $consumer; Bindings = $saved }
                if (-not $Cmdlet.ShouldProcess("WMI consumer $consumer", 'Remove its event binding(s); the filter and consumer stay, inert (Undo-WfxAction re-binds them)')) { return $null }
                $rec.Undo = [ordered]@{ Bindings = $saved }
                $binds | Remove-CimInstance -Confirm:$false -ErrorAction Stop
                $rec.Status = 'Done'; $rec.Message = "Removed $($binds.Count) binding(s)."
            }
            'BlockAddress' {
                $addr = [string](& $get 'Address')
                $why = Test-WfxRefusedAddress -Address $addr -Own (Get-WfxOwnAddress); if ($why) { return (& $refuse $why) }
                if (@(Get-WfxSessionAddress) -contains (($addr -split '/')[0])) { return (& $refuse 'That is the computer you are connected from (RDP / WinRM / SSH); blocking it would cut you off.') }
                $rec.Target = $addr
                if (Test-WfxPrivateIp (($addr -split '/')[0])) { if (-not (& $second "$addr is on a private network. Blocking it can cut this computer off from file servers, DNS or the domain controller. Block it anyway?")) { return $null } }
                if (-not $Cmdlet.ShouldProcess($addr, 'Block all traffic to and from this address (firewall rules in group WinForensicX)')) { return $null }
                $names = @("WFX-$($rec.Id)-in", "WFX-$($rec.Id)-out")
                New-NetFirewallRule -Name $names[0] -DisplayName "WinForensicX: block $addr (in)" -Group 'WinForensicX' -Direction Inbound -RemoteAddress $addr -Action Block -Profile Any -ErrorAction Stop | Out-Null
                try { New-NetFirewallRule -Name $names[1] -DisplayName "WinForensicX: block $addr (out)" -Group 'WinForensicX' -Direction Outbound -RemoteAddress $addr -Action Block -Profile Any -ErrorAction Stop | Out-Null }
                catch { Remove-NetFirewallRule -Name $names[0] -ErrorAction SilentlyContinue; throw }
                $rec.Undo = [ordered]@{ Rules = $names }
                $off = @(try { Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object Name } catch { })
                $rec.Status = 'Done'; $rec.Message = 'Blocked in and out.' + $(if ($off.Count) { " The firewall is OFF for: $($off -join ', '); the block does not apply there." } else { '' })
            }
            'BlockProgram' {
                $path = [string](& $get 'Path')
                if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { $rec.Status = 'NotFound'; $rec.Message = "No file at $path."; return $rec }
                $path = (Get-Item -LiteralPath $path -Force).FullName; $rec.Target = $path
                if ($env:SystemRoot -and $path.StartsWith($env:SystemRoot + '\', [StringComparison]::OrdinalIgnoreCase) -and (Test-WfxMicrosoftSigned $path)) { return (& $refuse 'A Microsoft-signed Windows program; blocking it can break networking for Windows itself (block the address instead).') }
                if (-not $Cmdlet.ShouldProcess($path, 'Block this program from making network connections (firewall rule in group WinForensicX)')) { return $null }
                $names = @("WFX-$($rec.Id)-prog")
                New-NetFirewallRule -Name $names[0] -DisplayName "WinForensicX: block $(Split-Path -Leaf $path)" -Group 'WinForensicX' -Direction Outbound -Program $path -Action Block -Profile Any -ErrorAction Stop | Out-Null
                $rec.Evidence = [ordered]@{ Path = $path; Sha256 = (Get-WfxBinaryHash $path); Signature = (Get-WfxSignature $path) }
                $rec.Undo = [ordered]@{ Rules = $names }
                $rec.Status = 'Done'; $rec.Message = 'Outbound connections blocked.'
            }
            'DisableAccount' {
                $name = [string](& $get 'Name')
                if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) { return (& $refuse 'Local account cmdlets are not available in this PowerShell (use 64-bit Windows PowerShell).') }
                $u = Get-LocalUser -Name ($name -replace '^.*\\', '') -ErrorAction SilentlyContinue
                if (-not $u) { return (& $refuse "$name is not a local account on this computer. Disable domain or Entra accounts in Active Directory / Entra ID.") }
                $last = $false
                try {
                    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Where-Object { $_.PrincipalSource -eq 'Local' -and $_.ObjectClass -eq 'User' } | ForEach-Object { Get-LocalUser -SID $_.SID -ErrorAction SilentlyContinue } | Where-Object Enabled)
                    $last = ($admins.Count -eq 1 -and [string]$admins[0].SID -eq [string]$u.SID)
                } catch { if (-not (& $second 'Could not list the local administrators to make sure this is not the last one. Disable it anyway?')) { return $null } }
                $why = Test-WfxRefusedAccount -Name $u.Name -IsLastAdmin $last; if ($why) { return (& $refuse $why) }
                $rec.Target = $u.Name
                $rec.Evidence = [ordered]@{ Name = $u.Name; Sid = [string]$u.SID; Enabled = [bool]$u.Enabled; LastLogon = (ConvertTo-WfxUtcString $u.LastLogon); PasswordLastSet = (ConvertTo-WfxUtcString $u.PasswordLastSet); Description = [string]$u.Description }
                if (-not $u.Enabled) { $rec.Status = 'NotFound'; $rec.Message = 'Already disabled.'; return $rec }
                if (-not $Cmdlet.ShouldProcess($u.Name, 'Disable the local account (Undo-WfxAction enables it again; existing sessions stay signed in)')) { return $null }
                $rec.Undo = [ordered]@{ Sid = [string]$u.SID }
                Disable-LocalUser -SID $u.SID -Confirm:$false -ErrorAction Stop
                $rec.Status = 'Done'; $rec.Message = 'Disabled. Sessions already signed in are not ended: sign them out (query user / logoff) if needed.'
            }
            default { return (& $refuse "Unknown action type '$type'.") }
        }
    } catch {
        $rec.Status = 'Failed'; $rec.Message = $_.Exception.Message
    }
    $rec
}

# ───────────────────────────── public ─────────────────────────────
function Invoke-WfxRespond {
    <#
    .SYNOPSIS
        Contain a threat: stop processes, quarantine files, disable autostarts, block addresses or programs,
        disable local accounts. Every action is confirmed, recorded first, and (except stopping a process)
        can be undone with Undo-WfxAction. Needs administrator rights.
    .DESCRIPTION
        From a triage: Invoke-WfxRespond -PlanPath <case folder or respond-plan.json> goes through the actions the
        triage suggested (critical and high ones are selected; -All for every one, -ActionId to pick).
        Directly: -KillProcess, -QuarantineFile, -DisableRunKey, -DisableTask, -DisableService, -DisableWmiConsumer,
        -BlockAddress, -BlockProgram, -DisableAccount.
        -WhatIf shows what would happen. Each action asks for confirmation; riskier ones ask twice unless -Force.
        Things Windows cannot run without are refused whatever the options.
    .PARAMETER QuarantinePath  Where quarantined files and action records go (default Downloads\WinForensicX-Quarantine).
    .EXAMPLE
        Invoke-WfxRespond -PlanPath E:\cases\WFX_PC01_20261127-101500Z -WhatIf
    .EXAMPLE
        Invoke-WfxRespond -KillProcess 4242 -QuarantineFile C:\Users\ana\AppData\Roaming\upd\upd.exe
    .EXAMPLE
        Invoke-WfxRespond -BlockAddress 203.0.113.7 -DisableRunKey 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Updater'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$PlanPath = '',
        [string[]]$ActionId = @(),
        [switch]$All,
        [int[]]$KillProcess = @(),
        [string[]]$QuarantineFile = @(),
        [string[]]$DisableRunKey = @(),
        [string[]]$DisableTask = @(),
        [string[]]$DisableService = @(),
        [string[]]$DisableWmiConsumer = @(),
        [string[]]$BlockAddress = @(),
        [string[]]$BlockProgram = @(),
        [string[]]$DisableAccount = @(),
        [string]$Reason = '',
        [string]$QuarantinePath = '',
        [switch]$Force
    )
    if (-not (Test-WfxWindows)) { throw 'Respond mode needs Windows.' }
    if (-not (Test-WfxAdmin) -and -not $WhatIfPreference) { throw 'Respond mode needs administrator rights (run the tool elevated). -WhatIf works without them.' }
    $actions = [System.Collections.Generic.List[object]]::new()
    $mk = { param($Type, $Target, [hashtable]$Params) $actions.Add([pscustomobject]@{ Type = $Type; Target = [string]$Target; Params = $Params; Reason = $(if ($Reason) { $Reason } else { 'Chosen by the operator' }); Findings = @() }) }

    if ($PlanPath) {
        $pf = if (Test-Path -LiteralPath $PlanPath -PathType Container) { Join-Path $PlanPath 'respond-plan.json' } else { $PlanPath }
        if (-not (Test-Path -LiteralPath $pf -PathType Leaf)) { throw "No response plan at $pf." }
        $plan = Get-Content -LiteralPath $pf -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$plan.Schema -ne 'winforensicx.respond-plan/1') { throw "$pf is not a WinForensicX response plan." }
        if ([string]$plan.Host -and [string]$plan.Host -ne [Environment]::MachineName) { throw "This plan is for $($plan.Host); this computer is $([Environment]::MachineName). Run it on that computer." }
        # A plan inside a closed case is covered by the case manifest: refuse one that was edited afterwards.
        $mf = Join-Path (Split-Path -Parent $pf) 'manifest.json'
        if (Test-Path -LiteralPath $mf) {
            $m = Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json
            $entry = @($m.files | Where-Object { $_.path -eq 'respond-plan.json' }) | Select-Object -First 1
            $now = (Get-FileHash -LiteralPath $pf -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($entry -and $entry.sha256 -ne $now -and -not $Force) { throw 'respond-plan.json was changed after the triage wrote it (its hash no longer matches manifest.json). Check it, then use -Force to run it anyway.' }
        }
        foreach ($a in @($plan.Actions)) {
            $pick = if ($ActionId.Count) { $ActionId -contains [string]$a.Id } elseif ($All) { $true } else { [bool]$a.Selected }
            if (-not $pick) { continue }
            $h = @{}; foreach ($pp in $a.Params.PSObject.Properties) { $h[$pp.Name] = $pp.Value }
            $actions.Add([pscustomobject]@{ Type = [string]$a.Type; Target = [string]$a.Target; Params = $h; Reason = [string]$a.Reason; Findings = @($a.Findings) })
        }
    }
    foreach ($x in $KillProcess) { & $mk 'Kill' "PID $x" @{ Pid = $x } }
    foreach ($x in $QuarantineFile) { & $mk 'Quarantine' $x @{ Path = $x } }
    foreach ($x in $DisableRunKey) {
        if ($x -notmatch '^(.+\\(?:Run|RunOnce))\\([^\\]+)$') { throw "Give the Run-key value as <key>\<value name>, e.g. HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Updater (got '$x')." }
        & $mk 'DisableRunKey' $x @{ Key = $Matches[1]; Name = $Matches[2] }
    }
    foreach ($x in $DisableTask) { & $mk 'DisableTask' $x @{ Task = $x } }
    foreach ($x in $DisableService) { & $mk 'DisableService' $x @{ Name = $x } }
    foreach ($x in $DisableWmiConsumer) { & $mk 'DisableWmi' $x @{ Consumer = $x } }
    foreach ($x in $BlockAddress) { & $mk 'BlockAddress' $x @{ Address = $x } }
    foreach ($x in $BlockProgram) { & $mk 'BlockProgram' $x @{ Path = $x } }
    foreach ($x in $DisableAccount) { & $mk 'DisableAccount' $x @{ Name = $x } }
    if (-not $actions.Count) { Write-Warning 'Nothing to do: no action selected.'; return }

    # Stop processes first (they may hold files open and recreate autostarts), then files and autostarts, then the network.
    $order = @{ Kill = 0; DisableService = 1; DisableTask = 2; DisableWmi = 3; DisableRunKey = 4; Quarantine = 5; BlockProgram = 6; BlockAddress = 7; DisableAccount = 8 }
    $sorted = @($actions | Sort-Object { if ($order.ContainsKey([string]$_.Type)) { $order[[string]$_.Type] } else { 9 } })
    $root = if ($WhatIfPreference) { Get-WfxQuarantineRoot -Path $QuarantinePath } else { Initialize-WfxQuarantineRoot -Path $QuarantinePath }
    foreach ($a in $sorted) {
        $r = Invoke-WfxResponseAction -Action $a -Cmdlet $PSCmdlet -Root $root -Force:$Force
        if (-not $r) { continue }
        if (-not $WhatIfPreference) { Save-WfxActionRecord -Record $r -Root $root }
        [pscustomobject]$r
    }
}

function Get-WfxAction {
    <#
    .SYNOPSIS What Respond mode has done on this computer: every action with its status, what was recorded
    before the change, and whether it can be undone.
    .EXAMPLE
        Get-WfxAction | Format-Table Time, Type, Target, Status, Undone
    #>
    [CmdletBinding()]
    param([string]$QuarantinePath = '', [int]$Days = 0)
    Get-WfxActionRecord -Root (Get-WfxQuarantineRoot -Path $QuarantinePath) -Days $Days
}

function Undo-WfxAction {
    <#
    .SYNOPSIS Puts back what a Respond action changed: restores a quarantined file (with its times and its
    downloaded-from-the-internet mark), a Run-key value, a task, a service start type, WMI bindings, a local
    account; removes firewall blocks and ends an isolation. Stopped processes cannot be brought back.
    .PARAMETER RestorePath  Restore a quarantined file somewhere else (for analysis) instead of its original place.
    .EXAMPLE
        Undo-WfxAction -Id 20261127101500-3fa2c1
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string[]]$Id, [string]$QuarantinePath = '', [string]$RestorePath = '')
    if (-not (Test-WfxAdmin) -and -not $WhatIfPreference) { throw 'Undo needs administrator rights.' }
    $root = Get-WfxQuarantineRoot -Path $QuarantinePath
    foreach ($one in $Id) {
        if ($one -notmatch '^[0-9]{14}-[0-9a-f]{6}$') { Write-Warning "Not an action id: $one"; continue }
        $f = Join-Path (Join-Path $root 'actions') "$one.json"
        if (-not (Test-Path -LiteralPath $f)) { Write-Warning "No action $one in $root."; continue }
        $rec = Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($rec.Status -ne 'Done') { Write-Warning "$one was not carried out ($($rec.Status)); nothing to undo."; continue }
        if ($rec.Undone) { Write-Warning "$one was already undone at $($rec.Undone)."; continue }
        if (-not $rec.Reversible -or -not $rec.Undo) { Write-Warning "$one ($($rec.Type)) cannot be undone."; continue }
        $u = $rec.Undo
        if (-not $PSCmdlet.ShouldProcess("$($rec.Type) $($rec.Target)", 'Undo')) { continue }
        try {
            switch ([string]$rec.Type) {
                'Quarantine' {
                    $dest = if ($RestorePath) { $RestorePath } else { [string]$u.Path }
                    if (Test-Path -LiteralPath $dest) { throw "$dest already exists; move it away or use -RestorePath." }
                    $blob = Join-Path $root ([string]$u.Blob)
                    $tmp = "$dest.wfx-restoring"
                    $sha = Read-WfxQuarantineFile -Source $blob -Target $tmp
                    if ($sha -ne [string]$u.Sha256) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; throw 'The quarantined copy does not match the recorded SHA-256; not restored.' }
                    Move-Item -LiteralPath $tmp -Destination $dest -Confirm:$false
                    $fi = Get-Item -LiteralPath $dest -Force
                    $fi.CreationTimeUtc = [datetime]::new([long]$u.Created, [DateTimeKind]::Utc); $fi.LastWriteTimeUtc = [datetime]::new([long]$u.Modified, [DateTimeKind]::Utc); $fi.LastAccessTimeUtc = [datetime]::new([long]$u.Accessed, [DateTimeKind]::Utc)
                    if ([string]$u.Zone) { Set-Content -LiteralPath $dest -Stream Zone.Identifier -Value ([string]$u.Zone) -NoNewline -ErrorAction SilentlyContinue }
                    $fi.Attributes = [IO.FileAttributes][int]$u.Attributes
                    if (-not $RestorePath) { Remove-Item -LiteralPath $blob -Force -ErrorAction SilentlyContinue }
                }
                'DisableRunKey' {
                    $val = $u.Value
                    if ([string]$u.Kind -eq 'Binary') { $val = [Convert]::FromBase64String([string]$val) }
                    elseif ([string]$u.Kind -eq 'MultiString') { $val = [string[]]@($val) }
                    New-ItemProperty -LiteralPath ([string]$u.Key) -Name ([string]$u.Name) -Value $val -PropertyType ([string]$u.Kind) -Force -Confirm:$false -ErrorAction Stop | Out-Null
                }
                'DisableTask' { if ($u.WasEnabled) { Enable-ScheduledTask -TaskPath ([string]$u.TaskPath) -TaskName ([string]$u.TaskName) -Confirm:$false -ErrorAction Stop | Out-Null } }
                'DisableService' {
                    $map = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }
                    $st = $map[[string]$u.StartMode]; if (-not $st) { $st = 'Manual' }
                    Set-Service -Name ([string]$u.Name) -StartupType $st -Confirm:$false -ErrorAction Stop
                    if ($null -ne $u.Delayed) { Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$([string]$u.Name)" -Name DelayedAutostart -Value ([int]$u.Delayed) -ErrorAction SilentlyContinue }
                    if ($u.WasRunning) { Write-Warning "Start type of $($u.Name) restored. It was running before; start it yourself if you want it running now (Start-Service $($u.Name))." }
                }
                'DisableWmi' {
                    foreach ($b in @($u.Bindings)) {
                        $flt = Get-CimInstance -Namespace 'root\subscription' -ClassName __EventFilter -Filter ("Name='{0}'" -f (([string]$b.Filter) -replace "'", "''")) -ErrorAction Stop
                        $con = Get-CimInstance -Namespace 'root\subscription' -ClassName ([string]$b.ConsumerClass) -Filter ("Name='{0}'" -f (([string]$b.Consumer) -replace "'", "''")) -ErrorAction Stop
                        if (-not $flt -or -not $con) { throw "The filter or consumer of binding $($b.Filter) -> $($b.Consumer) no longer exists." }
                        New-CimInstance -Namespace 'root\subscription' -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$flt; Consumer = [ref]$con } -ErrorAction Stop | Out-Null
                    }
                }
                { $_ -in 'BlockAddress', 'BlockProgram' } { foreach ($n in @($u.Rules)) { Remove-NetFirewallRule -Name ([string]$n) -Confirm:$false -ErrorAction SilentlyContinue } }
                'DisableAccount' { Enable-LocalUser -SID ([string]$u.Sid) -Confirm:$false -ErrorAction Stop }
                'Isolate' { Stop-WfxIsolationCore -Undo $u }
                default { throw "Unknown action type $($rec.Type)." }
            }
            $rec.Undone = Get-WfxUtcNow
            Save-WfxJson -InputObject $rec -Path $f -Depth 8
            try { Add-Content -LiteralPath (Join-Path $root 'actions.log') -Value (@{ time = $rec.Undone; undo = $one } | ConvertTo-Json -Compress) -Encoding UTF8 } catch {}
            [pscustomobject]@{ Id = $one; Type = $rec.Type; Target = $rec.Target; Undone = $rec.Undone }
        } catch { Write-Error "Undo of $one failed: $($_.Exception.Message)" }
    }
}
