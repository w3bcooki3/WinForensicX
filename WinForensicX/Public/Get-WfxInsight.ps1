# Live, read-only "insight" views of a Windows host — fast answers to "show me X" without running a full
# triage. Every topic returns plain objects (so they can be filtered, sorted, exported or piped), never
# changes anything, and degrades with a clear message when it needs administrator rights.

function Get-WfxShort { param([AllowEmptyString()][string]$Text, [int]$Max = 120) if (-not $Text) { return '' }; $t = ($Text -replace '\s+', ' ').Trim(); if ($t.Length -gt $Max) { $t.Substring(0, $Max - 1) + '…' } else { $t } }

function Get-WfxRegValueSafe { param([string]$Path, [string]$Name) try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null } }

$script:WfxLogonTypes = @{ '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch'; '5' = 'Service'; '7' = 'Unlock'; '8' = 'NetworkCleartext'; '9' = 'NewCredentials'; '10' = 'RemoteInteractive (RDP)'; '11' = 'CachedInteractive' }

$script:WfxInsightTopics = [ordered]@{
    # ───────────── System ─────────────
    'system'      = @{ Group = 'System'; Title = 'System overview'; Desc = 'OS, build, uptime, domain, hardware, time zone, Secure Boot, PowerShell.'; Admin = $false; Script = {
            $os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
            $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
            $sb = try { [string](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { 'unknown (needs admin / UEFI)' }
            $up = (Get-Date) - $os.LastBootUpTime
            $info = [ordered]@{
                'Computer' = $env:COMPUTERNAME; 'Domain / workgroup' = $cs.Domain; 'Part of domain' = $cs.PartOfDomain
                'OS' = $os.Caption; 'Version / build' = "$($os.Version) (build $($os.BuildNumber))"; 'Architecture' = $os.OSArchitecture
                'Installed' = $os.InstallDate; 'Last boot' = $os.LastBootUpTime; 'Uptime' = ('{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes)
                'Manufacturer / model' = "$($cs.Manufacturer) $($cs.Model)"; 'BIOS serial' = $(if ($bios) { $bios.SerialNumber } else { '' })
                'Memory (GB)' = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1); 'Logged-on user (console)' = $cs.UserName
                'Time zone' = (Get-TimeZone).Id; 'Secure Boot' = $sb; 'PowerShell' = $PSVersionTable.PSVersion.ToString()
                'Running elevated' = (Test-WfxAdmin)
            }
            $info.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Property = $_.Key; Value = [string]$_.Value } }
        }
    }
    'hotfixes'    = @{ Group = 'System'; Title = 'Installed updates (hotfixes)'; Desc = 'Windows updates and when they were installed — shows patch level.'; Admin = $false; Script = {
            Get-CimInstance Win32_QuickFixEngineering | Sort-Object { try { [datetime]$_.InstalledOn } catch { [datetime]::MinValue } } -Descending |
                Select-Object HotFixID, Description, InstalledOn, InstalledBy
        }
    }
    'software'    = @{ Group = 'System'; Title = 'Installed software'; Desc = 'Programs from the Uninstall registry keys (machine + per-user), newest first.'; Admin = $false; Script = {
            $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-|^S-1-12-1-' -and $_.PSChildName -notmatch '_Classes$' } |
                ForEach-Object { $keys += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
            $rows = foreach ($k in $keys) {
                Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object {
                    $d = [string]$_.InstallDate; $dt = $null
                    if ($d -match '^\d{8}$') { try { $dt = [datetime]::ParseExact($d, 'yyyyMMdd', $null) } catch {} }
                    [pscustomobject]@{ Name = $_.DisplayName; Version = $_.DisplayVersion; Publisher = $_.Publisher; Installed = $dt; Scope = $(if ($k -like 'Registry::HKEY_USERS*') { 'User' } elseif ($k -like '*WOW6432Node*') { 'Machine (32-bit)' } else { 'Machine' }); Location = $_.InstallLocation }
                }
            }
            $rows | Sort-Object Name, Version -Unique | Sort-Object @{ e = { if ($_.Installed) { $_.Installed } else { [datetime]::MinValue } } } -Descending
        }
    }
    'users'       = @{ Group = 'System'; Title = 'Local user accounts'; Desc = 'Local accounts, enabled state, last logon, password age.'; Admin = $false; Script = {
            if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
                Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, @{ n = 'SID'; e = { $_.SID.Value } }, Description
            } else { Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object Name, @{ n = 'Enabled'; e = { -not $_.Disabled } }, SID, Description }
        }
    }
    'groups'      = @{ Group = 'System'; Title = 'Privileged local groups'; Desc = 'Members of Administrators, Remote Desktop Users, Remote Management Users, Backup Operators and similar.'; Admin = $false; Script = {
            foreach ($g in 'Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators', 'Hyper-V Administrators', 'Event Log Readers', 'Distributed COM Users') {
                $members = @()
                try { $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Group = $g; Member = $_.Name; Type = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource } }) }
                catch {
                    # Get-LocalGroupMember fails on orphaned SIDs; fall back to `net localgroup` (English output).
                    $out = @(net localgroup "$g" 2>$null)
                    if ($LASTEXITCODE -eq 0) {
                        $in = $false
                        $members = foreach ($l in $out) { if ($l -match '^-{5,}') { $in = $true; continue }; if ($in -and $l -and $l -notmatch 'command completed') { [pscustomobject]@{ Group = $g; Member = $l.Trim(); Type = ''; Source = 'net localgroup' } } }
                    }
                }
                $members
            }
        }
    }
    'sessions'    = @{ Group = 'System'; Title = 'Logged-on sessions'; Desc = 'Interactive and RDP sessions right now (quser).'; Admin = $false; Script = {
            $q = @(quser 2>$null)
            if ($q.Count -lt 2) { return [pscustomobject]@{ User = (Get-CimInstance Win32_ComputerSystem).UserName; Session = 'console'; State = 'Active'; Idle = ''; LogonTime = '' } }
            foreach ($l in ($q | Select-Object -Skip 1)) {
                $t = ($l.Substring(1) -split '\s{2,}')
                if ($t.Count -ge 5) { [pscustomobject]@{ User = $t[0]; Session = $t[1]; Id = $t[2]; State = $t[3]; Idle = $t[4]; LogonTime = ($t[5..($t.Count - 1)] -join ' ') } }
                elseif ($t.Count -eq 4) { [pscustomobject]@{ User = $t[0]; Session = ''; Id = $t[1]; State = $t[2]; Idle = $t[3]; LogonTime = '' } }
            }
        }
    }
    'profiles'    = @{ Group = 'System'; Title = 'User profiles on disk'; Desc = 'Every profile folder, its SID, and when it was last used.'; Admin = $false; Script = {
            Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
                $n = try { (New-Object Security.Principal.SecurityIdentifier($_.SID)).Translate([Security.Principal.NTAccount]).Value } catch { '(unresolved)' }
                [pscustomobject]@{ Account = $n; Path = $_.LocalPath; LastUsed = $_.LastUseTime; Loaded = $_.Loaded; SID = $_.SID }
            } | Sort-Object LastUsed -Descending
        }
    }
    'shares'      = @{ Group = 'System'; Title = 'Network shares'; Desc = 'Folders shared from this host (custom shares are worth checking).'; Admin = $false; Script = {
            Get-CimInstance Win32_Share | Select-Object Name, Path, Description, @{ n = 'Kind'; e = { if ($_.Name -match '\$$') { 'Admin/hidden' } else { 'Custom' } } }
        }
    }
    'usb'         = @{ Group = 'System'; Title = 'USB storage history'; Desc = 'USB mass-storage devices ever connected (USBSTOR registry).'; Admin = $false; Script = {
            $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
            if (-not (Test-Path $root)) { return }
            foreach ($dev in Get-ChildItem $root -ErrorAction SilentlyContinue) {
                foreach ($inst in Get-ChildItem $dev.PSPath -ErrorAction SilentlyContinue) {
                    $p = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
                    [pscustomobject]@{ Device = $(if ($p.FriendlyName) { $p.FriendlyName } else { $dev.PSChildName }); Serial = ($inst.PSChildName -replace '&\d$', ''); Class = $dev.PSChildName; Manufacturer = $p.Mfg -replace '^@.*;', '' }
                }
            }
        }
    }
    'volumes'     = @{ Group = 'System'; Title = 'Drives & encryption'; Desc = 'Disks, free space, file system and BitLocker status (BitLocker needs admin).'; Admin = $false; Script = {
            $bl = @{}; try { Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { $bl[$_.MountPoint] = "$($_.ProtectionStatus) / $($_.VolumeStatus)" } } catch {}
            Get-CimInstance Win32_LogicalDisk | ForEach-Object {
                [pscustomobject]@{ Drive = $_.DeviceID; Label = $_.VolumeName; Type = @{ 2 = 'Removable'; 3 = 'Fixed'; 4 = 'Network'; 5 = 'CD/DVD' }[[int]$_.DriveType]; FileSystem = $_.FileSystem
                    SizeGB = [Math]::Round($_.Size / 1GB, 1); FreeGB = [Math]::Round($_.FreeSpace / 1GB, 1); BitLocker = $(if ($bl.ContainsKey($_.DeviceID)) { $bl[$_.DeviceID] } else { 'unknown' }); Network = $_.ProviderName }
            }
        }
    }

    # ───────────── Processes ─────────────
    'processes'   = @{ Group = 'Processes'; Title = 'Running processes (signed / owner / parent)'; Desc = 'Every process with user, signature status, company, parent and command line.'; Admin = $false; Script = {
            Get-WfxProcessData | Expand-WfxRecord | Add-WfxFlag Process | Sort-Object Name | Select-Object Flag, Why, Technique, Rule, Pid, Name, User, @{ n = 'Signature'; e = { $_.SignatureStatus } }, Company, @{ n = 'Parent'; e = { "$($_.ParentName) ($($_.Ppid))" } }, @{ n = 'Started'; e = { $_.CreateTime } }, @{ n = 'CommandLine'; e = { Get-WfxShort $_.CommandLine 160 } }, Path
        }
    }
    'tree'        = @{ Group = 'Processes'; Title = 'Process tree'; Desc = 'Parent → child hierarchy, so unusual chains stand out (e.g. winword → powershell).'; Admin = $false; Script = {
            $all = @(Get-CimInstance Win32_Process)
            $byPid = @{}; foreach ($p in $all) { $byPid[[int]$p.ProcessId] = $p }
            $kids = @{}
            foreach ($p in $all) {
                $pp = [int]$p.ParentProcessId; $parent = $byPid[$pp]
                if ($pp -eq [int]$p.ProcessId -or -not $parent -or ($parent.CreationDate -and $p.CreationDate -and $parent.CreationDate -gt $p.CreationDate)) { $pp = -1 }
                if (-not $kids.ContainsKey($pp)) { $kids[$pp] = [System.Collections.Generic.List[object]]::new() }
                $kids[$pp].Add($p)
            }
            $rows = [System.Collections.Generic.List[object]]::new()
            $walk = $null
            $walk = { param($ppid, $depth)
                if (-not $kids.ContainsKey($ppid) -or $depth -gt 40) { return }
                foreach ($c in ($kids[$ppid] | Sort-Object CreationDate)) {
                    $rows.Add([pscustomobject]@{ Tree = (('  ' * $depth) + $(if ($depth) { '└ ' } else { '' }) + $c.Name); Pid = [int]$c.ProcessId; Started = $c.CreationDate; CommandLine = (Get-WfxShort (Protect-WfxText $c.CommandLine) 140) })
                    & $walk ([int]$c.ProcessId) ($depth + 1)
                }
            }
            & $walk -1 0
            $rows
        }
    }
    'unsigned'    = @{ Group = 'Processes'; Title = 'Processes that are unsigned or run from user folders'; Desc = 'The short list worth a second look.'; Admin = $false; Script = {
            Get-WfxProcessData | Expand-WfxRecord | Add-WfxFlag Process | Where-Object { $_.Path -and (-not (Test-WfxTrustedSignature $_.SignatureStatus) -or (Test-WfxUserWritablePath $_.Path)) } |
                Select-Object Flag, Why, Technique, Rule, Pid, Name, User, @{ n = 'Signature'; e = { $_.SignatureStatus } }, Company, Path, @{ n = 'CommandLine'; e = { Get-WfxShort $_.CommandLine 140 } }
        }
    }

    # ───────────── Network ─────────────
    'listeners'   = @{ Group = 'Network'; Title = 'Listening ports'; Desc = 'Which programs accept network connections (TCP listen + UDP bound).'; Admin = $false; Script = {
            $paths = @{}; Get-CimInstance Win32_Process | ForEach-Object { $paths[[int]$_.ProcessId] = $_.ExecutablePath }
            Get-WfxNetworkData | Expand-WfxRecord | Add-WfxFlag Network | Where-Object { $_.State -in 'Listen', 'Bound' } | Sort-Object Protocol, LocalPort |
                Select-Object Flag, Why, Technique, Rule, Protocol, LocalAddress, LocalPort, Pid, Process, @{ n = 'Exposure'; e = { if ($_.LocalAddress -in '0.0.0.0', '::') { 'all interfaces' } elseif ($_.LocalAddress -match '^(127\.|::1)') { 'loopback only' } else { 'one interface' } } }, @{ n = 'Path'; e = { $paths[[int]$_.Pid] } }
        }
    }
    'connections' = @{ Group = 'Network'; Title = 'Active connections'; Desc = 'Established connections with process and name (from the DNS cache — no lookups are sent).'; Admin = $false; Script = {
            $map = Get-WfxDnsAddressMap -DnsEntry @(Get-WfxDnsData | Expand-WfxRecord)
            Get-WfxNetworkData | Expand-WfxRecord | Add-WfxFlag Network -DnsMap $map | Where-Object { $_.State -match 'Established|SynSent|CloseWait' } | Sort-Object Process |
                Select-Object Flag, Why, Technique, Rule, Process, Pid, LocalPort, RemoteAddress, RemotePort, State, @{ n = 'RemoteName'; e = { if ($map.ContainsKey([string]$_.RemoteAddress)) { @($map[[string]$_.RemoteAddress]) -join ', ' } else { '' } } }, @{ n = 'Public'; e = { -not (Test-WfxPrivateIp $_.RemoteAddress) } }
        }
    }
    'dns'         = @{ Group = 'Network'; Title = 'DNS cache'; Desc = 'Names this host resolved recently — a quick look at where it has been talking.'; Admin = $false; Script = { Get-WfxDnsData | Expand-WfxRecord | Add-WfxFlag Dns | Sort-Object Name | Select-Object Flag, Why, Technique, Rule, Name, Type, Data, TTL } }
    'adapters'    = @{ Group = 'Network'; Title = 'Network adapters & IP configuration'; Desc = 'IP addresses, gateways, DNS servers, DHCP, MAC.'; Admin = $false; Script = {
            Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description, MACAddress, @{ n = 'IP'; e = { $_.IPAddress -join ', ' } }, @{ n = 'Gateway'; e = { $_.DefaultIPGateway -join ', ' } }, @{ n = 'DNS servers'; e = { $_.DNSServerSearchOrder -join ', ' } }, DHCPEnabled, DHCPServer, DNSDomain
        }
    }
    'routes'      = @{ Group = 'Network'; Title = 'Routing table'; Desc = 'IPv4 routes (unexpected routes can indicate tunnelling or pivoting).'; Admin = $false; Script = { Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Sort-Object RouteMetric | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric } }
    'arp'         = @{ Group = 'Network'; Title = 'Neighbours (ARP cache)'; Desc = 'Hosts on the local network this machine has talked to.'; Admin = $false; Script = { Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -notin 'Unreachable', 'Permanent' -or $_.IPAddress -notmatch '^(22[4-9]|23\d|255)\.' } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias } }
    'hosts'       = @{ Group = 'Network'; Title = 'hosts file entries'; Desc = 'Static name overrides (malware sometimes redirects security sites here).'; Admin = $false; Script = {
            $f = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            Get-Content -LiteralPath $f -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#\s]' } | ForEach-Object { $t = ($_ -replace '#.*$', '').Trim() -split '\s+'; [pscustomobject]@{ Address = $t[0]; Names = ($t[1..($t.Count - 1)] -join ' ') } }
        }
    }
    'proxy'       = @{ Group = 'Network'; Title = 'Proxy settings'; Desc = 'System (WinHTTP) and user proxy / PAC settings — a classic traffic-interception trick.'; Admin = $false; Script = {
            $is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            [pscustomobject]@{ Scope = 'User (WinINet)'; Enabled = [bool](Get-WfxRegValueSafe $is 'ProxyEnable'); Server = (Get-WfxRegValueSafe $is 'ProxyServer'); PacUrl = (Get-WfxRegValueSafe $is 'AutoConfigURL'); Bypass = (Get-WfxRegValueSafe $is 'ProxyOverride') }
            $w = (@(netsh winhttp show proxy 2>$null) -join ' ') -replace '\s+', ' '
            [pscustomobject]@{ Scope = 'System (WinHTTP)'; Enabled = ($w -notmatch 'Direct access'); Server = $(if ($w -match 'Proxy Server\(s\)\s*:\s*(\S+)') { $Matches[1] } else { '' }); PacUrl = ''; Bypass = $(if ($w -match 'Bypass List\s*:\s*(\S+)') { $Matches[1] } else { '' }) }
        }
    }
    'wifi'        = @{ Group = 'Network'; Title = 'Saved Wi-Fi networks (names only)'; Desc = 'Networks this host has joined. Keys are never shown.'; Admin = $false; Script = {
            @(netsh wlan show profiles 2>$null) | Where-Object { $_ -match ':\s*(.+)$' -and $_ -match 'Profile' } | ForEach-Object { [pscustomobject]@{ Network = ($_ -split ':\s*', 2)[1].Trim() } }
        }
    }
    'firewall'    = @{ Group = 'Network'; Title = 'Custom inbound firewall allow rules'; Desc = 'Enabled inbound "allow" rules that were not part of a built-in Windows rule group.'; Admin = $false; Script = {
            $prof = Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)=$(if ($_.Enabled) { 'on' } else { 'OFF' })" }
            [pscustomobject]@{ Rule = "Profiles: $($prof -join ', ')"; Program = ''; Ports = ''; Profile = ''; Created = '' }
            Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop | Where-Object { -not $_.Group } | ForEach-Object {
                $app = try { ($_ | Get-NetFirewallApplicationFilter -ErrorAction Stop).Program } catch { '' }
                $port = try { (($_ | Get-NetFirewallPortFilter -ErrorAction Stop) | ForEach-Object { "$($_.Protocol) $($_.LocalPort)" }) -join ', ' } catch { '' }
                [pscustomobject]@{ Rule = $_.DisplayName; Program = $app; Ports = $port; Profile = [string]$_.Profile; Created = '' }
            }
        }
    }
    'smb'         = @{ Group = 'Network'; Title = 'SMB sessions to this host'; Desc = 'Who is connected to this machine''s shares right now (needs admin).'; Admin = $true; Script = { Get-SmbSession -ErrorAction Stop | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists, Dialect } }

    # ───────────── Persistence ─────────────
    'autoruns'    = @{ Group = 'Persistence'; Title = 'Autostart entries (Run keys, Startup, tasks, WMI, Winlogon, IFEO, …)'; Desc = 'Everything set to start automatically, with signature status.'; Admin = $false; Script = {
            Get-WfxPersistenceData | Expand-WfxRecord | Add-WfxFlag Autostart | Where-Object { $_.Kind -ne 'RunMRU' } | Sort-Object Kind, Name | Select-Object Flag, Why, Technique, Rule, Kind, Name, @{ n = 'Signature'; e = { $_.SignatureStatus } }, @{ n = 'Command'; e = { Get-WfxShort $_.Command 150 } }, Location, User
        }
    }
    'services'    = @{ Group = 'Persistence'; Title = 'Services that are not standard Windows services'; Desc = 'Services whose binary is outside Windows folders or not validly signed.'; Admin = $false; Script = {
            Get-WfxServiceAndDriver | Expand-WfxRecord | Add-WfxFlag Autostart | Where-Object { $_.Kind -eq 'Service' -and $_.Path -and (-not (Test-WfxSystemPath $_.Path) -or -not (Test-WfxTrustedSignature $_.SignatureStatus)) } |
                Sort-Object Name | Select-Object Flag, Why, Technique, Rule, Name, DisplayName, State, @{ n = 'Start'; e = { $_.Location -replace '^Service:' } }, User, @{ n = 'Signature'; e = { $_.SignatureStatus } }, Path
        }
    }
    'drivers'     = @{ Group = 'Persistence'; Title = 'Drivers outside System32\drivers or unsigned'; Desc = 'Kernel drivers worth checking (also flags known-vulnerable drivers in triage).'; Admin = $false; Script = {
            Get-WfxServiceAndDriver | Expand-WfxRecord | Add-WfxFlag Autostart | Where-Object { $_.Kind -eq 'Driver' -and ($_.Path -notmatch '(?i)\\system32\\drivers\\' -or -not (Test-WfxTrustedSignature $_.SignatureStatus)) } |
                Select-Object Flag, Why, Technique, Rule, Name, DisplayName, State, @{ n = 'Signature'; e = { $_.SignatureStatus } }, Path
        }
    }
    'tasks'       = @{ Group = 'Persistence'; Title = 'Scheduled tasks (non-Microsoft)'; Desc = 'Tasks outside \Microsoft\, with what they run, as whom, and last run time.'; Admin = $false; Script = {
            Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
                $i = try { $_ | Get-ScheduledTaskInfo -ErrorAction Stop } catch { $null }
                $act = @($_.Actions | ForEach-Object { if ($_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() } elseif ($_.ClassId) { "COM $($_.ClassId)" } }) -join ' ; '
                [pscustomobject]@{ Task = "$($_.TaskPath)$($_.TaskName)"; State = [string]$_.State; RunAs = $_.Principal.UserId; Action = (Get-WfxShort (Protect-WfxText $act) 160); _Text = (Protect-WfxText $act); Author = $_.Author; LastRun = $(if ($i) { $i.LastRunTime } else { $null }); NextRun = $(if ($i) { $i.NextRunTime } else { $null }) }
            } | Sort-Object LastRun -Descending
        }
    }
    'wmi'         = @{ Group = 'Persistence'; Title = 'WMI event subscriptions'; Desc = 'Filters, consumers and bindings in root\subscription (a stealthy persistence method).'; Admin = $false; Script = {
            foreach ($c in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__EventFilter', '__FilterToConsumerBinding') {
                Get-CimInstance -Namespace root\subscription -ClassName $c -ErrorAction SilentlyContinue | ForEach-Object {
                    [pscustomobject]@{ Type = $c; Name = [string]$_.Name; Detail = (Get-WfxShort (Protect-WfxText ([string]($_.CommandLineTemplate, $_.ScriptText, $_.Query, "$($_.Filter) -> $($_.Consumer)" | Where-Object { $_ } | Select-Object -First 1))) 160); _Text = (Protect-WfxText ([string]($_.CommandLineTemplate, $_.ScriptText | Where-Object { $_ } | Select-Object -First 1))) }
                }
            }
        }
    }

    # ───────────── Event logs ─────────────
    'logons'      = @{ Group = 'Events'; Title = 'Successful logons (summary)'; Desc = 'Who logged on, how (type) and from where, with first/last time (4624, needs admin).'; Admin = $true; Days = 7; Script = {
            param($Days)
            Get-WfxEventQuick -Log Security -Id 4624 -Days $Days -Max 20000 | Where-Object { $_.Fields.TargetUserName -notmatch '\$$|^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON)$' } |
                Group-Object { "$($_.Fields.TargetDomainName)\$($_.Fields.TargetUserName)|$($_.Fields.LogonType)|$($_.Fields.IpAddress)" } | ForEach-Object {
                    $f = $_.Group[0].Fields; $t = $_.Group | Sort-Object Time
                    [pscustomobject]@{ User = "$($f.TargetDomainName)\$($f.TargetUserName)"; LogonType = "$($f.LogonType) $($script:WfxLogonTypes[[string]$f.LogonType])"; Source = $(if ($f.IpAddress -and $f.IpAddress -ne '-') { $f.IpAddress } else { $f.WorkstationName }); Count = $_.Count; First = $t[0].Time; Last = $t[-1].Time }
                } | Sort-Object Last -Descending
        }
    }
    'failedlogons' = @{ Group = 'Events'; Title = 'Failed logons (summary)'; Desc = 'Failed logons grouped by account and source — password guessing shows up here (4625).'; Admin = $true; Days = 7; Script = {
            param($Days)
            $reason = @{ '0xc000006a' = 'wrong password'; '0xc0000064' = 'no such user'; '0xc0000234' = 'locked out'; '0xc0000072' = 'disabled'; '0xc000006f' = 'outside hours'; '0xc0000071' = 'password expired'; '0xc0000193' = 'account expired' }
            Get-WfxEventQuick -Log Security -Id 4625 -Days $Days -Max 20000 | Group-Object { "$($_.Fields.TargetUserName)|$($_.Fields.IpAddress)" } | ForEach-Object {
                $f = $_.Group[0].Fields; $t = $_.Group | Sort-Object Time
                [pscustomobject]@{ User = $f.TargetUserName; Source = $(if ($f.IpAddress -and $f.IpAddress -ne '-') { $f.IpAddress } else { $f.WorkstationName }); Count = $_.Count; Reason = $reason[([string]$f.SubStatus).ToLower()]; First = $t[0].Time; Last = $t[-1].Time }
            } | Sort-Object Count -Descending
        }
    }
    'rdp'         = @{ Group = 'Events'; Title = 'Remote Desktop activity'; Desc = 'RDP authentications (1149) and RDP logons (4624 type 10).'; Admin = $true; Days = 30; Script = {
            param($Days)
            Get-WfxEventQuick -Log 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 1149 -Days $Days -Max 2000 | ForEach-Object { [pscustomobject]@{ Time = $_.Time; Event = 'RDP auth (1149)'; User = "$($_.Fields.Param2)\$($_.Fields.Param1)"; Source = $_.Fields.Param3 } }
            Get-WfxEventQuick -Log Security -Id 4624 -Days $Days -Max 20000 | Where-Object { $_.Fields.LogonType -eq '10' } | ForEach-Object { [pscustomobject]@{ Time = $_.Time; Event = 'RDP logon (4624/10)'; User = "$($_.Fields.TargetDomainName)\$($_.Fields.TargetUserName)"; Source = $_.Fields.IpAddress } }
        }
    }
    'accounts'    = @{ Group = 'Events'; Title = 'Account & group changes'; Desc = 'Users created/deleted/enabled, password resets, group additions, lockouts.'; Admin = $true; Days = 30; Script = {
            param($Days)
            $name = @{ 4720 = 'User created'; 4722 = 'User enabled'; 4724 = 'Password reset'; 4726 = 'User deleted'; 4728 = 'Added to global group'; 4732 = 'Added to local group'; 4756 = 'Added to universal group'; 4740 = 'Account locked out'; 4738 = 'User changed' }
            Get-WfxEventQuick -Log Security -Id @($name.Keys) -Days $Days -Max 5000 | ForEach-Object {
                [pscustomobject]@{ Time = $_.Time; Change = $name[[int]$_.Id]; Target = $(if ($_.Fields.MemberName -and $_.Fields.MemberName -ne '-') { $_.Fields.MemberName } else { $_.Fields.TargetUserName }); Group = $(if ($_.Id -in 4728, 4732, 4756) { $_.Fields.TargetUserName } else { '' }); By = $_.Fields.SubjectUserName }
            }
        }
    }
    'newservices' = @{ Group = 'Events'; Title = 'Services installed'; Desc = 'New services (7045) — PsExec, remote-admin tools and many attacks install one.'; Admin = $false; Days = 30; Script = {
            param($Days)
            Get-WfxEventQuick -Log System -Id 7045 -Days $Days -Max 2000 | ForEach-Object { [pscustomobject]@{ Time = $_.Time; Service = $_.Fields.ServiceName; Binary = (Get-WfxShort (Protect-WfxText $_.Fields.ImagePath) 160); _Text = (Protect-WfxText $_.Fields.ImagePath); StartType = $_.Fields.StartType; Account = $_.Fields.AccountName } }
        }
    }
    'logclears'   = @{ Group = 'Events'; Title = 'Event logs cleared'; Desc = 'Security (1102) and other logs (104) being cleared — almost always intentional.'; Admin = $true; Days = 90; Script = {
            param($Days)
            Get-WfxEventQuick -Log Security -Id 1102 -Days $Days -Max 500 | ForEach-Object { [pscustomobject]@{ Time = $_.Time; Log = 'Security'; By = "$($_.Fields.SubjectDomainName)\$($_.Fields.SubjectUserName)" } }
            Get-WfxEventQuick -Log System -Id 104 -Days $Days -Max 500 | ForEach-Object { [pscustomobject]@{ Time = $_.Time; Log = $_.Fields.Channel; By = "$($_.Fields.SubjectDomainName)\$($_.Fields.SubjectUserName)" } }
        }
    }
    'reboots'     = @{ Group = 'Events'; Title = 'Startups, shutdowns and crashes'; Desc = 'Boot/shutdown times, unexpected shutdowns and who restarted the machine.'; Admin = $false; Days = 30; Script = {
            param($Days)
            $name = @{ 6005 = 'Event log started (boot)'; 6006 = 'Clean shutdown'; 6008 = 'Unexpected shutdown'; 1074 = 'Restart/shutdown requested'; 41 = 'Kernel power loss / crash' }
            Get-WfxEventQuick -Log System -Id 6005, 6006, 6008, 1074, 41 -Days $Days -Max 2000 | ForEach-Object {
                [pscustomobject]@{ Time = $_.Time; Event = $name[[int]$_.Id]; By = $_.Fields.param7; Process = $_.Fields.param1; Reason = $_.Fields.param3 }
            }
        }
    }
    'powershell'  = @{ Group = 'Events'; Title = 'PowerShell script blocks flagged as suspicious'; Desc = 'Script blocks PowerShell itself marked Warning (4104), newest first.'; Admin = $false; Days = 14; Script = {
            param($Days)
            Get-WfxEventQuick -Log 'Microsoft-Windows-PowerShell/Operational' -Id 4104 -Days $Days -Max 5000 | Where-Object { $_.Level -match 'Warn' } |
                ForEach-Object { [pscustomobject]@{ Time = $_.Time; ScriptBlockId = $_.Fields.ScriptBlockId; Path = $_.Fields.Path; Script = (Get-WfxShort (Protect-WfxText $_.Fields.ScriptBlockText) 200); _Text = (Protect-WfxText $_.Fields.ScriptBlockText) } }
        }
    }
    'defender'    = @{ Group = 'Events'; Title = 'Microsoft Defender detections'; Desc = 'Malware Defender found, the file, and whether it was removed.'; Admin = $false; Days = 90; Script = {
            param($Days)
            $th = @{}; try { Get-MpThreat -ErrorAction Stop | ForEach-Object { $th[[string]$_.ThreatID] = $_.ThreatName } } catch {}
            try {
                Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge (Get-Date).AddDays(-$Days) } | Sort-Object InitialDetectionTime -Descending | ForEach-Object {
                    [pscustomobject]@{ Time = $_.InitialDetectionTime; Threat = $th[[string]$_.ThreatID]; Resources = (Get-WfxShort (@($_.Resources) -join '; ') 160); Action = [string]$_.ActionSuccess; Process = $_.ProcessName; User = $_.DomainUser }
                }
            } catch {
                Get-WfxEventQuick -Log 'Microsoft-Windows-Windows Defender/Operational' -Id 1116, 1117 -Days $Days -Max 1000 | ForEach-Object { [pscustomobject]@{ Time = $_.Time; Threat = $_.Fields.'Threat Name'; Resources = $_.Fields.Path; Action = $(if ($_.Id -eq 1117) { 'action taken' } else { 'detected' }); Process = $_.Fields.'Process Name'; User = $_.Fields.'Detection User' } }
            }
        }
    }

    # ───────────── Evidence of execution & user activity (artifacts) ─────────────
    'execution'   = @{ Group = 'Evidence of execution'; Title = 'Programs that ran or existed (Amcache, ShimCache, Prefetch, BAM, UserAssist, PCA)'; Desc = 'Every execution artifact in one list, flagged: attack and exfiltration tools, programs in staging folders, system names in the wrong place. Survives deletion of the program.'; Admin = $true; Script = {
            Get-WfxArtifactCache | Where-Object { $_.Evidence -in 'Execution', 'Presence', 'Install' } | Sort-Object { [string]$_.Time } -Descending |
                ForEach-Object { $_.PSObject.Copy() } | Add-WfxFlag Artifact | Select-Object Flag, Why, Technique, Rule, Time, TimeKind, Artifact, Path, User, Sha1, Detail, Source
        }
    }
    'useractivity' = @{ Group = 'Evidence of execution'; Title = 'Folders and files users opened (ShellBags, Jump Lists, shortcuts, Run box, searches)'; Desc = 'What each user browsed and opened, including on USB drives and network shares, and what they typed into Win+R or searched for.'; Admin = $false; Script = {
            Get-WfxArtifactCache | Where-Object { $_.Artifact -in 'ShellBag', 'JumpList', 'Shortcut', 'TypedPath', 'Search', 'RunMRU' } | Sort-Object { [string]$_.Time } -Descending |
                ForEach-Object { $_.PSObject.Copy() } | Add-WfxFlag Artifact | Select-Object Flag, Why, Technique, Rule, Time, TimeKind, Artifact, User, Path, Detail, Source
        }
    }
    'browserdl'   = @{ Group = 'Evidence of execution'; Title = 'Browser download history (Chrome, Edge, Brave, Opera, Vivaldi, Firefox)'; Desc = 'Every download the browsers recorded: source URL, referrer, browser warnings, whether it was opened. Kept even after the file is deleted.'; Admin = $false; Script = {
            Get-WfxArtifactCache | Where-Object Artifact -eq 'Download' | Sort-Object { [string]$_.Time } -Descending |
                ForEach-Object { $_.PSObject.Copy() } | Add-WfxFlag Artifact | Select-Object Flag, Why, Technique, Rule, Time, User, Path, @{ n = 'Url'; e = { $_.Extra.Url } }, @{ n = 'Referrer'; e = { $_.Extra.Referrer } }, @{ n = 'Browser'; e = { $_.Extra.Browser } }, @{ n = 'Warning'; e = { $_.Extra.Danger } }, @{ n = 'Opened'; e = { $_.Extra.Opened } }, Source
        }
    }
    'defenderlog' = @{ Group = 'Evidence of execution'; Title = 'Microsoft Defender support logs (detections, processes seen)'; Desc = 'Detections and process names from MPLog files. These are separate from the event log, so they often survive log clearing (needs admin).'; Admin = $true; Script = {
            Get-WfxArtifactCache | Where-Object Artifact -eq 'DefenderLog' | Sort-Object { [string]$_.Time } -Descending |
                ForEach-Object { $_.PSObject.Copy() } | Add-WfxFlag Artifact | Select-Object Flag, Why, Technique, Rule, Time, TimeKind, Path, Name, Detail, Source
        }
    }

    # ───────────── Files & user activity ─────────────
    'downloads'   = @{ Group = 'Files'; Title = 'Recent downloads (with source URL)'; Desc = 'Files in users'' Downloads folders, newest first, with the Mark-of-the-Web download URL.'; Admin = $false; Days = 14; Script = {
            param($Days)
            $cut = (Get-Date).AddDays(-$Days)
            foreach ($prof in (Get-WfxUserProfilePath)) {
                $d = Join-Path $prof 'Downloads'
                if (-not (Test-Path -LiteralPath $d)) { continue }
                Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cut } | ForEach-Object {
                    $z = Get-WfxZoneId $_.FullName
                    [pscustomobject]@{ Modified = $_.LastWriteTime; File = $_.Name; SizeKB = [Math]::Round($_.Length / 1KB); Zone = $z.Zone; Source = $(if ($z.HostUrl) { $z.HostUrl } else { $z.ReferrerUrl }); Path = $_.FullName }
                }
            }
        }
    }
    'recentexe'   = @{ Group = 'Files'; Title = 'Recently written programs & scripts in user folders'; Desc = 'New .exe/.dll/.ps1/.js/.hta/… in Downloads, Desktop, Temp, AppData, ProgramData, Public.'; Admin = $false; Days = 7; Script = {
            param($Days)
            $cut = (Get-Date).AddDays(-$Days)
            $ext = @('.exe', '.dll', '.scr', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.hta', '.lnk', '.msi', '.iso', '.img', '.jar', '.wsf', '.one', '.xll', '.cpl')
            $dirs = @("$env:ProgramData", "$env:PUBLIC", "$env:SystemRoot\Temp") + @(Get-WfxUserProfilePath | ForEach-Object { "$_\Downloads"; "$_\Desktop"; "$_\AppData\Local\Temp"; "$_\AppData\Roaming"; "$_\AppData\Local" })
            foreach ($d in $dirs) {
                if (-not (Test-Path -LiteralPath $d)) { continue }
                Get-ChildItem -LiteralPath $d -File -Recurse -Depth 3 -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cut -and $_.Extension.ToLowerInvariant() -in $ext } |
                    Select-Object -First 300 | ForEach-Object { [pscustomobject]@{ Modified = $_.LastWriteTime; File = $_.Name; SizeKB = [Math]::Round($_.Length / 1KB); Signature = $(if ($_.Extension -in '.exe', '.dll', '.scr', '.msi', '.ps1') { Get-WfxSignature $_.FullName } else { '' }); Path = $_.FullName } }
            }
        }
    }
    'prefetch'    = @{ Group = 'Files'; Title = 'Program execution history (Prefetch)'; Desc = 'Programs that ran recently, from C:\Windows\Prefetch (needs admin; may be disabled on servers/SSDs).'; Admin = $true; Script = {
            Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Prefetch') -Filter *.pf -ErrorAction Stop | ForEach-Object {
                $pf = $null; try { $pf = Read-WfxPrefetch -Path $_.FullName } catch { }
                if ($pf -and @($pf.RunTimes).Count) {
                    $full = Get-WfxPrefetchExecutable $pf
                    [pscustomobject]@{ LastRun = $pf.RunTimes[0].ToLocalTime(); Program = $(if ($pf.Name) { $pf.Name } else { $_.BaseName -replace '-[0-9A-F]{8}$', '' }); Runs = $pf.RunCount
                        EarlierRuns = (@($pf.RunTimes | Select-Object -Skip 1 | ForEach-Object { $_.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') }) -join ', '); Path = $full; PrefetchFile = $_.Name }
                } else {
                    [pscustomobject]@{ LastRun = $_.LastWriteTime; Program = ($_.BaseName -replace '-[0-9A-F]{8}$', ''); Runs = ''; EarlierRuns = ''; Path = ''; PrefetchFile = $_.Name }
                }
            } | Sort-Object LastRun -Descending
        }
    }
    'recentfiles' = @{ Group = 'Files'; Title = 'Recently opened files (Recent items)'; Desc = 'Files and folders users opened, from their Recent shortcuts.'; Admin = $false; Days = 30; Script = {
            param($Days)
            $cut = (Get-Date).AddDays(-$Days)
            $(foreach ($prof in (Get-WfxUserProfilePath)) {
                $r = Join-Path $prof 'AppData\Roaming\Microsoft\Windows\Recent'
                Get-ChildItem -LiteralPath $r -Filter *.lnk -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cut } | ForEach-Object {
                    $lnk = Get-WfxLnkInfo -Path $_.FullName   # byte-level parse; nothing is resolved or run
                    [pscustomobject]@{ Opened = $_.LastWriteTime; Item = $_.BaseName; Target = $(if ($lnk) { $lnk.Target } else { '' }); TargetModifiedUtc = $(if ($lnk -and $lnk.Written) { ConvertTo-WfxUtcString $lnk.Written } else { '' }); User = (Split-Path -Leaf $prof) }
                }
            }) | Sort-Object Opened -Descending
        }
    }
    'pshistory'   = @{ Group = 'Files'; Title = 'PowerShell command history (redacted)'; Desc = 'Last commands typed in PowerShell per user (PSReadLine), with secrets redacted.'; Admin = $false; Script = {
            foreach ($prof in (Get-WfxUserProfilePath)) {
                $f = Join-Path $prof 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                if (-not (Test-Path -LiteralPath $f)) { continue }
                $lines = @(Get-Content -LiteralPath $f -Tail 50 -ErrorAction SilentlyContinue)
                $n = $lines.Count
                for ($i = 0; $i -lt $n; $i++) { [pscustomobject]@{ User = (Split-Path -Leaf $prof); Line = "-$($n - $i)"; Command = (Get-WfxShort (Protect-WfxText $lines[$i]) 200); _Text = (Protect-WfxText $lines[$i]) } }
            }
        }
    }
    'runmru'      = @{ Group = 'Files'; Title = 'Run-dialog history (Win+R)'; Desc = 'Commands typed into the Run box — where ClickFix / fake-CAPTCHA lures leave their command.'; Admin = $false; Script = {
            Get-WfxPersistenceData | Expand-WfxRecord | Add-WfxFlag Autostart | Where-Object Kind -eq 'RunMRU' | Select-Object Flag, Why, Technique, Rule, @{ n = 'Command'; e = { Get-WfxShort $_.Command 200 } }, Location
        }
    }

    # ───────────── Security posture ─────────────
    'posture'     = @{ Group = 'Security'; Title = 'Security posture checklist'; Desc = 'AV, firewall, UAC, LSA protection, Credential Guard, SMBv1, WDigest, LLMNR, logging, BitLocker, RDP — pass/fail with advice.'; Admin = $false; Script = {
            $s = Get-WfxSecurityData
            $row = { param($Check, $Ok, $Value, $Advice) [pscustomobject]@{ Check = $Check; Status = $(if ($null -eq $Ok) { 'UNKNOWN' } elseif ($Ok) { 'OK' } else { 'FIX' }); Value = [string]$Value; Advice = $(if ($Ok) { '' } else { $Advice }) } }
            $d = $s.Defender
            & $row 'Antivirus real-time protection' $(if ($d) { [bool]$d.RealTimeProtectionEnabled } elseif (@($s.ThirdPartyAV).Count) { $true } else { $null }) $(if ($d) { "Defender RTP=$($d.RealTimeProtectionEnabled)" } else { (@($s.ThirdPartyAV) -join ', ') }) 'Turn on real-time protection.'
            if ($d) {
                & $row 'Defender tamper protection' ([bool]$d.TamperProtectionEnabled) $d.TamperProtectionEnabled 'Enable Tamper Protection (Windows Security > Virus & threat protection settings).'
                & $row 'Defender signatures up to date' ($null -ne $d.SignatureAgeDays -and $d.SignatureAgeDays -le 3) "$($d.SignatureAgeDays) day(s) old" 'Update signatures.'
            }
            $fw = $s.Firewall
            if ($fw) { foreach ($p in 'Domain', 'Private', 'Public') { & $row "Firewall ($p profile)" ([bool](Get-WfxValue $fw $p $false)) (Get-WfxValue $fw $p '') "Enable the $p firewall profile." } }
            $lua = Get-WfxRegValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
            & $row 'User Account Control (UAC)' ($lua -ne 0) "EnableLUA=$lua" 'Re-enable UAC.'
            & $row 'LSASS protection (RunAsPPL)' ([bool]$s.Lsa.RunAsPPL) $s.Lsa.RunAsPPL 'Enable LSA protection to make credential dumping harder.'
            & $row 'Credential Guard running' ([bool]$s.Lsa.CredentialGuard) $s.Lsa.CredentialGuard 'Enable Credential Guard where supported.'
            $wd = Get-WfxRegValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
            & $row 'WDigest clear-text credentials off' ($wd -ne 1) "UseLogonCredential=$wd" 'Set UseLogonCredential to 0 (attackers enable it to harvest passwords).'
            $smb1 = try { [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $null }
            & $row 'SMBv1 server disabled' $(if ($null -eq $smb1) { $null } else { -not $smb1 }) "EnableSMB1Protocol=$smb1" 'Disable SMBv1.'
            $llmnr = Get-WfxRegValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
            & $row 'LLMNR disabled (blocks poisoning)' ($llmnr -eq 0) "EnableMulticast=$(if ($null -eq $llmnr) { 'not set (on)' } else { $llmnr })" 'Disable LLMNR by policy.'
            & $row 'Process-creation auditing (4688)' $s.Audit.ProcessCreation $s.Audit.ProcessCreation 'Enable "Audit Process Creation" (success).'
            & $row 'Command line in 4688' ([bool]$s.Audit.CommandLineInProcessCreation) $s.Audit.CommandLineInProcessCreation 'Enable "Include command line in process creation events".'
            & $row 'PowerShell script-block logging' ([bool]$s.Audit.ScriptBlockLogging) $s.Audit.ScriptBlockLogging 'Enable script-block logging.'
            & $row 'Sysmon installed' ([bool]$s.Audit.SysmonInstalled) $s.Audit.SysmonInstalled 'Consider deploying Sysmon for richer telemetry.'
            if ($s.Rdp) { & $row 'RDP requires NLA (if RDP on)' ((-not $s.Rdp.Enabled) -or $s.Rdp.NlaEnabled) "Enabled=$($s.Rdp.Enabled) NLA=$($s.Rdp.NlaEnabled)" 'Require Network Level Authentication.' }
            $al = Get-WfxRegValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
            & $row 'Automatic logon disabled' ($al -ne '1') "AutoAdminLogon=$al" 'Disable auto-logon (it stores a password in the registry).'
            $sys = Get-WfxRegValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
            & $row 'Remote UAC for local admins on' ($sys -ne 1) "LocalAccountTokenFilterPolicy=$sys" 'Set to 0 to limit pass-the-hash with local accounts.'
            $last = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | ForEach-Object { try { [datetime]$_.InstalledOn } catch {} } | Sort-Object -Descending | Select-Object -First 1
            & $row 'Updates installed in last 45 days' $(if ($last) { $last -ge (Get-Date).AddDays(-45) } else { $null }) $last 'Install the latest cumulative update.'
        }
    }
}

# ── Suspicious-activity checks for views that have no triage analyzer ───────────────────────────────
# Each check receives one row and calls Add-WfxVerdict / Add-WfxCommandVerdict. Properties starting with "_"
# carry the full (unshortened, redacted) text for checks and are removed before display.
# Value: 'first' = flagged rows are listed first (inventory views); 'keep' = keep the view's own order (time lines).
$script:WfxFlagTopic = [ordered]@{
    processes = 'first'; unsigned = 'first'; listeners = 'first'; connections = 'first'; dns = 'first'
    autoruns = 'first'; services = 'first'; drivers = 'first'; tasks = 'first'; wmi = 'first'; runmru = 'first'
    software = 'first'; users = 'first'; shares = 'first'; hosts = 'first'; firewall = 'first'; prefetch = 'first'
    downloads = 'first'; recentexe = 'first'; failedlogons = 'first'
    pshistory = 'keep'; powershell = 'keep'; newservices = 'keep'; logclears = 'keep'; accounts = 'keep'; rdp = 'keep'; defender = 'keep'
    execution = 'first'; useractivity = 'first'; browserdl = 'first'; defenderlog = 'first'
    changes = 'keep'; regchanges = 'keep'; filechanges = 'keep'; deleted = 'keep'; installs = 'keep'; executions = 'keep'; connhistory = 'keep'; configchanges = 'keep'
}
$script:WfxRiskyExt = '(?i)\.(?:iso|img|vhdx?|lnk|hta|js|jse|vbs|vbe|wsf|wsh|one|xll|cpl|scr|pif|bat|cmd|ps1|msc|jar|appref-ms|library-ms|search-ms|url)$'
$script:WfxDoubleExt = '(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|rar|mp4|mp3)\.(?:exe|scr|com|pif|js|jse|vbs|vbe|wsf|hta|bat|cmd|lnk|ps1)$'
$script:WfxProxyExec = @('mshta.exe', 'hh.exe', 'cmstp.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'msbuild.exe', 'odbcconf.exe', 'certutil.exe', 'bitsadmin.exe', 'msxsl.exe', 'wmic.exe', 'forfiles.exe', 'pcalua.exe', 'mavinject.exe', 'presentationhost.exe')
$script:WfxSecurityDomains = '(?i)(?:^|\.)(?:microsoft|windowsupdate|msftncsi|msftconnecttest|smartscreen|wdcp|virustotal|kaspersky|eset|sophos|symantec|norton|crowdstrike|sentinelone|malwarebytes|avast|avg|bitdefender|mcafee|trendmicro|f-secure|webroot|carbonblack|cylance|paloaltonetworks|fortinet|clamav|elastic|cisco|zscaler|withsecure|emsisoft|gdata|drweb|comodo)\.[a-z.]+$'

function Get-WfxArtifactCache {
    <# Live artifact collection is shared by the Explore views and kept for 5 minutes, so moving between
       views does not re-read every hive and Jump List. #>
    if ($script:WfxArtifactCache -and $script:WfxArtifactCacheTime -gt (Get-Date).AddMinutes(-5)) { return $script:WfxArtifactCache }
    $script:WfxArtifactCache = @(Get-WfxArtifactData | Expand-WfxRecord)
    $script:WfxArtifactCacheTime = Get-Date
    $script:WfxArtifactCache
}

function Get-WfxThreatList {
    param([ValidateSet('offensiveProcesses', 'rmmProcesses')][string]$Name)
    if (-not $script:WfxThreatCache) { $script:WfxThreatCache = @{} }
    if (-not $script:WfxThreatCache.ContainsKey($Name)) {
        $script:WfxThreatCache[$Name] = try { @((Get-WfxRulePack -Name 'threats').$Name) } catch { @() }
    }
    , $script:WfxThreatCache[$Name]
}

function Test-WfxProductName {
    <# Does an installed-program display name contain one of the tool names (e.g. "AnyDesk" ~ anydesk.exe)? #>
    param([string]$DisplayName, [object[]]$List)
    $d = ($DisplayName -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    if (-not $d) { return '' }
    foreach ($x in $List) {
        $n = (([string]$x).Trim() -replace '\.exe$', '' -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
        if ($n.Length -ge 5 -and $d.Contains($n)) { return ([string]$x).Trim() }
    }
    ''
}

$script:WfxInsightChecks = @{
    tasks = { param($r) Add-WfxCommandVerdict -InputObject $r -Text $r._Text -Context 'scheduled task' -CheckImagePath }
    wmi = {
        param($r)
        if ($r.Type -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') { Add-WfxVerdict $r 'High' 'Permanent WMI consumer that runs a command or script on an event trigger' @('T1546.003') }
        Add-WfxCommandVerdict -InputObject $r -Text $r._Text -Context 'WMI consumer'
    }
    pshistory = { param($r) Add-WfxCommandVerdict -InputObject $r -Text $r._Text -Context 'PowerShell history' }
    powershell = {
        param($r)
        Add-WfxVerdict $r 'Medium' 'PowerShell itself marked this script block as suspicious (logged as a warning)' @('T1059.001')
        Add-WfxCommandVerdict -InputObject $r -Text $r._Text -Context 'script block'
    }
    newservices = {
        param($r)
        if ([string]$r.Service -match '(?i)^(?:PSEXESVC|PAExec\S*|RemComSvc|csexecsvc|winexesvc|BTOBTO|SMBExec\S*)$') { Add-WfxVerdict $r 'High' 'Service name used by remote-execution tools (PsExec, PAExec, Impacket …)' @('T1569.002', 'T1021.002') }
        if ([string]$r._Text -match '(?i)\\\\[^\\]+\\(?:admin|c)\$|^\s*"?(?:%COMSPEC%|cmd(?:\.exe)?)\b.*/c|powershell') { Add-WfxVerdict $r 'High' 'Service runs a shell command or a binary from an admin share' @('T1543.003', 'T1569.002') }
        Add-WfxCommandVerdict -InputObject $r -Text $r._Text -Context 'new service' -CheckImagePath
    }
    logclears = { param($r) Add-WfxVerdict $r 'High' 'The Security event log was cleared (evidence destroyed)' @('T1070.001') }
    failedlogons = {
        param($r)
        $n = [int]$r.Count
        $what = if ([string]$r.Reason -eq 'no such user') { 'non-existent account (enumeration / spraying)' } else { 'repeated failures (password guessing)' }
        if ($n -ge 50) { Add-WfxVerdict $r 'High' "$n failed logons: $what" @('T1110') } elseif ($n -ge 10) { Add-WfxVerdict $r 'Medium' "$n failed logons: $what" @('T1110') }
    }
    accounts = {
        param($r)
        if ($r.Change -eq 'User created') { Add-WfxVerdict $r 'Medium' 'New local account created' @('T1136.001') }
        if ([string]$r.Change -like 'Added to*' -and [string]$r.Group -match '(?i)^(?:Administrators|Domain Admins|Enterprise Admins|Backup Operators)$') { Add-WfxVerdict $r 'High' "Account added to $($r.Group)" @('T1098') }
        elseif ([string]$r.Change -like 'Added to*' -and [string]$r.Group -match '(?i)^(?:Remote Desktop Users|Remote Management Users)$') { Add-WfxVerdict $r 'Medium' "Account given remote access ($($r.Group))" @('T1098') }
        if ($r.Change -eq 'User enabled' -and [string]$r.Target -match '(?i)(?:^|\\)(?:Guest|Administrator|DefaultAccount)$') { Add-WfxVerdict $r 'Medium' "Built-in account enabled: $($r.Target)" @('T1078') }
    }
    rdp = { param($r) if ($r.Source -and -not (Test-WfxPrivateIp ([string]$r.Source))) { Add-WfxVerdict $r 'Medium' "RDP logon from a public address ($($r.Source))" @('T1021.001', 'T1133') } }
    defender = {
        param($r)
        if ([string]$r.Action -eq 'True') { Add-WfxVerdict $r 'Medium' "Defender detection (remediated): $($r.Threat)" }
        else { Add-WfxVerdict $r 'High' "Defender detection NOT confirmed remediated: $($r.Threat)" }
    }
    hosts = {
        param($r)
        $names = @(([string]$r.Names) -split '\s+' | Where-Object { $_ })
        $sec = @($names | Where-Object { $_ -match $script:WfxSecurityDomains })
        if ($sec.Count) { Add-WfxVerdict $r 'High' "Security / update site overridden in the hosts file: $($sec -join ', ')" @('T1562.001') }
        elseif ([string]$r.Address -notmatch '^(?:127\.|0\.0\.0\.0$|::1?$)') { Add-WfxVerdict $r 'Low' 'Static name-to-address mapping — confirm it is intended (can redirect traffic)' @('T1565.001') }
    }
    firewall = {
        param($r)
        if ([string]$r.Rule -like 'Profiles:*' -and [string]$r.Rule -match '=OFF') { Add-WfxVerdict $r 'Medium' 'Windows Firewall is turned off for at least one profile' @('T1562.004') }
        if ($r.Program -and (Test-WfxUserWritablePath ([string]$r.Program))) { Add-WfxVerdict $r 'Medium' 'Inbound allow rule for a program in a user-writable folder' @('T1562.004') }
    }
    prefetch = {
        param($r)
        $p = [string]$r.Program
        if (Test-WfxNameInList $p (Get-WfxThreatList offensiveProcesses)) { Add-WfxVerdict $r 'High' "Known offensive / credential-theft tool ran: $p" @('T1588.002') }
        elseif (Test-WfxNameInList $p (Get-WfxThreatList rmmProcesses)) { Add-WfxVerdict $r 'Medium' "Remote-access tool ran: $p" @('T1219') }
        elseif (Test-WfxNameInList $p $script:WfxProxyExec) { Add-WfxVerdict $r 'Low' "Proxy-execution capable Windows binary ran (review the context): $p" @('T1218') }
    }
    downloads = {
        param($r)
        $f = [string]$r.File
        if ($f -match $script:WfxDoubleExt) { Add-WfxVerdict $r 'High' 'Disguised double extension (e.g. invoice.pdf.exe)' @('T1036.007') }
        if (Test-WfxNameInList $f (Get-WfxThreatList offensiveProcesses)) { Add-WfxVerdict $r 'High' "Known offensive tool downloaded: $f" @('T1588.002') }
        if ($f -match $script:WfxRiskyExt) { Add-WfxVerdict $r 'Medium' 'File type commonly used to deliver malware (disk image, shortcut, script, OneNote, HTA …)' @('T1204.002') }
        elseif ($f -match '(?i)\.(?:exe|msi|dll|msix|appx)$') { Add-WfxVerdict $r 'Low' 'Executable downloaded — confirm its origin (Source) and signature' @('T1204.002') }
    }
    recentexe = {
        param($r)
        $f = [string]$r.File; $path = [string]$r.Path
        if ($f -match $script:WfxDoubleExt) { Add-WfxVerdict $r 'High' 'Disguised double extension (e.g. invoice.pdf.exe)' @('T1036.007') }
        if ($path -match '(?i)\\Start Menu\\Programs\\Startup\\') { Add-WfxVerdict $r 'High' 'In a Startup folder — runs at every logon' @('T1547.001') }
        if (Test-WfxNameInList $f (Get-WfxThreatList offensiveProcesses)) { Add-WfxVerdict $r 'High' "Known offensive tool on disk: $f" @('T1588.002') }
        if ($f -match '(?i)\.(?:exe|dll|scr|msi)$' -and $r.Signature -and -not (Test-WfxTrustedSignature ([string]$r.Signature)) -and (Test-WfxUserWritablePath $path)) { Add-WfxVerdict $r 'Medium' "Unsigned binary in a user-writable folder (signature: $($r.Signature))" @('T1204.002') }
        if ($f -match '(?i)\.scr$') { Add-WfxVerdict $r 'Medium' 'Screen-saver executable (.scr) — rarely legitimate outside System32' @('T1546.002') }
    }
    software = {
        param($r)
        $rmm = Test-WfxProductName ([string]$r.Name) (Get-WfxThreatList rmmProcesses)
        if ($rmm) { Add-WfxVerdict $r 'Medium' "Remote-access software installed (matches $rmm) — confirm it is sanctioned" @('T1219') }
        $off = Test-WfxProductName ([string]$r.Name) (Get-WfxThreatList offensiveProcesses)
        if ($off) { Add-WfxVerdict $r 'Low' "Dual-use / offensive tool installed (matches $off)" @('T1588.002') }
    }
    users = {
        param($r)
        if ($r.Enabled -eq $true -and [string]$r.Name -eq 'Guest') { Add-WfxVerdict $r 'Medium' 'Guest account is enabled' @('T1078') }
        if ($r.Enabled -eq $true -and $r.PSObject.Properties['PasswordRequired'] -and $r.PasswordRequired -eq $false) { Add-WfxVerdict $r 'Medium' 'Enabled account that does not require a password' @('T1078') }
        if ($r.Enabled -eq $true -and [string]$r.SID -match '-500$') { Add-WfxVerdict $r 'Low' 'Built-in Administrator account is enabled' @('T1078') }
    }
    shares = {
        param($r)
        if ($r.Kind -eq 'Custom' -and [string]$r.Path -match '^[A-Za-z]:\\?$') { Add-WfxVerdict $r 'Medium' "Entire drive shared ($($r.Path))" @('T1039') }
        elseif ($r.Kind -eq 'Custom' -and [string]$r.Path -match '(?i)\\Users(?:\\|$)') { Add-WfxVerdict $r 'Low' 'User profile folder shared' @('T1039') }
    }
}

function Get-WfxInsight {
    <#
    .SYNOPSIS
        Live, read-only views of this Windows host: system, users, software, processes, network, autostarts,
        event-log summaries, recent files and security posture. Returns objects you can sort, filter and export.
    .PARAMETER Topic  A topic key (run Get-WfxInsight -List to see them all).
    .PARAMETER Days   Look-back for time-based topics (each topic has a sensible default).
    .PARAMETER List   List available topics.
    .EXAMPLE
        Get-WfxInsight -List
    .EXAMPLE
        Get-WfxInsight logons -Days 3 | Format-Table
    .EXAMPLE
        Get-WfxInsight listeners | Where-Object Exposure -eq 'all interfaces'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Topic')]
    param(
        [Parameter(ParameterSetName = 'Topic', Mandatory, Position = 0)][string]$Topic,
        [Parameter(ParameterSetName = 'Topic')][ValidateRange(1, 3650)][int]$Days = 0,
        [Parameter(ParameterSetName = 'List')][switch]$List
    )
    if ($List) {
        return $script:WfxInsightTopics.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Topic = $_.Key; Group = $_.Value.Group; Title = $_.Value.Title; NeedsAdmin = [bool]$_.Value.Admin; Description = $_.Value.Desc } }
    }
    $t = $script:WfxInsightTopics[$Topic]
    if (-not $t) { throw "Unknown topic '$Topic'. Run Get-WfxInsight -List." }
    if (-not (Test-WfxWindows)) { throw 'Live views need Windows.' }
    if ($t.Admin -and -not (Test-WfxAdmin)) { Write-Warning "'$($t.Title)' needs administrator rights — results will be empty or partial. Re-run elevated." }
    $d = if ($Days) { $Days } elseif ($t.Days) { [int]$t.Days } else { 7 }
    $gapsBefore = $script:WfxGaps.Count
    Clear-WfxViewPattern
    $rows = @(if ($t.Days) { & $t.Script $d | Expand-WfxRecord } else { & $t.Script | Expand-WfxRecord })
    $mode = $script:WfxFlagTopic[$Topic]
    if ($mode) {
        $check = $script:WfxInsightChecks[$Topic]
        if ($check) {
            foreach ($r in $rows) {
                if ($r -is [string] -or $r -is [System.ValueType]) { continue }
                try { & $check $r } catch { Add-WfxGap -Source "flags:$Topic" -Reason "A suspicious-activity check failed on one row: $($_.Exception.Message)" }
            }
        }
        $rows = @($rows | Complete-WfxFlagRow)
        if ($mode -eq 'first') {
            # Stable: flagged rows by severity, each group keeping the view's own order.
            $i = 0
            $rows = @($rows | ForEach-Object { [pscustomobject]@{ R = $_; K = -$script:WfxFlagRank[[string]$_.Flag]; N = $i++ } } | Sort-Object K, N | ForEach-Object { $_.R })
        }
    }
    $rows
    foreach ($p in (Get-WfxViewPattern)) { Write-Warning ("PATTERN [{0}] {1} {2}" -f $p.Severity, $p.Text, $(if ($p.Technique) { "($($p.Technique))" })) }
    # Say why results may be incomplete (missing rights, disabled logs, journal window ...).
    for ($g = $gapsBefore; $g -lt $script:WfxGaps.Count; $g++) { Write-Warning ("{0}: {1} {2}" -f $script:WfxGaps[$g].Source, $script:WfxGaps[$g].Reason, $script:WfxGaps[$g].Fix) }
}

function Save-WfxInsight {
    <#
    .SYNOPSIS Exports insight topics (default: all) to a case folder: one CSV per topic, an HTML inventory
    page and a SHA-256 manifest. A full "what does this machine look like" snapshot for a ticket or baseline.
    .EXAMPLE
        Save-WfxInsight -OutputPath E:\cases
    .EXAMPLE
        Save-WfxInsight -Topic system, software, users, groups, listeners
    #>
    [CmdletBinding()]
    param([string[]]$Topic = @(), [string]$OutputPath = '', [switch]$NoOpen)
    if (-not (Test-WfxWindows)) { throw 'Live views need Windows.' }
    $keys = if ($Topic.Count) { $Topic } else { @($script:WfxInsightTopics.Keys) }
    $case = New-WfxCase -OutputPath $OutputPath -Name 'inventory' -HostName ([Environment]::MachineName) -Mode 'inventory' -Parameters @{ Topics = $keys }
    $dir = Join-Path $case.Path 'insights'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $sections = New-Object System.Text.StringBuilder
    $toc = New-Object System.Text.StringBuilder
    $flagged = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($k in $keys) {
        $i++
        $t = $script:WfxInsightTopics[$k]; if (-not $t) { continue }
        Write-WfxConsole ("  [{0}/{1}] {2,-52}" -f $i, $keys.Count, $t.Title) -NoNewline
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $rows = @(); $err = ''
        try { $rows = @(Get-WfxInsight -Topic $k -WarningAction SilentlyContinue) } catch { $err = $_.Exception.Message; Add-WfxGap -Source "insight:$k" -Reason $err }
        Write-WfxConsole ("{0,6:N1}s  {1}" -f $sw.Elapsed.TotalSeconds, $(if ($err) { 'unavailable' } else { "$($rows.Count) rows" })) -Kind $(if ($err) { 'Warn' } else { 'Dim' })
        if ($rows.Count) { $rows | Export-Csv -Path (Join-Path $dir "$k.csv") -NoTypeInformation -Encoding UTF8 }
        $enc = [System.Net.WebUtility]
        $hits = @($rows | Where-Object { $_.PSObject.Properties['Flag'] -and $_.Flag -and $_.Flag -ne 'INFO' })
        foreach ($h in $hits) { $flagged.Add([pscustomobject]@{ Flag = $h.Flag; View = $t.Title; Why = $h.Why; Technique = $h.Technique; Key = $k }) }
        $badge = if ($hits.Count) { " <em>$($hits.Count) flagged</em>" } else { '' }
        [void]$toc.Append("<li><a href=""#$k"">$($enc::HtmlEncode($t.Title))</a> <span>$($rows.Count)$badge</span></li>")
        # ConvertTo-Html encodes every value; the severity cell is then turned into a badge.
        $body = if ($err) { "<p class=""err"">Unavailable: $($enc::HtmlEncode($err))</p>" } elseif (-not $rows.Count) { '<p class="none">Nothing found.</p>' } else { (($rows | Select-Object -First 1000 | ConvertTo-Html -Fragment) -join "`n") -replace '<tr><td>(CRITICAL|HIGH|MEDIUM|LOW)</td>', '<tr class="f-$1"><td><b class="b-$1">$1</b></td>' }
        [void]$sections.Append("<section id=""$k""><h2>$($enc::HtmlEncode($t.Group)): $($enc::HtmlEncode($t.Title))</h2><p class=""d"">$($enc::HtmlEncode($t.Desc))</p>$body</section>")
    }
    $hn = [System.Net.WebUtility]::HtmlEncode([Environment]::MachineName)
    $enc = [System.Net.WebUtility]
    $rank = $script:WfxFlagRank
    $top = @($flagged | Sort-Object @{ e = { -$rank[[string]$_.Flag] } }, View | Select-Object -First 300)
    $summary = if ($top.Count) {
        $li = foreach ($f in $top) { "<tr class=""f-$($f.Flag)""><td><b class=""b-$($f.Flag)"">$($f.Flag)</b></td><td><a href=""#$($f.Key)"">$($enc::HtmlEncode($f.View))</a></td><td>$($enc::HtmlEncode($f.Why))</td><td>$($enc::HtmlEncode($f.Technique))</td></tr>" }
        "<section id=""flagged""><h2>Suspicious items across all views ($(Get-WfxFlagSummary $flagged))</h2><p class=""d"">Rows that matched a suspicious-activity rule. Each is a lead to verify, not a verdict; the absence of flags is not proof that the host is clean.</p><table><tr><th>Flag</th><th>View</th><th>Why</th><th>ATT&amp;CK</th></tr>$($li -join '')</table></section>"
    } else { "<section id=""flagged""><h2>Suspicious items across all views</h2><p class=""none"">No row matched a suspicious-activity rule. This is not proof that the host is clean — run a full triage for event-log, file and memory-resident analysis.</p></section>" }
    $html = @"
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Inventory - $hn</title>
<style>html{font-variant-ligatures:none;font-feature-settings:"calt" 0,"liga" 0,"clig" 0}body{font:14px system-ui,Segoe UI,sans-serif;margin:0;color:#1b1f24;background:#f6f7f9}header{background:#14181f;color:#fff;padding:18px 24px}header small{color:#9aa4b2}
main{display:grid;grid-template-columns:260px 1fr;gap:20px;padding:20px}nav ul{list-style:none;padding:0;margin:0;position:sticky;top:12px}nav li{display:flex;justify-content:space-between;padding:3px 0}nav a{color:#2457c5;text-decoration:none}nav span{color:#8a93a0}
section{background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:14px 16px;margin-bottom:16px;overflow-x:auto}h2{font-size:16px;margin:0 0 4px}.d{color:#5b6470;margin:0 0 10px}.err{color:#b42318}.none{color:#8a93a0}
table{border-collapse:collapse;font-size:12.5px;min-width:100%}th{text-align:left;background:#f0f2f5;position:sticky;top:0;white-space:nowrap}td,th{border-bottom:1px solid #eceef1;padding:5px 8px;vertical-align:top}td{max-width:460px;overflow-wrap:anywhere}td:first-child{white-space:nowrap}
nav em{color:#b42318;font-style:normal;font-weight:600;margin-left:4px}tr.f-CRITICAL td,tr.f-HIGH td{background:#fdf1f0}tr.f-MEDIUM td{background:#fdf7ec}
b[class^=b-]{display:inline-block;white-space:nowrap;font-size:11px;letter-spacing:.04em;padding:2px 6px;border-radius:3px}.b-CRITICAL{background:#7a0e0e;color:#fff}.b-HIGH{background:#c0362c;color:#fff}.b-MEDIUM{background:#e8a33d;color:#1b1300}.b-LOW{background:#d5e3f2;color:#123}
@media(max-width:800px){main{grid-template-columns:1fr}}*,*::before,*::after{font-variant-ligatures:none!important;font-feature-settings:"calt" 0,"liga" 0,"clig" 0!important}
</style></head><body>
<header><b>WinForensicX system inventory</b> — $hn<br><small>Collected $(Get-WfxUtcNow) UTC, read-only snapshot, WinForensicX $script:WfxVersion</small></header>
<main><nav><ul><li><a href="#flagged"><b>Suspicious items</b></a> <span>$(if ($flagged.Count) { "<em>$($flagged.Count)</em>" } else { '0' })</span></li>$($toc.ToString())</ul></nav><div>$summary$($sections.ToString())</div></main></body></html>
"@
    [IO.File]::WriteAllText((Join-Path $case.Path 'inventory.html'), $html, (New-Object Text.UTF8Encoding($false)))
    $null = Complete-WfxCase
    Write-WfxConsole ''
    Write-WfxConsole "Inventory: $(Join-Path $case.Path 'inventory.html')" -Kind Info
    if (-not $NoOpen) { try { Start-Process (Join-Path $case.Path 'inventory.html') } catch {} }
    return $case.Path
}

# ───────────── Recent changes (listed first in the menu) ─────────────
$script:WfxActivityTopics = [ordered]@{
    'changes'       = @{ Group = 'Recent changes'; Title = 'Everything that changed recently (combined timeline)'; Desc = 'Registry, installs, services, tasks, accounts, firewall, Defender, executions, connections, deletions — newest first.'; Admin = $false; Days = 7; Script = { param($Days) Get-WfxActivityData -Days $Days | Expand-WfxRecord | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Category, Action, Target, Actor, Detail, Source } }
    'regchanges'    = @{ Group = 'Recent changes'; Title = 'Registry changes in persistence & security locations'; Desc = 'Run keys, Winlogon, IFEO, UAC-bypass handlers, LSA/WDigest, Defender exclusions, firewall rules, services, tasks, uninstall keys — by last-write time.'; Admin = $false; Days = 7; Script = { param($Days) Get-WfxRegistryActivity -Days $Days | Expand-WfxRecord | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Action, Target, Detail } }
    'filechanges'   = @{ Group = 'Recent changes'; Title = 'File system changes (NTFS change journal)'; Desc = 'Files created, deleted, content changed, renamed, alternate streams and timestamp changes on the system drive (needs admin).'; Admin = $true; Days = 2; Script = { param($Days) Get-WfxUsnActivity -Days $Days | Expand-WfxRecord | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Action, Target } }
    'deleted'       = @{ Group = 'Recent changes'; Title = 'Deleted files (Recycle Bin + Sysmon)'; Desc = 'What users deleted, from where, when, and whether it can still be recovered.'; Admin = $false; Days = 30; Script = { param($Days) @(Get-WfxRecycleBinActivity -Days $Days | Expand-WfxRecord) + @(Get-WfxEventActivity -Days $Days | Expand-WfxRecord | Where-Object { $_.Action -eq 'File deleted' }) | Sort-Object Time -Descending | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Action, Target, Detail, Actor, Source } }
    'installs'      = @{ Group = 'Recent changes'; Title = 'Software & driver installs / removals'; Desc = 'MSI installs and removals, new drivers and services, and newly written uninstall entries.'; Admin = $false; Days = 30; Script = { param($Days) @(Get-WfxEventActivity -Days $Days | Expand-WfxRecord | Where-Object { $_.Category -in 'Software', 'Service' }) + @(Get-WfxRegistryActivity -Days $Days | Expand-WfxRecord | Where-Object { $_.Action -like 'Software*' }) | Sort-Object Time -Descending | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Action, Target, Detail, Source } }
    'executions'    = @{ Group = 'Recent changes'; Title = 'Programs that ran (Prefetch, BAM, UserAssist)'; Desc = 'Execution evidence with full paths where available — including programs that are no longer running.'; Admin = $false; Days = 7; Script = { param($Days) Get-WfxExecutionActivity -Days $Days | Expand-WfxRecord | Sort-Object Time -Descending | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Action, Target, Actor, Detail } }
    'connhistory'   = @{ Group = 'Recent changes'; Title = 'Connection history'; Desc = 'Outbound connections recorded by Sysmon, Windows Filtering Platform (5156), the firewall log, the live table and saved RDP targets.'; Admin = $false; Days = 3; Script = { param($Days) Get-WfxConnectionActivity -Days $Days | Expand-WfxRecord | Sort-Object Time -Descending | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Action, Target, Actor, Detail, Source } }
    'configchanges' = @{ Group = 'Recent changes'; Title = 'Security-relevant configuration changes'; Desc = 'Accounts, groups, scheduled tasks, audit policy, firewall rules, Defender settings, time changes, log clearing, BITS, WMI.'; Admin = $false; Days = 14; Script = { param($Days) Get-WfxEventActivity -Days $Days | Expand-WfxRecord | Where-Object { $_.Category -notin 'Software', 'File' } | Sort-Object Time -Descending | Add-WfxFlag Activity | Select-Object Flag, Why, Technique, Rule, Time, Category, Action, Target, Actor, Detail } }
}
$i = 0
foreach ($k in $script:WfxActivityTopics.Keys) { $script:WfxInsightTopics.Insert($i, $k, $script:WfxActivityTopics[$k]); $i++ }
# Evidence of execution comes right after Recent changes in the menu.
foreach ($k in 'execution', 'useractivity', 'browserdl', 'defenderlog') { $v = $script:WfxInsightTopics[$k]; $script:WfxInsightTopics.Remove($k); $script:WfxInsightTopics.Insert($i, $k, $v); $i++ }

function Get-WfxActivity {
    <#
    .SYNOPSIS "What changed recently?" — registry writes in persistence/security locations, software and driver
    installs, services, tasks, accounts, firewall and Defender changes, program executions, connection history,
    deletions, and (with -Journal, admin) the NTFS change journal. Newest first.
    .EXAMPLE
        Get-WfxActivity -Days 2 | Where-Object Category -eq 'Registry'
    .EXAMPLE
        Get-WfxActivity -Days 1 -Journal | Export-Csv changes.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 365)][int]$Days = 7, [switch]$Journal)
    if (-not (Test-WfxWindows)) { throw 'Live views need Windows.' }
    Get-WfxActivityData -Days $Days -Journal:$Journal | Expand-WfxRecord
}
