# Persistence collector — enumerates autostart locations into normalized records.
# Covers Run keys, Startup folders, scheduled tasks, WMI subscriptions, Winlogon, AppInit,
# Image File Execution Options, LSA packages, and BootExecute. Services/drivers come from System.ps1.

function Get-WfxPersistenceData {
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]

    $add = {
        param($Kind, $Name, $Command, $Location, $User = '')
        $path = Get-WfxImagePath $Command
        # Store a secret-scrubbed command (a task action or WMI script text can embed credentials); the
        # image path above is taken from the raw value first so analysis is unaffected.
        $out.Add([pscustomobject]@{ Kind = $Kind; Name = $Name; Command = (Protect-WfxText ([string]$Command)); Path = $path; Location = $Location
                User = $User; Enabled = $true; SignatureStatus = (Get-WfxSignature $path) })
    }

    # ── Run / RunOnce keys (HKLM + all user hives) ──
    Invoke-WfxStep 'persist:runkeys' {
        $runPaths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        )
        foreach ($u in (Get-WfxUserHives)) {
            $runPaths += "$u\Software\Microsoft\Windows\CurrentVersion\Run"
            $runPaths += "$u\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        }
        foreach ($rp in $runPaths) {
            if (-not (Test-Path $rp)) { continue }
            $k = Get-Item $rp -ErrorAction SilentlyContinue
            foreach ($v in $k.GetValueNames()) {
                & $add 'RunKey' $v ($k.GetValue($v)) $rp
            }
        }
    }

    # ── Startup folders ──
    Invoke-WfxStep 'persist:startup' {
        $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $folders += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        }
        foreach ($f in $folders) {
            if (-not (Test-Path $f)) { continue }
            Get-ChildItem $f -File -ErrorAction SilentlyContinue | ForEach-Object { & $add 'Startup' $_.Name $_.FullName $f }
        }
    }

    # ── Scheduled tasks ──
    Invoke-WfxStep 'persist:tasks' {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $t = $_
            foreach ($a in @($t.Actions)) {
                $cmd = ''
                if ($a.Execute) { $cmd = $a.Execute; if ($a.Arguments) { $cmd += ' ' + $a.Arguments } }
                if (-not $cmd) { continue }
                & $add 'ScheduledTask' ($t.TaskPath + $t.TaskName) $cmd ('Task:' + $t.State) ($t.Principal.UserId)
            }
        }
    }

    # ── WMI event subscriptions (classic persistence) ──
    Invoke-WfxStep 'persist:wmi' {
        $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
        foreach ($c in $consumers) {
            $cmd = ''
            if ($c.CommandLineTemplate) { $cmd = $c.CommandLineTemplate }
            elseif ($c.ScriptText) { $cmd = $c.ScriptText }
            elseif ($c.ScriptFileName) { $cmd = $c.ScriptFileName }
            if ($cmd) { & $add 'WmiSubscription' ($c.Name) $cmd 'root\subscription' }
        }
    }

    # ── Winlogon (Shell / Userinit / Notify) ──
    Invoke-WfxStep 'persist:winlogon' {
        $wl = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (Test-Path $wl) {
            $k = Get-Item $wl
            foreach ($v in @('Shell', 'Userinit', 'Taskman', 'VmApplet')) {
                $val = $k.GetValue($v)
                if ($val -and $val -notin @('explorer.exe', 'C:\Windows\system32\userinit.exe,')) { & $add 'Winlogon' $v $val $wl }
            }
        }
    }

    # ── AppInit_DLLs ──
    Invoke-WfxStep 'persist:appinit' {
        foreach ($p in @('HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
            if (-not (Test-Path $p)) { continue }
            $v = (Get-ItemProperty $p -ErrorAction SilentlyContinue).AppInit_DLLs
            if ($v) { & $add 'AppInit' 'AppInit_DLLs' $v $p }
        }
    }

    # ── Image File Execution Options debuggers ──
    Invoke-WfxStep 'persist:ifeo' {
        $ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-Path $ifeo) {
            Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
                $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
                if ($dbg) { & $add 'ImageFileExecution' ($_.PSChildName) $dbg $ifeo }
            }
        }
    }

    # ── LSA security/authentication packages ──
    Invoke-WfxStep 'persist:lsa' {
        $lsa = 'HKLM:\System\CurrentControlSet\Control\Lsa'
        if (Test-Path $lsa) {
            $k = Get-ItemProperty $lsa -ErrorAction SilentlyContinue
            foreach ($v in @('Security Packages', 'Authentication Packages', 'Notification Packages')) {
                $known = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', '""', 'scecli', 'rassfm')
                foreach ($pkg in @($k.$v | Where-Object { $_ })) {
                    if ($pkg.ToLower().Trim('"') -notin $known) { & $add 'LsaProvider' "$v`:$pkg" $pkg $lsa }
                }
            }
        }
    }

    # ── BootExecute ──
    Invoke-WfxStep 'persist:bootexec' {
        $sm = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
        if (Test-Path $sm) {
            foreach ($be in @((Get-ItemProperty $sm -ErrorAction SilentlyContinue).BootExecute | Where-Object { $_ })) {
                if ($be -notmatch '^autocheck\s+autochk') { & $add 'BootExecute' $be $be $sm }
            }
        }
    }

    , @($out.ToArray())
}

function Get-WfxUserHives {
    <# Returns registry paths for all loaded user hives (Registry::HKEY_USERS\<sid>). #>
    $hives = @('HKCU:')
    try {
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
            $hives += "Registry::HKEY_USERS\$($_.PSChildName)"
        }
    } catch {}
    $hives
}
