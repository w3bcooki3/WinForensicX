# Respond mode safety: refusals, identity checks, confirmation, quarantine round trip, plans, isolation ranges.
# Pester 4/5 compatible. Nothing is stopped, removed or blocked: the commands that would change the system are
# mocked, and the tests check they are NOT called when they must not be.
$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
$mod = Join-Path $root 'WinForensicX'
foreach ($layer in 'Private', 'Analyzers', 'Collectors', 'Report', 'Public') {
    foreach ($f in Get-ChildItem (Join-Path $mod $layer) -Filter *.ps1 | Sort-Object Name) { . $f.FullName }
}
$script:WfxRuleRoot = Join-Path $mod 'Rules'
$script:WfxModuleRoot = $mod
$script:WfxQuiet = $true
# Linux / macOS PowerShell has no CIM cmdlets; stubs let the mocks below attach.
if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) { function Get-CimInstance { } }

function New-TestDir { $d = Join-Path ([IO.Path]::GetTempPath()) ('wfxq_' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $d | Out-Null; $d }
function New-FakeCmdlet {
    <# Stands in for $PSCmdlet: records the questions and answers them with $Answer. #>
    param([bool]$Answer)
    $c = [pscustomobject]@{ Asked = 0; Answer = $Answer }
    $c | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value { param($t, $a) $this.Asked++; $this.Answer }
    $c | Add-Member -MemberType ScriptMethod -Name ShouldContinue -Value { param($q, $c) $this.Asked++; $this.Answer }
    $c
}
function New-Proc { param($Name, $Id, $Path) [pscustomobject]@{ Name = $Name; ProcessId = $Id; ExecutablePath = $Path; CreationDate = [datetime]::new(2026, 11, 27, 10, 0, 0, [DateTimeKind]::Utc); CommandLine = $Path; ParentProcessId = 1 } }

Describe 'Never-touch rules' {
    It 'refuses critical processes, svchost, security products and itself' {
        foreach ($n in 'lsass.exe', 'csrss.exe', 'wininit.exe', 'smss.exe', 'services.exe', 'winlogon.exe', 'MsMpEng.exe', 'CSFalconService.exe') { Test-WfxRefusedProcess -Name $n -ProcessId 900 | Should -Not -BeNullOrEmpty }
        Test-WfxRefusedProcess -Name 'svchost.exe' -ProcessId 900 | Should -Match 'service'
        Test-WfxRefusedProcess -Name 'x' -ProcessId 4 | Should -Not -BeNullOrEmpty
        Test-WfxRefusedProcess -Name 'powershell.exe' -ProcessId 777 -Self 777 | Should -Not -BeNullOrEmpty
        Test-WfxRefusedProcess -Name 'evil.exe' -ProcessId 900 | Should -BeNullOrEmpty
    }
    It 'refuses services Windows depends on' {
        foreach ($n in 'RpcSs', 'WinDefend', 'EventLog', 'Dnscache', 'BFE', 'mpssvc', 'Netlogon') { Test-WfxRefusedService $n | Should -Not -BeNullOrEmpty }
        Test-WfxRefusedService 'UpdaterSvc' | Should -BeNullOrEmpty
    }
    It 'only removes values from the Run keys' {
        foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') { Test-WfxRunKeyPath $k | Should -Be $true }
        foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Services', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\..\..', 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') { Test-WfxRunKeyPath $k | Should -Be $false }
    }
    It 'refuses Microsoft-signed Windows files, drive roots and the quarantine itself' {
        Test-WfxRefusedFile -Path 'C:\Windows\System32\kernel32.dll' -SystemRoot 'C:\Windows' -Signature 'Valid' -Signer 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond' | Should -Not -BeNullOrEmpty
        Test-WfxRefusedFile -Path 'C:\Windows\Temp\dropper.exe' -SystemRoot 'C:\Windows' -Signature 'NotSigned' | Should -BeNullOrEmpty
        Test-WfxRefusedFile -Path 'C:\' -SystemRoot 'C:\Windows' | Should -Not -BeNullOrEmpty
        Test-WfxRefusedFile -Path 'C:\pagefile.sys' -SystemRoot 'C:\Windows' | Should -Not -BeNullOrEmpty
        Test-WfxRefusedFile -Path 'C:\Users\a\Downloads\WinForensicX-Quarantine\files\x.wfxq' -QuarantineRoot 'C:\Users\a\Downloads\WinForensicX-Quarantine' | Should -Not -BeNullOrEmpty
        Test-WfxRefusedFile -Path 'C:\Users\a\AppData\Roaming\upd\upd.exe' -SystemRoot 'C:\Windows' -Signature 'NotSigned' | Should -BeNullOrEmpty
    }
    It 'refuses blocking loopback, everything, wide ranges and this computer' {
        foreach ($a in '127.0.0.1', '::1', '0.0.0.0', '::', '255.255.255.255', '10.0.0.0/4', 'not-an-ip', '') { Test-WfxRefusedAddress -Address $a | Should -Not -BeNullOrEmpty }
        Test-WfxRefusedAddress -Address '192.0.2.10' -Own @('192.0.2.10') | Should -Not -BeNullOrEmpty
        Test-WfxRefusedAddress -Address '203.0.113.7' | Should -BeNullOrEmpty
        Test-WfxRefusedAddress -Address '198.51.100.0/24' | Should -BeNullOrEmpty
    }
    It 'refuses the account in use, system accounts and the last administrator' {
        Test-WfxRefusedAccount -Name 'ana' -Current 'ana' | Should -Not -BeNullOrEmpty
        Test-WfxRefusedAccount -Name 'PC01\ana' -Current 'ana' | Should -Not -BeNullOrEmpty
        Test-WfxRefusedAccount -Name 'WDAGUtilityAccount' -Current 'ana' | Should -Not -BeNullOrEmpty
        Test-WfxRefusedAccount -Name 'admin2' -Current 'ana' -IsLastAdmin $true | Should -Not -BeNullOrEmpty
        Test-WfxRefusedAccount -Name 'backdoor' -Current 'ana' | Should -BeNullOrEmpty
    }
    It 'keeps the quarantine out of cloud-synced folders' {
        Test-WfxCloudPath -Path 'C:\Users\a\OneDrive\Downloads\WinForensicX-Quarantine' -CloudRoots @('C:\Users\a\OneDrive') | Should -Be 'OneDrive'
        Test-WfxCloudPath -Path 'C:\Users\a\OneDrive - Contoso\Downloads\Q' -CloudRoots @() | Should -Not -BeNullOrEmpty
        Test-WfxCloudPath -Path 'C:\Users\a\Dropbox\Downloads\Q' -CloudRoots @() | Should -Not -BeNullOrEmpty
        Test-WfxCloudPath -Path '\\server\share\Q' -CloudRoots @() | Should -Not -BeNullOrEmpty
        Test-WfxCloudPath -Path 'C:\Users\a\Downloads\WinForensicX-Quarantine' -CloudRoots @('C:\Users\a\OneDrive') | Should -BeNullOrEmpty
    }
}

Describe 'Acting on a process' {
    It 'refuses LSASS and never calls Stop-Process' {
        Mock Get-CimInstance { New-Proc 'lsass.exe' 680 'C:\Windows\System32\lsass.exe' }
        Mock Stop-Process { }
        Mock Write-Warning { }
        $c = New-FakeCmdlet $true
        $r = Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'Kill'; Target = 'PID 680'; Params = @{ Pid = 680 } }) -Cmdlet $c -Root ''
        $r.Status | Should -Be 'Refused'
        Assert-MockCalled Stop-Process -Times 0 -Exactly
        $c.Asked | Should -Be 0
    }
    It 'refuses a PID that now belongs to another program' {
        Mock Get-CimInstance { New-Proc 'notepad.exe' 4242 'C:\Windows\System32\notepad.exe' }
        Mock Stop-Process { }
        Mock Write-Warning { }
        $r = Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'Kill'; Target = 'x'; Params = @{ Pid = 4242; Name = 'evil.exe' } }) -Cmdlet (New-FakeCmdlet $true) -Root ''
        $r.Status | Should -Be 'Refused'
        $r.Message | Should -Match 'reused'
        Mock Get-CimInstance { New-Proc 'evil.exe' 4242 'C:\Users\a\evil.exe' }
        $r = Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'Kill'; Target = 'x'; Params = @{ Pid = 4242; Name = 'evil.exe'; StartTime = '2026-11-27T09:00:00Z' } }) -Cmdlet (New-FakeCmdlet $true) -Root ''
        $r.Status | Should -Be 'Refused'
        Assert-MockCalled Stop-Process -Times 0 -Exactly
    }
    It 'asks first, and does nothing when the answer is no' {
        Mock Get-CimInstance { New-Proc 'evil.exe' 4242 'C:\Users\a\evil.exe' }
        Mock Stop-Process { }
        $c = New-FakeCmdlet $false
        $r = Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'Kill'; Target = 'x'; Params = @{ Pid = 4242 } }) -Cmdlet $c -Root ''
        $r | Should -BeNullOrEmpty
        $c.Asked | Should -Be 1
        Assert-MockCalled Stop-Process -Times 0 -Exactly
    }
    It 'reports a process that is already gone instead of failing' {
        Mock Get-CimInstance { }
        $r = Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'Kill'; Target = 'x'; Params = @{ Pid = 4242 } }) -Cmdlet (New-FakeCmdlet $true) -Root ''
        $r.Status | Should -Be 'NotFound'
    }
    It 'refuses registry values outside the Run keys and unknown action types' {
        Mock Write-Warning { }
        (Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'DisableRunKey'; Target = 'x'; Params = @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip'; Name = 'x' } }) -Cmdlet (New-FakeCmdlet $true) -Root '').Status | Should -Be 'Refused'
        (Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'FormatDisk'; Target = 'C:'; Params = @{} }) -Cmdlet (New-FakeCmdlet $true) -Root '').Status | Should -Be 'Refused'
        (Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'DisableService'; Target = 'x'; Params = @{ Name = 'WinDefend' } }) -Cmdlet (New-FakeCmdlet $true) -Root '').Status | Should -Be 'Refused'
        (Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'DisableService'; Target = 'x'; Params = @{ Name = "x' OR Name LIKE '%" } }) -Cmdlet (New-FakeCmdlet $true) -Root '').Status | Should -Be 'Refused'
        (Invoke-WfxResponseAction -Action ([pscustomobject]@{ Type = 'BlockAddress'; Target = 'x'; Params = @{ Address = '127.0.0.1' } }) -Cmdlet (New-FakeCmdlet $true) -Root '').Status | Should -Be 'Refused'
    }
}

Describe 'Quarantine file format' {
    It 'encrypts so the program cannot run, and restores it byte for byte' {
        $d = New-TestDir
        try {
            $src = Join-Path $d 'evil.exe'
            $bytes = [byte[]](@(0x4D, 0x5A) + (1..5000 | ForEach-Object { $_ % 251 }))
            [IO.File]::WriteAllBytes($src, $bytes)
            $blob = Join-Path $d 'a.wfxq'
            $sha = Write-WfxQuarantineFile -Source $src -Target $blob
            $sha | Should -Be (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant()
            $q = [IO.File]::ReadAllBytes($blob)
            [Text.Encoding]::ASCII.GetString($q, 0, 4) | Should -Be 'WFXQ'
            [Text.Encoding]::ASCII.GetString($q, 53, 2) | Should -Not -Be 'MZ'          # the program header is gone
            Read-WfxQuarantineFile -Source $blob | Should -Be $sha
            $back = Join-Path $d 'back.exe'
            Read-WfxQuarantineFile -Source $blob -Target $back | Should -Be $sha
            (Get-FileHash -LiteralPath $back -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $sha
            { Write-WfxQuarantineFile -Source $src -Target $blob } | Should -Throw    # never overwrites
            [IO.File]::WriteAllBytes((Join-Path $d 'bad.wfxq'), [byte[]](1, 2, 3))
            { Read-WfxQuarantineFile -Source (Join-Path $d 'bad.wfxq') } | Should -Throw
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Response plan from a triage' {
    It 'suggests stops, quarantines, disables and public blocks, and leaves the rest alone' {
        $F = {
            param($Id, $Sev, $Src, $Ev)
            New-WfxFinding -Id $Id -Title $Id -Severity $Sev -Category 'Process' -Source $Src -Evidence $Ev
        }
        $result = [pscustomobject]@{ HostName = 'PC01'; Findings = @(
                (& $F 'P1' 'High' 'process' ([ordered]@{ Pid = 4242; Process = 'evil.exe'; Path = 'C:\Users\a\AppData\Roaming\evil.exe' })),
                (& $F 'P2' 'High' 'process' ([ordered]@{ Pid = 680; Process = 'lsass.exe'; Path = 'C:\Windows\System32\lsass.exe' })),
                (& $F 'R1' 'Critical' 'persistence' ([ordered]@{ Kind = 'RunKey'; Name = 'Updater'; Location = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Path = 'C:\Users\a\AppData\Roaming\evil.exe' })),
                (& $F 'S1' 'Medium' 'persistence' ([ordered]@{ Kind = 'Service'; Name = 'WinDefend'; Location = 'Service:Auto' })),
                (& $F 'N1' 'High' 'network' ([ordered]@{ Pid = 4242; Process = 'evil.exe'; Remote = 'c2.example (203.0.113.7):443' })),
                (& $F 'N2' 'High' 'network' ([ordered]@{ Pid = 4242; Process = 'evil.exe'; Remote = '10.0.0.8:445' })),
                (& $F 'F1' 'Medium' 'files' ([ordered]@{ Path = 'C:\inetpub\wwwroot\shell.aspx' }))
            )
        }
        $bundle = [pscustomobject]@{ Process = @([pscustomobject]@{ Pid = 4242; Name = 'evil.exe'; Path = 'C:\Users\a\AppData\Roaming\evil.exe'; CreateTime = '2026-11-27T10:00:00.000Z'; Sha256 = ('a' * 64) }) }
        $plan = ConvertTo-WfxResponsePlan -Result $result -Bundle $bundle
        $plan.Host | Should -Be 'PC01'
        $a = @($plan.Actions)
        $kill = @($a | Where-Object Type -eq 'Kill')
        $kill.Count | Should -Be 1
        $kill[0].Params.Sha256 | Should -Be ('a' * 64)
        $kill[0].Params.StartTime | Should -Be '2026-11-27T10:00:00.000Z'
        @($a | Where-Object Type -eq 'DisableRunKey').Count | Should -Be 1
        @($a | Where-Object { $_.Type -eq 'Quarantine' -and $_.Target -like '*evil.exe' }).Count | Should -Be 1
        @($a | Where-Object { $_.Type -eq 'DisableService' }).Count | Should -Be 0          # WinDefend is never offered
        @($a | Where-Object { $_.Type -eq 'BlockAddress' }).Target | Should -Be '203.0.113.7' # the private one is not
        ($a | Where-Object { $_.Type -eq 'Quarantine' -and $_.Target -like '*shell.aspx' }).Selected | Should -Be $false
        ($a | Where-Object Type -eq 'DisableRunKey').Selected | Should -Be $true
    }
    It 'reads the address out of every form a finding records it in' {
        Get-WfxRemoteIp 'c2.example (203.0.113.7):443' | Should -Be '203.0.113.7'
        Get-WfxRemoteIp '203.0.113.7:8080' | Should -Be '203.0.113.7'
        Get-WfxRemoteIp '[2001:db8::7]:443' | Should -Be '2001:db8::7'
        Get-WfxRemoteIp 'c2.example' | Should -Be ''
    }
    It 'refuses a plan for another computer, and a plan edited after the triage' -Skip:(-not (Test-WfxWindows)) {
        $d = New-TestDir
        try {
            $pf = Join-Path $d 'respond-plan.json'
            Save-WfxJson -InputObject ([pscustomobject]@{ Schema = 'winforensicx.respond-plan/1'; Host = 'SOME-OTHER-PC'; Actions = @() }) -Path $pf
            { Invoke-WfxRespond -PlanPath $d -WhatIf } | Should -Throw '*SOME-OTHER-PC*'
            Save-WfxJson -InputObject ([pscustomobject]@{ Schema = 'winforensicx.respond-plan/1'; Host = [Environment]::MachineName; Actions = @() }) -Path $pf
            Save-WfxJson -InputObject ([pscustomobject]@{ files = @([pscustomobject]@{ path = 'respond-plan.json'; sha256 = ('0' * 64) }) }) -Path (Join-Path $d 'manifest.json')
            { Invoke-WfxRespond -PlanPath $d -WhatIf } | Should -Throw '*changed after the triage*'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Isolation address ranges' {
    It 'blocks everything except the allowed addresses and loopback' {
        $r = Get-WfxComplementRange -Allow @('10.0.0.5', '203.0.113.9') -Family 4
        ($r -join ',') | Should -Be '0.0.0.0-10.0.0.4,10.0.0.6-126.255.255.255,128.0.0.0-203.0.113.8,203.0.113.10-255.255.255.255'
        (Get-WfxComplementRange -Allow @() -Family 4) -join ',' | Should -Be '0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255'
        (Get-WfxComplementRange -Allow @('10.0.0.5') -Family 6) -join ',' | Should -Be '::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        (Get-WfxComplementRange -Allow @('2001:db8::1') -Family 6) -join ',' | Should -Be '::,::2-2001:db8::,2001:db8::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    }
    It 'handles allowed addresses at the very edges and duplicates' {
        (Get-WfxComplementRange -Allow @('0.0.0.0', '255.255.255.255', '0.0.0.0') -Family 4) -join ',' | Should -Be '0.0.0.1-126.255.255.255,128.0.0.0-255.255.255.254'
    }
}

Describe 'Injected-code findings' {
    It 'reports a program header in private memory, leniently for JIT processes, and RWX only outside them' {
        $v = [pscustomobject]@{ Pipes = @(); Modules = @(); Injected = @(
                [pscustomobject]@{ Pid = 10; Process = 'notepad'; Path = 'C:\Windows\notepad.exe'; Address = '0x1A0000'; Size = 65536; Protect = 'RX'; Type = 'Private'; PeHeader = $true; Jit = $false },
                [pscustomobject]@{ Pid = 10; Process = 'notepad'; Path = 'C:\Windows\notepad.exe'; Address = '0x2A0000'; Size = 8192; Protect = 'RWX'; Type = 'Private'; PeHeader = $false; Jit = $false },
                [pscustomobject]@{ Pid = 20; Process = 'powershell'; Path = 'x'; Address = '0x3A0000'; Size = 65536; Protect = 'RX'; Type = 'Private'; PeHeader = $true; Jit = $true }) }
        $f = @(Invoke-WfxVolatileAnalyzer -Volatile $v | Expand-WfxRecord)
        ($f | Where-Object { $_.Id -eq 'MEM-PE-IN-PRIVATE' -and $_.Title -match 'notepad' }).Severity | Should -Be 'High'
        ($f | Where-Object { $_.Id -eq 'MEM-PE-IN-PRIVATE' -and $_.Title -match 'powershell' }).Severity | Should -Be 'Medium'
        @($f | Where-Object Id -eq 'MEM-RWX-PRIVATE').Count | Should -Be 1
    }
    It 'never scans LSASS or security products' {
        foreach ($n in 'lsass', 'MsMpEng', 'csrss') { $script:WfxModuleSkip | Should -Contain $n }
        $src = $script:WfxMemSource
        $src | Should -Not -Match 'WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|PROCESS_ALL_ACCESS|0x1F0FFF'
        $src | Should -Match 'QUERY_INFORMATION \| VM_READ'
    }
}

Describe 'Quarantine folder' {
    It 'is only ever a new, empty or already-ours folder, never a root or a folder with other files' {
        $d = New-TestDir
        try {
            Test-WfxQuarantineFolder -Path (Join-Path $d 'WinForensicX-Quarantine') | Should -BeNullOrEmpty    # does not exist yet
            Set-Content -LiteralPath (Join-Path $d 'notes.txt') -Value 'mine'
            Test-WfxQuarantineFolder -Path $d | Should -Match 'other files'
            $q = Join-Path $d 'q'; New-Item -ItemType Directory -Path $q | Out-Null
            Test-WfxQuarantineFolder -Path $q | Should -BeNullOrEmpty                                           # empty
            Set-Content -LiteralPath (Join-Path $q '.wfx-quarantine') -Value 'x'; Set-Content -LiteralPath (Join-Path $q 'a.txt') -Value 'x'
            Test-WfxQuarantineFolder -Path $q | Should -BeNullOrEmpty                                           # ours
            if (Test-WfxWindows) { Test-WfxQuarantineFolder -Path 'C:\' | Should -Not -BeNullOrEmpty; Test-WfxQuarantineFolder -Path $env:SystemRoot | Should -Not -BeNullOrEmpty }
            else { Test-WfxQuarantineFolder -Path '/' | Should -Not -BeNullOrEmpty }
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
