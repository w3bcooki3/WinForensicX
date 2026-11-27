# Start-up (administrator prompt, self-check), the triage plan, and memory-capture readiness.
# Pester 4/5 compatible; runs on any OS (nothing is elevated, collected or started).
$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
$mod = Join-Path $root 'WinForensicX'
foreach ($layer in 'Private', 'Analyzers', 'Collectors', 'Report', 'Public') {
    foreach ($f in Get-ChildItem (Join-Path $mod $layer) -Filter *.ps1 | Sort-Object Name) { . $f.FullName }
}
$script:WfxRuleRoot = Join-Path $mod 'Rules'
$script:WfxModuleRoot = $mod
$script:WfxQuiet = $true

function New-TestDir { $d = Join-Path ([IO.Path]::GetTempPath()) ('wfxr_' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $d | Out-Null; $d }
function New-Ready {
    <# Readiness facts as Get-WfxReadinessData returns them; override parts with -Set. #>
    param([hashtable]$Dump = @{}, [hashtable]$Memory = @{}, [hashtable]$Power = @{}, [hashtable]$Protection = @{}, $BitLocker = 'default', [string]$Boot = '2026-11-20T08:00:00.000Z')
    $d = @{ CrashDumpEnabled = 1; FilterPages = $null; DedicatedDumpFile = ''; DumpFile = 'C:\Windows\MEMORY.DMP'; DumpVolumeFree = 200GB }
    $m = @{ RamBytes = 16GB; AutoPageFile = $false; PageFiles = @([pscustomobject]@{ Path = 'C:\pagefile.sys'; AllocatedMB = 17000 }); ClearPageFileAtShutdown = 0; Manufacturer = 'Dell Inc.'; Model = 'Latitude 7440'; VmVendor = ''; HasBattery = $false }
    $p = @{ HibernateEnabled = 1; HiberFileExists = $true; FastStartup = 0; CrashOnCtrlScrollUsb = 1; CrashOnCtrlScrollPs2 = $null }
    $r = @{ MemoryIntegrity = $false; CredentialGuard = $false; RunAsPPL = $false }
    foreach ($k in $Dump.Keys) { $d[$k] = $Dump[$k] }; foreach ($k in $Memory.Keys) { $m[$k] = $Memory[$k] }
    foreach ($k in $Power.Keys) { $p[$k] = $Power[$k] }; foreach ($k in $Protection.Keys) { $r[$k] = $Protection[$k] }
    $bl = if ($BitLocker -is [string] -and $BitLocker -eq 'default') { [pscustomobject]@{ Protection = 'On'; Status = 'FullyEncrypted'; ProtectorTypes = @('Tpm', 'RecoveryPassword') } } else { $BitLocker }
    [pscustomobject]@{ Collected = '2026-11-27T08:00:00.000Z'; Admin = $true; BootUtc = $Boot; Dump = [pscustomobject]$d; Memory = [pscustomobject]$m; Power = [pscustomobject]$p; Protection = [pscustomobject]$r; BitLocker = $bl }
}
function Get-Row { param($Rows, $Key) @($Rows | Where-Object { $_.Key -eq $Key }) | Select-Object -First 1 }

Describe 'Administrator prompt' {
    It 'quotes arguments so Windows splits them back unchanged' {
        ConvertTo-WfxArgument 'E:\cases' | Should -Be 'E:\cases'
        ConvertTo-WfxArgument 'E:\my cases' | Should -Be '"E:\my cases"'
        # A trailing backslash would otherwise escape the closing quote.
        ConvertTo-WfxArgument 'E:\my cases\' | Should -Be '"E:\my cases\\"'
        ConvertTo-WfxArgument 'a "b"' | Should -Be '"a \"b\""'
        ConvertTo-WfxArgument '' | Should -Be '""'
    }
    It 'restarts the same script with -NoProfile, the current policy and -NoElevate' {
        $c = Get-WfxElevationCommand -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ScriptPath 'C:\Tools\WFX 3\Start-WinForensicX.ps1' -Parameters @{ OutputPath = 'E:\cases'; RunTriage = $true; Menu = $false } -ExecutionPolicy 'RemoteSigned'
        $c.FilePath | Should -Be 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $c.Arguments | Should -Be '-NoProfile -ExecutionPolicy RemoteSigned -File "C:\Tools\WFX 3\Start-WinForensicX.ps1" -OutputPath E:\cases -RunTriage -NoElevate'
    }
    It 'never loosens the execution policy and never passes its own switches on' {
        $c = Get-WfxElevationCommand -Exe 'pwsh.exe' -ScriptPath 'C:\t\s.ps1' -Parameters @{ Elevate = $true; NoElevate = $false; OutputPath = '' } -ExecutionPolicy 'Restricted'
        $c.Arguments | Should -Be '-NoProfile -File C:\t\s.ps1 -NoElevate'
        (Get-WfxElevationCommand -Exe 'x' -ScriptPath 'y' -ExecutionPolicy 'Undefined').Arguments | Should -Not -Match 'ExecutionPolicy'
    }
    It 'refuses parameter names that are not plain words' {
        { Get-WfxElevationCommand -Exe 'x' -ScriptPath 'y' -Parameters @{ 'a; calc' = 'z' } } | Should -Throw
    }
    It 'does not ask when told not to, or when nobody can answer' {
        Request-WfxElevation -ScriptPath 'C:\t\s.ps1' -NoElevate | Should -Be 'Continue'
        Mock Test-WfxWindows { $true }
        Mock Test-WfxAdmin { $false }
        Mock Test-WfxInteractive { $false }
        Mock Start-Process { }
        Mock Read-WfxMenuChoice { 'A' }
        Request-WfxElevation -ScriptPath 'C:\t\s.ps1' | Should -Be 'Continue'
        Assert-MockCalled Read-WfxMenuChoice -Times 0 -Exactly
        Assert-MockCalled Start-Process -Times 0 -Exactly
    }
    It 'does nothing when already administrator' {
        Mock Test-WfxWindows { $true }
        Mock Test-WfxAdmin { $true }
        Mock Start-Process { }
        Request-WfxElevation -ScriptPath 'C:\t\s.ps1' -Elevate | Should -Be 'Continue'
        Assert-MockCalled Start-Process -Times 0 -Exactly
    }
    It 'follows the answer: Q quits, C continues, A opens an administrator window' {
        Mock Test-WfxWindows { $true }
        Mock Test-WfxAdmin { $false }
        Mock Test-WfxInteractive { $true }
        Mock Write-Host { }
        Mock Start-Process { }
        Mock Read-WfxMenuChoice { 'Q' }
        Request-WfxElevation -ScriptPath 'C:\t\s.ps1' | Should -Be 'Quit'
        Mock Read-WfxMenuChoice { 'C' }
        Request-WfxElevation -ScriptPath 'C:\t\s.ps1' | Should -Be 'Continue'
        Assert-MockCalled Start-Process -Times 0 -Exactly
        Mock Read-WfxMenuChoice { 'A' }
        Request-WfxElevation -ScriptPath 'C:\t\s.ps1' -Parameters @{ OutputPath = 'E:\x y' } | Should -Be 'Elevated'
        Assert-MockCalled Start-Process -Times 1 -Exactly -ParameterFilter { $Verb -eq 'RunAs' -and $ArgumentList -match '-NoProfile' -and $ArgumentList -match '-NoElevate' -and $ArgumentList -match '"E:\\x y"' }
    }
    It 'carries on without administrator rights when UAC is cancelled' {
        Mock Test-WfxWindows { $true }
        Mock Test-WfxAdmin { $false }
        Mock Write-Host { }
        Mock Start-Process { throw 'The operation was canceled by the user.' }
        Request-WfxElevation -ScriptPath 'C:\t\s.ps1' -Elevate | Should -Be 'Continue'
    }
}

Describe 'Self-check against SHA256SUMS.txt' {
    It 'reports OK, then changed, extra and missing code files, and NOSUMS without a list' {
        $saveRoot = $script:WfxModuleRoot; $saveSingle = $script:WfxSingleFilePath
        $rel = New-TestDir
        try {
            $m = Join-Path $rel 'WinForensicX'
            New-Item -ItemType Directory -Path (Join-Path $m 'Private') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $m 'Private/A.ps1') -Value 'function A { 1 }'
            Set-Content -LiteralPath (Join-Path $m 'WinForensicX.psm1') -Value '# loader'
            Set-Content -LiteralPath (Join-Path $rel 'README.md') -Value 'readme'
            $sums = foreach ($f in 'WinForensicX/Private/A.ps1', 'WinForensicX/WinForensicX.psm1', 'README.md') { '{0}  {1}' -f (Get-FileHash -LiteralPath (Join-Path $rel $f) -Algorithm SHA256).Hash, $f }
            Set-Content -LiteralPath (Join-Path $rel 'SHA256SUMS.txt') -Value $sums
            $script:WfxModuleRoot = $m; $script:WfxSingleFilePath = $null

            $r = Test-WfxIntegrity
            $r.Status | Should -Be 'OK'
            $r.Checked | Should -Be 2              # code files only; README is not code
            $r.SumsSha256 | Should -Match '^[0-9a-f]{64}$'

            Set-Content -LiteralPath (Join-Path $rel 'README.md') -Value 'edited docs'
            (Test-WfxIntegrity).Status | Should -Be 'OK'

            Set-Content -LiteralPath (Join-Path $m 'Private/A.ps1') -Value 'function A { 2 }'
            Set-Content -LiteralPath (Join-Path $m 'Private/Planted.ps1') -Value 'function B { }'
            $r = Test-WfxIntegrity
            $r.Status | Should -Be 'CHANGED'
            @($r.Changed) | Should -Contain 'winforensicx/private/a.ps1'
            @($r.Unexpected) | Should -Contain 'winforensicx/private/planted.ps1'

            Remove-Item -LiteralPath (Join-Path $m 'WinForensicX.psm1')
            @((Test-WfxIntegrity).Missing) | Should -Contain 'winforensicx/winforensicx.psm1'

            Remove-Item -LiteralPath (Join-Path $rel 'SHA256SUMS.txt')
            (Test-WfxIntegrity).Status | Should -Be 'NOSUMS'
        } finally { $script:WfxModuleRoot = $saveRoot; $script:WfxSingleFilePath = $saveSingle; Remove-Item -LiteralPath $rel -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'reads sha256sum-style lists, including Windows separators and binary-mode stars' {
        $d = New-TestDir
        try {
            $p = Join-Path $d 'SHA256SUMS.txt'
            Set-Content -LiteralPath $p -Value @(('A' * 64) + '  dist\WinForensicX.ps1', ('b' * 64) + ' *Start-WinForensicX.ps1', 'not a hash line')
            $s = Read-WfxSums -Path $p
            $s.Count | Should -Be 2
            $s['dist/winforensicx.ps1'] | Should -Be ('A' * 64)
            $s['start-winforensicx.ps1'] | Should -Be ('B' * 64)
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Triage plan' {
    It 'lists every stage for a live triage and marks what is not included' {
        $p = Get-WfxTriagePlan -Mode Local -Hours 24 -Admin $true
        @($p | Where-Object Stage -eq 'Event logs').Count | Should -Be 1
        ($p | Where-Object Stage -eq 'Event logs').Reads | Should -Match 'Last 24 hours'
        ($p | Where-Object Stage -eq 'Event logs').Reads | Should -Match 'Security'
        ($p | Where-Object Stage -eq 'File scan').Included | Should -Match '^No'
        (Get-WfxTriagePlan -Mode Local -FileScan | Where-Object Stage -eq 'File scan').Included | Should -Be 'Yes'
        @($p | Where-Object WithoutAdmin).Count | Should -Be 0
    }
    It 'says what is missing without administrator rights' {
        $p = Get-WfxTriagePlan -Mode Local -Admin $false
        ($p | Where-Object Stage -eq 'Event logs').WithoutAdmin | Should -Match 'Security log'
        ($p | Where-Object Stage -eq 'System information').WithoutAdmin | Should -BeNullOrEmpty
    }
    It 'reads nothing from this computer for offline, saved and collected evidence' {
        foreach ($mode in 'Offline', 'Reanalyze', 'Artifacts') {
            $p = Get-WfxTriagePlan -Mode $mode -Source 'D:\ev'
            ($p | Where-Object Stage -eq 'This computer').Reads | Should -Match '^Nothing'
            @($p | Where-Object Stage -eq 'Processes').Count | Should -Be 0
        }
    }
    It 'covers every step the collectors run (the plan cannot fall behind the code)' {
        $names = foreach ($f in Get-ChildItem (Join-Path $mod 'Collectors') -Filter *.ps1) {
            foreach ($m in [regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), 'Invoke-WfxStep\s+[''"]([a-z]+):')) { $m.Groups[1].Value + ':x' }
        }
        $names = @($names | Sort-Object -Unique)
        $names.Count | Should -BeGreaterThan 8
        $patterns = @($script:WfxPlanStage | ForEach-Object { $_.Steps })
        foreach ($n in $names) {
            $covered = @($patterns | Where-Object { $n -like $_ }).Count -gt 0
            if (-not $covered) { throw "Collector step '$n' is not described in Private/Plan.ps1" }
        }
    }
    It 'stops before collecting anything with -Plan' {
        $out = New-TestDir
        try {
            $rows = Invoke-WfxTriage -Plan -PassThru -Quiet -OutputPath $out
            @($rows).Count | Should -BeGreaterThan 5
            @(Get-ChildItem -LiteralPath $out).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Memory-capture readiness' {
    It 'recognises virtual machines by manufacturer and model, and not Surface or Dell laptops' {
        Get-WfxVmVendor 'VMware, Inc.' 'VMware7,1' | Should -Be 'VMware'
        Get-WfxVmVendor 'Microsoft Corporation' 'Virtual Machine' | Should -Be 'Hyper-V'
        Get-WfxVmVendor 'innotek GmbH' 'VirtualBox' | Should -Be 'VirtualBox'
        Get-WfxVmVendor 'QEMU' 'Standard PC (Q35 + ICH9, 2009)' | Should -Be 'QEMU/KVM'
        Get-WfxVmVendor 'Microsoft Corporation' 'Surface Laptop 5' | Should -Be ''
        Get-WfxVmVendor 'Dell Inc.' 'Latitude 7440' | Should -Be ''
    }
    It 'is ready when a complete dump, Ctrl+Scroll Lock and hibernation are set up' {
        $c = Get-WfxReadinessCheck -Data (New-Ready)
        (Get-Row $c 'dump').Status | Should -Be 'Ready'
        (Get-Row $c 'pagefile').Status | Should -Be 'Ready'
        (Get-Row $c 'dumpspace').Status | Should -Be 'Ready'
        (Get-Row $c 'ctrlscroll').Status | Should -Be 'Ready'
        (Get-Row $c 'hibernate').Status | Should -Be 'Ready'
        (Get-Row $c 'vm').Status | Should -Be 'Note'
        $s = Get-WfxReadinessSummary -Check $c
        $s | Should -Match 'shutdown /h'
        $s | Should -Match 'Scroll Lock'
    }
    It 'flags a kernel-only dump, a small page file, no hibernation, and says to leave it running' {
        $c = Get-WfxReadinessCheck -Data (New-Ready -Dump @{ CrashDumpEnabled = 7 } -Memory @{ PageFiles = @([pscustomobject]@{ Path = 'C:\pagefile.sys'; AllocatedMB = 4096 }) } -Power @{ HibernateEnabled = 0; HiberFileExists = $false; CrashOnCtrlScrollUsb = $null })
        (Get-Row $c 'dump').Status | Should -Be 'Not ready'
        (Get-Row $c 'dump').Fix | Should -Match 'Complete memory dump'
        (Get-Row $c 'pagefile').Status | Should -Be 'Not ready'
        (Get-Row $c 'pagefile').Value | Should -Match '16641 MB'
        (Get-Row $c 'hibernate').Status | Should -Be 'Not ready'
        (Get-Row $c 'ctrlscroll').Status | Should -Be 'Note'
        Get-WfxReadinessSummary -Check $c | Should -Match 'Leave it running'
    }
    It 'treats a system-managed page file and a dedicated dump file correctly' {
        (Get-Row (Get-WfxReadinessCheck -Data (New-Ready -Memory @{ AutoPageFile = $true })) 'pagefile').Status | Should -Be 'Note'
        (Get-Row (Get-WfxReadinessCheck -Data (New-Ready -Dump @{ DedicatedDumpFile = 'D:\dump.sys' } -Memory @{ PageFiles = @() })) 'pagefile').Status | Should -Be 'Ready'
    }
    It 'puts the hypervisor snapshot first on a virtual machine' {
        $c = Get-WfxReadinessCheck -Data (New-Ready -Memory @{ VmVendor = 'VMware' })
        (Get-Row $c 'vm').Status | Should -Be 'Ready'
        $card = Get-WfxIncidentCard -Check $c
        @($card | Where-Object Kind -eq 'Do')[2].Text | Should -Match 'snapshot'
        Get-WfxReadinessSummary -Check $c | Should -Match '^Memory can be kept by a snapshot'
    }
    It 'needs the BitLocker recovery key, and says so when there is no recovery password' {
        $c = Get-WfxReadinessCheck -Data (New-Ready -BitLocker ([pscustomobject]@{ Protection = 'On'; Status = 'FullyEncrypted'; ProtectorTypes = @('Tpm') }))
        (Get-Row $c 'bitlocker').Status | Should -Be 'Not ready'
        @(Get-WfxIncidentCard -Check $c | Where-Object { $_.Text -match 'recovery key' }).Count | Should -Be 1
        (Get-Row (Get-WfxReadinessCheck -Data (New-Ready -BitLocker $null)) 'bitlocker').Status | Should -Be 'Unknown'
        (Get-Row (Get-WfxReadinessCheck -Data (New-Ready -BitLocker ([pscustomobject]@{ Protection = 'Off'; Status = 'FullyDecrypted'; ProtectorTypes = @() }))) 'bitlocker').Status | Should -Be 'Ready'
    }
    It 'warns about Fast Startup and protections that affect capture' {
        $c = Get-WfxReadinessCheck -Data (New-Ready -Power @{ FastStartup = 1 } -Protection @{ MemoryIntegrity = $true; RunAsPPL = $true; CredentialGuard = $true })
        foreach ($k in 'faststartup', 'hvci', 'ppl', 'credguard') { (Get-Row $c $k).Status | Should -Be 'Note' }
        @(Get-WfxIncidentCard -Check $c | Where-Object { $_.Kind -eq 'Avoid' -and $_.Text -match 'Fast Startup' }).Count | Should -Be 1
    }
    It 'never tells anyone to shut the computer down' {
        foreach ($d in (New-Ready), (New-Ready -Memory @{ VmVendor = 'Hyper-V' }), (New-Ready -Power @{ HibernateEnabled = 0; HiberFileExists = $false })) {
            foreach ($x in @(Get-WfxIncidentCard -Check (Get-WfxReadinessCheck -Data $d) | Where-Object Kind -eq 'Do')) { $x.Text | Should -Not -Match '(?i)\bshut (it )?down\b|\brestart\b' }
        }
    }
    It 'gives the same answers from a saved bundle (JSON round trip)' {
        $d = New-Ready -BitLocker ([pscustomobject]@{ Protection = 'On'; Status = 'FullyEncrypted'; ProtectorTypes = @('RecoveryPassword') })
        $j = $d | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        $a = @(Get-WfxReadinessCheck -Data $d | ForEach-Object { "$($_.Key)=$($_.Status)" })
        $b = @(Get-WfxReadinessCheck -Data $j | ForEach-Object { "$($_.Key)=$($_.Status)" })
        ($b -join ',') | Should -Be ($a -join ',')
    }
    It 'returns nothing for no data, and the collector never copies a BitLocker recovery password' {
        @(Get-WfxReadinessCheck -Data $null).Count | Should -Be 0
        $src = Get-Content -LiteralPath (Join-Path $mod 'Collectors/Readiness.ps1') -Raw
        $src | Should -Not -Match '\.RecoveryPassword\b'
        $src | Should -Not -Match '=\s*\$v\.KeyProtector\s*(?:[;}]|$)'
    }
    It 'adds checks and the card to the result without changing the scores' {
        $base = [pscustomobject]@{ HostName = 'H'; Process = @([pscustomobject]@{ Pid = 1; Name = 'cmd.exe'; Path = 'C:\Windows\System32\cmd.exe'; CommandLine = 'cmd /c whoami' }) }
        $with = [pscustomobject]@{ HostName = 'H'; Process = $base.Process; Security = [pscustomobject]@{ Readiness = (New-Ready) } }
        $r0 = Invoke-WfxAnalyze -Bundle $base -AllowlistPath ''
        $r1 = Invoke-WfxAnalyze -Bundle $with -AllowlistPath ''
        @($r0.Readiness).Count | Should -Be 0
        @($r1.Readiness).Count | Should -BeGreaterThan 5
        @($r1.IncidentCard).Count | Should -BeGreaterThan 3
        $r1.ReadinessSummary | Should -Match 'Memory can be kept'
        $r1.Risk.Score | Should -Be $r0.Risk.Score
        $r1.Posture.Score | Should -Be $r0.Posture.Score
    }
    It 'shows them in the report, escaped, and leaves the section out when there are none' {
        $d = New-TestDir
        try {
            $b = [pscustomobject]@{ HostName = 'H'; Security = [pscustomobject]@{ Readiness = (New-Ready -Memory @{ Model = '<img src=x onerror=alert(1)>' }) } }
            $r = Invoke-WfxAnalyze -Bundle $b -AllowlistPath ''
            $html = Get-Content -LiteralPath (New-WfxReport -Result $r -Path (Join-Path $d 'r.html')) -Raw
            $html | Should -Match 'id="act"'
            $html | Should -Match '"readiness"'
            $html | Should -Not -Match '<img src=x'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
