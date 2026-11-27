# Volatile state (named pipes, loaded DLLs, sessions) and the fast file search.
# Pester 4/5 compatible; runs on any OS. The file search is tested on a temporary folder tree.
$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
$mod = Join-Path $root 'WinForensicX'
foreach ($layer in 'Private', 'Analyzers', 'Collectors', 'Report', 'Public') {
    foreach ($f in Get-ChildItem (Join-Path $mod $layer) -Filter *.ps1 | Sort-Object Name) { . $f.FullName }
}
$script:WfxRuleRoot = Join-Path $mod 'Rules'
$script:WfxModuleRoot = $mod
$script:WfxQuiet = $true

function New-TestDir { $d = Join-Path ([IO.Path]::GetTempPath()) ('wfxv_' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $d | Out-Null; $d }
function New-Mod { param($Exe, $Module, $Sig = 'NotSigned') [pscustomobject]@{ Pid = 100; Process = [IO.Path]::GetFileNameWithoutExtension(($Exe -split '\\')[-1]); ProcessPath = $Exe; Module = $Module; Signature = $Sig } }

Describe 'Named pipes' {
    It 'flags default C2 pipe names' {
        foreach ($n in 'MSSE-1234-server', 'msagent_ab12', 'postex_8f2a', 'status_4c') { (Test-WfxSuspiciousPipe -Name $n).Kind | Should -Be 'c2' }
    }
    It 'flags privilege-escalation and remote-execution pipes' {
        foreach ($n in 'PSEXESVC', 'RemCom_communicaton', 'test\pipe\spoolss', 'paexec-123-stdin') { (Test-WfxSuspiciousPipe -Name $n).Kind | Should -Be 'escalation' }
    }
    It 'leaves ordinary Windows and application pipes alone' {
        foreach ($n in 'mojo.5688.8052.183894939787088877', 'InitShutdown', 'lsass', 'srvsvc', 'ntsvcs', 'wkssvc', 'PSHost.133771.4242.DefaultAppDomain.powershell', 'vscode-ipc-1a2b-sock', 'Winsock2\CatalogChangeListener-3a4-0', '') {
            Test-WfxSuspiciousPipe -Name $n | Should -BeNullOrEmpty
        }
    }
}

Describe 'DLLs loaded from user-writable folders' {
    It 'rates an unsigned DLL from Temp inside a Windows program High' {
        (Test-WfxModuleLoad (New-Mod 'C:\Windows\System32\rundll32.exe' 'C:\Users\ana\AppData\Local\Temp\upd.dll')).Severity | Should -Be 'High'
    }
    It 'rates an unsigned DLL from outside the program''s own folder Medium' {
        (Test-WfxModuleLoad (New-Mod 'C:\Program Files\Vendor\app.exe' 'C:\Users\ana\AppData\Roaming\x\evil.dll')).Severity | Should -Be 'Medium'
    }
    It 'accepts a program''s own DLLs, signed DLLs, unchecked ones and DLLs outside user folders' {
        Test-WfxModuleLoad (New-Mod 'C:\Users\ana\AppData\Local\Programs\Code\Code.exe' 'C:\Users\ana\AppData\Local\Programs\Code\resources\app\x.dll') | Should -BeNullOrEmpty
        Test-WfxModuleLoad (New-Mod 'C:\Users\ana\AppData\Local\Discord\app-1.0.9\Discord.exe' 'C:\Users\ana\AppData\Local\Discord\modules\voice\v.dll') | Should -BeNullOrEmpty
        Test-WfxModuleLoad (New-Mod 'C:\Windows\explorer.exe' 'C:\Users\ana\AppData\Local\Microsoft\OneDrive\FileSyncShell64.dll' 'Valid') | Should -BeNullOrEmpty
        Test-WfxModuleLoad (New-Mod 'C:\Windows\explorer.exe' 'C:\Users\ana\AppData\Local\Temp\a.dll' 'NotChecked') | Should -BeNullOrEmpty
        Test-WfxModuleLoad (New-Mod 'C:\Windows\explorer.exe' 'C:\Program Files\Vendor\ext.dll') | Should -BeNullOrEmpty
    }
    It 'never opens LSASS or security products' {
        foreach ($n in 'lsass', 'csrss', 'MsMpEng', 'MsSense') { $script:WfxModuleSkip | Should -Contain $n }
    }
}

Describe 'Sessions' {
    It 'parses quser output, including disconnected sessions' {
        $q = @(
            ' USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME',
            '>ana                   console             1  Active      none   11/27/2026 9:02 AM',
            ' bob                                       2  Disc           5   11/26/2026 6:10 PM',
            ' carol                 rdp-tcp#3           3  Active         .   11/27/2026 8:00 AM')
        $r = @(ConvertFrom-WfxQuser -Line $q)
        $r.Count | Should -Be 3
        $r[0].User | Should -Be 'ana'; $r[0].Session | Should -Be 'console'; $r[0].LogonTime | Should -Be '11/27/2026 9:02 AM'; $r[0].Current | Should -Be $true
        $r[1].User | Should -Be 'bob'; $r[1].Session | Should -Be ''; $r[1].State | Should -Be 'Disc'; $r[1].LogonTime | Should -Be '11/26/2026 6:10 PM'
        $r[2].Session | Should -Be 'rdp-tcp#3'
    }
}

Describe 'Volatile analyzer' {
    It 'reports pipes and side-loaded DLLs as findings' {
        $v = [pscustomobject]@{ Pipes = @('MSSE-99-server', 'InitShutdown', 'PSEXESVC'); Sessions = @(); Arp = @()
            Modules = @((New-Mod 'C:\Windows\System32\rundll32.exe' 'C:\Users\ana\AppData\Local\Temp\upd.dll'), (New-Mod 'C:\Program Files\Vendor\app.exe' 'C:\Program Files\Vendor\ok.dll')) }
        $f = @(Invoke-WfxVolatileAnalyzer -Volatile $v -HostName 'H')
        @($f | Where-Object Id -eq 'VOL-PIPE-C2').Count | Should -Be 1
        @($f | Where-Object Id -eq 'VOL-PIPE-ESCALATION').Count | Should -Be 1
        @($f | Where-Object Id -eq 'VOL-MODULE-SIDELOAD-WINDOWS').Count | Should -Be 1
        $f.Count | Should -Be 3
        @(Invoke-WfxVolatileAnalyzer -Volatile $null).Count | Should -Be 0
    }
    It 'runs as part of the analysis of a bundle' {
        $b = [pscustomobject]@{ HostName = 'H'; Volatile = [pscustomobject]@{ Pipes = @('postex_1234'); Modules = @(); Sessions = @(); Arp = @() } }
        $r = Invoke-WfxAnalyze -Bundle $b -AllowlistPath ''
        @($r.Findings | Where-Object Id -eq 'VOL-PIPE-C2').Count | Should -Be 1
    }
}

Describe 'Fast file search' {
    BeforeAll {
        $script:T = New-TestDir
        $sep = [IO.Path]::DirectorySeparatorChar
        New-Item -ItemType Directory -Path (Join-Path $script:T "a${sep}b"), (Join-Path $script:T 'WinForensicX-Quarantine'), (Join-Path $script:T 'Invoice-folder') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:T "a${sep}x.ps1") -Value 'hi'
        Set-Content -LiteralPath (Join-Path $script:T "a${sep}b${sep}Y.EXE") -Value 'hello'
        Set-Content -LiteralPath (Join-Path $script:T "WinForensicX-Quarantine${sep}q.ps1") -Value 'held'
        Set-Content -LiteralPath (Join-Path $script:T "a${sep}noext") -Value 'abcdefghij'
        Set-Content -LiteralPath (Join-Path $script:T "a${sep}b${sep}my_invoice.pdf") -Value '1'
        # A program pretending to be a PDF.
        [IO.File]::WriteAllBytes((Join-Path $script:T "a${sep}report.pdf"), [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00))
    }
    AfterAll { Remove-Item -LiteralPath $script:T -Recurse -Force -ErrorAction SilentlyContinue }

    It 'normalises extensions and names' {
        $s = ConvertTo-WfxExtensionSet -Extension '*.EXE', 'ps1;hta', '.js'
        @($s | Sort-Object) -join ',' | Should -Be '.exe,.hta,.js,.ps1'
        ConvertTo-WfxExtensionSet -Extension @() | Should -BeNullOrEmpty
        $rx = ConvertTo-WfxNameRegex -Name '*invoice*', 'setup?.exe'
        $rx.IsMatch('My_Invoice.pdf') | Should -Be $true
        $rx.IsMatch('setup1.exe') | Should -Be $true
        $rx.IsMatch('setup12.exe') | Should -Be $false
        ConvertTo-WfxNameRegex -Name '*' | Should -BeNullOrEmpty
        (ConvertTo-WfxNameRegex -Name '^inv\d+$' -Regex).IsMatch('INV42') | Should -Be $true
    }
    It 'finds by extension, with or without the dot, and never searches the quarantine' {
        $r = @(Find-WfxFile -Extension ps1, '.exe' -Path $script:T -Method Walk -WarningAction SilentlyContinue)
        @($r.Name | Sort-Object) -join ',' | Should -Be 'x.ps1,Y.EXE'
        @($r | Where-Object { $_.Path -match 'Quarantine' }).Count | Should -Be 0
        ($r | Where-Object Name -eq 'Y.EXE').Size | Should -BeGreaterThan 0
        ($r | Where-Object Name -eq 'Y.EXE').Modified | Should -Match 'Z$'
    }
    It 'finds files and folders by name' {
        $r = @(Find-WfxFile -Name '*invoice*' -ItemType Any -Path $script:T -Method Walk -WarningAction SilentlyContinue)
        @($r.Name | Sort-Object) -join ',' | Should -Be 'Invoice-folder,my_invoice.pdf'
        ($r | Where-Object Name -eq 'Invoice-folder').Type | Should -Be 'Folder'
        @(Find-WfxFile -Name '*invoice*' -Path $script:T -Method Walk -WarningAction SilentlyContinue).Count | Should -Be 1
    }
    It 'finds files without an extension, with size and date limits' {
        @(Find-WfxFile -NoExtension -MinSize 5 -Path $script:T -Method Walk -WarningAction SilentlyContinue).Name | Should -Be 'noext'
        @(Find-WfxFile -NoExtension -MinSize 1000 -Path $script:T -Method Walk -WarningAction SilentlyContinue).Count | Should -Be 0
        @(Find-WfxFile -Name * -ModifiedAfter (Get-Date).AddDays(1) -Path $script:T -Method Walk -WarningAction SilentlyContinue).Count | Should -Be 0
    }
    It 'shows the real type and a mismatch with the extension' {
        $r = @(Find-WfxFile -Extension pdf -CheckType -Hash -Path $script:T -Method Walk -WarningAction SilentlyContinue)
        $fake = $r | Where-Object Name -eq 'report.pdf'
        $fake.TrueType | Should -Match 'PE executable'
        $fake.TypeMismatch | Should -Be $true
        $fake.Sha256 | Should -Match '^([0-9a-f]{64})?$'
    }
    It 'stops at the result limit and says so' {
        $w = $null
        $r = @(Find-WfxFile -Name * -ItemType Any -Path $script:T -Method Walk -MaxResults 2 -WarningVariable w -WarningAction SilentlyContinue)
        $r.Count | Should -Be 2
        (@($w) -join ' ') | Should -Match 'Stopped at 2'
    }
    It 'asks for something to look for, and rejects contradictory options' {
        { Find-WfxFile -Path $script:T } | Should -Throw
        { Find-WfxFile -Extension exe -NoExtension -Path $script:T } | Should -Throw
    }
    It 'only ever opens a volume for reading' {
        $src = $script:WfxFinderSource
        $src | Should -Not -Match 'GENERIC_WRITE|WriteFile|DeleteFile|SetFile|MoveFile'
        @([regex]::Matches($src, 'FSCTL_[A-Z_]+') | ForEach-Object Value | Sort-Object -Unique) -join ',' | Should -Be 'FSCTL_ENUM_USN_DATA'
    }
}
