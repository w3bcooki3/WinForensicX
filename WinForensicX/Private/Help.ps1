# Single source of truth for user-facing help: commands, examples, limitations, safety.
# Rendered to the terminal by Show-WfxHelp and to HTML by New-WfxGuide, so the two never drift.

function Get-WfxHelpModel {
    [pscustomobject]@{
        Version  = $script:WfxVersion
        Tagline  = 'Read-only DFIR toolkit for Windows. Start it from a PowerShell window with .\Start-WinForensicX.ps1 (it offers to restart as administrator), then use the menu: Investigate, Explore, Hunt & analyze, Cases.'
        Commands = @(
            [pscustomobject]@{ Name = 'Invoke-WfxTriage'; Summary = 'Collects, analyzes, scores and writes the case report. The main command.'
                Params = @('[-FileScan] [-ExposureScan] [-OutputPath <external media>] [-AllowlistPath <json>] [-SigmaPath <rules>] [-YaraRules <rules>]', '-Plan  (list what it would read, then stop: reads nothing)', '-ComputerName <hosts> [-Credential <cred>]  (remote, WinRM)', '-ArtifactPath <folder>  (collected evidence: hives, Amcache, Jump Lists, .lnk, browsers, SRUM, $MFT, .evtx)', '-EvtxPath <path>  (offline event logs only; nothing collected locally)', '-InputPath <case>  (re-analyze saved evidence)')
                Examples = @('Invoke-WfxTriage', 'Invoke-WfxTriage -FileScan -Plan', 'Invoke-WfxTriage -FileScan -ExposureScan', 'Invoke-WfxTriage -ArtifactPath D:\kape\C -CaseName ctf-01', 'Invoke-WfxTriage -SigmaPath D:\sigma\rules\windows -YaraRules D:\yara', 'Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)', 'Invoke-WfxTriage -EvtxPath D:\evidence\Security.evtx', 'Invoke-WfxTriage -InputPath C:\cases\WFX_host_20260101-000000Z') }
            [pscustomobject]@{ Name = 'Invoke-WfxAnalyze'; Summary = 'Run all analyzers over a collected bundle (object, bundle.json, or case folder). OS-neutral.'
                Params = @('-Bundle <path|object>'); Examples = @('Invoke-WfxAnalyze -Bundle .\WFX_host\raw\bundle.json') }
            [pscustomobject]@{ Name = 'Start-WfxMonitor'; Summary = 'Live baseline, then alert on new suspicious processes / connections / beacons.'
                Params = @('[-Interval <sec>] [-Duration <sec>] [-MinSeverity <sev>]'); Examples = @('Start-WfxMonitor -Interval 5 -Duration 300') }
            [pscustomobject]@{ Name = 'Invoke-WfxHunt'; Summary = 'Sweep a host, saved case or evidence folder for IOCs (MD5/SHA-1/SHA-256, exact IPs, domains+subdomains, strings): event logs, artifacts (Amcache SHA-1 finds deleted programs), downloads.'
                Params = @('-Ioc <list> | -IocFile <txt|csv|stix|misp> [-InputPath <case> | -ArtifactPath <folder>] [-FileScan] [-HashProcesses]'); Examples = @("Invoke-WfxHunt -Ioc 'evil.example','203.0.113.7' -FileScan", 'Invoke-WfxHunt -IocFile .\iocs.txt -InputPath .\WFX_host_case', 'Invoke-WfxHunt -IocFile .\iocs.txt -ArtifactPath D:\kape\C') }
            [pscustomobject]@{ Name = 'Get-WfxArtifact'; Summary = 'Parse execution and user-activity artifacts, live or from collected files: Amcache, ShimCache, Prefetch, BAM, UserAssist, PCA, ShellBags, Jump Lists, .lnk, RunMRU, typed paths, searches, browser downloads, Defender logs, SRUM, $MFT (collected). -Flag adds the triage verdict.'
                Params = @('[-Path <folder|file>] [-Artifact <types>] [-Flag]'); Examples = @('Get-WfxArtifact -Path D:\kape\C -Flag | Where-Object Flag', 'Get-WfxArtifact -Path .\Amcache.hve | Where-Object Sha1 -eq <sha1>', "Get-WfxArtifact -Artifact JumpList,Shortcut | Where-Object { `$_.Extra.DriveType -eq 'Removable' }") }
            [pscustomobject]@{ Name = 'Get-WfxActivity'; Summary = 'What changed recently: registry writes in persistence/security keys, software & driver installs, services, tasks, accounts, firewall/Defender/audit changes, executions (Prefetch/BAM/UserAssist), connection history, deletions; -Journal adds the NTFS change journal.'
                Params = @('[-Days <n>] [-Journal]'); Examples = @('Get-WfxActivity -Days 2', "Get-WfxActivity -Days 1 -Journal | Where-Object Category -eq 'File'") }
            [pscustomobject]@{ Name = 'New-WfxFileBaseline / Compare-WfxFileBaseline'; Summary = 'File-integrity baseline: hash folders now, later list added, deleted, content-changed and timestamp-only files.'
                Params = @('-Path <folders> [-OutputPath <json>]', '-Baseline <json>'); Examples = @('New-WfxFileBaseline -Path C:\inetpub\wwwroot -OutputPath E:\bl\web.json', 'Compare-WfxFileBaseline -Baseline E:\bl\web.json') }
            [pscustomobject]@{ Name = 'Get-WfxInsight'; Summary = '60 live read-only views, each suspicious row flagged with severity, reason and ATT&CK technique: system, updates, software, users, groups, sessions, USB, processes, process tree, ports, connections, DNS, routes, proxy, Wi-Fi, firewall, autostarts, services, tasks, WMI, logons, failed logons, RDP, account changes, Defender, downloads, Prefetch, recent files, PS history, posture, memory-capture readiness.'
                Params = @('-List', '<topic> [-Days <n>]'); Examples = @('Get-WfxInsight -List', 'Get-WfxInsight logons -Days 3 | Format-Table', "Get-WfxInsight listeners | Where-Object Exposure -eq 'all interfaces'") }
            [pscustomobject]@{ Name = 'Save-WfxInsight'; Summary = 'Export every live view to a hashed inventory case: inventory.html + one CSV per view.'
                Params = @('[-Topic <list>] [-OutputPath <folder>]'); Examples = @('Save-WfxInsight -OutputPath E:\cases') }
            [pscustomobject]@{ Name = 'Test-WfxCase'; Summary = 'Verify a case against its manifest: changed, missing or added files.'
                Params = @('-Path <case> [-ExpectedManifestSha256 <hash>]'); Examples = @('Test-WfxCase -Path E:\cases\WFX_PC01_20261103-101500Z') }
            [pscustomobject]@{ Name = 'Test-WfxIntegrity'; Summary = 'Self-check: compare this copy of WinForensicX with SHA256SUMS.txt (changed, missing, or extra code files the module would load). Also runs at start.'
                Params = @('[-Root <release folder>]'); Examples = @('Test-WfxIntegrity') }
            [pscustomobject]@{ Name = 'Find-WfxFile'; Summary = 'Fast file and folder search across all drives: name wildcards or regex, extensions, no extension, size, dates, hidden. As administrator it lists NTFS drives straight from the master file table (seconds). Optional SHA-256, real type and signature. Read-only.'
                Params = @('[-Name <patterns>] [-Extension <list> | -NoExtension] [-Path <folders>] [-ItemType File|Folder|Any] [-MinSize <n>] [-MaxSize <n>] [-ModifiedAfter <date>] [-Hidden] [-Hash] [-CheckType] [-Signature]')
                Examples = @('Find-WfxFile -Extension ps1,hta,js,vbs -ModifiedAfter (Get-Date).AddDays(-7)', "Find-WfxFile -Name '*invoice*' -ItemType Any", 'Find-WfxFile -NoExtension -Path C:\Users -CheckType | Where-Object TrueType') }
            [pscustomobject]@{ Name = 'Get-WfxFileTriage'; Summary = 'What is this file? Hashes, true type vs extension, entropy, MOTW download URL, ADS, signature, PE facts, strings + IOCs. Never executes.'
                Params = @('-Path <files> [-Strings] [-MaxReadMB <n>]'); Examples = @('Get-WfxFileTriage .\sample.bin -Strings | Format-List', 'Get-ChildItem .\Downloads -File | Get-WfxFileTriage | Where-Object ExtensionMismatch') }
            [pscustomobject]@{ Name = 'ConvertFrom-WfxEncodedCommand'; Summary = 'Decode -EncodedCommand / Base64 / gzip / nested FromBase64String payloads (decode only).'
                Params = @('<command line or base64>'); Examples = @("ConvertFrom-WfxEncodedCommand 'powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA=='") }
            [pscustomobject]@{ Name = 'Export-WfxTimeline'; Summary = 'UTC super-timeline of a case (processes, connections, events, files, findings) to CSV/JSON.'
                Params = @('-InputPath <case> [-Format Csv|Json] [-From <utc>] [-To <utc>]'); Examples = @('Export-WfxTimeline -InputPath .\WFX_host_case') }
            [pscustomobject]@{ Name = 'Compare-WfxCase'; Summary = 'Diff two cases: new processes, autostarts, services, listeners, DNS, exposure, findings.'
                Params = @('-Baseline <case> -Current <case> [-OutputPath <csv|json>]'); Examples = @('Compare-WfxCase -Baseline .\golden -Current .\today') }
            [pscustomobject]@{ Name = 'Export-WfxCase'; Summary = 'Export a case for other tools: Timesketch CSV, ECS JSON lines (Elastic, Splunk, Sentinel), STIX 2.1 (MISP, OpenCTI), indicator CSV. Written next to the case.'
                Params = @('-InputPath <case> [-Format Timesketch|Ecs|Stix|Indicators|All] [-OutputPath <folder>]'); Examples = @('Export-WfxCase -InputPath .\WFX_host_case', 'Export-WfxCase -InputPath .\case -Format Stix') }
            [pscustomobject]@{ Name = 'New-WfxFleetReport'; Summary = 'One page for many hosts: risk per host, patient zero and spread, indicators and findings shared between hosts, ATT&CK stages per host.'
                Params = @('-Path <folder of cases> [-OutputPath <html>]'); Examples = @('New-WfxFleetReport -Path E:\ir-cases') }
            [pscustomobject]@{ Name = 'Save-WfxEvidence'; Summary = 'Collect a hashed, read-only evidence bundle now; analyze later with -InputPath.'
                Params = @('[-FileScan] [-ExposureScan]'); Examples = @('Save-WfxEvidence -FileScan -ExposureScan') }
            [pscustomobject]@{ Name = 'Show-WfxMenu'; Summary = 'Interactive menu over everything above.'
                Params = @(); Examples = @('Show-WfxMenu') }
            [pscustomobject]@{ Name = 'Show-WfxHelp'; Summary = 'This help. Add -Html to open the full guide in a browser.'
                Params = @('[-Html]'); Examples = @('Show-WfxHelp', 'Show-WfxHelp -Html') }
        )
        Outputs  = @(
            'report.html   - self-contained triage report (open in any browser, offline)',
            'result.json   - findings + risk + ATT&CK coverage + gaps (machine-readable)',
            'findings.csv  - flat triage view for a spreadsheet / SIEM import',
            'raw/bundle.json - the normalized collected data (re-analyzable with -InputPath)',
            'audit.log     - every step the tool took, with timings (JSON lines)',
            'manifest.json - SHA-256 of every output + tool/rule hashes + parameters, written last; the case is then closed',
            'hunt.json / hunt.csv - IOC hits (Invoke-WfxHunt)',
            '<case>-timesketch.csv / -ecs.ndjson / -stix.json / -indicators.csv - Export-WfxCase, written next to the case'
        )
        Safety   = @(
            'Read-only: it changes no settings and executes nothing it finds. It sends no network traffic of its own (remote mode uses WinRM you initiate; -ExposureScan reads the domain SYSVOL share).',
            'It never elevates without asking: at start it offers to restart as administrator through the normal Windows prompt (-Elevate asks no question first, -NoElevate never asks). The new window runs without your PowerShell profile and with the execution policy you already have.',
            'Its only writes are its own case folder (default Desktop\WinForensicX) — use -OutputPath on external media for evidence work. Reading files can update NTFS last-access times.',
            'PowerShell 7 itself (not WinForensicX) sends anonymous start-up telemetry to Microsoft unless POWERSHELL_TELEMETRY_OPTOUT=1 is set; set it for evidence work, or use Windows PowerShell 5.1, which does not.',
            'Credential exposure is AUDITED, never extracted: it reports THAT a secret is exposed with the value redacted to type + length.',
            'No LSASS dumping, no SAM/NTDS hash parsing, no DPAPI/browser decryption, no exfiltration.',
            'Command lines, event messages and file contents are secret-scrubbed at collection time, so the raw bundle is safe to keep and ship.'
        )
        Limits   = @(
            'Findings are LEADS for an analyst, not verdicts. A finding means "look here," not "this host is compromised."',
            'Read findings alongside the collection gaps: with no process auditing and no Sysmon, "nothing found" mostly means "nothing could be seen" - the report says so.',
            'It is a TRIAGE tool, not a forensic imager. It does not acquire disk/memory images or carve deleted files.',
            'Detections are heuristic: expect some false positives and false negatives. Tune with custom rule packs ($env:WFX_RULES) and an allowlist (-AllowlistPath / $env:WFX_ALLOWLIST).',
            'Two scores: Compromise risk (evidence of attacker activity) and Posture (hardening/visibility gaps). A clean but un-hardened host scores low risk, high posture.',
            'Only loaded user registry hives (logged-on users) are inspected; event collection is capped per query and caps are reported as gaps.',
            'Administrator rights are recommended; without them some data is unavailable (recorded as gaps). Remote mode needs WinRM enabled on the target.',
            'It will not extract, decrypt, or dump secrets - that is a deliberate boundary, not a missing feature.',
            'The manifest is not signed: record its SHA-256 (printed at the end of each run) out-of-band to make the case tamper-evident.',
            'Artifacts: Amcache.hve is locked on a running system (collect it with a raw-copy tool and use -ArtifactPath); dirty hives are repaired from .LOG1/.LOG2 only when the logs continue the hive; SRUDB.dat is usually locked live (collect it); $MFT is read from collected files only, and deleted SRUM records are skipped.',
            'Sigma: rules run only on the event logs and IDs the tool collects (rules can add Security/System IDs they need); aggregations and correlation rules are skipped and counted as a gap. YARA needs a yara executable you provide.'
        )
        Requires = 'Windows PowerShell 5.1 or PowerShell 7+. No external modules. Live collection needs Windows; analysis, re-analysis, hunting in saved cases, timelines, diffs and file triage also run on Linux/macOS (PowerShell 7).'
    }
}
