# Single source of truth for user-facing help: commands, examples, limitations, safety.
# Rendered to the terminal by Show-WfxHelp and to HTML by New-WfxGuide, so the two never drift.

function Get-WfxHelpModel {
    [pscustomobject]@{
        Version  = $script:WfxVersion
        Tagline  = 'Read-only DFIR / incident-triage for Windows. Collect a host, analyze it against ATT&CK-mapped rules, score the risk, and get a report you can act on.'
        Commands = @(
            [pscustomobject]@{ Name = 'Invoke-WfxTriage'; Summary = 'Collect -> analyze -> score -> report. The main command.'
                Params = @('[-FileScan] [-ExposureScan] [-OutputPath <external media>] [-AllowlistPath <json>]', '-ComputerName <hosts> [-Credential <cred>]  (remote, WinRM)', '-EvtxPath <path>  (offline event logs only; nothing collected locally)', '-InputPath <case>  (re-analyze saved evidence)')
                Examples = @('Invoke-WfxTriage', 'Invoke-WfxTriage -FileScan -ExposureScan', 'Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)', 'Invoke-WfxTriage -EvtxPath D:\evidence\Security.evtx', 'Invoke-WfxTriage -InputPath C:\cases\WFX_host_20260101-000000Z') }
            [pscustomobject]@{ Name = 'Invoke-WfxAnalyze'; Summary = 'Run all analyzers over a collected bundle (object, bundle.json, or case folder). OS-neutral.'
                Params = @('-Bundle <path|object>'); Examples = @('Invoke-WfxAnalyze -Bundle .\WFX_host\raw\bundle.json') }
            [pscustomobject]@{ Name = 'Start-WfxMonitor'; Summary = 'Live baseline, then alert on new suspicious processes / connections / beacons.'
                Params = @('[-Interval <sec>] [-Duration <sec>] [-MinSeverity <sev>]'); Examples = @('Start-WfxMonitor -Interval 5 -Duration 300') }
            [pscustomobject]@{ Name = 'Invoke-WfxHunt'; Summary = 'Sweep a host or saved bundle for IOCs (MD5/SHA-1/SHA-256, exact IPs, domains+subdomains, strings), incl. event logs.'
                Params = @('-Ioc <list> | -IocFile <txt> [-InputPath <case>] [-FileScan] [-HashProcesses]'); Examples = @("Invoke-WfxHunt -Ioc 'evil.example','203.0.113.7' -FileScan", 'Invoke-WfxHunt -IocFile .\iocs.txt -InputPath .\WFX_host_case') }
            [pscustomobject]@{ Name = 'Get-WfxFileTriage'; Summary = 'What is this file? Hashes, true type vs extension, entropy, MOTW download URL, ADS, signature, PE facts, strings + IOCs. Never executes.'
                Params = @('-Path <files> [-Strings] [-MaxReadMB <n>]'); Examples = @('Get-WfxFileTriage .\sample.bin -Strings | Format-List', 'Get-ChildItem .\Downloads -File | Get-WfxFileTriage | Where-Object ExtensionMismatch') }
            [pscustomobject]@{ Name = 'ConvertFrom-WfxEncodedCommand'; Summary = 'Decode -EncodedCommand / Base64 / gzip / nested FromBase64String payloads (decode only).'
                Params = @('<command line or base64>'); Examples = @("ConvertFrom-WfxEncodedCommand 'powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA=='") }
            [pscustomobject]@{ Name = 'Export-WfxTimeline'; Summary = 'UTC super-timeline of a case (processes, connections, events, files, findings) to CSV/JSON.'
                Params = @('-InputPath <case> [-Format Csv|Json] [-From <utc>] [-To <utc>]'); Examples = @('Export-WfxTimeline -InputPath .\WFX_host_case') }
            [pscustomobject]@{ Name = 'Compare-WfxCase'; Summary = 'Diff two cases: new processes, autostarts, services, listeners, DNS, exposure, findings.'
                Params = @('-Baseline <case> -Current <case> [-OutputPath <csv|json>]'); Examples = @('Compare-WfxCase -Baseline .\golden -Current .	oday') }
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
            'hunt.json / hunt.csv - IOC hits (Invoke-WfxHunt)'
        )
        Safety   = @(
            'Read-only: it changes no settings and executes nothing it finds. It sends no network traffic of its own (remote mode uses WinRM you initiate; -ExposureScan reads the domain SYSVOL share).',
            'Its only writes are its own case folder (default Desktop\WinForensicX) — use -OutputPath on external media for evidence work. Reading files can update NTFS last-access times.',
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
            'The manifest is not signed: record its SHA-256 (printed at the end of each run) out-of-band to make the case tamper-evident.'
        )
        Requires = 'Windows PowerShell 5.1 or PowerShell 7+. No external modules. Live collection needs Windows; analysis, re-analysis, hunting in saved cases, timelines, diffs and file triage also run on Linux/macOS (PowerShell 7).'
    }
}
