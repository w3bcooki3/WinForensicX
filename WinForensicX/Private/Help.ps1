# Single source of truth for user-facing help: commands, examples, limitations, safety.
# Rendered to the terminal by Show-WfxHelp and to HTML by New-WfxGuide, so the two never drift.

function Get-WfxHelpModel {
    [pscustomobject]@{
        Version  = $script:WfxVersion
        Tagline  = 'Read-only DFIR / incident-triage for Windows. Collect a host, analyze it against ATT&CK-mapped rules, score the risk, and get a report you can act on.'
        Commands = @(
            [pscustomobject]@{ Name = 'Invoke-WfxTriage'; Summary = 'Collect -> analyze -> score -> report. The main command.'
                Params = @('[-FileScan] [-ExposureScan]', '-ComputerName <hosts> [-Credential <cred>]  (remote, WinRM)', '-EvtxPath <path>  (offline event logs)', '-InputPath <case>  (re-analyze saved evidence)')
                Examples = @('Invoke-WfxTriage', 'Invoke-WfxTriage -FileScan -ExposureScan', 'Invoke-WfxTriage -ComputerName srv01,srv02 -Credential (Get-Credential)', 'Invoke-WfxTriage -EvtxPath D:\evidence\Security.evtx', 'Invoke-WfxTriage -InputPath C:\cases\WFX_host_20260101-000000Z') }
            [pscustomobject]@{ Name = 'Invoke-WfxAnalyze'; Summary = 'Run all analyzers over a collected bundle (object, bundle.json, or case folder). OS-neutral.'
                Params = @('-Bundle <path|object>'); Examples = @('Invoke-WfxAnalyze -Bundle .\WFX_host\raw\bundle.json') }
            [pscustomobject]@{ Name = 'Start-WfxMonitor'; Summary = 'Live baseline, then alert on new suspicious processes / connections / beacons.'
                Params = @('[-Interval <sec>] [-Duration <sec>] [-MinSeverity <sev>]'); Examples = @('Start-WfxMonitor -Interval 5 -Duration 300') }
            [pscustomobject]@{ Name = 'Invoke-WfxHunt'; Summary = 'Sweep a host (or a saved bundle) for IOCs: hashes, IPs, domains, names, strings.'
                Params = @('-Ioc <list> [-InputPath <case>] [-FileScan]'); Examples = @("Invoke-WfxHunt -Ioc 'evil.com','1.2.3.4','5d41402abc4b2a76b9719d911017c592'") }
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
            'manifest.json - SHA-256 of every output file, written last (chain of custody)'
        )
        Safety   = @(
            'Strictly read-only: it observes, it does not change the host.',
            'Credential exposure is AUDITED, never extracted: it reports THAT a secret is exposed with the value redacted to type + length.',
            'No LSASS dumping, no SAM/NTDS hash parsing, no DPAPI/browser decryption, no exfiltration.',
            'Command lines, event messages and file contents are secret-scrubbed at collection time, so the raw bundle is safe to keep and ship.'
        )
        Limits   = @(
            'Findings are LEADS for an analyst, not verdicts. A finding means "look here," not "this host is compromised."',
            'Read findings alongside the collection gaps: with no process auditing and no Sysmon, "nothing found" mostly means "nothing could be seen" - the report says so.',
            'It is a TRIAGE tool, not a forensic imager. It does not acquire disk/memory images or carve deleted files.',
            'Detections are heuristic: expect some false positives and false negatives. Tune with custom rule packs ($env:WFX_RULES) and allowlist by finding Id + Entity.',
            'Administrator rights are recommended; without them some data is unavailable (recorded as gaps). Remote mode needs WinRM enabled on the target.',
            'It will not extract, decrypt, or dump secrets - that is a deliberate boundary, not a missing feature.'
        )
        Requires = 'Windows PowerShell 5.1 or PowerShell 7+. No external modules. Works on a standalone PC, a small business, or across a fleet.'
    }
}
