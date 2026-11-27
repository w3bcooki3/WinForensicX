@{
    RootModule        = 'WinForensicX.psm1'
    ModuleVersion     = '3.3.0'
    GUID              = 'b5e4f1c2-8a3d-4e7f-9c21-6d0a2f3b4c5e'
    Author            = 'WinForensicX contributors'
    CompanyName       = 'WinForensicX'
    Copyright         = '(c) WinForensicX contributors. MIT License.'
    Description       = 'A read-only DFIR / incident-triage toolkit for Windows: collects host, process, network, DNS, persistence, event-log, file and security-posture data; maps findings to MITRE ATT&CK; scores host risk; and produces a self-contained HTML report with full chain of custody. Credential exposure is audited and redacted, never extracted.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Invoke-WfxTriage', 'Invoke-WfxAnalyze', 'Start-WfxMonitor', 'Invoke-WfxHunt', 'Save-WfxEvidence', 'Show-WfxMenu', 'Show-WfxHelp', 'Get-WfxFileTriage', 'ConvertFrom-WfxEncodedCommand', 'Get-WfxTimeline', 'Export-WfxTimeline', 'Compare-WfxCase', 'Get-WfxInsight', 'Save-WfxInsight', 'Test-WfxCase', 'Test-WfxIntegrity', 'Find-WfxFile', 'Get-WfxActivity', 'New-WfxFileBaseline', 'Compare-WfxFileBaseline', 'Get-WfxArtifact', 'Export-WfxCase', 'New-WfxFleetReport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('DFIR', 'IncidentResponse', 'Security', 'Forensics', 'Triage', 'MITRE', 'ATTACK', 'BlueTeam', 'Windows', 'CTF', 'ThreatHunting', 'Timeline')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ReleaseNotes = 'v3.3.0 - built-in parsers checked against reference tools: event logs (including damaged files and records recovered from slack), compressed Prefetch, SQLite write-ahead logs, shell items, all registry control sets; 47 new event detections (DCSync, SID history, PsExec-style remote execution, UAC bypasses, process injection, DLL sideloading, persistence keys, named-pipe privilege escalation and more). v3.2.0 - event-log tampering checks (clock set back, a busy log falling silent, Sysmon stopped or reconfigured); process trees rebuilt from Sysmon, 4688 and the process list and shown with each finding; offline $MFT parsing with timestomp detection; SRUM network and disk usage per program with large-upload detection; fleet report shows movement between hosts and programs found on one host only. v3.1.0 - redesigned case report (a case file per finding: what happened, when, how we know, what to do; a chart of when it happened; likely starting point of each incident), Explore views, fleet report and help in one identity; findings corroborated across independent sources raise confidence and show the earliest trace; %SystemRoot% paths no longer flagged as masquerading. v3.0.0 - execution and user-activity artifacts (Amcache, ShimCache, Prefetch, BAM, UserAssist, PCA, ShellBags, Jump Lists, shortcuts, RunMRU, browser downloads, Defender logs) from the live host or collected files, Sigma rules, optional YARA, incident grouping, Timesketch / ECS / STIX 2.1 exports and a fleet report. v2.6.0 - redesigned case report: verdict and do-first list, attack path, indicators with defang/CSV, related events per finding, day-grouped timeline, ATT&CK Navigator layer, strict CSP. v2.5.0 - automated attack-scenario suite (clean to APT, evasion variants) and the detection fixes it drove. v2.4.0 - suspicious-activity flags in every relevant Explore view and in the inventory report, repaired and new activity detections, usage guide. v2.3.2 - fixes blank rows in Explore views, Recycle Bin and NTFS journal reconstruction, browser table view. v2.3.1 - launcher simplified (no self-elevation, no .cmd), native .lnk parsing. v2.3.0 - recent-activity reconstruction (registry writes, NTFS journal, Recycle Bin, installs, executions, connection history, config-change events) with detections, file-integrity baselines, and a redesigned case report. See CHANGELOG.md.'
        }
    }
}
