@{
    RootModule        = 'WinForensicX.psm1'
    ModuleVersion     = '2.6.0'
    GUID              = 'b5e4f1c2-8a3d-4e7f-9c21-6d0a2f3b4c5e'
    Author            = 'WinForensicX contributors'
    CompanyName       = 'WinForensicX'
    Copyright         = '(c) WinForensicX contributors. MIT License.'
    Description       = 'A read-only DFIR / incident-triage toolkit for Windows: collects host, process, network, DNS, persistence, event-log, file and security-posture data; maps findings to MITRE ATT&CK; scores host risk; and produces a self-contained HTML report with full chain of custody. Credential exposure is audited and redacted, never extracted.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Invoke-WfxTriage', 'Invoke-WfxAnalyze', 'Start-WfxMonitor', 'Invoke-WfxHunt', 'Save-WfxEvidence', 'Show-WfxMenu', 'Show-WfxHelp', 'Get-WfxFileTriage', 'ConvertFrom-WfxEncodedCommand', 'Get-WfxTimeline', 'Export-WfxTimeline', 'Compare-WfxCase', 'Get-WfxInsight', 'Save-WfxInsight', 'Test-WfxCase', 'Get-WfxActivity', 'New-WfxFileBaseline', 'Compare-WfxFileBaseline')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('DFIR', 'IncidentResponse', 'Security', 'Forensics', 'Triage', 'MITRE', 'ATTACK', 'BlueTeam', 'Windows', 'CTF', 'ThreatHunting', 'Timeline')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ReleaseNotes = 'v2.6.0 - redesigned case report: verdict and do-first list, attack path, indicators with defang/CSV, related events per finding, day-grouped timeline, ATT&CK Navigator layer, strict CSP. v2.5.0 - automated attack-scenario suite (clean to APT, evasion variants) and the detection fixes it drove. v2.4.0 - suspicious-activity flags in every relevant Explore view and in the inventory report, repaired and new activity detections, usage guide. v2.3.2 - fixes blank rows in Explore views, Recycle Bin and NTFS journal reconstruction, browser table view. v2.3.1 - launcher simplified (no self-elevation, no .cmd), native .lnk parsing. v2.3.0 - recent-activity reconstruction (registry writes, NTFS journal, Recycle Bin, installs, executions, connection history, config-change events) with detections, file-integrity baselines, and a redesigned case report. See CHANGELOG.md.'
        }
    }
}
