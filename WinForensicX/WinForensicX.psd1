@{
    RootModule        = 'WinForensicX.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'b5e4f1c2-8a3d-4e7f-9c21-6d0a2f3b4c5e'
    Author            = 'WinForensicX contributors'
    CompanyName       = 'WinForensicX'
    Copyright         = '(c) WinForensicX contributors. MIT License.'
    Description       = 'A read-only DFIR / incident-triage toolkit for Windows: collects host, process, network, DNS, persistence, event-log, file and security-posture data; maps findings to MITRE ATT&CK; scores host risk; and produces a self-contained HTML report with full chain of custody. Credential exposure is audited and redacted, never extracted.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Invoke-WfxTriage', 'Invoke-WfxAnalyze', 'Start-WfxMonitor', 'Invoke-WfxHunt', 'Save-WfxEvidence', 'Show-WfxMenu', 'Show-WfxHelp')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('DFIR', 'IncidentResponse', 'Security', 'Forensics', 'Triage', 'MITRE', 'ATTACK', 'BlueTeam', 'Windows')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ReleaseNotes = 'v2.0.0 — rebuilt engine: data-driven ATT&CK rule packs, normalized collector/analyzer split, composable risk scoring, AI-era threat coverage, secrets-exposure audit (redacted), remote/offline/re-analyze modes, self-contained HTML report.'
        }
    }
}
