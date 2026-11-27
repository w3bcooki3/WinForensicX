# WinForensicX module loader. Dot-sources the layers in dependency order and exports the public commands.
# Layer order matters: Private (core/helpers/rules) → Analyzers → Collectors → Report → Public (orchestration).
# $ErrorActionPreference = 'Stop' is deliberate: every collector step runs inside Invoke-WfxStep, which turns
# errors into recorded collection gaps — so nothing fails silently and nothing aborts the triage.
$ErrorActionPreference = 'Stop'
$script:WfxModuleRoot = $PSScriptRoot

foreach ($layer in 'Private', 'Analyzers', 'Collectors', 'Report', 'Public') {
    $dir = Join-Path $PSScriptRoot $layer
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $dir -Filter *.ps1 | Sort-Object Name) {
        . $file.FullName
    }
}

$script:WfxPublic = @('Invoke-WfxTriage', 'Invoke-WfxAnalyze', 'Start-WfxMonitor', 'Invoke-WfxHunt', 'Save-WfxEvidence', 'Show-WfxMenu', 'Show-WfxHelp', 'Get-WfxFileTriage', 'ConvertFrom-WfxEncodedCommand', 'Get-WfxTimeline', 'Export-WfxTimeline', 'Compare-WfxCase', 'Get-WfxInsight', 'Save-WfxInsight', 'Test-WfxCase', 'Test-WfxIntegrity', 'Find-WfxFile', 'Get-WfxActivity', 'New-WfxFileBaseline', 'Compare-WfxFileBaseline', 'Get-WfxArtifact', 'Export-WfxCase', 'New-WfxFleetReport')
Export-ModuleMember -Function $script:WfxPublic
