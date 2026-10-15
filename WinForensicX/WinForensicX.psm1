# WinForensicX module loader. Dot-sources the layers in dependency order and exports the public commands.
# Layer order matters: Private (core/helpers/rules) → Analyzers → Collectors → Public (orchestration).
$ErrorActionPreference = 'Stop'
$script:WfxModuleRoot = $PSScriptRoot

foreach ($layer in 'Private', 'Analyzers', 'Collectors', 'Report', 'Public') {
    $dir = Join-Path $PSScriptRoot $layer
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $dir -Filter *.ps1 | Sort-Object Name) {
        . $file.FullName
    }
}

$script:WfxPublic = @('Invoke-WfxTriage', 'Invoke-WfxAnalyze', 'Start-WfxMonitor', 'Invoke-WfxHunt', 'Save-WfxEvidence', 'Show-WfxMenu', 'Show-WfxHelp')
Export-ModuleMember -Function $script:WfxPublic
