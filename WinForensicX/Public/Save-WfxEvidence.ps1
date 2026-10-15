function Save-WfxEvidence {
    <#
    .SYNOPSIS
        Collects a full read-only evidence bundle and writes it to a chain-of-custody case folder WITHOUT
        running analysis — for when the priority is to preserve state quickly and analyze later (possibly
        on another machine with Invoke-WfxTriage -InputPath). Every output is hashed in manifest.json.
    .PARAMETER OutputPath   Case folder location (default: Desktop\WinForensicX).
    .PARAMETER CaseName     Optional case label.
    .PARAMETER Hours        Event look-back window (default 72).
    .PARAMETER FileScan     Include the web-root / drop-folder file scan.
    .PARAMETER ExposureScan Include the config-file secret scan (redacted).
    .PARAMETER Quiet        Suppress console output.
    .OUTPUTS The case folder path.
    .EXAMPLE
        Save-WfxEvidence -FileScan -ExposureScan -CaseName acme-ir
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = '',
        [string]$CaseName = '',
        [int]$Hours = 72,
        [switch]$FileScan,
        [switch]$ExposureScan,
        [switch]$Quiet
    )
    if (-not (Test-WfxWindows)) { Write-WfxConsole 'Evidence collection requires Windows.' -Kind Bad; return }
    $script:WfxQuiet = [bool]$Quiet
    Write-WfxBanner
    $hn = [Environment]::MachineName
    $case = New-WfxCase -OutputPath $OutputPath -Name ($(if ($CaseName) { $CaseName } else { 'evidence' })) -HostName $hn
    if (-not $case.Admin) { Write-WfxConsole 'Running without administrator rights — some data will be limited (recorded as gaps).' -Kind Warn }
    Write-WfxSection 'Collecting evidence'
    $bundle = Get-WfxCollectionBundle -Hours $Hours -FileScan:$FileScan -ExposureScan:$ExposureScan
    $raw = Join-Path $case.Path 'raw'
    Save-WfxJson -InputObject $bundle -Path (Join-Path $raw 'bundle.json') -Depth 12
    # A human-readable host summary alongside the machine-readable bundle.
    $h = $bundle.Host
    $txt = @(
        "WinForensicX evidence — $hn",
        "Collected (UTC): $($bundle.Collected)",
        "OS: $(Get-WfxValue $h 'Os' '')",
        "Operator: $(Get-WfxValue $h 'Operator' '')  Admin: $(Get-WfxValue $h 'Admin' '')",
        "Processes: $(@($bundle.Process).Count)  Connections: $(@($bundle.Network).Count)  Autostarts: $(@($bundle.Persistence).Count)  Events: $(@($bundle.Events).Count)",
        "Collection gaps: $(@($bundle.Gaps).Count)"
    ) -join "`r`n"
    [IO.File]::WriteAllText((Join-Path $raw 'host-summary.txt'), $txt, (New-Object Text.UTF8Encoding($false)))
    Complete-WfxCase
    Write-WfxSection 'Done'
    Write-WfxConsole ("Evidence bundle written and hashed: {0}" -f $case.Path) -Kind Info
    Write-WfxConsole ("Re-analyze later with:  Invoke-WfxTriage -InputPath '{0}'" -f $case.Path) -Kind Dim
    return $case.Path
}
