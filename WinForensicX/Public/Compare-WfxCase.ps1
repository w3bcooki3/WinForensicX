function Compare-WfxCase {
    <#
    .SYNOPSIS
        Diffs two collections of the same (or a reference) host — "what changed since the baseline?".
        Reports added / removed processes (by image), autostarts, services & drivers, listening ports,
        DNS names, exposure items and (when both cases have result.json) findings.
    .DESCRIPTION
        Typical uses: a known-good "golden" baseline vs. a suspect host; before vs. after a malware sample
        runs in a lab VM / CTF challenge; this week's collection vs. last week's.
    .PARAMETER Baseline  Case folder or bundle.json of the reference state.
    .PARAMETER Current   Case folder or bundle.json of the state to check.
    .PARAMETER OutputPath Optional .csv or .json file to write the differences to.
    .EXAMPLE
        Compare-WfxCase -Baseline .\WFX_pc01_baseline -Current .\WFX_pc01_today | Where-Object Change -eq 'Added'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Baseline, [Parameter(Mandatory)][string]$Current, [string]$OutputPath = '')
    $load = {
        param($p)
        $bp = Resolve-WfxBundlePath -Path $p
        $b = Get-Content -LiteralPath $bp -Raw -Encoding UTF8 | ConvertFrom-Json
        $rp = Join-Path (Split-Path -Parent (Split-Path -Parent $bp)) 'result.json'
        $r = if (Test-Path -LiteralPath $rp) { Get-Content -LiteralPath $rp -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
        [pscustomobject]@{ Bundle = $b; Result = $r }
    }
    $A = & $load $Baseline
    $B = & $load $Current
    $sections = [ordered]@{
        Process     = { param($x) @(Get-WfxValue $x.Bundle 'Process' @()) | ForEach-Object { $k = ("{0}|{1}" -f $_.Name, $_.Path).ToLowerInvariant(); [pscustomobject]@{ K = $k; D = "$($_.Name)  $($_.Path)" } } }
        Autostart   = { param($x) @(Get-WfxValue $x.Bundle 'Persistence' @()) | Where-Object { $_.Kind -notin 'Service', 'Driver' } | ForEach-Object { [pscustomobject]@{ K = ("{0}|{1}|{2}" -f $_.Kind, $_.Name, $_.Command).ToLowerInvariant(); D = "$($_.Kind): $($_.Name) → $($_.Command)" } } }
        Service     = { param($x) @(Get-WfxValue $x.Bundle 'Persistence' @()) | Where-Object { $_.Kind -in 'Service', 'Driver' } | ForEach-Object { [pscustomobject]@{ K = ("{0}|{1}|{2}" -f $_.Kind, $_.Name, $_.Path).ToLowerInvariant(); D = "$($_.Kind): $($_.Name) [$($_.Location)] $($_.Path) sig=$($_.SignatureStatus)" } } }
        Listener    = { param($x) @(Get-WfxValue $x.Bundle 'Network' @()) | Where-Object { $_.State -match '^(?:Listen|Bound)$' } | ForEach-Object { [pscustomobject]@{ K = ("{0}|{1}|{2}|{3}" -f $_.Protocol, $_.LocalAddress, $_.LocalPort, $_.Process).ToLowerInvariant(); D = "$($_.Protocol) $($_.LocalAddress):$($_.LocalPort) ($($_.Process))" } } }
        Dns         = { param($x) @(Get-WfxValue $x.Bundle 'Dns' @()) | ForEach-Object { [pscustomobject]@{ K = ([string]$_.Name).ToLowerInvariant(); D = "$($_.Name)" } } }
        Exposure    = { param($x) @(Get-WfxValue $x.Bundle 'Exposure' @()) | ForEach-Object { [pscustomobject]@{ K = ("{0}|{1}" -f $_.Kind, $_.Path).ToLowerInvariant(); D = "$($_.Kind): $($_.Path) $($_.Detail)" } } }
        Finding     = { param($x) if ($x.Result) { @($x.Result.Findings) | ForEach-Object { [pscustomobject]@{ K = ("{0}|{1}" -f $_.Id, $_.Entity).ToLowerInvariant(); D = "[$($_.Severity)] $($_.Title)" } } } }
    }
    $diff = New-Object System.Collections.Generic.List[object]
    foreach ($name in $sections.Keys) {
        $ia = @{}; foreach ($r in @(& $sections[$name] $A)) { if ($r) { $ia[$r.K] = $r.D } }
        $ib = @{}; foreach ($r in @(& $sections[$name] $B)) { if ($r) { $ib[$r.K] = $r.D } }
        foreach ($k in $ib.Keys) { if (-not $ia.ContainsKey($k)) { $diff.Add([pscustomobject]@{ Section = $name; Change = 'Added'; Detail = $ib[$k] }) } }
        foreach ($k in $ia.Keys) { if (-not $ib.ContainsKey($k)) { $diff.Add([pscustomobject]@{ Section = $name; Change = 'Removed'; Detail = $ia[$k] }) } }
    }
    $out = @($diff | Sort-Object Section, Change, Detail)
    Write-WfxSection 'Case comparison'
    Write-WfxConsole ("Baseline: {0} ({1})   Current: {2} ({3})" -f (Get-WfxValue $A.Bundle 'HostName' '?'), (Get-WfxValue $A.Bundle 'Collected' '?'), (Get-WfxValue $B.Bundle 'HostName' '?'), (Get-WfxValue $B.Bundle 'Collected' '?')) -Kind Dim
    foreach ($g in ($out | Group-Object Section)) {
        $add = @($g.Group | Where-Object Change -eq 'Added').Count; $rem = @($g.Group | Where-Object Change -eq 'Removed').Count
        Write-WfxConsole ("  {0,-10} +{1}  -{2}" -f $g.Name, $add, $rem) -Kind $(if ($add) { 'Warn' } else { 'Plain' })
    }
    if (-not $out.Count) { Write-WfxConsole '  No differences.' -Kind Ok }
    if ($OutputPath) {
        if ($OutputPath -match '\.json$') { Save-WfxJson -InputObject $out -Path $OutputPath -Depth 4 } else { $out | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
        Write-WfxConsole "Differences written to $OutputPath" -Kind Info
    }
    $out
}
