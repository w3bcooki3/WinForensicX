function Invoke-WfxHunt {
    <#
    .SYNOPSIS
        Sweeps a host (or a saved bundle) for specific indicators of compromise — file hashes, IP
        addresses, domains, file names or arbitrary strings — and reports every place each one appears.
        Use it to check a fleet for a known-bad IOC from an advisory or a previous case.
    .PARAMETER Ioc          One or more indicators (SHA-256 hash, IP, domain, file name, or any substring).
    .PARAMETER InputPath    Hunt inside a previously saved case/bundle instead of collecting live.
    .PARAMETER Hours        Event look-back when collecting live (default 72).
    .PARAMETER FileScan     Include the file scan when collecting live (lets hash/name IOCs match files).
    .PARAMETER PassThru     Return the match findings.
    .EXAMPLE
        Invoke-WfxHunt -Ioc 'evil.com','5d41402abc4b2a76b9719d911017c592','1.2.3.4'
    .EXAMPLE
        Invoke-WfxHunt -Ioc 'maldoc.doc' -InputPath C:\cases\WFX_host_20260101-000000Z
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Ioc,
        [string]$InputPath = '',
        [int]$Hours = 72,
        [switch]$FileScan,
        [switch]$PassThru
    )
    $iocs = @($Ioc | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    if (-not $iocs.Count) { Write-WfxConsole 'No IOCs supplied.' -Kind Warn; return }

    if ($InputPath) {
        $bundle = if ((Test-Path -LiteralPath $InputPath -PathType Container)) { (Invoke-WfxGetBundle $InputPath) } else { Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json }
    } else {
        if (-not (Test-WfxWindows)) { Write-WfxConsole 'Live hunt requires Windows (or pass -InputPath).' -Kind Bad; return }
        $bundle = Get-WfxCollectionBundle -Hours $Hours -FileScan:$FileScan
    }
    $hn = [string](Get-WfxValue $bundle 'HostName' ([Environment]::MachineName))

    # Build a flat, searchable index of (where, text, context) rows from the bundle.
    $rows = New-Object System.Collections.Generic.List[object]
    $push = { param($Where, $Text, $Ctx) if ($Text) { $rows.Add([pscustomobject]@{ Where = $Where; Text = [string]$Text; Ctx = $Ctx }) } }
    foreach ($p in @(Get-WfxValue $bundle 'Process' @())) {
        & $push 'process' $p.Name "pid $($p.Pid)"; & $push 'process' $p.Path "pid $($p.Pid)"; & $push 'process' $p.CommandLine "pid $($p.Pid)"
    }
    foreach ($c in @(Get-WfxValue $bundle 'Network' @())) {
        & $push 'network' $c.RemoteAddress "$($c.Process) → $($c.RemoteAddress):$($c.RemotePort)"; & $push 'network' $c.RemoteHost "$($c.Process)"
    }
    foreach ($d in @(Get-WfxValue $bundle 'Dns' @())) { & $push 'dns' $d.Name 'dns cache' }
    foreach ($a in @(Get-WfxValue $bundle 'Persistence' @())) { & $push 'persistence' $a.Command "$($a.Kind): $($a.Name)"; & $push 'persistence' $a.Path "$($a.Kind): $($a.Name)" }
    foreach ($f in @(Get-WfxValue $bundle 'Files' @())) { & $push 'file' $f.Path 'file'; & $push 'file' (Get-WfxValue $f 'SHA256' '') "sha256 of $(Get-WfxLeaf $f.Path)" }

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($i in $iocs) {
        $isHash = $i -match '^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$'
        foreach ($row in $rows) {
            $match = if ($isHash) { $row.Text -eq $i } else { $row.Text -and $row.Text.IndexOf($i, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
            if ($match) {
                $findings.Add((New-WfxFinding -Id 'HUNT-IOC-MATCH' -Title "IOC '$i' found in $($row.Where): $($row.Ctx)" `
                            -Severity 'High' -Confidence 'High' -Category 'Hunt' -Technique @() `
                            -Description "The indicator '$i' was located in $($row.Where) data on this host. This is a direct IOC hit and should be triaged immediately." `
                            -Recommendation "Correlate with the surrounding activity (process tree, connections, timing) and contain the host if confirmed malicious." `
                            -Entity "hunt:$i`:$($row.Where):$($row.Ctx)" -HostName $hn -Source 'hunt' `
                            -Evidence ([ordered]@{ Ioc = $i; Where = $row.Where; Context = $row.Ctx; Value = (Protect-WfxText $row.Text) })))
            }
        }
    }
    $merged = Merge-WfxFinding -Finding $findings.ToArray()
    Write-WfxSection 'Hunt'
    if (@($merged).Count -eq 0) { Write-WfxConsole ("No matches for {0} IOC(s) on {1}." -f $iocs.Count, $hn) -Kind Ok }
    else {
        Write-WfxConsole ("{0} IOC hit(s) on {1}:" -f @($merged).Count, $hn) -Kind Bad
        foreach ($f in $merged) { Write-WfxConsole "  $($f.Title)" -Kind Bad }
    }
    if ($PassThru) { return $merged }
}

function Invoke-WfxGetBundle {
    <# Loads a bundle.json from a case folder or path (shared by hunt / analyze). #>
    param([string]$PathOrDir)
    $p = $PathOrDir
    if (Test-Path -LiteralPath $p -PathType Container) {
        $cand = @((Join-Path $p 'bundle.json'), (Join-Path (Join-Path $p 'raw') 'bundle.json'))
        $p = @($cand | Where-Object { Test-Path -LiteralPath $_ }) | Select-Object -First 1
        if (-not $p) { throw "No bundle.json found under '$PathOrDir'." }
    }
    Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
}
