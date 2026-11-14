function Invoke-WfxHunt {
    <#
    .SYNOPSIS
        Sweeps a host (or a saved bundle) for specific indicators of compromise — file hashes, IP
        addresses, domains, file names or arbitrary strings — and reports every place each one appears.
    .DESCRIPTION
        Matching is type-aware so results are precise:
          • Hashes (MD5/SHA-1/SHA-256) — exact match against file hashes in the bundle. Live hunts with
            -FileScan compute all three for scanned files; -HashProcesses also hashes running/autostart binaries.
          • IPv4/IPv6 — exact address match (1.2.3.4 does NOT match 11.2.3.45).
          • Domains — the name itself or any subdomain (evil.com matches a.evil.com, not notevil.com).
          • Anything else — case-insensitive substring.
        Searched: processes, network, DNS cache, persistence, event logs (message + fields), files, exposure paths,
        recent activity, and execution / user-activity artifacts (Amcache SHA-1, ShimCache, Prefetch, BAM,
        Jump Lists, shortcuts, ShellBags, browser downloads with their URLs, Defender logs).
        Results are written to a hunt case folder (hunt.json / hunt.csv / manifest) unless -NoCase.
    .PARAMETER Ioc          One or more indicators.
    .PARAMETER IocFile      Text file with one indicator per line ('#' comments and blank lines ignored).
    .PARAMETER InputPath    Hunt inside a previously saved case/bundle instead of collecting live.
    .PARAMETER ArtifactPath Hunt inside a folder of collected evidence (hives, Jump Lists, .evtx, ...).
                            Amcache SHA-1 values let hash IOCs match programs that have since been deleted.
    .PARAMETER Hours        Event look-back when collecting live (default 72).
    .PARAMETER FileScan     Include the file scan when collecting live (lets hash/name IOCs match files).
    .PARAMETER HashProcesses Hash the binaries of running processes, services and autostarts (slower).
    .EXAMPLE
        Invoke-WfxHunt -Ioc 'evil.com','1.2.3.4','44d88612fea8a8f36de82e1278abb02f' -FileScan
    .EXAMPLE
        Invoke-WfxHunt -IocFile .\advisory-iocs.txt -InputPath C:\cases\WFX_host_20260101-000000Z
    #>
    [CmdletBinding()]
    param(
        [string[]]$Ioc = @(),
        [string]$IocFile = '',
        [string]$InputPath = '',
        [string]$ArtifactPath = '',
        [ValidateRange(1, 8760)][int]$Hours = 72,
        [switch]$FileScan,
        [switch]$HashProcesses,
        [string]$OutputPath = '',
        [switch]$NoCase,
        [switch]$PassThru
    )
    $list = @($Ioc)
    if ($IocFile) {
        if (-not (Test-Path -LiteralPath $IocFile -PathType Leaf)) { throw "IOC file not found: $IocFile" }
        $list += @(Get-Content -LiteralPath $IocFile | ForEach-Object { ($_ -replace '#.*$', '').Trim() })
    }
    # Accept defanged indicators from advisories: hxxp, [.] and (.)
    $iocs = @($list | Where-Object { $_ } | ForEach-Object { ($_.Trim() -replace '\[\.\]|\(\.\)', '.' -replace '^hxxp', 'http') } | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $iocs.Count) { Write-WfxConsole 'No IOCs supplied.' -Kind Warn; return }

    if ($InputPath) {
        $bundle = Read-WfxBundle -Path $InputPath
    } elseif ($ArtifactPath) {
        $bundle = Get-WfxArtifactBundle -Path $ArtifactPath
        $InputPath = $ArtifactPath            # offline: never hash files on the analysis machine
    } else {
        if (-not (Test-WfxWindows)) { Write-WfxConsole 'Live hunt requires Windows (or pass -InputPath).' -Kind Bad; return }
        $bundle = Get-WfxCollectionBundle -Hours $Hours -FileScan:$FileScan
    }
    $hn = [string](Get-WfxValue $bundle 'HostName' ([Environment]::MachineName))

    # Build a flat, searchable index of (where, text, context) rows from the bundle.
    $rows = New-Object System.Collections.Generic.List[object]
    $push = { param($Where, $Text, $Ctx) if ($Text) { $rows.Add([pscustomobject]@{ Where = $Where; Text = [string]$Text; Ctx = $Ctx }) } }
    $hashCache = @{}
    $hashFile = {
        param($Path, $Ctx)
        if (-not $Path -or -not (Test-WfxWindows) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
        if (-not $hashCache.ContainsKey($Path)) {
            $h = @{}
            foreach ($alg in 'MD5', 'SHA1', 'SHA256') { try { $h[$alg] = (Get-FileHash -LiteralPath $Path -Algorithm $alg -ErrorAction Stop).Hash } catch {} }
            $hashCache[$Path] = $h
        }
        foreach ($v in $hashCache[$Path].Values) { & $push 'hash' $v "$Ctx ($Path)" }
    }
    foreach ($p in @(Get-WfxValue $bundle 'Process' @())) {
        $ctx = "pid $($p.Pid) $($p.Name)"
        & $push 'process' $p.Name $ctx; & $push 'process' $p.Path $ctx; & $push 'process' $p.CommandLine $ctx
        if ($HashProcesses -and -not $InputPath) { & $hashFile $p.Path $ctx }
    }
    foreach ($c in @(Get-WfxValue $bundle 'Network' @())) {
        $ctx = "$($c.Process) $($c.LocalAddress):$($c.LocalPort) → $($c.RemoteAddress):$($c.RemotePort) $($c.State)"
        & $push 'network' $c.RemoteAddress $ctx; & $push 'network' $c.LocalAddress $ctx; & $push 'network' $c.RemoteHost $ctx
    }
    foreach ($d in @(Get-WfxValue $bundle 'Dns' @())) { & $push 'dns' $d.Name "dns cache → $($d.Data)"; & $push 'dns' (Get-WfxValue $d 'Data' '') "dns cache: $($d.Name)" }
    foreach ($a in @(Get-WfxValue $bundle 'Persistence' @())) {
        $ctx = "$($a.Kind): $($a.Name)"
        & $push 'persistence' $a.Command $ctx; & $push 'persistence' $a.Path $ctx
        if ($HashProcesses -and -not $InputPath) { & $hashFile $a.Path $ctx }
    }
    foreach ($e in @(Get-WfxValue $bundle 'Events' @())) {
        $ctx = "event $($e.Id) $($e.Log) @ $($e.TimeCreated)"
        & $push 'event' (Get-WfxValue $e 'Message' '') $ctx
        $fl = Get-WfxValue $e 'Fields' $null
        if ($fl) {
            $pairs = if ($fl -is [System.Collections.IDictionary]) { $fl.GetEnumerator() } else { $fl.PSObject.Properties }
            foreach ($kv in $pairs) { & $push 'event' ([string]$kv.Value) "$ctx [$($kv.Name)]" }
        }
    }
    foreach ($f in @(Get-WfxValue $bundle 'Files' @())) {
        & $push 'file' $f.Path 'file'
        foreach ($hk in 'SHA256', 'SHA1', 'MD5') { & $push 'hash' (Get-WfxValue $f $hk '') "$hk of $($f.Path)" }
        & $push 'file' (Get-WfxValue $f 'HostUrl' '') "download source of $($f.Path)"
        if (-not $InputPath -and (Test-WfxWindows)) { & $hashFile $f.Path 'file' }
    }
    foreach ($a in @(Get-WfxValue $bundle 'Activity' @())) { $ctx = "$($a.Category): $($a.Action) @ $($a.Time)"; & $push 'activity' $a.Target $ctx; & $push 'activity' $a.Detail $ctx; & $push 'activity' $a.Actor $ctx }
    foreach ($x in @(Get-WfxValue $bundle 'Exposure' @())) { & $push 'exposure' $x.Path "$($x.Kind)" }
    foreach ($a in @(Get-WfxValue $bundle 'Artifacts' @())) {
        $ctx = "$($a.Artifact) @ $($a.Time)$(if ($a.User) { " ($($a.User))" })"
        & $push 'artifact' $a.Path $ctx; & $push 'artifact' $a.Detail $ctx
        if ($a.Sha1) { & $push 'hash' ([string]$a.Sha1).ToUpperInvariant() "SHA1 of $($a.Path) ($($a.Artifact))" }
        $x = Get-WfxValue $a 'Extra' $null
        if ($x) { foreach ($k in 'Url', 'FirstUrl', 'Referrer', 'Arguments', 'Threat') { $v = [string](Get-WfxValue $x $k ''); if ($v) { & $push 'artifact' $v "$ctx [$k]" } } }
    }

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($i in $iocs) {
        $kind = Get-WfxIocKind $i
        $rx = switch ($kind) {
            'ip' { if ($i.Contains(':')) { '(?i)(?<![\d.:A-Fa-f])' + [regex]::Escape($i) + '(?![\d.:A-Fa-f])' } else { '(?<![\d.])' + [regex]::Escape($i) + '(?![\d]|\.\d)' } }
            'domain' { '(?i)(?<![A-Za-z0-9\-.])(?:[A-Za-z0-9\-]+\.)*' + [regex]::Escape($i) + '(?![A-Za-z0-9\-])' }
            default { $null }
        }
        foreach ($row in $rows) {
            $match = switch ($kind) {
                'hash' { $row.Where -eq 'hash' -and $row.Text -eq $i }
                { $_ -in 'ip', 'domain' } { Test-WfxRxMatch $rx $row.Text }
                default { $row.Text.IndexOf($i, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
            }
            if ($match) {
                $val = Protect-WfxText $row.Text
                if ($val.Length -gt 500) { $val = $val.Substring(0, 500) + ' …' }
                $findings.Add((New-WfxFinding -Id 'HUNT-IOC-MATCH' -Title "IOC '$i' ($kind) found in $($row.Where): $($row.Ctx)" `
                            -Severity 'High' -Confidence $(if ($kind -eq 'text') { 'Medium' } else { 'High' }) -Category 'Hunt' -Technique @() `
                            -Description "The indicator '$i' was located in $($row.Where) data on this host." `
                            -Recommendation "Correlate with the surrounding activity (process tree, connections, timing) and contain the host if confirmed malicious." `
                            -Entity "hunt:$i`:$($row.Where):$($row.Ctx)" -HostName $hn -Source 'hunt' `
                            -Evidence ([ordered]@{ Ioc = $i; Type = $kind; Where = $row.Where; Context = $row.Ctx; Value = $val })))
            }
        }
    }
    $merged = Merge-WfxFinding -Finding $findings.ToArray()
    Write-WfxSection 'Hunt'
    Write-WfxConsole ("Searched {0} data points for {1} IOC(s) on {2}." -f $rows.Count, $iocs.Count, $hn) -Kind Dim
    if (@($merged).Count -eq 0) { Write-WfxConsole 'No matches.' -Kind Ok }
    else {
        Write-WfxConsole ("{0} IOC hit(s):" -f @($merged).Count) -Kind Bad
        foreach ($f in $merged) { Write-WfxConsole "  $($f.Title)" -Kind Bad }
    }
    if (-not $NoCase) {
        $case = New-WfxCase -OutputPath $OutputPath -Name 'hunt' -HostName $hn -Mode 'hunt' -Parameters @{ Iocs = $iocs; InputPath = $InputPath; Hours = $Hours; FileScan = [bool]$FileScan }
        if ($InputPath) { try { Add-WfxCaseSource -Path (Resolve-WfxBundlePath -Path $InputPath) -Role 'source-bundle' } catch {} }
        Save-WfxJson -InputObject ([pscustomobject]@{ Schema = 'winforensicx.hunt/1'; Host = $hn; Iocs = $iocs; DataPoints = $rows.Count; Hits = @($merged) }) -Path (Join-Path $case.Path 'hunt.json') -Depth 8
        @($merged | ForEach-Object { [pscustomobject]@{ Ioc = $_.Evidence.Ioc; Type = $_.Evidence.Type; Where = $_.Evidence.Where; Context = $_.Evidence.Context; Value = $_.Evidence.Value; Host = $_.Host } }) |
            Export-Csv -Path (Join-Path $case.Path 'hunt.csv') -NoTypeInformation -Encoding UTF8
        $null = Complete-WfxCase
        Write-WfxConsole ("Results: {0}" -f $case.Path) -Kind Info
    }
    if ($PassThru) { return $merged }
}

function Get-WfxIocKind {
    <# Classifies an indicator: hash / ip / domain / text. #>
    param([string]$Value)
    if ($Value -match '^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$') { return 'hash' }
    $ip = $null
    if ($Value -match '^[0-9.]+$|:' -and [System.Net.IPAddress]::TryParse($Value, [ref]$ip)) { return 'ip' }
    if ($Value -match '^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$' -and $Value -notmatch '\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|lnk|zip|txt|doc|docx|xls|xlsx|pdf|sys|msi|iso)$') { return 'domain' }
    return 'text'
}
