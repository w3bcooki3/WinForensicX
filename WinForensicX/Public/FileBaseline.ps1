function New-WfxFileBaseline {
    <#
    .SYNOPSIS
        File-integrity baseline: records size, timestamps and SHA-256 of every file under the given folders,
        so a later Compare-WfxFileBaseline shows exactly what was added, deleted, or had its CONTENT changed.
    .DESCRIPTION
        Typical uses: snapshot C:\Windows\System32\drivers\etc, a web root, a startup folder or a CTF VM before
        running a sample, then compare afterwards. Read-only; the baseline is written to -OutputPath.
    .EXAMPLE
        New-WfxFileBaseline -Path C:\inetpub\wwwroot, C:\Windows\System32\drivers\etc -OutputPath E:\baselines\web.json
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Path, [string]$OutputPath = '', [int]$MaxFiles = 200000, [int]$MaxFileMB = 256)
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($root in $Path) {
        if (-not (Test-Path -LiteralPath $root)) { Write-Warning "Not found: $root"; continue }
        Write-WfxConsole "  Hashing $root ..." -Kind Dim
        foreach ($f in (Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            if ($files.Count -ge $MaxFiles) { Write-Warning "File cap ($MaxFiles) reached."; break }
            $h = if ($f.Length -le $MaxFileMB * 1MB) { try { (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'unreadable' } } else { 'too-large' }
            $files.Add([pscustomobject]@{ Path = $f.FullName; Size = $f.Length; Modified = (ConvertTo-WfxUtcString $f.LastWriteTimeUtc); Created = (ConvertTo-WfxUtcString $f.CreationTimeUtc); SHA256 = $h })
        }
    }
    if (-not $OutputPath) {
        $root = Get-WfxDefaultOutputRoot; if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
        $OutputPath = Join-Path $root ("baseline_{0}_{1}.json" -f [Environment]::MachineName, (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
    }
    Save-WfxJson -InputObject ([pscustomobject]@{ Schema = 'winforensicx.filebaseline/1'; Host = [Environment]::MachineName; Created = (Get-WfxUtcNow); Roots = @($Path); Files = $files.ToArray() }) -Path $OutputPath -Depth 4
    Write-WfxConsole ("Baseline of {0} files: {1}  (SHA-256 {2})" -f $files.Count, $OutputPath, (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()) -Kind Ok
    $OutputPath
}

function Compare-WfxFileBaseline {
    <#
    .SYNOPSIS Re-scans the folders of a baseline and reports Added, Deleted, ContentChanged and
    TimestampOnly (same content, different timestamps — possible timestomping or a touch) files.
    .EXAMPLE
        Compare-WfxFileBaseline -Baseline E:\baselines\web.json | Format-Table
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Baseline)
    $b = Get-Content -LiteralPath $Baseline -Raw -Encoding UTF8 | ConvertFrom-Json
    $old = @{}; foreach ($f in @($b.Files)) { $old[$f.Path.ToLowerInvariant()] = $f }
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($root in @($b.Roots)) {
        foreach ($f in (Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            $k = $f.FullName.ToLowerInvariant(); $seen[$k] = $true
            $o = $old[$k]
            $mod = ConvertTo-WfxUtcString $f.LastWriteTimeUtc
            if (-not $o) { $out.Add([pscustomobject]@{ Change = 'Added'; Path = $f.FullName; Modified = $mod; Detail = "$($f.Length) bytes" }); continue }
            if ([int64]$o.Size -ne $f.Length -or (ConvertTo-WfxUtcString $o.Modified) -ne $mod) {
                $h = try { (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'unreadable' }
                if ($h -ne $o.SHA256) { $out.Add([pscustomobject]@{ Change = 'ContentChanged'; Path = $f.FullName; Modified = $mod; Detail = "size $($o.Size) → $($f.Length); sha256 $($o.SHA256.Substring(0, [Math]::Min(12, $o.SHA256.Length)))… → $($h.Substring(0, [Math]::Min(12, $h.Length)))…" }) }
                else { $out.Add([pscustomobject]@{ Change = 'TimestampOnly'; Path = $f.FullName; Modified = $mod; Detail = "modified $(ConvertTo-WfxUtcString $o.Modified) → $mod (content identical)" }) }
            }
        }
    }
    foreach ($k in $old.Keys) { if (-not $seen.ContainsKey($k)) { $out.Add([pscustomobject]@{ Change = 'Deleted'; Path = $old[$k].Path; Modified = $old[$k].Modified; Detail = "$($old[$k].Size) bytes" }) } }
    $res = @($out | Sort-Object Change, Path)
    Write-WfxSection 'File baseline comparison'
    Write-WfxConsole ("Baseline {0} ({1} files) · now: added {2}, deleted {3}, content changed {4}, timestamp-only {5}" -f $b.Created, @($b.Files).Count, @($res | Where-Object Change -eq 'Added').Count, @($res | Where-Object Change -eq 'Deleted').Count, @($res | Where-Object Change -eq 'ContentChanged').Count, @($res | Where-Object Change -eq 'TimestampOnly').Count) -Kind Info
    $res
}
