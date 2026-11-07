function Test-WfxCase {
    <#
    .SYNOPSIS
        Verifies a case folder against its manifest.json: re-hashes every listed file and reports files that
        changed, are missing, or were added after the case was closed. Prints the manifest's own SHA-256 so it
        can be compared with the value recorded at collection time.
    .PARAMETER Path            Case folder (or any file inside it).
    .PARAMETER ExpectedManifestSha256  Optional: the manifest hash you recorded out-of-band.
    .EXAMPLE
        Test-WfxCase -Path E:\cases\WFX_PC01_20261103-101500Z
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$ExpectedManifestSha256 = '')
    $root = if (Test-Path -LiteralPath $Path -PathType Leaf) { Split-Path -Parent $Path } else { $Path }
    if ((Split-Path -Leaf $root) -eq 'raw') { $root = Split-Path -Parent $root }
    $mp = Join-Path $root 'manifest.json'
    if (-not (Test-Path -LiteralPath $mp)) { throw "No manifest.json in '$root' — not a completed WinForensicX case." }
    $root = (Resolve-Path -LiteralPath $root).Path
    $m = Get-Content -LiteralPath $mp -Raw -Encoding UTF8 | ConvertFrom-Json
    $mHash = (Get-FileHash -LiteralPath $mp -Algorithm SHA256).Hash.ToLowerInvariant()
    $rows = New-Object System.Collections.Generic.List[object]
    $listed = @{}
    foreach ($f in @($m.files)) {
        $full = Join-Path $root ([string]$f.path -replace '/', [IO.Path]::DirectorySeparatorChar)
        $listed[$full.ToLowerInvariant()] = $true
        if (-not (Test-Path -LiteralPath $full)) { $rows.Add([pscustomobject]@{ File = $f.path; Status = 'MISSING' }); continue }
        $h = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
        $rows.Add([pscustomobject]@{ File = $f.path; Status = $(if ($h -eq [string]$f.sha256) { 'OK' } else { 'CHANGED' }) })
    }
    Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' -and -not $listed.ContainsKey($_.FullName.ToLowerInvariant()) } |
        ForEach-Object { $rows.Add([pscustomobject]@{ File = $_.FullName.Substring($root.Length).TrimStart('\', '/'); Status = 'ADDED AFTER CLOSE' }) }
    $bad = @($rows | Where-Object Status -ne 'OK')
    $expectedOk = if ($ExpectedManifestSha256) { $ExpectedManifestSha256.Trim().ToLowerInvariant() -eq $mHash } else { $null }
    $valid = ($bad.Count -eq 0) -and ($expectedOk -ne $false)
    Write-WfxSection 'Case verification'
    Write-WfxConsole ("Case {0}  host {1}  completed {2}" -f $m.case, $m.host, $m.completed) -Kind Dim
    Write-WfxConsole ("Manifest SHA-256: {0}{1}" -f $mHash, $(if ($null -ne $expectedOk) { if ($expectedOk) { '  (matches the recorded value)' } else { '  (DOES NOT match the recorded value!)' } } else { '' })) -Kind $(if ($expectedOk -eq $false) { 'Bad' } else { 'Dim' })
    foreach ($b in $bad) { Write-WfxConsole ("  {0,-18} {1}" -f $b.Status, $b.File) -Kind Bad }
    Write-WfxConsole $(if ($valid) { "VALID — all $($rows.Count) files match the manifest." } else { "NOT VALID — $($bad.Count) problem(s) found." }) -Kind $(if ($valid) { 'Ok' } else { 'Bad' })
    if ($null -eq $expectedOk) { Write-WfxConsole 'Compare the manifest SHA-256 above with the value recorded when the case was collected.' -Kind Dim }
    [pscustomobject]@{ Path = $root; Valid = $valid; ManifestSha256 = $mHash; Files = $rows.Count; Problems = $bad }
}
