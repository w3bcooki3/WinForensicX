# Optional YARA scanning. WinForensicX does not ship or download YARA: it uses a yara executable the
# analyst already trusts (-YaraExe, $env:WFX_YARA_EXE, or yara64.exe / yara.exe / yara on PATH) with rules the
# analyst supplies (-YaraRules, $env:WFX_YARA). YARA only reads the files it scans.

function Find-WfxYaraExe {
    param([string]$Path = $env:WFX_YARA_EXE)
    if ($Path) { if (Test-Path -LiteralPath $Path -PathType Leaf) { return (Resolve-Path -LiteralPath $Path).Path }; return $null }
    foreach ($n in 'yara64.exe', 'yara.exe', 'yara') { $c = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { return $c.Source } }
    $null
}

function Invoke-WfxYaraScan {
    <#
    .SYNOPSIS Runs YARA rules over a list of files and/or folders and returns { Rule; Namespace; Tags; Path }.
    .PARAMETER Rules   .yar / .yara files or folders of them.
    .PARAMETER Target  Files to scan (deduplicated, missing files skipped).
    .PARAMETER Folder  Folders to scan recursively.
    .PARAMETER ListDir Case folder to keep the list of scanned files in (enables one yara run for all files).
    #>
    param([Parameter(Mandatory)][string[]]$Rules, [string[]]$Target = @(), [string[]]$Folder = @(), [string]$YaraExe = '', [int]$TimeoutSec = 60, [int]$MaxFiles = 20000, [string]$ListDir = '')
    $exe = Find-WfxYaraExe -Path $YaraExe
    if (-not $exe) { Add-WfxGap -Source 'yara' -Reason 'YARA rules were given but no yara executable was found.' -Fix 'Install YARA (virustotal.github.io/yara) and put yara64.exe on PATH, or pass -YaraExe / set WFX_YARA_EXE.'; return }
    $ruleFiles = @(foreach ($r in $Rules) {
            if (Test-Path -LiteralPath $r -PathType Container) { Get-ChildItem -LiteralPath $r -Recurse -File -Include *.yar, *.yara -ErrorAction SilentlyContinue | ForEach-Object FullName }
            elseif (Test-Path -LiteralPath $r) { (Resolve-Path -LiteralPath $r).Path }
        })
    if (-not $ruleFiles.Count) { Add-WfxGap -Source 'yara' -Reason "No .yar/.yara files found in: $($Rules -join ', ')"; return }
    $files = @($Target | Where-Object { $_ } | Sort-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First $MaxFiles)
    $out = New-Object System.Collections.Generic.List[object]
    $run = {
        param([string[]]$ArgList)
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $exe; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $psi.Arguments = (@($ArgList | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
        $p = [Diagnostics.Process]::Start($psi)
        $errTask = $p.StandardError.ReadToEndAsync()
        $text = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
        $err = $errTask.Result
        if ($p.ExitCode -ne 0 -and $err) { Add-WfxGap -Source 'yara' -Reason ("yara exited with {0}: {1}" -f $p.ExitCode, (Get-WfxShortText $err 300)) }
        foreach ($line in ($text -split "`r?`n")) {
            $m = [regex]::Match($line, '^(?:(?<ns>[^:\s]+):)?(?<rule>[A-Za-z_][A-Za-z0-9_]*)\s+(?:\[(?<tags>[^\]]*)\]\s+)?(?<path>.+)$')
            if ($m.Success) { $out.Add([pscustomobject]@{ Rule = $m.Groups['rule'].Value; Namespace = $m.Groups['ns'].Value; Tags = $m.Groups['tags'].Value; Path = $m.Groups['path'].Value.Trim() }) }
        }
    }
    $common = @('-w', '-g', '-a', [string]$TimeoutSec) + $ruleFiles
    if ($files.Count) {
        if ($ListDir -and (Test-Path -LiteralPath $ListDir -PathType Container)) {
            # The list of scanned files is kept in the case (raw\yara-scan-list.txt) as a record of what was scanned.
            $listFile = Join-Path $ListDir 'yara-scan-list.txt'
            [IO.File]::WriteAllLines($listFile, $files)
            & $run (@('--scan-list') + $common + @($listFile))
        } else {
            # No case folder to write a list into: one yara run per file (nothing is written anywhere).
            foreach ($f in @($files | Select-Object -First 500)) { & $run ($common + @($f)) }
            if ($files.Count -gt 500) { Add-WfxGap -Source 'yara' -Reason "Only the first 500 of $($files.Count) files were scanned (no case folder for a scan list)." }
        }
    }
    foreach ($d in $Folder) { if (Test-Path -LiteralPath $d -PathType Container) { & $run (@('-r') + $common + @($d)) } }
    $seen = @{}
    foreach ($h in $out) { $k = "$($h.Rule)|$($h.Path)"; if (-not $seen[$k]) { $seen[$k] = $true; $h } }
}

function Invoke-WfxYaraAnalyzer {
    param([object[]]$Hit, [string]$HostName = '')
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($Hit | Where-Object { $_ })) {
        $findings.Add((New-WfxFinding -Id "YARA-$($h.Rule)" -Title "YARA rule $($h.Rule) matched: $(Get-WfxLeaf $h.Path)" -Severity 'High' -Confidence 'Medium' -Category 'Malware' -Technique @() `
                    -Description "The file matched YARA rule $($h.Rule)$(if ($h.Tags) { " (tags: $($h.Tags))" }). How much this means depends on the rule: check its description and author." `
                    -Recommendation 'Hash the file, check it against threat intelligence, and look at how it arrived and whether it ran (Explore › Evidence of execution).' `
                    -Entity "file:$($h.Path)" -HostName $HostName -Source 'yara' -Evidence ([ordered]@{ Rule = $h.Rule; Namespace = $h.Namespace; Tags = $h.Tags; Path = $h.Path })))
    }
    , $findings.ToArray()
}
