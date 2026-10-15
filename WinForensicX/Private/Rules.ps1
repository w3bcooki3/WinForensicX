# Rule packs: JSON files in Rules/ (or embedded in the single-file build), plus optional
# custom packs from a folder (-RulePath / $env:WFX_RULES). Regexes are compiled once, with a
# match timeout so a badly written community rule can never hang a triage.

$script:WfxRuleRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'Rules'
$script:WfxEmbeddedRules = @{}          # filled by the single-file build
$script:WfxRuleCache = @{}
$script:WfxCustomRulePath = $env:WFX_RULES
$script:WfxRegexTimeout = [TimeSpan]::FromMilliseconds(250)

function Set-WfxRulePath {
    <# Adds a folder of custom rule packs (files named <pack>.<anything>.json, e.g. lotl.mycompany.json). #>
    param([string]$Path)
    $script:WfxCustomRulePath = $Path
    $script:WfxRuleCache = @{}
}

function New-WfxRegex {
    param([string]$Pattern)
    if ([string]::IsNullOrEmpty($Pattern)) { return $null }
    return New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::None, $script:WfxRegexTimeout)
}

function Test-WfxRegex {
    <# Regex match that treats a timeout as "no match" instead of throwing. #>
    param($Regex, [AllowEmptyString()][string]$Text)
    if ($null -eq $Regex -or [string]::IsNullOrEmpty($Text)) { return $false }
    try { return $Regex.IsMatch($Text) } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return $false }
}

function Read-WfxRuleJson {
    param([string]$Name)
    $docs = New-Object System.Collections.Generic.List[object]
    if ($script:WfxEmbeddedRules.ContainsKey($Name)) {
        $docs.Add(($script:WfxEmbeddedRules[$Name] | ConvertFrom-Json))
    } else {
        $file = Join-Path $script:WfxRuleRoot "$Name.json"
        if (Test-Path -LiteralPath $file) { $docs.Add((Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json)) }
    }
    if ($script:WfxCustomRulePath -and (Test-Path -LiteralPath $script:WfxCustomRulePath)) {
        foreach ($f in Get-ChildItem -LiteralPath $script:WfxCustomRulePath -Filter "$Name.*.json" -File) {
            try { $docs.Add((Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)) }
            catch { Add-WfxGap -Source "rules:$($f.Name)" -Reason "custom rule pack could not be parsed: $($_.Exception.Message)" }
        }
    }
    return , $docs.ToArray()
}

function Get-WfxRulePack {
    <#
    .SYNOPSIS Returns a rule pack as an object; list-like packs get compiled regexes attached.
    .DESCRIPTION Packs: lotl (command-line rules), events (event-log rules), ai (AI services/runtimes),
    threats (RMM, tunnels, offensive tools, named pipes, drivers), dns (TLDs and services).
    #>
    param([Parameter(Mandatory)][string]$Name)
    if ($script:WfxRuleCache.ContainsKey($Name)) { return $script:WfxRuleCache[$Name] }
    $docs = Read-WfxRuleJson -Name $Name
    if ($docs.Count -eq 0) { throw "Rule pack '$Name' not found." }
    $pack = $docs[0]
    if ($pack.PSObject.Properties['rules']) {
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($d in $docs) {
            foreach ($r in @($d.rules)) {
                if ($all | Where-Object { $_.id -eq $r.id }) { continue }   # first definition wins
                try {
                    $r | Add-Member -NotePropertyName rx -NotePropertyValue (New-WfxRegex $r.pattern) -Force
                    $ex = Get-WfxValue $r 'exclude'
                    $r | Add-Member -NotePropertyName rxExclude -NotePropertyValue (New-WfxRegex $ex) -Force
                    $imgs = @(Get-WfxValue $r 'images' @()) | ForEach-Object { ([string]$_).ToLowerInvariant() }
                    $r | Add-Member -NotePropertyName imageSet -NotePropertyValue @($imgs) -Force
                    $all.Add($r)
                } catch {
                    Add-WfxGap -Source "rules:$Name" -Reason "rule $($r.id) has an invalid pattern: $($_.Exception.Message)"
                }
            }
        }
        $pack | Add-Member -NotePropertyName rules -NotePropertyValue $all.ToArray() -Force
    }
    $script:WfxRuleCache[$Name] = $pack
    return $pack
}

function Test-WfxCommandLine {
    <#
    .SYNOPSIS Runs the command-line rule pack against one command line. Returns matching rules.
    .PARAMETER Image  Executable name or path; restricts image-specific rules. Inferred from the command line if omitted.
    #>
    param([AllowEmptyString()][string]$CommandLine, [string]$Image = '')
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    if (-not $Image) { $Image = Get-WfxImagePath $CommandLine }
    $leaf = (Get-WfxLeaf $Image).ToLowerInvariant()
    if ($leaf -and $leaf -notmatch '\.') { $leaf += '.exe' }
    $pack = Get-WfxRulePack -Name 'lotl'
    foreach ($r in $pack.rules) {
        if ($r.imageSet.Count -gt 0 -and $r.imageSet -notcontains $leaf) {
            # Image-specific rule: still applies when the binary is invoked through cmd/powershell in the same line.
            $named = $false
            foreach ($i in $r.imageSet) { if ($CommandLine -match ('(?i)(?:^|[\\/\s"''(;&|])' + [regex]::Escape(($i -replace '\.exe$', '')) + '(?:\.exe)?(?=[\s"'']|$)')) { $named = $true; break } }
            if (-not $named) { continue }
        }
        if (-not (Test-WfxRegex $r.rx $CommandLine)) { continue }
        if ($r.rxExclude -and (Test-WfxRegex $r.rxExclude $CommandLine)) { continue }
        $r
    }
}
