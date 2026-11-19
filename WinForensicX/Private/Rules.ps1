# Rule packs: JSON files in Rules/ (or embedded in the single-file build), plus optional
# custom packs from a folder (Set-WfxRulePath / $env:WFX_RULES). Regexes are compiled once, with a
# match timeout so a badly written (or malicious) community rule can never hang a triage. Every rule is
# validated when it is loaded; an invalid rule is skipped and recorded as a gap, never trusted.

# $PSScriptRoot is empty when this file is evaluated from a string (remote bootstrap) — guard it.
$script:WfxRuleRoot = if ($PSScriptRoot) { Join-Path (Split-Path -Parent $PSScriptRoot) 'Rules' } else { '' }
$script:WfxEmbeddedRules = @{}          # filled by the single-file build
$script:WfxRuleCache = @{}
$script:WfxRuleSources = New-Object System.Collections.Generic.List[string]
$script:WfxCustomRulePath = $env:WFX_RULES
$script:WfxRequiredPacks = @('lotl', 'events', 'ai', 'threats', 'dns')

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
    $docs = [System.Collections.Generic.List[object]]::new()
    if ($script:WfxEmbeddedRules.ContainsKey($Name)) {
        $docs.Add(($script:WfxEmbeddedRules[$Name] | ConvertFrom-Json))
    } elseif ($script:WfxRuleRoot) {
        $file = Join-Path $script:WfxRuleRoot "$Name.json"
        if (Test-Path -LiteralPath $file) { $docs.Add((Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json)) }
    }
    if ($script:WfxCustomRulePath -and (Test-Path -LiteralPath $script:WfxCustomRulePath)) {
        foreach ($f in Get-ChildItem -LiteralPath $script:WfxCustomRulePath -Filter "$Name.*.json" -File) {
            try {
                $docs.Add((Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json))
                if (-not $script:WfxRuleSources.Contains($f.FullName)) { $script:WfxRuleSources.Add($f.FullName) }
            } catch { Add-WfxGap -Source "rules:$($f.Name)" -Reason "custom rule pack could not be parsed: $($_.Exception.Message)" }
        }
    }
    return , $docs.ToArray()
}

function ConvertTo-WfxFieldMatch {
    <#
    Compiles a rule's field conditions: { "Image|NewProcessName": "regex", ... }. The key lists alternative field
    names (the first one present on the event is used), so one rule covers Sysmon and Security schemas.
    #>
    param($Spec)
    if (-not $Spec) { return }
    foreach ($p in $Spec.PSObject.Properties) {
        [pscustomobject]@{ Key = $p.Name; Names = @($p.Name -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); Rx = (New-WfxRegex ([string]$p.Value)) }
    }
}

function Test-WfxRuleDefinition {
    <# Validates one rule object. Returns '' when valid, otherwise the reason it was rejected. #>
    param($Rule)
    $id = [string](Get-WfxValue $Rule 'id' '')
    if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.\-]{1,80}$') { return "invalid id '$id'" }
    if ([string](Get-WfxValue $Rule 'severity' 'Medium') -notin $script:WfxSeverities) { return "invalid severity" }
    if ([string](Get-WfxValue $Rule 'confidence' 'Medium') -notin @('Low', 'Medium', 'High')) { return "invalid confidence" }
    foreach ($t in @(Get-WfxValue $Rule 'technique' @())) { if ([string]$t -notmatch '^T\d{4}(?:\.\d{3})?$') { return "invalid ATT&CK technique '$t'" } }
    foreach ($k in 'match', 'matchNot') {
        $m = Get-WfxValue $Rule $k
        if ($null -eq $m) { continue }
        if ($m -isnot [System.Management.Automation.PSCustomObject]) { return "'$k' must be an object of field: regex" }
        foreach ($p in $m.PSObject.Properties) {
            if ($p.Value -isnot [string] -or $p.Value -eq '') { return "'$k.$($p.Name)' must be a non-empty regex string" }
            try { $null = [regex]::new([string]$p.Value) } catch { return "'$k.$($p.Name)' is not a valid regex" }
        }
    }
    return ''
}

function Get-WfxRulePack {
    <#
    .SYNOPSIS Returns a rule pack as an object; list-like packs get compiled regexes attached.
    .DESCRIPTION Packs: lotl (command-line rules), events (event-log rules), ai (AI services/runtimes),
    threats (RMM, tunnels, offensive tools, named pipes, drivers), dns (TLDs and services).
    Throws a clear, actionable error if a built-in pack is missing (e.g. quarantined or deleted).
    #>
    param([Parameter(Mandatory)][string]$Name)
    if ($script:WfxRuleCache.ContainsKey($Name)) { return $script:WfxRuleCache[$Name] }
    $docs = Read-WfxRuleJson -Name $Name
    if ($docs.Count -eq 0) {
        throw "Rule pack '$Name' not found (expected $Name.json in '$script:WfxRuleRoot'). If antivirus quarantined it, restore it from the release archive; detections that depend on it are skipped."
    }
    $pack = $docs[0]
    if ($pack.PSObject.Properties['rules']) {
        $all = [System.Collections.Generic.List[object]]::new()
        $ids = @{}
        foreach ($d in $docs) {
            foreach ($r in @($d.rules)) {
                $why = Test-WfxRuleDefinition $r
                if ($why) { Add-WfxGap -Source "rules:$Name" -Reason "rule rejected: $why"; continue }
                if ($ids.ContainsKey($r.id)) { continue }   # first definition wins
                try {
                    $r | Add-Member -NotePropertyName rx -NotePropertyValue (New-WfxRegex (Get-WfxValue $r 'pattern' '')) -Force
                    $ex = Get-WfxValue $r 'exclude'
                    $r | Add-Member -NotePropertyName rxExclude -NotePropertyValue (New-WfxRegex $ex) -Force
                    $imgs = @(Get-WfxValue $r 'images' @()) | ForEach-Object { ([string]$_).ToLowerInvariant() }
                    $r | Add-Member -NotePropertyName imageSet -NotePropertyValue @($imgs) -Force
                    $r | Add-Member -NotePropertyName matchSet -NotePropertyValue @(ConvertTo-WfxFieldMatch (Get-WfxValue $r 'match')) -Force
                    $r | Add-Member -NotePropertyName matchNotSet -NotePropertyValue @(ConvertTo-WfxFieldMatch (Get-WfxValue $r 'matchNot')) -Force
                    $ids[$r.id] = $true
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

function Test-WfxRulePackSet {
    <# Checks that every built-in pack loads. Returns the names of packs that are missing/broken. #>
    $bad = foreach ($n in $script:WfxRequiredPacks) { try { $null = Get-WfxRulePack -Name $n } catch { $n } }
    $bad
}

function ConvertTo-WfxCanonicalCommand {
    <#
    .SYNOPSIS The command line as the shell will actually run it, for rule matching only (evidence keeps the original).
    .DESCRIPTION Undoes common, cheap obfuscation: en/em dashes and minus signs used as parameter prefixes (PowerShell
    accepts them), cmd caret escapes (p^o^w^e^r^s^h^e^l^l), empty-quote splitting (p""owershell), and "/switch"
    spellings of "-switch" for tools that accept both (certutil, regsvr32, msiexec ...).
    #>
    param([AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrEmpty($CommandLine)) { return $CommandLine }
    $c = $CommandLine -replace '[\u2013\u2014\u2015\u2212]', '-'
    $c = $c -replace '\^', ''
    $c = $c -replace '(?<=\w)""(?=\w)', ''
    $c = $c -replace '(?<=\s)/(?=[A-Za-z][\w:-]*)', '-'
    return $c
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
    # Match the text as written and as it will run (de-obfuscated); report each rule once.
    $texts = @($CommandLine)
    $canon = ConvertTo-WfxCanonicalCommand $CommandLine
    if ($canon -ne $CommandLine) { $texts += $canon }
    $seen = @{}
    foreach ($CommandLine in $texts) {
    foreach ($r in $pack.rules) {
        if ($seen.ContainsKey($r.id)) { continue }
        if ($r.imageSet.Count -gt 0 -and $r.imageSet -notcontains $leaf) {
            # Image-specific rule: still applies when the binary is invoked through cmd/powershell in the same line.
            $named = $false
            foreach ($i in $r.imageSet) { if (Test-WfxRxMatch ('(?i)(?:^|[\\/\s"''(;&|])' + [regex]::Escape(($i -replace '\.exe$', '')) + '(?:\.exe)?(?=[\s"'']|$)') $CommandLine) { $named = $true; break } }
            if (-not $named) { continue }
        }
        if (-not (Test-WfxRegex $r.rx $CommandLine)) { continue }
        if ($r.rxExclude -and (Test-WfxRegex $r.rxExclude $CommandLine)) { continue }
        $seen[$r.id] = $true
        $r
    }
    }
}
