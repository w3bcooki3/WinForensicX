# Sigma rule support: load community / in-house Sigma rules (YAML) and evaluate them against the Windows
# events the tool collects. Read-only and offline: rules are parsed as data, never executed.
#
# Supported: logsource product windows with the categories and services in $script:WfxSigmaSource;
# selections (maps, lists of maps, keyword lists); modifiers contains, startswith, endswith, all, re (with
# i / m / s), windash, cidr, base64offset, fieldref, exists, cased; conditions with and / or / not,
# parentheses, "1 of x*", "all of x*", "1 of them", "all of them".
# Not supported (the rule is skipped and listed as a gap): aggregations ("| count() by ...") and
# correlation rules. Events are matched only if the tool collected them (see $script:WfxEventQuery).

# Which collected events each Sigma logsource maps to, and how 4688 fields map to Sigma (Sysmon) names.
$script:WfxSigmaSource = @{
    'category:process_creation'     = @{ Logs = @('Microsoft-Windows-Sysmon/Operational', 'Security'); Ids = @(1, 4688) }
    'category:network_connection'   = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(3) }
    'category:image_load'           = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(7) }
    'category:create_remote_thread' = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(8) }
    'category:process_access'       = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(10) }
    'category:file_event'           = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(11) }
    'category:registry_add'         = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(12) }
    'category:registry_delete'      = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(12) }
    'category:registry_set'         = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(13) }
    'category:registry_event'       = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(12, 13, 14) }
    'category:dns_query'            = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(22) }
    'category:file_delete'          = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @(23, 26) }
    'category:ps_script'            = @{ Logs = @('Microsoft-Windows-PowerShell/Operational'); Ids = @(4104) }
    'service:security'              = @{ Logs = @('Security'); Ids = @() }
    'service:system'                = @{ Logs = @('System'); Ids = @() }
    'service:sysmon'                = @{ Logs = @('Microsoft-Windows-Sysmon/Operational'); Ids = @() }
    'service:windefend'             = @{ Logs = @('Microsoft-Windows-Windows Defender/Operational'); Ids = @() }
    'service:powershell'            = @{ Logs = @('Microsoft-Windows-PowerShell/Operational'); Ids = @() }
    'service:taskscheduler'         = @{ Logs = @('Microsoft-Windows-TaskScheduler/Operational'); Ids = @() }
    'service:terminalservices-localsessionmanager' = @{ Logs = @('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'); Ids = @() }
}
$script:WfxSigma4688Map = @{ Image = 'NewProcessName'; ParentImage = 'ParentProcessName'; User = 'SubjectUserName'; ProcessId = 'NewProcessId'; ParentProcessId = 'ProcessId'; IntegrityLevel = 'MandatoryLabel' }

# ───────────────────────────── minimal YAML (the subset Sigma uses) ─────────────────────────────
function ConvertFrom-WfxYaml {
    <# Parses one YAML document (block maps, block lists, flow lists, quoted / block scalars) into
       ordered dictionaries, arrays and strings. Not a general YAML parser: anchors, tags and complex
       keys are not supported. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $lines = [System.Collections.Generic.List[object]]::new()
    $raw = $Text -split "`r?`n"
    for ($i = 0; $i -lt $raw.Count; $i++) {
        $l = $raw[$i]
        if ($l -match '^\s*(#.*)?$') { continue }
        $ind = $l.Length - $l.TrimStart(' ').Length
        $lines.Add([pscustomobject]@{ I = $ind; T = (Remove-WfxYamlComment $l.Trim()); N = $i; Raw = $l })
    }
    $script:WfxYamlRaw = $raw
    $pos = [ref]0
    if (-not $lines.Count) { return $null }
    ConvertFrom-WfxYamlBlock $lines $pos $lines[0].I
}

function Remove-WfxYamlComment {
    <#
    Strips a trailing comment from one trimmed line. A quote opens a quoted scalar only where a value starts
    (after "- ", after "key: ", or inside a flow list after "[" or ","); in a plain scalar such as a regular
    expression, quotes are ordinary characters and " #" starts the comment.
    #>
    param([string]$S)
    $i = 0
    while ($S.Length -gt $i + 1 -and $S[$i] -eq '-' -and $S[$i + 1] -eq ' ') { $i += 2; while ($i -lt $S.Length -and $S[$i] -eq ' ') { $i++ } }
    $skipQuoted = {
        param([int]$at)
        $qc = $S[$at]; $j = $at + 1
        while ($j -lt $S.Length) {
            if ($qc -eq "'" -and $S[$j] -eq "'") { if ($j + 1 -lt $S.Length -and $S[$j + 1] -eq "'") { $j += 2; continue }; return $j + 1 }
            if ($qc -eq '"' -and $S[$j] -eq '\') { $j += 2; continue }
            if ($qc -eq '"' -and $S[$j] -eq '"') { return $j + 1 }
            $j++
        }
        $S.Length
    }
    # Key (plain or quoted), then the value.
    $v = $i
    if ($i -lt $S.Length -and ($S[$i] -eq "'" -or $S[$i] -eq '"')) {
        $k = & $skipQuoted $i
        if ($k -lt $S.Length -and $S[$k] -eq ':') { $v = $k + 1 }
    } else {
        $c = $S.IndexOf(': ', $i); $endColon = $S.EndsWith(':') -and $S.IndexOf(':', $i) -eq $S.Length - 1
        if ($c -ge 0 -and ($S.IndexOf(' #', $i) -lt 0 -or $S.IndexOf(' #', $i) -gt $c)) { $v = $c + 1 } elseif ($endColon) { return $S }
    }
    while ($v -lt $S.Length -and $S[$v] -eq ' ') { $v++ }
    if ($v -ge $S.Length) { return $S }
    $ch = $S[$v]
    if ($ch -eq "'" -or $ch -eq '"') {
        $k = & $skipQuoted $v
        $h = $S.IndexOf('#', $k)
        if ($h -ge 0 -and ($h -eq 0 -or $S[$h - 1] -eq ' ' -or $S[$h - 1] -eq "`t")) { return $S.Substring(0, $h).TrimEnd() }
        return $S
    }
    if ($ch -eq '[' -or $ch -eq '{') {
        $j = $v; $atStart = $true
        while ($j -lt $S.Length) {
            $c2 = $S[$j]
            if (($c2 -eq "'" -or $c2 -eq '"') -and $atStart) { $j = & $skipQuoted $j; $atStart = $false; continue }
            if ($c2 -eq '#' -and $j -gt 0 -and $S[$j - 1] -eq ' ') { return $S.Substring(0, $j).TrimEnd() }
            $atStart = $c2 -in '[', ',', '{', ' ' -or ($c2 -eq ':')
            if ($c2 -ne ' ' -and $c2 -notin '[', ',', '{', ':') { $atStart = $false }
            $j++
        }
        return $S
    }
    # Plain scalar: a comment starts at " #" (or "<tab>#").
    for ($j = $v; $j -lt $S.Length; $j++) { if ($S[$j] -eq '#' -and ($S[$j - 1] -eq ' ' -or $S[$j - 1] -eq "`t")) { return $S.Substring(0, $j).TrimEnd() } }
    $S
}

function ConvertFrom-WfxYamlDoubleQuoted {
    <# The body of a double-quoted YAML scalar with its escapes (\n \t \" \\ \xHH \uHHHH \UHHHHHHHH ...) decoded. #>
    param([string]$S)
    if ($S.IndexOf('\') -lt 0) { return $S }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $S.Length; $i++) {
        $c = $S[$i]
        if ($c -ne '\' -or $i + 1 -ge $S.Length) { [void]$sb.Append($c); continue }
        $n = $S[++$i]
        switch -CaseSensitive ($n) {
            'n' { [void]$sb.Append("`n") } 't' { [void]$sb.Append("`t") } 'r' { [void]$sb.Append("`r") } '0' { [void]$sb.Append([char]0) }
            'a' { [void]$sb.Append([char]7) } 'b' { [void]$sb.Append([char]8) } 'e' { [void]$sb.Append([char]27) } 'f' { [void]$sb.Append([char]12) } 'v' { [void]$sb.Append([char]11) }
            '"' { [void]$sb.Append('"') } '\' { [void]$sb.Append('\') } '/' { [void]$sb.Append('/') } ' ' { [void]$sb.Append(' ') }
            'N' { [void]$sb.Append([char]0x85) } '_' { [void]$sb.Append([char]0xA0) } 'L' { [void]$sb.Append([char]0x2028) } 'P' { [void]$sb.Append([char]0x2029) }
            'x' { if ($i + 2 -lt $S.Length + 0 -and $S.Substring($i + 1, 2) -match '^[0-9A-Fa-f]{2}$') { [void]$sb.Append([char][Convert]::ToInt32($S.Substring($i + 1, 2), 16)); $i += 2 } else { [void]$sb.Append('\x') } }
            'u' { if ($i + 4 -lt $S.Length + 0 -and $S.Substring($i + 1, 4) -match '^[0-9A-Fa-f]{4}$') { [void]$sb.Append([char][Convert]::ToInt32($S.Substring($i + 1, 4), 16)); $i += 4 } else { [void]$sb.Append('\u') } }
            'U' { if ($i + 8 -lt $S.Length + 0 -and $S.Substring($i + 1, 8) -match '^[0-9A-Fa-f]{8}$') { [void]$sb.Append([char]::ConvertFromUtf32([Convert]::ToInt32($S.Substring($i + 1, 8), 16))); $i += 8 } else { [void]$sb.Append('\U') } }
            default { [void]$sb.Append('\').Append($n) }
        }
    }
    $sb.ToString()
}

function ConvertFrom-WfxYamlScalar {
    param([string]$V)
    $v = $V.Trim()
    if ($v -eq '' -or $v -eq '~' -or $v -eq 'null') { return $null }
    if ($v.StartsWith("'") -and $v.EndsWith("'") -and $v.Length -ge 2) { return $v.Substring(1, $v.Length - 2).Replace("''", "'") }
    if ($v.StartsWith('"') -and $v.EndsWith('"') -and $v.Length -ge 2) { return (ConvertFrom-WfxYamlDoubleQuoted $v.Substring(1, $v.Length - 2)) }
    if ($v.StartsWith('[') -and $v.EndsWith(']')) {
        $inner = $v.Substring(1, $v.Length - 2); $items = @(); $cur = ''; $q = $null
        foreach ($c in $inner.ToCharArray()) {
            if ($q) { $cur += $c; if ($c -eq $q) { $q = $null }; continue }
            if (($c -eq "'" -or $c -eq '"') -and -not $cur.Trim()) { $q = $c; $cur += $c; continue }
            if ($c -eq ',') { $items += , (ConvertFrom-WfxYamlScalar $cur); $cur = ''; continue }
            $cur += $c
        }
        if ($cur.Trim()) { $items += , (ConvertFrom-WfxYamlScalar $cur) }
        return , $items
    }
    $v
}

function Get-WfxYamlContinuation {
    <# A scalar that goes on over more-indented lines (plain or quoted): those lines, joined with spaces. #>
    param($Lines, [ref]$Pos, [int]$Indent, [string]$First)
    $parts = New-Object System.Collections.Generic.List[string]; $parts.Add($First)
    while ($Pos.Value -lt $Lines.Count -and $Lines[$Pos.Value].I -gt $Indent) { $parts.Add($Lines[$Pos.Value].T); $Pos.Value++ }
    ($parts -join ' ')
}

function ConvertFrom-WfxYamlBlock {
    param($Lines, [ref]$Pos, [int]$Indent)
    if ($Pos.Value -ge $Lines.Count) { return $null }
    $first = $Lines[$Pos.Value]
    if ($first.T.StartsWith('- ') -or $first.T -eq '-') {
        $list = [System.Collections.Generic.List[object]]::new()
        while ($Pos.Value -lt $Lines.Count) {
            $ln = $Lines[$Pos.Value]
            if ($ln.I -lt $Indent -or -not ($ln.T.StartsWith('- ') -or $ln.T -eq '-')) { break }
            if ($ln.I -gt $Indent) { $Pos.Value++; continue }
            $rest = if ($ln.T -eq '-') { '' } else { $ln.T.Substring(2).Trim() }
            if ($rest -eq '') {
                $Pos.Value++
                if ($Pos.Value -lt $Lines.Count -and $Lines[$Pos.Value].I -gt $Indent) { $list.Add((ConvertFrom-WfxYamlBlock $Lines $Pos $Lines[$Pos.Value].I)) } else { $list.Add($null) }
            } elseif ($rest -match '^([^''"\s][^:]*?|''[^'']*''|"[^"]*"):(\s|$)') {
                # "- key: value" starts a map item; its other keys are indented under the first key.
                $childIndent = $ln.I + 2
                $Lines[$Pos.Value] = [pscustomobject]@{ I = $childIndent; T = $rest; N = $ln.N; Raw = $ln.Raw }
                $list.Add((ConvertFrom-WfxYamlBlock $Lines $Pos $childIndent))
            } else { $Pos.Value++; $list.Add((ConvertFrom-WfxYamlScalar (Get-WfxYamlContinuation $Lines $Pos $ln.I $rest))) }
        }
        return , $list.ToArray()
    }
    # Lines that are not "key: value" pairs here form one multi-line plain scalar (a long condition, for example).
    if ($first.T -notmatch '^(''[^'']*''|"[^"]*"|[^:]+?)\s*:(?:\s+(.*))?$') {
        $parts = New-Object System.Collections.Generic.List[string]
        while ($Pos.Value -lt $Lines.Count -and $Lines[$Pos.Value].I -ge $Indent) { $parts.Add($Lines[$Pos.Value].T); $Pos.Value++ }
        return (ConvertFrom-WfxYamlScalar ($parts -join ' '))
    }
    $map = [ordered]@{}
    while ($Pos.Value -lt $Lines.Count) {
        $ln = $Lines[$Pos.Value]
        if ($ln.I -lt $Indent) { break }
        if ($ln.I -gt $Indent) { $Pos.Value++; continue }
        $m = [regex]::Match($ln.T, '^(''[^'']*''|"[^"]*"|[^:]+?)\s*:(?:\s+(.*))?$')
        if (-not $m.Success) { $Pos.Value++; continue }
        $key = ConvertFrom-WfxYamlScalar $m.Groups[1].Value
        $val = $m.Groups[2].Value
        $Pos.Value++
        if ($val -match '^([|>])([+-]?)$') {
            # Block scalar: literal (|) keeps line breaks, folded (>) joins lines with spaces; chomping: clip
            # (one final line break), strip (-) or keep (+).
            $style = $Matches[1]; $chomp = $Matches[2]
            $buf = New-Object System.Collections.Generic.List[string]; $bi = -1
            $firstLine = if ($Pos.Value -lt $Lines.Count) { $Lines[$Pos.Value].N } else { 0 }
            $lastLine = $firstLine
            while ($Pos.Value -lt $Lines.Count -and $Lines[$Pos.Value].I -gt $Indent) {
                $r = $Lines[$Pos.Value].Raw; if ($bi -lt 0) { $bi = $Lines[$Pos.Value].I }
                # blank lines inside the block were dropped from $Lines; restore them from the raw text
                for ($g = $lastLine + 1; $g -lt $Lines[$Pos.Value].N -and $buf.Count; $g++) { $buf.Add('') }
                $lastLine = $Lines[$Pos.Value].N
                $buf.Add($(if ($r.Length -ge $bi) { $r.Substring($bi) } else { $r.Trim() })); $Pos.Value++
            }
            $body = if ($style -eq '>') { ((($buf -join "`n") -replace '(?<!\n)\n(?!\n)', ' ') -replace '\n\n', "`n") } else { ($buf -join "`n") }
            $map[$key] = if ($chomp -eq '-' -or -not $buf.Count) { $body } else { $body + "`n" }
        } elseif ($val -eq '') {
            if ($Pos.Value -lt $Lines.Count -and ($Lines[$Pos.Value].I -gt $Indent -or ($Lines[$Pos.Value].I -eq $Indent -and $Lines[$Pos.Value].T.StartsWith('-')))) {
                $map[$key] = ConvertFrom-WfxYamlBlock $Lines $Pos $Lines[$Pos.Value].I
            } else { $map[$key] = $null }
        } else { $map[$key] = ConvertFrom-WfxYamlScalar (Get-WfxYamlContinuation $Lines $Pos $Indent $val) }
    }
    $map
}

# ───────────────────────────── loading rules ─────────────────────────────
function Import-WfxSigmaRule {
    <#
    .SYNOPSIS Loads Sigma rules (*.yml / *.yaml) from a folder or file and compiles the ones that can run on
    collected Windows events. Returns compiled rules; unsupported or broken rules are recorded as one gap.
    #>
    param([Parameter(Mandatory)][string[]]$Path, [int]$Max = 5000)
    $files = foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p -PathType Container) { Get-ChildItem -LiteralPath $p -Recurse -File -Include *.yml, *.yaml -ErrorAction SilentlyContinue }
        elseif (Test-Path -LiteralPath $p) { Get-Item -LiteralPath $p }
    }
    $out = [System.Collections.Generic.List[object]]::new(); $skipped = @{}
    foreach ($f in @($files | Select-Object -First $Max)) {
        $text = try { [IO.File]::ReadAllText($f.FullName) } catch { ''; continue }
        foreach ($doc in ($text -split '(?m)^---\s*$')) {
            if (-not $doc.Trim()) { continue }
            try { $y = ConvertFrom-WfxYaml $doc } catch { $skipped['parse error'] = 1 + [int]$skipped['parse error']; continue }
            if (-not ($y -is [System.Collections.IDictionary]) -or -not $y['detection']) { continue }
            $r = ConvertTo-WfxSigmaRule $y $f.FullName
            if ($r -is [string]) { $skipped[$r] = 1 + [int]$skipped[$r] } elseif ($r) { $out.Add($r) }
        }
    }
    if ($skipped.Count) {
        Add-WfxGap -Source 'sigma' -Reason ("{0} rule(s) loaded; skipped: {1}." -f $out.Count, ((@($skipped.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Value) $($_.Key)" })) -join ', ')) -Fix 'Skipped rules need data or features this tool does not collect (other products, aggregations).'
    }
    , $out.ToArray()
}

function ConvertTo-WfxSigmaRule {
    # Compiles one parsed Sigma document. Returns the rule, or a short reason string when it cannot run.
    param($Y, [string]$File)
    $ls = $Y['logsource']; if (-not $ls) { return 'no logsource' }
    if ($ls['product'] -and [string]$ls['product'] -ne 'windows') { return 'not Windows' }
    $src = if ($ls['category']) { $script:WfxSigmaSource["category:$($ls['category'])"] } elseif ($ls['service']) { $script:WfxSigmaSource["service:$($ls['service'])"] } else { $null }
    if (-not $src) { return "logsource not collected ($(if ($ls['category']) { $ls['category'] } else { $ls['service'] }))" }
    if ($Y['status'] -in 'deprecated', 'unsupported') { return 'deprecated' }
    $det = $Y['detection']
    $cond = $det['condition']; if ($cond -is [array]) { $cond = '(' + ((@($cond) | ForEach-Object { "($_)" }) -join ' or ') + ')' }
    $cond = [string]$cond
    if (-not $cond -or $cond -match '\|') { return 'aggregation / correlation' }
    $sel = [ordered]@{}
    foreach ($k in $det.Keys) {
        if ($k -in 'condition', 'timeframe') { continue }
        $c = ConvertTo-WfxSigmaSelection $det[$k]
        if ($c -is [string]) { return $c }
        $sel[$k] = $c
    }
    $tree = try { ConvertTo-WfxSigmaCondition $cond @($sel.Keys) } catch { return 'condition syntax' }
    $level = switch ([string]$Y['level']) { 'critical' { 'Critical' } 'high' { 'High' } 'medium' { 'Medium' } 'low' { 'Low' } default { 'Info' } }
    $tech = @(@($Y['tags']) | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^attack\.t\d{4}(?:\.\d{3})?$' } | ForEach-Object { $_.Substring(7).ToUpperInvariant() })
    $pre = Get-WfxSigmaPrefilter $sel $tree
    [pscustomobject]@{
        Pre = $pre
        Id = [string]$Y['id']; Title = [string]$Y['title']; Description = [string]$Y['description']; Level = $level; Technique = $tech
        Author = [string]$Y['author']; FalsePositives = @(@($Y['falsepositives']) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        References = @(@($Y['references']) | Select-Object -First 3 | ForEach-Object { [string]$_ })
        Logs = $src.Logs; Ids = $src.Ids; Category = [string]$ls['category']; File = $File; Selections = $sel; Tree = $tree
    }
}

function Get-WfxSigmaPrefilter {
    <#
    Builds one regex of literal fragments such that an event can only match the rule if its text contains at
    least one of them, so most rules are skipped with a single regex test. Derived from the condition:
    AND keeps the stronger side, OR / "1 of" unions both sides, NOT gives no constraint. Returns $null when no
    sound filter exists (regex / null / exists / field-reference / CIDR tests, or purely negative logic).
    #>
    param($Sel, $Tree)
    # A literal set is $null (no constraint) or a string array. Stronger = longer shortest literal, then fewer.
    $better = { param($a, $b) if ($null -eq $a) { return $b }; if ($null -eq $b) { return $a }
        $ma = ($a | Measure-Object Length -Minimum).Minimum; $mb = ($b | Measure-Object Length -Minimum).Minimum
        if ($ma -ne $mb) { if ($ma -gt $mb) { return $a } else { return $b } }; if ($a.Count -le $b.Count) { $a } else { $b } }
    $union = { param($a, $b) if ($null -eq $a -or $null -eq $b) { return $null }; , @(@($a) + @($b) | Select-Object -Unique) }
    $testLits = { param($tt)
        if ($null -ne $tt.Exists -or 'fieldref' -in $tt.Mods -or 'cidr' -in $tt.Mods -or 're' -in $tt.Mods -or $tt.Field -in 'EventID', 'Provider_Name', 'Channel') { return $null }
        $l = @(foreach ($v in $tt.Values) {
                if ($null -eq $v) { return $null }
                $chunks = @(([string]$v -replace '\\([*?])', '$1') -split '[*?]' | ForEach-Object { $_.TrimStart('-', '/') } | Where-Object { $_.Length -ge 2 })
                if (-not $chunks.Count) { return $null }
                ([string]@($chunks | Sort-Object Length -Descending)[0]).ToLowerInvariant()
            })
        if ($tt.All) { return , @($l | Sort-Object Length -Descending | Select-Object -First 1) }
        , $l
    }
    $selLits = { param($name)
        $acc = @(); $first = $true
        foreach ($tests in $Sel[$name]) {
            $g = $null; foreach ($tt in $tests) { $g = & $better $g (& $testLits $tt) }
            if ($null -eq $g) { return $null }
            $acc = if ($first) { $g } else { & $union $acc $g }; $first = $false
        }
        , $acc
    }
    $walk = $null
    $walk = { param($n)
        switch ($n.Op) {
            'sel' { return (& $selLits $n.Name) }
            'not' { return $null }
            'and' { return (& $better (& $walk $n.A) (& $walk $n.B)) }
            'or' { return (& $union (& $walk $n.A) (& $walk $n.B)) }
            'of' {
                $acc = $null; $first = $true
                foreach ($s in $n.Sel) { $x = & $selLits $s; if ($n.Q -eq 'all') { $acc = & $better $acc $x } else { $acc = if ($first) { $x } else { & $union $acc $x } }; $first = $false; if ($n.Q -ne 'all' -and $null -eq $acc) { return $null } }
                return $acc
            }
        }
        $null
    }
    $lits = & $walk $Tree
    if ($null -eq $lits -or -not @($lits).Count) { return $null }
    Get-WfxRx ('(?:' + ((@($lits) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')') ([Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant, Compiled')
}

function ConvertTo-WfxSigmaSelection {
    # Selection → list of alternative "AND-groups"; each group is a list of field tests. Keyword lists become
    # a single 'keywords' test.
    param($S)
    $items = if ($S -is [System.Collections.IDictionary]) { , @($S) } else { @($S) }
    if (-not @($items | Where-Object { $_ -is [System.Collections.IDictionary] }).Count) {
        return , @(, @([pscustomobject]@{ Field = '*'; Mods = @('contains'); Values = @($items | ForEach-Object { [string]$_ }); All = $false; Exists = $null }))
    }
    $alts = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $items) {
        if ($m -isnot [System.Collections.IDictionary]) { return 'mixed selection' }
        $tests = [System.Collections.Generic.List[object]]::new()
        foreach ($k in $m.Keys) {
            $parts = ([string]$k) -split '\|'; $field = $parts[0]; $mods = @($parts | Select-Object -Skip 1)
            foreach ($md in $mods) { if ($md -notin 'contains', 'startswith', 'endswith', 'all', 're', 'i', 'm', 's', 'windash', 'cidr', 'base64offset', 'base64', 'fieldref', 'exists', 'cased') { return "modifier $md" } }
            [object[]]$vals = @($m[$k])                      # @($null) is a one-element array: "field: null"
            if ($null -eq $m[$k]) { $vals = [object[]]@($null) }
            if ('base64offset' -in $mods -or 'base64' -in $mods) {
                $vals = [object[]]@(foreach ($v in $vals) { ConvertTo-WfxBase64Variant -Value ([string]$v) -Offsets:('base64offset' -in $mods) })
                $mods = @($mods | Where-Object { $_ -notin 'base64offset', 'base64' }); if ('contains' -notin $mods) { $mods += 'contains' }
            }
            $exists = if ('exists' -in $mods) { [string]$vals[0] -match '^(?i)true$' } else { $null }
            $rx = $null
            if ($null -eq $exists -and 'fieldref' -notin $mods -and 'cidr' -notin $mods) { $rx = New-Object object[] $vals.Count; for ($q = 0; $q -lt $vals.Count; $q++) { $rx[$q] = New-WfxSigmaRegex $vals[$q] $mods } }
            # Any-of tests whose values are all plain patterns collapse into one regex: one match call per test.
            $any = $null
            if ($rx -and 'all' -notin $mods -and $vals -notcontains $null -and @($rx | Where-Object { $null -eq $_ }).Count -eq 0) {
                $o = $rx[0].Options; if (@($rx | Where-Object { $_.Options -ne $o }).Count -eq 0) { $any = Get-WfxRx ('(?:' + ((@($rx) | ForEach-Object { $_.ToString() }) -join ')|(?:') + ')') ($o -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant) }
            }
            $tests.Add([pscustomobject]@{ Field = $field; Mods = $mods; Values = $vals; All = ('all' -in $mods); Exists = $exists; Rx = $rx; Any = $any })
        }
        $alts.Add($tests.ToArray())
    }
    , $alts.ToArray()
}

function ConvertTo-WfxBase64Variant {
    # The base64 forms of a string at byte offsets 0/1/2, without the unstable edge characters (Sigma base64offset).
    param([string]$Value, [switch]$Offsets)
    $b = [Text.Encoding]::UTF8.GetBytes($Value)
    if (-not $Offsets) { return [Convert]::ToBase64String($b).TrimEnd('=') }
    $start = @(0, 2, 3); $endCut = @(0, 3, 2)
    for ($i = 0; $i -lt 3; $i++) {
        $pad = New-Object byte[] ($i + $b.Length); [Array]::Copy($b, 0, $pad, $i, $b.Length)
        $e = [Convert]::ToBase64String($pad)
        $cutEnd = $endCut[($b.Length + $i) % 3]
        $s = $e.Substring($start[$i]); if ($cutEnd) { $s = $s.Substring(0, [Math]::Max(0, $s.Length - $cutEnd)) }
        $s.TrimEnd('=')
    }
}

function ConvertTo-WfxSigmaCondition {
    # Parses a Sigma condition into a small tree: @{Op='and'|'or'|'not'|'sel'|'of'; ...}.
    param([string]$Text, [string[]]$Names)
    $tokens = @([regex]::Matches($Text, '\(|\)|[^\s()]+') | ForEach-Object Value)
    $i = [ref]0
    $parseOr = $null; $parseAnd = $null; $parseNot = $null; $parseAtom = $null
    $parseAtom = {
        if ($i.Value -ge $tokens.Count) { throw 'unexpected end' }
        $t = $tokens[$i.Value]
        if ($t -eq '(') { $i.Value++; $n = & $parseOr; if ($tokens[$i.Value] -ne ')') { throw 'missing )' }; $i.Value++; return $n }
        if ($t -match '^(?:1|all|any)$' -and $i.Value + 2 -lt $tokens.Count + 1 -and $tokens[$i.Value + 1] -eq 'of') {
            $q = if ($t -eq 'all') { 'all' } else { 'any' }; $pat = $tokens[$i.Value + 2]; $i.Value += 3
            $sel = if ($pat -eq 'them') { @($Names | Where-Object { $_ -notlike '_*' }) } else { @($Names | Where-Object { $_ -like $pat }) }
            return @{ Op = 'of'; Q = $q; Sel = $sel }
        }
        if ($Names -notcontains $t) { throw "unknown selection $t" }
        $i.Value++; return @{ Op = 'sel'; Name = $t }
    }
    $parseNot = { if ($tokens[$i.Value] -eq 'not') { $i.Value++; return @{ Op = 'not'; A = (& $parseNot) } }; & $parseAtom }
    $parseAnd = { $l = & $parseNot; while ($i.Value -lt $tokens.Count -and $tokens[$i.Value] -eq 'and') { $i.Value++; $l = @{ Op = 'and'; A = $l; B = (& $parseNot) } }; $l }
    $parseOr = { $l = & $parseAnd; while ($i.Value -lt $tokens.Count -and $tokens[$i.Value] -eq 'or') { $i.Value++; $l = @{ Op = 'or'; A = $l; B = (& $parseAnd) } }; $l }
    $tree = & $parseOr
    if ($i.Value -ne $tokens.Count) { throw 'trailing tokens' }
    $tree
}

# ───────────────────────────── evaluation ─────────────────────────────
function Get-WfxSigmaField {
    param($Event, [hashtable]$Fields, [string]$Name)
    switch ($Name) {
        'EventID' { return [string]$Event.Id }
        'Provider_Name' { return [string]$Event.Provider }
        'Channel' { return [string]$Event.Log }
        'Computer' { return [string]$Event.Computer }
    }
    if ($Fields.ContainsKey($Name)) { return [string]$Fields[$Name] }
    if ($Event.Id -eq 4688 -and $script:WfxSigma4688Map[$Name] -and $Fields.ContainsKey($script:WfxSigma4688Map[$Name])) { return [string]$Fields[$script:WfxSigma4688Map[$Name]] }
    if ($Name -eq 'ParentCommandLine' -or $Name -eq 'OriginalFileName') { return $null }
    $null
}

function New-WfxSigmaRegex {
    # One compiled regex per Sigma value (all variants joined), built when the rule is loaded.
    param($Want, [string[]]$Mods)
    if ($null -eq $Want) { return $null }
    $w = [string]$Want
    if ('re' -in $Mods) {
        $o = [Text.RegularExpressions.RegexOptions]::None
        if ('i' -in $Mods) { $o = $o -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase }
        if ('m' -in $Mods) { $o = $o -bor [Text.RegularExpressions.RegexOptions]::Multiline }
        if ('s' -in $Mods) { $o = $o -bor [Text.RegularExpressions.RegexOptions]::Singleline }
        try { return (Get-WfxRx $w $o) } catch { return (Get-WfxRx '(?!)') }
    }
    $variants = @($w)
    if ('windash' -in $Mods) { $variants = @(foreach ($d in '-', '/', [string][char]0x2013, [string][char]0x2014, [string][char]0x2015) { $w -replace '(?<=^|\s)-', $d }) | Select-Object -Unique }
    $alts = foreach ($v in $variants) {
        $rx = ''; for ($k = 0; $k -lt $v.Length; $k++) {
            $c = $v[$k]
            if ($c -eq '\' -and $k + 1 -lt $v.Length -and $v[$k + 1] -in '*', '?', '\') { $rx += [regex]::Escape([string]$v[$k + 1]); $k++ }
            elseif ($c -eq '*') { $rx += '.*' } elseif ($c -eq '?') { $rx += '.' } else { $rx += [regex]::Escape([string]$c) }
        }
        $rx
    }
    $body = '(?:' + ($alts -join '|') + ')'
    $rx = if ('contains' -in $Mods) { $body } elseif ('startswith' -in $Mods) { "^$body" } elseif ('endswith' -in $Mods) { "$body`$" } else { "^$body`$" }
    $opt = if ('cased' -in $Mods) { [Text.RegularExpressions.RegexOptions]::Singleline } else { [Text.RegularExpressions.RegexOptions]'IgnoreCase, Singleline' }
    Get-WfxRx $rx $opt
}

function Test-WfxSigmaValue {
    param([AllowNull()][string]$Have, $Want, [string[]]$Mods, [hashtable]$Fields, $Rx = $null)
    if ($null -eq $Want) { return [string]::IsNullOrEmpty($Have) }
    if ($null -eq $Have) { return $false }
    if ($Rx) { try { return $Rx.IsMatch($Have) } catch { return $false } }
    $w = [string]$Want
    if ('fieldref' -in $Mods) { $w = [string]$Fields[$w] }
    $cs = 'cased' -in $Mods
    if ('re' -in $Mods) {
        $o = [Text.RegularExpressions.RegexOptions]::None
        if ('i' -in $Mods) { $o = $o -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase }
        if ('m' -in $Mods) { $o = $o -bor [Text.RegularExpressions.RegexOptions]::Multiline }
        if ('s' -in $Mods) { $o = $o -bor [Text.RegularExpressions.RegexOptions]::Singleline }
        try { return (Get-WfxRx $w $o).IsMatch($Have) } catch { return $false }
    }
    if ('cidr' -in $Mods) { return (Test-WfxCidr -Address $Have -Cidr $w) }
    $variants = @($w)
    if ('windash' -in $Mods) { $variants = @(foreach ($d in '-', '/', [string][char]0x2013, [string][char]0x2014, [string][char]0x2015) { $w -replace '(?<=^|\s)-', $d }) | Select-Object -Unique }
    foreach ($v in $variants) {
        # Sigma wildcards: * and ? (escaped with backslash). Build a regex once per value.
        $rx = ''; for ($k = 0; $k -lt $v.Length; $k++) {
            $c = $v[$k]
            if ($c -eq '\' -and $k + 1 -lt $v.Length -and $v[$k + 1] -in '*', '?', '\') { $rx += [regex]::Escape([string]$v[$k + 1]); $k++ }
            elseif ($c -eq '*') { $rx += '.*' } elseif ($c -eq '?') { $rx += '.' } else { $rx += [regex]::Escape([string]$c) }
        }
        if ('contains' -in $Mods) { $rx = ".*$rx.*" } elseif ('startswith' -in $Mods) { $rx = "$rx.*" } elseif ('endswith' -in $Mods) { $rx = ".*$rx" }
        $opt = if ($cs) { [Text.RegularExpressions.RegexOptions]::Singleline } else { [Text.RegularExpressions.RegexOptions]'IgnoreCase, Singleline' }
        if ((Get-WfxRx "^(?:$rx)$" $opt).IsMatch($Have)) { return $true }
    }
    $false
}

function Test-WfxCidr {
    param([string]$Address, [string]$Cidr)
    $p = $Cidr -split '/'; $ip = $null; $net = $null
    if (-not [Net.IPAddress]::TryParse($Address.Trim('[', ']'), [ref]$ip) -or -not [Net.IPAddress]::TryParse($p[0], [ref]$net)) { return $false }
    $a = $ip.GetAddressBytes(); $n = $net.GetAddressBytes(); if ($a.Length -ne $n.Length) { return $false }
    $bits = if ($p.Count -gt 1) { [int]$p[1] } else { $a.Length * 8 }
    for ($k = 0; $k -lt $a.Length; $k++) {
        $take = [Math]::Max(0, [Math]::Min(8, $bits - 8 * $k)); if ($take -eq 0) { break }
        $mask = (0xFF -shl (8 - $take)) -band 0xFF
        if (($a[$k] -band $mask) -ne ($n[$k] -band $mask)) { return $false }
    }
    $true
}

function Test-WfxSigmaSelection {
    param($Alts, $Event, [hashtable]$Fields)
    foreach ($tests in $Alts) {
        $ok = $true
        foreach ($t in $tests) {
            if ($t.Field -eq '*') {
                $hay = ([string]$Event.Message) + "`n" + ((@($Fields.Values) | ForEach-Object { [string]$_ }) -join "`n")
                $ok = [bool]@($t.Values | Where-Object { $hay.IndexOf([string]$_, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count
            } else {
                $have = Get-WfxSigmaField $Event $Fields $t.Field
                if ($t.Any) { $ok = ($null -ne $have) -and $t.Any.IsMatch($have) }
                elseif ($null -ne $t.Exists) { $ok = ($t.Exists -eq ($null -ne $have)) }
                elseif ($t.All) { for ($k = 0; $k -lt $t.Values.Count; $k++) { if (-not (Test-WfxSigmaValue $have $t.Values[$k] $t.Mods $Fields $(if ($t.Rx) { $t.Rx[$k] }))) { $ok = $false; break } } }
                else { $ok = $false; for ($k = 0; $k -lt $t.Values.Count; $k++) { if (Test-WfxSigmaValue $have $t.Values[$k] $t.Mods $Fields $(if ($t.Rx) { $t.Rx[$k] })) { $ok = $true; break } } }
            }
            if (-not $ok) { break }
        }
        if ($ok) { return $true }
    }
    $false
}

function Test-WfxSigmaTree {
    param($Node, $Rule, $Event, [hashtable]$Fields, [hashtable]$Memo)
    switch ($Node.Op) {
        'sel' { if (-not $Memo.ContainsKey($Node.Name)) { $Memo[$Node.Name] = Test-WfxSigmaSelection $Rule.Selections[$Node.Name] $Event $Fields }; return $Memo[$Node.Name] }
        'not' { return -not (Test-WfxSigmaTree $Node.A $Rule $Event $Fields $Memo) }
        'and' { return ((Test-WfxSigmaTree $Node.A $Rule $Event $Fields $Memo) -and (Test-WfxSigmaTree $Node.B $Rule $Event $Fields $Memo)) }
        'or' { return ((Test-WfxSigmaTree $Node.A $Rule $Event $Fields $Memo) -or (Test-WfxSigmaTree $Node.B $Rule $Event $Fields $Memo)) }
        'of' {
            foreach ($s in $Node.Sel) {
                $r = Test-WfxSigmaTree @{ Op = 'sel'; Name = $s } $Rule $Event $Fields $Memo
                if ($Node.Q -eq 'any' -and $r) { return $true }
                if ($Node.Q -eq 'all' -and -not $r) { return $false }
            }
            return ($Node.Q -eq 'all' -and @($Node.Sel).Count -gt 0)
        }
    }
    $false
}

function Invoke-WfxSigmaAnalyzer {
    <# Runs compiled Sigma rules over collected events. At most -MaxPerRule findings per rule. #>
    param([object[]]$Event, [object[]]$Rule, [string]$HostName = '', [int]$MaxPerRule = 25)
    $findings = [System.Collections.Generic.List[object]]::new()
    $events = @($Event | Where-Object { $_ })
    if (-not $events.Count -or -not @($Rule).Count) { return , $findings.ToArray() }
    # Prepare each event once: field table, searchable text, and a signature so identical events
    # (the same command line run 500 times) are evaluated once per rule.
    $prep = foreach ($e in $events) {
        $f = @{}; $fl = $e.Fields
        if ($fl -is [System.Collections.IDictionary]) { foreach ($k in $fl.Keys) { $f[$k] = $fl[$k] } } elseif ($fl) { foreach ($p in $fl.PSObject.Properties) { $f[$p.Name] = $p.Value } }
        $vals = @($f.Keys | Sort-Object | Where-Object { $_ -notmatch '(?i)ProcessId$|ProcessGuid$|^UtcTime$|^RecordId$|LogonId$|^SequenceNumber$|^EventRecordID$|^TimeCreated$' } | ForEach-Object { "$_=$($f[$_])" })
        [pscustomobject]@{ E = $e; F = $f; Text = (([string]$e.Message) + "`n" + (($f.Values | ForEach-Object { [string]$_ }) -join "`n")); Sig = "$($e.Log)|$($e.Id)|$($vals -join '|')"; Log = [string]$e.Log; Id = [int]$e.Id }
    }
    $uniq = [ordered]@{}
    foreach ($pe in $prep) { if ($uniq.Contains($pe.Sig)) { $uniq[$pe.Sig].N++ } else { $pe | Add-Member -NotePropertyName N -NotePropertyValue 1; $uniq[$pe.Sig] = $pe } }
    $byLog = @{}; foreach ($pe in $uniq.Values) { if (-not $byLog.ContainsKey($pe.Log)) { $byLog[$pe.Log] = [System.Collections.Generic.List[object]]::new() }; $byLog[$pe.Log].Add($pe) }
    foreach ($r in $Rule) {
        $hits = 0
        $cands = foreach ($lg in $r.Logs) { if ($byLog[$lg]) { $byLog[$lg] } }
        foreach ($pe in $cands) {
            if ($r.Ids.Count -and $r.Ids -notcontains $pe.Id) { continue }
            if ($r.Pre -and -not $r.Pre.IsMatch($pe.Text)) { continue }
            if (-not (Test-WfxSigmaTree $r.Tree $r $pe.E $pe.F @{})) { continue }
            $e = $pe.E; $f = $pe.F
            $hits++
            $what = @('CommandLine', 'ScriptBlockText', 'TargetObject', 'TargetFilename', 'QueryName', 'ImageLoaded', 'DestinationIp', 'ServiceName', 'TargetUserName') | Where-Object { $f[$_] } | Select-Object -First 1
            $img = [string](Get-WfxSigmaField $e $f 'Image')
            $ev = [ordered]@{ Event = "$($e.Log) $($e.Id) record $($e.RecordId)"; Time = $e.TimeCreated; Image = $img; SameEvents = $pe.N }
            if ($what) { $ev[$what] = Get-WfxShortText ([string]$f[$what]) 600 }
            $ev['Rule'] = "$($r.Title) [$($r.Id)]"; $ev['RuleFile'] = (Split-Path -Leaf $r.File)
            $findings.Add((New-WfxFinding -Id ('SIGMA-' + $(if ($r.Id) { $r.Id.Substring(0, [Math]::Min(8, $r.Id.Length)) } else { 'RULE' })) -Title "Sigma: $($r.Title)" -Severity $r.Level -Confidence 'Medium' -Category 'Sigma' `
                        -Technique $r.Technique -Description ("{0}{1}" -f $r.Description, $(if ($r.Author) { " (Sigma rule by $($r.Author).)" })) `
                        -Recommendation $(if ($r.FalsePositives.Count) { "Known false positives: $($r.FalsePositives -join '; '). Check the event against these before acting." } else { 'Review the event in context.' }) `
                        -Entity ("sigma:{0}:{1}" -f $r.Id, $(if ($img) { $img.ToLowerInvariant() } else { $e.RecordId })) -HostName $HostName -Time $e.TimeCreated -Source "sigma:$(Split-Path -Leaf $r.File)" -Evidence $ev))
            if ($hits -ge $MaxPerRule) { break }
        }
    }
    , $findings.ToArray()
}

function Get-WfxSigmaRuleSet {
    <# Loads (once per session and path list) the Sigma rules in -Path. #>
    param([string[]]$Path)
    $key = (@($Path) -join '|')
    if ($script:WfxSigmaCache -and $script:WfxSigmaCache.Key -eq $key) { return , $script:WfxSigmaCache.Rules }
    $rules = Import-WfxSigmaRule -Path $Path
    $script:WfxSigmaCache = @{ Key = $key; Rules = $rules }
    , $rules
}

function Set-WfxSigmaEventQuery {
    <#
    .SYNOPSIS Makes event collection also read the logs / event IDs the loaded Sigma rules need (for example
    Security 4662 or 5145), so the rules have data to run on. Extra queries are capped like the built-in ones.
    #>
    param([object[]]$Rule)
    $have = @{}; foreach ($q in $script:WfxEventQuery) { foreach ($i in $q.Ids) { $have["$($q.Log)|$i"] = $true } }
    $want = @{}
    foreach ($r in @($Rule)) {
        $ids = @($r.Ids)
        if (-not $ids.Count) {
            $ids = @(foreach ($s in $r.Selections.Values) { foreach ($g in $s) { foreach ($tt in $g) { if ($tt.Field -eq 'EventID') { foreach ($v in $tt.Values) { $n = 0; if ([int]::TryParse([string]$v, [ref]$n)) { $n } } } } } })
        }
        foreach ($lg in $r.Logs) { foreach ($i in $ids) { if (-not $have["$lg|$i"]) { if (-not $want.ContainsKey($lg)) { $want[$lg] = New-Object System.Collections.Generic.HashSet[int] }; [void]$want[$lg].Add($i) } } }
    }
    $script:WfxSigmaEventQuery = @(foreach ($lg in $want.Keys) {
            $all = @($want[$lg] | Sort-Object)
            for ($k = 0; $k -lt $all.Count; $k += 20) { @{ Log = $lg; Ids = @($all[$k..([Math]::Min($k + 20, $all.Count) - 1)]); Max = 3000; Msg = $false } }
        })
    @($script:WfxSigmaEventQuery).Count
}
