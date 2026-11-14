# WinForensicX — core engine: findings, scoring, redaction, logging, case management, helpers.
# Compatible with Windows PowerShell 5.1 and PowerShell 7+. Analysis helpers here are
# platform-neutral so analyzers can run (and be tested) on any OS.

$script:WfxVersion = '3.0.0'
$script:WfxSeverities = @('Info', 'Low', 'Medium', 'High', 'Critical')
$script:WfxSeverityWeight = @{ Info = 0; Low = 2; Medium = 5; High = 10; Critical = 20 }
$script:WfxConfidenceFactor = @{ Low = 0.5; Medium = 0.8; High = 1.0 }
# Categories that describe hardening / visibility rather than evidence of compromise. They are scored
# separately (Posture score) so a well-run but un-hardened host is not reported as "compromised".
$script:WfxPostureCategories = @('Posture', 'Visibility')
$script:WfxCase = $null
$script:WfxGaps = New-Object System.Collections.Generic.List[object]
$script:WfxQuiet = $false
# Every built-in regex that runs over collected (potentially attacker-controlled) text uses this timeout.
$script:WfxRegexTimeout = [TimeSpan]::FromMilliseconds(250)
$script:WfxRxCache = @{}

# ───────────────────────────── platform ─────────────────────────────
function Test-WfxWindows {
    if ($PSVersionTable.PSVersion.Major -le 5) { return $true }
    return [bool]$IsWindows
}

function Test-WfxAdmin {
    if (-not (Test-WfxWindows)) { return $false }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ───────────────────────────── safe regex ─────────────────────────────
function Get-WfxRx {
    <# Returns a cached Regex with the global match timeout. Use for every pattern applied to collected data. #>
    param([Parameter(Mandatory)][string]$Pattern, [System.Text.RegularExpressions.RegexOptions]$Options = 'None')
    $key = "$([int]$Options)|$Pattern"
    if (-not $script:WfxRxCache.ContainsKey($key)) {
        $script:WfxRxCache[$key] = New-Object System.Text.RegularExpressions.Regex($Pattern, $Options, $script:WfxRegexTimeout)
    }
    $script:WfxRxCache[$key]
}

function Get-WfxRxMatches {
    <# All matches of a pattern; on a regex timeout returns what was found so far (never hangs). #>
    param([string]$Pattern, [AllowEmptyString()][string]$Text)
    # Emits Match objects to the pipeline (wrap the call in @() to count them).
    $list = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrEmpty($Text)) { return }
    try { foreach ($m in (Get-WfxRx $Pattern).Matches($Text)) { $list.Add($m) } }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { Write-Verbose "regex timeout: $Pattern" }
    $list.ToArray()
}

function Test-WfxRxMatch {
    param([string]$Pattern, [AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    try { return (Get-WfxRx $Pattern).IsMatch($Text) } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return $false }
}

# ───────────────────────────── time ─────────────────────────────
function ConvertTo-WfxDateTime {
    <# Parses a DateTime / ISO-8601 string / legacy "/Date(ms)/" value into a UTC DateTime. $null if unparseable. #>
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    $s = [string]$Value
    $m = [regex]::Match($s, '^/?\\?/?Date\((-?\d+)')
    if ($m.Success) { return [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddMilliseconds([double]$m.Groups[1].Value) }
    $dto = [System.DateTimeOffset]::MinValue
    if ([System.DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $dto.UtcDateTime }
    return $null
}

function ConvertTo-WfxUtcString {
    <# Normalizes any timestamp to an ISO-8601 UTC string ("...Z"). Collectors store ONLY this form, so bundles
       are identical across PowerShell 5.1 / 7 and re-analysis never shifts a timeline by a timezone. #>
    param($Value)
    $d = ConvertTo-WfxDateTime $Value
    if ($null -eq $d) { return $(if ($null -eq $Value) { '' } else { [string]$Value }) }
    return $d.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-WfxUtcNow { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture) }

# ───────────────────────────── console ─────────────────────────────
function Write-WfxConsole {
    <# Single place for interactive console output, so -Quiet and colors are consistent. #>
    param(
        [Parameter(Position = 0)][AllowEmptyString()][string]$Message = '',
        [ValidateSet('Info', 'Ok', 'Warn', 'Bad', 'Head', 'Dim', 'Plain')][string]$Kind = 'Plain',
        [switch]$NoNewline
    )
    if ($script:WfxQuiet) { return }
    $color = @{ Info = 'Cyan'; Ok = 'Green'; Warn = 'Yellow'; Bad = 'Red'; Head = 'White'; Dim = 'DarkGray'; Plain = 'Gray' }[$Kind]
    Write-Host $Message -ForegroundColor $color -NoNewline:$NoNewline
}

function Write-WfxSection {
    param([string]$Title)
    Write-WfxConsole ''
    Write-WfxConsole ("── {0} {1}" -f $Title, ('─' * [Math]::Max(3, 66 - $Title.Length))) -Kind Head
}

# ───────────────────────────── audit log & gaps ─────────────────────────────
function Write-WfxLog {
    <# Appends one JSON line to the OPEN case's audit log. Once a case is completed (manifest written) it is
       closed and nothing is ever appended again — so a later command can never invalidate its manifest. #>
    param([string]$Event, [hashtable]$Data = @{})
    $case = $script:WfxCase
    if (-not $case -or -not $case.Path -or $case.Closed) { return }
    $entry = [ordered]@{ time = (Get-WfxUtcNow); event = $Event }
    foreach ($k in $Data.Keys) { $entry[$k] = $Data[$k] }
    try {
        $line = ($entry | ConvertTo-Json -Compress -Depth 5)
        Add-Content -LiteralPath (Join-Path $case.Path 'audit.log') -Value $line -Encoding UTF8
    } catch { Write-Verbose "audit log write failed: $_" }
}

function Add-WfxGap {
    <# Records something the tool could not collect or analyze — shown in the report so absence of findings is never mistaken for absence of evidence. #>
    param([string]$Source, [string]$Reason, [string]$Fix = '')
    $script:WfxGaps.Add([pscustomobject]@{ Source = $Source; Reason = $Reason; Fix = $Fix })
    Write-WfxLog -Event 'gap' -Data @{ source = $Source; reason = $Reason }
    Write-Verbose "[$Source] gap: $Reason"
}

function Expand-WfxRecord {
    <#
    .SYNOPSIS Turns collector output into a stream of records.
    .DESCRIPTION Collectors and analyzers return their results as ONE array object (", @(...)") so that callers
    which assign them always get an array. Piped straight into Select-Object / Where-Object that single array
    object is treated as one record (one blank row). Every pipeline that consumes collector output starts with
    "Get-WfxXxx | Expand-WfxRecord | ...". Nulls are dropped; strings and dictionaries are never split.
    #>
    param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        if ($null -eq $InputObject) { return }
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string] -and $InputObject -isnot [System.Collections.IDictionary]) {
            foreach ($x in $InputObject) { if ($null -ne $x) { $x } }
        } else { $InputObject }
    }
}

function Get-WfxGap { , $script:WfxGaps.ToArray() }
function Clear-WfxGap { $script:WfxGaps.Clear() }

function Invoke-WfxStep {
    <# Runs one collector or analyzer step; failures become recorded gaps instead of aborting the triage. #>
    param([string]$Name, [scriptblock]$Script, $Default = @())
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $out = & $Script
        Write-WfxLog -Event 'step' -Data @{ name = $Name; ms = $sw.ElapsedMilliseconds; ok = $true }
        return $out
    } catch {
        Add-WfxGap -Source $Name -Reason $_.Exception.Message
        Write-WfxLog -Event 'step' -Data @{ name = $Name; ms = $sw.ElapsedMilliseconds; ok = $false; error = $_.Exception.Message }
        return $Default
    }
}

# ───────────────────────────── findings ─────────────────────────────
function New-WfxFinding {
    <#
    .SYNOPSIS Creates a normalized finding. Every analyzer returns these.
    .PARAMETER Id         Stable rule identifier (e.g. LOTL-CERTUTIL-DOWNLOAD). Used for dedupe, tuning and allowlists.
    .PARAMETER Entity     What the finding is about, in a stable form ("process:4412:powershell.exe", "file:C:\x.ps1").
    .PARAMETER Technique  ATT&CK ids. Anything that is not a well-formed id (T1234 / T1234.567) is dropped, so a
                          malformed or malicious custom rule pack can't inject markup into reports.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')][string]$Severity = 'Medium',
        [ValidateSet('Low', 'Medium', 'High')][string]$Confidence = 'Medium',
        [Parameter(Mandatory)][string]$Category,
        [string[]]$Technique = @(),
        [string]$Description = '',
        [string]$Entity = '',
        $Evidence = $null,
        [string]$Recommendation = '',
        [string]$HostName = '',
        $Time = $null,
        [string]$Source = ''
    )
    $weight = $script:WfxSeverityWeight[$Severity] * $script:WfxConfidenceFactor[$Confidence]
    $t = $null
    if ($Time) { $t = ConvertTo-WfxUtcString $Time }
    [pscustomobject]@{
        PSTypeName     = 'WinForensicX.Finding'
        Id             = $Id
        Title          = $Title
        Severity       = $Severity
        Confidence     = $Confidence
        Score          = [Math]::Round($weight, 1)
        Category       = $Category
        Technique      = @($Technique | Where-Object { $_ -and ([string]$_ -match '^T\d{4}(?:\.\d{3})?$') })
        Description    = $Description
        Entity         = $Entity
        Evidence       = $Evidence
        Recommendation = $Recommendation
        Host           = $HostName
        Time           = $t
        Source         = $Source
    }
}

function Merge-WfxFinding {
    <# Dedupes findings by Host + Id + Entity (keeps the highest-scoring one and counts repeats) and sorts by severity. #>
    param([object[]]$Finding)
    $byKey = [ordered]@{}
    foreach ($f in @($Finding | Where-Object { $_ })) {
        $key = "$($f.Host)|$($f.Id)|$($f.Entity)"
        if ($byKey.Contains($key)) {
            $prev = $byKey[$key]
            $prev | Add-Member -NotePropertyName Occurrences -NotePropertyValue ([int]$prev.Occurrences + 1) -Force
            if ($f.Score -gt $prev.Score) { $f | Add-Member -NotePropertyName Occurrences -NotePropertyValue $prev.Occurrences -Force; $byKey[$key] = $f }
        } else {
            if (-not $f.PSObject.Properties['Occurrences']) { $f | Add-Member -NotePropertyName Occurrences -NotePropertyValue 1 -Force }
            $byKey[$key] = $f
        }
    }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    , @($byKey.Values | Sort-Object @{ Expression = { $sevRank[$_.Severity] } }, @{ Expression = { $_.Score }; Descending = $true }, Title)
}

function Get-WfxRiskScore {
    <#
    .SYNOPSIS Score 0–100 over a set of findings. Combines them as independent evidence: risk = 1 - Π(1 - wᵢ/40).
    One high-confidence Critical ≈ 50, two ≈ 75; many Lows can't add up to a Critical.
    Invoke-WfxAnalyze calls this twice: once over compromise indicators (Risk) and once over
    hardening/visibility findings (Posture).
    #>
    param([object[]]$Finding)
    $p = 1.0
    foreach ($f in @($Finding | Where-Object { $_ })) {
        $w = [Math]::Min(39.0, [double]$f.Score)
        $p *= (1.0 - $w / 40.0)
    }
    $score = [int][Math]::Round(100 * (1 - $p))
    $level = if ($score -ge 75) { 'Critical' } elseif ($score -ge 50) { 'High' } elseif ($score -ge 20) { 'Elevated' } else { 'Low' }
    [pscustomobject]@{ Score = $score; Level = $level }
}

function Test-WfxPostureFinding { param($Finding) return ($script:WfxPostureCategories -contains [string]$Finding.Category) }

function Get-WfxSeveritySummary {
    param([object[]]$Finding)
    $o = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $o[$s] = @($Finding | Where-Object { $_.Severity -eq $s }).Count }
    [pscustomobject]$o
}

# ───────────────────────────── allowlist ─────────────────────────────
function Read-WfxAllowlist {
    <#
    .SYNOPSIS Loads an allowlist (JSON array) of known-good findings to suppress.
    Each entry: { "Id": "PERSIST-*", "Entity": "autostart:RunKey:OneDrive", "Host": "*", "Reason": "corporate standard" }.
    Id/Entity/Host accept -like wildcards; Id is required; a Reason is strongly recommended (it is shown in the report).
    #>
    param([string]$Path)
    if (-not $Path) { return , @() }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Allowlist not found: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $entries = foreach ($e in @($raw)) {
        $id = [string](Get-WfxValue $e 'Id' '')
        if (-not $id) { continue }
        [pscustomobject]@{ Id = $id; Entity = [string](Get-WfxValue $e 'Entity' '*'); Host = [string](Get-WfxValue $e 'Host' '*'); Reason = [string](Get-WfxValue $e 'Reason' '') }
    }
    , @($entries)
}

function Split-WfxAllowlisted {
    <# Splits findings into Kept and Suppressed according to the allowlist. Suppressed findings are never
       silently dropped — they are reported separately with the matching reason. #>
    param([object[]]$Finding, [object[]]$Allowlist)
    $kept = New-Object System.Collections.Generic.List[object]
    $supp = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($Finding | Where-Object { $_ })) {
        $hit = $null
        foreach ($a in @($Allowlist)) {
            if ($f.Id -like $a.Id -and [string]$f.Entity -like $a.Entity -and [string]$f.Host -like $a.Host) { $hit = $a; break }
        }
        if ($hit) {
            $supp.Add([pscustomobject]@{ Id = $f.Id; Title = $f.Title; Severity = $f.Severity; Entity = $f.Entity; Host = $f.Host; Reason = $hit.Reason; Rule = "$($hit.Id) / $($hit.Entity)" })
        } else { $kept.Add($f) }
    }
    [pscustomobject]@{ Kept = $kept.ToArray(); Suppressed = $supp.ToArray() }
}

# ───────────────────────────── text & entropy ─────────────────────────────
function Get-WfxEntropy {
    <# Shannon entropy (bits per symbol) of a string or byte array. #>
    param([Parameter(Mandatory)][AllowEmptyString()]$InputObject)
    if ($null -eq $InputObject) { return 0.0 }
    $n = 0
    if ($InputObject -is [byte[]]) {
        $counts = New-Object 'int[]' 256
        foreach ($b in $InputObject) { $counts[$b]++ }
        $n = $InputObject.Length
        if ($n -eq 0) { return 0.0 }
        $h = 0.0
        foreach ($v in $counts) { if ($v) { $p = $v / $n; $h -= $p * [Math]::Log($p, 2) } }
        return [Math]::Round($h, 3)
    }
    $counts = @{}
    foreach ($c in ([string]$InputObject).ToCharArray()) { $counts[$c] = 1 + [int]$counts[$c]; $n++ }
    if ($n -eq 0) { return 0.0 }
    $h = 0.0
    foreach ($v in $counts.Values) { $p = $v / $n; $h -= $p * [Math]::Log($p, 2) }
    [Math]::Round($h, 3)
}

function Format-WfxSecret {
    <# Shows only enough of a secret to identify it: at most 4 leading characters + length. Never the value. #>
    param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    $keep = [Math]::Min(4, [Math]::Floor($Value.Length / 4))
    return ('{0}…[redacted, {1} chars]' -f $Value.Substring(0, $keep), $Value.Length)
}

$script:WfxSecretPatterns = @(
    @{ Name = 'Anthropic API key'; Pattern = 'sk-ant-[A-Za-z0-9_\-]{20,}' }
    @{ Name = 'OpenRouter API key'; Pattern = 'sk-or-v1-[A-Fa-f0-9]{48,}' }
    @{ Name = 'OpenAI API key'; Pattern = 'sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}' }
    @{ Name = 'Google API key'; Pattern = 'AIza[0-9A-Za-z_\-]{35}' }
    @{ Name = 'Hugging Face token'; Pattern = 'hf_[A-Za-z0-9]{30,}' }
    @{ Name = 'Groq API key'; Pattern = 'gsk_[A-Za-z0-9]{40,}' }
    @{ Name = 'xAI API key'; Pattern = 'xai-[A-Za-z0-9]{40,}' }
    @{ Name = 'Replicate token'; Pattern = 'r8_[A-Za-z0-9]{30,}' }
    @{ Name = 'AWS access key id'; Pattern = '(?:AKIA|ASIA)[0-9A-Z]{16}' }
    @{ Name = 'GitHub token'; Pattern = 'gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}' }
    @{ Name = 'Slack token'; Pattern = 'xox[abprs]-[A-Za-z0-9\-]{10,}' }
    @{ Name = 'Stripe secret key'; Pattern = '[rs]k_live_[A-Za-z0-9]{20,}' }
    @{ Name = 'Azure storage key'; Pattern = 'AccountKey=[A-Za-z0-9+/=]{60,}' }
    @{ Name = 'JSON Web Token'; Pattern = 'eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}' }
    @{ Name = 'Private key block'; Pattern = '-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----' }
)

function Find-WfxSecret {
    <# Finds well-known secret formats in text. Returns type + redacted value + line number; never the secret. #>
    param([AllowEmptyString()][string]$Text)
    $out = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrEmpty($Text)) { return , $out.ToArray() }
    $lines = $Text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $seen = @{}
        foreach ($p in $script:WfxSecretPatterns) {
            foreach ($m in (Get-WfxRxMatches $p.Pattern $lines[$i])) {
                if ($seen.ContainsKey($m.Index)) { continue }   # one label per match position
                $seen[$m.Index] = $true
                $out.Add([pscustomobject]@{ Type = $p.Name; Line = $i + 1; Redacted = (Format-WfxSecret $m.Value) })
            }
        }
    }
    , $out.ToArray()
}

$script:WfxRedactRules = @(
    # key=value / "key value" credentials. The key name may be embedded in a larger identifier
    # (aws_secret_access_key, db-password, MYSQL_PWD), so allow an identifier prefix/suffix.
    , @('(?i)([A-Za-z0-9_.\-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|apikey|client[_-]?secret|access[_-]?key|token)[A-Za-z0-9_.\-]{0,20})(\s*[:=]\s*|\s+)("[^"]*"|''[^'']*''|[^\s;,&]+)', '$1$2***')
    # mysql/openssl-style concatenated password flag: -pSecret  (but not a lone -p)
    , @('(?i)(\s-p)(?!assword\b)([^\s]{2,})', '$1***')
    , @('(?i)(-(?:Password|Pass|Secret|Token|Key)\s+)("[^"]*"|''[^'']*''|\S+)', '$1***')
    , @('(?i)(/p(?:ass(?:word)?)?:)(\S+)', '$1***')
    , @('(?i)(\bnet1?(?:\.exe)?\s+user\s+[^\s/]+\s+)([^\s/][^\s]*)', '$1***')
    , @('(?i)(\bschtasks[^\n]*\s/rp\s+)(\S+)', '$1***')
    , @('(?i)(https?://[^:/\s]+:)([^@\s]+)(@)', '$1***$3')
)

$script:WfxRedactHint = '(?i)sk-|aiza|hf_|gsk_|xai-|r8_|akia|asia|gh[pousr]_|github_pat|xox|_live_|eyj|begin|pass|pwd|secret|key|token|\s-p|/p|net1?(?:\.exe)?\s+user|schtasks|://'

function Protect-WfxText {
    <# Redacts secrets and key=value credentials in free text before it is stored, displayed or reported.
       FAIL-CLOSED: if any redaction regex times out on hostile input, the text is withheld entirely. #>
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    # Cheap pre-filter: every pattern below needs one of these literals. Text without any of them is
    # returned unchanged without running ~20 regexes (this matters for large artifact sets).
    if (-not (Get-WfxRx $script:WfxRedactHint).IsMatch($Text)) { return $Text }
    $t = $Text
    try {
        foreach ($p in $script:WfxSecretPatterns) { $t = (Get-WfxRx $p.Pattern).Replace($t, [System.Text.RegularExpressions.MatchEvaluator] { param($m) Format-WfxSecret $m.Value }) }
        foreach ($r in $script:WfxRedactRules) { $t = (Get-WfxRx $r[0]).Replace($t, $r[1]) }
    } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        return "[content withheld: redaction timed out on $($Text.Length) chars]"
    }
    return $t
}

# ───────────────────────────── encoded commands ─────────────────────────────
function ConvertFrom-WfxBase64Text {
    <# Decodes base64 to text WITHOUT executing anything. Tries UTF-16LE (PowerShell -EncodedCommand), then
       gzip/deflate-wrapped payloads, then UTF-8. Returns $null if it isn't sensibly decodable. #>
    param([string]$Base64, [int]$MaxBytes = 1048576)
    if ([string]::IsNullOrWhiteSpace($Base64)) { return $null }
    $b = ($Base64 -replace '\s', '').Trim('"', "'")
    if ($b.Length -lt 8 -or $b.Length -gt ($MaxBytes * 2)) { return $null }
    $b = $b.PadRight($b.Length + ((4 - $b.Length % 4) % 4), '=')
    try { $bytes = [Convert]::FromBase64String($b) } catch { return $null }
    $printable = { param($s) if (-not $s) { return 0 }; @($s.ToCharArray() | Where-Object { [int]$_ -ge 32 -or $_ -in "`r", "`n", "`t" }).Count / [double]$s.Length }
    # gzip (1f 8b) or raw deflate commonly wrapped inside "FromBase64String | GzipStream" stagers
    if ($bytes.Length -gt 2 -and $bytes[0] -eq 0x1f -and $bytes[1] -eq 0x8b) {
        try {
            $ms = New-Object IO.MemoryStream(, $bytes)
            $gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
            $sr = New-Object IO.StreamReader($gz)
            $buf = New-Object char[] $MaxBytes; $n = $sr.Read($buf, 0, $MaxBytes); $sr.Dispose()
            return ('[gzip] ' + (New-Object string($buf, 0, $n)))
        } catch {}
    }
    # UTF-16LE of ASCII text has a 0x00 in (almost) every odd byte — that is the -EncodedCommand case.
    $zeroOdd = 0; for ($i = 1; $i -lt $bytes.Length; $i += 2) { if ($bytes[$i] -eq 0) { $zeroOdd++ } }
    $u16ok = $bytes.Length -ge 4 -and ($bytes.Length % 2) -eq 0
    if ($u16ok -and $zeroOdd -ge ($bytes.Length / 2) * 0.6) {
        $u16 = [Text.Encoding]::Unicode.GetString($bytes)
        if ((& $printable $u16) -ge 0.95) { return $u16 }
    }
    $u8 = [Text.Encoding]::UTF8.GetString($bytes)
    if ((& $printable $u8) -ge 0.95) { return $u8 }
    if ($u16ok) { $u16 = [Text.Encoding]::Unicode.GetString($bytes); if ((& $printable $u16) -ge 0.95) { return $u16 } }
    return $null
}

function Get-WfxEncodedCommandPayload {
    <# Extracts and decodes the -EncodedCommand / -enc / -e argument of a PowerShell command line. Text only. #>
    param([AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $m = [regex]::Match($CommandLine, '(?i)(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["'']?([A-Za-z0-9+/=]{8,})')
    if (-not $m.Success) { return $null }
    ConvertFrom-WfxBase64Text $m.Groups[1].Value
}

# ───────────────────────────── paths & command lines ─────────────────────────────
function Get-WfxImagePath {
    <# Extracts the executable path from a command line / service ImagePath / Run value. #>
    param([AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $c = $c -replace '^\\\?\?\\', ''
    if ($env:SystemRoot) { $c = $c -replace '^(?i)\\SystemRoot\\', "$env:SystemRoot\" }
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|scr|dll|msi|cpl|sys))(?=\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Get-WfxShortText {
    <# One-line, length-capped version of a text for tables. #>
    param([AllowEmptyString()][string]$Text, [int]$Max = 120)
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max - 1) + '…' }
    return $t
}

function Get-WfxLeaf {
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return '' }
    return ($Path -split '[\\/]')[-1]
}

function Test-WfxUserWritablePath {
    <# True for locations ordinary users can write to — where malware stages itself. #>
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant() -replace '/', '\'
    if (Test-WfxTrustedVendorPath $p) { return $false }
    return [bool]($p -match '\\appdata\\|\\temp\\|\\tmp\\|\\downloads\\|\\desktop\\|\\documents\\|\\users\\public\\|\\programdata\\|\\windows\\temp\\|\\windows\\tasks\\|\\windows\\tracing\\|\\perflogs\\|\\\$recycle\.bin\\|\\recycler\\|\\inetpub\\temp|\\windows\\debug\\|\\spool\\drivers\\color\\|\\music\\|\\videos\\|\\pictures\\' -or
        $p -match '^[a-z]:\\[^\\]+\.(exe|dll|ps1|bat|vbs|js|hta)$')
}

function Test-WfxTrustedVendorPath {
    <# Admin-only-writable vendor locations that happen to sit under ProgramData (Defender's platform folder,
       Windows Defender ATP). These are ACL-protected, so treating them as user-writable only creates noise. #>
    param([AllowEmptyString()][string]$Path)
    if (-not $Path) { return $false }
    return [bool]($Path -match '(?i)\\programdata\\microsoft\\(?:windows defender(?: advanced threat protection)?|defender)\\(?:platform|scans)?\\?')
}

function Test-WfxSystemPath {
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [bool]($Path -match '(?i)^(?:[a-z]:)?\\windows\\(system32|syswow64|winsxs)\\' -or $Path -match '(?i)^\\systemroot\\system32\\')
}

function Test-WfxTrustedSignature {
    param([AllowEmptyString()][string]$Status)
    return ($Status -in @('Valid', 'Signed', 'Trusted'))
}

function Test-WfxPrivateIp {
    param([AllowEmptyString()][string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $true }
    $a = $Ip.Trim('[', ']')
    if ($a -match '^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|255\.)') { return $true }
    if ($a -match '(?i)^(?:::1?$|::$|fe8|fe9|fea|feb|fc|fd|ff)') { return $true }
    if ($a -match '(?i)^::ffff:(.+)$') { return (Test-WfxPrivateIp $Matches[1]) }
    return $false
}

function ConvertTo-WfxArray {
    <# PS 5.1-safe: always returns an array (handles $null and single objects). #>
    param($InputObject)
    if ($null -eq $InputObject) { return , @() }
    return , @($InputObject)
}

function ConvertTo-WfxInt {
    <# Integer from saved evidence that may be malformed ("x", "", $null, "4625 "): never throws, returns -Default. #>
    param($Value, [int]$Default = 0)
    $n = 0
    if ($null -ne $Value -and [int]::TryParse(([string]$Value).Trim(), [ref]$n)) { return $n }
    return $Default
}

function Get-WfxValue {
    <# Reads a property that may not exist without tripping strict mode. #>
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] } else { return $Default }
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

# ───────────────────────────── tool integrity ─────────────────────────────
function Get-WfxToolIntegrity {
    <# SHA-256 of every file the tool loaded (module files or the single-file build) plus any custom rule
       packs, so a manifest records exactly which code and which rules produced a case. #>
    $files = New-Object System.Collections.Generic.List[string]
    if ($script:WfxSingleFilePath -and (Test-Path -LiteralPath $script:WfxSingleFilePath)) { $files.Add($script:WfxSingleFilePath) }
    elseif ($script:WfxModuleRoot -and (Test-Path -LiteralPath $script:WfxModuleRoot)) {
        Get-ChildItem -LiteralPath $script:WfxModuleRoot -Recurse -File -Include *.ps1, *.psm1, *.psd1, *.json -ErrorAction SilentlyContinue |
            Sort-Object FullName | ForEach-Object { $files.Add($_.FullName) }
    }
    foreach ($src in @($script:WfxRuleSources)) { if ($src -and -not $files.Contains($src)) { $files.Add($src) } }
    $entries = foreach ($f in $files) {
        try { [ordered]@{ file = (Get-WfxLeaf $f); path = $f; sha256 = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant() } } catch {}
    }
    $joined = (@($entries) | ForEach-Object { "$($_.path)|$($_.sha256)" }) -join "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    $combined = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($joined)) | ForEach-Object { $_.ToString('x2') })
    [ordered]@{ version = $script:WfxVersion; combinedSha256 = $combined; files = @($entries) }
}

# ───────────────────────────── case management ─────────────────────────────
function Get-WfxDefaultOutputRoot {
    if (Test-WfxWindows) {
        $d = [Environment]::GetFolderPath('Desktop')
        if ($d) { return (Join-Path $d 'WinForensicX') }
    }
    if ($HOME) { return (Join-Path $HOME 'WinForensicX') }
    return (Join-Path (Get-Location) 'WinForensicX')
}

function New-WfxCase {
    <# Creates the case folder (outputs, raw evidence, audit log) and records who ran what, where, when, how. #>
    param([string]$OutputPath = '', [string]$Name = '', [string]$HostName = '', [string]$Mode = 'local', [hashtable]$Parameters = @{})
    if ($script:WfxCase -and -not $script:WfxCase.Closed) { Write-Verbose "Closing previous unfinished case $($script:WfxCase.Path)"; $script:WfxCase.Closed = $true }
    if (-not $HostName) { $HostName = [Environment]::MachineName }
    if (-not $OutputPath) { $OutputPath = Get-WfxDefaultOutputRoot }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
    $safeHost = $HostName -replace '[^A-Za-z0-9._-]', '_'
    $folder = if ($Name) { ($Name -replace '[^A-Za-z0-9._-]', '_') + "_$safeHost`_$stamp" } else { "WFX_$safeHost`_$stamp" }
    $path = Join-Path $OutputPath $folder
    $n = 1; while (Test-Path -LiteralPath $path) { $path = Join-Path $OutputPath "$folder-$n"; $n++ }
    # Fail fast with one clear message: every later step writes into this folder.
    try {
        New-Item -ItemType Directory -Path (Join-Path $path 'raw') -Force -ErrorAction Stop | Out-Null
        $full = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
    } catch {
        throw "Cannot create the case folder '$path': $($_.Exception.Message) Choose a writable output folder (menu: Settings, or -OutputPath)."
    }
    $onSystem = $false
    if ((Test-WfxWindows) -and $env:SystemDrive -and $full.StartsWith($env:SystemDrive, [StringComparison]::OrdinalIgnoreCase) -and $Mode -in @('local', 'evidence', 'monitor')) { $onSystem = $true }
    $script:WfxCase = [pscustomobject]@{
        Id           = [guid]::NewGuid().ToString()
        Name         = $Name
        Path         = $full
        Host         = $HostName
        Mode         = $Mode
        StartedUtc   = Get-WfxUtcNow
        Operator     = [Environment]::UserName
        OperatorHost = [Environment]::MachineName
        Admin        = (Test-WfxAdmin)
        PSVersion    = $PSVersionTable.PSVersion.ToString()
        PSEdition    = [string]$PSVersionTable.PSEdition
        ToolVersion  = $script:WfxVersion
        Parameters   = $Parameters
        OutputOnSystemDrive = $onSystem
        Sources      = @()
        Closed       = $false
    }
    Clear-WfxGap
    Write-WfxLog -Event 'case-start' -Data @{ case = $script:WfxCase.Id; host = $HostName; mode = $Mode; operator = $script:WfxCase.Operator; admin = $script:WfxCase.Admin; ps = $script:WfxCase.PSVersion; tool = $script:WfxVersion; parameters = $Parameters }
    if ($onSystem) {
        Write-WfxConsole 'Note: the case is being written to the system drive of the host under investigation. For evidence work prefer -OutputPath on external/network media.' -Kind Warn
        Write-WfxLog -Event 'warning' -Data @{ message = 'output written to the evidence host system drive' }
    }
    return $script:WfxCase
}

function Add-WfxCaseSource {
    <# Records an input the case was derived from (e.g. the source bundle of a re-analysis) with its SHA-256. #>
    param([string]$Path, [string]$Role = 'input')
    if (-not $script:WfxCase -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $script:WfxCase.Sources = @($script:WfxCase.Sources) + [pscustomobject]@{ role = $Role; path = $Path; sha256 = $h }
    Write-WfxLog -Event 'source' -Data @{ role = $Role; path = $Path; sha256 = $h }
}

function Save-WfxJson {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Path, [int]$Depth = 8)
    $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Complete-WfxCase {
    <# Writes manifest.json — SHA-256 of every output, the tool/rule hashes, parameters and sources — then
       CLOSES the case so nothing can be appended afterwards. Returns the manifest path. #>
    $case = $script:WfxCase
    if (-not $case -or $case.Closed) { return }
    Write-WfxLog -Event 'case-end' -Data @{ case = $case.Id }
    $root = $case.Path
    $files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' } | Sort-Object FullName
    $entries = foreach ($f in $files) {
        [ordered]@{
            path   = $f.FullName.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
            bytes  = $f.Length
            sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schema       = 'winforensicx.manifest/2'
        case         = $case.Id
        name         = $case.Name
        host         = $case.Host
        mode         = $case.Mode
        tool         = "WinForensicX $script:WfxVersion"
        toolIntegrity = (Get-WfxToolIntegrity)
        operator     = $case.Operator
        operatorHost = $case.OperatorHost
        admin        = $case.Admin
        powershell   = "$($case.PSVersion) $($case.PSEdition)"
        parameters   = $case.Parameters
        sources      = @($case.Sources)
        started      = $case.StartedUtc
        completed    = (Get-WfxUtcNow)
        files        = @($entries)
        note         = 'Hashes prove these files are unchanged relative to this manifest. The manifest itself is not signed: record its SHA-256 out-of-band (ticket, evidence log) or sign it to make it tamper-evident.'
    }
    $mp = Join-Path $root 'manifest.json'
    Save-WfxJson -InputObject $manifest -Path $mp -Depth 8
    $case.Closed = $true
    $script:WfxCase = $null
    return $mp
}
