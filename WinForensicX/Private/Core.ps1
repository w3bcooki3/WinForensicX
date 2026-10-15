# WinForensicX — core engine: findings, scoring, redaction, logging, case management, helpers.
# Compatible with Windows PowerShell 5.1 and PowerShell 7+. Analysis helpers here are
# platform-neutral so analyzers can run (and be tested) on any OS.

$script:WfxVersion = '2.0.0'
$script:WfxSeverities = @('Info', 'Low', 'Medium', 'High', 'Critical')
$script:WfxSeverityWeight = @{ Info = 0; Low = 2; Medium = 5; High = 10; Critical = 20 }
$script:WfxConfidenceFactor = @{ Low = 0.5; Medium = 0.8; High = 1.0 }
$script:WfxCase = $null
$script:WfxGaps = New-Object System.Collections.Generic.List[object]
$script:WfxQuiet = $false

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
    <# Appends one JSON line to the case audit log: what the tool did, when, and with what result. #>
    param([string]$Event, [hashtable]$Data = @{})
    if (-not $script:WfxCase -or -not $script:WfxCase.Path) { return }
    $entry = [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('o'); event = $Event }
    foreach ($k in $Data.Keys) { $entry[$k] = $Data[$k] }
    try {
        $line = ($entry | ConvertTo-Json -Compress -Depth 5)
        Add-Content -LiteralPath (Join-Path $script:WfxCase.Path 'audit.log') -Value $line -Encoding UTF8
    } catch { Write-Verbose "audit log write failed: $_" }
}

function Add-WfxGap {
    <# Records something the tool could not collect (missing privilege, disabled log, error) — shown in the report so absence of findings is never mistaken for absence of evidence. #>
    param([string]$Source, [string]$Reason, [string]$Fix = '')
    $script:WfxGaps.Add([pscustomobject]@{ Source = $Source; Reason = $Reason; Fix = $Fix })
    Write-WfxLog -Event 'gap' -Data @{ source = $Source; reason = $Reason }
    Write-Verbose "[$Source] gap: $Reason"
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
    if ($Time) { try { $t = ([datetime]$Time).ToUniversalTime().ToString('o') } catch { $t = [string]$Time } }
    [pscustomobject]@{
        PSTypeName     = 'WinForensicX.Finding'
        Id             = $Id
        Title          = $Title
        Severity       = $Severity
        Confidence     = $Confidence
        Score          = [Math]::Round($weight, 1)
        Category       = $Category
        Technique      = @($Technique | Where-Object { $_ })
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
    <# Dedupes findings by Id + Entity (keeps the highest-scoring one and counts repeats) and sorts by severity. #>
    param([object[]]$Finding)
    $byKey = [ordered]@{}
    foreach ($f in @($Finding | Where-Object { $_ })) {
        $key = "$($f.Host)|$($f.Id)|$($f.Entity)"
        if ($byKey.Contains($key)) {
            $prev = $byKey[$key]
            $prev | Add-Member -NotePropertyName Occurrences -NotePropertyValue ([int]$prev.Occurrences + 1) -Force
            if ($f.Score -gt $prev.Score) { $f | Add-Member -NotePropertyName Occurrences -NotePropertyValue $prev.Occurrences -Force; $byKey[$key] = $f }
        } else {
            $f | Add-Member -NotePropertyName Occurrences -NotePropertyValue 1 -Force
            $byKey[$key] = $f
        }
    }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    , @($byKey.Values | Sort-Object @{ Expression = { $sevRank[$_.Severity] } }, @{ Expression = { $_.Score }; Descending = $true }, Title)
}

function Get-WfxRiskScore {
    <#
    .SYNOPSIS Host risk 0–100. Combines findings as independent evidence: risk = 1 - Π(1 - wᵢ/40).
    One high-confidence Critical ≈ 50, two ≈ 75; many Lows can't add up to a Critical.
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

function Get-WfxSeveritySummary {
    param([object[]]$Finding)
    $o = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $o[$s] = @($Finding | Where-Object { $_.Severity -eq $s }).Count }
    [pscustomobject]$o
}

# ───────────────────────────── text & entropy ─────────────────────────────
function Get-WfxEntropy {
    <# Shannon entropy (bits per symbol) of a string or byte array. #>
    param([Parameter(Mandatory)][AllowEmptyString()]$InputObject)
    if ($null -eq $InputObject) { return 0.0 }
    $counts = @{}
    $n = 0
    if ($InputObject -is [byte[]]) { foreach ($b in $InputObject) { $counts[$b] = 1 + [int]$counts[$b]; $n++ } }
    else { foreach ($c in ([string]$InputObject).ToCharArray()) { $counts[$c] = 1 + [int]$counts[$c]; $n++ } }
    if ($n -eq 0) { return 0.0 }
    $h = 0.0
    foreach ($v in $counts.Values) { $p = $v / $n; $h -= $p * [Math]::Log($p, 2) }
    [Math]::Round($h, 3)
}

function Format-WfxSecret {
    <# Shows only enough of a secret to identify it: first 4 characters + length. Never the value. #>
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
            foreach ($m in [regex]::Matches($lines[$i], $p.Pattern)) {
                if ($seen.ContainsKey($m.Index)) { continue }   # one label per match position
                $seen[$m.Index] = $true
                $out.Add([pscustomobject]@{ Type = $p.Name; Line = $i + 1; Redacted = (Format-WfxSecret $m.Value) })
            }
        }
    }
    , $out.ToArray()
}

function Protect-WfxText {
    <# Redacts secrets and key=value credentials in free text before it is displayed or written to a report. #>
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    foreach ($p in $script:WfxSecretPatterns) { $t = [regex]::Replace($t, $p.Pattern, { param($m) Format-WfxSecret $m.Value }) }
    # key=value / "key value" credentials. The key name may be embedded in a larger identifier
    # (aws_secret_access_key, db-password, MYSQL_PWD), so allow an identifier prefix/suffix.
    $t = [regex]::Replace($t, '(?i)([A-Za-z0-9_.\-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|apikey|client[_-]?secret|access[_-]?key|token)[A-Za-z0-9_.\-]{0,20})(\s*[:=]\s*|\s+)("[^"]*"|''[^'']*''|[^\s;,&]+)', '$1$2***')
    # mysql/openssl-style concatenated password flag: -pSecret  (but not a lone -p)
    $t = [regex]::Replace($t, '(?i)(\s-p)(?!assword\b)([^\s]{2,})', '$1***')
    $t = [regex]::Replace($t, '(?i)(-(?:Password|Pass|Secret|Token|Key)\s+)("[^"]*"|''[^'']*''|\S+)', '$1***')
    $t = [regex]::Replace($t, '(?i)(/p(?:ass(?:word)?)?:)(\S+)', '$1***')
    $t = [regex]::Replace($t, '(?i)(\bnet1?\s+user\s+[^\s/]+\s+)([^\s/][^\s]*)', '$1***')
    $t = [regex]::Replace($t, '(?i)(\bschtasks[^\n]*\s/rp\s+)(\S+)', '$1***')
    $t = [regex]::Replace($t, '(?i)(https?://[^:/\s]+:)([^@\s]+)(@)', '$1***$3')
    return $t
}

# ───────────────────────────── paths & command lines ─────────────────────────────
function Get-WfxImagePath {
    <# Extracts the executable path from a command line / service ImagePath / Run value. #>
    param([AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|scr|dll|msi|cpl|sys))(?=\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
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
    return [bool]($p -match '\\appdata\\|\\temp\\|\\tmp\\|\\downloads\\|\\desktop\\|\\documents\\|\\users\\public\\|\\programdata\\|\\windows\\temp\\|\\windows\\tasks\\|\\windows\\tracing\\|\\perflogs\\|\\\$recycle\.bin\\|\\recycler\\|\\inetpub\\temp|\\windows\\debug\\|\\spool\\drivers\\color\\|\\music\\|\\videos\\|\\pictures\\' -or
        $p -match '^[a-z]:\\[^\\]+\.(exe|dll|ps1|bat|vbs|js|hta)$')
}

function Test-WfxSystemPath {
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [bool]($Path -match '(?i)^[a-z]:\\windows\\(system32|syswow64|winsxs)\\')
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

function Get-WfxValue {
    <# Reads a property that may not exist without tripping strict mode. #>
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [hashtable] -or $Object -is [System.Collections.Specialized.OrderedDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] } else { return $Default }
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

# ───────────────────────────── case management ─────────────────────────────
function New-WfxCase {
    <# Creates the case folder (outputs, raw evidence, audit log) and records who ran what, where, when. #>
    param([string]$OutputPath = '', [string]$Name = '', [string]$HostName = '')
    if (-not $HostName) { $HostName = [Environment]::MachineName }
    if (-not $OutputPath) {
        $base = if (Test-WfxWindows) { Join-Path ([Environment]::GetFolderPath('Desktop')) 'WinForensicX' } else { Join-Path $HOME 'WinForensicX' }
        if (-not $base -or $base -eq 'WinForensicX') { $base = Join-Path (Get-Location) 'WinForensicX' }
        $OutputPath = $base
    }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
    $safeHost = $HostName -replace '[^A-Za-z0-9._-]', '_'
    $folder = if ($Name) { ($Name -replace '[^A-Za-z0-9._-]', '_') + "_$safeHost`_$stamp" } else { "WFX_$safeHost`_$stamp" }
    $path = Join-Path $OutputPath $folder
    New-Item -ItemType Directory -Path (Join-Path $path 'raw') -Force | Out-Null
    $script:WfxCase = [pscustomobject]@{
        Id          = [guid]::NewGuid().ToString()
        Name        = $Name
        Path        = (Resolve-Path $path).Path
        Host        = $HostName
        StartedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        Operator    = [Environment]::UserName
        OperatorHost = [Environment]::MachineName
        Admin       = (Test-WfxAdmin)
        PSVersion   = $PSVersionTable.PSVersion.ToString()
        ToolVersion = $script:WfxVersion
    }
    Clear-WfxGap
    Write-WfxLog -Event 'case-start' -Data @{ case = $script:WfxCase.Id; host = $HostName; operator = $script:WfxCase.Operator; admin = $script:WfxCase.Admin; ps = $script:WfxCase.PSVersion; tool = $script:WfxVersion }
    return $script:WfxCase
}

function Save-WfxJson {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Path, [int]$Depth = 8)
    $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Complete-WfxCase {
    <# Writes manifest.json with SHA-256 of every output file (chain of custody) and closes the audit log. #>
    if (-not $script:WfxCase) { return }
    Write-WfxLog -Event 'case-end' -Data @{ case = $script:WfxCase.Id }
    $root = $script:WfxCase.Path
    $files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' } | Sort-Object FullName
    $entries = foreach ($f in $files) {
        [ordered]@{
            path   = $f.FullName.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
            bytes  = $f.Length
            sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        case = $script:WfxCase.Id; host = $script:WfxCase.Host; tool = "WinForensicX $script:WfxVersion"
        operator = $script:WfxCase.Operator; started = $script:WfxCase.StartedUtc; completed = (Get-Date).ToUniversalTime().ToString('o')
        files = @($entries)
    }
    Save-WfxJson -InputObject $manifest -Path (Join-Path $root 'manifest.json')
}
