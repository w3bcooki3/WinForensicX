# ─────────────────────────────────────────────────────────────────────────────────────────────
# Secrets-exposure & security-hygiene COLLECTOR.  DEFENSIVE / READ-ONLY by design.
#
# What this does:  detects and reports THAT sensitive material or a misconfiguration EXISTS and is
#   exposed (GPP cPassword, unattend passwords, accessible SAM/SYSTEM/SECURITY/NTDS, world-readable
#   cloud-credential files, auto-logon password, unencrypted SSH keys, AI/API keys, secrets in env
#   vars / PowerShell history / config files) so an analyst can remediate it.
#
# What this deliberately does NOT do — and must never be extended to do:
#   • It never opens, copies, parses or decrypts a credential store (SAM/NTDS, LSA secrets, DPAPI
#     blobs, browser login DBs, LSASS). For hives it checks existence and ACLs only.
#   • It never emits a secret VALUE. Every match is reduced to type + length via Find-WfxSecret /
#     Format-WfxSecret BEFORE it leaves this collector. Records returned here carry only redacted
#     strings in a .Redacted field — raw values are discarded immediately and never persisted.
#   • It never decrypts the GPP cPassword (reversible though it is): reporting its presence is enough.
#
# The exposure analyzer consumes: { Kind, Path, Detail, Accessible, WorldReadable, Redacted }.
# ─────────────────────────────────────────────────────────────────────────────────────────────

# Identities that should not normally be able to read a per-user or protected file.
$script:WfxOtherReadSids = @(
    'S-1-1-0'        # Everyone
    'S-1-5-11'       # Authenticated Users
    'S-1-5-32-545'   # BUILTIN\Users
    'S-1-5-4'        # INTERACTIVE
    'S-1-5-7'        # ANONYMOUS
)
# Secret types that are specifically AI-provider keys (routed to the AiKey finding).
$script:WfxAiKeyTypes = @('Anthropic API key', 'OpenAI API key', 'OpenRouter API key', 'Google API key',
    'Hugging Face token', 'Groq API key', 'xAI API key', 'Replicate token')

function Test-WfxOtherUserReadable {
    <# True if a non-admin, non-owner principal (Everyone / Users / Authenticated Users / INTERACTIVE)
       is granted read access. ACL-only; the file's contents are never opened. #>
    param([string]$Path)
    if (-not (Test-WfxWindows) -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.FileSystemRights -notmatch 'Read|FullControl|Modify') { continue }
            $sid = ''
            try { $sid = ($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])).Value } catch { $sid = [string]$ace.IdentityReference }
            if ($sid -in $script:WfxOtherReadSids) { return $true }
        }
    } catch {}
    return $false
}

function Get-WfxRedactedHits {
    <# Returns redacted secret descriptors for a block of text WITHOUT returning any raw value.
       Combines Find-WfxSecret (known key formats) with a generic key=value / assignment detector. #>
    param([AllowEmptyString()][string]$Text, [int]$MaxHits = 20)
    $hits = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrEmpty($Text)) { return , $hits.ToArray() }
    foreach ($s in (Find-WfxSecret $Text)) {
        if ($hits.Count -ge $MaxHits) { break }
        $hits.Add([pscustomobject]@{ Type = $s.Type; Line = $s.Line; Redacted = "$($s.Type) (line $($s.Line)): $($s.Redacted)" })
    }
    # Generic assignments (db_password=..., ANTHROPIC_API_KEY=..., clientSecret: ...) not caught by a
    # known key format. The name may carry an underscore/dot prefix, so we match the whole identifier.
    $lines = $Text -split "`r?`n"
    $assignRx = '(?i)([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|credential|connectionstring|access[_-]?key)[A-Za-z0-9_.\-]*)\s*[:=]\s*("[^"]{4,}"|''[^'']{4,}''|\S{4,})'
    $seen = @{}
    foreach ($h in $hits) { $seen["$($h.Line)"] = $true }
    for ($i = 0; $i -lt $lines.Count -and $hits.Count -lt $MaxHits; $i++) {
        $m = [regex]::Match($lines[$i], $assignRx)
        if (-not $m.Success) { continue }
        if ($seen.ContainsKey([string]($i + 1))) { continue }   # a known-format key already covered this line
        $raw = $m.Groups[2].Value.Trim('"', "'")
        # Skip obvious placeholders.
        if ($raw -match '(?i)^(?:\*+|x+|changeme|your[_-]?\w+|<[^>]+>|%[^%]+%|\$\{?\w+\}?|null|none|empty|example|xxx+)$') { continue }
        $name = $m.Groups[1].Value
        $hits.Add([pscustomobject]@{ Type = "$name assignment"; Line = $i + 1; Redacted = "$name (line $($i+1)): $(Format-WfxSecret $raw)" })
    }
    # Command-line secrets passed as separate args or concatenated flags (mysql -pSecret, aws ... set
    # aws_secret_access_key <value>) — common in shell history. Guarded to avoid placeholder noise.
    for ($i = 0; $i -lt $lines.Count -and $hits.Count -lt $MaxHits; $i++) {
        if ($seen.ContainsKey([string]($i + 1))) { continue }
        $mp = [regex]::Match($lines[$i], '(?i)(?:^|\s)-p(?!assword\b)([^\s]{4,})')
        if ($mp.Success) { $hits.Add([pscustomobject]@{ Type = 'password flag'; Line = $i + 1; Redacted = "password flag (line $($i+1)): $(Format-WfxSecret $mp.Groups[1].Value)" }); continue }
        $ma = [regex]::Match($lines[$i], '(?i)\b([A-Za-z0-9_.\-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)[A-Za-z0-9_.\-]{0,20})\s+(\S{8,})\s*$')
        if ($ma.Success -and $ma.Groups[2].Value -notmatch '(?i)^(?:changeme|example|<[^>]+>|%[^%]+%)$') {
            $hits.Add([pscustomobject]@{ Type = "$($ma.Groups[1].Value) value"; Line = $i + 1; Redacted = "$($ma.Groups[1].Value) (line $($i+1)): $(Format-WfxSecret $ma.Groups[2].Value)" })
        }
    }
    , $hits.ToArray()
}

function Get-WfxExposureData {
    <#
    .SYNOPSIS Defensive secrets-exposure audit. Returns redacted exposure records (see file header).
    .PARAMETER IncludeFileScan  Also scan a small set of likely-credential config files in user profiles.
    #>
    param([switch]$IncludeFileScan)
    if (-not (Test-WfxWindows)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($Kind, $Path, $Detail = '', $Accessible = $false, $WorldReadable = $false, $Redacted = @())
        $out.Add([pscustomobject]@{ Kind = $Kind; Path = $Path; Detail = $Detail; Accessible = [bool]$Accessible; WorldReadable = [bool]$WorldReadable; Content = ''; Redacted = @($Redacted) }) }

    # ── 1. GPP cPassword (presence only; never decrypted) ──
    Invoke-WfxStep 'expo:gpp' {
        $gppRoots = @("$env:SystemRoot\SYSVOL", 'C:\ProgramData\Microsoft\Group Policy\History')
        try { $dom = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain; if ($dom -and $dom -ne 'WORKGROUP') { $gppRoots += "\\$dom\SYSVOL" } } catch {}
        foreach ($root in $gppRoots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            Get-ChildItem -LiteralPath $root -Recurse -File -Include 'Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml' -ErrorAction SilentlyContinue |
                Select-Object -First 100 | ForEach-Object {
                    $hit = $false
                    try { $hit = (Select-String -LiteralPath $_.FullName -Pattern 'cpassword\s*=\s*"[^"]+"' -SimpleMatch:$false -Quiet -ErrorAction Stop) } catch {}
                    if ($hit) { & $add 'GppCpassword' $_.FullName 'GPP XML with cpassword attribute' }
                }
        }
    } | Out-Null

    # ── 2. Unattend / sysprep passwords (presence only) ──
    Invoke-WfxStep 'expo:unattend' {
        $cand = @(
            "$env:SystemDrive\unattend.xml", "$env:SystemDrive\autounattend.xml"
            "$env:SystemRoot\Panther\unattend.xml", "$env:SystemRoot\Panther\Unattend\unattend.xml"
            "$env:SystemRoot\System32\Sysprep\unattend.xml", "$env:SystemRoot\System32\Sysprep\Panther\unattend.xml"
            "$env:SystemRoot\System32\Sysprep\sysprep.xml", "$env:SystemRoot\System32\sysprep.inf"
        )
        foreach ($f in $cand) {
            if (-not (Test-Path -LiteralPath $f)) { continue }
            $hasPw = $false
            try { $hasPw = (Select-String -LiteralPath $f -Pattern '<Password>|<AdministratorPassword>|<DomainPassword>|\bpassword\b' -Quiet -ErrorAction Stop) } catch {}
            if ($hasPw) { & $add 'UnattendPassword' $f 'Unattended-setup file containing a password element' }
        }
    } | Out-Null

    # ── 3. Sensitive hives — existence + ACL only, contents NEVER read ──
    Invoke-WfxStep 'expo:hives' {
        $hiveFiles = @(
            @{ P = "$env:SystemRoot\System32\config\RegBack\SAM"; D = 'SAM hive backup (RegBack)' }
            @{ P = "$env:SystemRoot\System32\config\RegBack\SYSTEM"; D = 'SYSTEM hive backup (RegBack)' }
            @{ P = "$env:SystemRoot\System32\config\RegBack\SECURITY"; D = 'SECURITY hive backup (RegBack)' }
            @{ P = "$env:SystemRoot\repair\SAM"; D = 'SAM hive copy (repair)' }
            @{ P = "$env:SystemRoot\repair\SYSTEM"; D = 'SYSTEM hive copy (repair)' }
            @{ P = "$env:SystemRoot\repair\SECURITY"; D = 'SECURITY hive copy (repair)' }
            @{ P = "$env:SystemDrive\Windows.old\Windows\System32\config\SAM"; D = 'SAM hive in Windows.old' }
            @{ P = "$env:SystemDrive\NTDS\ntds.dit"; D = 'Active Directory database (NTDS.dit)' }
        )
        foreach ($h in $hiveFiles) {
            if (-not (Test-Path -LiteralPath $h.P)) { continue }
            $f = Get-Item -LiteralPath $h.P -ErrorAction SilentlyContinue
            if (-not $f -or $f.Length -eq 0) { continue }   # RegBack is often present but zero-length
            $readable = Test-WfxOtherUserReadable $h.P
            & $add 'SensitiveHive' $h.P $h.D $readable $readable
        }
    } | Out-Null

    # ── 4. Shadow copies (informational) ──
    Invoke-WfxStep 'expo:shadow' {
        $sc = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)
        if ($sc.Count -gt 0) { & $add 'ShadowCopy' '' "$($sc.Count) volume shadow copy(ies) present" }
    } | Out-Null

    # ── 5. World/other-readable cloud & credential files ──
    Invoke-WfxStep 'expo:credfiles' {
        $rel = @(
            @{ R = '.aws\credentials'; D = 'AWS CLI credentials' }
            @{ R = '.azure\accessTokens.json'; D = 'Azure CLI access tokens' }
            @{ R = '.azure\msal_token_cache.json'; D = 'Azure MSAL token cache' }
            @{ R = '.config\gcloud\credentials.db'; D = 'gcloud credentials' }
            @{ R = '.config\gcloud\access_tokens.db'; D = 'gcloud access tokens' }
            @{ R = '.docker\config.json'; D = 'Docker registry auth' }
            @{ R = '.kube\config'; D = 'Kubernetes config (cluster tokens)' }
            @{ R = '.git-credentials'; D = 'Git stored credentials' }
            @{ R = '_netrc'; D = 'netrc credentials' }
            @{ R = '.netrc'; D = 'netrc credentials' }
            @{ R = '.npmrc'; D = 'npm auth token' }
            @{ R = '.pypirc'; D = 'PyPI upload credentials' }
        )
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userHome = $_.FullName
            foreach ($c in $rel) {
                $p = Join-Path $userHome $c.R
                if (-not (Test-Path -LiteralPath $p)) { continue }
                if (Test-WfxOtherUserReadable $p) { & $add 'CredFileWorldReadable' $p $c.D $true $true }
            }
        }
    } | Out-Null

    # ── 6. Auto-logon password in Winlogon (presence only; value never read) ──
    Invoke-WfxStep 'expo:autologon' {
        $wl = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (Test-Path $wl) {
            $k = Get-ItemProperty $wl -ErrorAction SilentlyContinue
            if ("$($k.AutoAdminLogon)" -eq '1' -and $k.PSObject.Properties['DefaultPassword'] -and $k.DefaultPassword) {
                & $add 'AutoLogon' $wl ("DefaultUserName=" + $k.DefaultUserName)
            }
        }
    } | Out-Null

    # ── 7. Unencrypted SSH private keys (header inspected for cipher only; key bytes never emitted) ──
    Invoke-WfxStep 'expo:sshkeys' {
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $sshDir = Join-Path $_.FullName '.ssh'
            if (-not (Test-Path -LiteralPath $sshDir)) { return }
            Get-ChildItem -LiteralPath $sshDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^(id_(rsa|dsa|ecdsa|ed25519)|.*\.(pem|key|ppk))$' -and $_.Name -notmatch '\.pub$' } |
                ForEach-Object {
                    $head = ''
                    try { $head = (Get-Content -LiteralPath $_.FullName -TotalCount 5 -ErrorAction Stop) -join "`n" } catch { return }
                    if ($head -notmatch 'PRIVATE KEY|PuTTY-User-Key') { return }
                    $encrypted = $false
                    if ($head -match 'Proc-Type:\s*4,ENCRYPTED' -or $head -match 'DEK-Info:' -or $head -match 'Encryption:\s*aes') { $encrypted = $true }
                    elseif ($head -match 'BEGIN OPENSSH PRIVATE KEY') {
                        # OpenSSH keys embed the cipher name; 'none' = unencrypted. Inspect header block only.
                        try {
                            $b64 = ((Get-Content -LiteralPath $_.FullName -ErrorAction Stop) | Where-Object { $_ -notmatch 'PRIVATE KEY-----' } | Select-Object -First 2) -join ''
                            $bytes = [Convert]::FromBase64String($b64.PadRight([int](([Math]::Ceiling($b64.Length / 4.0)) * 4), '='))
                            $asText = [Text.Encoding]::ASCII.GetString($bytes)
                            if ($asText -notmatch 'none' -and ($asText -match 'aes|chacha|3des')) { $encrypted = $true }
                        } catch { $encrypted = $true }  # if unsure, assume protected (avoid false alarm)
                    }
                    elseif ($_.Extension -eq '.ppk') { $encrypted = $true }  # conservative
                    if (-not $encrypted) { & $add 'SshKeyUnprotected' $_.FullName 'SSH private key without a passphrase' }
                }
        }
    } | Out-Null

    # ── 8. Secrets in environment variables (redacted immediately) ──
    Invoke-WfxStep 'expo:env' {
        $nameRx = '(?i)(key|token|secret|password|passwd|pwd|credential|conn(ection)?string|sas|dsn)'
        foreach ($scope in @('Process', 'User', 'Machine')) {
            $vars = @{}
            try { $vars = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::$scope) } catch { continue }
            foreach ($name in $vars.Keys) {
                $val = [string]$vars[$name]
                if ([string]::IsNullOrWhiteSpace($val) -or $val.Length -lt 8) { continue }
                $known = Find-WfxSecret $val
                if ($known.Count -gt 0) {
                    $type = $known[0].Type
                    $red = "$type`: $($known[0].Redacted)"
                    if ($type -in $script:WfxAiKeyTypes) { & $add 'AiKey' "env:$scope`:$name" "$type in `$env:$name" $false $false @($red) }
                    else { & $add 'SecretInEnv' "env:$scope" $name $false $false @("$name ($scope): $($known[0].Redacted)") }
                } elseif ($name -match $nameRx -and $val -notmatch '(?i)^(?:\*+|changeme|your[_-]?\w+|%[^%]+%|<[^>]+>|true|false|\d{1,4})$') {
                    & $add 'SecretInEnv' "env:$scope" $name $false $false @("$name ($scope): $(Format-WfxSecret $val)")
                }
            }
        }
    } | Out-Null

    # ── 9. Secrets in PowerShell / shell history (redacted immediately) ──
    Invoke-WfxStep 'expo:history' {
        $histFiles = New-Object System.Collections.Generic.List[string]
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $histFiles.Add((Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'))
            $histFiles.Add((Join-Path $_.FullName '.bash_history'))
        }
        foreach ($hf in $histFiles) {
            if (-not (Test-Path -LiteralPath $hf)) { continue }
            $text = ''
            try { $text = Get-Content -LiteralPath $hf -Raw -ErrorAction Stop } catch { continue }
            $hits = Get-WfxRedactedHits $text
            if ($hits.Count -gt 0) { & $add 'SecretInHistory' $hf 'credential(s) typed on the command line' $false $false @($hits.Redacted) }
        }
    } | Out-Null

    # ── 10. Optional: secrets in common config files (bounded; redacted immediately) ──
    if ($IncludeFileScan) {
        Invoke-WfxStep 'expo:configfiles' {
            $names = @('.env', '.env.local', 'web.config', 'appsettings.json', 'appsettings.Development.json', 'secrets.json', 'config.json', 'settings.py', 'application.properties', 'credentials.json', '.env.production')
            $scanned = 0
            Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if ($scanned -ge 400) { return }
                Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Depth 4 -Include $names -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -le 262144 } | Select-Object -First 100 | ForEach-Object {
                        if ($scanned -ge 400) { return }
                        $scanned++
                        $text = ''
                        try { $text = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop } catch { return }
                        $hits = Get-WfxRedactedHits $text
                        if ($hits.Count -gt 0) {
                            $ai = @($hits | Where-Object { $_.Type -in $script:WfxAiKeyTypes })
                            if ($ai.Count -gt 0) { & $add 'AiKey' $_.FullName ($ai[0].Type) $false $false @($ai.Redacted) }
                            $other = @($hits | Where-Object { $_.Type -notin $script:WfxAiKeyTypes })
                            if ($other.Count -gt 0) { & $add 'SecretInFile' $_.FullName (($other[0].Type)) $false $false @($other.Redacted) }
                        }
                    }
            }
        } | Out-Null
    }

    , @($out.ToArray())
}
