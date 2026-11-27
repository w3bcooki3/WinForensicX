# Indicator extraction from findings (the same rules the case report uses), shared by the STIX export,
# the fleet report and the console. Only attacker-related findings are used; private addresses, local
# names and Windows system binaries are left out so the list is something you could act on.

function Get-WfxIndicator {
    <#
    .SYNOPSIS Extracts indicators (IPv4, domain, URL, MD5 / SHA-1 / SHA-256) from findings' evidence.
    Returns { Type; Value; Severity; Findings (ids); FirstSeen }.
    #>
    param([object[]]$Finding)
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $fileExt = '^(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|scr|msi|iso|img|zip|rar|7z|txt|log|xml|json|csv|html?|docx?|docm|xlsx?|xlsm|pptx?|pdf|dat|tmp|ini|cfg|config|dmp|evtx|etl|pf|db|sqlite|jpg|png|gif|cpl|ocx|mui|cab|reg|bak|old|lockd|locked|encrypted|crypt|enc|key|pem|pfx|kdbx|vhdx?|one|jar|sct|aspx?|php|jsp|dit|blf|regtrans-ms|hve|library-ms|automaticdestinations-ms|customdestinations-ms)$'
    $map = [ordered]@{}
    $add = {
        param($Type, $Value, $F)
        $v = ([string]$Value).TrimEnd(')', ',', '.', ';', "'", '"', ']')
        if (-not $v -or $v.Length -gt 400) { return }
        $k = "$Type|$($v.ToLowerInvariant())"
        if (-not $map.Contains($k)) { $map[$k] = [pscustomobject]@{ Type = $Type; Value = $v; Severity = $F.Severity; Findings = New-Object System.Collections.Generic.List[string]; FirstSeen = $F.Time } }
        $x = $map[$k]
        if (-not $x.Findings.Contains($F.Id)) { $x.Findings.Add($F.Id) }
        if ($rank[[string]$F.Severity] -lt $rank[[string]$x.Severity]) { $x.Severity = $F.Severity }
        if ($F.Time -and (-not $x.FirstSeen -or [string]$F.Time -lt [string]$x.FirstSeen)) { $x.FirstSeen = $F.Time }
    }
    foreach ($f in @($Finding | Where-Object { $_ -and -not (Test-WfxPostureFinding $_) -and $_.Id -notlike 'HUNT-*' })) {
        $texts = New-Object System.Collections.Generic.List[string]
        $texts.Add([string]$f.Entity)
        $ev = $f.Evidence
        if ($ev) {
            $pairs = if ($ev -is [System.Collections.IDictionary]) { $ev.GetEnumerator() } else { $ev.PSObject.Properties }
            foreach ($p in $pairs) { $v = $p.Value; $texts.Add($(if ($v -is [string] -or $v -is [System.ValueType]) { [string]$v } else { try { $v | ConvertTo-Json -Compress -Depth 4 } catch { [string]$v } })) }
        }
        foreach ($s in $texts) {
            if (-not $s) { continue }
            foreach ($m in [regex]::Matches($s, '(?i)\b(?:hxxps?|https?|ftp)://[^\s"''<>]+')) {
                $u = $m.Value -replace '^hxxp', 'http'; $uh = ''; try { $uh = ([uri]$u).Host } catch { }
                if ($uh -match '(?i)(?:^|\.)(?:invalid|example|test|localhost|local)$|^localhost$' -or ($uh -match '^\d' -and (Test-WfxPrivateIp $uh))) { continue }
                & $add 'url' $u $f
            }
            foreach ($m in [regex]::Matches($s, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) { $ip = $m.Value; if (@($ip.Split('.') | Where-Object { [int]$_ -gt 255 }).Count) { continue }; if (-not (Test-WfxPrivateIp $ip) -and $ip -notmatch '^(?:0\.|127\.|255\.|22[4-9]\.|23\d\.)') { & $add 'ipv4' $ip $f } }
            foreach ($m in [regex]::Matches($s, '(?i)(?<![a-f0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])')) { $h = $m.Value.ToLowerInvariant(); & $add $(switch ($h.Length) { 64 { 'sha256' } 40 { 'sha1' } default { 'md5' } }) $h $f }
            $noUrl = [regex]::Replace($s, '(?i)\b(?:hxxps?|https?|ftp)://[^\s"''<>]+', ' ')
            foreach ($m in [regex]::Matches($noUrl, '(?i)(?<![/\\:@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b(?![!\w-])')) {
                $d = $m.Value.ToLowerInvariant(); $tld = ($d -split '\.')[-1]
                if ($tld -match $fileExt -or $d -match '^(?:system|microsoft|io|net|ws|mshtml|scrobj|comsvcs|wscript|shell32|kernel32)\.' -or $d -match '\.(?:local|lan|internal|corp|home|localdomain|arpa|invalid|example)$' -or $d -match '^(?:[^.]+\.)?(?:example\.(?:com|org|net))$') { continue }
                & $add 'domain' $d $f
            }
        }
    }
    foreach ($x in $map.Values) { $x | Add-Member -NotePropertyName FindingIds -NotePropertyValue (@($x.Findings) -join ', ') -PassThru }
}

function New-WfxUuidV5 {
    <# Deterministic UUID (version 5, SHA-1) so re-exporting a case gives the same STIX ids. #>
    param([string]$Name, [guid]$Namespace = '00abedb4-aa42-466c-9c01-fed23315a9b7')
    $ns = $Namespace.ToByteArray()
    # .NET stores the first three GUID fields little-endian; RFC 4122 hashing wants network order.
    [Array]::Reverse($ns, 0, 4); [Array]::Reverse($ns, 4, 2); [Array]::Reverse($ns, 6, 2)
    $bytes = $ns + [Text.Encoding]::UTF8.GetBytes($Name)
    $h = [Security.Cryptography.SHA1]::Create().ComputeHash([byte[]]$bytes)
    $u = $h[0..15]
    $u[6] = ($u[6] -band 0x0F) -bor 0x50; $u[8] = ($u[8] -band 0x3F) -bor 0x80
    $hex = -join ($u | ForEach-Object { '{0:x2}' -f $_ })
    '{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20, 12)
}

function Read-WfxIocFile {
    <#
    .SYNOPSIS Reads indicators from a file: plain text (one per line), a CSV with a value column (OSINTrix,
    MISP and WinForensicX indicator exports), a STIX 2.x bundle, or a MISP event (JSON).
    In plain text '#' starts a comment only at the start of a line or after a space or tab, so a URL
    fragment (page#section) is kept. Returns the values as found; the caller re-fangs and de-duplicates.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "IOC file not found: $Path" }
    $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).ProviderPath)
    $text = $text.TrimStart([char]0xFEFF)
    $out = [System.Collections.Generic.List[string]]::new()
    $t = $text.Trim()

    # ── JSON: STIX 2.x bundle / objects, a MISP event, or an array of strings ──
    if ($t.StartsWith('{') -or $t.StartsWith('[')) {
        $json = $null
        try { $json = ConvertFrom-Json -InputObject $t -ErrorAction Stop } catch { $json = $null }
        if ($null -ne $json) {
            $addMisp = {
                param($a)
                $v = [string](Get-WfxValue $a 'value' ''); $ty = [string](Get-WfxValue $a 'type' '')
                if (-not $v) { return }
                if ($ty -match '\|' -and $v -match '\|') {
                    # composite attributes: ip-dst|port, domain|ip, filename|sha256 ... (ports are not indicators)
                    $tp = $ty -split '\|'; $vp = $v -split '\|'
                    for ($i = 0; $i -lt $vp.Count; $i++) { if ($i -lt $tp.Count -and $tp[$i] -eq 'port') { continue }; if ($vp[$i]) { $out.Add($vp[$i]) } }
                } else { $out.Add($v) }
            }
            $objects = [System.Collections.Generic.List[object]]::new()
            foreach ($j in @($json)) {
                if ($null -eq $j) { continue }
                if ($j -is [string]) { $out.Add($j); continue }
                $ev = Get-WfxValue $j 'Event' $null
                if ($ev) {
                    foreach ($a in @(Get-WfxValue $ev 'Attribute' @())) { & $addMisp $a }
                    foreach ($o in @(Get-WfxValue $ev 'Object' @())) { foreach ($a in @(Get-WfxValue $o 'Attribute' @())) { & $addMisp $a } }
                    continue
                }
                $objs = Get-WfxValue $j 'objects' $null
                if ($null -ne $objs) { foreach ($o in @($objs)) { $objects.Add($o) } } else { $objects.Add($j) }
            }
            foreach ($o in $objects) {
                if ($null -eq $o) { continue }
                if ($o -is [string]) { $out.Add($o); continue }
                $type = [string](Get-WfxValue $o 'type' '')
                if ($type -eq 'indicator') {
                    # [ipv4-addr:value = '1.2.3.4'], [file:hashes.'SHA-256' = '...'] OR [...]; MATCHES (regex) is not a value
                    foreach ($m in [regex]::Matches([string](Get-WfxValue $o 'pattern' ''), "(?<![!<>])=\s*'((?:[^'\\]|\\.)*)'")) {
                        $out.Add(($m.Groups[1].Value -replace "\\(['\\])", '$1'))
                    }
                } elseif ($type -in @('ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'email-addr')) {
                    $v = [string](Get-WfxValue $o 'value' ''); if ($v) { $out.Add($v) }
                } elseif ($type -eq 'file') {
                    $h = Get-WfxValue $o 'hashes' $null
                    if ($h) { foreach ($p in $h.PSObject.Properties) { if ($p.Value) { $out.Add([string]$p.Value) } } }
                }
            }
            return $out.ToArray()
        }
    }

    $lines = @($text -split "`r?`n")
    # ── CSV with a header that names the value column ──
    $hi = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { $l = $lines[$i].Trim(); if ($l -and -not $l.StartsWith('#')) { $hi = $i; break } }
    if ($hi -ge 0 -and $lines[$hi].Contains(',')) {
        $cols = @($lines[$hi].Split(',') | ForEach-Object { $_.Trim().Trim('"').Trim() })
        $col = $null
        foreach ($want in 'value', 'indicator', 'ioc', 'ioc_value', 'observable', 'observable_value') {
            $col = $cols | Where-Object { $_ -ieq $want } | Select-Object -First 1
            if ($col) { break }
        }
        if ($col) {
            $body = @($lines[$hi..($lines.Count - 1)] | Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') })
            foreach ($row in @($body | ConvertFrom-Csv)) {
                $v = [string]$row.$col
                if ($v -match "^'[\s=+\-@|]") { $v = $v.Substring(1) }      # spreadsheet formula guard added on export
                $v = $v.Trim(); if ($v) { $out.Add($v) }
            }
            return $out.ToArray()
        }
    }

    # ── plain text: one indicator per line ──
    foreach ($l in $lines) {
        $v = ($l -replace '(?:^|\s)#.*$', '').Trim()
        if ($v) { $out.Add($v) }
    }
    return $out.ToArray()
}
