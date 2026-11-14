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
