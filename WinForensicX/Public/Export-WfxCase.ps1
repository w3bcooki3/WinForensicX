function Export-WfxCase {
    <#
    .SYNOPSIS
        Exports a case for other tools: Timesketch (CSV), Elastic / Splunk / Sentinel (ECS JSON lines),
        threat-intel platforms such as MISP or OpenCTI (STIX 2.1 bundle), or a plain indicator list.
    .DESCRIPTION
        Formats:
          • Timesketch — CSV with message / datetime / timestamp_desc and the source of every row: findings,
                         events, activity, execution artifacts, processes, connections, files.
          • Ecs        — one JSON object per line. Findings are event.kind "alert" with rule.*, threat.technique.*
                         and host.*; timeline rows are event.kind "event". Load with Filebeat / Elastic Agent,
                         Splunk HEC or Sentinel's custom-log ingestion.
          • Stix       — STIX 2.1 bundle: a report, the indicators (addresses, domains, URLs, hashes) with
                         patterns, the ATT&CK techniques seen as attack-pattern objects, and "indicates" links.
          • Indicators — CSV of type, value, severity, first seen and the findings each came from.
          • All        — every format.
        Files are written NEXT TO the case folder (<case>-<format>.<ext>), so the hashed case is not modified.
    .PARAMETER InputPath  A case folder (containing result.json and raw\bundle.json).
    .PARAMETER Format     Timesketch | Ecs | Stix | Indicators | All (default All).
    .PARAMETER OutputPath Folder for the exports (default: the folder that contains the case).
    .EXAMPLE
        Export-WfxCase -InputPath E:\cases\WFX_PC01_20261103-101500Z -Format Stix
    .EXAMPLE
        Export-WfxCase -InputPath .\case -Format Ecs -OutputPath \\siem\drop
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [ValidateSet('Timesketch', 'Ecs', 'Stix', 'Indicators', 'All')][string[]]$Format = @('All'),
        [string]$OutputPath = '',
        [switch]$PassThru
    )
    $bp = Resolve-WfxBundlePath -Path $InputPath
    $caseDir = if ((Split-Path -Leaf (Split-Path -Parent $bp)) -eq 'raw') { Split-Path -Parent (Split-Path -Parent $bp) } else { Split-Path -Parent $bp }
    $resultPath = Join-Path $caseDir 'result.json'
    if (-not (Test-Path -LiteralPath $resultPath)) { throw "No result.json in $caseDir — export works on a completed case (run Invoke-WfxTriage first)." }
    $r = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $OutputPath) { $OutputPath = Split-Path -Parent $caseDir }
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $base = Join-Path $OutputPath (Split-Path -Leaf $caseDir)
    $want = if ($Format -contains 'All') { @('Timesketch', 'Ecs', 'Stix', 'Indicators') } else { $Format }
    $hn = [string]$r.HostName
    $findings = @($r.Findings | Where-Object { $_ })
    $utf8 = New-Object Text.UTF8Encoding($false)
    $written = New-Object System.Collections.Generic.List[string]
    $timeline = $null
    if ($want -contains 'Timesketch' -or $want -contains 'Ecs') { $timeline = @(Get-WfxTimeline -InputPath $caseDir) }
    $techName = @{}; foreach ($c in @($r.AttackCoverage)) { if ($c) { $techName[[string]$c.Id] = $c } }

    if ($want -contains 'Timesketch') {
        $rows = foreach ($t in $timeline) {
            [pscustomobject]@{ message = (Get-WfxShortText ("{0} {1}" -f $t.Summary, $t.Detail).Trim() 2000); datetime = $t.TimeUtc; timestamp_desc = $t.Type
                data_type = "winforensicx:$($t.Source -replace ':.*$', '')"; source = $t.Source; hostname = $t.Host; summary = $t.Summary; detail = $t.Detail }
        }
        $p = "$base-timesketch.csv"
        @($rows) | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8
        $written.Add($p)
    }

    if ($want -contains 'Ecs') {
        $sevNum = @{ Info = 1; Low = 21; Medium = 47; High = 73; Critical = 99 }
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($f in $findings) {
            $ev = $f.Evidence
            $get = { param($k) if ($ev -and $ev.PSObject.Properties[$k]) { [string]$ev.$k } else { '' } }
            $doc = [ordered]@{
                '@timestamp' = $(if ($f.Time) { $f.Time } else { $r.Analyzed })
                message      = $f.Title
                event        = [ordered]@{ kind = 'alert'; module = 'winforensicx'; dataset = 'winforensicx.finding'; severity = $sevNum[[string]$f.Severity]; risk_score = [double]$f.Score; category = @('intrusion_detection'); provider = [string]$f.Source }
                rule         = [ordered]@{ id = $f.Id; name = $f.Title; description = $f.Description; category = $f.Category }
                host         = [ordered]@{ name = $hn }
                observer     = [ordered]@{ product = 'WinForensicX'; version = [string]$r.ToolVersion; type = 'triage' }
                labels       = [ordered]@{ severity = $f.Severity; confidence = $f.Confidence; entity = $f.Entity }
            }
            $tech = @($f.Technique | Where-Object { $_ })
            if ($tech.Count) {
                $doc.threat = [ordered]@{ framework = 'MITRE ATT&CK'
                    technique = @($tech | ForEach-Object { [ordered]@{ id = $_; name = $(if ($techName[$_]) { $techName[$_].Name } else { '' }); reference = "https://attack.mitre.org/techniques/$($_ -replace '\.', '/')/" } })
                    tactic = @($tech | ForEach-Object { if ($techName[$_] -and $techName[$_].Tactic) { [ordered]@{ name = $techName[$_].Tactic } } } | Select-Object -First 3) }
            }
            $img = & $get 'Image'; if (-not $img) { $img = & $get 'Path' }
            $cmd = & $get 'CommandLine'; if (-not $cmd) { $cmd = & $get 'Command' }
            if ($cmd -or ($img -match '\.exe$')) { $doc.process = [ordered]@{ executable = $img; command_line = $cmd; pid = $(if (& $get 'Pid') { [int](ConvertTo-WfxInt (& $get 'Pid')) } else { $null }) } }
            elseif ($img) { $doc.file = [ordered]@{ path = $img } }
            $user = & $get 'User'; if (-not $user) { $user = & $get 'TargetUserName' }; if ($user) { $doc.user = [ordered]@{ name = $user } }
            $rip = & $get 'RemoteAddress'; if ($rip) { $doc.destination = [ordered]@{ ip = $rip; port = $(if (& $get 'RemotePort') { [int](ConvertTo-WfxInt (& $get 'RemotePort')) } else { $null }) } }
            $sha = & $get 'Sha1'; if ($sha) { if (-not $doc.file) { $doc.file = [ordered]@{} }; $doc.file.hash = [ordered]@{ sha1 = $sha } }
            $doc.winforensicx = [ordered]@{ evidence = $ev; recommendation = $f.Recommendation; occurrences = $f.Occurrences }
            $lines.Add((ConvertTo-Json -InputObject $doc -Depth 8 -Compress))
        }
        foreach ($t in $timeline) {
            if ($t.Source -eq 'finding') { continue }
            $doc = [ordered]@{ '@timestamp' = $t.TimeUtc; message = (Get-WfxShortText ("{0} {1}" -f $t.Summary, $t.Detail).Trim() 2000)
                event = [ordered]@{ kind = 'event'; module = 'winforensicx'; dataset = 'winforensicx.timeline'; action = $t.Type; provider = $t.Source }
                host = [ordered]@{ name = $t.Host }; observer = [ordered]@{ product = 'WinForensicX'; version = [string]$r.ToolVersion } }
            $lines.Add((ConvertTo-Json -InputObject $doc -Depth 6 -Compress))
        }
        $p = "$base-ecs.ndjson"
        [IO.File]::WriteAllLines($p, $lines.ToArray(), $utf8)
        $written.Add($p)
    }

    $iocs = @(Get-WfxIndicator -Finding $findings)
    if ($want -contains 'Indicators') {
        $p = "$base-indicators.csv"
        @($iocs | Select-Object Type, Value, Severity, FirstSeen, FindingIds) | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8
        $written.Add($p)
    }

    if ($want -contains 'Stix') {
        $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $caseId = if ($r.Case -and $r.Case.Id) { [string]$r.Case.Id } else { $hn }
        $identity = "identity--$(New-WfxUuidV5 'WinForensicX')"
        $objs = New-Object System.Collections.Generic.List[object]
        $objs.Add([ordered]@{ type = 'identity'; spec_version = '2.1'; id = $identity; created = '2026-01-01T00:00:00.000Z'; modified = '2026-01-01T00:00:00.000Z'; name = 'WinForensicX'; identity_class = 'system' })
        $apIds = @{}
        foreach ($tq in @($findings | ForEach-Object { $_.Technique } | Where-Object { $_ } | Sort-Object -Unique)) {
            $id = "attack-pattern--$(New-WfxUuidV5 "attack:$tq")"; $apIds[$tq] = $id
            $objs.Add([ordered]@{ type = 'attack-pattern'; spec_version = '2.1'; id = $id; created = $now; modified = $now; created_by_ref = $identity
                    name = $(if ($techName[$tq] -and $techName[$tq].Name) { $techName[$tq].Name } else { $tq })
                    external_references = @([ordered]@{ source_name = 'mitre-attack'; external_id = $tq; url = "https://attack.mitre.org/techniques/$($tq -replace '\.', '/')/" }) })
        }
        $fById = @{}; foreach ($f in $findings) { if (-not $fById[$f.Id]) { $fById[$f.Id] = @() }; $fById[$f.Id] += $f }
        $refs = New-Object System.Collections.Generic.List[string]
        foreach ($x in $iocs) {
            $esc = ([string]$x.Value).Replace('\', '\\').Replace("'", "\'")
            $pattern = switch ($x.Type) {
                'ipv4' { "[ipv4-addr:value = '$esc']" } 'domain' { "[domain-name:value = '$esc']" } 'url' { "[url:value = '$esc']" }
                'md5' { "[file:hashes.MD5 = '$esc']" } 'sha1' { "[file:hashes.'SHA-1' = '$esc']" } 'sha256' { "[file:hashes.'SHA-256' = '$esc']" }
            }
            if (-not $pattern) { continue }
            $iid = "indicator--$(New-WfxUuidV5 "$caseId|$($x.Type)|$($x.Value)")"
            $vf = if ($x.FirstSeen) { ([datetime](ConvertTo-WfxDateTime $x.FirstSeen)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $now }
            $objs.Add([ordered]@{ type = 'indicator'; spec_version = '2.1'; id = $iid; created = $now; modified = $now; created_by_ref = $identity
                    name = "$($x.Type) $($x.Value)"; description = "Seen on $hn in: $($x.FindingIds). Extracted automatically by WinForensicX; review before blocking."
                    indicator_types = @('anomalous-activity'); pattern = $pattern; pattern_type = 'stix'; valid_from = $vf
                    labels = @("severity:$(([string]$x.Severity).ToLowerInvariant())") })
            $refs.Add($iid)
            $techs = @(foreach ($fid in $x.Findings) { foreach ($f in @($fById[$fid])) { $f.Technique } }) | Where-Object { $_ } | Sort-Object -Unique
            foreach ($tq in $techs) {
                if (-not $apIds[$tq]) { continue }
                $rid = "relationship--$(New-WfxUuidV5 "$iid|$tq")"
                $objs.Add([ordered]@{ type = 'relationship'; spec_version = '2.1'; id = $rid; created = $now; modified = $now; created_by_ref = $identity; relationship_type = 'indicates'; source_ref = $iid; target_ref = $apIds[$tq] })
                $refs.Add($rid)
            }
        }
        foreach ($v in $apIds.Values) { $refs.Add($v) }
        if (-not $refs.Count) { $refs.Add($identity) }
        $objs.Add([ordered]@{ type = 'report'; spec_version = '2.1'; id = "report--$(New-WfxUuidV5 "report|$caseId")"; created = $now; modified = $now; created_by_ref = $identity
                name = "WinForensicX triage of $hn"; published = $now; report_types = @('observed-data', 'indicator', 'attack-pattern')
                description = "Compromise risk $($r.Risk.Score)/100 ($($r.Risk.Level)). $(@($findings).Count) findings. Collected $($r.Collected) UTC. Case $caseId."
                object_refs = @($refs | Select-Object -Unique) })
        $bundle = [ordered]@{ type = 'bundle'; id = "bundle--$([guid]::NewGuid().ToString())"; objects = $objs.ToArray() }
        $p = "$base-stix.json"
        [IO.File]::WriteAllText($p, (ConvertTo-Json -InputObject $bundle -Depth 10), $utf8)
        $written.Add($p)
    }
    foreach ($p in $written) { Write-WfxConsole "Exported: $p" -Kind Info }
    if ($PassThru) { $written.ToArray() }
}
