function New-WfxFleetReport {
    <#
    .SYNOPSIS
        One overview of many triaged hosts: which are compromised, where the intrusion started and spread,
        which indicators and findings appear on more than one host, and the ATT&CK stages seen per host.
    .DESCRIPTION
        Reads every result.json under -Path (case folders from Invoke-WfxTriage, local or -ComputerName) and
        writes one offline HTML page with the same safety rules as the case report (no network access, all
        evidence escaped). Case folders are only read.
    .PARAMETER Path        Folder(s) containing case folders (searched two levels deep), or case folders.
    .PARAMETER OutputPath  HTML file to write (default: fleet-report_<utc>.html next to the first -Path).
    .PARAMETER AllCases    Keep every case per host (default: only the newest case of each host).
    .EXAMPLE
        Invoke-WfxTriage -ComputerName (Get-Content hosts.txt) -OutputPath E:\ir ; New-WfxFleetReport -Path E:\ir
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Path, [string]$OutputPath = '', [switch]$AllCases, [switch]$PassThru)
    $files = foreach ($p in $Path) {
        if (Test-Path -LiteralPath (Join-Path $p 'result.json')) { Get-Item -LiteralPath (Join-Path $p 'result.json') }
        else { Get-ChildItem -LiteralPath $p -Filter result.json -Recurse -Depth 2 -File -ErrorAction SilentlyContinue }
    }
    $cases = foreach ($f in @($files)) {
        try { $r = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Write-Warning "Skipped $($f.FullName): $($_.Exception.Message)"; continue }
        if (-not $r.HostName -or -not $r.PSObject.Properties['Findings']) { continue }
        [pscustomobject]@{ R = $r; Dir = $f.DirectoryName; Host = [string]$r.HostName; Collected = [string]$r.Collected }
    }
    $cases = @($cases)
    if (-not $cases.Count) { throw "No case results (result.json) found under: $($Path -join ', ')" }
    if (-not $AllCases) { $cases = @($cases | Group-Object { $_.Host.ToLowerInvariant() } | ForEach-Object { $_.Group | Sort-Object Collected -Descending | Select-Object -First 1 }) }

    $hosts = New-Object System.Collections.Generic.List[object]
    $iocHosts = @{}; $ruleHosts = @{}
    foreach ($c in $cases) {
        $r = $c.R
        $fs = @($r.Findings | Where-Object { $_ })
        $attack = @($fs | Where-Object { -not (Test-WfxPostureFinding $_) })
        $techTac = @{}; foreach ($t in @($r.AttackCoverage)) { if ($t) { $techTac[[string]$t.Id] = [string]$t.Tactic } }
        $tac = @{}; foreach ($f in $attack) { foreach ($tq in @($f.Technique)) { $x = $techTac[[string]$tq]; if ($x) { $tac[$x] = 1 + [int]$tac[$x] } } }
        $times = @($attack | Where-Object { $_.Time -and $_.Severity -in 'Critical', 'High', 'Medium' } | ForEach-Object { [string]$_.Time } | Sort-Object)
        $top = @($attack | Sort-Object @{ e = { @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }[[string]$_.Severity] } }, @{ e = { -[double]$_.Score } } | Select-Object -First 5 | ForEach-Object { [ordered]@{ Severity = $_.Severity; Title = $_.Title; Id = $_.Id } })
        $hosts.Add([ordered]@{
                Host = $c.Host; Os = $(if ($r.Host) { [string]$(if ($r.Host.Os) { $r.Host.Os } else { $r.Host.OS }) } else { '' }); Collected = $c.Collected; Case = $(if ($r.Case) { [string]$r.Case.Id } else { '' }); Mode = $(if ($r.Case) { [string]$r.Case.Mode } else { '' })
                Risk = [int]$r.Risk.Score; Level = [string]$r.Risk.Level; Posture = [int]$r.Posture.Score; Summary = $r.Summary
                First = $(if ($times) { $times[0] } else { '' }); Last = $(if ($times) { $times[-1] } else { '' }); Tactics = $tac; Top = $top
                Incidents = @($r.Incidents).Count; Gaps = @($r.Gaps).Count; Folder = $c.Dir
            })
        foreach ($x in @(Get-WfxIndicator -Finding $attack)) { $k = "$($x.Type)|$($x.Value.ToLowerInvariant())"; if (-not $iocHosts[$k]) { $iocHosts[$k] = @{ Type = $x.Type; Value = $x.Value; Hosts = @{}; Sev = $x.Severity } }; $iocHosts[$k].Hosts[$c.Host] = $x.FirstSeen }
        foreach ($f in $attack) { if ($f.Severity -eq 'Info') { continue }; $k = [string]$f.Id; if (-not $ruleHosts[$k]) { $ruleHosts[$k] = @{ Id = $k; Title = ($f.Title -replace ':.*$', ''); Sev = $f.Severity; Hosts = @{} } }; $ruleHosts[$k].Hosts[$c.Host] = 1 + [int]$ruleHosts[$k].Hosts[$c.Host] }
    }
    $shared = @($iocHosts.Values | Where-Object { $_.Hosts.Count -ge 2 } | Sort-Object { -$_.Hosts.Count } | ForEach-Object { [ordered]@{ Type = $_.Type; Value = $_.Value; Severity = $_.Sev; Hosts = @($_.Hosts.GetEnumerator() | Sort-Object Value | ForEach-Object { [ordered]@{ Host = $_.Key; First = $_.Value } }) } })
    $common = @($ruleHosts.Values | Where-Object { $_.Hosts.Count -ge 2 } | Sort-Object { -$_.Hosts.Count } | Select-Object -First 200 | ForEach-Object { [ordered]@{ Id = $_.Id; Title = $_.Title; Severity = $_.Sev; Hosts = @($_.Hosts.Keys | Sort-Object) } })
    $data = [ordered]@{ tool = "WinForensicX $script:WfxVersion"; generated = (Get-WfxUtcNow); hosts = $hosts.ToArray(); shared = $shared; common = $common }
    $json = ConvertTo-Json -InputObject $data -Depth 10
    $bs = [string][char]0x5C
    $json = $json.Replace('&', "${bs}u0026").Replace('<', "${bs}u003c").Replace('>', "${bs}u003e").Replace([string][char]0x2028, "${bs}u2028").Replace([string][char]0x2029, "${bs}u2029")
    if (-not $OutputPath) { $OutputPath = Join-Path $Path[0] ("fleet-report_{0}.html" -f (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')) }
    [IO.File]::WriteAllText($OutputPath, $script:WfxFleetTemplate.Replace('/*__WFX_DATA__*/', $json), (New-Object Text.UTF8Encoding($false)))
    Write-WfxConsole ("Fleet report: {0} host(s), {1} shared indicator(s) → {2}" -f $hosts.Count, $shared.Count, $OutputPath) -Kind Info
    if ($PassThru) { $OutputPath }
}

$script:WfxFleetTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Fleet report</title>
<style>
:root{--bg:#FFFFFF;--bg2:#F6F7F9;--bg3:#EEF0F3;--ink:#1B1F24;--ink2:#535C66;--ink3:#7A838C;--line:#D7DCE1;--line2:#E7EAEE;--link:#0B5CAD;
  --crit:#8E1B1B;--high:#C2351C;--med:#B26B00;--low:#3B6EA8;--info:#7A838C;--mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace;--sans:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#15181C;--bg2:#1B1F24;--bg3:#232830;--ink:#E4E8EC;--ink2:#A3ADB8;--ink3:#7F8995;--line:#323941;--line2:#272D34;--link:#7DB3F0;--crit:#F07070;--high:#FF8A5C;--med:#E9B04D;--low:#86B4EA;--info:#8D97A2}}
*{box-sizing:border-box}
*,*::before,*::after{font-variant-ligatures:none!important;font-feature-settings:"calt" 0,"liga" 0,"clig" 0!important}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans);font-variant-numeric:tabular-nums}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
h1,h2{margin:0;font-weight:600;letter-spacing:-.01em}h1{font-size:28px}h2{font-size:20px;margin-bottom:4px}
.wrap{max-width:1240px;margin:0 auto;padding:0 28px}
.bar{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
.bar .wrap{display:flex;align-items:center;gap:20px;height:48px}.brand{font-weight:600}.brand span{color:var(--ink3);font-weight:400}
.nav{display:flex;gap:2px;overflow-x:auto;flex:1}.nav a{color:var(--ink2);padding:13px 8px 12px;white-space:nowrap}
.btn{font:inherit;font-size:13px;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:5px 10px;cursor:pointer}
.title{padding:30px 0 22px;border-bottom:1px solid var(--line)}.sub{color:var(--ink2);margin-top:6px}
section{padding:34px 0 8px;border-bottom:1px solid var(--line2)}
.desc{color:var(--ink2);max-width:80ch;margin:0 0 14px}
.head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:12px}.head .desc{margin:0}
.tbl{width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:4px}
table{border-collapse:collapse;width:100%}
th{font-weight:600;font-size:12.5px;color:var(--ink2);text-align:left;padding:8px 12px;background:var(--bg2);border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid var(--line2);vertical-align:top}tr:last-child>td{border-bottom:0}
td.t,td.nw{white-space:nowrap}td.t{color:var(--ink2)}td.m{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}td.num{text-align:right}
.sq{display:inline-block;width:9px;height:9px;background:var(--c)}
.sev{display:inline-flex;align-items:center;gap:7px;white-space:nowrap;font-weight:600;font-size:13px}
.sev.Critical{--c:var(--crit);color:var(--crit)}.sev.High{--c:var(--high);color:var(--high)}.sev.Medium,.sev.Elevated{--c:var(--med);color:var(--med)}.sev.Low{--c:var(--low);color:var(--low)}.sev.Info{--c:var(--info);color:var(--info)}
.small{font-size:12.5px;color:var(--ink2)}.muted{color:var(--ink3)}.m{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
.meter{display:inline-block;width:70px;height:6px;background:var(--bg3);vertical-align:middle;margin-left:8px;position:relative}.meter i{position:absolute;left:0;top:0;bottom:0;background:var(--ink2)}
.cells{display:flex;gap:2px}.cells i{display:block;width:16px;height:16px;background:var(--bg3)}.cells i.on1{background:var(--med)}.cells i.on2{background:var(--high)}.cells i.on3{background:var(--crit)}
.legend{display:flex;flex-wrap:wrap;gap:4px 16px;color:var(--ink2);font-size:12.5px;margin:8px 0}
.empty{color:var(--ink2);padding:16px 0}
footer{color:var(--ink3);font-size:12.5px;padding:24px 0 40px}
@media (max-width:640px){.wrap{padding:0 16px}.brand span{display:none}}
@media print{.bar,.btn{display:none}.tbl{overflow:visible;border:0}}
</style>
</head>
<body>
<header class="bar"><div class="wrap"><div class="brand">Fleet <span>report</span></div>
<nav class="nav"><a href="#hosts">Hosts</a><a href="#spread">Spread</a><a href="#shared">Shared indicators</a><a href="#common">Common findings</a><a href="#stages">Stages by host</a></nav>
<button class="btn" id="csv" type="button">Hosts CSV</button></div></header>
<main class="wrap">
<div class="title"><h1 id="h1"></h1><div class="sub" id="sub"></div></div>
<section id="hosts"><h2>Hosts</h2><p class="desc">Every triaged host, most at risk first. Risk is evidence of attacker activity; hardening is how exposed the host is.</p><div id="hbox"></div></section>
<section id="spread"><h2>Spread</h2><p class="desc">When each host first showed medium-or-higher attacker activity, earliest first. The first host is a candidate for patient zero; check the shared indicators to see how activity moved.</p><div id="sbox"></div></section>
<section id="shared"><div class="head"><div><h2>Shared indicators</h2><p class="desc">Addresses, domains, URLs and hashes from attacker-related findings that appear on two or more hosts.</p></div><button class="btn" id="icsv" type="button">Download CSV</button></div><div id="ibox"></div></section>
<section id="common"><h2>Common findings</h2><p class="desc">Detections that fired on two or more hosts: the same tool, technique or persistence across the estate.</p><div id="cbox"></div></section>
<section id="stages"><h2>Stages by host</h2><p class="desc">ATT&amp;CK tactics seen on each host. Darker cells mean more findings.</p><div class="legend" id="leg"></div><div id="xbox"></div></section>
<footer id="foot"></footer>
</main>
<script id="wfx-data" type="application/json">/*__WFX_DATA__*/</script>
<script>
(function () {
  'use strict';
  var D = JSON.parse(document.getElementById('wfx-data').textContent);
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var RANK = { Critical: 0, High: 1, Elevated: 2, Medium: 2, Low: 3, Info: 4 };
  var TAC = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
  var sev = function (s) { return '<span class="sev ' + esc(s) + '"><i class="sq"></i>' + esc(s) + '</span>'; };
  var pad = function (n) { return (n < 10 ? '0' : '') + n; };
  var fmt = function (s) { if (!s) return ''; var d = new Date(s); return isNaN(d) ? esc(s) : d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); };
  var csv = function (rows) { return rows.map(function (r) { return r.map(function (v) { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(','); }).join('\r\n'); };
  var download = function (name, text) { var b = new Blob([text], { type: 'text/csv' }), a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = name; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500); };
  var H = (D.hosts || []).slice().sort(function (a, b) { return b.Risk - a.Risk || String(a.Host).localeCompare(b.Host); });
  var bad = H.filter(function (h) { return h.Level === 'Critical' || h.Level === 'High'; }).length;
  $('h1').textContent = H.length + ' host' + (H.length === 1 ? '' : 's') + ', ' + bad + ' with strong indicators of compromise';
  $('sub').textContent = D.tool + ' \u00b7 generated ' + String(D.generated || '').replace('T', ' ').replace(/\.\d+Z$/, ' UTC') + ' \u00b7 ' + (D.shared || []).length + ' shared indicators \u00b7 ' + (D.common || []).length + ' findings on more than one host';
  var meter = function (n) { return '<span class="meter"><i style="width:' + Math.max(0, Math.min(100, n)) + '%"></i></span>'; };
  $('hbox').innerHTML = '<div class="tbl"><table><thead><tr><th>Host</th><th>Risk</th><th>Hardening gaps</th><th>Findings</th><th>Attacker activity</th><th>Most severe findings</th></tr></thead><tbody>' + H.map(function (h) {
    var S = h.Summary || {};
    var counts = ['Critical', 'High', 'Medium', 'Low'].filter(function (k) { return S[k]; }).map(function (k) { return S[k] + ' ' + k.toLowerCase(); }).join(', ') || 'none';
    return '<tr><td><b>' + esc(h.Host) + '</b><div class="small">' + esc(h.Os || '') + '</div><div class="small">' + esc(h.Mode || '') + (h.Case ? ' \u00b7 case ' + esc(String(h.Case).slice(0, 8)) : '') + '</div></td><td class="nw">' + sev(h.Level) + '<div class="small">' + esc(h.Risk) + ' / 100' + meter(h.Risk) + '</div></td><td class="nw">' + esc(h.Posture) + ' / 100' + meter(h.Posture) +
      '</td><td>' + esc(counts) + (h.Incidents ? '<div class="small">' + esc(h.Incidents) + ' incident' + (h.Incidents === 1 ? '' : 's') + '</div>' : '') + (h.Gaps ? '<div class="small">' + esc(h.Gaps) + ' sources not visible</div>' : '') + '</td><td class="t">' + (h.First ? esc(fmt(h.First)) + (h.Last && h.Last !== h.First ? '<div class="small">to ' + esc(fmt(h.Last)) + '</div>' : '') : '<span class="muted">none</span>') +
      '</td><td>' + (h.Top || []).map(function (f) { return '<div>' + sev(f.Severity).replace(/>\w+<\/span>$/, '></span>') + ' ' + esc(f.Title) + '</div>'; }).join('') + '<div class="small m">' + esc(h.Folder) + '</div></td></tr>';
  }).join('') + '</tbody></table></div>';
  var Sp = H.filter(function (h) { return h.First; }).sort(function (a, b) { return a.First < b.First ? -1 : 1; });
  $('sbox').innerHTML = Sp.length ? '<div class="tbl"><table><thead><tr><th>#</th><th>First activity</th><th>Host</th><th>Risk</th><th>Indicators shared with earlier hosts</th></tr></thead><tbody>' + Sp.map(function (h, i) {
    var earlier = Sp.slice(0, i).map(function (x) { return x.Host; });
    var links = (D.shared || []).filter(function (x) { var hs = x.Hosts.map(function (y) { return y.Host; }); return hs.indexOf(h.Host) >= 0 && hs.some(function (y) { return earlier.indexOf(y) >= 0; }); });
    return '<tr><td class="num">' + (i + 1) + '</td><td class="t">' + esc(fmt(h.First)) + '</td><td><b>' + esc(h.Host) + '</b></td><td>' + sev(h.Level) + '</td><td>' + (links.length ? links.slice(0, 5).map(function (x) { return '<div class="m">' + esc(x.Type) + ' ' + esc(x.Value) + '</div>'; }).join('') : (i ? '<span class="muted">none</span>' : '<span class="small">earliest host</span>')) + '</td></tr>';
  }).join('') + '</tbody></table></div>' : '<div class="empty">No host has time-stamped attacker activity.</div>';
  var SH = D.shared || [];
  $('ibox').innerHTML = SH.length ? '<div class="tbl"><table><thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Hosts</th></tr></thead><tbody>' + SH.map(function (x) {
    return '<tr><td class="nw">' + esc(x.Type) + '</td><td class="m">' + esc(x.Value) + '</td><td>' + sev(x.Severity) + '</td><td>' + x.Hosts.map(function (y) { return '<div>' + esc(y.Host) + (y.First ? ' <span class="small">' + esc(fmt(y.First)) + '</span>' : '') + '</div>'; }).join('') + '</td></tr>';
  }).join('') + '</tbody></table></div>' : '<div class="empty">No indicator appears on more than one host.</div>';
  $('icsv').onclick = function () { download('fleet-shared-indicators.csv', csv([['type', 'value', 'severity', 'hosts']].concat(SH.map(function (x) { return [x.Type, x.Value, x.Severity, x.Hosts.map(function (y) { return y.Host; }).join(' ')]; })))); };
  var C = D.common || [];
  $('cbox').innerHTML = C.length ? '<div class="tbl"><table><thead><tr><th>Severity</th><th>Finding</th><th>Rule</th><th class="num">Hosts</th><th>Where</th></tr></thead><tbody>' + C.map(function (x) {
    return '<tr><td>' + sev(x.Severity) + '</td><td>' + esc(x.Title) + '</td><td class="m">' + esc(x.Id) + '</td><td class="num">' + x.Hosts.length + '</td><td>' + esc(x.Hosts.join(', ')) + '</td></tr>';
  }).join('') + '</tbody></table></div>' : '<div class="empty">No detection fired on more than one host.</div>';
  $('leg').innerHTML = TAC.map(function (t, i) { return '<span>' + (i + 1) + ' ' + esc(t) + '</span>'; }).join('');
  $('xbox').innerHTML = '<div class="tbl"><table><thead><tr><th>Host</th><th>Stages 1\u2013' + TAC.length + '</th><th>Stages seen</th></tr></thead><tbody>' + H.map(function (h) {
    var T = h.Tactics || {};
    return '<tr><td><b>' + esc(h.Host) + '</b></td><td><div class="cells">' + TAC.map(function (t) { var n = T[t] || 0; return '<i class="' + (n >= 5 ? 'on3' : n >= 2 ? 'on2' : n ? 'on1' : '') + '" title="' + esc(t) + ': ' + n + '"></i>'; }).join('') + '</div></td><td class="small">' + esc(TAC.filter(function (t) { return T[t]; }).join(', ') || 'none') + '</td></tr>';
  }).join('') + '</tbody></table></div>';
  $('csv').onclick = function () { download('fleet-hosts.csv', csv([['host', 'risk_level', 'risk', 'hardening_gaps', 'critical', 'high', 'medium', 'low', 'first_activity_utc', 'last_activity_utc', 'incidents', 'case_folder']].concat(H.map(function (h) { var S = h.Summary || {}; return [h.Host, h.Level, h.Risk, h.Posture, S.Critical || 0, S.High || 0, S.Medium || 0, S.Low || 0, h.First, h.Last, h.Incidents, h.Folder]; })))); };
  $('foot').textContent = D.tool + '. Built from the result.json of each case folder; open a host\u2019s report.html for the evidence.';
})();
</script>
</body>
</html>
'@
