function New-WfxReport {
    <#
    .SYNOPSIS
        Renders a self-contained (no external assets, works offline) HTML case report from an
        Invoke-WfxAnalyze result: verdict, prioritized findings with evidence, recent activity, a merged
        timeline, ATT&CK coverage, what could not be seen, and chain of custody.
        Embeds only already-redacted data — never raw secret values.
    .PARAMETER Result  The result object from Invoke-WfxAnalyze.
    .PARAMETER Path    Output .html path.
    .OUTPUTS The output path.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Path)

    $help = Get-WfxHelpModel
    $data = [ordered]@{
        tool          = "WinForensicX $($script:WfxVersion)"
        generated     = (Get-WfxUtcNow)
        hostName      = [string](Get-WfxValue $Result 'HostName' '')
        host          = (Get-WfxValue $Result 'Host' $null)
        risk          = (Get-WfxValue $Result 'Risk' $null)
        posture       = (Get-WfxValue $Result 'Posture' $null)
        collected     = (ConvertTo-WfxUtcString (Get-WfxValue $Result 'Collected' ''))
        case          = (Get-WfxValue $Result 'Case' $null)
        suppressed    = @(Get-WfxValue $Result 'Suppressed' @())
        summary       = (Get-WfxValue $Result 'Summary' $null)
        findings      = @(Get-WfxValue $Result 'Findings' @())
        activity      = @(Get-WfxValue $Result 'Activity' @())
        activityTotal = (ConvertTo-WfxInt (Get-WfxValue $Result 'ActivityTotal' 0))
        coverage      = @(Get-WfxValue $Result 'AttackCoverage' @())
        incidents     = @(Get-WfxValue $Result 'Incidents' @())
        artifacts     = @(@(Get-WfxValue $Result 'Artifacts' @()) | Select-Object -First 3000 | ForEach-Object { [ordered]@{ Artifact = $_.Artifact; Time = $_.Time; TimeKind = $_.TimeKind; Evidence = $_.Evidence; Path = $_.Path; User = $_.User; Sha1 = $_.Sha1; Detail = $_.Detail } })
        artifactTotal = (ConvertTo-WfxInt (Get-WfxValue $Result 'ArtifactTotal' 0))
        gaps          = @(Get-WfxValue $Result 'Gaps' @())
        limits        = @($help.Limits)
    }
    $json = ConvertTo-Json -InputObject $data -Depth 12
    # Neutralise markup-significant characters inside the JSON island; JSON.parse restores them as text.
    $bs = [string][char]0x5C
    $json = $json.Replace('&', "${bs}u0026").Replace('<', "${bs}u003c").Replace('>', "${bs}u003e").Replace([string][char]0x2028, "${bs}u2028").Replace([string][char]0x2029, "${bs}u2029")

    # Template placeholders first, data LAST, so collected text can never fill a placeholder.
    $html = $script:WfxReportTemplate
    $html = $html.Replace('__WFX_HOST__', [System.Net.WebUtility]::HtmlEncode($data.hostName))
    $html = $html.Replace('/*__WFX_DATA__*/', $json)
    [IO.File]::WriteAllText($Path, $html, (New-Object Text.UTF8Encoding($false)))
    return $Path
}

$script:WfxReportTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Case report: __WFX_HOST__</title>
<style>
html{font-variant-ligatures:none;font-feature-settings:"calt" 0,"liga" 0,"clig" 0;-webkit-text-size-adjust:100%}
:root{
  --bg:#FFFFFF; --bg2:#F6F7F9; --bg3:#EEF0F3; --ink:#1B1F24; --ink2:#535C66; --ink3:#7A838C;
  --line:#D7DCE1; --line2:#E7EAEE; --link:#0B5CAD; --sel:#E8F0FB;
  --crit:#8E1B1B; --high:#C2351C; --med:#B26B00; --low:#3B6EA8; --info:#7A838C;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace;
  --sans:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#15181C;--bg2:#1B1F24;--bg3:#232830;--ink:#E4E8EC;--ink2:#A3ADB8;--ink3:#7F8995;--line:#323941;--line2:#272D34;--link:#7DB3F0;--sel:#1E2B3B;--crit:#F07070;--high:#FF8A5C;--med:#E9B04D;--low:#86B4EA;--info:#8D97A2}}
:root[data-theme=dark]{--bg:#15181C;--bg2:#1B1F24;--bg3:#232830;--ink:#E4E8EC;--ink2:#A3ADB8;--ink3:#7F8995;--line:#323941;--line2:#272D34;--link:#7DB3F0;--sel:#1E2B3B;--crit:#F07070;--high:#FF8A5C;--med:#E9B04D;--low:#86B4EA;--info:#8D97A2}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans);font-variant-numeric:tabular-nums}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--link);outline-offset:2px}
h1,h2,h3{margin:0;font-weight:600;letter-spacing:-.01em}
h1{font-size:28px;line-height:1.2}
h2{font-size:20px;line-height:1.3;margin-bottom:4px}
h3{font-size:15px;margin:22px 0 8px}
p{margin:0 0 10px}
code,.mono{font-family:var(--mono);font-size:12.5px}
.wrap{max-width:1240px;margin:0 auto;padding:0 28px}

/* top bar */
.bar{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
.bar .wrap{display:flex;align-items:center;gap:20px;height:48px}
.brand{font-weight:600;white-space:nowrap}
.brand span{color:var(--ink3);font-weight:400}
.nav{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none;flex:1}
.nav::-webkit-scrollbar{display:none}
.nav a{color:var(--ink2);padding:13px 7px 12px;white-space:nowrap;border-bottom:2px solid transparent}
.nav a:hover{color:var(--ink);text-decoration:none}
.nav a.on{color:var(--ink);border-bottom-color:var(--ink)}
.nav a .n{color:var(--ink3);margin-left:4px;font-size:12px}
.btn{font:inherit;font-size:13px;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:5px 10px;cursor:pointer;white-space:nowrap}
.btn:hover{background:var(--bg2)}
.btn[aria-pressed=true]{background:var(--bg3)}
.tools{display:flex;gap:6px}

/* sections */
section{padding:34px 0 8px;border-bottom:1px solid var(--line2)}
section:last-of-type{border-bottom:0}
.desc{color:var(--ink2);max-width:78ch;margin-bottom:16px}
.head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:12px}
.head .desc{margin:0}

/* summary */
.title{padding:30px 0 22px;border-bottom:1px solid var(--line)}
.title .sub{color:var(--ink2);margin-top:6px}
.assess{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:40px;padding-top:26px}
.verdict{font-size:22px;font-weight:600;display:flex;align-items:center;gap:10px;margin-bottom:8px}
.lead{font-size:15px;color:var(--ink);max-width:66ch}
ol.todo{margin:6px 0 0;padding:0;list-style:none;counter-reset:t}
ol.todo li{counter-increment:t;display:grid;grid-template-columns:26px 1fr;padding:9px 0;border-top:1px solid var(--line2)}
ol.todo li::before{content:counter(t);color:var(--ink3);font-weight:600}
ol.todo b{display:block;font-weight:600}
ol.todo span{color:var(--ink2)}
dl.facts{margin:0;display:grid;grid-template-columns:auto 1fr;border-top:1px solid var(--line)}
dl.facts dt,dl.facts dd{margin:0;padding:8px 0;border-bottom:1px solid var(--line2)}
dl.facts dt{color:var(--ink2);padding-right:18px;white-space:nowrap}
dl.facts dd{text-align:right;overflow-wrap:anywhere}
.meter{display:inline-block;width:90px;height:6px;background:var(--bg3);vertical-align:middle;margin-left:8px;position:relative}
.meter i{position:absolute;left:0;top:0;bottom:0;background:var(--ink2)}
.sevline{display:inline-flex;flex-wrap:wrap;gap:4px 12px;justify-content:flex-end}

/* severity */
.sq{display:inline-block;width:9px;height:9px;background:var(--c);flex:none}
.sev{display:inline-flex;align-items:center;gap:7px;white-space:nowrap;font-weight:600;font-size:13px}
.sev.Critical{--c:var(--crit);color:var(--crit)}.sev.High{--c:var(--high);color:var(--high)}.sev.Medium{--c:var(--med);color:var(--med)}.sev.Low{--c:var(--low);color:var(--low)}.sev.Info{--c:var(--info);color:var(--info)}
.sev.plain{color:var(--ink);font-weight:400}

/* tables */
.tbl{width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:4px}
table{border-collapse:collapse;width:100%}
th{font-weight:600;font-size:12.5px;color:var(--ink2);text-align:left;padding:8px 12px;background:var(--bg2);border-bottom:1px solid var(--line);white-space:nowrap;position:sticky;top:0}
th.sort{cursor:pointer;user-select:none}th.sort:hover{color:var(--ink)}
th[aria-sort=ascending]::after{content:" \2191"}th[aria-sort=descending]::after{content:" \2193"}
td{padding:8px 12px;border-bottom:1px solid var(--line2);vertical-align:top}
tr:last-child>td{border-bottom:0}
td.t,td.nw{white-space:nowrap}td.t{color:var(--ink2)}
td.m{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere;min-width:16ch}
td.num{text-align:right}
.small{font-size:12.5px;color:var(--ink2)}
.muted{color:var(--ink3)}

/* toolbar */
.tb{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;margin:0 0 12px}
.tb input[type=search]{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--ink);min-width:260px;flex:1;max-width:420px}
.tb select{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--ink)}
.tb label{display:inline-flex;align-items:center;gap:5px;color:var(--ink2);white-space:nowrap}
.tb .sp{flex:1}
.count{color:var(--ink3);font-size:12.5px;margin-top:8px}

/* findings */
#ftbl tr.row{cursor:pointer}
#ftbl tr.row:hover>td{background:var(--bg2)}
#ftbl tr.row.open>td{background:var(--sel);border-bottom-color:transparent}
#ftbl td.ftl b{font-weight:600}
#ftbl td.ftl .ent{display:block;font-family:var(--mono);font-size:12px;color:var(--ink2);overflow-wrap:anywhere;margin-top:2px}
#ftbl .tg{display:block;margin:0;background:none;border:0;padding:0;font:inherit;line-height:inherit;color:inherit;text-align:left;cursor:pointer}
tr.detail>td{background:var(--sel);padding:4px 12px 18px}
.dgrid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.15fr);gap:28px}
.dgrid h4{font-size:12.5px;font-weight:600;color:var(--ink2);margin:12px 0 6px}
.dgrid p{max-width:70ch}
table.kv{border:1px solid var(--line);background:var(--bg)}
table.kv td{padding:5px 10px;font-size:12.5px}
table.kv td.k{color:var(--ink2);white-space:nowrap;width:1%}
table.kv td.v{font-family:var(--mono);white-space:pre-wrap;overflow-wrap:anywhere}
ul.rel{list-style:none;margin:0;padding:0;border:1px solid var(--line);background:var(--bg)}
ul.rel li{display:grid;grid-template-columns:62px 1fr;gap:8px;padding:5px 10px;border-bottom:1px solid var(--line2);font-size:12.5px}
ul.rel li:last-child{border-bottom:0}
ul.rel li.self{background:var(--bg3)}
ul.rel .m{font-family:var(--mono);overflow-wrap:anywhere}
.meta{font-size:12px;color:var(--ink3);margin-top:12px}
.meta a{margin-right:10px}

/* attack path */
#path td.stage{font-weight:600;white-space:nowrap}

/* matrix */
.matrix{display:flex;border:1px solid var(--line);border-radius:4px;overflow-x:auto}
.mcol{border-right:1px solid var(--line2);flex:1 1 150px;min-width:150px}
.mcol.none{flex:0 0 88px;min-width:88px}
.mcol:last-child{border-right:0}
.mcol h4{margin:0;padding:8px 9px;font-size:12px;font-weight:600;background:var(--bg2);border-bottom:1px solid var(--line);min-height:52px;overflow-wrap:break-word;hyphens:auto}
.mcol h4 span{display:block;color:var(--ink3);font-weight:400}
.mcol.none h4{color:var(--ink3);background:var(--bg)}
.mt{display:block;padding:7px 9px;border-bottom:1px solid var(--line2);font-size:12px;color:var(--ink)}
.mt:hover{background:var(--bg2);text-decoration:none}
.mt b{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-weight:600;font-size:11.5px}
.mt.Critical b .sq{--c:var(--crit)}.mt.High b .sq{--c:var(--high)}.mt.Medium b .sq{--c:var(--med)}.mt.Low b .sq{--c:var(--low)}.mt.Info b .sq{--c:var(--info)}

/* misc */
.empty{padding:16px;border:1px dashed var(--line);border-radius:4px;color:var(--ink2)}
ul.list{margin:0;padding:0;list-style:none;border-top:1px solid var(--line2)}
ul.list li{padding:9px 0;border-bottom:1px solid var(--line2)}
ul.list li b{font-weight:600}
ul.list .fix{color:var(--ink2);margin-top:2px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:36px}
pre.cmd{font-family:var(--mono);font-size:12.5px;background:var(--bg2);border:1px solid var(--line);border-radius:4px;padding:10px 12px;overflow-x:auto;margin:8px 0 0}
footer{padding:26px 0 40px;color:var(--ink3);font-size:12.5px}
.day td{background:var(--bg2);font-weight:600;color:var(--ink2)}
.kind{color:var(--ink2);white-space:nowrap}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:7px 14px;border-radius:4px;font-size:13px;opacity:0;transition:opacity .15s;pointer-events:none}
.toast.on{opacity:1}
@media (prefers-reduced-motion:reduce){.toast{transition:none}}

@media (max-width:980px){.assess,.dgrid,.two{grid-template-columns:1fr;gap:22px}.wrap{padding:0 16px}h1{font-size:24px}}
@media (max-width:640px){.brand span{display:none}.tools .btn.hide-s{display:none}.tb input[type=search]{min-width:0;max-width:none;width:100%}#ftbl .c-tac,#ftbl .c-cnt,#ftbl .c-time{display:none}dl.facts dd{text-align:left}dl.facts{grid-template-columns:1fr}dl.facts dt{border-bottom:0;padding-bottom:0}}
@media print{
  .bar,.tb,.btn,.toast{display:none!important}
  #abox,#ebox,#tbox tr.chg{display:none}
  .pnote{display:block!important;color:#555;margin:4px 0 8px}
  body{font-size:11.5px}section{break-inside:auto;padding-top:18px}
  tr.detail{display:table-row!important}tr.row{break-inside:avoid}
  .tbl{overflow:visible;border:0}th{position:static}
  .matrix{flex-wrap:wrap}.mcol.none{display:none}
  a{color:inherit}
}
*,*::before,*::after{font-variant-ligatures:none!important;font-feature-settings:"calt" 0,"liga" 0,"clig" 0!important}
</style>
</head>
<body>
<header class="bar"><div class="wrap">
  <div class="brand">__WFX_HOST__ <span>case report</span></div>
  <nav class="nav" id="nav" aria-label="Sections">
    <a href="#summary">Summary</a><a href="#incidents">Incidents<span class="n" id="n-n"></span></a><a href="#path">Path<span class="n" id="n-p"></span></a><a href="#findings">Findings<span class="n" id="n-f"></span></a><a href="#iocs">IOCs<span class="n" id="n-i"></span></a><a href="#timeline">Timeline<span class="n" id="n-t"></span></a><a href="#activity">Changes<span class="n" id="n-a"></span></a><a href="#execution">Execution<span class="n" id="n-e"></span></a><a href="#attack">ATT&amp;CK<span class="n" id="n-x"></span></a><a href="#visibility">Gaps<span class="n" id="n-g"></span></a><a href="#custody">Custody</a>
  </nav>
  <div class="tools"><button class="btn hide-s" id="theme" type="button">Dark</button><button class="btn" id="print" type="button">Print</button></div>
</div></header>

<main class="wrap">
<div class="title" id="summary">
  <h1>__WFX_HOST__</h1>
  <div class="sub" id="sub"></div>
  <div class="assess">
    <div>
      <div class="verdict" id="verdict"></div>
      <p class="lead" id="lead"></p>
      <h3>Do first</h3>
      <ol class="todo" id="todo"></ol>
    </div>
    <dl class="facts" id="facts"></dl>
  </div>
</div>

<section id="incidents">
  <h2>Incidents</h2>
  <p class="desc">Findings grouped into incidents: findings that share a file, account or address and happen close together, or high-severity findings within minutes of each other. Each row is one story to investigate; the links say why findings were grouped.</p>
  <div id="nbox"></div>
</section>

<section id="path">
  <h2>Attack path</h2>
  <p class="desc">Findings placed on the attack lifecycle, earliest stage first, with the time each stage was first seen. Read it top to bottom as the intrusion story; select a finding to open it.</p>
  <div id="pathbox"></div>
</section>

<section id="findings">
  <div class="head"><div><h2>Findings</h2><p class="desc">Every lead, most severe first. Select a row for why it matters, what to do, the evidence and what else happened within 30 minutes.</p></div>
    <div class="tools"><button class="btn" id="fx-csv" type="button">Download CSV</button><button class="btn" id="fexp" type="button" aria-pressed="false">Expand all</button></div></div>
  <div class="tb">
    <input type="search" id="fq" placeholder="Search titles, paths, users, IPs" aria-label="Search findings">
    <span id="fsev"></span>
    <select id="ftac" aria-label="Stage"></select>
    <select id="fcat" aria-label="Area"></select>
  </div>
  <div class="tbl"><table id="ftbl"><thead><tr>
    <th class="sort" data-k="sev" aria-sort="ascending">Severity</th><th class="sort" data-k="title">Finding</th><th class="sort c-tac" data-k="tac">Stage</th><th class="c-tec">Technique</th><th class="sort c-time" data-k="time">First seen</th><th class="sort c-cnt num" data-k="cnt">Seen</th>
  </tr></thead><tbody></tbody></table></div>
  <div class="count" id="fcount"></div>
</section>

<section id="iocs">
  <div class="head"><div><h2>Indicators</h2><p class="desc">Addresses, domains, URLs, hashes, files, registry keys and accounts extracted from the evidence of attacker-related findings. Extraction is automatic: check each value before blocking it.</p></div>
    <div class="tools"><button class="btn" id="i-copy" type="button">Copy values</button><button class="btn" id="i-csv" type="button">Download CSV</button></div></div>
  <div class="tb">
    <input type="search" id="iq" placeholder="Search indicators" aria-label="Search indicators">
    <select id="itype" aria-label="Type"></select>
    <label><input type="checkbox" id="idef"> Defang for sharing</label>
    <label><input type="checkbox" id="ipriv"> Include private addresses</label>
    <label><input type="checkbox" id="isys"> Include Windows binaries</label>
  </div>
  <div id="ibox"></div>
</section>

<section id="timeline">
  <div class="head"><div><h2>Timeline</h2><p class="desc">Findings and notable changes in one sequence, shown in your local time (UTC in the CSV).</p></div>
    <div class="tools"><button class="btn" id="t-csv" type="button">Download CSV</button></div></div>
  <div class="tb">
    <input type="search" id="tq" placeholder="Search the timeline" aria-label="Search timeline">
    <label><input type="checkbox" id="tonly"> Findings only</label>
  </div>
  <p class="pnote" hidden>Printed copy lists findings only; every change is in the timeline CSV and raw/bundle.json.</p>
  <div id="tbox"></div>
</section>

<section id="activity">
  <h2>Recent changes</h2>
  <p class="desc" id="asub">What changed on the host in the look-back window: registry, files, software, services, tasks, accounts, security settings, executions and connections.</p>
  <div class="tb">
    <input type="search" id="aq" placeholder="Search changes" aria-label="Search changes">
    <select id="acat" aria-label="Area"></select>
  </div>
  <p class="pnote" hidden>Left out of the printed copy; see the timeline CSV or raw/bundle.json.</p>
  <div id="abox"></div>
</section>

<section id="execution">
  <div class="head"><div><h2>Evidence of execution and user activity</h2><p class="desc" id="esub">Programs that ran or existed (Amcache, ShimCache, Prefetch, BAM, UserAssist, PCA), what users opened (ShellBags, Jump Lists, shortcuts, Run box, searches), browser downloads and Defender's own logs. These records outlive the files they describe. A severity mark means a finding refers to that path.</p></div>
    <div class="tools"><button class="btn" id="e-csv" type="button">Download CSV</button></div></div>
  <div class="tb">
    <input type="search" id="eq" placeholder="Search paths, users, hashes" aria-label="Search execution evidence">
    <select id="eart" aria-label="Artifact"></select>
    <select id="eev" aria-label="Evidence type"></select>
    <label><input type="checkbox" id="eflag"> Flagged only</label>
  </div>
  <p class="pnote" hidden>Left out of the printed copy; see the CSV or raw/bundle.json.</p>
  <div id="ebox"></div>
</section>

<section id="attack">
  <div class="head"><div><h2>MITRE ATT&amp;CK</h2><p class="desc">Techniques behind the findings, by tactic. The square shows the most severe finding for each technique.</p></div>
    <div class="tools"><button class="btn" id="x-layer" type="button">Download Navigator layer</button></div></div>
  <div id="xbox"></div>
</section>

<section id="visibility">
  <h2>What this report could not see</h2>
  <p class="desc">Collection limits. An empty finding list means nothing matched in what was visible, not that nothing happened.</p>
  <div class="two"><div><h3>Not visible or incomplete</h3><div id="gbox"></div></div><div><h3>Suppressed by the allowlist</h3><div id="sbox"></div></div></div>
</section>

<section id="custody">
  <h2>Case and custody</h2>
  <p class="desc">How and when this evidence was collected. Verify the case folder before relying on it.</p>
  <div class="two"><div id="cbox"></div><div><h3 style="margin-top:0">Verify this case</h3><p class="small">Re-hashes every file against manifest.json and reports anything changed, missing or added.</p><pre class="cmd" id="verify"></pre>
    <h3>Method and limits</h3><ul class="list" id="lbox"></ul></div></div>
</section>
<footer id="foot"></footer>
</main>
<div class="toast" id="toast" role="status" aria-live="polite"></div>

<script id="wfx-data" type="application/json">/*__WFX_DATA__*/</script>
<script>
(function () {
  'use strict';
  var D = JSON.parse(document.getElementById('wfx-data').textContent);
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var SEV = ['Critical', 'High', 'Medium', 'Low', 'Info'], RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  var TAC = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
  var TID = /^T\d{4}(?:\.\d{3})?$/;
  var sevHtml = function (s) { s = RANK[s] === undefined ? 'Info' : s; return '<span class="sev ' + s + '"><i class="sq"></i>' + s + '</span>'; };
  var dt = function (s) { if (s === null || s === undefined || s === '') return null; var d = new Date(s); return isNaN(d) ? null : d; };
  var pad = function (n) { return (n < 10 ? '0' : '') + n; };
  var fmt = function (d) { return d ? d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) : ''; };
  var fmtT = function (d) { return d ? pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) : ''; };
  var utc = function (d) { return d ? d.toISOString().replace(/\.\d{3}Z$/, 'Z') : ''; };
  var isAcct = function (v) { v = String(v || '').trim(); return !!v && v.length < 64 && !/[:\/]|\.[A-Za-z0-9]{2,4}$|^-$|^(SYSTEM|NT AUTHORITY\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)|LOCAL SERVICE|NETWORK SERVICE|S-1-5-(18|19|20))$/i.test(v); };
  var toast = function (m) { var t = $('toast'); t.textContent = m; t.classList.add('on'); clearTimeout(t._h); t._h = setTimeout(function () { t.classList.remove('on'); }, 1600); };
  var download = function (name, text, type) {
    var b = new Blob([text], { type: type || 'text/plain' }), a = document.createElement('a');
    a.href = URL.createObjectURL(b); a.download = name; document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500); toast('Saved ' + name);
  };
  var csv = function (rows) { return rows.map(function (r) { return r.map(function (v) { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(','); }).join('\r\n'); };
  var copy = function (text) {
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(function () { toast('Copied'); }); return; }
    var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); toast('Copied'); } catch (e) { } ta.remove();
  };

  /* theme and print */
  var setThemeLabel = function () { var cur = document.documentElement.getAttribute('data-theme'); var dark = cur ? cur === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; $('theme').textContent = dark ? 'Light' : 'Dark'; };
  try { var saved = localStorage.getItem('wfx-theme'); if (saved) document.documentElement.setAttribute('data-theme', saved); } catch (e) { }
  setThemeLabel();
  $('theme').onclick = function () { var cur = document.documentElement.getAttribute('data-theme'); var dark = cur ? cur === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; var nx = dark ? 'light' : 'dark'; document.documentElement.setAttribute('data-theme', nx); try { localStorage.setItem('wfx-theme', nx); } catch (e) { } setThemeLabel(); };
  $('print').onclick = function () { window.print(); };

  /* data */
  var F = (D.findings || []).map(function (f, i) { f._i = i; f._d = dt(f.Time); return f; });
  var A = (D.activity || []).map(function (a) { a._d = dt(a.Time); return a; });
  var risk = D.risk || { Score: 0, Level: 'Low' }, pos = D.posture || { Score: 0, Level: 'Low' }, host = D.host || {}, cs = D.case || {};
  var techTac = {}, techName = {};
  (D.coverage || []).forEach(function (t) { techTac[t.Id] = t.Tactic; techName[t.Id] = t.Name; });
  var isHygiene = function (f) { return f.Category === 'Posture' || f.Category === 'Visibility'; };
  F.forEach(function (f) {
    var tacs = (f.Technique || []).map(function (t) { return techTac[t]; }).filter(Boolean);
    tacs.sort(function (a, b) { return TAC.indexOf(a) - TAC.indexOf(b); });
    f._tac = isHygiene(f) ? 'Hardening' : (tacs[0] || 'Other');
  });
  var attackF = F.filter(function (f) { return !isHygiene(f); });

  /* summary */
  var collected = dt(D.collected);
  $('sub').textContent = [host.Os || host.OS, host.Domain ? 'domain ' + host.Domain : '', collected ? 'collected ' + utc(collected).replace('T', ' ').replace('Z', ' UTC') : '', cs.Id ? 'case ' + String(cs.Id).slice(0, 8) : ''].filter(Boolean).join('  /  ');
  var V = { Critical: ['Compromise indicated', 'Treat this host as compromised until proven otherwise: isolate it, preserve evidence and scope the intrusion.'],
    High: ['Compromise likely', 'Strong indicators of attacker activity. Investigate now and consider isolating the host.'],
    Elevated: ['Suspicious activity', 'Some findings need an analyst to confirm or rule out attacker activity.'],
    Low: ['No strong indicators', 'Nothing in what could be seen strongly indicates compromise.'] };
  var v = V[risk.Level] || V.Low, vs = risk.Level === 'Critical' ? 'Critical' : risk.Level === 'High' ? 'High' : risk.Level === 'Elevated' ? 'Medium' : 'Low';
  $('verdict').innerHTML = '<span class="sev ' + vs + '" style="font-size:22px;gap:10px"><i class="sq" style="width:12px;height:12px"></i></span>' + esc(v[0]);
  var times = attackF.map(function (f) { return f._d; }).filter(Boolean).sort(function (a, b) { return a - b; });
  var hc = attackF.filter(function (f) { return RANK[f.Severity] <= 1; }).length;
  var stages = []; attackF.forEach(function (f) { if (TAC.indexOf(f._tac) >= 0 && stages.indexOf(f._tac) < 0) stages.push(f._tac); });
  stages.sort(function (a, b) { return TAC.indexOf(a) - TAC.indexOf(b); });
  $('lead').textContent = v[1] + ' ' + attackF.length + ' attacker-related finding' + (attackF.length === 1 ? '' : 's') + (hc ? ', ' + hc + ' critical or high' : '') +
    (stages.length ? ', across ' + stages.length + ' stage' + (stages.length === 1 ? '' : 's') + ' of the attack lifecycle (' + stages.join(', ') + ').' : '.') +
    ((D.gaps || []).length ? ' Some sources were not visible; see "What this report could not see" before concluding.' : '');
  var seenRule = {}; var top = attackF.slice().sort(function (a, b) { return RANK[a.Severity] - RANK[b.Severity] || b.Score - a.Score; }).filter(function (f) { var k = String(f.Id).replace(/-\d+$/, ''); if (seenRule[k] || seenRule[f.Title.replace(/\s*\(.*\)$/, '')]) return false; seenRule[k] = seenRule[f.Title.replace(/\s*\(.*\)$/, '')] = 1; return true; }).slice(0, 5);
  if (!top.length) top = F.slice().sort(function (a, b) { return RANK[a.Severity] - RANK[b.Severity]; }).slice(0, 3);
  var firstSentence = function (s) { s = String(s || 'Review the evidence.'); var m = s.match(/^.*?[.;](\s|$)/); s = (m ? m[0] : s).trim().replace(/[;,:]$/, ''); return /[.!?]$/.test(s) ? s : s + '.'; };
  $('todo').innerHTML = top.length ? top.map(function (f) { return '<li><div><b><a href="#f' + f._i + '" data-open="' + f._i + '">' + esc(f.Title) + '</a></b><span>' + esc(firstSentence(f.Recommendation)) + '</span></div></li>'; }).join('')
    : '<li><div><b>Nothing to act on</b><span>Check "What this report could not see" before concluding the host is clean.</span></div></li>';
  var S = D.summary || {};
  var accounts = {}, ext = {};
  var addAcct = function (v) { if (isAcct(v)) accounts[String(v).trim()] = 1; };
  attackF.forEach(function (f) { var e = f.Evidence || {}; ['User', 'Actor', 'Account', 'TargetUserName', 'SubjectUserName', 'MemberName'].forEach(function (k) { if (e[k]) addAcct(e[k]); }); });
  var meter = function (n) { return '<span class="meter"><i style="width:' + Math.max(0, Math.min(100, n)) + '%"></i></span>'; };
  var facts = [
    ['Compromise risk', esc(risk.Score) + ' / 100' + meter(risk.Score)],
    ['Hardening gaps', esc(pos.Score) + ' / 100' + meter(pos.Score)],
    ['Findings', '<span class="sevline">' + (SEV.filter(function (x) { return S[x]; }).map(function (x) { return '<span class="sev ' + x + '"><i class="sq"></i>' + S[x] + ' ' + x.toLowerCase() + '</span>'; }).join('') || 'none') + '</span>'],
    ['Suspicious activity', times.length ? esc(fmt(times[0])) + (times.length > 1 ? ' to ' + esc(fmt(times[times.length - 1])) : '') : '<span class="muted">no time-stamped findings</span>'],
    ['Accounts involved', Object.keys(accounts).length ? esc(Object.keys(accounts).slice(0, 4).join(', ')) + (Object.keys(accounts).length > 4 ? ' and ' + (Object.keys(accounts).length - 4) + ' more' : '') : '<span class="muted">none identified</span>'],
    ['External addresses', '<span id="f-ext">0</span>'],
    ['Changes recorded', esc(D.activityTotal || A.length || 0)],
    ['Execution artifacts', (D.artifactTotal || (D.artifacts || []).length) ? '<a href="#execution">' + esc(D.artifactTotal || D.artifacts.length) + '</a>' : '0'],
    ['Sources not visible', (D.gaps || []).length ? '<a href="#visibility">' + (D.gaps || []).length + '</a>' : '0']
  ];
  $('facts').innerHTML = facts.map(function (r) { return '<dt>' + r[0] + '</dt><dd>' + r[1] + '</dd>'; }).join('');

  /* indicator extraction */
  var IOC = [], seenI = {};
  var isPriv = function (ip) { var p = ip.split('.').map(Number); return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] >= 224 || (p[0] === 100 && p[1] >= 64 && p[1] <= 127); };
  var FILEEXT = /^(exe|dll|sys|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|scr|msi|iso|img|zip|rar|7z|txt|log|xml|json|csv|html?|docx?|docm|xlsx?|xlsm|pptx?|pdf|dat|tmp|ini|cfg|config|dmp|evtx|etl|pf|db|sqlite|jpg|png|gif|cpl|ocx|tlb|mui|manifest|ps|sh|py|dit|save|lockd|aspx?|php|jsp|sct|inf|reg|cer|crt|pem|key|pfx|bin)$/i;
  var addI = function (type, value, f) {
    value = String(value).replace(/[),.;'"\]]+$/, '');
    if (!value || value.length > 400) return;
    var k = type + '|' + value.toLowerCase(); var x = seenI[k];
    if (!x) { x = seenI[k] = { type: type, value: value, from: [], sev: f.Severity }; IOC.push(x); }
    if (x.from.indexOf(f._i) < 0) x.from.push(f._i);
    if (RANK[f.Severity] < RANK[x.sev]) x.sev = f.Severity;
  };
  var scan = function (s, f) {
    s = String(s);
    (s.match(/\b(?:hxxps?|https?|ftp):\/\/[^\s"'<>]+/gi) || []).forEach(function (u) { addI('URL', u, f); });
    (s.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).forEach(function (ip) { if (ip.split('.').every(function (o) { return +o <= 255; })) addI('IP address', ip, f); });
    (s.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) || []).forEach(function (h) { addI(h.length === 64 ? 'SHA-256' : h.length === 40 ? 'SHA-1' : 'MD5', h.toLowerCase(), f); });
    (s.match(/\b(?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+)\\[^\r\n"'<>|]+/g) || []).forEach(function (r) { addI('Registry key', r.trim(), f); });
    (s.match(/(?:\b[A-Za-z]:|\\\\[\w.$-]+)\\[^\r\n"'<>|*?]*?\.(?:exe|dll|sys|ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|scr|msi|iso|img|cpl|jar|sct|aspx?|php|jsp|dmp|dit|docm|xlsm)\b/gi) || []).forEach(function (p) { addI('File', p, f); });
    var noUrls = s.replace(/\b(?:hxxps?|https?|ftp):\/\/[^\s"'<>]+/gi, ' ');
    (noUrls.match(/(?:^|[^\/\\:@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b(?![!\w-])/g) || []).map(function (d) { return d.replace(/^[^a-z0-9]/, ''); }).forEach(function (d) {
      var tld = d.split('.').pop();
      if (FILEEXT.test(tld) || /^(system|microsoft|io|net|ws|mshtml|scrobj|comsvcs|wscript|shell32|kernel32)\./.test(d)) return;
      if (/^\d+(\.\d+)+$/.test(d)) return;
      if (/\.(local|lan|internal|corp|home|localdomain|arpa)$/.test(d)) return;
      addI('Domain', d, f);
    });
  };
  attackF.forEach(function (f) {
    var e = f.Evidence || {};
    Object.keys(e).forEach(function (k) { var v = e[k]; scan(typeof v === 'object' ? JSON.stringify(v) : v, f); });
    scan(f.Entity || '', f);
    ['User', 'Actor', 'Account', 'TargetUserName', 'MemberName'].forEach(function (k) { if (isAcct(e[k])) addI('Account', e[k], f); });
  });
  var extCount = IOC.filter(function (x) { return x.type === 'IP address' && !isPriv(x.value); }).length;
  $('f-ext').textContent = extCount;

  /* attack path */
  var byStage = {};
  attackF.forEach(function (f) { (byStage[f._tac] = byStage[f._tac] || []).push(f); });
  var stageKeys = Object.keys(byStage).sort(function (a, b) { var ia = TAC.indexOf(a), ib = TAC.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  $('n-p').textContent = stageKeys.length || '';
  if (!stageKeys.length) $('pathbox').innerHTML = '<div class="empty">No attacker-related findings to place on the attack lifecycle.</div>';
  else {
    $('pathbox').innerHTML = '<div class="tbl"><table><thead><tr><th>Stage</th><th>First seen</th><th>Most severe</th><th>What was found</th></tr></thead><tbody>' + stageKeys.map(function (k) {
      var L = byStage[k].slice().sort(function (a, b) { return RANK[a.Severity] - RANK[b.Severity] || b.Score - a.Score; });
      var ds = L.map(function (f) { return f._d; }).filter(Boolean).sort(function (a, b) { return a - b; });
      var shown = L.slice(0, 4).map(function (f) { return '<div><a href="#f' + f._i + '" data-open="' + f._i + '">' + esc(f.Title) + '</a></div>'; }).join('') + (L.length > 4 ? '<div class="small">and ' + (L.length - 4) + ' more</div>' : '');
      return '<tr><td class="stage">' + esc(k) + '</td><td class="t">' + (ds.length ? esc(fmt(ds[0])) : '<span class="muted">not time-stamped</span>') + '</td><td>' + sevHtml(L[0].Severity) + '</td><td>' + shown + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }

  /* findings table */
  $('n-f').textContent = F.length;
  var sevOn = {}; SEV.forEach(function (x) { sevOn[x] = true; });
  $('fsev').innerHTML = SEV.filter(function (x) { return S[x]; }).map(function (x) { return '<label><input type="checkbox" checked data-s="' + x + '"> ' + x + ' <span class="muted">' + S[x] + '</span></label>'; }).join(' ');
  var tacs = []; F.forEach(function (f) { if (tacs.indexOf(f._tac) < 0) tacs.push(f._tac); });
  tacs.sort(function (a, b) { var ia = TAC.indexOf(a), ib = TAC.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  $('ftac').innerHTML = '<option value="">All stages</option>' + tacs.map(function (t) { return '<option>' + esc(t) + '</option>'; }).join('');
  var cats = []; F.forEach(function (f) { if (cats.indexOf(f.Category) < 0) cats.push(f.Category); }); cats.sort();
  $('fcat').innerHTML = '<option value="">All areas</option>' + cats.map(function (c) { return '<option>' + esc(c) + '</option>'; }).join('');
  var sortK = 'sev', sortD = 1, openSet = {};
  var techLinks = function (f) { return (f.Technique || []).filter(function (t) { return TID.test(t); }).map(function (t) { return '<a class="mono" href="https://attack.mitre.org/techniques/' + esc(t.replace('.', '/')) + '/" target="_blank" rel="noopener noreferrer" title="' + esc(techName[t] || '') + '">' + esc(t) + '</a>'; }).join(' '); };
  var evTable = function (ev) {
    if (!ev || typeof ev !== 'object' || !Object.keys(ev).length) return '<p class="small">No structured evidence recorded.</p>';
    return '<table class="kv">' + Object.keys(ev).map(function (k) { var x = ev[k];
      if (Array.isArray(x)) x = x.map(function (y) { return (y && typeof y === 'object') ? JSON.stringify(y) : y; }).join('\n'); else if (x && typeof x === 'object') x = JSON.stringify(x, null, 1);
      return '<tr><td class="k">' + esc(k) + '</td><td class="v">' + esc(x == null || x === '' ? '-' : x) + '</td></tr>'; }).join('') + '</table>'; };
  var related = function (f) {
    if (!f._d) return '<p class="small">This finding has no time stamp, so related events cannot be lined up.</p>';
    var w = 30 * 60 * 1000, t0 = f._d.getTime(), ev = [];
    F.forEach(function (g) { if (g !== f && g._d && Math.abs(g._d - t0) <= w) ev.push({ d: g._d, h: sevHtml(g.Severity).replace('</span>', '') + '</span> <a href="#f' + g._i + '" data-open="' + g._i + '">' + esc(g.Title) + '</a>' }); });
    A.forEach(function (a) { if (a._d && Math.abs(a._d - t0) <= w) ev.push({ d: a._d, h: esc(a.Action) + ' <span class="m">' + esc(a.Target) + '</span>' }); });
    ev.push({ d: f._d, h: '<b>This finding</b>', self: true });
    ev.sort(function (a, b) { return a.d - b.d; });
    var more = ev.length > 14 ? ev.length - 14 : 0;
    if (more) { var si = ev.findIndex(function (e) { return e.self; }); var s = Math.max(0, Math.min(si - 7, ev.length - 14)); ev = ev.slice(s, s + 14); }
    return '<ul class="rel">' + ev.map(function (e) { return '<li' + (e.self ? ' class="self"' : '') + '><span class="muted">' + esc(fmtT(e.d)) + '</span><span>' + e.h + '</span></li>'; }).join('') + '</ul>' + (more ? '<p class="small" style="margin-top:6px">' + more + ' more events in this window; see the timeline.</p>' : '');
  };
  var detail = function (f) {
    return '<div class="dgrid"><div><h4>Why it matters</h4><p>' + esc(f.Description) + '</p>' + (f.Recommendation ? '<h4>What to do</h4><p>' + esc(f.Recommendation) + '</p>' : '') +
      '<h4>Within 30 minutes</h4>' + related(f) + '</div><div><h4>Evidence</h4>' + evTable(f.Evidence) +
      '<div class="meta">Rule <span class="mono">' + esc(f.Id) + '</span>' + (f.Source ? ' from ' + esc(f.Source) : '') + ', ' + esc(f.Confidence) + ' confidence. ' +
      '<button class="btn" type="button" data-copy="' + f._i + '" style="margin-left:6px">Copy finding</button></div></div></div>';
  };
  var renderF = function () {
    var q = $('fq').value.toLowerCase(), c = $('fcat').value, tc = $('ftac').value;
    var rows = F.filter(function (f) { return sevOn[f.Severity] && (!c || f.Category === c) && (!tc || f._tac === tc) && (!q || JSON.stringify(f).toLowerCase().indexOf(q) >= 0); });
    var key = { sev: function (f) { return RANK[f.Severity] * 1000 - (f.Score || 0); }, title: function (f) { return String(f.Title).toLowerCase(); }, tac: function (f) { var i = TAC.indexOf(f._tac); return i < 0 ? 99 : i; }, time: function (f) { return f._d ? f._d.getTime() : Infinity; }, cnt: function (f) { return -(f.Occurrences || 1); } }[sortK];
    rows.sort(function (a, b) { var x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * sortD || a._i - b._i; });
    var tb = $('ftbl').tBodies[0];
    tb.innerHTML = rows.length ? rows.map(function (f) {
      var o = openSet[f._i];
      return '<tr class="row' + (o ? ' open' : '') + '" id="f' + f._i + '" data-i="' + f._i + '"><td class="nw">' + sevHtml(f.Severity) + '</td><td class="ftl"><button class="tg" type="button" aria-expanded="' + (o ? 'true' : 'false') + '"><b>' + esc(f.Title) + '</b></button><span class="ent">' + esc(f.Entity || '') + '</span></td><td class="nw c-tac">' + esc(f._tac) + '</td><td class="nw c-tec">' + techLinks(f) + '</td><td class="t c-time">' + esc(fmt(f._d)) + '</td><td class="num c-cnt">' + esc(f.Occurrences || 1) + '</td></tr>' +
        (o ? '<tr class="detail"><td colspan="6">' + detail(f) + '</td></tr>' : '');
    }).join('') : '<tr><td colspan="6"><div class="empty">' + (F.length ? 'No findings match these filters.' : 'No findings. Check "What this report could not see" before concluding the host is clean.') + '</div></td></tr>';
    $('fcount').textContent = rows.length + ' of ' + F.length + ' findings shown.';
  };
  var openFinding = function (i, scroll) { openSet[i] = true; var f = F[i]; if (f && !sevOn[f.Severity]) { sevOn[f.Severity] = true; var cb = document.querySelector('#fsev input[data-s="' + f.Severity + '"]'); if (cb) cb.checked = true; } $('fq').value = ''; $('fcat').value = ''; $('ftac').value = ''; renderF(); if (scroll) { var el = $('f' + i); if (el) el.scrollIntoView({ block: 'start' }); } };
  $('ftbl').tBodies[0].addEventListener('click', function (e) {
    if (e.target.closest('a')) return;
    var cb = e.target.closest('[data-copy]');
    if (cb) { var f = F[+cb.getAttribute('data-copy')]; copy([f.Severity + ': ' + f.Title, 'Rule: ' + f.Id + '  Techniques: ' + (f.Technique || []).join(', '), 'Time (UTC): ' + utc(f._d), 'Entity: ' + (f.Entity || ''), '', f.Description, '', 'What to do: ' + (f.Recommendation || ''), '', 'Evidence: ' + JSON.stringify(f.Evidence || {}, null, 2)].join('\n')); return; }
    var tr = e.target.closest('tr.row'); if (!tr || e.target.closest('tr.detail')) return;
    var i = +tr.getAttribute('data-i'); openSet[i] = !openSet[i]; renderF();
  });
  document.addEventListener('click', function (e) { var a = e.target.closest('[data-open]'); if (!a) return; e.preventDefault(); openFinding(+a.getAttribute('data-open'), true); });
  $('fq').oninput = renderF; $('fcat').onchange = renderF; $('ftac').onchange = renderF;
  $('fsev').onchange = function (e) { var s = e.target.getAttribute('data-s'); if (s) { sevOn[s] = e.target.checked; renderF(); } };
  Array.prototype.forEach.call(document.querySelectorAll('#ftbl th.sort'), function (th) {
    th.tabIndex = 0;
    var go = function () { var k = th.getAttribute('data-k'); if (sortK === k) sortD = -sortD; else { sortK = k; sortD = 1; }
      Array.prototype.forEach.call(document.querySelectorAll('#ftbl th'), function (x) { x.removeAttribute('aria-sort'); });
      th.setAttribute('aria-sort', sortD > 0 ? 'ascending' : 'descending'); renderF(); };
    th.onclick = go; th.onkeydown = function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } };
  });
  $('fexp').onclick = function () { var on = this.getAttribute('aria-pressed') !== 'true'; this.setAttribute('aria-pressed', on); this.textContent = on ? 'Collapse all' : 'Expand all'; F.forEach(function (f) { openSet[f._i] = on; }); renderF(); };
  $('fx-csv').onclick = function () { download('findings_' + (D.hostName || 'host') + '.csv', csv([['severity', 'title', 'stage', 'techniques', 'time_utc', 'occurrences', 'area', 'rule', 'confidence', 'score', 'entity', 'recommendation', 'evidence']].concat(F.map(function (f) { return [f.Severity, f.Title, f._tac, (f.Technique || []).join(' '), utc(f._d), f.Occurrences || 1, f.Category, f.Id, f.Confidence, f.Score, f.Entity, f.Recommendation, JSON.stringify(f.Evidence || {})]; }))), 'text/csv'); };
  window.addEventListener('beforeprint', function () { F.forEach(function (f) { openSet[f._i] = true; }); renderF(); });
  renderF();
  if (/^#f\d+$/.test(location.hash)) openFinding(+location.hash.slice(2), true);

  /* indicators */
  var defang = function (t, v) { if (!$('idef').checked) return v; if (t === 'URL') return v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]'); if (t === 'Domain' || t === 'IP address') return v.replace(/\./g, '[.]'); return v; };
  var itypes = ['IP address', 'Domain', 'URL', 'SHA-256', 'SHA-1', 'MD5', 'File', 'Registry key', 'Account'];
  var present = itypes.filter(function (t) { return IOC.some(function (x) { return x.type === t; }); });
  $('itype').innerHTML = '<option value="">All types</option>' + present.map(function (t) { return '<option>' + t + '</option>'; }).join('');
  var isSysFile = function (x) { return x.type === 'File' && /^[a-z]:\\windows\\(?:system32|syswow64|winsxs)\\[^\\]+\.(?:exe|dll)$/i.test(x.value); };
  var iRows = function () { var q = $('iq').value.toLowerCase(), t = $('itype').value, pv = $('ipriv').checked, sy = $('isys').checked;
    return IOC.filter(function (x) { return (!t || x.type === t) && (pv || x.type !== 'IP address' || !isPriv(x.value)) && (sy || !isSysFile(x)) && (!q || x.value.toLowerCase().indexOf(q) >= 0); })
      .sort(function (a, b) { return itypes.indexOf(a.type) - itypes.indexOf(b.type) || RANK[a.sev] - RANK[b.sev] || a.value.localeCompare(b.value); }); };
  var renderI = function () {
    var rows = iRows(); $('n-i').textContent = IOC.filter(function (x) { return (x.type !== 'IP address' || !isPriv(x.value)) && !isSysFile(x); }).length;
    $('ibox').innerHTML = rows.length ? '<div class="tbl"><table><thead><tr><th>Type</th><th>Value</th><th>Most severe</th><th>Found in</th></tr></thead><tbody>' + rows.map(function (x) {
      return '<tr><td class="nw">' + esc(x.type) + (x.type === 'IP address' && isPriv(x.value) ? ' <span class="muted">(private)</span>' : '') + '</td><td class="m">' + esc(defang(x.type, x.value)) + '</td><td class="nw">' + sevHtml(x.sev) + '</td><td>' +
        x.from.slice(0, 3).map(function (i) { return '<div><a href="#f' + i + '" data-open="' + i + '">' + esc(F[i].Title) + '</a></div>'; }).join('') + (x.from.length > 3 ? '<div class="small">and ' + (x.from.length - 3) + ' more</div>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div><div class="count">' + rows.length + ' indicators shown.</div>'
      : '<div class="empty">' + (IOC.length ? 'No indicators match these filters.' : 'No indicators were found in the evidence of attacker-related findings.') + '</div>';
  };
  ['iq', 'itype', 'idef', 'ipriv', 'isys'].forEach(function (id) { $(id).addEventListener(id === 'iq' ? 'input' : 'change', renderI); });
  $('i-copy').onclick = function () { var r = iRows(); if (!r.length) { toast('Nothing to copy'); return; } copy(r.map(function (x) { return defang(x.type, x.value); }).join('\n')); };
  $('i-csv').onclick = function () { download('indicators_' + (D.hostName || 'host') + '.csv', csv([['type', 'value', 'severity', 'private', 'findings']].concat(iRows().map(function (x) { return [x.type, defang(x.type, x.value), x.sev, x.type === 'IP address' ? isPriv(x.value) : '', x.from.map(function (i) { return F[i].Title; }).join(' | ')]; }))), 'text/csv'); };
  renderI();

  /* timeline */
  var notable = /Hijack|Defen[cs]e|Credentials|Service installed|Software (installed|removed)|User created|Added to group|log cleared|Audit policy|Firewall|disabled|Malware|WMI|BITS|timestomp|Deleted to Recycle|Permanently deleted|Scheduled task (created|registered|changed)|Outbound RDP|Program ran|Executable\/script created|Kernel driver/i;
  var T = F.filter(function (f) { return f._d; }).map(function (f) { return { d: f._d, k: 'f', sev: f.Severity, what: f.Title, det: f.Entity || '', i: f._i }; })
    .concat(A.filter(function (a) { return a._d && notable.test(a.Action); }).map(function (a) { return { d: a._d, k: 'a', sev: '', what: a.Action, det: a.Target + (a.Actor ? '  (by ' + a.Actor + ')' : ''), src: a.Source }; }));
  T.sort(function (a, b) { return a.d - b.d; });
  $('n-t').textContent = T.length;
  var tRows = function () { var q = $('tq').value.toLowerCase(), only = $('tonly').checked; return T.filter(function (e) { return (!only || e.k === 'f') && (!q || (e.what + ' ' + e.det).toLowerCase().indexOf(q) >= 0); }); };
  var renderT = function () {
    var rows = tRows(), last = '', html = [];
    rows.slice(0, 3000).forEach(function (e) {
      var day = e.d.toLocaleDateString([], { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
      if (day !== last) { html.push('<tr class="day"><td colspan="4">' + esc(day) + '</td></tr>'); last = day; }
      html.push('<tr' + (e.k === 'f' ? '' : ' class="chg"') + '><td class="t">' + esc(fmtT(e.d)) + '</td><td class="nw">' + (e.k === 'f' ? sevHtml(e.sev) : '<span class="kind">Change</span>') + '</td><td>' + (e.k === 'f' ? '<a href="#f' + e.i + '" data-open="' + e.i + '">' + esc(e.what) + '</a>' : esc(e.what)) + '</td><td class="m">' + esc(e.det) + '</td></tr>');
    });
    $('tbox').innerHTML = rows.length ? '<div class="tbl"><table><thead><tr><th>Time</th><th>Kind</th><th>Event</th><th>Detail</th></tr></thead><tbody>' + html.join('') + '</tbody></table></div><div class="count">' + rows.length + ' events' + (rows.length > 3000 ? ', first 3,000 shown' : '') + '.</div>'
      : '<div class="empty">No time-stamped findings or notable changes.</div>';
  };
  $('tq').oninput = renderT; $('tonly').onchange = renderT;
  $('t-csv').onclick = function () { download('timeline_' + (D.hostName || 'host') + '.csv', csv([['time_utc', 'kind', 'severity', 'event', 'detail', 'source']].concat(tRows().map(function (e) { return [utc(e.d), e.k === 'f' ? 'finding' : 'change', e.sev, e.what, e.det, e.src || '']; }))), 'text/csv'); };
  renderT();

  /* changes */
  $('n-a').textContent = D.activityTotal || A.length || '';
  if (D.activityTotal > A.length) $('asub').textContent += ' Showing the newest ' + A.length + ' of ' + D.activityTotal + '; the full list is in raw\\bundle.json and the timeline export.';
  var acats = []; A.forEach(function (a) { if (acats.indexOf(a.Category) < 0) acats.push(a.Category); }); acats.sort();
  $('acat').innerHTML = '<option value="">All areas</option>' + acats.map(function (c) { return '<option>' + esc(c) + '</option>'; }).join('');
  var renderA = function () {
    if (!A.length) { $('abox').innerHTML = '<div class="empty">No change history was collected (an older bundle, offline re-analysis, or not run on Windows).</div>'; return; }
    var q = $('aq').value.toLowerCase(), c = $('acat').value;
    var rows = A.filter(function (a) { return (!c || a.Category === c) && (!q || JSON.stringify(a).toLowerCase().indexOf(q) >= 0); });
    $('abox').innerHTML = '<div class="tbl"><table><thead><tr><th>Time</th><th>Area</th><th>Change</th><th>Target</th><th>By</th><th>Source</th></tr></thead><tbody>' +
      rows.slice(0, 1500).map(function (a) { return '<tr><td class="t">' + esc(fmt(a._d)) + '</td><td class="nw">' + esc(a.Category) + '</td><td>' + esc(a.Action) + '</td><td class="m">' + esc(a.Target) + (a.Detail ? '<div class="small">' + esc(a.Detail) + '</div>' : '') + '</td><td class="m">' + esc(a.Actor) + '</td><td class="small">' + esc(a.Source) + '</td></tr>'; }).join('') +
      '</tbody></table></div><div class="count">' + rows.length + ' of ' + A.length + ' shown' + (rows.length > 1500 ? '; first 1,500 rendered' : '') + '.</div>';
  };
  $('aq').oninput = renderA; $('acat').onchange = renderA; renderA();

  /* incidents */
  var N = D.incidents || [];
  $('n-n').textContent = N.length || '';
  var fIndex = {}; F.forEach(function (f) { fIndex[f.Id + '|' + f.Entity] = f._i; });
  var entLabel = function (k) { var p = String(k).split(':'); var kind = p.shift(); return '<span class="kind">' + esc({ file: 'file', user: 'account', ip: 'address' }[kind] || kind) + '</span> ' + esc(p.join(':')); };
  $('nbox').innerHTML = N.length ? '<div class="tbl"><table><thead><tr><th>Incident</th><th>When</th><th>Severity</th><th>Stages</th><th>Involving</th><th>Findings</th></tr></thead><tbody>' + N.map(function (n) {
    var s = dt(n.Start), e = dt(n.End);
    var fl = (n.Findings || []).map(function (x) { var i = fIndex[x.Id + '|' + x.Entity]; return '<div>' + sevHtml(x.Severity).replace(/>\w+<\/span>$/, '></span>') + ' ' + (i === undefined ? esc(x.Title) : '<a href="#f' + i + '" data-open="' + i + '">' + esc(x.Title) + '</a>') + '</div>'; });
    return '<tr><td class="nw"><b>' + esc(n.Id) + '</b><div class="small">' + esc(n.Count) + ' findings</div></td><td class="t">' + esc(fmt(s)) + (e && s && e - s > 60000 ? '<div class="small">to ' + esc(fmt(e)) + '</div>' : '') + '</td><td>' + sevHtml(n.Severity) + '</td><td>' +
      esc((n.Tactics || []).join(' \u2192 ') || 'Other') + '</td><td>' + (n.Entities || []).slice(0, 5).map(function (k) { return '<div>' + entLabel(k) + '</div>'; }).join('') + '</td><td>' + fl.slice(0, 6).join('') + (fl.length > 6 ? '<div class="small">and ' + (fl.length - 6) + ' more</div>' : '') +
      ((n.Links || []).length ? '<div class="small">Grouped by: ' + esc(n.Links.slice(0, 4).join('; ')) + '</div>' : '') + '</td></tr>';
  }).join('') + '</tbody></table></div>' : '<div class="empty">No related findings to group. Single findings are listed under Findings.</div>';

  /* execution evidence */
  var E = (D.artifacts || []).map(function (a) { a._d = dt(a.Time); return a; });
  $('n-e').textContent = D.artifactTotal || E.length || '';
  if (D.artifactTotal > E.length) $('esub').textContent += ' Showing the newest ' + E.length + ' of ' + D.artifactTotal + '; all are in raw\\bundle.json.';
  var pathSev = {};
  var pkey = function (p) { return String(p || '').toLowerCase().replace(/^\(volume\)/, '').replace(/^[a-z]:/, ''); };
  attackF.forEach(function (f) { var e = f.Evidence || {}; ['Path', 'Image', 'File', 'Target'].forEach(function (k) { if (e[k]) { var key = pkey(e[k]); if (!pathSev[key] || RANK[f.Severity] < RANK[pathSev[key].s]) pathSev[key] = { s: f.Severity, i: f._i }; } }); });
  var eArts = [], eEvs = []; E.forEach(function (a) { if (eArts.indexOf(a.Artifact) < 0) eArts.push(a.Artifact); if (eEvs.indexOf(a.Evidence) < 0) eEvs.push(a.Evidence); });
  eArts.sort(); eEvs.sort();
  $('eart').innerHTML = '<option value="">All artifacts</option>' + eArts.map(function (x) { return '<option>' + esc(x) + '</option>'; }).join('');
  $('eev').innerHTML = '<option value="">All evidence</option>' + eEvs.map(function (x) { return '<option>' + esc(x) + '</option>'; }).join('');
  var eRows = function () {
    var q = $('eq').value.toLowerCase(), ar = $('eart').value, ev = $('eev').value, fo = $('eflag').checked;
    return E.filter(function (a) { return (!ar || a.Artifact === ar) && (!ev || a.Evidence === ev) && (!fo || pathSev[pkey(a.Path)]) && (!q || (a.Path + ' ' + a.User + ' ' + a.Sha1 + ' ' + a.Detail).toLowerCase().indexOf(q) >= 0); });
  };
  var renderE = function () {
    if (!E.length) { $('ebox').innerHTML = '<div class="empty">No execution artifacts in this case (an older bundle, event logs only, or not collected).</div>'; return; }
    var rows = eRows();
    $('ebox').innerHTML = '<div class="tbl"><table><thead><tr><th></th><th>Time</th><th>Artifact</th><th>Path</th><th>User</th><th>Detail</th></tr></thead><tbody>' +
      rows.slice(0, 1500).map(function (a) { var ps = pathSev[pkey(a.Path)]; return '<tr><td class="nw">' + (ps ? '<a href="#f' + ps.i + '" data-open="' + ps.i + '" title="' + esc(ps.s) + ' finding">' + sevHtml(ps.s) + '</a>' : '') + '</td><td class="t">' + (a._d ? esc(fmt(a._d)) : '<span class="muted">no time</span>') + (a.TimeKind ? '<div class="small">' + esc(a.TimeKind) + '</div>' : '') + '</td><td class="nw">' + esc(a.Artifact) + '<div class="small">' + esc(a.Evidence) + '</div></td><td class="m">' + esc(a.Path) + (a.Sha1 ? '<div class="small mono" title="SHA-1 ' + esc(a.Sha1) + '">sha1 ' + esc(String(a.Sha1).slice(0, 16)) + '\u2026</div>' : '') + '</td><td class="nw">' + esc(a.User || '') + '</td><td>' + esc(a.Detail || '') + '</td></tr>'; }).join('') +
      '</tbody></table></div><div class="count">' + rows.length + ' of ' + E.length + ' shown' + (rows.length > 1500 ? '; first 1,500 rendered' : '') + '.</div>';
  };
  $('eq').oninput = renderE; $('eart').onchange = renderE; $('eev').onchange = renderE; $('eflag').onchange = renderE; renderE();
  $('e-csv').onclick = function () { download('execution_' + (D.hostName || 'host') + '.csv', csv([['time_utc', 'time_meaning', 'artifact', 'evidence', 'path', 'user', 'sha1', 'detail', 'flag']].concat(eRows().map(function (a) { var ps = pathSev[pkey(a.Path)]; return [a.Time || '', a.TimeKind || '', a.Artifact, a.Evidence, a.Path, a.User || '', a.Sha1 || '', a.Detail || '', ps ? ps.s : '']; }))), 'text/csv'); };

  /* ATT&CK matrix + Navigator layer */
  var techMax = {}, techFind = {};
  F.forEach(function (f) { (f.Technique || []).forEach(function (t) { if (!TID.test(t)) return; if (techMax[t] === undefined || RANK[f.Severity] < RANK[techMax[t]]) techMax[t] = f.Severity; (techFind[t] = techFind[t] || []).push(f); }); });
  var techs = Object.keys(techMax);
  $('n-x').textContent = techs.length || '';
  if (!techs.length) $('xbox').innerHTML = '<div class="empty">No ATT&amp;CK techniques were observed.</div>';
  else {
    $('xbox').innerHTML = '<div class="matrix">' + TAC.map(function (tac) {
      var L = techs.filter(function (t) { return techTac[t] === tac; }).sort(function (a, b) { return RANK[techMax[a]] - RANK[techMax[b]] || a.localeCompare(b); });
      return '<div class="mcol' + (L.length ? '' : ' none') + '"><h4>' + esc(tac) + '<span>' + (L.length ? L.length + ' technique' + (L.length === 1 ? '' : 's') : 'none') + '</span></h4>' +
        L.map(function (t) { return '<a class="mt ' + techMax[t] + '" href="https://attack.mitre.org/techniques/' + esc(t.replace('.', '/')) + '/" target="_blank" rel="noopener noreferrer"><b><i class="sq"></i>' + esc(t) + '</b>' + esc(techName[t] || '') + '</a>'; }).join('') + '</div>';
    }).join('') + '</div>' + (techs.some(function (t) { return !techTac[t]; }) ? '<p class="small" style="margin-top:8px">Other techniques: ' + techs.filter(function (t) { return !techTac[t]; }).map(esc).join(', ') + '</p>' : '');
  }
  $('x-layer').onclick = function () {
    var color = { Critical: '#8e1b1b', High: '#c2351c', Medium: '#e3a008', Low: '#7aa7d9', Info: '#c8ccd1' }, score = { Critical: 100, High: 75, Medium: 50, Low: 25, Info: 10 };
    var layer = { name: 'WinForensicX ' + (D.hostName || ''), versions: { attack: '16', navigator: '5.1.0', layer: '4.5' }, domain: 'enterprise-attack',
      description: 'Techniques observed by ' + D.tool + ' on ' + (D.hostName || '') + ', collected ' + (D.collected || '') + ' UTC.',
      techniques: techs.map(function (t) { return { techniqueID: t, score: score[techMax[t]], color: color[techMax[t]], comment: techFind[t].map(function (f) { return f.Severity + ': ' + f.Title; }).slice(0, 10).join('\n'), enabled: true, showSubtechniques: true }; }),
      gradient: { colors: ['#ffffff', '#c2351c'], minValue: 0, maxValue: 100 },
      legendItems: SEV.slice(0, 4).map(function (s) { return { label: s, color: color[s] }; }), showTacticRowBackground: false, selectSubtechniquesWithParent: false };
    download('attack-layer_' + (D.hostName || 'host') + '.json', JSON.stringify(layer, null, 2), 'application/json');
  };

  /* visibility, custody, limits */
  var G = D.gaps || []; $('n-g').textContent = G.length || '';
  $('gbox').innerHTML = G.length ? '<ul class="list">' + G.map(function (x) { return '<li><b>' + esc(x.Source) + '</b>: ' + esc(x.Reason) + (x.Fix ? '<div class="fix">To fix: ' + esc(x.Fix) + '</div>' : '') + '</li>'; }).join('') + '</ul>' : '<div class="empty">Nothing was limited: collection ran with the visibility it attempted.</div>';
  var SP = D.suppressed || [];
  $('sbox').innerHTML = SP.length ? '<ul class="list">' + SP.map(function (x) { return '<li>' + sevHtml(x.Severity) + ' <b>' + esc(x.Title) + '</b><div class="fix">Reason: ' + esc(x.Reason || 'none given') + '. Allowlist rule ' + esc(x.Rule) + '.</div></li>'; }).join('') + '</ul>' : '<div class="empty">Nothing was suppressed.</div>';
  var kv = function (k, v) { return (v === undefined || v === null || v === '') ? '' : '<tr><td class="k">' + esc(k) + '</td><td class="v">' + esc(typeof v === 'object' ? JSON.stringify(v) : v) + '</td></tr>'; };
  $('cbox').innerHTML = '<table class="kv" style="width:100%">' + kv('Case id', cs.Id) + kv('Mode', cs.Mode) + kv('Collected (UTC)', D.collected) + kv('Case started (UTC)', cs.Started) + kv('Report generated (UTC)', D.generated) +
    kv('Operator', (cs.Operator || '') + (cs.OperatorHost ? ' on ' + cs.OperatorHost : '')) + kv('Elevated', cs.Admin) + kv('PowerShell', cs.PowerShell) + kv('Tool', D.tool) +
    kv('Host OS', host.Os) + kv('Host time zone', host.TimeZone) + kv('Parameters', cs.Parameters) +
    kv('Sources', (cs.Sources || []).map(function (s) { return s.role + ': ' + s.path + '  sha256 ' + s.sha256; }).join('\n')) + kv('Written to the evidence system drive', cs.OutputOnSystemDrive) + '</table>';
  $('verify').textContent = 'Test-WfxCase -Path "<this case folder>"';
  $('lbox').innerHTML = (D.limits || []).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('');
  $('foot').textContent = D.tool + '. Report generated ' + (D.generated || '') + ' UTC. Self-contained and offline; collection was read-only.';

  /* section highlight in the top bar */
  var links = Array.prototype.slice.call(document.querySelectorAll('#nav a'));
  var secs = links.map(function (a) { return document.querySelector(a.getAttribute('href')); });
  var onScroll = function () { var y = window.scrollY + 70, cur = 0; secs.forEach(function (s, i) { if (s && s.offsetTop <= y) cur = i; }); links.forEach(function (a, i) { a.classList.toggle('on', i === cur); }); var nav = $('nav'), on = links[cur]; if (on && (on.offsetLeft < nav.scrollLeft || on.offsetLeft + on.offsetWidth > nav.scrollLeft + nav.clientWidth)) nav.scrollLeft = on.offsetLeft - 20; };
  window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
})();
</script>
</body>
</html>
'@
