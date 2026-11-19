# Self-contained, offline HTML page for one Explore view: summary of flagged rows, filters, sortable table,
# a row panel with every field in full, copy and CSV export.
# Evidence values can be attacker-controlled (file names, command lines, registry data), so they are embedded
# as JSON with "<" escaped and inserted with textContent only — never as HTML. A strict CSP forbids any
# network access from the page.

function ConvertTo-WfxViewHtml {
    param([object[]]$Rows, [string]$Title, [object[]]$Note = @(), [string]$HostName = [Environment]::MachineName)
    $rows = @($Rows | Expand-WfxRecord)
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) { foreach ($p in $r.PSObject.Properties) { if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) } } }
    $data = [System.Collections.Generic.List[object]]::new()      # list of string[] — stays 2-D even with one row
    foreach ($r in $rows) {
        $cells = New-Object string[] $cols.Count
        for ($i = 0; $i -lt $cols.Count; $i++) {
            $p = $r.PSObject.Properties[$cols[$i]]
            $v = if ($p) { $p.Value } else { $null }
            $cells[$i] = if ($v -is [datetime]) { ConvertTo-WfxUtcString $v }
            elseif ($null -eq $v) { '' }
            elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { (@($v) -join '; ') }
            else { [string]$v }
        }
        $data.Add($cells)
    }
    $payload = [ordered]@{
        title = $Title; host = $HostName; generated = (Get-WfxUtcNow); tool = "WinForensicX $script:WfxVersion"
        columns = $cols.ToArray(); rows = $data.ToArray()
        notes = @($Note | Expand-WfxRecord | ForEach-Object { "$($_.Reason) $($_.Fix)".Trim() } | Select-Object -Unique)
    }
    $bs = [string][char]0x5C
    $json = (ConvertTo-Json -InputObject $payload -Depth 5 -Compress).Replace('&', "${bs}u0026").Replace('<', "${bs}u003c").Replace('>', "${bs}u003e").Replace([string][char]0x2028, "${bs}u2028").Replace([string][char]0x2029, "${bs}u2029")
    $script:WfxViewTemplate.Replace('<title>WinForensicX view</title>', '<title>' + [System.Net.WebUtility]::HtmlEncode("$Title, $HostName") + '</title>').Replace('/*DATA*/', $json)
}

function Save-WfxViewHtml {
    <# Writes ConvertTo-WfxViewHtml output to <case root>\views\ and returns the file path. #>
    param([object[]]$Rows, [string]$Title, [string]$Key = 'view', [object[]]$Note = @())
    $dir = Join-Path (Get-WfxCaseRoot) 'views'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $safeKey = $Key -replace '[^A-Za-z0-9_-]', '_'
    $f = Join-Path $dir ("{0}_{1}_{2}.html" -f [Environment]::MachineName, $safeKey, (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
    [IO.File]::WriteAllText($f, (ConvertTo-WfxViewHtml -Rows $Rows -Title $Title -Note $Note), (New-Object System.Text.UTF8Encoding($false)))
    $f
}

$script:WfxViewTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WinForensicX view</title>
<style>
:root {
  --canvas: #FFFFFF; --paper: #FFFFFF; --alt: #F5F6F8; --ink: #17202C; --ink2: #4E5967; --ink3: #7B8591;
  --rule: #D3D8DE; --rule2: #E6E9ED; --link: #0B57A4; --sel: #E7EEF7; --band: #14233A; --band-ink: #F1F4F8; --band-dim: #A9B6C6;
  --crit: #9B1C1C; --high: #C2410C; --med: #A16207; --low: #2B6CB0; --info: #6B7280; --row-hover: #F5F6F8; --mark: .028;
  --sans: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --display: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --mono: "Cascadia Mono", "Cascadia Code", Consolas, "SF Mono", Menlo, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --canvas: #14181D; --paper: #14181D; --alt: #1A1F25; --ink: #E3E7EC; --ink2: #A4AEBA; --ink3: #7D8793;
  --rule: #333B45; --rule2: #262D35; --link: #7CB1EC; --sel: #1F2B3A; --band: #0D141D;
  --crit: #F07171; --high: #F59056; --med: #E2B04A; --low: #7FB0E6; --info: #9AA3AE; --row-hover: #1A1F25; --mark: .04; color-scheme: dark; } }
:root[data-theme="dark"] {
  --canvas: #14181D; --paper: #14181D; --alt: #1A1F25; --ink: #E3E7EC; --ink2: #A4AEBA; --ink3: #7D8793;
  --rule: #333B45; --rule2: #262D35; --link: #7CB1EC; --sel: #1F2B3A; --band: #0D141D;
  --crit: #F07171; --high: #F59056; --med: #E2B04A; --low: #7FB0E6; --info: #9AA3AE; --row-hover: #1A1F25; --mark: .04; color-scheme: dark; }

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; font-variant-ligatures: none; }
body { margin: 0; background: var(--canvas); color: var(--ink); font: 14px/1.5 var(--sans); }
button, input, select { font: inherit; color: inherit; }
a { color: var(--link); text-decoration: none; } a:hover { text-decoration: underline; }
:focus-visible { outline: 2px solid var(--link); outline-offset: 2px; border-radius: 3px; }
.watermark { position: fixed; left: 50%; top: 58%; width: min(64vw, 520px); transform: translate(-50%, -50%) rotate(-12deg); color: var(--ink); opacity: var(--mark); pointer-events: none; z-index: 20; }
.watermark text { font: 700 7px var(--display); }

.mast { background: var(--band); color: var(--band-ink); }
.mast-in { max-width: 1600px; margin: 0 auto; padding: 14px 24px 18px; }
.brandrow { display: flex; align-items: center; gap: 12px; }
.logo { display: flex; align-items: center; gap: 9px; }
.logo svg { width: 26px; height: 26px; }
.logo b { font: 600 15.5px/1 var(--display); }
.logo span { font-size: 12.5px; opacity: .7; padding-left: 9px; border-left: 1px solid rgba(255,255,255,.22); }
.mbtns { margin-left: auto; display: flex; gap: 8px; }
.mbtn { background: transparent; border: 1px solid rgba(255,255,255,.25); border-radius: 3px; padding: 3px 10px; cursor: pointer; font-size: 12.5px; color: var(--band-ink); }
.mbtn:hover { border-color: rgba(255,255,255,.6); }
.mast h1 { font: 600 26px/1.2 var(--display); letter-spacing: -.01em; margin: 18px 0 6px; overflow-wrap: anywhere; }
.meta { display: flex; flex-wrap: wrap; gap: 3px 22px; font-size: 13px; color: var(--band-dim); }
.meta b { color: var(--band-ink); font-weight: 500; }

main { max-width: 1600px; margin: 0 auto; padding: 18px 24px 40px; }

/* what this view says, before the table */
.summary { display: flex; flex-wrap: wrap; gap: 6px 26px; align-items: baseline; padding: 0 0 12px; border-bottom: 1px solid var(--rule2); margin-bottom: 14px; font-size: 13.5px; color: var(--ink2); }
.summary b { color: var(--ink); font-weight: 600; }
.summary > span { min-width: 0; max-width: 100%; overflow-wrap: anywhere; }
.summary .sevs { display: inline-flex; flex-wrap: wrap; gap: 4px 14px; }
.clean { color: var(--ink2); }
.notes { margin: 0 0 14px; border: 1px solid var(--rule); background: var(--alt); }
.notes summary { padding: 8px 12px; cursor: pointer; font-size: 13.5px; }
.notes summary b { font-weight: 600; }
.notes ul { margin: 0; padding: 0 16px 10px 30px; font-size: 13px; color: var(--ink2); }
.notes li { margin: 3px 0; }
.toolbar select { padding: 6px 8px; border: 1px solid var(--rule); border-radius: 3px; background: var(--paper); font-size: 13.5px; max-width: 220px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.toolbar input[type=search] { flex: 1 1 280px; padding: 6px 10px; border: 1px solid var(--rule); border-radius: 3px; background: var(--paper); }
.tbtn { background: var(--paper); border: 1px solid var(--rule); border-radius: 3px; padding: 6px 11px; cursor: pointer; font-size: 13.5px; }
.tbtn:hover { border-color: var(--ink3); }
.tbtn[aria-pressed="true"] { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.count { color: var(--ink2); font-size: 13px; margin-left: auto; font-variant-numeric: tabular-nums; }
.colmenu { position: relative; }
.colmenu .pop { position: absolute; right: 0; top: calc(100% + 4px); z-index: 30; background: var(--paper); border: 1px solid var(--rule); padding: 8px 12px; display: grid; gap: 4px; min-width: 190px; }
.colmenu .pop[hidden] { display: none; }
.colmenu label { display: flex; gap: 8px; align-items: center; font-size: 13.5px; cursor: pointer; }

.layout { display: grid; grid-template-columns: minmax(0, 1fr); gap: 14px; align-items: start; }
.layout.open { grid-template-columns: minmax(0, 1fr) 420px; }
.tablewrap { background: var(--paper); border: 1px solid var(--rule); border-radius: 0; overflow: auto; max-height: calc(100vh - 120px); position: relative; }
table { border-collapse: separate; border-spacing: 0; width: 100%; font-size: 13px; }
th { position: sticky; top: 0; z-index: 2; background: var(--alt); text-align: left; font-weight: 600; font-size: 12.5px; color: var(--ink2); padding: 9px 12px; border-bottom: 1px solid var(--rule); white-space: nowrap; cursor: pointer; user-select: none; }
th:hover { color: var(--ink); }
th[aria-sort] { color: var(--ink); }
th[aria-sort="ascending"]::after { content: " \2191"; color: var(--link); }
th[aria-sort="descending"]::after { content: " \2193"; color: var(--link); }
td { padding: 8px 12px; border-bottom: 1px solid var(--rule2); vertical-align: top; max-width: 460px; overflow-wrap: break-word; }
td .c { min-width: 12ch; }
td.m { font-family: var(--mono); font-size: 12px; min-width: 24ch; }
td.m .c { min-width: 26ch; overflow-wrap: anywhere; }
td.why .c { min-width: 30ch; }
td .c { display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 3; line-clamp: 3; overflow: hidden; }
@media print { td .c { display: block; -webkit-line-clamp: unset; } }
td.nw { white-space: nowrap; }
td.why { min-width: 260px; max-width: 420px; }
td.ts { white-space: nowrap; font-variant-numeric: tabular-nums; color: var(--ink2); }
td.hash { font-family: var(--mono); font-size: 12px; color: var(--ink2); white-space: nowrap; }
td.dim { color: var(--ink3); }
tbody tr { cursor: pointer; }
tbody tr:hover td { background: var(--row-hover); }
tbody tr.sel td { background: var(--sel); }
.more { padding: 12px; text-align: center; border-top: 1px solid var(--rule2); }
.empty { padding: 40px 20px; text-align: center; color: var(--ink2); }

.sev { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; font-weight: 600; white-space: nowrap; }
.sev::before { content: ""; width: 9px; height: 9px; background: currentColor; flex: none; }
.sev.Critical { color: var(--crit); } .sev.Critical::before { transform: rotate(45deg); }
.sev.High { color: var(--high); } .sev.High::before { clip-path: polygon(50% 0, 100% 100%, 0 100%); width: 10px; }
.sev.Medium { color: var(--med); }
.sev.Low { color: var(--low); } .sev.Low::before { border-radius: 50%; }
.sev.Info { color: var(--info); } .sev.Info::before { border-radius: 50%; background: transparent; border: 2px solid currentColor; }

/* detail panel */
.detail { background: var(--paper); border: 1px solid var(--rule); border-radius: 0; position: sticky; top: 12px; max-height: calc(100vh - 24px); overflow: auto; }
.detail[hidden] { display: none; }
.dtop { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--rule); position: sticky; top: 0; background: var(--paper); z-index: 1; }
.dtop .nav { margin-left: auto; display: flex; gap: 6px; }
.dtop button { background: var(--paper); border: 1px solid var(--rule); border-radius: 3px; padding: 3px 9px; cursor: pointer; font-size: 13px; }
.dbody { padding: 14px 16px 18px; }
.dwhy { font: 500 17px/1.35 var(--display); margin: 0 0 8px; overflow-wrap: anywhere; }
.dlbl { color: var(--ink2); font-size: 12.5px; margin: 0 0 3px; }
.techs { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 14px; }
.tech { font-size: 12.5px; font-family: var(--mono); }
.techs .tech + .tech::before { content: ''; }
.dfields { display: grid; gap: 0; border-top: 1px solid var(--rule2); }
.df { padding: 8px 0; border-bottom: 1px solid var(--rule2); display: grid; grid-template-columns: 1fr auto; gap: 2px 8px; }
.df dt { color: var(--ink2); font-size: 12.5px; grid-column: 1; }
.df dd { margin: 0; grid-column: 1 / -1; font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; white-space: pre-wrap; }
.df button { grid-column: 2; grid-row: 1; background: none; border: 0; color: var(--link); font-size: 12px; cursor: pointer; padding: 0; }
.dempty { padding: 26px 16px; color: var(--ink2); }

footer { max-width: 1600px; margin: 0 auto; padding: 0 24px 28px; color: var(--ink3); font-size: 12.5px; display: flex; flex-wrap: wrap; gap: 6px 18px; }

@media (max-width: 1100px) { .layout.open { grid-template-columns: 1fr; } .detail { position: static; max-height: none; } }
@media (max-width: 720px) {
  .mast-in, main, footer { padding-left: 16px; padding-right: 16px; }
  .mast h1 { font-size: 22px; }
  .count { margin-left: 0; width: 100%; }
}
@media print {
  html, body { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: #fff; }
  .mast { background: #fff; color: #000; border-bottom: 2px solid #000; }
  .mast .meta, .mast .meta b, .logo span { color: #000; }
  .mbtns, .toolbar, .detail, .more { display: none; }
  .tablewrap { max-height: none; overflow: visible; border: 0; }
  th { position: static; }
  tr { break-inside: avoid; }
  tbody tr.sel td { background: none; }
}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="wfx-mark" viewBox="0 0 64 64">
    <path d="M6 20V6h14M44 6h14v14M58 44v14H44M20 58H6V44" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="square"/>
    <path d="M20 20l24 24M44 20L20 44" fill="none" stroke="currentColor" stroke-width="6"/>
    <circle cx="32" cy="32" r="9" fill="var(--lens, #14233A)" stroke="currentColor" stroke-width="5"/>
    <circle cx="32" cy="32" r="3" fill="currentColor"/>
  </symbol>
</svg>
<svg class="watermark" viewBox="0 0 64 80" aria-hidden="true" style="--lens: transparent"><use href="#wfx-mark" width="64" height="64"/><text x="32" y="77" text-anchor="middle" fill="currentColor">WinForensicX</text></svg>

<header class="mast">
  <div class="mast-in">
    <div class="brandrow">
      <div class="logo"><svg viewBox="0 0 64 64" aria-hidden="true" style="color:var(--band-ink); --lens: #14233A"><use href="#wfx-mark"/></svg><b>WinForensicX</b><span>Explore view</span></div>
      <div class="mbtns"><button class="mbtn" id="theme" type="button">Dark</button><button class="mbtn" type="button" id="printbtn">Print</button></div>
    </div>
    <h1 id="title"></h1>
    <div class="meta" id="meta"></div>
  </div>
</header>

<main>
  <div class="summary" id="summary"></div>
  <details class="notes" id="notes" hidden><summary></summary><ul></ul></details>

  <div class="toolbar">
    <input id="q" type="search" placeholder="Search every column" aria-label="Search every column">
    <select id="fsev" aria-label="Flag"></select>
    <span id="facetsel"></span>
    <div class="colmenu"><button class="tbtn" id="colbtn" type="button" aria-expanded="false">Columns</button><div class="pop" id="colpop" hidden></div></div>
    <button class="tbtn" id="copy" type="button">Copy rows</button>
    <button class="tbtn" id="csv" type="button">Download CSV</button>
    <span class="count" id="count" aria-live="polite"></span>
  </div>

  <div class="layout" id="layout">
    <div class="tablewrap" id="wrap">
      <table><thead><tr id="head"></tr></thead><tbody id="body"></tbody></table>
      <div class="more" id="more" hidden><button class="tbtn" type="button" id="morebtn"></button></div>
    </div>
    <aside class="detail" id="detail" hidden aria-label="Row details">
      <div class="dtop"><span id="dsev"></span><div class="nav"><button type="button" id="dprev" aria-label="Previous row">Previous</button><button type="button" id="dnext" aria-label="Next row">Next</button><button type="button" id="dclose" aria-label="Close details">Close</button></div></div>
      <div class="dbody" id="dbody"></div>
    </aside>
  </div>
</main>
<footer id="foot"></footer>

<script type="application/json" id="data">/*DATA*/</script>
<script>
(function () {
'use strict';
var D = JSON.parse(document.getElementById('data').textContent);
var $ = function (id) { return document.getElementById(id); };
var mk = function (tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
var cols = D.columns, rows = D.rows;
var SEV = ['Critical', 'High', 'Medium', 'Low', 'Info'];
var title = function (s) { s = String(s || ''); return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : ''; };
var ci = function (n) { return cols.indexOf(n); };
var FC = ci('Flag'), WC = ci('Why'), TC = ci('Technique'), RC = ci('Rule');
var isTs = function (v) { return /^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(v); };
var pad = function (n) { return (n < 10 ? '0' : '') + n; };
var fmtTs = function (v) { var d = new Date(v); return isNaN(d) ? v : d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()); };

// theme (per-viewer convenience; storage can fail, the page works without it)
var root = document.documentElement, tbtn = $('theme');
function applyTheme(t) { if (t) root.setAttribute('data-theme', t); var dark = t ? t === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; tbtn.textContent = dark ? 'Light' : 'Dark'; }
try { applyTheme(localStorage.getItem('wfx-theme')); } catch (e) { applyTheme(null); }
tbtn.onclick = function () { var dark = tbtn.textContent === 'Dark'; applyTheme(dark ? 'dark' : 'light'); try { localStorage.setItem('wfx-theme', dark ? 'dark' : 'light'); } catch (e) {} };
$('printbtn').onclick = function () { print(); };

// header
$('title').textContent = D.title; document.title = D.title + ' — ' + D.host;
var meta = [['Host', D.host], ['Generated', fmtTs(D.generated) + ' UTC'], ['', 'Read-only snapshot']];
meta.forEach(function (m) { var s = mk('span'); if (m[0]) { s.appendChild(document.createTextNode(m[0] + ' ')); s.appendChild(mk('b', '', m[1])); } else s.textContent = m[1]; $('meta').appendChild(s); });
var foot = $('foot'); [D.tool, 'Generated ' + fmtTs(D.generated) + ' UTC on ' + D.host, 'Values are shown as text and never run. Flags are leads, not verdicts.'].forEach(function (t) { foot.appendChild(mk('span', '', t)); });

// column shape: which are short (no wrap), hashes, timestamps, mono
var kind = cols.map(function (c, i) {
  var max = 0, ts = 0, hex = 0, n = Math.min(rows.length, 3000);
  for (var r = 0; r < n; r++) { var v = rows[r][i]; if (v.length > max) max = v.length; if (isTs(v)) ts++; if (/^[0-9a-f]{32,64}$/i.test(v)) hex++; }
  if (i === FC) return 'flag'; if (i === WC) return 'why';
  if (ts && ts >= n * 0.5) return 'ts'; if (hex && hex >= n * 0.3) return 'hash';
  if (/path|command|target|location|image|file|key|url|arguments|detail/i.test(c)) return 'm';
  return max <= 28 ? 'nw' : '';
});
// rule ID and technique are shown in the row panel; start with them hidden so paths fit
var hidden = {}; if (RC >= 0) hidden[RC] = true; if (TC >= 0 && FC >= 0) hidden[TC] = true;

// filters
var state = { q: '', flag: '', facet: {}, sort: -1, dir: 1, limit: 300, sel: -1 };
var view = [];

// summary line and filters: flag level and the most useful short columns
var tally = {}; if (FC >= 0) rows.forEach(function (r) { var f = title(r[FC]); if (f) tally[f] = (tally[f] || 0) + 1; });
var flagged = SEV.filter(function (s) { return tally[s]; });
var sm = $('summary');
var addSum = function (label, node) { var s = mk('span'); if (label) s.appendChild(document.createTextNode(label + ' ')); s.appendChild(node); sm.appendChild(s); };
addSum('', mk('b', '', rows.length.toLocaleString('en-US') + ' rows'));
if (FC >= 0) {
  if (!flagged.length) addSum('', mk('span', 'clean', 'No row matched a triage rule.'));
  else { var sv = mk('span', 'sevs'); flagged.forEach(function (s) { sv.appendChild(mk('span', 'sev ' + s, tally[s].toLocaleString('en-US') + ' ' + s.toLowerCase())); }); addSum('Flagged by the triage rules:', sv); }
  var fs = $('fsev'); fs.appendChild(new Option('All rows', '')); fs.appendChild(new Option('Flagged rows only', '*'));
  flagged.forEach(function (s) { fs.appendChild(new Option(s + ' only (' + tally[s] + ')', s)); });
  fs.onchange = function () { state.flag = fs.value; state.limit = 300; refresh(); };
} else $('fsev').hidden = true;
var prefer = /^(artifact|evidence|category|kind|action|type|state|status|source|log)$/i;
var facetCols = cols.map(function (c, i) { return i; }).filter(function (i) {
  if (i === FC || i === WC || i === TC || i === RC || kind[i] === 'ts' || kind[i] === 'hash') return false;
  var seen = {}, k = 0; for (var r = 0; r < rows.length; r++) { var v = rows[r][i]; if (v && !seen[v]) { seen[v] = 1; if (++k > 40) return false; } } return k >= 2;
}).sort(function (a, b) { return (prefer.test(cols[b]) ? 1 : 0) - (prefer.test(cols[a]) ? 1 : 0) || a - b; }).slice(0, 2);
facetCols.forEach(function (i) {
  var counts = {}; rows.forEach(function (r) { var v = r[i]; if (v) counts[v] = (counts[v] || 0) + 1; });
  var keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a] || (a < b ? -1 : 1); });
  var sel = mk('select'); sel.setAttribute('aria-label', cols[i]); sel.appendChild(new Option(cols[i] + ': all', ''));
  keys.forEach(function (k) { sel.appendChild(new Option(k + ' (' + counts[k].toLocaleString('en-US') + ')', k)); });
  sel.onchange = function () { state.facet[i] = sel.value || null; state.limit = 300; refresh(); };
  $('facetsel').appendChild(sel);
  if (keys.length <= 12) { var by = mk('span'); by.textContent = keys.slice(0, 6).map(function (k) { return k + ' ' + counts[k].toLocaleString('en-US'); }).join(', ') + (keys.length > 6 ? ', and ' + (keys.length - 6) + ' more' : ''); addSum(cols[i] + ':', by); }
});
if (D.notes && D.notes.length) {
  var nt = $('notes'); nt.hidden = false;
  var su = nt.querySelector('summary'); su.appendChild(mk('b', '', D.notes.length + (D.notes.length === 1 ? ' note' : ' notes') + ' from collection')); su.appendChild(document.createTextNode(': what this view could not see or read fully. Read them before concluding something is absent.'));
  D.notes.forEach(function (n) { nt.querySelector('ul').appendChild(mk('li', '', n)); });
  if (D.notes.length <= 2) nt.open = true;
}

// column picker
cols.forEach(function (c, i) {
  var l = mk('label'), cb = mk('input'); cb.type = 'checkbox'; cb.checked = !hidden[i];
  cb.onchange = function () { hidden[i] = !cb.checked; drawHead(); drawBody(); };
  l.appendChild(cb); l.appendChild(document.createTextNode(c)); $('colpop').appendChild(l);
});
$('colbtn').onclick = function () { var p = $('colpop'); p.hidden = !p.hidden; $('colbtn').setAttribute('aria-expanded', !p.hidden); };
document.addEventListener('click', function (e) { if (!e.target.closest('.colmenu')) { $('colpop').hidden = true; $('colbtn').setAttribute('aria-expanded', 'false'); } });

// table
var sevRank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
function key(v, i) { if (i === FC) return [0, -(sevRank[v] || 0)]; if (v === '') return [2, '']; var n = Number(v); if (!isNaN(n)) return [0, n]; if (isTs(v)) return [0, Date.parse(v)]; return [1, v.toLowerCase()]; }
function drawHead() {
  var h = $('head'); h.textContent = '';
  cols.forEach(function (c, i) {
    if (hidden[i]) return;
    var th = mk('th', '', c); th.tabIndex = 0; th.scope = 'col';
    if (state.sort === i) th.setAttribute('aria-sort', state.dir > 0 ? 'ascending' : 'descending');
    var go = function () { state.dir = state.sort === i ? -state.dir : 1; state.sort = i; refresh(); };
    th.onclick = go; th.onkeydown = function (e) { if (e.key === 'Enter') go(); };
    h.appendChild(th);
  });
}
function refresh() {
  var q = state.q.toLowerCase();
  view = [];
  for (var r = 0; r < rows.length; r++) {
    var row = rows[r], f = FC >= 0 ? title(row[FC]) : '';
    if (state.flag === '*' && (!f || f === 'Info')) continue;
    if (state.flag && state.flag !== '*' && f !== state.flag) continue;
    var ok = true; for (var k in state.facet) { if (state.facet[k] && row[k] !== state.facet[k]) { ok = false; break; } } if (!ok) continue;
    if (q && row.join('\u0001').toLowerCase().indexOf(q) < 0) continue;
    view.push(r);
  }
  if (state.sort >= 0) { var i = state.sort, d = state.dir; view.sort(function (a, b) { var x = key(rows[a][i], i), y = key(rows[b][i], i); if (x[0] !== y[0]) return x[0] - y[0]; return x[1] < y[1] ? -d : x[1] > y[1] ? d : a - b; }); }
  drawHead(); drawBody();
}
function drawBody() {
  var b = $('body'); b.textContent = '';
  var n = Math.min(view.length, state.limit), frag = document.createDocumentFragment();
  for (var k = 0; k < n; k++) {
    var r = view[k], row = rows[r], tr = mk('tr'), f = FC >= 0 ? title(row[FC]) : '';
    tr.tabIndex = 0; tr.setAttribute('data-r', r); if (f) tr.className = 'f-' + f; if (r === state.sel) tr.className += ' sel';
    for (var i = 0; i < cols.length; i++) {
      if (hidden[i]) continue;
      var v = row[i], td = mk('td');
      if (i === FC) { if (v) td.appendChild(mk('span', 'sev ' + f, f)); td.className = 'nw'; }
      else if (kind[i] === 'ts' && v) { td.className = 'ts'; td.textContent = fmtTs(v); td.title = v; }
      else if (kind[i] === 'hash' && v) { td.className = 'hash'; td.textContent = v.slice(0, 12) + '…'; td.title = v; }
      else { td.className = kind[i] === 'why' ? 'why' : kind[i]; var c = mk('span', 'c', v); td.appendChild(c); if (v.length > 120) td.title = v; }
      tr.appendChild(td);
    }
    frag.appendChild(tr);
  }
  b.appendChild(frag);
  if (!view.length) { var tr0 = mk('tr'), td0 = mk('td', 'empty', 'No row matches. Clear the search or the filters above.'); td0.colSpan = cols.length; tr0.appendChild(td0); b.appendChild(tr0); }
  var more = view.length - n; $('more').hidden = more <= 0; $('morebtn').textContent = 'Show ' + Math.min(more, 300) + ' more of ' + more.toLocaleString('en-US');
  $('count').textContent = (view.length === rows.length ? rows.length.toLocaleString('en-US') + ' rows' : view.length.toLocaleString('en-US') + ' of ' + rows.length.toLocaleString('en-US') + ' rows');
}
$('morebtn').onclick = function () { state.limit += 300; drawBody(); };
var qt; $('q').addEventListener('input', function () { clearTimeout(qt); qt = setTimeout(function () { state.q = $('q').value; state.limit = 300; refresh(); }, 120); });

// row details: the whole row, full values, why it is flagged first
function openRow(r) {
  state.sel = r; var row = rows[r], f = FC >= 0 ? title(row[FC]) : '';
  [].forEach.call(document.querySelectorAll('#body tr'), function (tr) { tr.classList.toggle('sel', +tr.getAttribute('data-r') === r); });
  $('layout').classList.add('open'); $('detail').hidden = false;
  var ds = $('dsev'); ds.textContent = ''; ds.appendChild(f ? mk('span', 'sev ' + f, f) : mk('span', 'clean', 'Not flagged'));
  var b = $('dbody'); b.textContent = '';
  if (WC >= 0 && row[WC]) { b.appendChild(mk('p', 'dlbl', 'Why it is flagged')); b.appendChild(mk('p', 'dwhy', row[WC])); }
  if (TC >= 0 && row[TC]) {
    var tw = mk('div', 'techs');
    row[TC].split(/[,;]\s*/).forEach(function (t) { if (!/^T\d{4}(\.\d{3})?$/.test(t)) return; var a = mk('a', 'tech', t); a.href = 'https://attack.mitre.org/techniques/' + t.replace('.', '/') + '/'; a.target = '_blank'; a.rel = 'noopener noreferrer'; tw.appendChild(a); });
    if (RC >= 0 && row[RC]) tw.appendChild(mk('span', 'tech', row[RC]));
    b.appendChild(tw);
  }
  var dl = mk('dl', 'dfields');
  cols.forEach(function (c, i) {
    if (i === FC || i === WC || i === TC || i === RC || !row[i]) return;
    var d = mk('div', 'df'); d.appendChild(mk('dt', '', c));
    var cp = mk('button', '', 'Copy'); cp.type = 'button'; cp.onclick = function () { copyText(row[i], cp); }; d.appendChild(cp);
    d.appendChild(mk('dd', '', kind[i] === 'ts' ? fmtTs(row[i]) + ' UTC  (' + row[i] + ')' : row[i])); dl.appendChild(d);
  });
  b.appendChild(dl);
}
function closeRow() { state.sel = -1; $('detail').hidden = true; $('layout').classList.remove('open'); [].forEach.call(document.querySelectorAll('#body tr.sel'), function (t) { t.classList.remove('sel'); }); }
function step(d) { var k = view.indexOf(state.sel) + d; if (k < 0 || k >= view.length) return; if (k >= state.limit) { state.limit += 300; drawBody(); } openRow(view[k]); var tr = document.querySelector('#body tr[data-r="' + view[k] + '"]'); if (tr) tr.scrollIntoView({ block: 'nearest' }); }
$('body').addEventListener('click', function (e) { var tr = e.target.closest('tr[data-r]'); if (tr) openRow(+tr.getAttribute('data-r')); });
$('body').addEventListener('keydown', function (e) { var tr = e.target.closest('tr[data-r]'); if (tr && e.key === 'Enter') openRow(+tr.getAttribute('data-r')); });
$('dclose').onclick = closeRow; $('dprev').onclick = function () { step(-1); }; $('dnext').onclick = function () { step(1); };
document.addEventListener('keydown', function (e) {
  if (e.target.matches('input')) return;
  if (e.key === 'Escape') closeRow();
  if (state.sel >= 0 && (e.key === 'ArrowDown' || e.key === 'j')) { e.preventDefault(); step(1); }
  if (state.sel >= 0 && (e.key === 'ArrowUp' || e.key === 'k')) { e.preventDefault(); step(-1); }
});

// export what is visible
function visibleCols() { return cols.map(function (c, i) { return i; }).filter(function (i) { return !hidden[i]; }); }
function copyText(t, btn) { var done = function () { if (btn) { var o = btn.textContent; btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = o; }, 1200); } }; try { navigator.clipboard.writeText(t).then(done, function () {}); } catch (e) {} }
$('copy').onclick = function () { var vc = visibleCols(); var t = [vc.map(function (i) { return cols[i]; }).join('\t')].concat(view.map(function (r) { return vc.map(function (i) { return String(rows[r][i]).replace(/[\t\r\n]+/g, ' '); }).join('\t'); })).join('\r\n'); copyText(t, this); };
$('csv').onclick = function () {
  var vc = visibleCols(), q = function (v) { v = String(v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
  var t = '\ufeff' + [vc.map(function (i) { return q(cols[i]); }).join(',')].concat(view.map(function (r) { return vc.map(function (i) { return q(rows[r][i]); }).join(','); })).join('\r\n');
  var a = mk('a'); a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(t); a.download = (D.title.replace(/[^\w.-]+/g, '_').slice(0, 60) || 'view') + '.csv'; document.body.appendChild(a); a.click(); a.remove();
};

// start sorted as the console had it (most severe first); open the first flagged row so the panel is discoverable
refresh();
})();
</script>
</body>
</html>
'@
