function New-WfxReport {
    <#
    .SYNOPSIS
        Renders a self-contained (no external assets, works offline) HTML case report from an
        Invoke-WfxAnalyze result: verdict, a chart of when it happened, incidents, the attack path, each
        finding as a case file (what happened, when, how we know, what to do), indicators, a merged timeline,
        execution evidence, ATT&CK coverage, what could not be seen, and chain of custody. Times are UTC.
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
:root {
  --page: #FFFFFF; --alt: #F5F6F8; --alt2: #ECEEF1; --ink: #17202C; --ink2: #4E5967; --ink3: #7B8591;
  --line: #D3D8DE; --line2: #E6E9ED; --link: #0B57A4; --sel: #E7EEF7;
  --band: #14233A; --band2: #1C2E48; --band-ink: #F1F4F8; --band-dim: #A9B6C6;
  --crit: #9B1C1C; --high: #C2410C; --med: #A16207; --low: #2B6CB0; --info: #6B7280;
  --mark: .028;
  --sans: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --mono: "Cascadia Mono", "Cascadia Code", Consolas, "SF Mono", Menlo, monospace;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme=light]) {
  --page: #14181D; --alt: #1A1F25; --alt2: #222830; --ink: #E3E7EC; --ink2: #A4AEBA; --ink3: #7D8793;
  --line: #333B45; --line2: #262D35; --link: #7CB1EC; --sel: #1F2B3A; --band: #0D141D; --band2: #152131;
  --crit: #F07171; --high: #F59056; --med: #E2B04A; --low: #7FB0E6; --info: #9AA3AE; --mark: .04; } }
:root[data-theme=dark] {
  --page: #14181D; --alt: #1A1F25; --alt2: #222830; --ink: #E3E7EC; --ink2: #A4AEBA; --ink3: #7D8793;
  --line: #333B45; --line2: #262D35; --link: #7CB1EC; --sel: #1F2B3A; --band: #0D141D; --band2: #152131;
  --crit: #F07171; --high: #F59056; --med: #E2B04A; --low: #7FB0E6; --info: #9AA3AE; --mark: .04; }
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--page); color: var(--ink); font: 14px/1.5 var(--sans); font-variant-numeric: tabular-nums; }
*, *::before, *::after { font-variant-ligatures: none; font-feature-settings: "calt" 0, "liga" 0, "clig" 0; }
a { color: var(--link); text-decoration: none; } a:hover { text-decoration: underline; }
:focus-visible { outline: 2px solid var(--link); outline-offset: 2px; }
h1, h2, h3, h4 { margin: 0; font-weight: 600; }
h2 { font-size: 20px; line-height: 1.3; }
h3 { font-size: 14px; margin: 22px 0 8px; }
p { margin: 0 0 10px; }
code, .mono { font-family: var(--mono); font-size: 12.5px; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 0 28px; }
.small { font-size: 12.5px; color: var(--ink2); }
.muted { color: var(--ink3); }
.btn { font: inherit; font-size: 13px; color: var(--ink); background: var(--page); border: 1px solid var(--line); border-radius: 3px; padding: 4px 10px; cursor: pointer; white-space: nowrap; }
.btn:hover { background: var(--alt); }
.btn[aria-pressed=true] { background: var(--alt2); }
.watermark { position: fixed; left: 50%; top: 55%; width: min(66vw, 520px); transform: translate(-50%, -50%) rotate(-12deg); color: var(--ink); opacity: var(--mark); pointer-events: none; z-index: 50; }
.watermark text { font: 700 7px var(--sans); }

/* masthead */
.mast { background: var(--band); color: var(--band-ink); }
.mast .wrap { padding-top: 16px; padding-bottom: 26px; }
.brandrow { display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--band-dim); }
.brandrow svg { width: 22px; height: 22px; color: var(--band-ink); }
.brandrow b { color: var(--band-ink); font-weight: 600; font-size: 14px; }
.brandrow .tools { margin-left: auto; display: flex; gap: 6px; }
.mbtn { font: inherit; font-size: 12.5px; color: var(--band-ink); background: transparent; border: 1px solid rgba(255,255,255,.28); border-radius: 3px; padding: 3px 10px; cursor: pointer; }
.mbtn:hover { border-color: rgba(255,255,255,.6); }
.casehead { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-end; gap: 18px 40px; margin-top: 30px; }
.casehead h1 { font-size: 40px; line-height: 1.05; letter-spacing: -.02em; overflow-wrap: anywhere; }
.facts-line { display: flex; flex-wrap: wrap; gap: 4px 26px; margin-top: 12px; font-size: 13px; color: var(--band-dim); }
.facts-line span b { color: var(--band-ink); font-weight: 500; }
.verdictbox { text-align: left; }
.verdictbox .v { font-size: 21px; font-weight: 600; display: inline-flex; align-items: center; gap: 10px; }
.verdictbox .s { font-size: 13px; color: var(--band-dim); margin-top: 4px; }

/* sticky section bar */
.bar { position: sticky; top: 0; z-index: 10; background: var(--page); border-bottom: 1px solid var(--line); }
.nav { display: flex; overflow-x: auto; scrollbar-width: none; }
.nav::-webkit-scrollbar { display: none; }
.nav a { color: var(--ink2); padding: 12px 10px 11px; white-space: nowrap; border-bottom: 2px solid transparent; font-size: 13.5px; }
.nav a:first-child { padding-left: 0; }
.nav a:hover { color: var(--ink); text-decoration: none; }
.nav a.on { color: var(--ink); border-bottom-color: var(--ink); }
.nav a .n { color: var(--ink3); margin-left: 4px; font-size: 12px; }

/* sections */
section { padding: 34px 0 10px; border-bottom: 1px solid var(--line2); scroll-margin-top: 44px; }
section:last-of-type { border-bottom: 0; }
.desc { color: var(--ink2); max-width: 80ch; margin: 4px 0 16px; }
.head { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; flex-wrap: wrap; margin-bottom: 4px; }
.head .tools { display: flex; gap: 6px; }

/* summary */
.assess { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(0, 1fr); gap: 44px; }
.assess > *, .two > * { min-width: 0; }
.mono, .case .tech, .story, ol.todo a { overflow-wrap: anywhere; }
.story { font-size: 16px; line-height: 1.6; max-width: 68ch; margin-bottom: 6px; }
ol.todo { margin: 0; padding: 0; list-style: none; counter-reset: t; border-top: 1px solid var(--line); }
ol.todo li { counter-increment: t; display: grid; grid-template-columns: 26px 1fr; padding: 9px 0; border-bottom: 1px solid var(--line2); }
ol.todo li::before { content: counter(t) "."; color: var(--ink3); }
ol.todo span { display: block; color: var(--ink2); font-size: 13.5px; }
dl.facts { margin: 0; display: grid; align-content: start; grid-template-columns: auto 1fr; border-top: 1px solid var(--line); }
dl.facts dt, dl.facts dd { margin: 0; padding: 8px 0; border-bottom: 1px solid var(--line2); }
dl.facts dt { color: var(--ink2); padding-right: 18px; white-space: nowrap; }
dl.facts dd { text-align: right; overflow-wrap: anywhere; }
.sevcount { display: inline-flex; flex-wrap: wrap; gap: 4px 14px; justify-content: flex-end; }

/* severity: a shape plus the word, so it reads in greyscale print and for colour-blind readers */
.sev { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; font-weight: 600; font-size: 13px; }
.sev i { display: inline-block; width: 8px; height: 8px; background: currentColor; flex: none; }
.sev.Critical { color: var(--crit); } .sev.Critical i { transform: rotate(45deg); }
.sev.High { color: var(--high); } .sev.High i { width: 9px; clip-path: polygon(50% 0, 100% 100%, 0 100%); }
.sev.Medium { color: var(--med); }
.sev.Low { color: var(--low); } .sev.Low i { border-radius: 50%; }
.sev.Info { color: var(--info); } .sev.Info i { border-radius: 50%; background: none; border: 1.5px solid currentColor; }
.sev.bare { font-weight: 400; }

/* when it happened (chart) */
.chart { border: 1px solid var(--line); padding: 14px 16px 10px; margin-top: 4px; }
.chart .ctl { display: flex; gap: 10px; align-items: center; font-size: 13px; color: var(--ink2); margin-bottom: 8px; flex-wrap: wrap; }
.chart select { font: inherit; font-size: 13px; padding: 3px 6px; border: 1px solid var(--line); border-radius: 3px; background: var(--page); color: var(--ink); }
.chart svg { display: block; width: 100%; height: auto; }
.chart .lane { font: 12px var(--sans); fill: var(--ink2); }
.chart .grid { stroke: var(--line2); }
.chart .day { stroke: var(--line); }
.chart .tick { font: 11px var(--sans); fill: var(--ink3); }
.chart .tick.d { fill: var(--ink2); font-weight: 600; }
.chart .band { fill: var(--ink); opacity: .055; }
.chart .bandl { font: 11px var(--sans); fill: var(--ink2); }
.chart .pt { cursor: pointer; }
.chart .pt:focus { outline: none; }
.chart .pt:hover .mk, .chart .pt:focus .mk, .chart .pt.on .mk { stroke: var(--ink); stroke-width: 1.6; }
.chart .legend { display: flex; flex-wrap: wrap; gap: 4px 16px; font-size: 12.5px; color: var(--ink2); border-top: 1px solid var(--line2); padding-top: 8px; margin-top: 4px; }

/* tables */
.tbl { width: 100%; overflow-x: auto; border: 1px solid var(--line); }
table { border-collapse: collapse; width: 100%; }
th { font-weight: 600; font-size: 12.5px; color: var(--ink2); text-align: left; padding: 7px 12px; background: var(--alt); border-bottom: 1px solid var(--line); white-space: nowrap; }
td { padding: 7px 12px; border-bottom: 1px solid var(--line2); vertical-align: top; }
tr:last-child > td { border-bottom: 0; }
td.t, td.nw { white-space: nowrap; } td.t { color: var(--ink2); }
td.m { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; min-width: 16ch; }
td.num { text-align: right; }
tr.day td { background: var(--alt); font-weight: 600; color: var(--ink2); }
.kind { color: var(--ink2); white-space: nowrap; }
.tb { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: center; margin: 0 0 10px; }
.tb input[type=search] { font: inherit; padding: 5px 9px; border: 1px solid var(--line); border-radius: 3px; background: var(--page); color: var(--ink); min-width: 240px; flex: 1; max-width: 420px; }
.tb select { font: inherit; padding: 4px 6px; border: 1px solid var(--line); border-radius: 3px; background: var(--page); color: var(--ink); }
.tb label { display: inline-flex; align-items: center; gap: 5px; color: var(--ink2); white-space: nowrap; }
#itbl .ipick { width: 28px; padding-right: 0; } #itbl .ipick input { margin: 0; vertical-align: middle; cursor: pointer; }
.btn:disabled { opacity: .5; cursor: default; }
.count { color: var(--ink3); font-size: 12.5px; margin-top: 8px; }
.empty { padding: 16px; border: 1px solid var(--line2); background: var(--alt); color: var(--ink2); }

/* findings: list and case file */
.fwrap { display: grid; grid-template-columns: minmax(300px, 380px) minmax(0, 1fr); border: 1px solid var(--line); min-height: 560px; }
.flist { border-right: 1px solid var(--line); min-width: 0; display: flex; flex-direction: column; }
.flist .tb { padding: 10px; margin: 0; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.flist .tb input[type=search] { grid-column: 1 / -1; max-width: none; min-width: 0; }
.flist .tb > *, .fwrap > * { min-width: 0; }
.flist .tb select { width: 100%; }
.fitems { overflow-y: auto; max-height: 860px; }
.fg { padding: 6px 12px; font-size: 12px; color: var(--ink2); background: var(--alt); border-bottom: 1px solid var(--line2); }
.fi { display: block; width: 100%; text-align: left; font: inherit; color: inherit; background: none; border: 0; border-bottom: 1px solid var(--line2); padding: 9px 12px 10px; cursor: pointer; }
.fi:hover { background: var(--alt); }
.fi[aria-selected=true] { background: var(--sel); }
.fi .t { display: block; font-weight: 500; line-height: 1.35; overflow-wrap: anywhere; }
.fi .m { display: flex; flex-wrap: wrap; gap: 2px 12px; margin-top: 3px; font-size: 12px; color: var(--ink3); }
.fcount { padding: 8px 12px; font-size: 12px; color: var(--ink3); border-top: 1px solid var(--line2); margin-top: auto; }
.case { padding: 22px 28px 28px; min-width: 0; }
.case .top { display: flex; flex-wrap: wrap; gap: 4px 18px; align-items: center; font-size: 13px; color: var(--ink2); }
.case .top .tools { margin-left: auto; display: flex; gap: 6px; }
.case h3.ft { font-size: 22px; line-height: 1.25; margin: 10px 0 4px; overflow-wrap: anywhere; letter-spacing: -.01em; }
.case .tech { font-size: 13px; color: var(--ink2); margin-bottom: 14px; }
.case .tech a { font-family: var(--mono); font-size: 12.5px; }
dl.cf { margin: 0; display: grid; grid-template-columns: 150px minmax(0, 1fr); border-top: 1px solid var(--line); }
dl.cf > dt { padding: 14px 16px 14px 0; border-bottom: 1px solid var(--line2); font-weight: 600; font-size: 13px; }
dl.cf > dd { margin: 0; padding: 14px 0; border-bottom: 1px solid var(--line2); min-width: 0; overflow-wrap: anywhere; }
dl.cf > dd > :last-child { margin-bottom: 0; }
.stamp { font-size: 17px; font-weight: 600; }
.sub { color: var(--ink2); font-size: 13px; }
.lbl { font-size: 12.5px; color: var(--ink2); margin: 12px 0 4px; }
pre.box { font-family: var(--mono); font-size: 12.5px; line-height: 1.55; background: var(--alt); border: 1px solid var(--line2); padding: 9px 12px; margin: 0 0 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
pre.box mark { background: none; color: var(--high); font-weight: 700; text-decoration: underline; text-underline-offset: 2px; }
table.kv { border: 1px solid var(--line2); }
table.kv td { padding: 5px 10px; font-size: 12.5px; }
table.kv td.k { color: var(--ink2); white-space: nowrap; width: 1%; }
table.kv td.v { font-family: var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; }
dl.cf table.kv { table-layout: fixed; width: 100%; }
dl.cf table.kv td.k { width: 28%; white-space: normal; overflow-wrap: anywhere; }
table.seq td { padding: 4px 10px; font-size: 13px; }
table.seq tr.self td { background: var(--sel); font-weight: 600; }
table.seq button { font: inherit; color: var(--link); background: none; border: 0; padding: 0; cursor: pointer; text-align: left; }

/* attack path, incidents, matrix */
td.stage { font-weight: 600; white-space: nowrap; }
.matrix { display: flex; border: 1px solid var(--line); overflow-x: auto; }
.mcol { border-right: 1px solid var(--line2); flex: 1 1 150px; min-width: 150px; }
.mcol.none { flex: 0 0 84px; min-width: 84px; }
.mcol:last-child { border-right: 0; }
.mcol h4 { padding: 8px 9px; font-size: 12px; background: var(--alt); border-bottom: 1px solid var(--line); min-height: 52px; overflow-wrap: break-word; hyphens: auto; }
.mcol h4 span { display: block; color: var(--ink3); font-weight: 400; }
.mcol.none h4 { color: var(--ink3); background: var(--page); }
.mt { display: block; padding: 7px 9px; border-bottom: 1px solid var(--line2); font-size: 12px; color: var(--ink); }
.mt:hover { background: var(--alt); text-decoration: none; }
.mt b { display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-weight: 600; font-size: 11.5px; }
ul.list { margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--line2); }
ul.list li { padding: 9px 0; border-bottom: 1px solid var(--line2); overflow-wrap: anywhere; }
ul.list .fix { color: var(--ink2); margin-top: 2px; }
.two { display: grid; grid-template-columns: 1fr 1fr; gap: 36px; }
footer { padding: 26px 0 40px; color: var(--ink3); font-size: 12.5px; }
.toast { position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%); background: var(--ink); color: var(--page); padding: 6px 14px; border-radius: 3px; font-size: 13px; opacity: 0; transition: opacity .15s; pointer-events: none; z-index: 60; }
.toast.on { opacity: 1; }
#printall, .pnote { display: none; }

@media (max-width: 1000px) {
  .assess, .two { grid-template-columns: 1fr; gap: 24px; }
  .fwrap { grid-template-columns: 1fr; }
  .flist { border-right: 0; border-bottom: 1px solid var(--line); }
  .fitems { max-height: 340px; }
}
@media (max-width: 640px) {
  .wrap { padding: 0 16px; }
  .casehead h1 { font-size: 30px; }
  .case { padding: 18px 14px; }
  dl.cf { grid-template-columns: 1fr; }
  dl.cf > dt { border-bottom: 0; padding-bottom: 2px; }
  dl.cf > dd { padding-top: 2px; }
  dl.facts { grid-template-columns: 1fr; } dl.facts dt { border-bottom: 0; padding-bottom: 0; } dl.facts dd { text-align: left; }
  .tb input[type=search] { min-width: 0; max-width: none; width: 100%; }
}
@media (prefers-reduced-motion: reduce) { .toast { transition: none; } }
@media print {
  @page { margin: 16mm 13mm 15mm; }
  html, body { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: #fff; }
  body { font-size: 10pt; }
  .mast { background: #fff; color: #000; border-bottom: 2px solid #000; break-after: page; min-height: 55vh; }
  .mast .brandrow, .mast .brandrow b, .facts-line, .facts-line span b, .verdictbox .s { color: #000; }
  .brandrow svg { color: #000; }
  .bar, .tb, .btn, .mbtn, .toast, .chart .ctl, .flist, #case, .head .tools, #itbl .ipick { display: none !important; }
  #printall { display: block; }
  #printall .case { padding: 14px 0 18px; border-bottom: 1px solid #999; }
  #printall dl.cf > dt, #printall dl.cf > dd { padding: 8px 0; }
  .fwrap { display: block; border: 0; min-height: 0; }
  #abox, #ebox, #tbox tr.chg { display: none; }
  .pnote { display: block; color: #555; margin: 4px 0 8px; }
  section { padding-top: 18px; break-inside: auto; }
  .chart, .assess { break-inside: avoid; }
  .tbl { overflow: visible; border: 0; }
  tr, .mt, dl.cf > dd { break-inside: avoid; }
  .matrix { flex-wrap: wrap; } .mcol.none { display: none; }
  a { color: inherit; }
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

<header class="mast"><div class="wrap">
  <div class="brandrow"><svg viewBox="0 0 64 64" aria-hidden="true"><use href="#wfx-mark"/></svg><b>WinForensicX</b><span>Case report</span>
    <div class="tools"><button class="mbtn" id="theme" type="button">Dark</button><button class="mbtn" id="print" type="button">Print</button></div></div>
  <div class="casehead">
    <div><h1>__WFX_HOST__</h1><div class="facts-line" id="sub"></div></div>
    <div class="verdictbox"><div class="v" id="verdict"></div><div class="s" id="vsub"></div></div>
  </div>
</div></header>

<div class="bar"><div class="wrap"><nav class="nav" id="nav" aria-label="Sections">
  <a href="#summary">Summary</a><a href="#incidents">Incidents<span class="n" id="n-n"></span></a><a href="#path">Path<span class="n" id="n-p"></span></a><a href="#findings">Findings<span class="n" id="n-f"></span></a><a href="#iocs">Indicators<span class="n" id="n-i"></span></a><a href="#timeline">Timeline<span class="n" id="n-t"></span></a><a href="#activity">Changes<span class="n" id="n-a"></span></a><a href="#execution">Execution<span class="n" id="n-e"></span></a><a href="#attack">ATT&amp;CK<span class="n" id="n-x"></span></a><a href="#visibility">Gaps<span class="n" id="n-g"></span></a><a href="#custody">Custody</a>
</nav></div></div>

<main class="wrap">
<section id="summary">
  <div class="assess">
    <div>
      <h2>Summary</h2>
      <p class="story" id="lead"></p>
      <h3>Do first</h3>
      <ol class="todo" id="todo"></ol>
    </div>
    <dl class="facts" id="facts"></dl>
  </div>
  <h3 style="margin-top:30px">When it happened</h3>
  <p class="desc">Each time-stamped finding on its ATT&amp;CK stage. Grey bands are incidents. Select a point to open the finding.</p>
  <div class="chart" id="chart"><div class="ctl"><label for="zoom">Show</label><select id="zoom"></select><span id="notime"></span></div><div id="chartsvg"></div><div class="legend" id="legend"></div></div>
</section>

<section id="incidents">
  <h2>Incidents</h2>
  <p class="desc">Findings grouped because they share a file, account or address close in time, or are high-severity findings minutes apart. The last column says why they were grouped and which finding is the likely starting point.</p>
  <div id="nbox"></div>
</section>

<section id="path">
  <h2>Attack path</h2>
  <p class="desc">Findings placed on the attack lifecycle, earliest stage first, with the time each stage was first seen.</p>
  <div id="pathbox"></div>
</section>

<section id="findings">
  <div class="head"><div><h2>Findings</h2><p class="desc">Each finding answers four questions: what happened, when, how we know, and what to do.</p></div>
    <div class="tools"><button class="btn" id="fx-csv" type="button">Download CSV</button></div></div>
  <div class="fwrap">
    <div class="flist">
      <div class="tb">
        <input type="search" id="fq" placeholder="Search titles, paths, users, IPs, rule IDs" aria-label="Search findings">
        <select id="fsev" aria-label="Severity"></select>
        <select id="ftac" aria-label="Stage"></select>
        <select id="fcat" aria-label="Area"></select>
        <select id="ford" aria-label="Order"><option value="sev">Most severe first</option><option value="time">Oldest first</option><option value="inc">By incident</option></select>
      </div>
      <div class="fitems" id="fitems" role="listbox" aria-label="Findings"></div>
      <div class="fcount" id="fcount"></div>
    </div>
    <article class="case" id="case" aria-live="polite"></article>
    <div id="printall"></div>
  </div>
</section>

<section id="iocs">
  <div class="head"><div><h2>Indicators</h2><p class="desc">Addresses, domains, URLs, hashes, files, registry keys and accounts taken from the evidence of attacker-related findings. Extraction is automatic: check each value before blocking it.</p></div>
    <div class="tools"><button class="btn" id="i-copy" type="button">Copy values</button><button class="btn" id="i-csv" type="button">Download CSV</button><button class="btn" id="i-pick" type="button" title="Tick every public address, domain, URL and hash">Tick external and hashes</button><button class="btn" id="i-osint" type="button" disabled title="Save the ticked indicators as a STIX 2.1 file for OSINTrix (Threat Intel, Indicators, Import)">Export for OSINT</button></div></div>
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
  <div class="head"><div><h2>Timeline</h2><p class="desc">Findings and notable changes in one sequence. All times are UTC.</p></div>
    <div class="tools"><button class="btn" id="t-csv" type="button">Download CSV</button></div></div>
  <div class="tb">
    <input type="search" id="tq" placeholder="Search the timeline" aria-label="Search timeline">
    <label><input type="checkbox" id="tonly"> Findings only</label>
  </div>
  <p class="pnote">The printed copy lists findings only; every change is in the timeline CSV and raw/bundle.json.</p>
  <div id="tbox"></div>
</section>

<section id="activity">
  <h2>Recent changes</h2>
  <p class="desc" id="asub">What changed on the host in the look-back window: registry, files, software, services, tasks, accounts, security settings, executions and connections.</p>
  <div class="tb">
    <input type="search" id="aq" placeholder="Search changes" aria-label="Search changes">
    <select id="acat" aria-label="Area"></select>
  </div>
  <p class="pnote">Left out of the printed copy; see the timeline CSV or raw/bundle.json.</p>
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
  <p class="pnote">Left out of the printed copy; see the CSV or raw/bundle.json.</p>
  <div id="ebox"></div>
</section>

<section id="attack">
  <div class="head"><div><h2>MITRE ATT&amp;CK</h2><p class="desc">Techniques behind the findings, by tactic. The mark shows the most severe finding for each technique.</p></div>
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
  <div class="two"><div id="cbox"></div><div><h3 style="margin-top:0">Verify this case</h3><p class="small">Re-hashes every file against manifest.json and reports anything changed, missing or added.</p><pre class="box" id="verify"></pre>
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
  var sevOf = function (s) { return RANK[s] === undefined ? 'Info' : s; };
  var sevHtml = function (s, word) { s = sevOf(s); return '<span class="sev ' + s + '"><i></i>' + esc(word === undefined ? s : word) + '</span>'; };
  var dt = function (s) { if (s === null || s === undefined || s === '') return null; var d = new Date(s); return isNaN(d) ? null : d; };
  var pad = function (n) { return (n < 10 ? '0' : '') + n; };
  var fmtD = function (d) { return d ? d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) : ''; };
  var fmt = function (d) { return d ? fmtD(d) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) : ''; };
  var fmtT = function (d) { return d ? pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) : ''; };
  var utc = function (d) { return d ? d.toISOString().replace(/\.\d{3}Z$/, 'Z') : ''; };
  var span = function (ms) { var m = Math.round(Math.abs(ms) / 60000); if (m < 1) return 'under a minute'; if (m < 90) return m + ' minute' + (m === 1 ? '' : 's'); var h = Math.round(m / 6) / 10; if (h < 48) return h + ' hours'; return Math.round(h / 24) + ' days'; };
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
  var reduceMotion = function () { return window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches; };

  /* theme and print */
  var setThemeLabel = function () { var cur = document.documentElement.getAttribute('data-theme'); var dark = cur ? cur === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; $('theme').textContent = dark ? 'Light' : 'Dark'; };
  try { var saved = localStorage.getItem('wfx-theme'); if (saved === 'dark' || saved === 'light') document.documentElement.setAttribute('data-theme', saved); } catch (e) { }
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
    f._late = isHygiene(f) ? 'Hardening' : (tacs[tacs.length - 1] || 'Other');
  });
  var attackF = F.filter(function (f) { return !isHygiene(f); });
  var N = D.incidents || [];
  var fIndex = {}; F.forEach(function (f) { fIndex[f.Id + '|' + f.Entity] = f._i; });
  N.forEach(function (n) { n._m = []; (n.Findings || []).forEach(function (x) { var i = fIndex[x.Id + '|' + x.Entity]; if (i !== undefined) { n._m.push(F[i]); F[i]._inc = n; } }); });
  var timed = attackF.filter(function (f) { return f._d; }).sort(function (a, b) { return a._d - b._d; });

  /* masthead */
  var collected = dt(D.collected);
  var subBits = [];
  if (host.Os || host.OS) subBits.push('<span>' + esc(host.Os || host.OS) + '</span>');
  if (host.Domain) subBits.push('<span>Domain <b>' + esc(host.Domain) + '</b></span>');
  if (collected) subBits.push('<span>Collected <b>' + esc(fmt(collected)) + ' UTC</b></span>');
  if (cs.Id) subBits.push('<span>Case <b class="mono">' + esc(String(cs.Id).slice(0, 8)) + '</b></span>');
  if (cs.Operator) subBits.push('<span>Analyst <b>' + esc(cs.Operator) + '</b></span>');
  $('sub').innerHTML = subBits.join('');
  var V = { Critical: ['Compromise indicated', 'Treat this host as compromised until proven otherwise: isolate it, preserve evidence and scope the intrusion.'],
    High: ['Compromise likely', 'Strong indicators of attacker activity. Investigate now and consider isolating the host.'],
    Elevated: ['Suspicious activity', 'Some findings need an analyst to confirm or rule out attacker activity.'],
    Low: ['No strong indicators', 'Nothing in what could be seen strongly indicates compromise.'] };
  var v = V[risk.Level] || V.Low, vs = risk.Level === 'Critical' ? 'Critical' : risk.Level === 'High' ? 'High' : risk.Level === 'Elevated' ? 'Medium' : 'Low';
  $('verdict').innerHTML = '<span class="sev ' + vs + '" style="font-size:21px"><i style="width:11px;height:11px"></i></span>' + esc(v[0]);
  $('vsub').textContent = 'Compromise risk ' + risk.Score + ' of 100, hardening gaps ' + pos.Score + ' of 100';

  /* summary */
  var hc = attackF.filter(function (f) { return RANK[f.Severity] <= 1; }).length;
  var stages = []; attackF.forEach(function (f) { if (TAC.indexOf(f._tac) >= 0 && stages.indexOf(f._tac) < 0) stages.push(f._tac); });
  stages.sort(function (a, b) { return TAC.indexOf(a) - TAC.indexOf(b); });
  var lead = esc(v[1]) + ' ' + attackF.length + ' attacker-related finding' + (attackF.length === 1 ? '' : 's') + (hc ? ', ' + hc + ' critical or high' : '') +
    (stages.length ? ', across ' + stages.length + ' stage' + (stages.length === 1 ? '' : 's') + ' of the attack lifecycle (' + esc(stages.join(', ')) + ').' : '.');
  if (timed.length > 1) { var a0 = timed[0], a1 = timed[timed.length - 1]; lead += ' The earliest is <a href="#f' + a0._i + '" data-open="' + a0._i + '">' + esc(a0.Title) + '</a> at ' + esc(fmt(a0._d)) + ' UTC; the latest, ' + esc(span(a1._d - a0._d)) + ' later, is <a href="#f' + a1._i + '" data-open="' + a1._i + '">' + esc(a1.Title) + '</a>.'; }
  if (N.length) lead += ' They form ' + N.length + ' incident' + (N.length === 1 ? '' : 's') + '.';
  if ((D.gaps || []).length) lead += ' Some sources were not visible; read <a href="#visibility">what this report could not see</a> before concluding.';
  $('lead').innerHTML = lead;
  var seenRule = {}; var top = attackF.slice().sort(function (a, b) { return RANK[a.Severity] - RANK[b.Severity] || b.Score - a.Score; }).filter(function (f) { var k = String(f.Id).replace(/-\d+$/, ''), tk = f.Title.replace(/\s*\(.*\)$/, ''); if (seenRule[k] || seenRule[tk]) return false; seenRule[k] = seenRule[tk] = 1; return true; }).slice(0, 5);
  if (!top.length) top = F.slice().sort(function (a, b) { return RANK[a.Severity] - RANK[b.Severity]; }).slice(0, 3);
  var firstSentence = function (s) { s = String(s || 'Review the evidence.'); var m = s.match(/^.*?[.;](\s|$)/); s = (m ? m[0] : s).trim().replace(/[;,:]$/, ''); return /[.!?]$/.test(s) ? s : s + '.'; };
  $('todo').innerHTML = top.length ? top.map(function (f) { return '<li><div><a href="#f' + f._i + '" data-open="' + f._i + '">' + esc(f.Title) + '</a><span>' + esc(firstSentence(f.Recommendation)) + '</span></div></li>'; }).join('')
    : '<li><div>Nothing to act on<span>Check what this report could not see before concluding the host is clean.</span></div></li>';
  var S = D.summary || {};
  var accounts = {};
  attackF.forEach(function (f) { var e = f.Evidence || {}; ['User', 'Users', 'Actor', 'Account', 'TargetUserName', 'SubjectUserName', 'MemberName'].forEach(function (k) { if (e[k]) String(e[k]).split(/,\s*/).forEach(function (u) { if (isAcct(u)) accounts[u.trim()] = 1; }); }); });
  // One account per person: "analyst" is dropped when "CORP\analyst" is also listed, and case variants count once.
  var acctList = (function () { var ks = Object.keys(accounts), qual = {}, seen = {}; ks.forEach(function (k) { var l = k.toLowerCase(); if (l.indexOf('\\') >= 0) qual[l.split('\\').pop()] = 1; });
    return ks.filter(function (k) { var l = k.toLowerCase(); if (seen[l] || (l.indexOf('\\') < 0 && qual[l])) return false; seen[l] = 1; return true; }); })();
  var facts = [
    ['Findings', '<span class="sevcount">' + (SEV.filter(function (x) { return S[x]; }).map(function (x) { return sevHtml(x, S[x] + ' ' + x.toLowerCase()); }).join('') || 'none') + '</span>'],
    ['Suspicious activity', timed.length ? esc(fmt(timed[0]._d)) + (timed.length > 1 ? ' to ' + esc(fmt(timed[timed.length - 1]._d)) : '') + ' UTC' : '<span class="muted">no time-stamped findings</span>'],
    ['Incidents', N.length ? '<a href="#incidents">' + N.length + '</a>' : '0'],
    ['Accounts involved', acctList.length ? esc(acctList.slice(0, 4).join(', ')) + (acctList.length > 4 ? ' and ' + (acctList.length - 4) + ' more' : '') : '<span class="muted">none identified</span>'],
    ['External addresses', '<span id="f-ext">0</span>'],
    ['Changes recorded', esc(D.activityTotal || A.length || 0)],
    ['Execution artifacts', (D.artifactTotal || (D.artifacts || []).length) ? '<a href="#execution">' + esc(D.artifactTotal || D.artifacts.length) + '</a>' : '0'],
    ['Sources not visible', (D.gaps || []).length ? '<a href="#visibility">' + (D.gaps || []).length + '</a>' : '0']
  ];
  $('facts').innerHTML = facts.map(function (r) { return '<dt>' + r[0] + '</dt><dd>' + r[1] + '</dd>'; }).join('');

  /* when it happened: one lane per stage, incidents as bands */
  var current = null, zoomInc = null;
  var lanes = TAC.filter(function (t) { return timed.some(function (f) { return f._tac === t; }); });
  if (timed.some(function (f) { return TAC.indexOf(f._tac) < 0; })) lanes.push('Other');
  var laneOf = function (f) { return TAC.indexOf(f._tac) >= 0 ? f._tac : 'Other'; };
  var sortedN = N.filter(function (n) { return dt(n.Start); }).slice().sort(function (a, b) { return dt(a.Start) - dt(b.Start); });
  $('zoom').innerHTML = '<option value="">Whole case</option>' + sortedN.map(function (n) { return '<option value="' + esc(n.Id) + '">' + esc(n.Id) + ', ' + esc(fmt(dt(n.Start))) + ' UTC</option>'; }).join('');
  $('zoom').onchange = function () { var id = this.value; zoomInc = N.filter(function (n) { return n.Id === id; })[0] || null; drawChart(); };
  var nt = attackF.length - timed.length;
  $('notime').textContent = nt ? nt + ' finding' + (nt === 1 ? ' has' : 's have') + ' no time stamp (state seen at collection) and ' + (nt === 1 ? 'is' : 'are') + ' not plotted.' : '';
  var shape = function (s, x, y) {
    var r = { Critical: 6.5, High: 6, Medium: 5, Low: 4.5, Info: 4 }[s] || 4, st = ' class="mk" style="fill:var(--' + { Critical: 'crit', High: 'high', Medium: 'med', Low: 'low', Info: 'info' }[s] + ');stroke:var(--page);stroke-width:1.2"';
    if (s === 'Critical') return '<rect x="' + (x - r) + '" y="' + (y - r) + '" width="' + 2 * r + '" height="' + 2 * r + '" transform="rotate(45 ' + x + ' ' + y + ')"' + st + '/>';
    if (s === 'High') return '<path d="M' + x + ' ' + (y - r - 1) + 'L' + (x + r + 1) + ' ' + (y + r) + 'L' + (x - r - 1) + ' ' + (y + r) + 'Z"' + st + '/>';
    if (s === 'Medium') return '<rect x="' + (x - r) + '" y="' + (y - r) + '" width="' + 2 * r + '" height="' + 2 * r + '"' + st + '/>';
    return '<circle cx="' + x + '" cy="' + y + '" r="' + r + '"' + st + '/>';
  };
  var drawChart = function () {
    var box = $('chartsvg');
    if (!timed.length) { $('chart').hidden = true; return; }
    var W = Math.max(600, box.clientWidth || 1200), L = 160, R = 18, top0 = 26, lh = 30;
    var t0 = timed[0]._d.getTime(), t1 = timed[timed.length - 1]._d.getTime();
    if (zoomInc) { t0 = dt(zoomInc.Start).getTime(); t1 = (dt(zoomInc.End) || dt(zoomInc.Start)).getTime(); }
    var spanMs = Math.max(t1 - t0, zoomInc ? 20 * 60000 : 3600000);
    if (t1 - t0 < spanMs) { var mid = (t0 + t1) / 2; t0 = mid - spanMs / 2; t1 = mid + spanMs / 2; }
    t0 -= spanMs * .04; t1 += spanMs * .04; spanMs = t1 - t0;
    var x = function (t) { return L + (W - L - R) * (t - t0) / spanMs; };
    var H = top0 + lanes.length * lh + 18;
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Findings over time by attack stage">';
    var steps = [6e4, 5 * 6e4, 15 * 6e4, 36e5, 3 * 36e5, 6 * 36e5, 12 * 36e5, 864e5, 7 * 864e5], step = steps[steps.length - 1];
    for (var k = 0; k < steps.length; k++) { if (spanMs / steps[k] <= 14) { step = steps[k]; break; } }
    for (var g = Math.ceil(t0 / step) * step; g <= t1; g += step) {
      var d = new Date(g), midnight = d.getUTCHours() === 0 && d.getUTCMinutes() === 0;
      var lbl = midnight || step >= 864e5 ? fmtD(d) : pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
      s += '<line class="' + (midnight ? 'day' : 'grid') + '" x1="' + x(g) + '" x2="' + x(g) + '" y1="' + (top0 - 6) + '" y2="' + (H - 16) + '"/>';
      s += '<text class="tick' + (midnight ? ' d' : '') + '" x="' + (x(g) + 3) + '" y="' + (top0 - 11) + '">' + lbl + '</text>';
    }
    var lastL = -1e9;
    sortedN.forEach(function (n) {
      var a = dt(n.Start).getTime(), b = (dt(n.End) || dt(n.Start)).getTime(); if (b < t0 || a > t1) return;
      var xa = Math.max(L, x(a) - 6), xb = Math.min(W - R, Math.max(x(b) + 6, xa + 12));
      s += '<rect class="band" x="' + xa + '" y="' + (top0 - 4) + '" width="' + (xb - xa) + '" height="' + (lanes.length * lh + 2) + '"/>';
      if (xa - lastL > 44) { s += '<text class="bandl" x="' + xa + '" y="' + (H - 3) + '">' + esc(n.Id) + '</text>'; lastL = xa; }
    });
    lanes.forEach(function (ln, i) { var y = top0 + i * lh + lh / 2; s += '<line class="grid" x1="' + L + '" x2="' + (W - R) + '" y1="' + y + '" y2="' + y + '"/><text class="lane" x="0" y="' + (y + 4) + '">' + esc(ln) + '</text>'; });
    var used = {};
    timed.forEach(function (f) {
      var t = f._d.getTime(); if (t < t0 || t > t1) return;
      var li = lanes.indexOf(laneOf(f)), px = x(t), key = li + ':' + Math.round(px / 9), c = used[key] = (used[key] || 0) + 1;
      var py = top0 + li * lh + lh / 2 + (c === 1 ? 0 : (c % 2 ? 1 : -1) * Math.ceil((c - 1) / 2) * 6);
      s += '<g class="pt' + (current === f ? ' on' : '') + '" tabindex="0" role="button" data-open="' + f._i + '" aria-label="' + esc(f.Severity + ', ' + fmt(f._d) + ' UTC: ' + f.Title) + '"><title>' + esc(fmt(f._d) + ' UTC  ' + f.Title) + '</title>' + shape(sevOf(f.Severity), px, py) + '</g>';
    });
    box.innerHTML = s + '</svg>';
  };
  $('legend').innerHTML = SEV.filter(function (x) { return S[x]; }).map(function (x) { return sevHtml(x); }).join('') + '<span>Grey band: incident</span>';
  drawChart();
  var rt; window.addEventListener('resize', function () { clearTimeout(rt); rt = setTimeout(drawChart, 150); });
  document.addEventListener('keydown', function (e) { if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('pt')) { e.preventDefault(); openFinding(+e.target.getAttribute('data-open'), true); } });

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
    Object.keys(e).forEach(function (k) { var x = e[k]; scan(typeof x === 'object' ? JSON.stringify(x) : x, f); });
    scan(f.Entity || '', f);
    ['User', 'Actor', 'Account', 'TargetUserName', 'MemberName'].forEach(function (k) { if (isAcct(e[k])) addI('Account', e[k], f); });
  });
  $('f-ext').textContent = IOC.filter(function (x) { return x.type === 'IP address' && !isPriv(x.value); }).length;

  /* attack path */
  var byStage = {};
  attackF.forEach(function (f) { (byStage[f._tac] = byStage[f._tac] || []).push(f); });
  var stageKeys = Object.keys(byStage).sort(function (a, b) { var ia = TAC.indexOf(a), ib = TAC.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  $('n-p').textContent = stageKeys.length || '';
  $('pathbox').innerHTML = !stageKeys.length ? '<div class="empty">No attacker-related findings to place on the attack lifecycle.</div>' :
    '<div class="tbl"><table id="pathtbl"><thead><tr><th>Stage</th><th>First seen (UTC)</th><th>Most severe</th><th>What was found</th></tr></thead><tbody>' + stageKeys.map(function (k) {
      var L = byStage[k].slice().sort(function (a, b) { return RANK[a.Severity] - RANK[b.Severity] || b.Score - a.Score; });
      var ds = L.map(function (f) { return f._d; }).filter(Boolean).sort(function (a, b) { return a - b; });
      var shown = L.slice(0, 4).map(function (f) { return '<div><a href="#f' + f._i + '" data-open="' + f._i + '">' + esc(f.Title) + '</a></div>'; }).join('') + (L.length > 4 ? '<div class="small">and ' + (L.length - 4) + ' more</div>' : '');
      return '<tr><td class="stage">' + esc(k) + '</td><td class="t">' + (ds.length ? esc(fmt(ds[0])) : '<span class="muted">not time-stamped</span>') + '</td><td>' + sevHtml(L[0].Severity) + '</td><td>' + shown + '</td></tr>';
    }).join('') + '</tbody></table></div>';

  /* findings: list on the left, the case file on the right */
  $('n-f').textContent = F.length;
  $('fsev').innerHTML = '<option value="">All severities</option>' + SEV.filter(function (x) { return S[x]; }).map(function (x) { return '<option value="' + x + '">' + x + ' (' + S[x] + ')</option>'; }).join('');
  var tacs = []; F.forEach(function (f) { if (tacs.indexOf(f._tac) < 0) tacs.push(f._tac); });
  tacs.sort(function (a, b) { var ia = TAC.indexOf(a), ib = TAC.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  $('ftac').innerHTML = '<option value="">All stages</option>' + tacs.map(function (t) { return '<option>' + esc(t) + '</option>'; }).join('');
  var cats = []; F.forEach(function (f) { if (cats.indexOf(f.Category) < 0) cats.push(f.Category); }); cats.sort();
  $('fcat').innerHTML = '<option value="">All areas</option>' + cats.map(function (c) { return '<option>' + esc(c) + '</option>'; }).join('');
  var techLinks = function (f) { return (f.Technique || []).filter(function (t) { return TID.test(t); }).map(function (t) { return '<a href="https://attack.mitre.org/techniques/' + esc(t.replace('.', '/')) + '/" target="_blank" rel="noopener noreferrer">' + esc(t) + '</a> ' + esc(techName[t] || '') + (techTac[t] ? ' (' + esc(techTac[t]) + ')' : ''); }).join('; '); };
  var srcName = function (f) {
    var s = String(f.Source || ''), e = f.Evidence || {};
    if (s === 'process') return ['Running process', 'seen in the process list at collection'];
    if (s === 'persistence') return ['Autostart entry', e.Location || e.Kind || ''];
    if (s === 'network') return ['Network connection', 'open at collection'];
    if (s === 'dns') return ['DNS cache', 'name resolved recently'];
    if (s === 'file') return ['File system', 'files present at collection'];
    if (s === 'exposure') return ['Exposed secret', e.Location || ''];
    if (s === 'posture') return ['Security configuration', ''];
    if (s === 'artifacts') return [e.SeenIn ? 'Execution artifacts' : (e.Artifact || 'Artifact'), e.SeenIn ? 'recorded in ' + e.SeenIn : (e.Source || '')];
    if (s.indexOf('evt:') === 0) return ['Event log', s.slice(4) + (e.EventId ? ', event ' + e.EventId : '')];
    if (s.indexOf('activity:') === 0) return ['Recorded change', s.slice(9)];
    if (s.indexOf('sigma') === 0) return ['Sigma rule', e.Rule || ''];
    if (s.indexOf('yara') === 0) return ['YARA rule', e.Rule || ''];
    return [s || 'Collected data', ''];
  };
  var timeMeaning = function (f) { var e = f.Evidence || {}, s = String(f.Source || ''); if (e.TimeKind) return String(e.TimeKind).toLowerCase(); if (s.indexOf('evt:') === 0) return 'event recorded'; if (s === 'process') return 'process started'; if (s === 'artifacts') return 'last recorded'; if (s.indexOf('activity:') === 0) return 'change recorded'; return 'time in the source'; };
  var hl = function (cmd) {
    var h = esc(cmd);
    [/(\s-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{12,})/gi, /(\bdelete\s+shadows\b|\bshadowcopy\s+delete\b|\/all\b|\/quiet\b|\bcl\s+\w+|\bclear-log\b|\bportproxy\b|-w(?:indowstyle)?\s+hidden|\s-nop\b|\biex\b|downloadstring|frombase64string|\bbypass\b|\b-R\s+\d+:)/gi].forEach(function (rx) { h = h.replace(rx, '<mark>$1</mark>'); });
    return h;
  };
  var kvTable = function (ev, skip) {
    var keys = Object.keys(ev || {}).filter(function (k) { return !skip[k] && ev[k] !== null && ev[k] !== ''; });
    if (!keys.length) return '';
    return '<table class="kv">' + keys.map(function (k) { var x = ev[k];
      if (Array.isArray(x)) x = x.map(function (y) { return (y && typeof y === 'object') ? JSON.stringify(y) : y; }).join('\n'); else if (x && typeof x === 'object') x = JSON.stringify(x, null, 1);
      return '<tr><td class="k">' + esc(k.replace(/([a-z])([A-Z])/g, '$1 $2')) + '</td><td class="v">' + esc(x) + '</td></tr>'; }).join('') + '</table>';
  };
  var neighbours = function (f) {
    var list;
    if (f._inc) list = f._inc._m.filter(function (g) { return g._d; });
    else if (f._d) list = F.filter(function (g) { return g._d && Math.abs(g._d - f._d) <= 30 * 60000; });
    else return '';
    list = list.slice().sort(function (a, b) { return a._d - b._d; });
    var at = list.indexOf(f); if (at < 0) return '';
    if (list.length < 2) return '';
    var lo = Math.max(0, at - 4), hi = Math.min(list.length, lo + 9);
    return '<div class="lbl">' + (f._inc ? 'Sequence in ' + esc(f._inc.Id) : 'Other findings within 30 minutes') + '</div><table class="seq"><tbody>' + list.slice(lo, hi).map(function (g) {
      return '<tr' + (g === f ? ' class="self"' : '') + '><td class="t">' + esc(fmtT(g._d)) + '</td><td class="nw">' + sevHtml(g.Severity) + '</td><td>' + (g === f ? esc(g.Title) : '<button type="button" data-open="' + g._i + '">' + esc(g.Title) + '</button>') + '</td></tr>'; }).join('') + '</tbody></table>' +
      (list.length > hi - lo ? '<p class="small" style="margin-top:6px">' + (list.length - (hi - lo)) + ' more in this sequence; see the timeline.</p>' : '');
  };
  var caseFile = function (f) {
    var e = f.Evidence || {}, src = srcName(f), h = '';
    h += '<div class="top">' + sevHtml(f.Severity) + '<span>' + esc(f.Confidence || 'Unknown') + ' confidence</span><span>Rule <span class="mono">' + esc(f.Id) + '</span></span>' + (f._inc ? '<span>Part of <a href="#incidents">' + esc(f._inc.Id) + '</a></span>' : '') + '<span>' + esc(f.Category || '') + '</span>' +
      '<span class="tools"><button class="btn" type="button" data-copy="' + f._i + '">Copy finding</button></span></div>';
    h += '<h3 class="ft">' + esc(f.Title) + '</h3>';
    var tl = techLinks(f); h += '<div class="tech">' + (tl || '<span class="muted">No ATT&amp;CK technique</span>') + '</div>';
    h += '<dl class="cf">';
    h += '<dt>What happened</dt><dd><p>' + esc(f.Description || 'No description.') + '</p>' + (f.Entity ? '<p class="small">Subject: <span class="mono">' + esc(f.Entity) + '</span></p>' : '') + ((f.Occurrences || 1) > 1 ? '<p class="small">Seen ' + esc(f.Occurrences) + ' times.</p>' : '') + '</dd>';
    var w = '';
    if (f._d) {
      w += '<div class="stamp">' + esc(fmt(f._d)) + ' UTC</div><div class="sub">' + esc(timeMeaning(f)) + (timed.length && timed[timed.length - 1] !== f && !isHygiene(f) ? ', ' + esc(span(timed[timed.length - 1]._d - f._d)) + ' before the last finding' : '') + '</div>';
      if (e.FirstSeen && e.LastSeen && e.FirstSeen !== e.LastSeen) w += '<div class="sub">First recorded ' + esc(fmt(dt(e.FirstSeen))) + ', last ' + esc(fmt(dt(e.LastSeen))) + ' UTC</div>';
    } else {
      w += '<div class="stamp" style="font-size:15px">No time stamp in this source</div><div class="sub">Observed at collection, ' + esc(fmt(collected)) + ' UTC. When it began is not recorded here.</div>';
    }
    var co = (f.Corroboration || []).filter(function (c) { return c && dt(c.First); }).sort(function (a, b) { return dt(a.First) - dt(b.First); });
    if (co.length && (!f._d || dt(co[0].First) < f._d)) w += '<div class="sub">Earliest trace: ' + esc(co[0].Source) + ', ' + esc(fmt(dt(co[0].First))) + ' UTC</div>';
    w += neighbours(f);
    h += '<dt>When</dt><dd>' + w + '</dd>';
    var how = '<p>' + esc(src[0]) + (src[1] ? ': ' + esc(src[1]) : '') + '.</p>';
    var proc = e.Process || (e.Image ? String(e.Image).split('\\').pop() : '');
    var skip = { Time: 1, TimeKind: 1 };
    if ((f.Lineage || []).length > 1) {
      var srcs = []; f.Lineage.forEach(function (n) { var s = String(n.Source || '').replace(/ \(parent named by child\)$/, ''); if (s && srcs.indexOf(s) < 0) srcs.push(s); });
      how += '<div class="lbl">Process tree (' + esc(srcs.join(', ')) + ')</div><pre class="box">' + f.Lineage.map(function (n, i) {
        var ind = new Array(2 * i + 1).join(' '), last = i === f.Lineage.length - 1, d = dt(n.Time), cl = String(n.CommandLine || '');
        var line = (i ? ind + '└ ' : '') + (last ? '<b>' : '') + esc(String(n.Image || '?').split('\\').pop()) + (last ? '</b>' : '') + (n.Pid !== null && n.Pid !== undefined && n.Pid !== '' ? '  PID ' + esc(n.Pid) : '') + (d ? '  ' + esc(fmt(d)) + ' UTC' : '') + (n.User ? '  ' + esc(n.User) : '');
        if (cl) line += '\n' + (i ? ind + '  ' : '') + (last ? hl(cl.length > 400 ? cl.slice(0, 400) + ' …' : cl) : esc(cl.length > 160 ? cl.slice(0, 160) + ' …' : cl));
        return line; }).join('\n') + '</pre>';
      skip.Parent = skip.Process = skip.Pid = 1;
    } else if (e.Parent && proc) { how += '<div class="lbl">Process chain</div><pre class="box">' + esc(String(e.Parent).split('\\').pop()) + '\n  └ ' + esc(proc) + (e.Pid ? '   PID ' + esc(e.Pid) : '') + (e.User ? '   user ' + esc(e.User) : '') + '</pre>'; skip.Parent = skip.Process = skip.Pid = 1; if (e.User) skip.User = 1; }
    var cmd = e.CommandLine || e.Command || e.Arguments;
    if (cmd) { how += '<div class="lbl">Command line</div><pre class="box">' + hl(cmd) + '</pre>'; skip.CommandLine = skip.Command = skip.Arguments = 1; }
    var kv = kvTable(e, skip); if (kv) how += '<div class="lbl">Evidence</div>' + kv;
    if ((f.Corroboration || []).length) {
      how += '<div class="lbl">Also recorded in ' + f.Corroboration.length + ' independent source' + (f.Corroboration.length === 1 ? '' : 's') + '</div><table class="kv">' + f.Corroboration.map(function (c) {
        return '<tr><td class="k">' + esc(c.Source) + '</td><td class="v">' + esc((c.First ? fmt(dt(c.First)) + ' UTC' + (c.Last && c.Last !== c.First ? ' to ' + fmt(dt(c.Last)) : '') + '  ' : '') + (c.Detail || '')) + '</td></tr>'; }).join('') + '</table>';
      if (f.ConfidenceNote) how += '<p class="small" style="margin-top:6px">' + esc(f.ConfidenceNote) + '</p>';
    }
    h += '<dt>How we know</dt><dd>' + how + '</dd>';
    h += '<dt>What to do</dt><dd><p>' + esc(f.Recommendation || 'Review the evidence and decide whether this is expected on this host.') + '</p></dd>';
    return h + '</dl>';
  };
  var fRows = function () {
    var q = $('fq').value.toLowerCase(), sv = $('fsev').value, c = $('fcat').value, tc = $('ftac').value;
    return F.filter(function (f) { return (!sv || f.Severity === sv) && (!c || f.Category === c) && (!tc || f._tac === tc) && (!q || JSON.stringify(f).toLowerCase().indexOf(q) >= 0); });
  };
  var bySev = function (a, b) { return RANK[a.Severity] - RANK[b.Severity] || (b.Score || 0) - (a.Score || 0) || a._i - b._i; };
  var byTime = function (a, b) { return (a._d ? a._d.getTime() : 9e15) - (b._d ? b._d.getTime() : 9e15) || a._i - b._i; };
  var renderF = function () {
    var rows = fRows(), ord = $('ford').value, groups = [];
    if (ord === 'inc') {
      N.forEach(function (n) { var m = rows.filter(function (f) { return f._inc === n; }).sort(byTime); if (m.length) groups.push([n.Id + ', ' + n.Severity.toLowerCase() + ', ' + m.length + ' finding' + (m.length === 1 ? '' : 's'), m]); });
      var rest = rows.filter(function (f) { return !f._inc; }).sort(bySev); if (rest.length) groups.push(['Not part of an incident', rest]);
    } else if (ord === 'time') groups.push(['', rows.sort(byTime)]);
    else SEV.forEach(function (s) { var m = rows.filter(function (f) { return f.Severity === s; }).sort(bySev); if (m.length) groups.push([s + ' (' + m.length + ')', m]); });
    $('fitems').innerHTML = rows.length ? groups.map(function (g) {
      return (g[0] ? '<div class="fg">' + esc(g[0]) + '</div>' : '') + g[1].map(function (f) {
        return '<button class="fi" type="button" role="option" id="f' + f._i + '" data-i="' + f._i + '" aria-selected="' + (current === f) + '"><span class="t">' + esc(f.Title) + '</span><span class="m">' + sevHtml(f.Severity) + '<span>' + (f._d ? esc(fmt(f._d)) : 'at collection') + '</span><span>' + esc(srcName(f)[0]) + '</span></span></button>';
      }).join('');
    }).join('') : '<div class="empty" style="margin:10px">' + (F.length ? 'No finding matches. Clear the search or the filters.' : 'No findings. Check what this report could not see before concluding the host is clean.') + '</div>';
    $('fcount').textContent = rows.length + ' of ' + F.length + ' findings';
  };
  var showCase = function (f) {
    current = f;
    $('case').innerHTML = f ? caseFile(f) : '<div class="empty">No findings in this case.</div>';
    Array.prototype.forEach.call(document.querySelectorAll('.fi'), function (b) { b.setAttribute('aria-selected', +b.getAttribute('data-i') === (f ? f._i : -1)); });
    Array.prototype.forEach.call(document.querySelectorAll('#chartsvg .pt'), function (p) { p.classList.toggle('on', f && +p.getAttribute('data-open') === f._i); });
  };
  var openFinding = function (i, scroll) {
    var f = F[i]; if (!f) return;
    if (fRows().indexOf(f) < 0) { $('fq').value = ''; $('fsev').value = ''; $('fcat').value = ''; $('ftac').value = ''; renderF(); }
    showCase(f);
    var it = $('f' + i); if (it && it.scrollIntoView) it.scrollIntoView({ block: 'nearest' });
    if (scroll) $('findings').scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth' });
  };
  $('fitems').addEventListener('click', function (e) { var b = e.target.closest('.fi'); if (b) showCase(F[+b.getAttribute('data-i')]); });
  $('fitems').addEventListener('keydown', function (e) {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    var items = Array.prototype.slice.call(document.querySelectorAll('.fi')), k = items.indexOf(document.activeElement); if (k < 0) return;
    e.preventDefault(); var nx = items[k + (e.key === 'ArrowDown' ? 1 : -1)]; if (nx) { nx.focus(); showCase(F[+nx.getAttribute('data-i')]); }
  });
  $('case').addEventListener('click', function (e) {
    var cb = e.target.closest('[data-copy]'); if (!cb) return;
    var f = F[+cb.getAttribute('data-copy')];
    copy([f.Severity + ': ' + f.Title, 'Rule: ' + f.Id + '  Techniques: ' + (f.Technique || []).join(', '), 'Time (UTC): ' + utc(f._d), 'Subject: ' + (f.Entity || ''), '', f.Description, '', 'What to do: ' + (f.Recommendation || ''), '', 'Evidence: ' + JSON.stringify(f.Evidence || {}, null, 2)].join('\n'));
  });
  document.addEventListener('click', function (e) { var a = e.target.closest('[data-open]'); if (!a) return; e.preventDefault(); openFinding(+a.getAttribute('data-open'), !a.closest('#findings')); });
  ['fq', 'fsev', 'fcat', 'ftac', 'ford'].forEach(function (id) { $(id).addEventListener(id === 'fq' ? 'input' : 'change', renderF); });
  $('fx-csv').onclick = function () { download('findings_' + (D.hostName || 'host') + '.csv', csv([['severity', 'title', 'stage', 'techniques', 'time_utc', 'occurrences', 'area', 'rule', 'confidence', 'score', 'incident', 'entity', 'recommendation', 'evidence', 'also_recorded_in']].concat(F.map(function (f) { return [f.Severity, f.Title, f._tac, (f.Technique || []).join(' '), utc(f._d), f.Occurrences || 1, f.Category, f.Id, f.Confidence, f.Score, f._inc ? f._inc.Id : '', f.Entity, f.Recommendation, JSON.stringify(f.Evidence || {}), (f.Corroboration || []).map(function (c) { return c.Source; }).join(' | ')]; }))), 'text/csv'); };
  window.addEventListener('beforeprint', function () { var keep = current; $('printall').innerHTML = F.slice().sort(bySev).map(function (f) { return '<article class="case">' + caseFile(f) + '</article>'; }).join(''); current = keep; });
  window.addEventListener('afterprint', function () { $('printall').innerHTML = ''; });
  renderF();
  showCase(F.slice().sort(bySev)[0] || null);
  if (/^#f\d+$/.test(location.hash)) openFinding(+location.hash.slice(2), true);

  /* indicators */
  var defang = function (t, x) { if (!$('idef').checked) return x; if (t === 'URL') return x.replace(/^http/i, 'hxxp').replace(/\./g, '[.]'); if (t === 'Domain' || t === 'IP address') return x.replace(/\./g, '[.]'); return x; };
  var itypes = ['IP address', 'Domain', 'URL', 'SHA-256', 'SHA-1', 'MD5', 'File', 'Registry key', 'Account'];
  var present = itypes.filter(function (t) { return IOC.some(function (x) { return x.type === t; }); });
  $('itype').innerHTML = '<option value="">All types</option>' + present.map(function (t) { return '<option>' + t + '</option>'; }).join('');
  var OSINT_KIND = { 'IP address': 'ipv4-addr:value', 'Domain': 'domain-name:value', 'URL': 'url:value', 'SHA-256': "file:hashes.'SHA-256'", 'SHA-1': "file:hashes.'SHA-1'", 'MD5': 'file:hashes.MD5' };
  var canPick = function (x) { return !!OSINT_KIND[x.type] && !(x.type === 'IP address' && isPriv(x.value)); };
  var isSysFile = function (x) { return x.type === 'File' && /^[a-z]:\\windows\\(?:system32|syswow64|winsxs)\\[^\\]+\.(?:exe|dll)$/i.test(x.value); };
  var iRows = function () { var q = $('iq').value.toLowerCase(), t = $('itype').value, pv = $('ipriv').checked, sy = $('isys').checked;
    return IOC.filter(function (x) { return (!t || x.type === t) && (pv || x.type !== 'IP address' || !isPriv(x.value)) && (sy || !isSysFile(x)) && (!q || x.value.toLowerCase().indexOf(q) >= 0); })
      .sort(function (a, b) { return itypes.indexOf(a.type) - itypes.indexOf(b.type) || RANK[a.sev] - RANK[b.sev] || a.value.localeCompare(b.value); }); };
  var renderI = function () {
    var rows = iRows(); $('n-i').textContent = IOC.filter(function (x) { return (x.type !== 'IP address' || !isPriv(x.value)) && !isSysFile(x); }).length;
    var pickable = rows.filter(canPick);
    $('ibox').innerHTML = rows.length ? '<div class="tbl"><table id="itbl"><thead><tr><th class="ipick">' + (pickable.length ? '<input type="checkbox" id="i-all" aria-label="Tick every indicator shown"' + (pickable.every(function (x) { return x.pick; }) ? ' checked' : '') + '>' : '') + '</th><th>Type</th><th>Value</th><th>Most severe</th><th>Found in</th></tr></thead><tbody>' + rows.map(function (x) {
      return '<tr><td class="ipick">' + (canPick(x) ? '<input type="checkbox" data-pick="' + IOC.indexOf(x) + '" aria-label="Tick for OSINT"' + (x.pick ? ' checked' : '') + '>' : '') + '</td><td class="nw">' + esc(x.type) + (x.type === 'IP address' && isPriv(x.value) ? ' <span class="muted">(private)</span>' : '') + '</td><td class="m">' + esc(defang(x.type, x.value)) + '</td><td class="nw">' + sevHtml(x.sev) + '</td><td>' +
        x.from.slice(0, 3).map(function (i) { return '<div><a href="#f' + i + '" data-open="' + i + '">' + esc(F[i].Title) + '</a></div>'; }).join('') + (x.from.length > 3 ? '<div class="small">and ' + (x.from.length - 3) + ' more</div>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div><div class="count">' + rows.length + ' indicators shown.</div>'
      : '<div class="empty">' + (IOC.length ? 'No indicators match these filters.' : 'No indicators were found in the evidence of attacker-related findings.') + '</div>';
  };
  ['iq', 'itype', 'idef', 'ipriv', 'isys'].forEach(function (id) { $(id).addEventListener(id === 'iq' ? 'input' : 'change', renderI); });
  // Ticked indicators go to OSINTrix as STIX 2.1. Only what it can research: public addresses, domains, URLs, hashes.
  var updPick = function () { var n = IOC.filter(function (x) { return x.pick; }).length; $('i-osint').disabled = !n; $('i-osint').textContent = n ? 'Export for OSINT (' + n + ')' : 'Export for OSINT'; };
  $('ibox').addEventListener('change', function (e) {
    var t = e.target;
    if (t.id === 'i-all') { iRows().filter(canPick).forEach(function (x) { x.pick = t.checked; }); renderI(); updPick(); }
    else if (t.hasAttribute && t.hasAttribute('data-pick')) { IOC[+t.getAttribute('data-pick')].pick = t.checked; var a = $('i-all'); if (a) a.checked = iRows().filter(canPick).every(function (x) { return x.pick; }); updPick(); }
  });
  $('i-pick').onclick = function () { var n = 0; IOC.forEach(function (x) { if (canPick(x)) { x.pick = true; n++; } }); renderI(); updPick(); toast(n ? n + ' ticked' : 'No external indicators or hashes in this case'); };
  var rid = function () { var b = new Uint8Array(16); crypto.getRandomValues(b); b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128; var h = Array.prototype.map.call(b, function (v) { return (v + 256).toString(16).slice(1); }).join(''); return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20); };
  var stxq = function (v) { return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); };
  $('i-osint').onclick = function () {
    var pick = IOC.filter(function (x) { return x.pick && canPick(x); });
    if (!pick.length) { toast('Tick the indicators to send first'); return; }
    var now = new Date().toISOString(), hostN = String(D.hostName || 'host'), caseId = String(cs.Id || ''), AMBER = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82';
    var idn = { type: 'identity', spec_version: '2.1', id: 'identity--' + rid(), created: now, modified: now, name: 'WinForensicX', identity_class: 'system' };
    var objs = [idn], refs = [];
    pick.forEach(function (x) {
      var v = x.type === 'URL' ? x.value.replace(/^hxxp/i, 'http') : x.value;
      var titles = x.from.map(function (i) { return F[i].Title; });
      var first = x.from.map(function (i) { return F[i]._d; }).filter(Boolean).sort(function (a, b) { return a - b; })[0];
      var o = { type: 'indicator', spec_version: '2.1', id: 'indicator--' + rid(), created: now, modified: now, created_by_ref: idn.id,
        name: hostN + ': ' + titles[0], description: 'Found on ' + hostN + (caseId ? ' (WinForensicX case ' + caseId + ')' : '') + ' in: ' + titles.join('; '),
        pattern: '[' + OSINT_KIND[x.type] + " = '" + stxq(v) + "']", pattern_type: 'stix', valid_from: (first || new Date()).toISOString(),
        indicator_types: ['anomalous-activity'], labels: ['winforensicx', 'host:' + hostN, 'severity:' + String(x.sev).toLowerCase()], object_marking_refs: [AMBER] };
      objs.push(o); refs.push(o.id);
    });
    objs.push({ type: 'report', spec_version: '2.1', id: 'report--' + rid(), created: now, modified: now, created_by_ref: idn.id, name: 'WinForensicX: ' + hostN + (caseId ? ' (case ' + caseId.slice(0, 8) + ')' : ''), published: now, report_types: ['indicator'], object_refs: refs, object_marking_refs: [AMBER] });
    download('osint_' + hostN.replace(/[^\w.-]+/g, '_') + '.stix.json', JSON.stringify({ type: 'bundle', id: 'bundle--' + rid(), objects: objs }, null, 2), 'application/json');
  };
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
      var day = fmtD(e.d) + ', ' + ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][e.d.getUTCDay()];
      if (day !== last) { html.push('<tr class="day"><td colspan="4">' + esc(day) + '</td></tr>'); last = day; }
      html.push('<tr' + (e.k === 'f' ? '' : ' class="chg"') + '><td class="t">' + esc(fmtT(e.d)) + '</td><td class="nw">' + (e.k === 'f' ? sevHtml(e.sev) : '<span class="kind">Change</span>') + '</td><td>' + (e.k === 'f' ? '<a href="#f' + e.i + '" data-open="' + e.i + '">' + esc(e.what) + '</a>' : esc(e.what)) + '</td><td class="m">' + esc(e.det) + '</td></tr>');
    });
    $('tbox').innerHTML = rows.length ? '<div class="tbl"><table><thead><tr><th>Time (UTC)</th><th>Kind</th><th>Event</th><th>Detail</th></tr></thead><tbody>' + html.join('') + '</tbody></table></div><div class="count">' + rows.length + ' events' + (rows.length > 3000 ? ', first 3,000 shown' : '') + '.</div>'
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
    $('abox').innerHTML = '<div class="tbl"><table><thead><tr><th>Time (UTC)</th><th>Area</th><th>Change</th><th>Target</th><th>By</th><th>Source</th></tr></thead><tbody>' +
      rows.slice(0, 1500).map(function (a) { return '<tr><td class="t">' + esc(fmt(a._d)) + '</td><td class="nw">' + esc(a.Category) + '</td><td>' + esc(a.Action) + '</td><td class="m">' + esc(a.Target) + (a.Detail ? '<div class="small">' + esc(a.Detail) + '</div>' : '') + '</td><td class="m">' + esc(a.Actor) + '</td><td class="small">' + esc(a.Source) + '</td></tr>'; }).join('') +
      '</tbody></table></div><div class="count">' + rows.length + ' of ' + A.length + ' shown' + (rows.length > 1500 ? '; first 1,500 rendered' : '') + '.</div>';
  };
  $('aq').oninput = renderA; $('acat').onchange = renderA; renderA();

  /* incidents */
  $('n-n').textContent = N.length || '';
  var entLabel = function (k) { var p = String(k).split(':'); var kind = p.shift(); return '<span class="kind">' + esc({ file: 'File', user: 'Account', ip: 'Address' }[kind] || kind) + '</span> ' + esc(p.join(':')); };
  $('nbox').innerHTML = N.length ? '<div class="tbl"><table id="ntbl"><thead><tr><th>Incident</th><th>When (UTC)</th><th>Severity</th><th>Stages</th><th>Involving</th><th>Findings</th></tr></thead><tbody>' + N.map(function (n) {
    var s = dt(n.Start), e = dt(n.End);
    var fl = (n.Findings || []).map(function (x) { var i = fIndex[x.Id + '|' + x.Entity]; return '<div>' + sevHtml(x.Severity, '') + ' ' + (i === undefined ? esc(x.Title) : '<a href="#f' + i + '" data-open="' + i + '">' + esc(x.Title) + '</a>') + '</div>'; });
    var entry = n.Entry ? (function () { var i = fIndex[n.Entry.Id + '|' + n.Entry.Entity]; return '<div class="small">Likely starting point: ' + (i === undefined ? esc(n.Entry.Title) : '<a href="#f' + i + '" data-open="' + i + '">' + esc(n.Entry.Title) + '</a>') + (n.Entry.Why ? ' (' + esc(n.Entry.Why) + ')' : '') + '</div>'; })() : '';
    return '<tr><td class="nw"><b>' + esc(n.Id) + '</b><div class="small">' + esc(n.Count) + ' findings</div></td><td class="t">' + esc(fmt(s)) + (e && s && e - s > 60000 ? '<div class="small">to ' + esc(fmt(e)) + ', ' + esc(span(e - s)) + '</div>' : '') + '</td><td>' + sevHtml(n.Severity) + '</td><td>' +
      esc((n.Tactics || []).join(', ') || 'Other') + '</td><td>' + (n.Entities || []).slice(0, 5).map(function (k) { return '<div>' + entLabel(k) + '</div>'; }).join('') + '</td><td>' + fl.slice(0, 6).join('') + (fl.length > 6 ? '<div class="small">and ' + (fl.length - 6) + ' more</div>' : '') +
      entry + ((n.Links || []).length ? '<div class="small">Grouped by: ' + esc(n.Links.slice(0, 4).join('; ')) + '</div>' : '') + '</td></tr>';
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
    $('ebox').innerHTML = '<div class="tbl"><table id="etbl"><thead><tr><th>Finding</th><th>Time (UTC)</th><th>Artifact</th><th>Path</th><th>User</th><th>Detail</th></tr></thead><tbody>' +
      rows.slice(0, 1500).map(function (a) { var ps = pathSev[pkey(a.Path)]; return '<tr><td class="nw">' + (ps ? '<a href="#f' + ps.i + '" data-open="' + ps.i + '" title="Open the finding">' + sevHtml(ps.s) + '</a>' : '') + '</td><td class="t">' + (a._d ? esc(fmt(a._d)) : '<span class="muted">no time</span>') + (a.TimeKind ? '<div class="small">' + esc(a.TimeKind) + '</div>' : '') + '</td><td class="nw">' + esc(a.Artifact) + '<div class="small">' + esc(a.Evidence) + '</div></td><td class="m">' + esc(a.Path) + (a.Sha1 ? '<div class="small mono" title="SHA-1 ' + esc(a.Sha1) + '">SHA-1 ' + esc(String(a.Sha1).slice(0, 16)) + '…</div>' : '') + '</td><td class="nw">' + esc(a.User || '') + '</td><td>' + esc(a.Detail || '') + '</td></tr>'; }).join('') +
      '</tbody></table></div><div class="count">' + rows.length + ' of ' + E.length + ' shown' + (rows.length > 1500 ? '; first 1,500 rendered' : '') + '.</div>';
  };
  $('eq').oninput = renderE; $('eart').onchange = renderE; $('eev').onchange = renderE; $('eflag').onchange = renderE; renderE();
  $('e-csv').onclick = function () { download('execution_' + (D.hostName || 'host') + '.csv', csv([['time_utc', 'time_meaning', 'artifact', 'evidence', 'path', 'user', 'sha1', 'detail', 'flag']].concat(eRows().map(function (a) { var ps = pathSev[pkey(a.Path)]; return [a.Time || '', a.TimeKind || '', a.Artifact, a.Evidence, a.Path, a.User || '', a.Sha1 || '', a.Detail || '', ps ? ps.s : '']; }))), 'text/csv'); };

  /* ATT&CK matrix and Navigator layer */
  var techMax = {}, techFind = {};
  F.forEach(function (f) { (f.Technique || []).forEach(function (t) { if (!TID.test(t)) return; if (techMax[t] === undefined || RANK[f.Severity] < RANK[techMax[t]]) techMax[t] = f.Severity; (techFind[t] = techFind[t] || []).push(f); }); });
  var techs = Object.keys(techMax);
  $('n-x').textContent = techs.length || '';
  $('xbox').innerHTML = !techs.length ? '<div class="empty">No ATT&amp;CK techniques were observed.</div>' :
    '<div class="matrix">' + TAC.map(function (tac) {
      var L = techs.filter(function (t) { return techTac[t] === tac; }).sort(function (a, b) { return RANK[techMax[a]] - RANK[techMax[b]] || a.localeCompare(b); });
      return '<div class="mcol' + (L.length ? '' : ' none') + '"><h4>' + esc(tac) + '<span>' + (L.length ? L.length + ' technique' + (L.length === 1 ? '' : 's') : 'none') + '</span></h4>' +
        L.map(function (t) { return '<a class="mt" href="https://attack.mitre.org/techniques/' + esc(t.replace('.', '/')) + '/" target="_blank" rel="noopener noreferrer"><b>' + sevHtml(techMax[t], '') + esc(t) + '</b>' + esc(techName[t] || '') + '</a>'; }).join('') + '</div>';
    }).join('') + '</div>' + (techs.some(function (t) { return !techTac[t]; }) ? '<p class="small" style="margin-top:8px">Other techniques: ' + techs.filter(function (t) { return !techTac[t]; }).map(esc).join(', ') + '</p>' : '');
  $('x-layer').onclick = function () {
    var color = { Critical: '#9b1c1c', High: '#c2410c', Medium: '#e3a008', Low: '#7aa7d9', Info: '#c8ccd1' }, score = { Critical: 100, High: 75, Medium: 50, Low: 25, Info: 10 };
    var layer = { name: 'WinForensicX ' + (D.hostName || ''), versions: { attack: '16', navigator: '5.1.0', layer: '4.5' }, domain: 'enterprise-attack',
      description: 'Techniques observed by ' + D.tool + ' on ' + (D.hostName || '') + ', collected ' + (D.collected || '') + ' UTC.',
      techniques: techs.map(function (t) { return { techniqueID: t, score: score[techMax[t]], color: color[techMax[t]], comment: techFind[t].map(function (f) { return f.Severity + ': ' + f.Title; }).slice(0, 10).join('\n'), enabled: true, showSubtechniques: true }; }),
      gradient: { colors: ['#ffffff', '#c2410c'], minValue: 0, maxValue: 100 },
      legendItems: SEV.slice(0, 4).map(function (s) { return { label: s, color: color[s] }; }), showTacticRowBackground: false, selectSubtechniquesWithParent: false };
    download('attack-layer_' + (D.hostName || 'host') + '.json', JSON.stringify(layer, null, 2), 'application/json');
  };

  /* visibility, custody, limits */
  var G = D.gaps || []; $('n-g').textContent = G.length || '';
  $('gbox').innerHTML = G.length ? '<ul class="list">' + G.map(function (x) { return '<li><b>' + esc(x.Source) + '</b>: ' + esc(x.Reason) + (x.Fix ? '<div class="fix">To fix: ' + esc(x.Fix) + '</div>' : '') + '</li>'; }).join('') + '</ul>' : '<div class="empty">Nothing was limited: collection ran with the visibility it attempted.</div>';
  var SP = D.suppressed || [];
  $('sbox').innerHTML = SP.length ? '<ul class="list">' + SP.map(function (x) { return '<li>' + sevHtml(x.Severity) + ' <b>' + esc(x.Title) + '</b><div class="fix">Reason: ' + esc(x.Reason || 'none given') + '. Allowlist rule ' + esc(x.Rule) + '.</div></li>'; }).join('') + '</ul>' : '<div class="empty">Nothing was suppressed.</div>';
  var kv = function (k, x) { return (x === undefined || x === null || x === '') ? '' : '<tr><td class="k">' + esc(k) + '</td><td class="v">' + esc(typeof x === 'object' ? JSON.stringify(x) : x) + '</td></tr>'; };
  $('cbox').innerHTML = '<table class="kv" style="width:100%">' + kv('Case id', cs.Id) + kv('Mode', cs.Mode) + kv('Collected (UTC)', D.collected) + kv('Case started (UTC)', cs.Started) + kv('Report generated (UTC)', D.generated) +
    kv('Operator', (cs.Operator || '') + (cs.OperatorHost ? ' on ' + cs.OperatorHost : '')) + kv('Elevated', cs.Admin) + kv('PowerShell', cs.PowerShell) + kv('Tool', D.tool) +
    kv('Host OS', host.Os || host.OS) + kv('Host time zone', host.TimeZone) + kv('Parameters', cs.Parameters) +
    kv('Sources', (cs.Sources || []).map(function (s) { return s.role + ': ' + s.path + '  sha256 ' + s.sha256; }).join('\n')) + kv('Written to the evidence system drive', cs.OutputOnSystemDrive) + '</table>';
  $('verify').textContent = 'Test-WfxCase -Path "<this case folder>"';
  $('lbox').innerHTML = (D.limits || []).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('');
  $('foot').textContent = D.tool + '. Report generated ' + (D.generated || '') + ' UTC. Self-contained and offline; collection was read-only. Findings are leads for an analyst, not verdicts.';

  /* running header and footer on printed pages */
  var cssq = function (x) { return '"' + String(x).replace(/["\\\r\n]/g, ' ') + '"'; };
  var ps = document.createElement('style');
  ps.textContent = '@media print { @page { @top-left { content: ' + cssq('WinForensicX case report, ' + (D.hostName || '')) + '; font: 8pt sans-serif; color: #444; } @top-right { content: ' + cssq(cs.Id ? 'Case ' + String(cs.Id).slice(0, 8) : '') + '; font: 8pt sans-serif; color: #444; } ' +
    '@bottom-left { content: ' + cssq('Generated ' + (D.generated || '') + ' UTC by ' + D.tool) + '; font: 8pt sans-serif; color: #444; } @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt sans-serif; color: #444; } } }';
  document.head.appendChild(ps);

  /* section highlight in the bar */
  var links = Array.prototype.slice.call(document.querySelectorAll('#nav a'));
  var secs = links.map(function (a) { return document.querySelector(a.getAttribute('href')); });
  var onScroll = function () { var y = window.scrollY + 60, cur = 0; secs.forEach(function (s, i) { if (s && s.offsetTop <= y) cur = i; }); links.forEach(function (a, i) { a.classList.toggle('on', i === cur); }); var nav = $('nav'), on = links[cur]; if (on && (on.offsetLeft < nav.scrollLeft || on.offsetLeft + on.offsetWidth > nav.scrollLeft + nav.clientWidth)) nav.scrollLeft = on.offsetLeft - 20; };
  window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
})();
</script>
</body>
</html>
'@
