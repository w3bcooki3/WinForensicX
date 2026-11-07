# Self-contained, offline HTML table for one Explore view: sort by any column, filter, copy as TSV.
# Evidence values can be attacker-controlled (file names, command lines, registry data), so they are embedded
# as JSON with "<" escaped and inserted with textContent only — never as HTML. A strict CSP forbids any
# network access from the page.

function ConvertTo-WfxViewHtml {
    param([object[]]$Rows, [string]$Title, [object[]]$Note = @(), [string]$HostName = [Environment]::MachineName)
    $rows = @($Rows | Expand-WfxRecord)
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) { foreach ($p in $r.PSObject.Properties) { if (-not $cols.Contains($p.Name)) { $cols.Add($p.Name) } } }
    $data = New-Object System.Collections.Generic.List[object]      # list of string[] — stays 2-D even with one row
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
    $json = (ConvertTo-Json -InputObject $payload -Depth 5 -Compress) -replace '<', '\u003c' -replace '>', '\u003e' -replace '&', '\u0026'
    $enc = [System.Net.WebUtility]::HtmlEncode("$Title · $HostName")
    @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$enc</title>
<style>html{font-variant-ligatures:none;font-feature-settings:"calt" 0,"liga" 0,"clig" 0}

:root{--bg:#EDF0F3;--card:#fff;--ink:#16202B;--dim:#5B6B7B;--line:#D5DCE3;--head:#1F2C3A;--acc:#1F5FAD;--mark:#F2C230}
@media (prefers-color-scheme:dark){:root{--bg:#10161D;--card:#18212B;--ink:#E3E9EF;--dim:#8C9AA8;--line:#2A3743;--head:#0B1117;--acc:#7EB3F0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:13.5px/1.45 "Segoe UI",system-ui,sans-serif}
header{background:var(--head);color:#fff;padding:14px 20px;border-bottom:4px solid var(--mark)}
header h1{margin:0;font-size:17px;font-weight:600}header p{margin:3px 0 0;color:#B8C4CF;font-size:12.5px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:12px 20px}
input{flex:1 1 260px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink);font:inherit}
button{padding:8px 12px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink);font:inherit;cursor:pointer}
button:hover{border-color:var(--acc)}#count{color:var(--dim)}
.notes{margin:0 20px 10px;padding:10px 14px;border-left:4px solid var(--mark);background:var(--card);border-radius:4px}
.notes li{margin:2px 0}.wrap{margin:0 20px 20px;overflow:auto;max-height:calc(100vh - 170px);background:var(--card);border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;min-width:100%}th,td{padding:6px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card);font-weight:600;cursor:pointer;white-space:nowrap;user-select:none;box-shadow:0 1px 0 var(--line)}
th[aria-sort=ascending]::after{content:" ▲";color:var(--acc)}th[aria-sort=descending]::after{content:" ▼";color:var(--acc)}
td{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px;min-width:18ch;max-width:520px;overflow-wrap:break-word;word-break:normal}
td.nw{white-space:nowrap;max-width:none}
tr:hover td{background:rgba(31,95,173,.06)}
td.ts{white-space:nowrap}
td.sev{font:600 11px/1 "Segoe UI",system-ui,sans-serif;letter-spacing:.04em;white-space:nowrap;min-width:0}
td.sev span{display:inline-block;padding:3px 6px;border-radius:3px}
.sev-critical span{background:#7A0E0E;color:#fff}.sev-high span{background:#C0362C;color:#fff}.sev-medium span{background:#E8A33D;color:#1B1300}
.sev-low span{background:#D5E3F2;color:#123}.sev-info span{background:var(--line);color:var(--ink)}
tr.flag-critical td,tr.flag-high td{background:rgba(192,54,44,.07)}
label.so{display:flex;gap:6px;align-items:center;color:var(--dim);white-space:nowrap}
td.why{font:13px/1.4 "Segoe UI",system-ui,sans-serif;min-width:220px}label.so[hidden]{display:none}
#sum{font-weight:600;color:#C0362C}
@media print{.bar,header p{display:none}.wrap{max-height:none;overflow:visible}}
*,*::before,*::after{font-variant-ligatures:none!important;font-feature-settings:"calt" 0,"liga" 0,"clig" 0!important}
</style></head><body>
<header><h1 id="t"></h1><p id="m"></p></header>
<div class="bar"><input id="q" type="search" placeholder="Filter rows (all columns)…" aria-label="Filter"><label class="so" id="sol" hidden><input type="checkbox" id="so"> Suspicious only</label><span id="sum"></span><span id="count"></span><button id="copy" type="button">Copy visible rows (TSV)</button></div>
<ul class="notes" id="notes" hidden></ul>
<div class="wrap"><table><thead><tr id="h"></tr></thead><tbody id="b"></tbody></table></div>
<script type="application/json" id="data">$json</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent),cols=D.columns,rows=D.rows,view=rows.slice(),sc=-1,dir=1;
document.getElementById('t').textContent=D.title;
document.getElementById('m').textContent=D.host+' · generated '+D.generated+' (UTC) · '+D.tool+' · read-only view';
document.title=D.title+' · '+D.host;
if(D.notes.length){var n=document.getElementById('notes');n.hidden=false;D.notes.forEach(function(x){var li=document.createElement('li');li.textContent=x;n.appendChild(li);});}
var h=document.getElementById('h'),b=document.getElementById('b'),cnt=document.getElementById('count'),fc=cols.indexOf('Flag'),wc=cols.indexOf('Why'),so=document.getElementById('so');
var rank={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};
var nw=cols.map(function(c,i){var m=c.length;for(var r=0;r<rows.length&&r<2000;r++){var l=String(rows[r][i]).length;if(l>m)m=l;}return m<=30;});
if(fc>=0){document.getElementById('sol').hidden=false;var tally={};rows.forEach(function(r){var f=r[fc];if(f&&f!=='INFO')tally[f]=(tally[f]||0)+1;});
document.getElementById('sum').textContent=Object.keys(tally).sort(function(a,b){return rank[b]-rank[a]}).map(function(k){return tally[k]+' '+k}).join(' · ');}
cols.forEach(function(c,i){var th=document.createElement('th');th.textContent=c;th.tabIndex=0;th.onclick=function(){sort(i,th)};th.onkeydown=function(e){if(e.key==='Enter')sort(i,th)};h.appendChild(th);});
function key(v){var n=Number(v);if(v!==''&&!isNaN(n))return[0,n];var d=/^\d{4}-\d\d-\d\dT/.test(v)?Date.parse(v):NaN;if(!isNaN(d))return[0,d];return[1,v.toLowerCase()];}
function sort(i,th){dir=(sc===i)?-dir:1;sc=i;[].forEach.call(h.children,function(x){x.removeAttribute('aria-sort')});th.setAttribute('aria-sort',dir>0?'ascending':'descending');
view.sort(function(a,b){var x=key(a[i]),y=key(b[i]);if(x[0]!==y[0])return x[0]-y[0];return x[1]<y[1]?-dir:x[1]>y[1]?dir:0;});draw();}
function draw(){var f=document.createDocumentFragment(),lim=Math.min(view.length,5000);for(var r=0;r<lim;r++){var tr=document.createElement('tr');if(fc>=0&&view[r][fc])tr.className='flag-'+view[r][fc].toLowerCase();for(var c=0;c<cols.length;c++){var td=document.createElement('td');if(c===fc){td.className='sev'+(view[r][c]?' sev-'+view[r][c].toLowerCase():'');if(view[r][c]){var sp=document.createElement('span');sp.textContent=view[r][c];td.appendChild(sp);}tr.appendChild(td);continue;}td.textContent=view[r][c];if(c===wc)td.className='why';else if(nw[c])td.className='nw';if(/^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(view[r][c]))td.className='ts';tr.appendChild(td);}f.appendChild(tr);}
b.textContent='';b.appendChild(f);cnt.textContent=view.length+' of '+rows.length+' rows'+(view.length>lim?' (first '+lim+' shown)':'');}
var q=document.getElementById('q');so.onchange=function(){q.oninput();};q.oninput=function(){var s=q.value.toLowerCase(),only=so.checked&&fc>=0;view=rows.filter(function(r){return (!only||(r[fc]&&r[fc]!=='INFO'))&&(!s||r.join('\u0001').toLowerCase().indexOf(s)>=0);});if(sc>=0){dir=-dir;sort(sc,h.children[sc]);}else draw();};
document.getElementById('copy').onclick=function(){var t=[cols.join('\t')].concat(view.map(function(r){return r.map(function(v){return String(v).replace(/[\t\r\n]+/g,' ')}).join('\t')})).join('\r\n');
if(navigator.clipboard){navigator.clipboard.writeText(t).then(function(){cnt.textContent='Copied '+view.length+' rows';});}};
draw();
})();
</script></body></html>
"@
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
