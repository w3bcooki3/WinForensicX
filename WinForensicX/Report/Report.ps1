function New-WfxReport {
    <#
    .SYNOPSIS
        Renders a self-contained (no external assets) HTML triage report from an Invoke-WfxAnalyze result.
        Decision-first "Beacon" design. Embeds only already-redacted findings data — never raw collected
        data or secret values.
    .PARAMETER Result  The result object from Invoke-WfxAnalyze.
    .PARAMETER Path    Output .html path.
    .OUTPUTS The output path.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Path)

    $help = Get-WfxHelpModel
    $data = [ordered]@{
        tool      = "WinForensicX $($script:WfxVersion)"
        version   = [string]$script:WfxVersion
        generated = (Get-Date).ToUniversalTime().ToString('o')
        hostName  = [string](Get-WfxValue $Result 'HostName' '')
        host      = (Get-WfxValue $Result 'Host' $null)
        risk      = (Get-WfxValue $Result 'Risk' $null)
        summary   = (Get-WfxValue $Result 'Summary' $null)
        findings  = @(Get-WfxValue $Result 'Findings' @())
        coverage  = @(Get-WfxValue $Result 'AttackCoverage' @())
        gaps      = @(Get-WfxValue $Result 'Gaps' @())
        meta      = (Get-WfxValue $Result 'Meta' $null)
        limits    = @($help.Limits)
        safety    = @($help.Safety)
    }
    $json = ConvertTo-Json -InputObject $data -Depth 12
    # \uXXXX escapes built from a literal backslash char so they can't collapse to a no-op; JSON.parse
    # restores them, so any "</script>" in a field becomes inert "</script>".
    $bs = [string][char]0x5C
    $json = $json.Replace('&', "${bs}u0026").Replace('<', "${bs}u003c").Replace('>', "${bs}u003e").Replace([string][char]0x2028, "${bs}u2028").Replace([string][char]0x2029, "${bs}u2029")

    $html = $script:WfxReportTemplate
    $html = $html.Replace('/*__WFX_THEME__*/', (Get-WfxThemeCss))
    $html = $html.Replace('/*__WFX_DATA__*/', $json)
    $html = $html.Replace('__WFX_HOST__', [System.Net.WebUtility]::HtmlEncode($data.hostName))

    [IO.File]::WriteAllText($Path, $html, (New-Object Text.UTF8Encoding($false)))
    return $Path
}

$script:WfxReportTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WinForensicX · __WFX_HOST__</title>
<style>
/*__WFX_THEME__*/
.wrap{max-width:1080px;margin:0 auto;padding:24px 22px 90px}
/* hero */
.hero{display:grid;grid-template-columns:230px 1fr;gap:28px;background:var(--card);border:1px solid var(--line);
  border-radius:18px;padding:26px 28px;box-shadow:var(--sh2);margin-bottom:18px}
@media(max-width:760px){.hero{grid-template-columns:1fr;gap:18px}}
.ring{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;border-right:1px solid var(--line);padding-right:12px}
@media(max-width:760px){.ring{border-right:0;border-bottom:1px solid var(--line);padding:0 0 18px}}
.rwrap{position:relative;width:168px;height:168px}
.rwrap .c{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.rwrap .c b{font-size:52px;font-weight:800;letter-spacing:-2px;line-height:1;color:var(--ink2)}
.rwrap .c small{font-size:11px;color:var(--faint);font-weight:600;letter-spacing:.05em}
.rlvl{font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;padding:5px 14px;border-radius:999px}
.hd .k{font-size:11px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;color:var(--faint);margin-bottom:6px}
.hd h1{font-size:23px;font-weight:750;letter-spacing:-.03em;margin-bottom:7px;color:var(--ink2)}
.hd .blurb{color:var(--dim);font-size:14.5px;max-width:64ch;margin-bottom:18px}
.pa .t{font-size:11px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;color:var(--faint);margin-bottom:9px}
.pa .it{display:flex;gap:12px;align-items:flex-start;padding:11px 14px;border:1px solid var(--line);border-radius:12px;background:var(--card2);margin-bottom:8px}
.pa .it .dot{width:9px;height:9px;border-radius:50%;margin-top:6px;flex:none}
.pa .it b{font-size:14px;font-weight:650;display:block;color:var(--ink2)}
.pa .it span{font-size:13px;color:var(--dim)}
/* metrics */
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:16px 0 8px}
@media(max-width:760px){.metrics{grid-template-columns:1fr 1fr}}
.m{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;box-shadow:var(--sh)}
.m .k{font-size:12.5px;color:var(--dim);margin-bottom:10px;font-weight:550}
.m .v{font-size:30px;font-weight:800;letter-spacing:-.03em;line-height:1;color:var(--ink2)}
.m .sb{height:6px;border-radius:4px;background:var(--line);margin-top:13px;overflow:hidden;display:flex}
.m .sb i{height:100%}
.m .leg{display:flex;flex-wrap:wrap;gap:4px 12px;margin-top:11px}
.m .leg span{font-size:12px;color:var(--dim);display:flex;align-items:center;gap:6px}
.m .leg .q{width:8px;height:8px;border-radius:2px}
.m .hint{font-size:12px;color:var(--faint);margin-top:11px}
/* section header + controls */
.sec{display:flex;align-items:center;gap:12px;margin:30px 0 14px;flex-wrap:wrap}
.sec h2{font-size:14px;font-weight:750;letter-spacing:.01em;color:var(--ink2)}
.sec .ct{font-size:12.5px;color:var(--faint);font-weight:600}
.sec .sp{flex:1}
.ctrls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.ctrls input,.ctrls select{font-size:13px;background:var(--card);border:1px solid var(--line2);color:var(--ink);
  border-radius:9px;padding:8px 11px;box-shadow:var(--sh)}
.ctrls input{min-width:180px}.ctrls input:focus,.ctrls select:focus{outline:none;border-color:var(--acc)}
.filters{display:flex;gap:8px;flex-wrap:wrap}
.ff{font-size:12.5px;font-weight:600;color:var(--dim);background:var(--card);border:1px solid var(--line2);
  border-radius:999px;padding:6px 13px;cursor:pointer;display:flex;align-items:center;gap:7px;box-shadow:var(--sh)}
.ff .d{width:8px;height:8px;border-radius:50%}
/* findings */
.flist{display:flex;flex-direction:column;gap:10px}
.f{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh);overflow:hidden;transition:box-shadow .12s,transform .12s}
.f:hover{box-shadow:var(--sh2);transform:translateY(-1px)}
.f.open{transform:none}
.fhead{display:grid;grid-template-columns:96px 1fr auto;gap:18px;align-items:center;padding:16px 18px;cursor:pointer}
.fhead .pill{font-size:11px;font-weight:800;letter-spacing:.05em;padding:5px 0;border-radius:8px;text-align:center;color:#fff}
.fhead .ti{font-size:15.5px;font-weight:650;letter-spacing:-.01em;color:var(--ink2)}
.fhead .wy{font-size:13.5px;color:var(--dim);margin-top:3px}
.fhead .tags{margin-top:9px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.fhead .tags .cat{font-size:11px;color:var(--faint);font-weight:600}
.fhead .tags a{font-family:var(--mono);font-size:11px;color:var(--acc);background:var(--acc2);border-radius:6px;padding:2px 8px;text-decoration:none}
.fhead .rt{text-align:right;white-space:nowrap}
.fhead .rt .sc{font-size:22px;font-weight:800;letter-spacing:-1px}
.fhead .rt .id{font-family:var(--mono);font-size:10.5px;color:var(--faint);margin-top:2px}
.fbody{display:none;padding:2px 18px 18px;border-top:1px solid var(--line)}
.f.open .fbody{display:block}
.fbody p{margin:14px 0;color:var(--ink);max-width:80ch;font-size:14px}
.fbody .ent{font-family:var(--mono);font-size:11.5px;color:var(--faint)}
.kv{width:100%;border-collapse:collapse;margin:12px 0;font-family:var(--mono);font-size:12px}
.kv td{border:1px solid var(--line);padding:7px 10px;vertical-align:top}
.kv td.k{color:var(--dim);white-space:nowrap;width:160px;background:var(--card2)}
.kv td.v{color:var(--ink);word-break:break-word}
.rec{border:1px solid var(--line);border-left:3px solid var(--ok);border-radius:11px;background:var(--card2);padding:12px 15px;margin-top:12px;font-size:14px}
.rec .k{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--ok);font-weight:800;display:block;margin-bottom:4px}
.empty{color:var(--dim);padding:22px;text-align:center;border:1px dashed var(--line2);border-radius:var(--r);background:var(--card)}
/* attack + timeline + notes */
.attack{display:flex;flex-wrap:wrap;gap:9px}
.at{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:11px 14px;box-shadow:var(--sh);min-width:150px}
.at h4{font-size:12px;font-weight:700;color:var(--ink2);margin-bottom:8px}
.at a{display:block;font-family:var(--mono);font-size:11px;color:var(--dim);padding:2px 0;text-decoration:none}
.at a:hover{color:var(--acc)}.at a b{color:var(--acc);font-weight:600}
.tl{border-left:2px solid var(--line);margin-left:7px;padding-left:18px}
.tl .ev{position:relative;padding:4px 0 14px}
.tl .ev::before{content:"";position:absolute;left:-25px;top:6px;width:11px;height:11px;border-radius:50%;border:2px solid var(--bg)}
.tl time{font-family:var(--mono);font-size:12px;color:var(--faint);margin-right:10px}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:700px){.cards{grid-template-columns:1fr}}
.note{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 15px;box-shadow:var(--sh);font-size:13.5px;color:var(--ink);display:flex;gap:11px}
.note .n{font-family:var(--mono);font-weight:800;color:var(--acc);flex:none}
.gap{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--high);border-radius:12px;padding:11px 14px;margin-bottom:8px;box-shadow:var(--sh);font-size:13.5px}
.gap b{color:var(--high);font-family:var(--mono);font-size:12.5px}
.gap .fix{color:var(--dim);font-size:12.5px;margin-top:3px}
.foot{margin-top:34px;color:var(--faint);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
</style>
</head>
<body>
<div class="wrap">
  <div class="bar">
    <div class="bz">W</div><div class="bn">WinForensicX<span>incident triage</span></div>
    <div class="sp"></div>
    <div class="chip">Host <b id="host"></b></div>
    <div class="chip" id="when"></div>
    <button class="gbtn" id="themebtn" title="Toggle theme (t)">Theme</button>
  </div>

  <div class="hero">
    <div class="ring">
      <div class="rwrap"><svg viewBox="0 0 168 168" width="168" height="168">
        <circle cx="84" cy="84" r="72" fill="none" stroke="var(--line)" stroke-width="14"></circle>
        <circle id="ring" cx="84" cy="84" r="72" fill="none" stroke-width="14" stroke-linecap="round" transform="rotate(-90 84 84)"></circle>
      </svg><div class="c"><b id="rn">0</b><small>RISK / 100</small></div></div>
      <div class="rlvl" id="lvl">&mdash;</div>
    </div>
    <div class="hd">
      <div class="k">Executive summary</div>
      <h1 id="verdict">&mdash;</h1>
      <div class="blurb" id="blurb"></div>
      <div class="pa"><div class="t">Priority actions</div><div id="actions"></div></div>
    </div>
  </div>

  <div class="metrics">
    <div class="m"><div class="k">Total findings</div><div class="v" id="tf">0</div><div class="sb" id="sb"></div><div class="leg" id="leg"></div></div>
    <div class="m"><div class="k">Critical &amp; High</div><div class="v fg-Critical" id="tch">0</div><div class="hint">act on these first</div></div>
    <div class="m"><div class="k">ATT&amp;CK techniques</div><div class="v" id="tt">0</div><div class="hint">adversary behaviors seen</div></div>
    <div class="m"><div class="k">Visibility gaps</div><div class="v fg-High" id="tg">0</div><div class="hint">areas the tool couldn't see</div></div>
  </div>

  <div class="sec" id="findings">
    <h2>Findings</h2><span class="ct" id="fct"></span><span class="sp"></span>
    <div class="ctrls">
      <input id="q" placeholder="Search findings…" autocomplete="off" spellcheck="false">
      <select id="sort"><option value="sev">Severity</option><option value="score">Score</option><option value="cat">Category</option></select>
    </div>
  </div>
  <div class="filters" id="filters" style="margin-bottom:14px"></div>
  <div class="flist" id="list"></div>

  <div class="sec" id="attack"><h2>ATT&amp;CK coverage</h2></div>
  <div class="attack" id="matrix"></div>

  <div class="sec" id="timeline"><h2>Timeline</h2></div>
  <div id="tlwrap"></div>

  <div class="sec" id="limits"><h2>Limitations &amp; how to read this</h2></div>
  <div class="cards" id="limwrap"></div>

  <div class="sec" id="gaps"><h2>Collection gaps</h2></div>
  <div id="gapwrap"></div>

  <div class="foot" id="foot"></div>
</div>

<script id="wfx-data" type="application/json">/*__WFX_DATA__*/</script>
<script>
(function(){
  "use strict";
  var D; try{ D=JSON.parse(document.getElementById('wfx-data').textContent); }
  catch(e){ document.body.innerHTML='<p style="padding:24px">Could not load report data.</p>'; return; }
  var SEV=['Critical','High','Medium','Low','Info'], RK={Critical:0,High:1,Medium:2,Low:3,Info:4};
  var el=function(id){return document.getElementById(id);};
  var esc=function(s){var d=document.createElement('div');d.textContent=(s==null?'':String(s));return d.innerHTML;};
  var au=function(id){return 'https://attack.mitre.org/techniques/'+String(id).replace('.','/')+'/';};
  var why=function(f){var d=(f.Description||'').trim();if(d.length>135)d=d.slice(0,132).replace(/\s+\S*$/,'')+'…';return d;};
  var F=(D.findings||[]).slice();
  var COL={Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--info)'};

  // theme
  try{var sv=localStorage.getItem('wfx-theme');if(sv)document.documentElement.setAttribute('data-theme',sv);}catch(e){}
  el('themebtn').onclick=function(){var cur=document.documentElement.getAttribute('data-theme');
    var nx=cur==='light'?'dark':(cur==='dark'?'light':(matchMedia('(prefers-color-scheme:dark)').matches?'light':'dark'));
    document.documentElement.setAttribute('data-theme',nx);try{localStorage.setItem('wfx-theme',nx);}catch(e){} };

  // header + hero
  el('host').textContent=D.hostName||'(unknown)';
  el('when').textContent=new Date(D.generated).toLocaleString();
  var risk=D.risk||{Score:0,Level:'Low'};
  var vc={Critical:'var(--crit)',High:'var(--high)',Elevated:'var(--med)',Low:'var(--ok)'}[risk.Level]||'var(--ok)';
  el('rn').textContent=risk.Score;
  var ring=el('ring'),C=2*Math.PI*72;ring.style.stroke=vc;ring.style.strokeDasharray=C;ring.style.strokeDashoffset=C*(1-risk.Score/100);
  var lvl=el('lvl');lvl.textContent=risk.Level;lvl.style.color=vc;lvl.style.background='color-mix(in srgb,'+vc+' 15%,transparent)';
  var ch=F.filter(function(f){return f.Severity==='Critical'||f.Severity==='High';}).length;
  el('verdict').textContent=(risk.Level==='Critical'||risk.Level==='High')?'Immediate investigation recommended':(risk.Level==='Elevated'?'Review advised':'No urgent action — monitor');
  el('blurb').textContent='Host '+(D.hostName||'this host')+' scored '+risk.Score+'/100 with '+ch+' high-severity indicator'+(ch===1?'':'s')+' across credential exposure, process tradecraft, network C2 and security posture. Findings are leads for an analyst — confirm before acting, and read them alongside the visibility gaps below.';
  var byScore=F.slice().sort(function(a,b){return RK[a.Severity]-RK[b.Severity]||b.Score-a.Score;});
  el('actions').innerHTML=byScore.slice(0,3).map(function(f){return '<div class="it"><span class="dot" style="background:'+COL[f.Severity]+'"></span><div><b>'+esc(f.Title)+'</b><span>'+esc((f.Recommendation||'').split('. ')[0].replace(/\.$/,''))+'.</span></div></div>';}).join('')||'<div class="empty">No priority actions.</div>';

  // metrics
  var s=D.summary||{},tot=SEV.reduce(function(a,x){return a+(s[x]||0);},0);
  el('tf').textContent=F.length;
  el('sb').innerHTML=SEV.map(function(x){return '<i class="bg-'+x+'" style="width:'+(tot?(s[x]||0)/tot*100:0)+'%"></i>';}).join('');
  el('leg').innerHTML=SEV.filter(function(x){return s[x];}).map(function(x){return '<span><span class="q bg-'+x+'"></span>'+x+' '+s[x]+'</span>';}).join('');
  el('tch').textContent=ch; el('tt').textContent=(D.coverage||[]).length; el('tg').textContent=(D.gaps||[]).length;

  // filters + search + sort + expandable list
  var active='all', q='', sort='sev';
  var counts={}; SEV.forEach(function(x){counts[x]=s[x]||0;});
  var filt=el('filters');
  filt.innerHTML='<button class="ff" data-k="all">All '+F.length+'</button>'+SEV.filter(function(x){return counts[x];}).map(function(x){return '<button class="ff" data-k="'+x+'"><span class="d bg-'+x+'"></span>'+x+' '+counts[x]+'</button>';}).join('');
  function paintFilters(){Array.prototype.forEach.call(filt.children,function(b){var on=b.dataset.k===active;
    b.style.background=on?(b.dataset.k==='all'?'var(--ink)':COL[b.dataset.k]):'';b.style.color=on?'#fff':'';b.style.borderColor=on?'transparent':'';b.style.fontWeight=on?'700':'';});}
  function evidence(ev){
    if(ev==null)return '';
    if(typeof ev!=='object')return '<table class="kv"><tr><td class="k">evidence</td><td class="v">'+esc(ev)+'</td></tr></table>';
    var rows='';Object.keys(ev).forEach(function(k){var v=ev[k];
      if(Array.isArray(v))v=v.length?v.map(function(x){return (x&&typeof x==='object')?esc(JSON.stringify(x)):esc(x);}).join('<br>'):'&mdash;';
      else if(v&&typeof v==='object')v=esc(JSON.stringify(v));else v=esc(v);
      rows+='<tr><td class="k">'+esc(k)+'</td><td class="v">'+v+'</td></tr>';});
    return '<table class="kv">'+rows+'</table>';}
  function card(f){
    var tech=(f.Technique||[]).map(function(t){return '<a href="'+au(t)+'" target="_blank" rel="noopener">'+esc(t)+'</a>';}).join('');
    var occ=(f.Occurrences&&f.Occurrences>1)?('  ×'+f.Occurrences):'';
    var d=document.createElement('div');d.className='f';
    d.innerHTML='<div class="fhead"><div class="pill bg-'+f.Severity+'">'+f.Severity.toUpperCase()+'</div>'+
      '<div class="mid"><div class="ti">'+esc(f.Title)+'</div><div class="wy">'+esc(why(f))+'</div>'+
        '<div class="tags"><span class="cat">'+esc(f.Category)+'</span>'+tech+'</div></div>'+
      '<div class="rt"><div class="sc fg-'+f.Severity+'">'+f.Score+occ+'</div><div class="id">'+esc(f.Id)+'</div></div></div>'+
      '<div class="fbody"><p>'+esc(f.Description)+'</p>'+
        (f.Entity?'<div class="ent">entity: '+esc(f.Entity)+(f.Host?'  ·  host: '+esc(f.Host):'')+(f.Time?'  ·  '+esc(new Date(f.Time).toLocaleString()):'')+'</div>':'')+
        evidence(f.Evidence)+
        (f.Recommendation?'<div class="rec"><span class="k">Recommended</span>'+esc(f.Recommendation)+'</div>':'')+'</div>';
    d.querySelector('.fhead').onclick=function(){d.classList.toggle('open');};
    return d;}
  function render(){
    var rows=F.filter(function(f){
      if(active!=='all'&&f.Severity!==active)return false;
      if(q){var h=(f.Title+' '+f.Id+' '+f.Entity+' '+(f.Technique||[]).join(' ')+' '+JSON.stringify(f.Evidence||'')+' '+f.Category+' '+f.Description).toLowerCase();if(h.indexOf(q)<0)return false;}
      return true;});
    rows.sort(function(a,b){if(sort==='score')return b.Score-a.Score;
      if(sort==='cat')return (a.Category||'').localeCompare(b.Category||'')||(RK[a.Severity]-RK[b.Severity]);
      return (RK[a.Severity]-RK[b.Severity])||(b.Score-a.Score);});
    el('fct').textContent='· '+rows.length+' of '+F.length;
    var list=el('list');list.innerHTML='';
    if(!rows.length){list.innerHTML='<div class="empty">No findings match the current filters.</div>';return;}
    rows.forEach(function(f){list.appendChild(card(f));});}
  filt.addEventListener('click',function(e){var b=e.target.closest('.ff');if(!b)return;active=b.dataset.k;paintFilters();render();});
  el('q').oninput=function(){q=this.value.toLowerCase();render();};
  el('sort').onchange=function(){sort=this.value;render();};
  paintFilters();render();

  // keyboard
  document.addEventListener('keydown',function(e){
    if(e.target.tagName==='INPUT'||e.target.tagName==='SELECT'){if(e.key==='Escape')e.target.blur();return;}
    if(e.key==='/'){e.preventDefault();el('q').focus();return;}
    if(e.key==='t'){el('themebtn').click();return;}
    if(e.key>='1'&&e.key<='5'){var sev=SEV[+e.key-1];active=(active===sev?'all':sev);paintFilters();render();return;}
    if(e.key==='e'){Array.prototype.forEach.call(el('list').children,function(c){c.classList&&c.classList.add('open');});return;}
    if(e.key==='c'){Array.prototype.forEach.call(el('list').children,function(c){c.classList&&c.classList.remove('open');});return;}
  });

  // ATT&CK
  var bt={};(D.coverage||[]).forEach(function(t){var k=t.Tactic||'Other';(bt[k]=bt[k]||[]).push(t);});
  var tk=Object.keys(bt).sort(),mx=el('matrix');
  mx.innerHTML=tk.length?tk.map(function(k){return '<div class="at"><h4>'+esc(k)+'</h4>'+bt[k].map(function(t){return '<a href="'+au(t.Id)+'" target="_blank" rel="noopener"><b>'+esc(t.Id)+'</b> '+esc(t.Name||'')+'</a>';}).join('')+'</div>';}).join(''):'<div class="empty">No techniques observed.</div>';

  // timeline
  var timed=F.filter(function(f){return f.Time;}).sort(function(a,b){return new Date(a.Time)-new Date(b.Time);});
  el('tlwrap').innerHTML=timed.length?'<div class="tl">'+timed.map(function(f){return '<div class="ev"><span class="bg-'+f.Severity+'" style="position:absolute;left:-25px;top:6px;width:11px;height:11px;border-radius:50%;border:2px solid var(--bg)"></span><time>'+esc(new Date(f.Time).toLocaleString())+'</time><span class="fg-'+f.Severity+'" style="font-weight:600">'+esc(f.Title)+'</span></div>';}).join('')+'</div>':'<div class="empty">No time-stamped findings.</div>';

  // limitations
  el('limwrap').innerHTML=(D.limits||[]).map(function(x,i){return '<div class="note"><span class="n">'+String(i+1).padStart(2,'0')+'</span><div>'+esc(x)+'</div></div>';}).join('')||'<div class="empty">&mdash;</div>';

  // gaps
  var g=D.gaps||[];
  el('gapwrap').innerHTML=g.length?g.map(function(x){return '<div class="gap"><b>'+esc(x.Source)+'</b> &mdash; '+esc(x.Reason)+(x.Fix?'<div class="fix">fix: '+esc(x.Fix)+'</div>':'')+'</div>';}).join(''):'<div class="note"><span class="n">ok</span><div>No collection gaps recorded — the triage ran with the visibility it attempted.</div></div>';

  el('foot').innerHTML=esc(D.tool)+' · generated '+new Date(D.generated).toLocaleString()+' · read-only, self-contained. Risk = 1 − Π(1 − wᵢ/40): many low-confidence leads cannot sum to a critical. Keys: <kbd>/</kbd> search · <kbd>1</kbd>–<kbd>5</kbd> filter · <kbd>e</kbd>/<kbd>c</kbd> expand · <kbd>t</kbd> theme.';
})();
</script>
</body>
</html>
'@
