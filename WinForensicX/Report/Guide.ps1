function New-WfxGuide {
    <#
    .SYNOPSIS Writes a self-contained HTML usage guide (how to use, commands, outputs, limitations, safety),
              in the same "Beacon" look as the report.
    .PARAMETER Path  Output .html path.
    .OUTPUTS The output path.
    #>
    [CmdletBinding()]
    param([string]$Path = (Join-Path ([IO.Path]::GetTempPath()) 'WinForensicX-guide.html'))
    $h = Get-WfxHelpModel
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $cmdHtml = foreach ($c in $h.Commands) {
        $ex = ($c.Examples | ForEach-Object { "<div class='ex mono'>$(& $enc $_)</div>" }) -join ''
        $pr = if (@($c.Params).Count) { "<div class='params mono'>" + ((@($c.Params) | ForEach-Object { & $enc $_ }) -join '<br>') + "</div>" } else { '' }
        @"
<div class="cmd">
  <div class="cmd-h"><span class="cmd-n mono">$(& $enc $c.Name)</span><span class="cmd-s">$(& $enc $c.Summary)</span></div>
  $pr$ex
</div>
"@
    }
    $outRows = ($h.Outputs | ForEach-Object { "<li class='mono'>$(& $enc $_)</li>" }) -join ''
    $limRows = ($h.Limits | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join ''
    $safeRows = ($h.Safety | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join ''

    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WinForensicX $(& $enc $h.Version) · Guide</title>
<style>
$(Get-WfxThemeCss)
.wrap{max-width:900px;margin:0 auto;padding:24px 22px 90px}
.hero{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:26px 28px;box-shadow:var(--sh2);margin-bottom:24px}
.hero .k{font-size:11px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;color:var(--faint);margin-bottom:8px}
.hero h1{font-size:26px;font-weight:800;letter-spacing:-.03em;color:var(--ink2)}
.hero h1 small{font-family:var(--mono);font-size:12px;color:var(--faint);font-weight:400;margin-left:9px}
.hero p{color:var(--dim);max-width:70ch;margin-top:11px;font-size:14.5px}
.sec{display:flex;align-items:center;gap:12px;margin:28px 0 14px}
.sec h2{font-size:14px;font-weight:750;color:var(--ink2)}
.sec::after{content:"";flex:1;height:1px;background:var(--line)}
.cmd{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:15px 17px;margin-bottom:11px;box-shadow:var(--sh)}
.cmd-h{display:flex;flex-wrap:wrap;gap:9px;align-items:baseline;margin-bottom:4px}
.cmd-n{color:var(--acc);font-size:14.5px;font-weight:700}.cmd-s{color:var(--dim);font-size:13.5px}
.params{color:var(--ink);font-size:12.5px;margin:9px 0 2px;padding:8px 11px;border-left:2px solid var(--line2);background:var(--card2);border-radius:7px}
.ex{color:var(--ink2);font-size:12.5px;background:var(--card2);border:1px solid var(--line);border-radius:7px;padding:8px 11px;margin-top:7px;overflow-x:auto}
.ex::before{content:"$ ";color:var(--ok)}
ul.list{list-style:none}
ul.list li{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 13px;margin-bottom:8px;font-size:13.5px;color:var(--ink);box-shadow:var(--sh)}
ul.list.mono-list li{font-family:var(--mono);font-size:12px}
ul.list.warn li{border-left:3px solid var(--high)}
ul.list.safe li{border-left:3px solid var(--ok)}
.req{font-family:var(--mono);font-size:12.5px;color:var(--dim);border:1px dashed var(--line2);border-radius:12px;padding:11px 14px;background:var(--card)}
.foot{margin-top:32px;border-top:1px solid var(--line);padding-top:16px;color:var(--faint);font-size:12.5px}
</style></head><body>
<div class="wrap">
  <div class="bar"><div class="bz">W</div><div class="bn">WinForensicX<span>help &amp; how-to</span></div>
    <div class="sp"></div><div class="chip" id="when"></div>
    <button class="gbtn" id="themebtn" title="Toggle theme">Theme</button></div>

  <div class="hero"><div class="k">Getting started</div>
    <h1>WinForensicX <small>$(& $enc $h.Version) · read-only DFIR triage</small></h1>
    <p>$(& $enc $h.Tagline)</p></div>

  <div class="sec"><h2>Commands</h2></div>$($cmdHtml -join "`n")
  <div class="sec"><h2>What a run produces</h2></div><ul class="list mono-list">$outRows</ul>
  <div class="sec"><h2>Safety &amp; defensive posture</h2></div><ul class="list safe">$safeRows</ul>
  <div class="sec"><h2>Limitations</h2></div><ul class="list warn">$limRows</ul>
  <div class="sec"><h2>Requirements</h2></div><div class="req">$(& $enc $h.Requires)</div>
  <div class="foot">WinForensicX $(& $enc $h.Version) · generated $(Get-Date -Format 'u') · self-contained and safe to share.</div>
</div>
<script>
(function(){try{var s=localStorage.getItem('wfx-theme');if(s)document.documentElement.setAttribute('data-theme',s);}catch(e){}
var t=document.getElementById('themebtn');if(t)t.onclick=function(){var c=document.documentElement.getAttribute('data-theme');
var n=c==='light'?'dark':(c==='dark'?'light':(matchMedia('(prefers-color-scheme:dark)').matches?'light':'dark'));
document.documentElement.setAttribute('data-theme',n);try{localStorage.setItem('wfx-theme',n);}catch(e){}};
var w=document.getElementById('when');if(w)w.textContent=new Date().toLocaleString();})();
</script>
</body></html>
"@
    [IO.File]::WriteAllText($Path, $html, (New-Object Text.UTF8Encoding($false)))
    return $Path
}
