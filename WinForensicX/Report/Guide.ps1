function New-WfxGuide {
    <#
    .SYNOPSIS Writes a self-contained HTML usage guide (how to use, commands, outputs, limitations, safety),
              in the same look as the case report.
    .PARAMETER Path  Output .html path.
    .OUTPUTS The output path.
    #>
    [CmdletBinding()]
    param([string]$Path = (Join-Path ([IO.Path]::GetTempPath()) 'WinForensicX-guide.html'))
    $h = Get-WfxHelpModel
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $cmdHtml = foreach ($c in $h.Commands) {
        $ex = if (@($c.Examples).Count) { "<pre class='ex'>" + ((@($c.Examples) | ForEach-Object { & $enc $_ }) -join "`n") + "</pre>" } else { '' }
        $pr = if (@($c.Params).Count) { "<ul class='params'>" + ((@($c.Params) | ForEach-Object { "<li class='mono'>$(& $enc $_)</li>" }) -join '') + "</ul>" } else { '' }
        @"
<div class="cmd">
  <h3 class="mono">$(& $enc $c.Name)</h3><p>$(& $enc $c.Summary)</p>
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
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>WinForensicX $(& $enc $h.Version) help</title>
<style>
$(Get-WfxThemeCss)
.wrap{max-width:960px;margin:0 auto;padding:8px 24px 80px}
h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.cmd{padding:14px 0 16px;border-bottom:1px solid var(--line2)}
.cmd h3{font-size:14.5px;color:var(--ink)}
.cmd p{margin:4px 0 8px;color:var(--ink2)}
ul.params{margin:0 0 8px;padding-left:18px;color:var(--ink2)}
ul.params li{margin:2px 0}
pre.ex{font:12.5px/1.5 var(--mono);background:var(--alt);border:1px solid var(--line2);padding:8px 11px;margin:6px 0 0;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere}
ul.list{margin:0;padding-left:20px}
ul.list li{margin:6px 0}
.req{font-family:var(--mono);font-size:12.5px;color:var(--ink2);border:1px solid var(--line);background:var(--alt);padding:10px 13px}
.foot{margin-top:36px;border-top:1px solid var(--line);padding-top:14px;color:var(--ink3);font-size:12.5px}
@media (max-width:640px){.mast .in,.wrap{padding-left:16px;padding-right:16px}.mast h1{font-size:24px}}
</style></head><body>
<header class="mast"><div class="in">
  <div class="brandrow">$(Get-WfxMarkSvg)<b>WinForensicX</b><span>Help</span><span class="tools"><button class="mbtn" id="themebtn" type="button">Dark</button></span></div>
  <h1>WinForensicX $(& $enc $h.Version)</h1>
  <p>$(& $enc $h.Tagline)</p>
</div></header>
<main class="wrap">
  <h2>Commands</h2>$($cmdHtml -join "`n")
  <h2>What a run produces</h2><ul class="list">$outRows</ul>
  <h2>Safety</h2><ul class="list">$safeRows</ul>
  <h2>Limitations</h2><ul class="list">$limRows</ul>
  <h2>Requirements</h2><div class="req">$(& $enc $h.Requires)</div>
  <div class="foot">WinForensicX $(& $enc $h.Version). Generated $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC. Self-contained and offline.</div>
</main>
<script>
(function(){var r=document.documentElement,b=document.getElementById('themebtn');
function lbl(){var c=r.getAttribute('data-theme');var d=c?c==='dark':matchMedia('(prefers-color-scheme: dark)').matches;b.textContent=d?'Light':'Dark';}
try{var s=localStorage.getItem('wfx-theme');if(s==='dark'||s==='light')r.setAttribute('data-theme',s);}catch(e){}
lbl();b.onclick=function(){var n=b.textContent==='Dark'?'dark':'light';r.setAttribute('data-theme',n);try{localStorage.setItem('wfx-theme',n);}catch(e){}lbl();};})();
</script>
</body></html>
"@
    [IO.File]::WriteAllText($Path, $html, (New-Object Text.UTF8Encoding($false)))
    return $Path
}
