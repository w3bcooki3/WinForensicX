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
        # PowerShell 7 turns ISO time strings into DateTime while reading JSON; put them back in the one
        # UTC string form the rest of the report compares and sorts as text.
        $ut = { param($o, [string[]]$Names) foreach ($x in @($o)) { if (-not $x) { continue }; foreach ($n in $Names) { if ($x.PSObject.Properties[$n] -and $x.$n -is [datetime]) { $x.$n = ConvertTo-WfxUtcString $x.$n } } } }
        & $ut $r 'Collected'
        & $ut @($r.Findings) 'Time'
        if ($r.PSObject.Properties['Programs']) { & $ut @($r.Programs) 'Last' }
        if ($r.PSObject.Properties['Logons']) { & $ut @($r.Logons) 'First', 'Last' }
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
    $rare = Get-WfxFleetRarity -Case $cases
    $move = Get-WfxFleetMovement -Case $cases
    $data = [ordered]@{ tool = "WinForensicX $script:WfxVersion"; generated = (Get-WfxUtcNow); hosts = $hosts.ToArray(); shared = $shared; common = $common
        rare = $rare.Items; rareTotal = $rare.Total; rareHosts = $rare.Hosts; moves = $move.Edges; outside = $move.Outside }
    $json = ConvertTo-Json -InputObject $data -Depth 10
    $bs = [string][char]0x5C
    $json = $json.Replace('&', "${bs}u0026").Replace('<', "${bs}u003c").Replace('>', "${bs}u003e").Replace([string][char]0x2028, "${bs}u2028").Replace([string][char]0x2029, "${bs}u2029")
    if (-not $OutputPath) { $OutputPath = Join-Path $Path[0] ("fleet-report_{0}.html" -f (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')) }
    [IO.File]::WriteAllText($OutputPath, $script:WfxFleetTemplate.Replace('/*__WFX_DATA__*/', $json), (New-Object Text.UTF8Encoding($false)))
    Write-WfxConsole ("Fleet report: {0} host(s), {1} shared indicator(s), {2} movement link(s) between hosts. Written to {3}" -f $hosts.Count, $shared.Count, @($move.Edges).Count, $OutputPath) -Kind Info
    if ($PassThru) { $OutputPath }
}

function Get-WfxFleetRarity {
    <#
    Programs recorded on exactly one host, when at least three hosts have program lists. Paths are compared
    without drive, user name or version folders. Listed first: programs named by that host's findings, then
    programs in folders any user can write to.
    #>
    param([object[]]$Case, [int]$Max = 150)
    $with = @($Case | Where-Object { $_.R.PSObject.Properties['Programs'] -and @($_.R.Programs).Count })
    if ($with.Count -lt 3) { return [pscustomobject]@{ Items = @(); Total = 0; Hosts = $with.Count } }
    $seen = @{}
    foreach ($c in $with) { foreach ($k in @($c.R.Programs | ForEach-Object { [string]$_.Key } | Where-Object { $_ } | Sort-Object -Unique)) { $seen[$k] = 1 + [int]$seen[$k] } }
    $userRx = '\\users\\|\\programdata\\|\\temp\\|\\tmp\\|\\appdata\\|\\perflogs\\|\\\$recycle\.bin\\|\\windows\\tasks\\|\\public\\|\\downloads\\'
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($c in $with) {
        $text = (@($c.R.Findings | Where-Object { $_ } | ForEach-Object { "$($_.Title) $($_.Entity) $(try { ConvertTo-Json -InputObject $_.Evidence -Depth 4 -Compress } catch { '' })" }) -join "`n").ToLowerInvariant()
        $done = @{}
        foreach ($p in @($c.R.Programs)) {
            $k = [string]$p.Key
            if (-not $k -or $seen[$k] -ne 1 -or $done[$k]) { continue }
            $done[$k] = 1
            $leaf = ($k -split '\\')[-1]
            $named = $leaf.Length -ge 5 -and $text.Contains($leaf)
            $user = $k -match $userRx
            $why = @(); if ($named) { $why += 'named in a finding' }; if ($user) { $why += 'user-writable folder' }
            $items.Add([pscustomobject]@{ Host = $c.Host; Path = [string]$p.Path; Sources = [string]$p.Sources; Last = [string]$p.Last; Why = ($why -join ', '); Rank = $(if ($named) { 0 } elseif ($user) { 1 } else { 2 }) })
        }
    }
    $sorted = @($items | Sort-Object Rank, Host, Path)
    [pscustomobject]@{ Items = @($sorted | Select-Object -First $Max | ForEach-Object { [ordered]@{ Host = $_.Host; Path = $_.Path; Sources = $_.Sources; Last = $_.Last; Why = $_.Why } }); Total = $sorted.Count; Hosts = $with.Count }
}

function Get-WfxFleetMovement {
    <#
    Links between triaged hosts from each host's own records: remote logons in (4624 type 3 and 10, by source
    address or workstation name), explicit-credential logons out (4648) and SMB, RDP, WinRM, RPC or SSH
    connections out (Sysmon 3). Peers are matched to hosts by name or by the addresses each host recorded for
    itself. Peers that match no triaged host are listed separately, as places to collect from next.
    #>
    param([object[]]$Case, [int]$Max = 500)
    $id = @{}
    foreach ($c in $Case) {
        $n = $c.Host.ToUpperInvariant(); $id[$n] = $c.Host; $id[($n -split '\.')[0]] = $c.Host
    }
    # Addresses second, and only those that belong to one host: copies of a lab image, NAT or VPN pools can
    # give several hosts the same address, and such a match would link the wrong machines.
    $addrHosts = @{}
    foreach ($c in $Case) { foreach ($a in @($c.R.Addresses)) { if ($a) { $u = ([string]$a).ToUpperInvariant(); if (-not $addrHosts[$u]) { $addrHosts[$u] = @{} }; $addrHosts[$u][$c.Host] = 1 } } }
    foreach ($u in $addrHosts.Keys) { if ($addrHosts[$u].Count -eq 1 -and -not $id.ContainsKey($u)) { $id[$u] = @($addrHosts[$u].Keys)[0] } }
    $resolve = {
        param($Peer, $Name)
        foreach ($v in @([string]$Name, [string]$Peer)) {
            if (-not $v) { continue }
            $u = $v.Trim().TrimStart('\').ToUpperInvariant() -replace '^::FFFF:', ''
            if ($id.ContainsKey($u)) { return $id[$u] }
            $s = ($u -split '\.')[0]; if ($u -notmatch '^\d+\.\d+\.\d+\.\d+$' -and $id.ContainsKey($s)) { return $id[$s] }
        }
        $null
    }
    $edges = @{}; $out = @{}
    foreach ($c in $Case) {
        if (-not $c.R.PSObject.Properties['Logons']) { continue }
        foreach ($l in @($c.R.Logons)) {
            if (-not $l) { continue }
            $other = & $resolve $l.Peer $l.PeerName
            if ($other -eq $c.Host) { continue }
            $label = (@([string]$l.PeerName, [string]$l.Peer) | Where-Object { $_ -and $_ -ne '-' } | Select-Object -Unique) -join ' '
            if (-not $other) {
                $k = $label.ToLowerInvariant()
                if (-not $out[$k]) { $out[$k] = [pscustomobject]@{ Peer = $label; Hosts = New-Object System.Collections.Generic.List[string]; How = New-Object System.Collections.Generic.List[string]; Count = 0; First = ''; Last = '' } }
                $o = $out[$k]
                $h = "$($c.Host) ($(if ($l.Direction -eq 'In') { 'in' } else { 'out' }))"; if (-not $o.Hosts.Contains($h)) { $o.Hosts.Add($h) }
                if (-not $o.How.Contains([string]$l.Kind)) { $o.How.Add([string]$l.Kind) }
                $o.Count += [int]$l.Count
                if ($l.First -and (-not $o.First -or [string]$l.First -lt $o.First)) { $o.First = [string]$l.First }
                if ($l.Last -and [string]$l.Last -gt $o.Last) { $o.Last = [string]$l.Last }
                continue
            }
            $from = if ($l.Direction -eq 'In') { $other } else { $c.Host }; $to = if ($l.Direction -eq 'In') { $c.Host } else { $other }
            $how = ([string]$l.Kind) -replace ' (logon|connection)$', ''
            $k = "$from|$to|$how".ToLowerInvariant()
            if (-not $edges[$k]) { $edges[$k] = [pscustomobject]@{ From = $from; To = $to; How = $how; Accounts = New-Object System.Collections.Generic.List[string]; Recorded = New-Object System.Collections.Generic.List[string]; Count = 0; First = ''; Last = '' } }
            $e = $edges[$k]
            if ($l.Account -and -not $e.Accounts.Contains([string]$l.Account)) { $e.Accounts.Add([string]$l.Account) }
            if (-not $e.Recorded.Contains($c.Host)) { $e.Recorded.Add($c.Host) }
            $e.Count += [int]$l.Count
            if ($l.First -and (-not $e.First -or [string]$l.First -lt $e.First)) { $e.First = [string]$l.First }
            if ($l.Last -and [string]$l.Last -gt $e.Last) { $e.Last = [string]$l.Last }
        }
    }
    [pscustomobject]@{
        Edges   = @($edges.Values | Sort-Object First, From, To | Select-Object -First $Max | ForEach-Object { [ordered]@{ From = $_.From; To = $_.To; How = $_.How; Accounts = @($_.Accounts | Select-Object -First 10); Recorded = @($_.Recorded); Count = $_.Count; First = $_.First; Last = $_.Last } })
        Outside = @($out.Values | Sort-Object @{ e = { -$_.Hosts.Count } }, @{ e = { -$_.Count } }, Peer | Select-Object -First 100 | ForEach-Object { [ordered]@{ Peer = $_.Peer; Hosts = @($_.Hosts); How = @($_.How); Count = $_.Count; First = $_.First; Last = $_.Last } })
    }
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
:root{--bg:#FFFFFF;--bg2:#F5F6F8;--bg3:#ECEEF1;--ink:#17202C;--ink2:#4E5967;--ink3:#7B8591;--line:#D3D8DE;--line2:#E6E9ED;--link:#0B57A4;
  --band:#14233A;--band-ink:#F1F4F8;--band-dim:#A9B6C6;
  --crit:#9B1C1C;--high:#C2410C;--med:#A16207;--low:#2B6CB0;--info:#6B7280;--mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace;--sans:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#14181D;--bg2:#1A1F25;--bg3:#222830;--ink:#E3E7EC;--ink2:#A4AEBA;--ink3:#7D8793;--line:#333B45;--line2:#262D35;--link:#7CB1EC;--band:#0D141D;--crit:#F07171;--high:#F59056;--med:#E2B04A;--low:#7FB0E6;--info:#9AA3AE}}
*{box-sizing:border-box}
*,*::before,*::after{font-variant-ligatures:none!important;font-feature-settings:"calt" 0,"liga" 0,"clig" 0!important}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans);font-variant-numeric:tabular-nums}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--link);outline-offset:2px}
h1,h2,h3{margin:0;font-weight:600}h3{font-size:15px;margin-top:22px}h1{font-size:30px;line-height:1.15;letter-spacing:-.01em}h2{font-size:20px;margin-bottom:4px}
.wrap{max-width:1280px;margin:0 auto;padding:0 28px}
.mast{background:var(--band);color:var(--band-ink)}.mast .wrap{padding-top:16px;padding-bottom:26px}
.brandrow{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--band-dim)}.brandrow svg{width:22px;height:22px;color:var(--band-ink)}.brandrow b{color:var(--band-ink);font-weight:600;font-size:14px}
.mast h1{margin-top:26px}.mast .sub{color:var(--band-dim);margin-top:8px;display:flex;flex-wrap:wrap;gap:4px 24px;font-size:13px}.mast .sub b{color:var(--band-ink);font-weight:500}
.bar{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
.bar .wrap{display:flex;align-items:center;gap:16px}
.nav{display:flex;overflow-x:auto;flex:1;scrollbar-width:none}.nav a{color:var(--ink2);padding:12px 10px 11px;white-space:nowrap;font-size:13.5px}.nav a:first-child{padding-left:0}
.btn{font:inherit;font-size:13px;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:3px;padding:4px 10px;cursor:pointer}.btn:hover{background:var(--bg2)}
section{padding:34px 0 8px;border-bottom:1px solid var(--line2);scroll-margin-top:44px}
.desc{color:var(--ink2);max-width:80ch;margin:4px 0 14px}
.head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:12px}.head .desc{margin:0}
.tbl{width:100%;overflow-x:auto;border:1px solid var(--line)}
table{border-collapse:collapse;width:100%}
th{font-weight:600;font-size:12.5px;color:var(--ink2);text-align:left;padding:7px 12px;background:var(--bg2);border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:7px 12px;border-bottom:1px solid var(--line2);vertical-align:top}tr:last-child>td{border-bottom:0}
td.t,td.nw{white-space:nowrap}td.t{color:var(--ink2)}td.m{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}td.num{text-align:right}
.sq{display:inline-block;width:8px;height:8px;background:currentColor;flex:none}
.sev{display:inline-flex;align-items:center;gap:6px;white-space:nowrap;font-weight:600;font-size:13px}
.sev.Critical{color:var(--crit)}.sev.Critical .sq{transform:rotate(45deg)}.sev.High{color:var(--high)}.sev.High .sq{width:9px;clip-path:polygon(50% 0,100% 100%,0 100%)}.sev.Medium,.sev.Elevated{color:var(--med)}.sev.Low{color:var(--low)}.sev.Low .sq{border-radius:50%}.sev.Info{color:var(--info)}.sev.Info .sq{border-radius:50%;background:none;border:1.5px solid currentColor}
.small{font-size:12.5px;color:var(--ink2)}.muted{color:var(--ink3)}.m{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
.meter{display:inline-block;width:70px;height:6px;background:var(--bg3);vertical-align:middle;margin-left:8px;position:relative}.meter i{position:absolute;left:0;top:0;bottom:0;background:var(--ink2)}
.cells{display:flex;gap:2px}.cells i{display:block;width:16px;height:16px;background:var(--bg3)}.cells i.on1{background:var(--med)}.cells i.on2{background:var(--high)}.cells i.on3{background:var(--crit)}
.legend{display:flex;flex-wrap:wrap;gap:4px 16px;color:var(--ink2);font-size:12.5px;margin:8px 0}
.empty{color:var(--ink2);padding:14px;border:1px solid var(--line2);background:var(--bg2)}
footer{color:var(--ink3);font-size:12.5px;padding:24px 0 40px}
@media (max-width:640px){.wrap{padding:0 16px}.mast h1{font-size:24px}}
@media print{.bar,.btn{display:none}.tbl{overflow:visible;border:0}.mast{background:#fff;color:#000;border-bottom:2px solid #000}.mast .sub,.mast .sub b,.brandrow,.brandrow b,.brandrow svg{color:#000}}
</style>
</head>
<body>
<header class="mast"><div class="wrap">
<div class="brandrow"><svg viewBox="0 0 64 64" aria-hidden="true"><path d="M6 20V6h14M44 6h14v14M58 44v14H44M20 58H6V44" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="square"/><path d="M20 20l24 24M44 20L20 44" fill="none" stroke="currentColor" stroke-width="6"/><circle cx="32" cy="32" r="9" fill="var(--band)" stroke="currentColor" stroke-width="5"/><circle cx="32" cy="32" r="3" fill="currentColor"/></svg><b>WinForensicX</b><span>Fleet report</span></div>
<h1 id="h1"></h1><div class="sub" id="sub"></div></div></header>
<div class="bar"><div class="wrap"><nav class="nav"><a href="#hosts">Hosts</a><a href="#spread">Spread</a><a href="#movement">Movement</a><a href="#shared">Shared indicators</a><a href="#common">Common findings</a><a href="#rare">Rare programs</a><a href="#stages">Stages by host</a></nav>
<button class="btn" id="csv" type="button">Hosts CSV</button></div></div>
<main class="wrap">
<section id="hosts"><h2>Hosts</h2><p class="desc">Every triaged host, most at risk first. Risk is evidence of attacker activity; hardening is how exposed the host is.</p><div id="hbox"></div></section>
<section id="spread"><h2>Spread</h2><p class="desc">When each host first showed medium-or-higher attacker activity, earliest first. The first host is a candidate for patient zero; check the shared indicators to see how activity moved.</p><div id="sbox"></div></section>
<section id="movement"><h2>Movement between hosts</h2><p class="desc">Remote logons, logons with explicit credentials and SMB, remote desktop, WinRM, RPC or SSH connections from one triaged host to another, read from each host&#39;s own event logs. Hosts are matched by name or by the addresses they recorded for themselves.</p><div id="mbox"></div><h3>Other machines in these records</h3><p class="desc">Sources and targets that match no triaged host. Collect from them next if the activity is not expected.</p><div id="obox"></div></section>
<section id="shared"><div class="head"><div><h2>Shared indicators</h2><p class="desc">Addresses, domains, URLs and hashes from attacker-related findings that appear on two or more hosts.</p></div><button class="btn" id="icsv" type="button">Download CSV</button></div><div id="ibox"></div></section>
<section id="common"><h2>Common findings</h2><p class="desc">Detections that fired on two or more hosts: the same tool, technique or persistence across the estate.</p><div id="cbox"></div></section>
<section id="rare"><h2>Rare programs</h2><p class="desc">Programs recorded on only one host. On a uniform estate, a program no other host has is worth a look. Programs named in that host&#39;s findings come first, then programs in folders any user can write to.</p><div id="rbox"></div></section>
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
  var fmt = function (s) { if (!s) return ''; var d = new Date(s); return isNaN(d) ? esc(s) : d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()); };
  var csv = function (rows) { return rows.map(function (r) { return r.map(function (v) { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(','); }).join('\r\n'); };
  var download = function (name, text) { var b = new Blob([text], { type: 'text/csv' }), a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = name; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500); };
  var H = (D.hosts || []).slice().sort(function (a, b) { return b.Risk - a.Risk || String(a.Host).localeCompare(b.Host); });
  var bad = H.filter(function (h) { return h.Level === 'Critical' || h.Level === 'High'; }).length;
  $('h1').textContent = H.length + ' host' + (H.length === 1 ? '' : 's') + ', ' + bad + ' with strong indicators of compromise';
  var subs = [['Generated', String(D.generated || '').replace('T', ' ').replace(/\.\d+Z$/, '').replace(/Z$/, '') + ' UTC'], ['Shared indicators', (D.shared || []).length], ['Findings on more than one host', (D.common || []).length]];
  $('sub').innerHTML = subs.map(function (s) { return '<span>' + esc(s[0]) + ' <b>' + esc(s[1]) + '</b></span>'; }).join('') + '<span>' + esc(D.tool) + '</span>';
  var meter = function (n) { return '<span class="meter"><i style="width:' + Math.max(0, Math.min(100, n)) + '%"></i></span>'; };
  $('hbox').innerHTML = '<div class="tbl"><table><thead><tr><th>Host</th><th>Risk</th><th>Hardening gaps</th><th>Findings</th><th>Attacker activity</th><th>Most severe findings</th></tr></thead><tbody>' + H.map(function (h) {
    var S = h.Summary || {};
    var counts = ['Critical', 'High', 'Medium', 'Low'].filter(function (k) { return S[k]; }).map(function (k) { return S[k] + ' ' + k.toLowerCase(); }).join(', ') || 'none';
    return '<tr><td><b>' + esc(h.Host) + '</b><div class="small">' + esc(h.Os || '') + '</div><div class="small">' + esc(h.Mode || '') + (h.Case ? ', case ' + esc(String(h.Case).slice(0, 8)) : '') + '</div></td><td class="nw">' + sev(h.Level) + '<div class="small">' + esc(h.Risk) + ' / 100' + meter(h.Risk) + '</div></td><td class="nw">' + esc(h.Posture) + ' / 100' + meter(h.Posture) +
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
  var join = function (a) { return esc((a || []).join(', ')); };
  var MV = D.moves || [];
  $('mbox').innerHTML = MV.length ? '<div class="tbl"><table><thead><tr><th>From</th><th>To</th><th>How</th><th>Accounts</th><th>First</th><th>Last</th><th class="num">Events</th><th>Recorded on</th></tr></thead><tbody>' + MV.map(function (e) {
    return '<tr><td><b>' + esc(e.From) + '</b></td><td><b>' + esc(e.To) + '</b></td><td class="nw">' + esc(e.How) + '</td><td class="m">' + join(e.Accounts) + '</td><td class="t">' + esc(fmt(e.First)) + '</td><td class="t">' + esc(fmt(e.Last)) + '</td><td class="num">' + esc(e.Count) + '</td><td class="small">' + join(e.Recorded) + '</td></tr>';
  }).join('') + '</tbody></table></div>' : '<div class="empty">No logon or connection links one triaged host to another. Hosts triaged before version 3.2 carry no logon summary; triage them again to include them.</div>';
  var OU = D.outside || [];
  $('obox').innerHTML = OU.length ? '<div class="tbl"><table><thead><tr><th>Machine</th><th>Seen by</th><th>How</th><th>First</th><th>Last</th><th class="num">Events</th></tr></thead><tbody>' + OU.map(function (o) {
    return '<tr><td class="m">' + esc(o.Peer) + '</td><td>' + join(o.Hosts) + '</td><td class="small">' + join(o.How) + '</td><td class="t">' + esc(fmt(o.First)) + '</td><td class="t">' + esc(fmt(o.Last)) + '</td><td class="num">' + esc(o.Count) + '</td></tr>';
  }).join('') + '</tbody></table></div>' : '<div class="empty">None.</div>';
  var RA = D.rare || [];
  $('rbox').innerHTML = (D.rareHosts || 0) < 3 ? '<div class="empty">Needs at least three hosts with program lists; ' + esc(D.rareHosts || 0) + ' available.</div>' : RA.length ? '<p class="small">' + esc(D.rareTotal) + ' program' + (D.rareTotal === 1 ? '' : 's') + ' recorded on one host only, across ' + esc(D.rareHosts) + ' hosts' + (D.rareTotal > RA.length ? '; the first ' + RA.length + ' are shown' : '') + '.</p><div class="tbl"><table><thead><tr><th>Host</th><th>Program</th><th>Recorded by</th><th>Last seen</th><th>Listed first because</th></tr></thead><tbody>' + RA.map(function (r) {
    return '<tr><td class="nw"><b>' + esc(r.Host) + '</b></td><td class="m">' + esc(r.Path) + '</td><td class="small">' + esc(r.Sources) + '</td><td class="t">' + esc(fmt(r.Last)) + '</td><td class="small">' + esc(r.Why) + '</td></tr>';
  }).join('') + '</tbody></table></div>' : '<div class="empty">Every recorded program appears on at least two hosts.</div>';
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
