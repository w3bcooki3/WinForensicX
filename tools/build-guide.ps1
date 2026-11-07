<#
.SYNOPSIS
    Builds docs\guide.html from docs\guide.template.html.
.DESCRIPTION
    The narrative parts of the guide are hand-written in the template. The command reference, the list of live
    views (with their menu keys), the case-folder outputs, the limits and the safety statements are generated
    from the tool's own help model and view table, so the guide always matches the code it ships with.
    The screenshot docs\img\flagged-view.png is referenced, not embedded, and must ship next to the guide.
#>
[CmdletBinding()]
param([string]$Template = (Join-Path $PSScriptRoot '..\docs\guide.template.html'), [string]$OutFile = (Join-Path $PSScriptRoot '..\docs\guide.html'))
$ErrorActionPreference = 'Stop'
$mod = Join-Path $PSScriptRoot '..\WinForensicX'
foreach ($layer in 'Private', 'Analyzers', 'Collectors', 'Report', 'Public') {
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $mod $layer) -Filter *.ps1 | Sort-Object Name) { . $f.FullName }
}
$enc = { param([string]$s) [System.Net.WebUtility]::HtmlEncode($s) }
$tag = { param([string[]]$Keys) '<span class="tag">' + (($Keys | ForEach-Object { "<kbd>$_</kbd>" }) -join '<span class="sep">›</span>') + '</span>' }
$model = Get-WfxHelpModel

# Views, grouped exactly as the Explore menu numbers them.
$groups = @($script:WfxInsightTopics.Values | ForEach-Object { $_.Group } | Select-Object -Unique)
$views = New-Object System.Text.StringBuilder
$gi = 0
foreach ($g in $groups) {
    $gi++
    [void]$views.Append("<div class=""group""><h3>$(& $enc $g) $(& $tag @('2', [string]$gi))</h3><table class=""tbl views""><tr><th>Keys</th><th>View</th><th>What it shows</th><th>Checks</th></tr>")
    $ti = 0
    foreach ($t in @($script:WfxInsightTopics.GetEnumerator() | Where-Object { $_.Value.Group -eq $g })) {
        $ti++
        $marks = @()
        if ($script:WfxFlagTopic.Contains($t.Key)) { $marks += '<span class="yes">flagged</span>' }
        if ($t.Value.Admin) { $marks += 'admin' }
        $m = if ($marks.Count) { $marks -join ', ' } else { '<span class="no">data only</span>' }
        [void]$views.Append("<tr><td>$(& $tag @('2', [string]$gi, [string]$ti))</td><td>$(& $enc $t.Value.Title)</td><td>$(& $enc $t.Value.Desc)</td><td>$m</td></tr>")
    }
    [void]$views.Append('</table></div>')
}

# Commands.
$cmds = New-Object System.Text.StringBuilder
foreach ($c in $model.Commands) {
    $lines = @(@($c.Params | ForEach-Object { "<span class=""dim"">$(& $enc ($c.Name -replace ' /.*$', '')) $(& $enc $_)</span>" }) + @($c.Examples | ForEach-Object { "<span class=""ps"">PS&gt;</span> $(& $enc $_)" }))
    [void]$cmds.Append("<details class=""cmd""><summary>$(& $enc $c.Name)<span>$(& $enc $c.Summary)</span></summary><pre class=""console"">$($lines -join "`n")</pre></details>")
}

# Outputs: "name - description" lines.
$out = New-Object System.Text.StringBuilder
[void]$out.Append('<table class="tbl"><tr><th>File</th><th>What it holds</th></tr>')
foreach ($o in $model.Outputs) {
    $parts = ([string]$o) -split '\s+-\s+', 2
    [void]$out.Append("<tr><td><code>$(& $enc $parts[0].Trim())</code></td><td>$(& $enc $(if ($parts.Count -gt 1) { $parts[1] } else { '' }))</td></tr>")
}
[void]$out.Append('</table>')
$list = { param($items) '<ul class="plain">' + (($items | ForEach-Object { "<li>$(& $enc ([string]$_))</li>" }) -join '') + '</ul>' }

$html = Get-Content -LiteralPath $Template -Raw -Encoding UTF8
# The screenshot ships as docs\img\flagged-view.png next to the guide (not inlined: large Base64 blobs inside
# HTML look like HTML smuggling to antivirus heuristics). Drop the figure if the image is missing.
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '..\docs\img\flagged-view.png'))) { $html = [regex]::Replace($html, '(?s)\s*<figure>.*?</figure>', '') }
$html = $html.Replace('{{VERSION}}', $script:WfxVersion).
    Replace('<!--@VIEWS-->', $views.ToString()).Replace('<!--@COMMANDS-->', $cmds.ToString()).Replace('<!--@OUTPUTS-->', $out.ToString()).
    Replace('<!--@SAFETY-->', (& $list $model.Safety)).Replace('<!--@LIMITS-->', (& $list $model.Limits)).Replace('<!--@REQUIRES-->', (& $list $model.Requires))
if ($html -match '\{\{[A-Z_]+\}\}|<!--@[A-Z]+-->') { throw "Unfilled placeholder in the guide: $($Matches[0])" }
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutFile), $html, (New-Object System.Text.UTF8Encoding($false)))
$h = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
Write-Host ("Built {0}  ({1:N0} bytes, {2} views, {3} commands)  SHA-256 {4}" -f $OutFile, (Get-Item $OutFile).Length, $script:WfxInsightTopics.Count, @($model.Commands).Count, $h)
