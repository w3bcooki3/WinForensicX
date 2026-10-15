function ConvertTo-WfxFileUri {
    <# Turns a local path into a file:// URI that most modern terminals render as a clickable link. #>
    param([string]$Path)
    $full = $Path
    try { $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path } catch {}
    $p = ($full -replace '\\', '/')
    if ($p -notmatch '^/') { $p = '/' + $p }   # Windows "C:/..." -> "/C:/..." so we get file:///C:/...
    return 'file://' + ($p -replace ' ', '%20')
}

function Show-WfxHelp {
    <#
    .SYNOPSIS
        Prints how to use WinForensicX — commands, examples, limitations and the defensive posture — to the
        terminal, and writes a matching HTML guide you can open in a browser.
    .PARAMETER Html      Open the HTML guide in the default browser after printing.
    .PARAMETER GuidePath Where to write the HTML guide (default: a temp file).
    .PARAMETER NoGuide   Don't write the HTML guide (terminal only).
    .EXAMPLE
        Show-WfxHelp
    .EXAMPLE
        Show-WfxHelp -Html
    #>
    [CmdletBinding()]
    param([switch]$Html, [string]$GuidePath = (Join-Path ([IO.Path]::GetTempPath()) 'WinForensicX-guide.html'), [switch]$NoGuide)
    $wasQuiet = $script:WfxQuiet; $script:WfxQuiet = $false
    $h = Get-WfxHelpModel

    Write-WfxConsole ''
    Write-WfxConsole '  WinForensicX' -Kind Head -NoNewline
    Write-WfxConsole "  v$($h.Version)  —  read-only DFIR triage" -Kind Dim
    Write-WfxConsole "  $($h.Tagline)" -Kind Plain
    Write-WfxConsole "  $($h.Requires)" -Kind Dim

    Write-WfxSection 'Commands'
    foreach ($c in $h.Commands) {
        Write-WfxConsole ("  {0}" -f $c.Name) -Kind Info -NoNewline
        Write-WfxConsole ("  $($c.Summary)") -Kind Dim
        foreach ($p in @($c.Params)) { Write-WfxConsole "      $p" -Kind Plain }
        if (@($c.Examples).Count) { Write-WfxConsole ("      e.g.  {0}" -f $c.Examples[0]) -Kind Dim }
    }

    Write-WfxSection 'What a run produces'
    foreach ($o in $h.Outputs) { Write-WfxConsole "  $o" -Kind Plain }

    Write-WfxSection 'Safety'
    foreach ($s in $h.Safety) { Write-WfxConsole "  + $s" -Kind Ok }

    Write-WfxSection 'Limitations'
    foreach ($l in $h.Limits) { Write-WfxConsole "  ! $l" -Kind Warn }

    if (-not $NoGuide -and (Get-Command New-WfxGuide -ErrorAction SilentlyContinue)) {
        try {
            $gp = New-WfxGuide -Path $GuidePath
            $uri = ConvertTo-WfxFileUri $gp
            Write-WfxSection 'Full guide'
            Write-WfxConsole '  Open the full illustrated guide in a browser (Ctrl/Cmd-click the link):' -Kind Plain
            Write-WfxConsole "  $uri" -Kind Info
            if ($Html) { try { Start-Process $gp -ErrorAction Stop } catch { Write-WfxConsole "  (could not auto-open; copy the link above)" -Kind Dim } }
        } catch { Write-WfxConsole "  (HTML guide unavailable: $($_.Exception.Message))" -Kind Dim }
    }
    Write-WfxConsole ''
    $script:WfxQuiet = $wasQuiet
}
