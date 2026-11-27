# Starting up: the administrator prompt and the self-check.
#
# Administrator prompt. Without administrator rights a triage cannot read the Security log, other users'
# processes, Prefetch, the NTFS change journal or BitLocker. Request-WfxElevation asks once, at start:
#   [A] restart as administrator  — opens a new window through the normal Windows UAC prompt
#   [C] continue without          — what cannot be read is listed in the report as gaps
#   [Q] quit
# Rules it keeps:
#   * It never elevates without asking. -Elevate is the operator asking in advance; -NoElevate skips it.
#   * It never prompts when nobody can answer (non-interactive sessions, redirected input).
#   * The new window runs the same script with the same options, with -NoProfile (no profile scripts run
#     with administrator rights) and with the execution policy this window already has (nothing is loosened
#     or changed; a Group Policy setting still wins).
#   * If UAC is cancelled or refused, it carries on in this window without administrator rights.
#
# Self-check. Test-WfxIntegrity compares the code files that load with SHA256SUMS.txt from the release, and
# lists code files that are not in it: the module loads every .ps1 in its folders, so a file added there
# would run. SHA256SUMS.txt travels in the same folder, so this catches damage, files removed by antivirus
# and accidental or planted changes, not a whole package swapped by someone who also rewrote the list.
# For that, compare the list's own SHA-256 (printed) with the release page.

function Test-WfxInteractive {
    <# $true when a person can answer a prompt in this session. #>
    if (-not [Environment]::UserInteractive) { return $false }
    foreach ($a in [Environment]::GetCommandLineArgs()) { if ([string]$a -match '(?i)^(?:-|--|/)noni') { return $false } }
    try { if ([Console]::IsInputRedirected) { return $false } } catch {}
    return $true
}

function ConvertTo-WfxArgument {
    <# Quotes one command-line argument the way Windows splits command lines (CommandLineToArgvW), so a path
       with spaces, quotes or a trailing backslash arrives as exactly one, unchanged argument. #>
    param([AllowEmptyString()][string]$Value)
    if ($Value -eq '') { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $s = [regex]::Replace($Value, '(\\*)"', { param($m) ($m.Groups[1].Value * 2) + '\"' })
    $s = [regex]::Replace($s, '(\\+)$', { param($m) $m.Groups[1].Value * 2 })
    return '"' + $s + '"'
}

function Get-WfxPowerShellExe {
    <# The PowerShell executable running this session (Windows PowerShell or PowerShell 7), so the new window
       uses the same one. Falls back to $PSHOME when the host is not powershell.exe or pwsh.exe (e.g. the ISE). #>
    $exe = ''
    try { $exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName } catch {}
    if ($exe -and ([IO.Path]::GetFileName($exe) -in 'powershell.exe', 'pwsh.exe')) { return $exe }
    $leaf = if ($PSVersionTable.PSVersion.Major -le 5) { 'powershell.exe' } else { 'pwsh.exe' }
    return (Join-Path $PSHOME $leaf)
}

function Get-WfxElevationCommand {
    <#
    .SYNOPSIS The program and argument string that restart a script as administrator. Pure; starts nothing.
    .PARAMETER Parameters  Options to pass on. Switches are passed when $true; empty strings are left out.
                           Names must be plain words (they come from the caller, never from collected data).
    .PARAMETER ExecutionPolicy  The policy in effect in this window, passed on unchanged.
    #>
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string]$ScriptPath,
        [System.Collections.IDictionary]$Parameters = @{},
        [string]$ExecutionPolicy = ''
    )
    $a = [System.Collections.Generic.List[string]]::new()
    $a.Add('-NoProfile')
    # Only a policy that let this script run is passed on; Restricted/Undefined would not have.
    if ($ExecutionPolicy -in 'AllSigned', 'RemoteSigned', 'Unrestricted', 'Bypass') { $a.Add('-ExecutionPolicy'); $a.Add($ExecutionPolicy) }
    $a.Add('-File'); $a.Add((ConvertTo-WfxArgument $ScriptPath))
    foreach ($k in @($Parameters.Keys | Sort-Object)) {
        if ([string]$k -notmatch '^[A-Za-z][A-Za-z0-9]*$') { throw "Invalid parameter name: $k" }
        if ($k -in 'Elevate', 'NoElevate') { continue }
        $v = $Parameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter] -or $v -is [bool]) { if ([bool]$v) { $a.Add("-$k") } }
        elseif ($null -ne $v -and [string]$v -ne '') { $a.Add("-$k"); $a.Add((ConvertTo-WfxArgument ([string]$v))) }
    }
    # The new window must never ask again (for example when UAC hands back a non-elevated token).
    $a.Add('-NoElevate')
    [pscustomobject]@{ FilePath = $Exe; Arguments = ($a -join ' ') }
}

function Request-WfxElevation {
    <#
    .SYNOPSIS Offers to restart as administrator. Returns 'Elevated' (a new administrator window was opened:
    stop here), 'Continue' (carry on in this window) or 'Quit'.
    .PARAMETER ScriptPath  The script to restart (the launcher or the single-file build).
    .PARAMETER Parameters  The options it was started with.
    .PARAMETER Elevate     Restart as administrator without asking (UAC still asks).
    .PARAMETER NoElevate   Never ask.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [System.Collections.IDictionary]$Parameters = @{},
        [switch]$Elevate,
        [switch]$NoElevate
    )
    if (-not (Test-WfxWindows) -or (Test-WfxAdmin) -or $NoElevate) { return 'Continue' }
    if (-not $Elevate) {
        if (-not (Test-WfxInteractive)) { return 'Continue' }
        Write-Host ''
        Write-Host '  WinForensicX is running without administrator rights.' -ForegroundColor Yellow
        Write-Host '  Without them it cannot read the Security event log, other users'' processes, Prefetch,' -ForegroundColor Gray
        Write-Host '  the NTFS change journal, BitLocker or Defender exclusions. Nothing on this computer is changed either way.' -ForegroundColor Gray
        Write-Host ''
        Write-Host '   A  ' -ForegroundColor Cyan -NoNewline; Write-Host 'Restart as administrator (Windows asks you to confirm)'
        Write-Host '   C  ' -ForegroundColor Cyan -NoNewline; Write-Host 'Continue without (the report lists what could not be read)'
        Write-Host '   Q  ' -ForegroundColor Cyan -NoNewline; Write-Host 'Quit'
        Write-Host ''
        $c = Read-WfxMenuChoice -Valid 'A', 'C', 'Q' -Prompt 'A, C or Q'
        if ($c -eq 'Q') { return 'Quit' }
        if ($c -eq 'C') { return 'Continue' }
    }
    $policy = ''
    try { $policy = [string](Get-ExecutionPolicy) } catch {}
    $cmd = Get-WfxElevationCommand -Exe (Get-WfxPowerShellExe) -ScriptPath $ScriptPath -Parameters $Parameters -ExecutionPolicy $policy
    try {
        Start-Process -FilePath $cmd.FilePath -ArgumentList $cmd.Arguments -Verb RunAs -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ''
        Write-Host '  No administrator window was opened (the Windows prompt was cancelled or is not allowed here).' -ForegroundColor Yellow
        Write-Host '  Continuing without administrator rights.' -ForegroundColor Gray
        return 'Continue'
    }
    return 'Elevated'
}

# ───────────────────────────── self-check ─────────────────────────────
function Get-WfxReleaseRoot {
    <# The folder that holds SHA256SUMS.txt: the parent of the module folder, or of dist\ for the single file. #>
    if ($script:WfxSingleFilePath) {
        $d = Split-Path -Parent $script:WfxSingleFilePath
        if ((Split-Path -Leaf $d) -eq 'dist') { return (Split-Path -Parent $d) }
        return $d
    }
    if ($script:WfxModuleRoot) { return (Split-Path -Parent $script:WfxModuleRoot) }
    return $null
}

function Read-WfxSums {
    <# Parses a "<sha256>  <path>" list (the output of sha256sum / Get-FileHash). Keys: path with '/'
       separators, lower-case. Values: the upper-case hash. Lines that are not in that form are ignored. #>
    param([Parameter(Mandatory)][string]$Path)
    $map = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $m = [regex]::Match($line, '^\s*([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$')
        if ($m.Success) { $map[($m.Groups[2].Value -replace '\\', '/').ToLowerInvariant()] = $m.Groups[1].Value.ToUpperInvariant() }
    }
    $map
}

function Test-WfxIntegrity {
    <#
    .SYNOPSIS
        Checks this copy of WinForensicX against SHA256SUMS.txt: code files changed or missing, and code files
        that are not in the list (the module would load them). Read-only.
    .DESCRIPTION
        SHA256SUMS.txt ships in the same folder, so this catches damage, files removed by antivirus and changed
        or added files. It cannot catch a whole package replaced together with its list: compare SumsSha256
        with the value on the release page for that.
    .PARAMETER Root  The release folder (default: the folder this copy was loaded from).
    .EXAMPLE
        Test-WfxIntegrity
    #>
    [CmdletBinding()]
    param([string]$Root = '')
    if (-not $Root) { $Root = Get-WfxReleaseRoot }
    $sumsPath = if ($Root) { Join-Path $Root 'SHA256SUMS.txt' } else { '' }
    $out = [ordered]@{ Status = 'NOSUMS'; Root = $Root; Checked = 0; Changed = @(); Missing = @(); Unexpected = @(); SumsSha256 = '' }
    if (-not $sumsPath -or -not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) { return [pscustomobject]$out }
    $out.SumsSha256 = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sums = Read-WfxSums -Path $sumsPath
    $single = [bool]$script:WfxSingleFilePath
    $code = '^(?:winforensicx/.+\.(?:ps1|psm1|psd1|json)|start-winforensicx\.ps1|dist/winforensicx\.ps1)$'
    $changed = [System.Collections.Generic.List[string]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    $unexpected = [System.Collections.Generic.List[string]]::new()
    $checked = 0
    if ($single) {
        $full = $script:WfxSingleFilePath
        $key = if ((Split-Path -Leaf (Split-Path -Parent $full)) -eq 'dist') { 'dist/' + (Split-Path -Leaf $full).ToLowerInvariant() } else { (Split-Path -Leaf $full).ToLowerInvariant() }
        if ($sums.ContainsKey($key)) {
            $checked = 1
            if ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ne $sums[$key]) { $changed.Add($key) }
        } else { $unexpected.Add($key) }
    } else {
        foreach ($k in @($sums.Keys | Where-Object { $_ -match $code } | Sort-Object)) {
            $full = Join-Path $Root ($k -replace '/', [IO.Path]::DirectorySeparatorChar)
            if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
                # Only files the module loads matter here; a missing launcher or single file does not run.
                if ($k -like 'winforensicx/*') { $missing.Add($k) }
                continue
            }
            $checked++
            if ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ne $sums[$k]) { $changed.Add($k) }
        }
        # Extra code files the loader would pick up: named relative to the module folder, so no path
        # normalisation (8.3 names, symbolic links) can hide one.
        if ($script:WfxModuleRoot -and (Test-Path -LiteralPath $script:WfxModuleRoot)) {
            $modName = (Split-Path -Leaf $script:WfxModuleRoot).ToLowerInvariant()
            $modFull = (Get-Item -LiteralPath $script:WfxModuleRoot).FullName.TrimEnd('\', '/')
            Get-ChildItem -LiteralPath $modFull -Recurse -File -Include *.ps1, *.psm1, *.psd1, *.json -ErrorAction SilentlyContinue | ForEach-Object {
                $k = $modName + '/' + ($_.FullName.Substring($modFull.Length).TrimStart('\', '/') -replace '\\', '/').ToLowerInvariant()
                if (-not $sums.ContainsKey($k)) { $unexpected.Add($k) }
            }
        }
    }
    $out.Checked = $checked
    $out.Changed = @($changed)
    $out.Missing = @($missing)
    $out.Unexpected = @($unexpected | Sort-Object)
    $out.Status = if ($changed.Count -or $missing.Count -or $unexpected.Count) { 'CHANGED' } elseif ($checked) { 'OK' } else { 'NOSUMS' }
    [pscustomobject]$out
}

function Write-WfxIntegrityLine {
    <# One line at start-up; the full lists on request (-Detail). Never stops the tool. #>
    param($Check, [switch]$Detail)
    if (-not $Check) { return }
    switch ($Check.Status) {
        'OK' { Write-WfxConsole ("  Self-check: {0} code file(s) match SHA256SUMS.txt (list SHA-256 {1}…)" -f $Check.Checked, $Check.SumsSha256.Substring(0, 16)) -Kind Dim }
        'NOSUMS' { Write-WfxConsole '  Self-check: no SHA256SUMS.txt next to this copy, so it was not verified. Verify the download against the release page.' -Kind Dim }
        default {
            Write-WfxConsole ("  Self-check: this copy differs from SHA256SUMS.txt: {0} changed, {1} missing, {2} not in the list." -f @($Check.Changed).Count, @($Check.Missing).Count, @($Check.Unexpected).Count) -Kind Warn
            $show = if ($Detail) { 50 } else { 5 }
            foreach ($p in @(@($Check.Changed | ForEach-Object { "changed:    $_" }) + @($Check.Missing | ForEach-Object { "missing:    $_" }) + @($Check.Unexpected | ForEach-Object { "not listed: $_" })) | Select-Object -First $show) { Write-WfxConsole "    $p" -Kind Warn }
            Write-WfxConsole '  If you did not edit these files, get a fresh copy from the release and verify it before using it for evidence.' -Kind Dim
        }
    }
}
