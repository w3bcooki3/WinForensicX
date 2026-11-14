function Get-WfxArtifact {
    <#
    .SYNOPSIS
        Parses execution and user-activity artifacts — from this computer, or from files collected elsewhere —
        and returns one normalised record per entry, optionally flagged by the triage rules.
    .DESCRIPTION
        Sources: Amcache (programs, drivers, installed apps, SHA-1), ShimCache, Prefetch, BAM, UserAssist,
        PCA (Windows 11), ShellBags, Jump Lists, shortcut (.lnk) files, RunMRU, typed paths, Explorer searches,
        browser download history (Chromium browsers and Firefox) and Microsoft Defender support logs.

        Without -Path the live host is read (Windows, administrator recommended). With -Path, a folder of
        collected files (KAPE / Velociraptor output, a mounted image, CTF evidence) or a single file is parsed.
        Files are recognised by content, so renamed hives still work. Nothing is executed or modified, and
        hives are never loaded into the registry; dirty hives are repaired in memory from their .LOG1/.LOG2.

        Every record has: Artifact, Time, TimeKind (what the time means), Evidence (Execution, Presence,
        Access, Download, Detection, Install), Path, Name, Sha1, User, Detail, Source and Extra.
    .PARAMETER Path      Folder or file to parse. Omit for the live host.
    .PARAMETER Artifact  Keep only these artifact types (e.g. Amcache, ShimCache, JumpList, Download).
    .PARAMETER Flag      Add Flag / Why / Technique / Rule columns from the triage rules.
    .EXAMPLE
        Get-WfxArtifact -Path D:\kape\C -Flag | Where-Object Flag | Format-Table Flag, Why, Path
    .EXAMPLE
        Get-WfxArtifact -Path .\Amcache.hve | Where-Object Sha1 -eq 'e3b0c442...'
    .EXAMPLE
        Get-WfxArtifact -Artifact JumpList, Shortcut | Where-Object { $_.Extra.DriveType -eq 'Removable' }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Path = '',
        [ValidateSet('Amcache', 'AmcacheProgram', 'AmcacheDriver', 'ShimCache', 'Prefetch', 'BAM', 'UserAssist', 'PCA', 'ShellBag', 'JumpList', 'Shortcut', 'RunMRU', 'TypedPath', 'Search', 'Download', 'DefenderLog')]
        [string[]]$Artifact = @(),
        [switch]$Flag
    )
    $before = $script:WfxGaps.Count
    $rows = if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Path not found: $Path" }
        @(Import-WfxArtifact -Path $Path | Expand-WfxRecord)
    } else {
        if (-not (Test-WfxWindows)) { throw 'Reading the live host needs Windows. Use -Path for collected files.' }
        if (-not (Test-WfxAdmin)) { Write-Warning 'Not elevated: ShimCache, Amcache, Prefetch, PCA and Defender logs need administrator rights.' }
        @(Get-WfxArtifactData | Expand-WfxRecord)
    }
    if ($Artifact.Count) { $rows = @($rows | Where-Object { $_.Artifact -in $Artifact }) }
    if ($Flag) { $rows = @($rows | Add-WfxFlag Artifact) }
    $rows
    for ($g = $before; $g -lt $script:WfxGaps.Count; $g++) { Write-Warning ("{0}: {1}" -f $script:WfxGaps[$g].Source, $script:WfxGaps[$g].Reason) }
}
