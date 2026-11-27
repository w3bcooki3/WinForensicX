# Fast file and folder search across the whole computer: by name (wildcards or a regular expression), by
# extension, or for files with no extension, with size, date and hidden filters. Read-only.
#
# Two ways to list files:
#   MFT   (administrator, local NTFS volumes) asks NTFS for every file record at once (FSCTL_ENUM_USN_DATA,
#         the same read-only call file indexers use) and rebuilds the paths. A whole volume of a million
#         files takes seconds. Nothing is written; the volume is opened for reading.
#   Walk  goes folder by folder. Works everywhere (no administrator rights, other file systems, network
#         drives with -IncludeNetwork), slower. Junctions and symbolic links are not followed, so it never
#         loops or leaves the drive.
# Both are compiled once from the small C# helper below; if compiling is not allowed (Constrained Language
# Mode), a slower PowerShell walk is used and the reason is shown.
# Only names and file-system metadata are read, unless -Hash, -CheckType or -Signature ask for file content.
# The quarantine folder (WinForensicX-Quarantine) is never searched.

$script:WfxFinderSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

public sealed class WfxFoundItem {
    public string Path;
    public bool IsDirectory;
    public uint Attributes;
    public long Size = -1;
    public long CreatedUtcTicks;
    public long ModifiedUtcTicks;
}

public sealed class WfxFindQuery {
    public Regex Name;                 // null = any name
    public HashSet<string> Extensions; // ".exe" style, lower case; null = any
    public bool NoExtension;
    public int Mode;                   // 0 files, 1 folders, 2 both
    public bool HiddenOnly;
    public long MinSize = -1, MaxSize = -1;
    public long AfterTicks, BeforeTicks;   // UTC ticks of the last-write time; 0 = no limit
    public string[] Skip = new string[0];  // folder names never entered
    public string[] Prefixes = new string[0];  // MFT only: keep paths under these folders
    public int Max = 10000;
    public bool Truncated;
    public int Denied;
}

public static class WfxFileFinder {
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x10, FILE_ATTRIBUTE_HIDDEN = 0x2, FILE_ATTRIBUTE_SYSTEM = 0x4, FILE_ATTRIBUTE_REPARSE = 0x400;

    static bool NameMatches(string name, bool isDir, WfxFindQuery q) {
        if (q.Mode == 0 && isDir) return false;
        if (q.Mode == 1 && !isDir) return false;
        if (q.Extensions != null || q.NoExtension) {
            int dot = name.LastIndexOf('.');
            string ext = (dot > 0) ? name.Substring(dot).ToLowerInvariant() : "";
            if (q.NoExtension && ext.Length > 0) return false;
            if (q.Extensions != null && !q.Extensions.Contains(ext)) return false;
        }
        if (q.Name != null) {
            try { if (!q.Name.IsMatch(name)) return false; } catch (RegexMatchTimeoutException) { return false; }
        }
        return true;
    }

    static bool InSkipped(string path, WfxFindQuery q) {
        char sep = System.IO.Path.DirectorySeparatorChar;
        foreach (string s in q.Skip) {
            string seg = sep + s;
            int i = path.IndexOf(seg, StringComparison.OrdinalIgnoreCase);
            while (i >= 0) {
                int end = i + seg.Length;
                if (end == path.Length || path[end] == sep) return true;
                i = path.IndexOf(seg, end, StringComparison.OrdinalIgnoreCase);
            }
        }
        return false;
    }

    // Size, time and hidden filters; fills the item. False = filtered out.
    static bool Finish(WfxFoundItem it, FileSystemInfo fi, WfxFindQuery q) {
        if (q.HiddenOnly && (it.Attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) == 0) return false;
        bool needStat = fi != null || q.MinSize >= 0 || q.MaxSize >= 0 || q.AfterTicks > 0 || q.BeforeTicks > 0;
        try {
            if (fi == null) fi = it.IsDirectory ? (FileSystemInfo)new DirectoryInfo(it.Path) : new FileInfo(it.Path);
            if (!fi.Exists) return !needStat || (q.MinSize < 0 && q.MaxSize < 0 && q.AfterTicks == 0 && q.BeforeTicks == 0);
            if (!it.IsDirectory) it.Size = ((FileInfo)fi).Length;
            it.CreatedUtcTicks = fi.CreationTimeUtc.Ticks;
            it.ModifiedUtcTicks = fi.LastWriteTimeUtc.Ticks;
            if (it.Attributes == 0) it.Attributes = (uint)fi.Attributes;
        } catch (Exception) { return q.MinSize < 0 && q.MaxSize < 0 && q.AfterTicks == 0 && q.BeforeTicks == 0; }
        if (q.MinSize >= 0 && (it.IsDirectory || it.Size < q.MinSize)) return false;
        if (q.MaxSize >= 0 && (it.IsDirectory || it.Size > q.MaxSize)) return false;
        if (q.AfterTicks > 0 && it.ModifiedUtcTicks < q.AfterTicks) return false;
        if (q.BeforeTicks > 0 && it.ModifiedUtcTicks > q.BeforeTicks) return false;
        if (q.HiddenOnly && (it.Attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) == 0) return false;
        return true;
    }

    // ── folder walk ──
    public static List<WfxFoundItem> Walk(string root, WfxFindQuery q) {
        var res = new List<WfxFoundItem>();
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0) {
            string dir = stack.Pop();
            try {
                foreach (FileSystemInfo e in new DirectoryInfo(dir).EnumerateFileSystemInfos()) {
                    uint attr = (uint)e.Attributes;
                    bool isDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
                    if (isDir) {
                        if (InSkipped(e.FullName, q)) continue;
                        if ((attr & FILE_ATTRIBUTE_REPARSE) == 0) stack.Push(e.FullName);
                    }
                    if (!NameMatches(e.Name, isDir, q)) continue;
                    var it = new WfxFoundItem { Path = e.FullName, IsDirectory = isDir, Attributes = attr };
                    if (!Finish(it, e, q)) continue;
                    res.Add(it);
                    if (res.Count >= q.Max) { q.Truncated = true; return res; }
                }
            } catch (UnauthorizedAccessException) { q.Denied++; }
            catch (IOException) { q.Denied++; }
            catch (System.Security.SecurityException) { q.Denied++; }
        }
        return res;
    }

    // ── NTFS master file table ──
    [StructLayout(LayoutKind.Sequential)]
    struct MftEnumDataV0 { public ulong StartFileReferenceNumber; public long LowUsn; public long HighUsn; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, ref MftEnumDataV0 inBuf, int inSize, IntPtr outBuf, int outSize, out int returned, IntPtr overlapped);

    struct Rec { public ulong Parent; public string Name; public uint Attr; }

    // drive: "C:". Opens the volume for reading only (GENERIC_READ, shared) and lists every file record.
    public static List<WfxFoundItem> Mft(string drive, WfxFindQuery q) {
        const uint GENERIC_READ = 0x80000000, SHARE_RW = 0x3, OPEN_EXISTING = 3, FSCTL_ENUM_USN_DATA = 0x000900B3;
        const int ERROR_HANDLE_EOF = 38, BUF = 1 << 16;
        var dirs = new Dictionary<ulong, Rec>();
        var hits = new List<Rec>();
        using (SafeFileHandle h = CreateFileW(@"\\.\" + drive, GENERIC_READ, SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero)) {
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr buf = Marshal.AllocHGlobal(BUF);
            try {
                var med = new MftEnumDataV0 { StartFileReferenceNumber = 0, LowUsn = 0, HighUsn = long.MaxValue };
                int got;
                while (true) {
                    if (!DeviceIoControl(h, FSCTL_ENUM_USN_DATA, ref med, Marshal.SizeOf(typeof(MftEnumDataV0)), buf, BUF, out got, IntPtr.Zero)) {
                        int err = Marshal.GetLastWin32Error();
                        if (err == ERROR_HANDLE_EOF) break;
                        throw new Win32Exception(err);
                    }
                    if (got <= 8) break;
                    med.StartFileReferenceNumber = (ulong)Marshal.ReadInt64(buf);
                    int off = 8;
                    while (off + 60 <= got) {
                        int len = Marshal.ReadInt32(buf, off);
                        if (len <= 0 || off + len > got) break;
                        if (Marshal.ReadInt16(buf, off + 4) == 2) {
                            ulong frn = (ulong)Marshal.ReadInt64(buf, off + 8);
                            ulong parent = (ulong)Marshal.ReadInt64(buf, off + 16);
                            uint attr = (uint)Marshal.ReadInt32(buf, off + 52);
                            int nlen = (ushort)Marshal.ReadInt16(buf, off + 56);
                            int noff = (ushort)Marshal.ReadInt16(buf, off + 58);
                            if (off + noff + nlen <= off + len) {
                                string name = Marshal.PtrToStringUni(IntPtr.Add(buf, off + noff), nlen / 2);
                                bool isDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
                                var r = new Rec { Parent = parent, Name = name, Attr = attr };
                                if (isDir) dirs[frn] = r;
                                // The root folder itself is the drive, not a search result.
                                if ((frn & 0x0000FFFFFFFFFFFFUL) != 5 && NameMatches(name, isDir, q)) hits.Add(r);
                            }
                        }
                        off += len;
                    }
                }
            } finally { Marshal.FreeHGlobal(buf); }
        }
        // Rebuild paths from the parent references (memoised per folder).
        var cache = new Dictionary<ulong, string>();
        var res = new List<WfxFoundItem>();
        foreach (Rec r in hits) {
            string parentPath = PathOf(r.Parent, drive, dirs, cache, 0);
            if (parentPath == null) continue;   // orphaned record (deleted folder)
            string full = parentPath + "\\" + r.Name;
            if (InSkipped(full, q)) continue;
            if (q.Prefixes.Length > 0) {
                bool under = false;
                foreach (string p in q.Prefixes) { if (full.StartsWith(p, StringComparison.OrdinalIgnoreCase) || (full + "\\").Equals(p, StringComparison.OrdinalIgnoreCase)) { under = true; break; } }
                if (!under) continue;
            }
            var it = new WfxFoundItem { Path = full, IsDirectory = (r.Attr & FILE_ATTRIBUTE_DIRECTORY) != 0, Attributes = r.Attr };
            if (!Finish(it, null, q)) continue;
            res.Add(it);
            if (res.Count >= q.Max) { q.Truncated = true; break; }
        }
        return res;
    }

    static string PathOf(ulong frn, string drive, Dictionary<ulong, Rec> dirs, Dictionary<ulong, string> cache, int depth) {
        if ((frn & 0x0000FFFFFFFFFFFFUL) == 5) return drive;          // the root folder
        string p;
        if (cache.TryGetValue(frn, out p)) return p;
        Rec d;
        if (depth > 512 || !dirs.TryGetValue(frn, out d)) return null;
        string parent = PathOf(d.Parent, drive, dirs, cache, depth + 1);
        p = parent == null ? null : parent + "\\" + d.Name;
        cache[frn] = p;
        return p;
    }
}
'@

function Initialize-WfxFileFinder {
    <# Compiles the finder once. $false (with the reason in $script:WfxFinderError) where compiling is not allowed. #>
    if ('WfxFileFinder' -as [type]) { return $true }
    if ($script:WfxFinderError) { return $false }
    try { Add-Type -TypeDefinition $script:WfxFinderSource -ErrorAction Stop; return $true }
    catch { $script:WfxFinderError = $_.Exception.Message; return $false }
}

function ConvertTo-WfxNameRegex {
    <# One case-insensitive pattern for the names given: wildcards (* ?) unless -Regex. $null for "any name". Pure. #>
    param([string[]]$Name = @(), [switch]$Regex)
    $n = @($Name | Where-Object { $_ -and $_ -ne '*' })
    if (-not $n.Count) { return $null }
    $parts = foreach ($x in $n) {
        if ($Regex) { "(?:$x)" }
        else { '^' + ([regex]::Escape($x) -replace '\\\*', '.*' -replace '\\\?', '.') + '$' }
    }
    $opt = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
    New-Object Text.RegularExpressions.Regex((@($parts) -join '|'), $opt, [TimeSpan]::FromMilliseconds(100))
}

function ConvertTo-WfxExtensionSet {
    <# "exe", ".EXE", "*.exe" -> ".exe". $null for "any extension". Pure. #>
    param([string[]]$Extension = @())
    $e = @($Extension | ForEach-Object { ([string]$_ -split '[,;\s]+') } | Where-Object { $_ } | ForEach-Object { '.' + $_.Trim().TrimStart('*').TrimStart('.').ToLowerInvariant() } | Where-Object { $_ -ne '.' })
    if (-not $e.Count) { return $null }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in $e) { [void]$set.Add($x) }
    , $set
}

function Find-WfxFile {
    <#
    .SYNOPSIS
        Finds files and folders across this computer, fast: by name (wildcards, or -Regex), by extension, or
        files with no extension; with size, date and hidden filters. Read-only.
    .DESCRIPTION
        As administrator, local NTFS drives are listed straight from the master file table (seconds for a whole
        drive). Otherwise, and for other drives, it walks the folders (junctions and links are not followed).
        Searches all fixed and removable drives unless -Path is given; network drives only with -IncludeNetwork.
        Stops at -MaxResults (10,000) and says so. File contents are read only for -Hash, -CheckType, -Signature.
    .PARAMETER Name        File or folder name patterns: wildcards (*invoice*, ?.ps1), or regular expressions with -Regex.
    .PARAMETER Extension   Extensions, with or without the dot: exe, .ps1, "hta,js,vbs".
    .PARAMETER NoExtension Only files with no extension.
    .PARAMETER Path        Folders or drives to search (default: all fixed and removable drives).
    .PARAMETER ItemType    File (default), Folder or Any.
    .PARAMETER MinSize     Smallest size in bytes (PowerShell understands 10MB, 1GB ...).
    .PARAMETER MaxSize     Largest size in bytes.
    .PARAMETER ModifiedAfter / ModifiedBefore   Last-write time limits (local time unless the value says otherwise).
    .PARAMETER Hidden      Only hidden or system items.
    .PARAMETER Hash        Add the SHA-256 of each file (reads the files).
    .PARAMETER CheckType   Add the real file type from its first bytes, and whether it disagrees with the extension.
    .PARAMETER Signature   Add the Authenticode signature status of each file.
    .PARAMETER Method      Auto (default: MFT when possible), Mft or Walk.
    .EXAMPLE
        Find-WfxFile -Extension ps1,hta,js,vbs -Path C:\Users -ModifiedAfter (Get-Date).AddDays(-7)
    .EXAMPLE
        Find-WfxFile -Name '*invoice*' -ItemType Any
    .EXAMPLE
        Find-WfxFile -NoExtension -Path C:\Users\Public -CheckType | Where-Object TrueType
    .EXAMPLE
        Find-WfxFile -Extension exe -Path C:\ProgramData -Hash -Signature | Where-Object Signature -ne 'Valid'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Name = @(),
        [string[]]$Extension = @(),
        [switch]$NoExtension,
        [switch]$Regex,
        [string[]]$Path = @(),
        [ValidateSet('File', 'Folder', 'Any')][string]$ItemType = 'File',
        [long]$MinSize = -1,
        [long]$MaxSize = -1,
        [Nullable[datetime]]$ModifiedAfter = $null,
        [Nullable[datetime]]$ModifiedBefore = $null,
        [switch]$Hidden,
        [switch]$Hash,
        [switch]$CheckType,
        [switch]$Signature,
        [switch]$IncludeNetwork,
        [ValidateRange(1, 1000000)][int]$MaxResults = 10000,
        [ValidateSet('Auto', 'Mft', 'Walk')][string]$Method = 'Auto'
    )
    if (-not ($Name.Count -or $Extension.Count -or $NoExtension -or $MinSize -ge 0 -or $MaxSize -ge 0 -or $ModifiedAfter -or $ModifiedBefore -or $Hidden)) {
        throw 'Say what to look for: -Name, -Extension, -NoExtension, a size or date limit, or -Hidden. Use -Name * to list everything.'
    }
    if ($NoExtension -and $Extension.Count) { throw '-NoExtension and -Extension cannot be used together.' }
    $q = $null
    $compiled = Initialize-WfxFileFinder
    $nameRx = ConvertTo-WfxNameRegex -Name $Name -Regex:$Regex
    $extSet = ConvertTo-WfxExtensionSet -Extension $Extension
    $mode = @{ File = 0; Folder = 1; Any = 2 }[$ItemType]
    $skip = @('WinForensicX-Quarantine')

    # ── where to look ──
    $targets = [System.Collections.Generic.List[string]]::new()
    if ($Path.Count) {
        foreach ($p in $Path) {
            $rp = try { (Resolve-Path -LiteralPath $p -ErrorAction Stop).ProviderPath } catch { throw "Path not found: $p" }
            if (-not (Test-Path -LiteralPath $rp -PathType Container)) { throw "Not a folder: $p" }
            $targets.Add($rp)
        }
    } elseif (Test-WfxWindows) {
        foreach ($d in [IO.DriveInfo]::GetDrives()) {
            if (-not $d.IsReady) { continue }
            if ($d.DriveType -in 'Fixed', 'Removable' -or ($IncludeNetwork -and $d.DriveType -eq 'Network')) { $targets.Add($d.RootDirectory.FullName) }
        }
    } else { $targets.Add([IO.Path]::GetPathRoot((Get-Location).ProviderPath)) }

    $admin = Test-WfxAdmin
    $notes = [System.Collections.Generic.List[string]]::new()
    $found = [System.Collections.Generic.List[object]]::new()
    $truncated = $false; $denied = 0
    # MFT jobs: one per drive, keeping only the requested folders on it.
    $byDrive = [ordered]@{}
    foreach ($t in $targets) {
        $useMft = $false
        if ($compiled -and (Test-WfxWindows) -and $Method -ne 'Walk') {
            $di = $null; try { $di = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($t)) } catch {}
            $ok = $di -and $di.DriveType -in 'Fixed', 'Removable' -and $di.DriveFormat -eq 'NTFS'
            if ($ok -and $admin) { $useMft = $true }
            elseif ($Method -eq 'Mft') { $notes.Add("MFT listing not possible for $t ($(if (-not $admin) { 'needs administrator rights' } else { 'not a local NTFS drive' })); walked the folders instead.") }
        }
        if ($useMft) {
            $drv = $t.Substring(0, 2).ToUpperInvariant()
            if (-not $byDrive.Contains($drv)) { $byDrive[$drv] = [System.Collections.Generic.List[string]]::new() }
            $root = $t.TrimEnd('\')
            if ($root.Length -gt 2) { $byDrive[$drv].Add($root + '\') } else { $byDrive[$drv].Add('') }
        } else { $byDrive["walk:$t"] = $null }
    }
    if (-not $compiled) { $notes.Add("The fast search helper could not be compiled ($script:WfxFinderError); used a slower PowerShell walk.") }
    elseif ($Method -ne 'Walk' -and -not $admin -and (Test-WfxWindows)) { $notes.Add('Not administrator: folders were walked one by one (slower), and folders this account cannot open were skipped.') }

    foreach ($k in @($byDrive.Keys)) {
        if ($found.Count -ge $MaxResults) { $truncated = $true; break }
        $left = $MaxResults - $found.Count
        if ($compiled) {
            $q = New-Object WfxFindQuery
            $q.Name = $nameRx; $q.Extensions = $extSet; $q.NoExtension = [bool]$NoExtension; $q.Mode = $mode; $q.HiddenOnly = [bool]$Hidden
            $q.MinSize = $MinSize; $q.MaxSize = $MaxSize; $q.Max = $left; $q.Skip = [string[]]$skip
            if ($ModifiedAfter) { $q.AfterTicks = ([datetime]$ModifiedAfter).ToUniversalTime().Ticks }
            if ($ModifiedBefore) { $q.BeforeTicks = ([datetime]$ModifiedBefore).ToUniversalTime().Ticks }
        }
        if ($k -like 'walk:*') {
            $root = $k.Substring(5)
            if ($compiled) {
                foreach ($it in [WfxFileFinder]::Walk($root, $q)) { $found.Add([pscustomobject]@{ I = $it; Source = 'Walk' }) }
                if ($q.Truncated) { $truncated = $true }; $denied += $q.Denied
            } else {
                $r = Find-WfxFileSlow -Root $root -NameRegex $nameRx -ExtensionSet $extSet -NoExtension:$NoExtension -Mode $mode -Hidden:$Hidden -MinSize $MinSize -MaxSize $MaxSize -ModifiedAfter $ModifiedAfter -ModifiedBefore $ModifiedBefore -Skip $skip -Max $left
                foreach ($it in $r.Items) { $found.Add([pscustomobject]@{ I = $it; Source = 'Walk' }) }
                if ($r.Truncated) { $truncated = $true }; $denied += $r.Denied
            }
        } else {
            $pref = @($byDrive[$k] | Where-Object { $_ })
            if (@($byDrive[$k]) -contains '') { $pref = @() }   # the whole drive was asked for
            $q.Prefixes = [string[]]$pref
            try {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                foreach ($it in [WfxFileFinder]::Mft($k, $q)) { $found.Add([pscustomobject]@{ I = $it; Source = 'MFT' }) }
                if ($q.Truncated) { $truncated = $true }
                Write-Verbose ("{0} listed from the MFT in {1:N1}s" -f $k, $sw.Elapsed.TotalSeconds)
            } catch {
                $notes.Add("MFT listing of $k failed ($($_.Exception.Message)); walked the folders instead.")
                $roots = if ($pref.Count) { $pref } else { @("$k\") }
                foreach ($root in $roots) {
                    $q.Truncated = $false; $q.Max = $MaxResults - $found.Count
                    if ($q.Max -le 0) { $truncated = $true; break }
                    foreach ($it in [WfxFileFinder]::Walk($root, $q)) { $found.Add([pscustomobject]@{ I = $it; Source = 'Walk' }) }
                    if ($q.Truncated) { $truncated = $true }; $denied += $q.Denied
                }
            }
        }
    }
    if ($truncated) { $notes.Add("Stopped at $MaxResults results. Narrow the search, or raise -MaxResults.") }
    if ($denied) { $notes.Add("$denied folder(s) could not be opened and were skipped$(if (-not $admin) { ' (run as administrator to include them)' }).") }

    $epoch = [datetime]::new(1, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    foreach ($f in $found) {
        $it = $f.I
        $leaf = [IO.Path]::GetFileName($it.Path)
        $ext = if ($it.IsDirectory) { '' } else { [IO.Path]::GetExtension($leaf).ToLowerInvariant() }
        $row = [ordered]@{
            Path     = $it.Path
            Name     = $leaf
            Type     = $(if ($it.IsDirectory) { 'Folder' } else { 'File' })
            Extension = $ext
            Size     = $(if ($it.IsDirectory -or $it.Size -lt 0) { $null } else { [long]$it.Size })
            Modified = $(if ($it.ModifiedUtcTicks -gt 0) { ConvertTo-WfxUtcString $epoch.AddTicks($it.ModifiedUtcTicks) } else { '' })
            Created  = $(if ($it.CreatedUtcTicks -gt 0) { ConvertTo-WfxUtcString $epoch.AddTicks($it.CreatedUtcTicks) } else { '' })
            Hidden   = [bool]($it.Attributes -band 0x6)
            Source   = $f.Source
        }
        if (-not $it.IsDirectory) {
            if ($Hash) { $row.Sha256 = (Get-WfxBinaryHash $it.Path) }
            if ($CheckType) {
                $tt = ''; $mm = $false
                try {
                    $fs = [IO.File]::Open($it.Path, 'Open', 'Read', 'ReadWrite, Delete')
                    try { $buf = New-Object byte[] 64; $n = $fs.Read($buf, 0, 64); if ($n -gt 0) { $m = Get-WfxFileMagic -Head $buf[0..($n - 1)]; if ($m) { $tt = $m.T; $mm = @($m.E).Count -gt 0 -and (@($m.E) -notcontains $ext) } } } finally { $fs.Dispose() }
                } catch {}
                $row.TrueType = $tt; $row.TypeMismatch = $mm
            }
            if ($Signature) { $row.Signature = (Get-WfxSignature $it.Path) }
        }
        [pscustomobject]$row
    }
    foreach ($n in $notes) { Write-Warning $n }
}

function Find-WfxFileSlow {
    <# PowerShell-only folder walk, for sessions where the compiled helper is not allowed. Same rules. #>
    param([string]$Root, $NameRegex, $ExtensionSet, [switch]$NoExtension, [int]$Mode, [switch]$Hidden, [long]$MinSize = -1, [long]$MaxSize = -1, $ModifiedAfter, $ModifiedBefore, [string[]]$Skip, [int]$Max)
    $items = [System.Collections.Generic.List[object]]::new()
    $stack = [System.Collections.Generic.Stack[string]]::new(); $stack.Push($Root)
    $denied = 0; $trunc = $false
    while ($stack.Count -and -not $trunc) {
        $dir = $stack.Pop()
        try { $entries = @([IO.DirectoryInfo]::new($dir).EnumerateFileSystemInfos()) } catch { $denied++; continue }
        foreach ($e in $entries) {
            $isDir = [bool]($e.Attributes -band [IO.FileAttributes]::Directory)
            if ($isDir) {
                if ($Skip -contains $e.Name) { continue }
                if (-not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($e.FullName) }
            }
            if ($Mode -eq 0 -and $isDir) { continue }
            if ($Mode -eq 1 -and -not $isDir) { continue }
            $x = if ($isDir) { '' } else { $e.Extension.ToLowerInvariant() }
            if ($NoExtension -and $x) { continue }
            if ($ExtensionSet -and -not $ExtensionSet.Contains($x)) { continue }
            if ($NameRegex) { $okName = $false; try { $okName = $NameRegex.IsMatch($e.Name) } catch {}; if (-not $okName) { continue } }
            if ($Hidden -and -not ($e.Attributes -band 6)) { continue }
            $size = if ($isDir) { -1L } else { [long]$e.Length }
            if ($MinSize -ge 0 -and ($isDir -or $size -lt $MinSize)) { continue }
            if ($MaxSize -ge 0 -and ($isDir -or $size -gt $MaxSize)) { continue }
            if ($ModifiedAfter -and $e.LastWriteTimeUtc -lt $ModifiedAfter.ToUniversalTime()) { continue }
            if ($ModifiedBefore -and $e.LastWriteTimeUtc -gt $ModifiedBefore.ToUniversalTime()) { continue }
            $items.Add([pscustomobject]@{ Path = $e.FullName; IsDirectory = $isDir; Attributes = [uint32]$e.Attributes; Size = $size; CreatedUtcTicks = $e.CreationTimeUtc.Ticks; ModifiedUtcTicks = $e.LastWriteTimeUtc.Ticks })
            if ($items.Count -ge $Max) { $trunc = $true; break }
        }
    }
    [pscustomobject]@{ Items = $items.ToArray(); Truncated = $trunc; Denied = $denied }
}
