# Injected-code scan (-DeepScan, opt-in): executable memory that no file on disk accounts for.
#
# For each process it may open, it lists the memory regions (VirtualQueryEx) and keeps the ones that are
# executable but private or mapped rather than loaded from a program file: that is where injected shellcode,
# reflectively loaded DLLs and hollowed code live. Of those regions it reads at most the first 1 KB, only to
# see whether a program header (MZ ... PE) sits there. No other memory is read, nothing is saved but the
# region's address, size and protection, and nothing is written.
# Never opened: LSASS, the other critical system processes and security products (same list as the loaded-DLL
# check). Protected processes refuse to be opened anyway. Browsers, .NET and Java compile code at run time
# into exactly this kind of memory, so they are marked (Jit) and judged more leniently.
# Opt-in because reading other processes' memory is slow and some EDR products report it.

$script:WfxMemSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public sealed class WfxMemRegion {
    public int Pid;
    public long Base;
    public long Size;
    public uint Protect;
    public uint Type;
    public bool PeHeader;
}

public static class WfxMemScan {
    [StructLayout(LayoutKind.Sequential)]
    struct MBI { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI info, UIntPtr len);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);

    const uint QUERY_INFORMATION = 0x400, VM_READ = 0x10, MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, MEM_MAPPED = 0x40000;
    const uint EXEC = 0x10 | 0x20 | 0x40 | 0x80, GUARD = 0x100, NOACCESS = 0x01;

    // Returns null when the process cannot be opened. Read-only: query and read access only.
    public static List<WfxMemRegion> Scan(int pid, int maxRegions) {
        IntPtr h = OpenProcess(QUERY_INFORMATION | VM_READ, false, pid);
        if (h == IntPtr.Zero) return null;
        var res = new List<WfxMemRegion>();
        try {
            long addr = 0;
            long max = IntPtr.Size == 8 ? 0x7FFFFFFFFFFFL : 0x7FFFFFFFL;
            uint mbiSize = (uint)Marshal.SizeOf(typeof(MBI));
            while (addr < max) {
                MBI m;
                if (VirtualQueryEx(h, new IntPtr(addr), out m, new UIntPtr(mbiSize)) == UIntPtr.Zero) break;
                long size = m.RegionSize.ToInt64();
                if (size <= 0) break;
                if (m.State == MEM_COMMIT && (m.Type == MEM_PRIVATE || m.Type == MEM_MAPPED) && (m.Protect & EXEC) != 0 && (m.Protect & (GUARD | NOACCESS)) == 0) {
                    var r = new WfxMemRegion { Pid = pid, Base = m.BaseAddress.ToInt64(), Size = size, Protect = m.Protect, Type = m.Type };
                    byte[] buf = new byte[(int)Math.Min(1024L, size)];
                    IntPtr read;
                    if (ReadProcessMemory(h, m.BaseAddress, buf, new IntPtr(buf.Length), out read) && read.ToInt64() >= 64 && buf[0] == 0x4D && buf[1] == 0x5A) {
                        int lfanew = BitConverter.ToInt32(buf, 0x3C);
                        if (lfanew > 0 && lfanew + 4 <= read.ToInt64() && buf[lfanew] == 0x50 && buf[lfanew + 1] == 0x45 && buf[lfanew + 2] == 0 && buf[lfanew + 3] == 0) r.PeHeader = true;
                    }
                    res.Add(r);
                    if (res.Count >= maxRegions) break;
                }
                long next = m.BaseAddress.ToInt64() + size;
                if (next <= addr) break;
                addr = next;
            }
        } finally { CloseHandle(h); }
        return res;
    }
}
'@

$script:WfxJitProcess = @('chrome', 'msedge', 'msedgewebview2', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore', 'java', 'javaw', 'node', 'electron',
    'code', 'teams', 'ms-teams', 'slack', 'discord', 'spotify', 'whatsapp', 'signal', 'obsidian', 'notion', 'figma', 'postman', 'powershell', 'pwsh',
    'powershell_ise', 'devenv', 'msbuild', 'dotnet', 'w3wp', 'searchapp', 'searchhost', 'startmenuexperiencehost', 'shellexperiencehost', 'widgets', 'msteams')

function Get-WfxInjectedCode {
    <# Executable private / mapped memory regions per process (see the header). Opt-in, read-only. #>
    param([int]$MaxRegionsPerProcess = 64)
    if (-not (Test-WfxWindows)) { return }
    if ([IntPtr]::Size -eq 4 -and [Environment]::Is64BitOperatingSystem) { Add-WfxGap -Source 'memory:scan' -Reason 'A 32-bit PowerShell cannot read the memory of 64-bit processes.' -Fix 'Run the 64-bit PowerShell.'; return }
    if (-not ('WfxMemScan' -as [type])) {
        try { Add-Type -TypeDefinition $script:WfxMemSource -ErrorAction Stop }
        catch { Add-WfxGap -Source 'memory:scan' -Reason "The memory scanner could not be compiled: $($_.Exception.Message)"; return }
    }
    $skip = @{}; foreach ($n in $script:WfxModuleSkip) { $skip[$n.ToLowerInvariant()] = $true }
    $jit = @{}; foreach ($n in $script:WfxJitProcess) { $jit[$n] = $true }
    $denied = 0
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Sort-Object Id)) {
        $n = ([string]$p.ProcessName).ToLowerInvariant()
        if ($p.Id -le 4 -or $p.Id -eq $PID -or $skip.ContainsKey($n)) { continue }
        $regions = [WfxMemScan]::Scan($p.Id, $MaxRegionsPerProcess)
        if ($null -eq $regions) { $denied++; continue }
        if (-not $regions.Count) { continue }
        $path = ''; try { $path = [string]$p.MainModule.FileName } catch {}
        $isJit = $jit.ContainsKey($n)
        if (-not $isJit) { try { $isJit = [bool](@($p.Modules | Where-Object { $_.ModuleName -in 'clr.dll', 'coreclr.dll', 'jvm.dll', 'v8.dll', 'libcef.dll', 'mscorwks.dll' }).Count) } catch {} }
        foreach ($r in $regions) {
            # JIT memory in browsers, .NET and Java is expected; only a program header there is worth keeping.
            if ($isJit -and -not $r.PeHeader) { continue }
            [pscustomobject]@{
                Pid = $p.Id; Process = [string]$p.ProcessName; Path = $path
                Address = ('0x{0:X}' -f $r.Base); Size = $r.Size
                Protect = $(switch ($r.Protect -band 0xFF) { 0x10 { 'X' } 0x20 { 'RX' } 0x40 { 'RWX' } 0x80 { 'WCX' } default { '0x{0:X}' -f $r.Protect } })
                Type = $(if ($r.Type -eq 0x20000) { 'Private' } else { 'Mapped' })
                PeHeader = [bool]$r.PeHeader; Jit = $isJit
            }
        }
    }
    if ($denied) { Add-WfxGap -Source 'memory:scan' -Reason "$denied process(es) could not be opened for the injected-code scan$(if (-not (Test-WfxAdmin)) { ' (run as administrator for other users'' and system processes)' } else { ' (protected processes)' })." }
}
