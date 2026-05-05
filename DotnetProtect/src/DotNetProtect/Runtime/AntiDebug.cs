using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DotNetProtect.Runtime;

/// <summary>
/// Heuristic debugger / tracer / VM checks (noise for static analysis — not a security boundary).
/// </summary>
public static class AntiDebug
{
    private static volatile bool s_timingChecked;

    /// <summary>Returns true if a debugger or ptrace tracer is likely attached.</summary>
    public static bool LikelyUnderDebugger()
    {
        if (Debugger.IsAttached)
            return true;
        if (OperatingSystem.IsWindows())
            return WinIsDebuggerPresent();
        if (OperatingSystem.IsLinux())
            return LinuxTracerPidNonZero() || LinuxParentIsDebugger();
        if (OperatingSystem.IsMacOS())
            return MacOsTracerPresent();
        return false;
    }

    /// <summary>Returns true if the process appears to be running inside a hypervisor or known VM.</summary>
    public static bool LikelyVirtualMachine()
    {
        if (OperatingSystem.IsLinux())
            return LinuxHypervisorFlagSet() || LinuxDmiVendorIsVm();
        if (OperatingSystem.IsWindows())
            return WindowsVmDriverPresent();
        return false;
    }

    /// <summary>
    /// Runs a one-shot startup check: debugger presence + timing anomaly.
    /// Safe to call from a module initializer — subsequent calls are no-ops.
    /// </summary>
    public static void CheckTimingOnce(int milliseconds = 10)
    {
        if (s_timingChecked) return;
        s_timingChecked = true;
        if (LikelyUnderDebugger() || SuspiciouslyFastSleep(milliseconds))
            Environment.Exit(0);
    }

    /// <summary>
    /// If <see cref="Thread.Sleep"/> finishes far too early, something may be single-stepping
    /// or faking time (high false-positive rate on heavily loaded hosts).
    /// </summary>
    public static bool SuspiciouslyFastSleep(int milliseconds = 10)
    {
        var sw = Stopwatch.StartNew();
        Thread.Sleep(milliseconds);
        return sw.Elapsed.TotalMilliseconds < milliseconds * 0.35;
    }

    // -------------------------------------------------------------------------
    // Windows
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", EntryPoint = "IsDebuggerPresent")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinIsDebuggerPresent();

    private static bool WindowsVmDriverPresent()
    {
        var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var drv = Path.Combine(sys, "drivers");
        return File.Exists(Path.Combine(drv, "vmhgfs.sys"))     // VMware Host Guest FS
            || File.Exists(Path.Combine(drv, "vboxguest.sys"))  // VirtualBox guest
            || File.Exists(Path.Combine(drv, "vboxmouse.sys"))  // VirtualBox mouse
            || File.Exists(Path.Combine(sys, "vmtoolsd.exe"));  // VMware Tools
    }

    // -------------------------------------------------------------------------
    // Linux
    // -------------------------------------------------------------------------

    // NOTE: ptrace(PTRACE_TRACEME) is intentionally NOT used here.
    // On systems with Yama ptrace_scope >= 1, the syscall returns -1/EPERM even
    // without a debugger attached, causing false positives that kill the app.
    // /proc/self/status TracerPid + parent comm are reliable alternatives.

    private static bool LinuxTracerPidNonZero()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/self/status"))
            {
                if (!line.StartsWith("TracerPid:", StringComparison.Ordinal))
                    continue;
                var s = line.AsSpan("TracerPid:".Length).Trim();
                return int.TryParse(s, out var p) && p != 0;
            }
        }
        catch { }
        return false;
    }

    private static bool LinuxParentIsDebugger()
    {
        try
        {
            var ppid = GetLinuxParentPid();
            if (ppid <= 0) return false;
            var comm = File.ReadAllText($"/proc/{ppid}/comm").Trim();
            return comm is "gdb" or "lldb" or "strace" or "ltrace"
                        or "radare2" or "r2" or "x64dbg" or "edb" or "rr";
        }
        catch { return false; }
    }

    private static int GetLinuxParentPid()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/self/status"))
            {
                if (!line.StartsWith("PPid:", StringComparison.Ordinal)) continue;
                var s = line.AsSpan("PPid:".Length).Trim();
                return int.TryParse(s, out var p) ? p : 0;
            }
        }
        catch { }
        return 0;
    }

    private static bool LinuxHypervisorFlagSet()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/cpuinfo"))
            {
                if (!line.StartsWith("flags", StringComparison.Ordinal) &&
                    !line.StartsWith("Features", StringComparison.Ordinal))
                    continue;
                if (line.Contains("hypervisor", StringComparison.Ordinal))
                    return true;
            }
        }
        catch { }
        return false;
    }

    private static bool LinuxDmiVendorIsVm()
    {
        try
        {
            var vendor = File.ReadAllText("/sys/class/dmi/id/sys_vendor").Trim();
            return vendor.Contains("VMware", StringComparison.OrdinalIgnoreCase)
                || vendor.Contains("QEMU", StringComparison.OrdinalIgnoreCase)
                || vendor.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)
                || vendor.Contains("Xen", StringComparison.OrdinalIgnoreCase)
                || vendor.Contains("KVM", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    // -------------------------------------------------------------------------
    // macOS
    // -------------------------------------------------------------------------

    /// <summary>
    /// Checks the P_TRACED flag in the process's kinfo_proc via sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID).
    /// On 64-bit macOS, p_flag sits at byte offset 32 inside the extern_proc (kp_proc) member.
    /// </summary>
    private static bool MacOsTracerPresent()
    {
        try
        {
            int[] mib = [1, 14, 1, Environment.ProcessId];
            nuint size = 0;
            MacSysctl(mib, 4, IntPtr.Zero, ref size, IntPtr.Zero, 0);
            if (size < 36)
                return false;

            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (MacSysctl(mib, 4, buf, ref size, IntPtr.Zero, 0) != 0)
                    return false;
                const int P_TRACED = 0x00000800;
                var pFlag = Marshal.ReadInt32(buf, 32);
                return (pFlag & P_TRACED) != 0;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { return false; }
    }

    [DllImport("libc", EntryPoint = "sysctl")]
    private static extern int MacSysctl(int[] name, uint namelen, IntPtr oldp, ref nuint oldlenp, IntPtr newp, nuint newlen);
}
