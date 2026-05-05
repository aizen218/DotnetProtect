using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DotNetProtect.Runtime;

/// <summary>
/// Compares a mapped RX window of the main executable with the corresponding bytes on disk.
/// Intended for native AOT where tampering targets machine code rather than IL blobs.
/// </summary>
public static class NativeTextIntegrity
{
    private const int MaxWindow = 65536;

    public static void VerifyProcessImageMatchesOnDiskOrFail(int mappedByteCount = 512)
    {
        if (mappedByteCount <= 0 || mappedByteCount > MaxWindow)
            Environment.FailFast(null);

        if (OperatingSystem.IsWindows())
        {
            VerifyWindowsPeTextOrFail(mappedByteCount);
            return;
        }

        if (OperatingSystem.IsLinux())
        {
            VerifyLinuxMapsRxOrFail(mappedByteCount);
            return;
        }
    }

    private static void VerifyLinuxMapsRxOrFail(int byteCount)
    {
        var path = NormalizePath(Environment.ProcessPath);
        if (path is null)
            Environment.FailFast(null);

        if (!TryGetLinuxPrimaryRx(path, out var memStart, out var memLen, out var fileOff))
            Environment.FailFast(null);

        var len = (int)Math.Min(byteCount, (long)memLen);
        if (len <= 0)
            Environment.FailFast(null);

        var mem = new byte[len];
        if (!TryReadMemory(memStart, mem))
            Environment.FailFast(null);

        var memHash = SHA256.HashData(mem.AsSpan());

        using var fs = File.OpenRead(Environment.ProcessPath!);
        fs.Seek((long)fileOff, SeekOrigin.Begin);
        var fileBuf = new byte[len];
        if (fs.Read(fileBuf, 0, len) != len)
            Environment.FailFast(null);

        var fileHash = SHA256.HashData(fileBuf);
        if (!CryptographicOperations.FixedTimeEquals(memHash, fileHash))
            Environment.FailFast(null);
    }

    private static bool TryReadMemory(nuint start, byte[] dest)
    {
        try
        {
            unsafe
            {
                fixed (byte* p = dest)
                {
                    var src = (byte*)start;
                    for (var i = 0; i < dest.Length; i++)
                        p[i] = src[i];
                }
            }
            return true;
        }
        catch (AccessViolationException)
        {
            return false;
        }
    }

    private static string? NormalizePath(string? p)
    {
        if (string.IsNullOrEmpty(p))
            return null;
        try { return Path.GetFullPath(p); }
        catch { return p; }
    }

    private static bool TryGetLinuxPrimaryRx(string exePath, out nuint memStart, out nuint memLen, out ulong fileOff)
    {
        memStart = 0;
        memLen = 0;
        fileOff = 0;

        try
        {
            foreach (var line in File.ReadLines("/proc/self/maps"))
            {
                if (!line.Contains(" r-xp ", StringComparison.Ordinal))
                    continue;

                if (!TryParseMapsLine(line, out var start, out var end, out var off, out var mappedPath))
                    continue;

                if (mappedPath is null || !PathsReferToSameFile(exePath, mappedPath))
                    continue;

                memStart = start;
                memLen = end - start;
                fileOff = off;
                return true;
            }
        }
        catch
        {
            // ignore
        }

        return false;
    }

    private static bool PathsReferToSameFile(string a, string b)
    {
        try
        {
            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
                return true;
            var fa = Path.GetFullPath(a);
            var fb = Path.GetFullPath(b);
            return string.Equals(fa, fb, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryParseMapsLine(string line, out nuint start, out nuint end, out ulong fileOff, out string? path)
    {
        start = 0;
        end = 0;
        fileOff = 0;
        path = null;

        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 6)
            return false;

        var dash = parts[0].IndexOf('-');
        if (dash <= 0)
            return false;

        if (!ulong.TryParse(parts[0].AsSpan(0, dash), System.Globalization.NumberStyles.HexNumber, null, out var s))
            return false;
        if (!ulong.TryParse(parts[0].AsSpan(dash + 1), System.Globalization.NumberStyles.HexNumber, null, out var e))
            return false;
        if (!ulong.TryParse(parts[2], System.Globalization.NumberStyles.HexNumber, null, out fileOff))
            return false;

        start = (nuint)s;
        end = (nuint)e;

        path = parts[^1];
        if (path == "[vdso]" || path == "[vsyscall]" || path.StartsWith('['))
            path = null;

        return path is not null;
    }

    private static void VerifyWindowsPeTextOrFail(int byteCount)
    {
        var path = Environment.ProcessPath;
        if (string.IsNullOrEmpty(path))
            Environment.FailFast(null);

        var h = GetModuleHandleW(null);
        if (h == IntPtr.Zero)
            Environment.FailFast(null);

        if (!TryGetPeTextLayout(path, out var rva, out var rawPtr, out var rawSize))
            Environment.FailFast(null);

        var len = (int)Math.Min(byteCount, Math.Min((int)rawSize, MaxWindow));
        if (len <= 0)
            Environment.FailFast(null);

        var mem = new byte[len];
        Marshal.Copy(IntPtr.Add(h, (int)rva), mem, 0, len);

        using var fs = File.OpenRead(path);
        fs.Seek(rawPtr, SeekOrigin.Begin);
        var fileBuf = new byte[len];
        if (fs.Read(fileBuf, 0, len) != len)
            Environment.FailFast(null);

        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(mem), SHA256.HashData(fileBuf)))
            Environment.FailFast(null);
    }

    private static bool TryGetPeTextLayout(string imagePath, out uint textRva, out int rawPtr, out uint rawSize)
    {
        textRva = 0;
        rawPtr = 0;
        rawSize = 0;

        byte[] hdr;
        try
        {
            using var fs = File.OpenRead(imagePath);
            // PE headers + full section table fit comfortably in 64 KB; avoid loading the entire binary.
            var headerSize = (int)Math.Min(fs.Length, 65536);
            hdr = new byte[headerSize];
            var read = 0;
            while (read < headerSize)
            {
                var n = fs.Read(hdr, read, headerSize - read);
                if (n == 0) break;
                read += n;
            }
            if (read < headerSize)
                Array.Resize(ref hdr, read);
        }
        catch
        {
            return false;
        }

        if (hdr.Length < 0x40 || hdr[0] != 0x4D || hdr[1] != 0x5A)
            return false;

        var peOff = BitConverter.ToInt32(hdr, 0x3C);
        if (peOff < 0 || peOff + 24 > hdr.Length)
            return false;
        if (hdr[peOff] != 0x50 || hdr[peOff + 1] != 0x45)
            return false;

        var coff = peOff + 4;
        var numSections = BitConverter.ToUInt16(hdr, coff + 2);
        var optSize = BitConverter.ToUInt16(hdr, coff + 16);
        var opt = coff + 20;
        if (opt + optSize > hdr.Length || numSections == 0)
            return false;

        var firstSection = opt + optSize;
        const int SectionSize = 40;
        for (var i = 0; i < numSections; i++)
        {
            var o = firstSection + i * SectionSize;
            if (o + SectionSize > hdr.Length)
                return false;

            var name = System.Text.Encoding.ASCII.GetString(hdr, o, 8).TrimEnd('\0');
            if (name != ".text")
                continue;

            textRva = BitConverter.ToUInt32(hdr, o + 12);
            rawSize = BitConverter.ToUInt32(hdr, o + 16);
            rawPtr = (int)BitConverter.ToUInt32(hdr, o + 20);

            if (textRva == 0 || rawPtr == 0 || rawSize == 0)
                return false;

            return true;
        }

        return false;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandleW(string? lpModuleName);
}
