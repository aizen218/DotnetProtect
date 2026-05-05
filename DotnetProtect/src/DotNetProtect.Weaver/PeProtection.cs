using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    /// <summary>
    /// Removes cosmetic assembly-level attributes that reveal the original project name,
    /// build configuration, and version strings. <c>AssemblyVersion</c> is intentionally
    /// kept because the .NET runtime uses it for assembly identity.
    /// </summary>
    private static bool StripAssemblyInfoAttributes(ModuleDefinition module)
    {
        // Attributes that leak project identity / build metadata but are not required at runtime.
        var cosmetic = new HashSet<string>(StringComparer.Ordinal)
        {
            "System.Reflection.AssemblyCompanyAttribute",
            "System.Reflection.AssemblyProductAttribute",
            "System.Reflection.AssemblyTitleAttribute",
            "System.Reflection.AssemblyConfigurationAttribute",
            "System.Reflection.AssemblyFileVersionAttribute",
            "System.Reflection.AssemblyInformationalVersionAttribute",
            "System.Reflection.AssemblyDescriptionAttribute",
            "System.Reflection.AssemblyCopyrightAttribute",
            "System.Reflection.AssemblyTrademarkAttribute",
            "System.Reflection.AssemblyMetadataAttribute",
        };

        var attrs = module.Assembly.CustomAttributes;
        var any = false;
        for (var i = attrs.Count - 1; i >= 0; i--)
        {
            if (cosmetic.Contains(attrs[i].AttributeType.FullName))
            {
                attrs.RemoveAt(i);
                any = true;
            }
        }

        // Module-level AssemblyMetadata entries
        var modAttrs = module.CustomAttributes;
        for (var i = modAttrs.Count - 1; i >= 0; i--)
        {
            if (modAttrs[i].AttributeType.FullName == "System.Reflection.AssemblyMetadataAttribute")
            {
                modAttrs.RemoveAt(i);
                any = true;
            }
        }

        return any;
    }

    /// <summary>
    /// Binary-patches the PE file written by Cecil:
    /// <list type="bullet">
    ///   <item>Randomises the COFF timestamp (removes build-time fingerprint).</item>
    ///   <item>Zeros the debug directory data-directory entry (removes PDB-path / CodeView records).</item>
    ///   <item>Strips the Rich header if present (removes linker / toolchain version data).</item>
    /// </list>
    /// Failures are non-fatal — a warning is printed and the file is left as-is.
    /// </summary>
    private static void ApplyPeBinaryProtection(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);

            // Validate MZ signature.
            if (bytes.Length < 0x40 || bytes[0] != 0x4D || bytes[1] != 0x5A)
                return;

            var peOffset = BitConverter.ToInt32(bytes, 0x3C);
            if (peOffset < 0x40 || peOffset + 24 > bytes.Length)
                return;

            // Validate PE signature.
            if (bytes[peOffset] != 0x50 || bytes[peOffset + 1] != 0x45 ||
                bytes[peOffset + 2] != 0x00 || bytes[peOffset + 3] != 0x00)
                return;

            var modified = false;

            // 1. Randomise COFF timestamp (4 bytes at COFF header offset 4 = PE+8).
            var tsOffset = peOffset + 8;
            if (tsOffset + 4 <= bytes.Length)
            {
                RandomNumberGenerator.Fill(bytes.AsSpan(tsOffset, 4));
                modified = true;
            }

            // 2. Zero debug data-directory entry (8 bytes: RVA + Size).
            if (ZeroDebugDirectory(bytes, peOffset))
                modified = true;

            // 3. Strip Rich header (between DOS stub and PE header, if present).
            if (StripRichHeader(bytes, peOffset))
                modified = true;

            if (modified)
                File.WriteAllBytes(path, bytes);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"DotNetProtect.Weaver: PE binary protection warning — {ex.Message}");
        }
    }

    private static void ApplyUnifiedBinaryProtection(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> magic = stackalloc byte[4];
            if (fs.Read(magic) < 4)
                return;

            if (magic[0] == 0x4D && magic[1] == 0x5A)
            {
                ApplyPeBinaryProtection(path);
                return;
            }

            if (magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46)
                ApplyElfBinaryProtection(path);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"DotNetProtect.Weaver: native binary protection warning — {ex.Message}");
        }
    }

    private static void ApplyElfBinaryProtection(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length < 64 || bytes[0] != 0x7F || bytes[1] != 0x45 || bytes[2] != 0x4C || bytes[3] != 0x46)
                return;

            var is64 = bytes[4] == 2;
            var little = bytes[5] == 1;
            if (!little)
                return;

            var modified = false;
            if (ZeroElfGnuBuildId(bytes, is64))
                modified = true;

            // Strip sections that reveal symbol names and function boundaries.
            // .symtab/.strtab → function/variable names visible via `nm`.
            // .eh_frame/.eh_frame_hdr → CFI unwind tables that expose function start offsets.
            // .dynsym and .dynstr are intentionally preserved (required for dynamic linking).
            if (ZeroElfSectionsByName(bytes, is64, ".symtab", ".strtab", ".eh_frame", ".eh_frame_hdr"))
                modified = true;

            if (modified)
                File.WriteAllBytes(path, bytes);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"DotNetProtect.Weaver: ELF binary protection warning — {ex.Message}");
        }
    }

    private static bool ZeroElfSectionsByName(byte[] bytes, bool is64, params string[] names)
    {
        int shoff, shentsize, shnum, shstrndx;
        if (is64)
        {
            shoff     = (int)BitConverter.ToUInt64(bytes, 0x28);
            shentsize = BitConverter.ToUInt16(bytes, 0x3A);
            shnum     = BitConverter.ToUInt16(bytes, 0x3C);
            shstrndx  = BitConverter.ToUInt16(bytes, 0x3E);
        }
        else
        {
            shoff     = BitConverter.ToInt32(bytes, 0x20);
            shentsize = BitConverter.ToUInt16(bytes, 0x2E);
            shnum     = BitConverter.ToUInt16(bytes, 0x30);
            shstrndx  = BitConverter.ToUInt16(bytes, 0x32);
        }

        if (shoff <= 0 || shentsize <= 0 || shnum <= 0 || shstrndx < 0 || shstrndx >= shnum)
            return false;
        if (shoff + (long)shentsize * shnum > bytes.Length)
            return false;

        int strTabOff;
        if (is64)
            strTabOff = (int)BitConverter.ToUInt64(bytes, shoff + shstrndx * shentsize + 0x18);
        else
            strTabOff = BitConverter.ToInt32(bytes, shoff + shstrndx * shentsize + 0x10);
        if (strTabOff <= 0 || strTabOff >= bytes.Length)
            return false;

        var target = new HashSet<string>(names, StringComparer.Ordinal);
        var any = false;

        for (var i = 0; i < shnum; i++)
        {
            var secOff  = shoff + i * shentsize;
            if (secOff + shentsize > bytes.Length) break;

            var nameOff = BitConverter.ToInt32(bytes, secOff);
            var secName = ReadElfString(bytes, strTabOff + nameOff);
            if (!target.Contains(secName))
                continue;

            int dataOff, dataSize;
            if (is64)
            {
                dataOff  = (int)BitConverter.ToUInt64(bytes, secOff + 0x18);
                dataSize = (int)BitConverter.ToUInt64(bytes, secOff + 0x20);
            }
            else
            {
                dataOff  = BitConverter.ToInt32(bytes, secOff + 0x10);
                dataSize = BitConverter.ToInt32(bytes, secOff + 0x14);
            }

            if (dataOff <= 0 || dataSize <= 0 || dataOff + dataSize > bytes.Length)
                continue;

            Array.Clear(bytes, dataOff, dataSize);
            any = true;
        }

        return any;
    }

    private static bool ZeroElfGnuBuildId(byte[] bytes, bool is64)
    {
        int shoff, shentsize, shnum, shstrndx;
        if (is64)
        {
            shoff = (int)BitConverter.ToUInt64(bytes, 0x28);
            shentsize = BitConverter.ToUInt16(bytes, 0x3A);
            shnum = BitConverter.ToUInt16(bytes, 0x3C);
            shstrndx = BitConverter.ToUInt16(bytes, 0x3E);
        }
        else
        {
            shoff = BitConverter.ToInt32(bytes, 0x20);
            shentsize = BitConverter.ToUInt16(bytes, 0x2E);
            shnum = BitConverter.ToUInt16(bytes, 0x30);
            shstrndx = BitConverter.ToUInt16(bytes, 0x32);
        }

        if (shoff <= 0 || shentsize <= 0 || shnum <= 0 || shstrndx < 0 || shstrndx >= shnum)
            return false;
        if (shoff + (long)shentsize * shnum > bytes.Length)
            return false;

        int strTabOff;
        if (is64)
            strTabOff = (int)BitConverter.ToUInt64(bytes, shoff + shstrndx * shentsize + 0x18);
        else
            strTabOff = BitConverter.ToInt32(bytes, shoff + shstrndx * shentsize + 0x10);
        if (strTabOff <= 0 || strTabOff >= bytes.Length)
            return false;

        for (var i = 0; i < shnum; i++)
        {
            var off = shoff + i * shentsize;
            if (off + shentsize > bytes.Length)
                return false;

            var nameOff = BitConverter.ToInt32(bytes, off);
            var secName = ReadElfString(bytes, strTabOff + nameOff);
            if (!string.Equals(secName, ".note.gnu.build-id", StringComparison.Ordinal))
                continue;

            int dataOff;
            int dataSize;
            if (is64)
            {
                dataOff = (int)BitConverter.ToUInt64(bytes, off + 0x18);
                dataSize = (int)BitConverter.ToUInt64(bytes, off + 0x20);
            }
            else
            {
                dataOff = BitConverter.ToInt32(bytes, off + 0x10);
                dataSize = BitConverter.ToInt32(bytes, off + 0x14);
            }

            if (dataOff <= 0 || dataSize <= 0 || dataOff + dataSize > bytes.Length)
                return false;

            Array.Clear(bytes, dataOff, dataSize);
            return true;
        }

        return false;
    }

    private static string ReadElfString(byte[] bytes, int offset)
    {
        if (offset < 0 || offset >= bytes.Length)
            return string.Empty;
        var end = offset;
        while (end < bytes.Length && bytes[end] != 0)
            end++;
        return Encoding.ASCII.GetString(bytes, offset, end - offset);
    }

    /// <summary>
    /// Zeros the debug data-directory entry (entry index 6) in the PE optional header,
    /// removing any reference to CodeView / PDB records or reproducibility hashes.
    /// </summary>
    private static bool ZeroDebugDirectory(byte[] bytes, int peOffset)
    {
        var optHeaderOffset = peOffset + 24; // COFF header = 20 bytes + PE sig = 4 bytes
        if (optHeaderOffset + 4 > bytes.Length) return false;

        var magic = BitConverter.ToUInt16(bytes, optHeaderOffset);
        int dataDirectoriesOffset = magic switch
        {
            0x010B => optHeaderOffset + 96,  // PE32
            0x020B => optHeaderOffset + 112, // PE32+
            _ => -1,
        };
        if (dataDirectoriesOffset < 0) return false;

        // Debug directory = entry 6 (each entry = 8 bytes: RVA + Size).
        var debugEntryOffset = dataDirectoriesOffset + 6 * 8;
        if (debugEntryOffset + 8 > bytes.Length) return false;

        var rva  = BitConverter.ToUInt32(bytes, debugEntryOffset);
        var size = BitConverter.ToUInt32(bytes, debugEntryOffset + 4);
        if (rva == 0 && size == 0) return false; // already absent

        Array.Clear(bytes, debugEntryOffset, 8);
        return true;
    }

    /// <summary>
    /// Locates and zeros the Rich header (if present) between the DOS stub and the PE header.
    /// The Rich header is a Microsoft linker artifact that encodes the compiler tool versions used.
    /// </summary>
    private static bool StripRichHeader(byte[] bytes, int peOffset)
    {
        // Scan for the "Rich" signature (52 69 63 68) in the DOS stub region.
        for (var i = 0x40; i < peOffset - 8; i++)
        {
            if (bytes[i] != 0x52 || bytes[i + 1] != 0x69 || bytes[i + 2] != 0x63 || bytes[i + 3] != 0x68)
                continue;

            // Found "Rich" at offset i; key is the following 4 bytes.
            var key = BitConverter.ToUInt32(bytes, i + 4);

            // The Rich header starts with "DanS" XOR'd with key.
            // "DanS" in little-endian = 0x536E6144.
            var danSExpected = 0x536E6144u ^ key;
            for (var j = 0x40; j < i; j += 4)
            {
                if (j + 4 > bytes.Length) break;
                if (BitConverter.ToUInt32(bytes, j) != danSExpected) continue;

                // Zero from the "DanS" start to the end of "Rich" + key.
                var richEnd = i + 8;
                if (richEnd <= bytes.Length)
                {
                    Array.Clear(bytes, j, richEnd - j);
                    return true;
                }
            }

            // "Rich" found but "DanS" not located — zero just the signature.
            Array.Clear(bytes, i, 8);
            return true;
        }

        return false;
    }
}
