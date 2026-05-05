using System.Runtime.CompilerServices;

namespace DotNetProtect.Runtime;

/// <summary>
/// XOR obfuscation of primitive bit patterns (AOT-safe: no reflection).
/// Key is a 4-byte int; each data byte is XORed with <c>keyBytes[i % 4]</c>,
/// making brute-force 256× harder than a single-byte key.
/// </summary>
public static class ConstantDecrypt
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int FromXorInt32(byte[] data, int key)
    {
        if (data is null || data.Length != 4)
            return 0;

        return BitConverter.ToInt32(data) ^ key;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static long FromXorInt64(byte[] data, int key)
    {
        if (data is null || data.Length != 8)
            return 0;

        var lo = (long)(uint)(BitConverter.ToInt32(data, 0) ^ key);
        var hi = (long)(uint)(BitConverter.ToInt32(data, 4) ^ key);
        return lo | (hi << 32);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static float FromXorSingle(byte[] data, int key)
    {
        if (data is null || data.Length != 4)
            return 0f;

        var bits = BitConverter.ToInt32(data) ^ key;
        return BitConverter.Int32BitsToSingle(bits);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static double FromXorDouble(byte[] data, int key)
    {
        if (data is null || data.Length != 8)
            return 0d;

        var lo = (long)(uint)(BitConverter.ToInt32(data, 0) ^ key);
        var hi = (long)(uint)(BitConverter.ToInt32(data, 4) ^ key);
        var bits = lo | (hi << 32);
        return BitConverter.Int64BitsToDouble(bits);
    }

    /// <summary>
    /// XOR of an entire buffer with a 4-byte rolling key.
    /// The weaver does not emit this automatically; use manually for custom byte patterns.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static byte[] FromXorBytes(byte[]? data, int key)
    {
        if (data is null || data.Length == 0)
            return Array.Empty<byte>();

        Span<byte> keyBytes = stackalloc byte[4];
        BitConverter.TryWriteBytes(keyBytes, key);

        var r = new byte[data.Length];
        for (var i = 0; i < data.Length; i++)
            r[i] = (byte)(data[i] ^ keyBytes[i % 4]);

        return r;
    }
}
