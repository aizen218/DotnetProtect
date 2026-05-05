using System.Security.Cryptography;
using System.Text;

namespace DotNetProtect.Runtime;

/// <summary>
/// Called from weaver-injected IL. AOT-friendly: no reflection.
/// Payload layout: 16-byte IV followed by AES-256-CBC ciphertext (PKCS7) of UTF-8 plaintext.
/// </summary>
public static class StringDecrypt
{
    public static string FromAes256CbcUtf8(byte[] ivAndCiphertext, byte[] key)
    {
        if (ivAndCiphertext is null || ivAndCiphertext.Length <= 16)
            return string.Empty;

        if (key is null || key.Length != 32)
            throw new ArgumentException("AES-256 requires a 32-byte key.", nameof(key));

        var cipherLen = ivAndCiphertext.Length - 16;
        if (cipherLen <= 0 || (cipherLen & 0xF) != 0)
            return string.Empty;

        var iv = new byte[16];
        Buffer.BlockCopy(ivAndCiphertext, 0, iv, 0, 16);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;

        try
        {
            using var decryptor = aes.CreateDecryptor();
            var plain = decryptor.TransformFinalBlock(ivAndCiphertext, 16, cipherLen);
            return Encoding.UTF8.GetString(plain);
        }
        catch (CryptographicException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Combines three equal-length byte arrays via XOR. The master key is split into three
    /// FieldRVA fragments at build time (key = a ^ b ^ c) so a single <c>strings</c> / hex
    /// scan over the AOT binary cannot reveal it; an attacker has to identify and combine
    /// all three fragments.
    /// </summary>
    public static byte[] CombineKey(byte[] a, byte[] b, byte[] c)
    {
        if (a is null || b is null || c is null)
            return Array.Empty<byte>();
        if (a.Length != b.Length || b.Length != c.Length)
            return Array.Empty<byte>();

        var r = new byte[a.Length];
        for (var i = 0; i < r.Length; i++)
            r[i] = (byte)(a[i] ^ b[i] ^ c[i]);
        return r;
    }

    /// <summary>
    /// Combines five equal-length byte arrays via XOR. Used when the master key is split into
    /// five FieldRVA fragments (key = a ^ b ^ c ^ d ^ e). Five fragments require locating and
    /// correlating more RVA payloads, raising the bar for manual key extraction.
    /// </summary>
    public static byte[] CombineKey5(byte[] a, byte[] b, byte[] c, byte[] d, byte[] e)
    {
        if (a is null || b is null || c is null || d is null || e is null)
            return Array.Empty<byte>();
        if (a.Length != b.Length || b.Length != c.Length || c.Length != d.Length || d.Length != e.Length)
            return Array.Empty<byte>();

        var r = new byte[a.Length];
        for (var i = 0; i < r.Length; i++)
            r[i] = (byte)(a[i] ^ b[i] ^ c[i] ^ d[i] ^ e[i]);
        return r;
    }
}
