using System.Security.Cryptography;
using Mono.Cecil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    /// <summary>
    /// Embeds <paramref name="watermark"/> into the assembly as an unreferenced FieldRVA blob.
    /// Layout: 8-byte magic prefix (stable per-project, owner-known) ‖ watermark XOR'd with a
    /// random 4-byte key ‖ the key itself.  An attacker cannot distinguish this from cipher blobs;
    /// the owner strips the prefix and XORs back to recover the original bytes.
    /// </summary>
    private static void EmbedWatermark(ModuleDefinition module, TypeDefinition holder, byte[] watermark)
    {
        // Stable magic prefix — identifies watermark blobs. Change per project for uniqueness.
        Span<byte> magic = [0xD0, 0x4E, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63]; // "DNProtec" in hex

        Span<byte> keyBuf = stackalloc byte[4];
        RandomNumberGenerator.Fill(keyBuf);

        var payload = new byte[magic.Length + watermark.Length + 4];
        magic.CopyTo(payload.AsSpan());
        for (var i = 0; i < watermark.Length; i++)
            payload[magic.Length + i] = (byte)(watermark[i] ^ keyBuf[i % 4]);
        keyBuf.CopyTo(payload.AsSpan(magic.Length + watermark.Length));

        var name = "wm_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        CreateNamedBlobMethod(module, holder, name, payload);
    }
}
