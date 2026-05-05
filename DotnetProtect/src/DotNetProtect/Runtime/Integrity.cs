using System.Security.Cryptography;

namespace DotNetProtect.Runtime;

/// <summary>
/// Build-time keyed digest over ordered blob payloads (weaver-generated callsites). AOT-safe.
/// </summary>
public static class Integrity
{
    /// <summary>
    /// Verifies <c>SHA256(seed || chunk[0] || chunk[1] || …) == expectedSha256</c> using a fixed-time comparison.
    /// Chunks are pulled via <paramref name="getChunk"/> one at a time so only one blob payload
    /// needs to be live in memory (plus the incremental hasher state).
    /// On mismatch the process terminates immediately via <see cref="Environment.FailFast(string?)"/>.
    /// </summary>
    public static void VerifyTableOrFail(byte[]? seed, byte[]? expectedSha256, int chunkCount, Func<int, byte[]>? getChunk)
    {
        if (chunkCount < 0)
            Environment.FailFast(null);
        if (chunkCount > 0 && getChunk is null)
            Environment.FailFast(null);
        if (seed is null || seed.Length != 16 || expectedSha256 is null || expectedSha256.Length != 32)
            Environment.FailFast(null);

        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData(seed);
        if (chunkCount > 0)
        {
            var g = getChunk!;
            for (var i = 0; i < chunkCount; i++)
            {
                var c = g(i);
                if (c is null)
                    Environment.FailFast(null);
                h.AppendData(c);
            }
        }

        var digest = h.GetHashAndReset();
        if (!CryptographicOperations.FixedTimeEquals(digest, expectedSha256))
            Environment.FailFast(null);
    }
}
