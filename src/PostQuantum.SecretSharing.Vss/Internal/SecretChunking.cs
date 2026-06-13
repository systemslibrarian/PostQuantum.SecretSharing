using Org.BouncyCastle.Math;

namespace PostQuantum.SecretSharing.Vss.Internal;

/// <summary>
/// Encodes a secret byte string as a sequence of scalar-field elements and back.
/// Each element holds at most <see cref="ChunkBytes"/> = 31 bytes (248 bits), which is
/// strictly less than the 256-bit group order <c>q</c>, so every chunk is an unambiguous
/// element &lt; <c>q</c> (no modular wraparound) and the mapping is injective.
/// See <c>docs/VSS-DESIGN.md</c> §3.2.
/// </summary>
internal static class SecretChunking
{
    /// <summary>Maximum bytes carried by one field element (248 bits &lt; 256-bit q).</summary>
    internal const int ChunkBytes = 31;

    /// <summary>Number of field elements needed to carry <paramref name="secretLength"/> bytes.</summary>
    internal static int ChunkCount(int secretLength) =>
        secretLength == 0 ? 0 : (secretLength + ChunkBytes - 1) / ChunkBytes;

    /// <summary>Splits a secret into big-endian field elements, 31 bytes per element.</summary>
    internal static BigInteger[] ToElements(ReadOnlySpan<byte> secret)
    {
        int m = ChunkCount(secret.Length);
        var elements = new BigInteger[m];
        for (int k = 0; k < m; k++)
        {
            int offset = k * ChunkBytes;
            int width = Math.Min(ChunkBytes, secret.Length - offset);
            elements[k] = new BigInteger(1, secret.Slice(offset, width).ToArray());
        }
        return elements;
    }

    /// <summary>
    /// Reassembles the secret from its field elements, given the original length so the
    /// final (possibly short) chunk and any leading zero bytes are restored exactly.
    /// </summary>
    internal static byte[] FromElements(BigInteger[] elements, int secretLength)
    {
        var secret = new byte[secretLength];
        for (int k = 0; k < elements.Length; k++)
        {
            int offset = k * ChunkBytes;
            int width = Math.Min(ChunkBytes, secretLength - offset);
            byte[] raw = elements[k].ToByteArrayUnsigned();
            if (raw.Length > width)
                throw new ShareConsistencyException("Recovered chunk wider than its declared length.");
            // Right-align into the fixed-width window (restores leading zeros).
            Array.Copy(raw, 0, secret, offset + (width - raw.Length), raw.Length);
        }
        return secret;
    }
}
