using System.Security.Cryptography;

namespace PostQuantum.SecretSharing;

/// <summary>
/// A lightweight, dealer-published commitment to <em>the single intended secret</em>.
/// The dealer computes it once with <see cref="Compute"/> and publishes it
/// out-of-band to every trustee; each quorum checks its reconstructed secret with
/// <see cref="Verify(ZeroizingBuffer, ReadOnlySpan{byte})"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is for.</b> The embedded per-share check value confirms that a
/// quorum recovered a self-consistent secret, but it cannot catch a dealer who
/// hands different (internally consistent) splits to different quorums — each
/// reconstructs and check-verifies its own secret. A single commitment published
/// to <em>all</em> trustees lets them notice that two quorums recovered different
/// values: at most one can match the published commitment.
/// </para>
/// <para>
/// <b>What this is NOT.</b> This is <em>not</em> Verifiable Secret Sharing. It does
/// not prove, before reconstruction, that the shares are consistent, and its
/// guarantee holds only if the commitment is published through a channel the
/// dealer cannot equivocate on (e.g. a broadcast all trustees see the same way) —
/// exactly like pinning the dealer public key. A dealer who can show different
/// commitments to different parties is not constrained by it. True VSS
/// (Feldman/Pedersen) is a v2 goal; see KNOWN-GAPS.md.
/// </para>
/// <para>
/// <b>Oracle caveat.</b> The commitment is a hash of the secret, so for a
/// low-entropy secret it is an offline guessing oracle, just like the check value.
/// Commit to high-entropy secrets (or commit to the KEK of a wrapped secret).
/// </para>
/// </remarks>
public static class DealerCommitment
{
    /// <summary>The commitment length in bytes (SHA-256).</summary>
    public const int Length = 32;

    /// <summary>
    /// Computes the commitment <c>SHA-256(secret)</c>. The dealer publishes this
    /// once, out-of-band, to all trustees.
    /// </summary>
    public static byte[] Compute(ReadOnlySpan<byte> secret) => SHA256.HashData(secret);

    /// <summary>Constant-time check that <paramref name="reconstructed"/> matches <paramref name="commitment"/>.</summary>
    public static bool Verify(ReadOnlySpan<byte> reconstructed, ReadOnlySpan<byte> commitment)
    {
        if (commitment.Length != Length)
            return false;
        Span<byte> actual = stackalloc byte[Length];
        SHA256.HashData(reconstructed, actual);
        return CryptographicOperations.FixedTimeEquals(actual, commitment);
    }

    /// <summary>Constant-time check that a reconstructed-secret buffer matches <paramref name="commitment"/>.</summary>
    public static bool Verify(ZeroizingBuffer reconstructed, ReadOnlySpan<byte> commitment)
    {
        ArgumentNullException.ThrowIfNull(reconstructed);
        return Verify(reconstructed.Span, commitment);
    }
}
