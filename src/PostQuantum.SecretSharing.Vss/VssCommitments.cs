using PostQuantum.SecretSharing.Vss.Internal;

namespace PostQuantum.SecretSharing.Vss;

/// <summary>
/// The dealer's public Pedersen commitment broadcast for one split. It reveals
/// <b>nothing</b> about the secret (the commitments are perfectly hiding), and is the
/// value every trustee verifies their share against. Treat it like the dealer public
/// key: <b>pin/broadcast it non-equivocably</b> — the consistency guarantee is only as
/// trustworthy as every trustee seeing the <em>same</em> commitments.
/// </summary>
public sealed class VssCommitments
{
    private readonly byte[] _bytes;

    internal VssCommitments(CommitmentsData data, byte[] canonicalBytes)
    {
        Data = data;
        _bytes = canonicalBytes;
    }

    internal CommitmentsData Data { get; }

    /// <summary>The threshold <c>K</c>.</summary>
    public int Threshold => Data.K;

    /// <summary>The total number of shares <c>N</c>.</summary>
    public int TotalShares => Data.N;

    /// <summary>The secret length in bytes this split commits to.</summary>
    public int SecretLength => Data.SecretLength;

    /// <summary>Canonical <c>.pqss</c> v2 bytes of the commitment broadcast, for distribution.</summary>
    public byte[] Export() => (byte[])_bytes.Clone();

    /// <summary>Strict, fail-closed parse of a commitment broadcast.</summary>
    /// <exception cref="ShareFormatException">If the bytes are not a canonical, valid commitment record.</exception>
    public static VssCommitments Import(ReadOnlySpan<byte> bytes) =>
        new(Vss2Format.DecodeCommitments(bytes), bytes.ToArray());
}
