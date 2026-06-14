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

    /// <summary>
    /// <see langword="true"/> if the broadcast carries a dealer signature (ML-DSA-65) over
    /// its contents. Verify it with <see cref="VerifyDealerSignature(ReadOnlySpan{byte})"/>.
    /// An unsigned broadcast must be pinned out-of-band instead.
    /// </summary>
    public bool IsDealerSigned => Data.AuthKind == ShareAuthenticationKind.MlDsa65;

    /// <summary>
    /// The ML-DSA-65 dealer public key embedded in (and bound by) a signed broadcast, or an
    /// empty span if the broadcast is unsigned.
    /// </summary>
    public ReadOnlyMemory<byte> DealerPublicKey => Data.DealerPublicKey ?? ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// Verifies the dealer signature over this broadcast against the trustee's
    /// <paramref name="pinnedDealerPublicKey"/>. Returns <see langword="true"/> iff the
    /// broadcast is signed, its embedded dealer key equals the pinned key, and the signature
    /// validates. This authenticates the pin itself: a trustee who has pinned the dealer key
    /// out-of-band can confirm the broadcast it received was produced by that dealer and not
    /// substituted by a man-in-the-middle. It does <b>not</b> replace per-share
    /// <see cref="VssShare.Verify(VssCommitments)"/> — that proves share/polynomial consistency.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// If ML-DSA-65 verification is unavailable on this target/platform (requires net10.0 with
    /// a supporting backend; see the README platform matrix).
    /// </exception>
    public bool VerifyDealerSignature(ReadOnlySpan<byte> pinnedDealerPublicKey)
    {
        if (!IsDealerSigned)
            return false;
        if (!pinnedDealerPublicKey.SequenceEqual(Data.DealerPublicKey))
            return false;

        byte[] payload = Vss2Format.EncodeCommitmentsSigningPayload(Data, Data.DealerPublicKey!);
        return ShareSignatureVerifier.Verify(
            Data.AuthKind, Data.DealerPublicKey!, payload, Data.Signature!);
    }

    /// <summary>Canonical <c>.pqss</c> v2 bytes of the commitment broadcast, for distribution.</summary>
    public byte[] Export() => (byte[])_bytes.Clone();

    /// <summary>Strict, fail-closed parse of a commitment broadcast.</summary>
    /// <exception cref="ShareFormatException">If the bytes are not a canonical, valid commitment record.</exception>
    public static VssCommitments Import(ReadOnlySpan<byte> bytes) =>
        new(Vss2Format.DecodeCommitments(bytes), bytes.ToArray());
}
