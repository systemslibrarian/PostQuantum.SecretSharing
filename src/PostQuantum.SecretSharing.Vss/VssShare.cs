using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PostQuantum.SecretSharing.Vss.Internal;

namespace PostQuantum.SecretSharing.Vss;

/// <summary>
/// One trustee's verifiable share. Unlike a plain Shamir share, a trustee can
/// <see cref="Verify"/> it against the dealer's public <see cref="VssCommitments"/>
/// <em>before</em> any reconstruction, proving it lies on the single committed
/// polynomial — i.e. that a malicious dealer did not hand out inconsistent shares.
/// </summary>
public sealed class VssShare
{
    private readonly byte[] _bytes;

    internal VssShare(ShareData data, byte[] canonicalBytes)
    {
        Data = data;
        _bytes = canonicalBytes;
    }

    internal ShareData Data { get; }

    /// <summary>This share's 1-based index <c>i</c>.</summary>
    public int ShareIndex => Data.Index;

    /// <summary>The threshold <c>K</c>.</summary>
    public int Threshold => Data.K;

    /// <summary>The total number of shares <c>N</c>.</summary>
    public int TotalShares => Data.N;

    /// <summary>Canonical <c>.pqss</c> v2 bytes of this share, for distribution.</summary>
    public byte[] Export() => (byte[])_bytes.Clone();

    /// <summary>Strict, fail-closed parse of a VSS share.</summary>
    /// <exception cref="ShareFormatException">If the bytes are not a canonical, valid share record.</exception>
    public static VssShare Import(ReadOnlySpan<byte> bytes) =>
        new(Vss2Format.DecodeShare(bytes), bytes.ToArray());

    /// <summary>
    /// Verifies this share against the dealer's commitments: checks, for every chunk,
    /// that <c>sᵢ·G + tᵢ·H == Σⱼ iʲ·Cⱼ</c>. Returns <see langword="true"/> iff the share
    /// is consistent with the committed polynomials. A trustee should call this when the
    /// share is received and reject the ceremony on <see langword="false"/>.
    /// </summary>
    public bool Verify(VssCommitments commitments)
    {
        ArgumentNullException.ThrowIfNull(commitments);
        CommitmentsData c = commitments.Data;
        ShareData s = Data;

        if (c.K != s.K || c.N != s.N || c.SecretLength != s.SecretLength
            || c.Points.Length != s.S.Length
            || !c.SplitId.AsSpan().SequenceEqual(s.SplitId))
            return false;
        if (s.Index < 1 || s.Index > s.N)
            return false;

        BigInteger x = BigInteger.ValueOf(s.Index);
        for (int k = 0; k < c.Points.Length; k++)
        {
            ECPoint lhs = Secp256r1Group.OpenLhs(s.S[k], s.T[k]);
            ECPoint rhs = Secp256r1Group.CommittedEvaluation(c.Points[k], x);
            if (!Secp256r1Group.PointsEqual(lhs, rhs))
                return false;
        }
        return true;
    }
}
