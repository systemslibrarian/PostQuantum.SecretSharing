using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

public class FacadeTests
{
    private static SecretShare[] Split(byte[] secret, int k, int n)
        => ShamirSecretSharing.Split(secret, new SharePolicy(k, n));

    // --- Split policy validation ---

    [Fact]
    public void Split_ThresholdOne_Throws()
        => Assert.Throws<SharePolicyException>(() => Split(new byte[32], 1, 3));

    [Fact]
    public void Split_ThresholdGreaterThanTotal_Throws()
        => Assert.Throws<SharePolicyException>(() => Split(new byte[32], 4, 3));

    [Fact]
    public void Split_TotalAbove255_Throws()
        => Assert.Throws<SharePolicyException>(() => Split(new byte[32], 2, 256));

    [Fact]
    public void Split_EmptySecret_Throws()
        => Assert.Throws<SharePolicyException>(() => Split(Array.Empty<byte>(), 2, 3));

    [Fact]
    public void Split_SecretTooLong_Throws()
        => Assert.Throws<SharePolicyException>(() => Split(new byte[65537], 2, 3));

    [Fact]
    public void Split_ProducesNDistinctIndexedShares()
    {
        SecretShare[] shares = Split(RandomNumberGenerator.GetBytes(16), 3, 5);
        Assert.Equal(5, shares.Length);
        Assert.Equal(new[] { 1, 2, 3, 4, 5 }, shares.Select(s => s.ShareIndex).OrderBy(x => x).ToArray());
        // All shares of one split share the same splitId.
        Assert.All(shares, s => Assert.True(s.SplitId.Span.SequenceEqual(shares[0].SplitId.Span)));
    }

    // --- Reconstruct: counting ---

    [Fact]
    public void Reconstruct_FewerThanK_Throws()
    {
        SecretShare[] shares = Split(new byte[32], 2, 3);
        Assert.Throws<SharePolicyException>(() => ShamirSecretSharing.Reconstruct(new[] { shares[0] }));
    }

    [Fact]
    public void Reconstruct_MoreThanK_Throws()
    {
        SecretShare[] shares = Split(new byte[32], 2, 3);
        Assert.Throws<SharePolicyException>(() => ShamirSecretSharing.Reconstruct(shares));
    }

    [Fact]
    public void Reconstruct_ExactlyK_Succeeds()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        SecretShare[] shares = Split(secret, 2, 3);
        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[2] });
        Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));
    }

    // --- Reconstruct: consistency corpus ---

    [Fact]
    public void Reconstruct_FlippedShareDataBit_ThrowsConsistency()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        SecretShare[] shares = Split(secret, 2, 3);
        SecretShare tampered = TamperShareData(shares[1]);
        Assert.Throws<ShareConsistencyException>(
            () => ShamirSecretSharing.Reconstruct(new[] { shares[0], tampered }));
    }

    [Fact]
    public void Reconstruct_MixedSplitIds_ThrowsConsistency()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        SecretShare[] a = Split(secret, 2, 3);
        SecretShare[] b = Split(secret, 2, 3); // different splitId
        Assert.Throws<ShareConsistencyException>(
            () => ShamirSecretSharing.Reconstruct(new[] { a[0], b[1] }));
    }

    [Fact]
    public void Reconstruct_DuplicateIndex_ThrowsConsistency()
    {
        SecretShare[] shares = Split(new byte[32], 2, 3);
        Assert.Throws<ShareConsistencyException>(
            () => ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[0] }));
    }

    [Fact]
    public void Reconstruct_MismatchedMetadata_ThrowsConsistency()
    {
        SecretShare[] a = Split(new byte[32], 2, 3);
        SecretShare[] b = Split(new byte[16], 2, 3); // different secretLength
        Assert.Throws<ShareConsistencyException>(
            () => ShamirSecretSharing.Reconstruct(new[] { a[0], b[1] }));
    }

    // --- Reconstruct: pin against unauthenticated shares ---

    [Fact]
    public void Reconstruct_PinnedKey_AgainstUnauthenticatedShares_ThrowsAuth()
    {
        SecretShare[] shares = Split(new byte[32], 2, 3);
        ReadOnlyMemory<byte> pin = new byte[SecretShare.MlDsa65PublicKeyLength];
        Assert.Throws<ShareAuthenticationException>(
            () => ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[1] }, pin));
    }

    /// <summary>
    /// Builds a corrupted copy of a share (one flipped share-data bit) reusing the
    /// internal constructor so all other fields — including the check value —
    /// remain those of the original split.
    /// </summary>
    private static SecretShare TamperShareData(SecretShare s)
    {
        byte[] badY = s.ShareData.ToArray();
        badY[0] ^= 0x01;
        return new SecretShare(
            s.Threshold, s.TotalShares, s.ShareIndex, s.SplitId.ToArray(), s.SecretLength,
            badY, s.CheckValue.ToArray(), s.Authentication, s.DealerPublicKey.ToArray(), s.Signature.ToArray());
    }
}
