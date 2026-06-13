using System.Security.Cryptography;
using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Vss;
using PostQuantum.SecretSharing.Vss.Internal;
using Xunit;

namespace PostQuantum.SecretSharing.Vss.Tests;

/// <summary>
/// End-to-end behavior of the Pedersen VSS public API: honest splits verify and
/// reconstruct, every quorum agrees, and tampering / a malicious dealer / operator
/// error are detected and rejected — never silently mis-reconstructed.
/// </summary>
public class VssTests
{
    private static byte[] RandomSecret(int len)
    {
        byte[] s = new byte[len];
        RandomNumberGenerator.Fill(s);
        return s;
    }

    [Theory]
    [InlineData(2, 3, 1)]
    [InlineData(3, 5, 16)]
    [InlineData(3, 5, 31)]   // exactly one chunk
    [InlineData(3, 5, 32)]   // spills into a second chunk
    [InlineData(5, 9, 64)]
    [InlineData(2, 2, 100)]  // multi-chunk, no redundancy
    public void Honest_split_verifies_and_reconstructs(int k, int n, int len)
    {
        byte[] secret = RandomSecret(len);
        VssSplit split = PedersenVss.Split(secret, new SharePolicy(k, n));

        Assert.Equal(n, split.Shares.Length);
        Assert.All(split.Shares, s => Assert.True(s.Verify(split.Commitments)));

        using ZeroizingBuffer recovered = PedersenVss.Reconstruct(
            split.Shares.Take(k).ToArray(), split.Commitments);
        Assert.True(recovered.Span.SequenceEqual(secret));
    }

    [Fact]
    public void Every_quorum_reconstructs_the_same_secret()
    {
        byte[] secret = RandomSecret(40);
        VssSplit split = PedersenVss.Split(secret, new SharePolicy(3, 5));
        VssShare[] s = split.Shares;

        int[][] quorums = { new[] { 0, 1, 2 }, new[] { 2, 3, 4 }, new[] { 0, 2, 4 }, new[] { 1, 3, 4 } };
        foreach (int[] q in quorums)
        {
            using ZeroizingBuffer r = PedersenVss.Reconstruct(
                new[] { s[q[0]], s[q[1]], s[q[2]] }, split.Commitments);
            Assert.True(r.Span.SequenceEqual(secret));
        }
    }

    [Fact]
    public void Reconstruct_requires_exactly_k_shares()
    {
        VssSplit split = PedersenVss.Split(RandomSecret(32), new SharePolicy(3, 5));
        Assert.Throws<SharePolicyException>(() =>
            PedersenVss.Reconstruct(split.Shares.Take(2).ToArray(), split.Commitments));
        Assert.Throws<SharePolicyException>(() =>
            PedersenVss.Reconstruct(split.Shares.Take(4).ToArray(), split.Commitments));
    }

    [Fact]
    public void Duplicate_share_index_is_rejected()
    {
        VssSplit split = PedersenVss.Split(RandomSecret(32), new SharePolicy(3, 5));
        Assert.Throws<ShareConsistencyException>(() =>
            PedersenVss.Reconstruct(new[] { split.Shares[0], split.Shares[0], split.Shares[1] }, split.Commitments));
    }

    [Fact]
    public void Shares_from_different_splits_are_rejected()
    {
        byte[] secret = RandomSecret(32);
        VssSplit a = PedersenVss.Split(secret, new SharePolicy(3, 5));
        VssSplit b = PedersenVss.Split(secret, new SharePolicy(3, 5));
        Assert.Throws<ShareConsistencyException>(() =>
            PedersenVss.Reconstruct(new[] { a.Shares[0], a.Shares[1], b.Shares[2] }, a.Commitments));
    }

    [Fact]
    public void Malicious_or_tampered_share_fails_verification_and_reconstruction()
    {
        VssSplit split = PedersenVss.Split(RandomSecret(40), new SharePolicy(3, 5));

        // Forge a well-formed-but-inconsistent share by nudging a scalar off the
        // committed polynomial (what a malicious dealer or a tamperer would produce).
        ShareData good = split.Shares[0].Data;
        var badS = (Org.BouncyCastle.Math.BigInteger[])good.S.Clone();
        badS[0] = badS[0].Add(Org.BouncyCastle.Math.BigInteger.One).Mod(Secp256r1Group.Q);
        var forgedData = good with { S = badS };
        VssShare forged = VssShare.Import(Vss2Format.EncodeShare(forgedData));

        Assert.False(forged.Verify(split.Commitments));
        Assert.Throws<ShareConsistencyException>(() =>
            PedersenVss.Reconstruct(new[] { forged, split.Shares[1], split.Shares[2] }, split.Commitments));
    }

    [Fact]
    public void Share_does_not_verify_against_foreign_commitments()
    {
        VssSplit a = PedersenVss.Split(RandomSecret(32), new SharePolicy(3, 5));
        VssSplit b = PedersenVss.Split(RandomSecret(32), new SharePolicy(3, 5));
        Assert.False(a.Shares[0].Verify(b.Commitments));
    }

    [Fact]
    public void Share_and_commitments_export_import_round_trip_byte_identically()
    {
        VssSplit split = PedersenVss.Split(RandomSecret(50), new SharePolicy(3, 5));

        foreach (VssShare s in split.Shares)
        {
            byte[] bytes = s.Export();
            Assert.Equal(bytes, VssShare.Import(bytes).Export());
        }
        byte[] cb = split.Commitments.Export();
        Assert.Equal(cb, VssCommitments.Import(cb).Export());

        // A re-imported share still verifies and still reconstructs.
        VssShare[] reimported = split.Shares.Take(3).Select(s => VssShare.Import(s.Export())).ToArray();
        VssCommitments rc = VssCommitments.Import(split.Commitments.Export());
        Assert.All(reimported, s => Assert.True(s.Verify(rc)));
        using ZeroizingBuffer r = PedersenVss.Reconstruct(reimported, rc);
        Assert.Equal(50, r.Length);
    }

    [Fact]
    public void Empty_or_oversized_secret_is_rejected()
    {
        Assert.Throws<SharePolicyException>(() => PedersenVss.Split(Array.Empty<byte>(), new SharePolicy(2, 3)));
        Assert.Throws<SharePolicyException>(() => PedersenVss.Split(new byte[65537], new SharePolicy(2, 3)));
    }

    [Fact]
    public void Reconstruct_recovers_secrets_with_leading_zero_bytes()
    {
        // Leading zeros must survive the BigInteger element round-trip.
        byte[] secret = new byte[31];
        secret[30] = 0x01; // value 1, 30 leading zero bytes
        VssSplit split = PedersenVss.Split(secret, new SharePolicy(2, 3));
        using ZeroizingBuffer r = PedersenVss.Reconstruct(split.Shares.Take(2).ToArray(), split.Commitments);
        Assert.True(r.Span.SequenceEqual(secret));
    }
}
