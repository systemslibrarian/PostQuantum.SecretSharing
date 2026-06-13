using System.Security.Cryptography;
using FsCheck;
using FsCheck.Xunit;
using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Vss;
using PostQuantum.SecretSharing.Vss.Internal;
using Xunit;
using BigInteger = Org.BouncyCastle.Math.BigInteger;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace PostQuantum.SecretSharing.Vss.Tests;

/// <summary>
/// Fail-closed parsing of the <c>.pqss</c> v2 records, and direct correctness checks on
/// the group math (P-256), scalar/point codecs, GF(q) interpolation, and secret chunking.
/// </summary>
public class VssFormatAndMathTests
{
    private static readonly byte[] SampleShare =
        PedersenVss.Split(RandomBytes(40), new SharePolicy(3, 5)).Shares[0].Export();

    private static readonly byte[] SampleCommitments =
        PedersenVss.Split(RandomBytes(40), new SharePolicy(3, 5)).Commitments.Export();

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    // ── Fail-closed format ────────────────────────────────────────────────────

    [Property(MaxTest = 3000)]
    public void Import_of_arbitrary_bytes_only_throws_library_exceptions(byte[]? input)
    {
        input ??= Array.Empty<byte>();
        try { VssShare.Import(input); } catch (SecretSharingException) { }
        try { VssCommitments.Import(input); } catch (SecretSharingException) { }
    }

    [Property(MaxTest = 3000)]
    public void Mutated_valid_share_only_throws_library_exceptions(NonNegativeInt pos, byte val)
    {
        byte[] m = (byte[])SampleShare.Clone();
        m[pos.Get % m.Length] = val;
        try { VssShare.Import(m); } catch (SecretSharingException) { }
    }

    [Property(MaxTest = 3000)]
    public void Mutated_valid_commitments_only_throws_library_exceptions(NonNegativeInt pos, byte val)
    {
        byte[] m = (byte[])SampleCommitments.Clone();
        m[pos.Get % m.Length] = val;
        try { VssCommitments.Import(m); } catch (SecretSharingException) { }
    }

    [Fact]
    public void Truncating_a_valid_record_is_rejected_with_a_format_error()
    {
        for (int cut = 0; cut < SampleShare.Length; cut++)
            Assert.ThrowsAny<SecretSharingException>(() => VssShare.Import(SampleShare.AsSpan(0, cut).ToArray()));
    }

    [Fact]
    public void Trailing_bytes_are_rejected()
    {
        byte[] withTail = new byte[SampleShare.Length + 1];
        SampleShare.CopyTo(withTail, 0);
        Assert.Throws<ShareFormatException>(() => VssShare.Import(withTail));
    }

    // ── Group math ────────────────────────────────────────────────────────────

    [Fact]
    public void Second_generator_H_is_valid_independent_and_deterministic()
    {
        ECPoint h = Secp256r1Group.H;
        Assert.False(h.IsInfinity);
        Assert.False(Secp256r1Group.PointsEqual(h, Secp256r1Group.G));

        byte[] enc = Secp256r1Group.EncodePoint(h);
        Assert.Equal(Secp256r1Group.PointLength, enc.Length);
        Assert.True(Secp256r1Group.TryDecodePoint(enc, out ECPoint decoded));
        Assert.True(Secp256r1Group.PointsEqual(decoded, h));

        // Pinned vector: the nothing-up-my-sleeve derivation of H must be byte-stable
        // forever (it is part of the wire contract). Anyone can reproduce this from the
        // domain string in Secp256r1Group. Published in docs/test-vectors-vss.md.
        Assert.Equal(
            "02C210CA1DD338B122F04B3FF2C7A7F8360D7C43BCFD9647BD022A845B3C33278C",
            Convert.ToHexString(enc));

        // Cached / deterministic across accesses.
        Assert.True(Secp256r1Group.PointsEqual(Secp256r1Group.H, h));
    }

    [Fact]
    public void Scalar_codec_round_trips_and_rejects_non_canonical()
    {
        for (int i = 0; i < 200; i++)
        {
            BigInteger s = Secp256r1Group.RandomScalar();
            byte[] e = Secp256r1Group.EncodeScalar(s);
            Assert.Equal(Secp256r1Group.ScalarLength, e.Length);
            Assert.True(Secp256r1Group.TryDecodeScalar(e, out BigInteger d));
            Assert.Equal(s, d);
        }

        // q and above are out of range; wrong widths are non-canonical.
        Assert.False(Secp256r1Group.TryDecodeScalar(Secp256r1Group.EncodeScalar(Secp256r1Group.Q), out _));
        byte[] allFf = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        Assert.False(Secp256r1Group.TryDecodeScalar(allFf, out _));
        Assert.False(Secp256r1Group.TryDecodeScalar(new byte[31], out _));
        Assert.False(Secp256r1Group.TryDecodeScalar(new byte[33], out _));
    }

    [Fact]
    public void Point_codec_round_trips_and_rejects_invalid()
    {
        ECPoint c = Secp256r1Group.Commit(Secp256r1Group.RandomScalar(), Secp256r1Group.RandomScalar());
        byte[] e = Secp256r1Group.EncodePoint(c);
        Assert.Equal(Secp256r1Group.PointLength, e.Length);
        Assert.True(Secp256r1Group.TryDecodePoint(e, out ECPoint d));
        Assert.True(Secp256r1Group.PointsEqual(d, c));

        Assert.False(Secp256r1Group.TryDecodePoint(new byte[33], out _));        // wrong/zero
        byte[] badX = new byte[33];
        badX[0] = 0x02;
        for (int i = 1; i < 33; i++) badX[i] = 0xFF;                              // x not on curve
        Assert.False(Secp256r1Group.TryDecodePoint(badX, out _));
        Assert.False(Secp256r1Group.TryDecodePoint(new byte[32], out _));        // wrong length
    }

    [Fact]
    public void Lagrange_interpolation_at_zero_recovers_the_constant_term()
    {
        for (int trial = 0; trial < 50; trial++)
        {
            int k = 2 + trial % 6;
            var coeffs = new BigInteger[k];
            for (int j = 0; j < k; j++) coeffs[j] = Secp256r1Group.RandomScalar();

            var xs = new BigInteger[k];
            var ys = new BigInteger[k];
            for (int i = 0; i < k; i++)
            {
                xs[i] = BigInteger.ValueOf(i + 1);
                ys[i] = Secp256r1Group.Evaluate(coeffs, xs[i]);
            }
            Assert.Equal(coeffs[0], Secp256r1Group.InterpolateAtZero(xs, ys));
        }
    }

    // ── Secret chunking ───────────────────────────────────────────────────────

    [Property(MaxTest = 1000)]
    public void Chunking_round_trips(byte[]? secret)
    {
        if (secret is null || secret.Length == 0 || secret.Length > 4096)
            return;
        BigInteger[] elements = SecretChunking.ToElements(secret);
        Assert.Equal(SecretChunking.ChunkCount(secret.Length), elements.Length);
        Assert.Equal(secret, SecretChunking.FromElements(elements, secret.Length));
    }
}
