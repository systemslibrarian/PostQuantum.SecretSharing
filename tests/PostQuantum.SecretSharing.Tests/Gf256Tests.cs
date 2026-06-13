using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

public class Gf256Tests
{
    [Fact]
    public void MulTable_FullDigest_MatchesReferenceVector()
    {
        // Recompute the entire 256x256 multiplication table via Gf256.Mul and
        // compare its SHA-256 digest to the independent Python reference. One
        // assertion that exercises every (a,b) pair.
        byte[] table = new byte[256 * 256];
        for (int a = 0; a < 256; a++)
            for (int b = 0; b < 256; b++)
                table[a * 256 + b] = Gf256.Mul((byte)a, (byte)b);

        string digest = Convert.ToHexString(SHA256.HashData(table)).ToLowerInvariant();
        Assert.Equal(Vectors.File.GfMulTableSha256, digest);
    }

    [Fact]
    public void Inverses_1_To_255_MatchReferenceVector()
    {
        int[] expected = Vectors.File.GfInverses;
        Assert.Equal(255, expected.Length);
        for (int a = 1; a <= 255; a++)
            Assert.Equal(expected[a - 1], Gf256.Inv((byte)a));
    }

    [Fact]
    public void Inverse_RoundTrips_ToOne()
    {
        for (int a = 1; a <= 255; a++)
            Assert.Equal(1, Gf256.Mul((byte)a, Gf256.Inv((byte)a)));
    }

    [Fact]
    public void Inverse_OfZero_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => Gf256.Inv(0));
    }

    [Fact]
    public void Add_IsXor()
    {
        for (int a = 0; a < 256; a += 17)
            for (int b = 0; b < 256; b += 13)
                Assert.Equal((byte)(a ^ b), Gf256.Add((byte)a, (byte)b));
    }

    [Fact]
    public void Mul_IsCommutative_AndHasIdentity()
    {
        for (int a = 0; a < 256; a += 7)
        {
            Assert.Equal((byte)a, Gf256.Mul((byte)a, 1));
            Assert.Equal(0, Gf256.Mul((byte)a, 0));
            for (int b = 0; b < 256; b += 11)
                Assert.Equal(Gf256.Mul((byte)a, (byte)b), Gf256.Mul((byte)b, (byte)a));
        }
    }
}
