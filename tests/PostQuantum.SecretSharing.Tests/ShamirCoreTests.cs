using Xunit;

namespace PostQuantum.SecretSharing.Tests;

public class ShamirCoreTests
{
    /// <summary>
    /// Drives <see cref="ShamirCore.Split"/> with the exact fixed coefficients
    /// from each published split vector and asserts the resulting shares match
    /// the independent Python reference byte-for-byte.
    /// </summary>
    [Fact]
    public void Split_FixedCoefficients_MatchReferenceVectors()
    {
        foreach (SplitVector v in Vectors.File.Split)
        {
            byte[] secret = Vectors.Hex(v.Secret);

            // The (k-1)*len coefficient matrix in row-major order is exactly the
            // concatenation of the per-power coefficient rows.
            byte[] coeffMatrix = v.CoeffRows.SelectMany(Vectors.Hex).ToArray();
            Assert.Equal((v.K - 1) * v.SecretLength, coeffMatrix.Length);

            int offset = 0;
            ShamirCore.RandomFill fill = dest =>
            {
                coeffMatrix.AsSpan(offset, dest.Length).CopyTo(dest);
                offset += dest.Length;
            };

            byte[][] shares = ShamirCore.Split(secret, v.K, v.N, fill);

            Assert.Equal(v.N, shares.Length);
            foreach (ShareVector sv in v.Shares)
            {
                byte[] expectedY = Vectors.Hex(sv.Y);
                Assert.Equal(expectedY, shares[sv.X - 1]);
            }
        }
    }

    [Fact]
    public void Reconstruct_MatchesReferenceVectors()
    {
        foreach (ReconstructVector v in Vectors.File.Reconstruct)
        {
            byte[] xs = v.Shares.Select(s => (byte)s.X).ToArray();
            var ys = v.Shares.Select(s => Vectors.Hex(s.Y)).ToList();
            byte[] expected = Vectors.Hex(v.ExpectedSecret);

            byte[] output = new byte[expected.Length];
            ShamirCore.Reconstruct(xs, ys, output);

            Assert.Equal(expected, output);
        }
    }

    /// <summary>
    /// Demonstrates (not proves) information-theoretic secrecy: with k=3, two
    /// shares constrain the secret to nothing. For every one of the 256 candidate
    /// values of a 1-byte secret, there exists a consistent degree-2 polynomial
    /// passing through the two known shares — so the two shares are equally
    /// compatible with all 256 secrets.
    /// </summary>
    [Fact]
    public void TwoSharesOfThree_AreConsistentWithEverySecret()
    {
        // A real 3-of-5 split of a 1-byte secret; coefficients are arbitrary here.
        byte[] secret = { 0x42 };
        byte[] coeff = { 0x9A, 0x3C }; // c1, c2 for the single byte (matrix is 2*1)
        int off = 0;
        ShamirCore.RandomFill fill = d => { coeff.AsSpan(off, d.Length).CopyTo(d); off += d.Length; };
        byte[][] shares = ShamirCore.Split(secret, k: 3, n: 5, fill);

        byte x1 = 1, x2 = 2;
        byte y1 = shares[0][0], y2 = shares[1][0];

        int consistent = 0;
        for (int s = 0; s < 256; s++)
        {
            // Solve for (a1, a2) such that p(x) = s + a1*x + a2*x^2 passes through
            // (x1,y1),(x2,y2):
            //   a1*x1 + a2*x1^2 = y1 ^ s
            //   a1*x2 + a2*x2^2 = y2 ^ s
            byte r1 = (byte)(y1 ^ s);
            byte r2 = (byte)(y2 ^ s);
            byte x1sq = Gf256.Mul(x1, x1);
            byte x2sq = Gf256.Mul(x2, x2);

            // Cramer's rule over GF(2^8). Determinant is nonzero for distinct x.
            byte det = (byte)(Gf256.Mul(x1, x2sq) ^ Gf256.Mul(x2, x1sq));
            Assert.NotEqual(0, det);
            byte a1 = Gf256.Div((byte)(Gf256.Mul(r1, x2sq) ^ Gf256.Mul(r2, x1sq)), det);
            byte a2 = Gf256.Div((byte)(Gf256.Mul(x1, r2) ^ Gf256.Mul(x2, r1)), det);

            byte p1 = (byte)(s ^ Gf256.Mul(a1, x1) ^ Gf256.Mul(a2, x1sq));
            byte p2 = (byte)(s ^ Gf256.Mul(a1, x2) ^ Gf256.Mul(a2, x2sq));
            if (p1 == y1 && p2 == y2)
                consistent++;
        }

        Assert.Equal(256, consistent);
    }
}
