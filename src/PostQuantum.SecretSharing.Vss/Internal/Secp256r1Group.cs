using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace PostQuantum.SecretSharing.Vss.Internal;

/// <summary>
/// The prime-order group (NIST P-256 / secp256r1) and its scalar field GF(<c>q</c>),
/// plus the canonical encodings the <c>.pqss</c> v2 format uses. All heavy EC and
/// big-integer arithmetic is delegated to the vetted BouncyCastle implementation; this
/// type is the thin, reviewable adapter around it (see <c>docs/VSS-DESIGN.md</c> §3.1
/// and <c>docs/AUDIT.md</c> §5).
/// </summary>
/// <remarks>
/// This code is deliberately <b>not</b> constant-time: secrecy in Pedersen VSS is
/// information-theoretic (the commitment transcript perfectly hides the secret), so the
/// timing of this arithmetic leaks nothing about the secret. The constant-time path is
/// the GF(2⁸) core, which this package does not touch.
/// </remarks>
internal static class Secp256r1Group
{
    /// <summary>Group identifier recorded in the wire format. 1 == secp256r1.</summary>
    internal const int GroupId = 1;

    /// <summary>Compressed EC point width, in bytes (0x02/0x03 prefix + 32-byte x).</summary>
    internal const int PointLength = 33;

    /// <summary>Scalar (field element) width, in bytes — fixed 32-byte big-endian.</summary>
    internal const int ScalarLength = 32;

    private static readonly X9ECParameters Params = ECNamedCurveTable.GetByName("P-256");
    private static readonly ECDomainParameters Domain =
        new(Params.Curve, Params.G, Params.N, Params.H, Params.GetSeed());

    /// <summary>The prime order <c>q</c> of the group (also the scalar-field modulus).</summary>
    internal static BigInteger Q => Params.N;

    /// <summary>The standard base generator <c>G</c>.</summary>
    internal static ECPoint G => Params.G;

    /// <summary>The point at infinity (additive identity).</summary>
    internal static ECPoint Infinity => Params.Curve.Infinity;

    /// <summary>
    /// The second generator <c>H</c>, derived by a fixed nothing-up-my-sleeve procedure
    /// so that no party knows <c>log_G(H)</c>. Computed once and cached.
    /// </summary>
    internal static ECPoint H { get; } = DeriveH();

    // ── Randomness seam ───────────────────────────────────────────────────────

    /// <summary>
    /// Fills a span with random bytes. Production always uses
    /// <see cref="RandomNumberGenerator.Fill(Span{byte})"/>; the test project (via
    /// <c>InternalsVisibleTo</c>) substitutes a deterministic filler to drive the
    /// published reference vectors, exactly as the GF(2⁸) core does with
    /// <c>ShamirCore.RandomFill</c>. There is <b>no public way to inject an RNG</b> —
    /// this seam is assembly-internal only (see <c>docs/KNOWN-GAPS.md</c> §7).
    /// </summary>
    internal delegate void RandomFill(Span<byte> destination);

    /// <summary>The randomness source. Defaults to the system CSPRNG; test-only override.</summary>
    internal static RandomFill FillRandom { get; set; } = RandomNumberGenerator.Fill;

    /// <summary>Returns <paramref name="count"/> random bytes from <see cref="FillRandom"/>.</summary>
    internal static byte[] RandomBytes(int count)
    {
        byte[] b = new byte[count];
        FillRandom(b);
        return b;
    }

    // ── Scalars ───────────────────────────────────────────────────────────────

    /// <summary>A uniform scalar in [0, q) via rejection sampling over <see cref="FillRandom"/>.</summary>
    internal static BigInteger RandomScalar()
    {
        Span<byte> buf = stackalloc byte[ScalarLength];
        while (true)
        {
            FillRandom(buf);
            var candidate = new BigInteger(1, buf.ToArray());
            if (candidate.CompareTo(Q) < 0)
                return candidate;
        }
    }

    /// <summary>Encodes a scalar as fixed-width 32-byte big-endian (left-zero-padded).</summary>
    internal static byte[] EncodeScalar(BigInteger s)
    {
        byte[] raw = s.ToByteArrayUnsigned(); // no sign byte, big-endian, no leading zeros
        if (raw.Length > ScalarLength)
            throw new InvalidOperationException("Scalar exceeds field width."); // unreachable for s < q
        if (raw.Length == ScalarLength)
            return raw;
        byte[] padded = new byte[ScalarLength];
        Array.Copy(raw, 0, padded, ScalarLength - raw.Length, raw.Length);
        return padded;
    }

    /// <summary>
    /// Decodes a fixed-width scalar, requiring it to be canonical: exactly 32 bytes and
    /// strictly less than <c>q</c>. Returns false on any deviation (the caller maps this
    /// to a <see cref="ShareFormatException"/>).
    /// </summary>
    internal static bool TryDecodeScalar(ReadOnlySpan<byte> bytes, out BigInteger scalar)
    {
        scalar = BigInteger.Zero;
        if (bytes.Length != ScalarLength)
            return false;
        var value = new BigInteger(1, bytes.ToArray());
        if (value.CompareTo(Q) >= 0)
            return false;
        scalar = value;
        return true;
    }

    // ── Points ────────────────────────────────────────────────────────────────

    /// <summary><c>a·G + b·H</c> — a Pedersen commitment to <c>a</c> with blinding <c>b</c>.</summary>
    internal static ECPoint Commit(BigInteger a, BigInteger b) =>
        G.Multiply(a).Add(H.Multiply(b)).Normalize();

    /// <summary><c>s·G + t·H</c> — the left-hand side of the share-verification equation.</summary>
    internal static ECPoint OpenLhs(BigInteger s, BigInteger t) => Commit(s, t);

    /// <summary>Compressed (33-byte) encoding of a normalized point.</summary>
    internal static byte[] EncodePoint(ECPoint p) => p.Normalize().GetEncoded(true);

    /// <summary>
    /// Decodes a compressed point, requiring exactly 33 bytes, a valid on-curve point,
    /// and not the identity. Returns false on any deviation.
    /// </summary>
    internal static bool TryDecodePoint(ReadOnlySpan<byte> bytes, out ECPoint point)
    {
        point = Infinity;
        if (bytes.Length != PointLength)
            return false;
        try
        {
            ECPoint p = Params.Curve.DecodePoint(bytes.ToArray()); // validates on-curve
            if (p.IsInfinity)
                return false;
            point = p.Normalize();
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or ArithmeticException)
        {
            return false;
        }
    }

    /// <summary>True if two points are equal (compared via their canonical encodings).</summary>
    internal static bool PointsEqual(ECPoint a, ECPoint b) =>
        EncodePoint(a).AsSpan().SequenceEqual(EncodePoint(b));

    // ── Polynomial / interpolation over GF(q) ─────────────────────────────────

    /// <summary>Evaluates a polynomial (coefficients low-order first) at <paramref name="x"/> mod q.</summary>
    internal static BigInteger Evaluate(BigInteger[] coefficients, BigInteger x)
    {
        BigInteger acc = BigInteger.Zero;
        for (int j = coefficients.Length - 1; j >= 0; j--)
            acc = acc.Multiply(x).Add(coefficients[j]).Mod(Q);
        return acc;
    }

    /// <summary>
    /// <c>Σ_j (x^j mod q) · C_j</c> — the right-hand side of the verification equation,
    /// the committed evaluation of the polynomial at the share index <paramref name="x"/>.
    /// </summary>
    internal static ECPoint CommittedEvaluation(ECPoint[] commitments, BigInteger x)
    {
        ECPoint acc = Infinity;
        BigInteger power = BigInteger.One; // x^0
        foreach (ECPoint cj in commitments)
        {
            acc = acc.Add(cj.Multiply(power));
            power = power.Multiply(x).Mod(Q);
        }
        return acc.Normalize();
    }

    /// <summary>
    /// Lagrange interpolation of points <c>(x_i, y_i)</c> evaluated at 0 over GF(q):
    /// recovers a polynomial's constant term from any <c>K</c> evaluations.
    /// </summary>
    internal static BigInteger InterpolateAtZero(BigInteger[] xs, BigInteger[] ys)
    {
        BigInteger acc = BigInteger.Zero;
        for (int i = 0; i < xs.Length; i++)
        {
            BigInteger numerator = BigInteger.One;
            BigInteger denominator = BigInteger.One;
            for (int j = 0; j < xs.Length; j++)
            {
                if (j == i)
                    continue;
                numerator = numerator.Multiply(xs[j]).Mod(Q);                       // Π x_j
                denominator = denominator.Multiply(xs[j].Subtract(xs[i])).Mod(Q);   // Π (x_j - x_i)
            }
            BigInteger lambda = numerator.Multiply(denominator.ModInverse(Q)).Mod(Q);
            acc = acc.Add(ys[i].Multiply(lambda)).Mod(Q);
        }
        return acc.Mod(Q);
    }

    // ── Nothing-up-my-sleeve derivation of H ──────────────────────────────────

    // Try-and-increment from a fixed domain string. For a single, public, one-time
    // generator this is a standard, simple NUMS construction; the security property
    // (nobody knows log_G(H)) comes from H being the hash of a fixed string, not from
    // the choice of map. Documented in docs/VSS-DESIGN.md §3.1. The domain is a local
    // (not a static field) to avoid any static-initialization ordering dependency with
    // the H property initializer above.
    private static ECPoint DeriveH()
    {
        byte[] domain = System.Text.Encoding.ASCII.GetBytes("PostQuantum.SecretSharing/vss/H/secp256r1/v1");
        BigInteger p = Params.Curve.Field.Characteristic; // field prime
        for (uint counter = 0; counter < uint.MaxValue; counter++)
        {
            byte[] digest = Sha256(domain, counter);
            var x = new BigInteger(1, digest);
            if (x.CompareTo(p) >= 0)
                continue;

            byte[] candidate = new byte[PointLength];
            candidate[0] = 0x02; // even-y branch
            byte[] xb = x.ToByteArrayUnsigned();
            Array.Copy(xb, 0, candidate, 1 + (ScalarLength - xb.Length), xb.Length);

            if (TryDecodePoint(candidate, out ECPoint h) && !PointsEqual(h, G))
                return h;
        }
        throw new InvalidOperationException("Failed to derive H."); // unreachable
    }

    private static byte[] Sha256(byte[] domain, uint counter)
    {
        Span<byte> ctr = stackalloc byte[4];
        ctr[0] = (byte)(counter >> 24);
        ctr[1] = (byte)(counter >> 16);
        ctr[2] = (byte)(counter >> 8);
        ctr[3] = (byte)counter;
        using var sha = SHA256.Create();
        sha.TransformBlock(domain, 0, domain.Length, null, 0);
        byte[] ctrArr = ctr.ToArray();
        sha.TransformFinalBlock(ctrArr, 0, ctrArr.Length);
        return sha.Hash!;
    }
}
