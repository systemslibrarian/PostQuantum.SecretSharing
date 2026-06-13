using System.Security.Cryptography;

namespace PostQuantum.SecretSharing;

/// <summary>
/// The split/interpolate engine over GF(2^8). Pure field math; performs no
/// validation (callers in the public facade validate policy and consistency
/// first) and no authentication. All multiplications go through the
/// constant-time <see cref="Gf256.Mul"/>.
/// </summary>
internal static class ShamirCore
{
    /// <summary>
    /// Fills a destination span with random bytes. The production facade supplies
    /// <see cref="RandomNumberGenerator.Fill(Span{byte})"/>; the test project
    /// (via <c>InternalsVisibleTo</c>) supplies a deterministic filler to drive
    /// the engine with the fixed coefficients used by the published test vectors.
    /// </summary>
    internal delegate void RandomFill(Span<byte> destination);

    /// <summary>
    /// Splits <paramref name="secret"/> into <paramref name="n"/> shares with
    /// threshold <paramref name="k"/>. Each secret byte is the constant term of
    /// an independent degree-(k−1) polynomial whose higher coefficients come from
    /// <paramref name="fillRandom"/>.
    /// </summary>
    /// <returns>
    /// An array of <paramref name="n"/> y-rows; element <c>i</c> is the share for
    /// x-coordinate <c>i + 1</c> and has the same length as the secret.
    /// </returns>
    /// <remarks>
    /// The full <c>(k−1) × secretLen</c> coefficient matrix is filled in a single
    /// pass for performance, then wiped with
    /// <see cref="CryptographicOperations.ZeroMemory"/> in a <c>finally</c> block.
    /// Per standard Shamir (matching HashiCorp Vault / SLIP-0039), a zero top
    /// coefficient for an individual byte is permitted — see SPEC.md.
    /// </remarks>
    internal static byte[][] Split(ReadOnlySpan<byte> secret, int k, int n, RandomFill fillRandom)
    {
        int len = secret.Length;
        // Row r (0-based) holds the coefficient of x^(r+1) for every secret byte.
        byte[] coeffs = new byte[(k - 1) * len];
        // Copy the secret into a local so the lambda-free loop below reads a span.
        // (secret is a ReadOnlySpan and cannot be captured; we index it directly.)
        try
        {
            fillRandom(coeffs);

            var shares = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                byte x = (byte)(i + 1);
                var y = new byte[len];
                for (int j = 0; j < len; j++)
                {
                    // Horner from the highest coefficient (x^(k-1)) down to the
                    // constant term (the secret byte).
                    byte acc = coeffs[(k - 2) * len + j]; // coefficient of x^(k-1)
                    for (int p = k - 2; p >= 1; p--)
                        acc = Gf256.Add(Gf256.Mul(acc, x), coeffs[(p - 1) * len + j]);
                    acc = Gf256.Add(Gf256.Mul(acc, x), secret[j]);
                    y[j] = acc;
                }
                shares[i] = y;
            }
            return shares;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(coeffs);
        }
    }

    /// <summary>
    /// Lagrange-interpolates the secret at x=0 from exactly <c>k</c> shares
    /// (where <c>k = xs.Length</c>) and writes it into <paramref name="output"/>.
    /// </summary>
    /// <param name="xs">The k distinct x-coordinates (all non-zero).</param>
    /// <param name="ys">The k y-rows, parallel to <paramref name="xs"/>, all of length <c>output.Length</c>.</param>
    /// <param name="output">Destination for the reconstructed secret (typically a <see cref="ZeroizingBuffer"/> span).</param>
    /// <remarks>
    /// The k Lagrange basis coefficients depend only on the public x-coordinates,
    /// so they are computed once (O(k²)) and then applied across every byte
    /// column (O(k·len)), rather than recomputed per column.
    /// </remarks>
    internal static void Reconstruct(ReadOnlySpan<byte> xs, IReadOnlyList<byte[]> ys, Span<byte> output)
    {
        int k = xs.Length;
        int len = output.Length;

        // Basis coefficient for share i at x=0:  prod_{m!=i} x_m / (x_m XOR x_i).
        Span<byte> basis = stackalloc byte[k];
        for (int i = 0; i < k; i++)
        {
            byte num = 1, den = 1;
            for (int m = 0; m < k; m++)
            {
                if (m == i) continue;
                num = Gf256.Mul(num, xs[m]);
                den = Gf256.Mul(den, Gf256.Add(xs[m], xs[i]));
            }
            basis[i] = Gf256.Div(num, den);
        }

        for (int j = 0; j < len; j++)
        {
            byte acc = 0;
            for (int i = 0; i < k; i++)
                acc = Gf256.Add(acc, Gf256.Mul(ys[i][j], basis[i]));
            output[j] = acc;
        }
    }
}
