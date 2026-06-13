namespace PostQuantum.SecretSharing;

/// <summary>
/// Constant-time arithmetic in the finite field GF(2^8) using the AES reduction
/// polynomial <c>x^8 + x^4 + x^3 + x + 1</c> (0x11B).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why no log/antilog tables.</b> The textbook fast Shamir implementation
/// multiplies via precomputed logarithm and exponentiation tables indexed by
/// the field elements. When those elements are share <c>y</c>-values — which
/// are secret-dependent — the memory access pattern leaks through the CPU data
/// cache. This is the classic timing/cache side channel in Shamir libraries.
/// Every routine here is branchless and table-free: the instruction sequence
/// and memory accesses are independent of the operand values.
/// </para>
/// </remarks>
internal static class Gf256
{
    /// <summary>The AES field reduction polynomial, low 9 bits of x^8+x^4+x^3+x+1.</summary>
    private const int ReductionPoly = 0x11B;

    /// <summary>Field addition: XOR. Trivially constant-time.</summary>
    internal static byte Add(byte a, byte b) => (byte)(a ^ b);

    /// <summary>
    /// Constant-time multiplication in GF(2^8) via branchless Russian-peasant
    /// multiplication over a fixed eight iterations. No data-dependent branches
    /// and no table lookups: the loop count and operations are identical for all
    /// operands, so timing does not depend on <paramref name="a"/> or
    /// <paramref name="b"/>.
    /// </summary>
    internal static byte Mul(byte a, byte b)
    {
        int r = 0, aa = a, bb = b;
        for (int i = 0; i < 8; i++)
        {
            // Add (XOR) the running 'aa' into r iff the low bit of bb is set.
            // -(bb & 1) is 0x00000000 or 0xFFFFFFFF — a branchless conditional mask.
            r ^= aa & -(bb & 1);

            // Mask is all-ones iff the high bit of aa is set, selecting whether to
            // reduce after the shift. Again branchless.
            int hi = -((aa >> 7) & 1);
            aa = (aa << 1) ^ (ReductionPoly & hi);

            bb >>= 1;
        }
        return (byte)r;
    }

    /// <summary>
    /// Multiplicative inverse in GF(2^8), computed as <c>a^254</c> (since the
    /// multiplicative group has order 255 and <c>a^255 = 1</c>, so
    /// <c>a^-1 = a^254</c>). The exponent 254 is a public constant, so a fixed
    /// square-and-multiply pattern leaks nothing about <paramref name="a"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <paramref name="a"/> is zero. Zero has no inverse; reaching this
    /// indicates duplicate x-coordinates that must already have been rejected
    /// upstream, i.e. a broken internal invariant.
    /// </exception>
    internal static byte Inv(byte a)
    {
        if (a == 0)
            throw new InvalidOperationException(
                "GF(2^8) inverse of zero requested — duplicate x-coordinates should " +
                "have been rejected before reconstruction. This is an internal invariant violation.");

        // 254 = 0b11111110. Fixed square-and-multiply over the constant exponent:
        // multiply into the accumulator for every set bit except bit 0.
        byte result = 1;
        byte power = a;            // a^(2^0)
        for (int bit = 0; bit < 8; bit++)
        {
            if (((254 >> bit) & 1) != 0)   // exponent is a public constant — branch is fine
                result = Mul(result, power);
            power = Mul(power, power);      // square to advance to a^(2^(bit+1))
        }
        return result;
    }

    /// <summary>Field division: <c>a / b = a * b^-1</c>. Constant-time in the data.</summary>
    /// <exception cref="InvalidOperationException">Thrown if <paramref name="b"/> is zero.</exception>
    internal static byte Div(byte a, byte b) => Mul(a, Inv(b));
}
