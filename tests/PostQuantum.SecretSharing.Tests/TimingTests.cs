using System.Diagnostics;
using Xunit;
using Xunit.Abstractions;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// Empirical evidence that the GF(2⁸) primitives are constant-time with respect to
/// their operands. The strong guarantee is structural — the code is branchless and
/// table-free, so the instruction stream and memory accesses do not depend on the
/// data (this test merely corroborates it). Tagged "timing" so it is excluded from
/// the CI gate (wall-clock measurements are inherently noisy on shared runners);
/// run it explicitly with <c>--filter Category=timing</c>.
/// </summary>
[Trait("Category", "timing")]
public class TimingTests
{
    private readonly ITestOutputHelper _out;
    public TimingTests(ITestOutputHelper output) => _out = output;

    private static volatile int _sink;

    [Fact]
    public void Mul_TimingIsIndependentOfOperands()
    {
        const int n = 20_000_000;

        // Three operand classes that would diverge badly if the code branched on
        // data or used secret-indexed table lookups.
        double tZero = TimeMul(n, 0x00);   // multiply by 0 every time
        double tFF = TimeMul(n, 0xFF);     // multiply by 0xFF (all bits set) every time
        double tAlt = TimeMulVarying(n);   // multiply by a varying value each time

        _out.WriteLine($"Mul x0x00 : {tZero:F2} ns/op");
        _out.WriteLine($"Mul x0xFF : {tFF:F2} ns/op");
        _out.WriteLine($"Mul vary  : {tAlt:F2} ns/op");

        double max = Math.Max(tZero, Math.Max(tFF, tAlt));
        double min = Math.Min(tZero, Math.Min(tFF, tAlt));
        double ratio = max / Math.Max(min, 1e-9);
        _out.WriteLine($"max/min ratio : {ratio:F3} (closer to 1.0 = more uniform)");

        // Loose bound: branch/table-based code typically diverges far more than this.
        Assert.True(ratio < 3.0, $"GF Mul timing varied by {ratio:F2}x across operand classes — investigate.");
    }

    [Fact]
    public void Inv_TimingIsIndependentOfOperand()
    {
        const int n = 5_000_000;
        double tOne = TimeInv(n, 0x01);
        double tFF = TimeInv(n, 0xFF);
        double tMid = TimeInv(n, 0x53);

        _out.WriteLine($"Inv(0x01) : {tOne:F2} ns/op");
        _out.WriteLine($"Inv(0xFF) : {tFF:F2} ns/op");
        _out.WriteLine($"Inv(0x53) : {tMid:F2} ns/op");

        double max = Math.Max(tOne, Math.Max(tFF, tMid));
        double min = Math.Min(tOne, Math.Min(tFF, tMid));
        Assert.True(max / Math.Max(min, 1e-9) < 3.0);
    }

    private static double TimeMul(int n, byte b)
    {
        // Warm up.
        for (int i = 0; i < 1_000_000; i++) _sink ^= Gf256.Mul((byte)i, b);
        var sw = Stopwatch.StartNew();
        int acc = 0;
        for (int i = 0; i < n; i++) acc ^= Gf256.Mul((byte)i, b);
        sw.Stop();
        _sink ^= acc;
        return sw.Elapsed.TotalMilliseconds * 1e6 / n;
    }

    private static double TimeMulVarying(int n)
    {
        for (int i = 0; i < 1_000_000; i++) _sink ^= Gf256.Mul((byte)i, (byte)(i * 7));
        var sw = Stopwatch.StartNew();
        int acc = 0;
        for (int i = 0; i < n; i++) acc ^= Gf256.Mul((byte)i, (byte)(i * 7 + 1));
        sw.Stop();
        _sink ^= acc;
        return sw.Elapsed.TotalMilliseconds * 1e6 / n;
    }

    private static double TimeInv(int n, byte a)
    {
        for (int i = 0; i < 500_000; i++) _sink ^= Gf256.Inv(a);
        var sw = Stopwatch.StartNew();
        int acc = 0;
        for (int i = 0; i < n; i++) acc ^= Gf256.Inv(a);
        sw.Stop();
        _sink ^= acc;
        return sw.Elapsed.TotalMilliseconds * 1e6 / n;
    }
}
