using System.Diagnostics;
using System.Security.Cryptography;
using Xunit;
using Xunit.Abstractions;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// Performance smoke tests. Tagged with the "bench" trait so the CI gate can
/// exclude them (<c>--filter Category!=bench</c>); they print numbers rather than
/// asserting tight bounds, to avoid flaking on shared CI hardware.
/// </summary>
[Trait("Category", "bench")]
public class BenchTests
{
    private readonly ITestOutputHelper _out;
    public BenchTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public void Split_3of5_32Bytes_IsFast()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var policy = new SharePolicy(3, 5);

        // Warm up.
        for (int i = 0; i < 100; i++) _ = ShamirSecretSharing.Split(secret, policy);

        var sw = Stopwatch.StartNew();
        const int iters = 1000;
        for (int i = 0; i < iters; i++) _ = ShamirSecretSharing.Split(secret, policy);
        sw.Stop();

        double perOp = sw.Elapsed.TotalMilliseconds / iters;
        _out.WriteLine($"3-of-5 split of 32 bytes: {perOp:F4} ms/op");
        Assert.True(perOp < 5.0, $"split unexpectedly slow: {perOp:F4} ms/op");
    }

    [Fact]
    public void Split_Reconstruct_64KiB_Under250ms()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(65536);
        var policy = new SharePolicy(3, 5);

        var sw = Stopwatch.StartNew();
        SecretShare[] shares = ShamirSecretSharing.Split(secret, policy);
        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[1], shares[2] });
        sw.Stop();

        _out.WriteLine($"64 KiB 3-of-5 split+reconstruct: {sw.Elapsed.TotalMilliseconds:F2} ms");
        Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));
        Assert.True(sw.Elapsed.TotalMilliseconds < 250.0, $"too slow: {sw.Elapsed.TotalMilliseconds:F2} ms");
    }
}
