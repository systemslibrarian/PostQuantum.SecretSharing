using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using PostQuantum.SecretSharing;

// Accepts standard BenchmarkDotNet args, e.g. `-- --job short` or `-- --filter *Split*`.
BenchmarkSwitcher.FromTypes(new[] { typeof(ShamirBenchmarks) }).Run(args);

/// <summary>
/// Public, reproducible benchmarks for the unauthenticated core (split,
/// reconstruct, and the canonical <c>.pqss</c> serializer/parser). Run with:
/// <code>dotnet run -c Release --project benchmarks/PostQuantum.SecretSharing.Benchmarks</code>
/// </summary>
[MemoryDiagnoser]
public class ShamirBenchmarks
{
    [Params(32, 1024, 65536)]
    public int SecretLength { get; set; }

    private byte[] _secret = Array.Empty<byte>();
    private SharePolicy _policy = new(3, 5);
    private SecretShare[] _shares = Array.Empty<SecretShare>();
    private SecretShare[] _quorum = Array.Empty<SecretShare>();
    private byte[] _oneShareBytes = Array.Empty<byte>();

    [GlobalSetup]
    public void Setup()
    {
        _secret = RandomNumberGenerator.GetBytes(SecretLength);
        _policy = new SharePolicy(3, 5);
        _shares = ShamirSecretSharing.Split(_secret, _policy);
        _quorum = new[] { _shares[0], _shares[2], _shares[4] };
        _oneShareBytes = _shares[0].Export();
    }

    [Benchmark]
    public SecretShare[] Split() => ShamirSecretSharing.Split(_secret, _policy);

    [Benchmark]
    public int Reconstruct()
    {
        using ZeroizingBuffer buf = ShamirSecretSharing.Reconstruct(_quorum);
        return buf.Length;
    }

    [Benchmark]
    public byte[] Export() => _shares[0].Export();

    [Benchmark]
    public SecretShare Import() => SecretShare.Import(_oneShareBytes);
}
