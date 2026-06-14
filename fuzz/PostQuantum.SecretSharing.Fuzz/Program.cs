using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Vss;
using SharpFuzz;

// Coverage-guided fuzz target for the strict .pqss parsers — the library's primary
// untrusted-input attack surface. The property under test is fail-closed-ness:
//
//   For ANY byte sequence, the Import entry points must either succeed or throw a
//   SecretSharingException (the declared, intentional rejection hierarchy).
//   ANY other exception — IndexOutOfRange, Overflow, OutOfMemory, etc. — is a bug,
//   and letting it escape the lambda makes libFuzzer record a crash + repro.
//
// Three readers share one harness: the v1 share reader (SecretShare) and the opt-in
// v2 / VSS readers (VssShare, VssCommitments). The same input is fed to all three;
// each must fail closed.
//
// Usage:
//   --seed <dir>   write a small valid-record seed corpus, then exit (no fuzzing).
//   (no args)      run under libFuzzer (via libfuzzer-dotnet).

if (args.Length >= 2 && args[0] == "--seed")
{
    WriteSeedCorpus(args[1]);
    return;
}

Fuzzer.LibFuzzer.Run(static (ReadOnlySpan<byte> data) =>
{
    try { _ = SecretShare.Import(data); } catch (SecretSharingException) { }
    try { _ = VssShare.Import(data); } catch (SecretSharingException) { }
    try { _ = VssCommitments.Import(data); } catch (SecretSharingException) { }
    // Expected: every malformed / out-of-policy input is rejected via the declared
    // SecretSharingException hierarchy. Any other escaping exception is a crash.
});

static void WriteSeedCorpus(string dir)
{
    Directory.CreateDirectory(dir);

    // A spread of valid shares (varying k/n and secret length) gives the fuzzer
    // realistic, structurally-valid starting points to mutate from.
    (int k, int n, int len)[] shapes =
    {
        (2, 3, 1),
        (2, 3, 2),
        (3, 5, 16),
        (2, 2, 32),
        (5, 9, 64),
    };

    int i = 0;
    foreach ((int k, int n, int len) in shapes)
    {
        byte[] secret = new byte[len];
        for (int b = 0; b < len; b++)
            secret[b] = (byte)(b * 31 + k + n);

        SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(k, n));
        // A couple of shares per split is plenty of seed diversity.
        for (int s = 0; s < Math.Min(2, shares.Length); s++)
            File.WriteAllBytes(Path.Combine(dir, $"seed-{i++:000}.pqss"), shares[s].Export());

        // Matching v2 / VSS seeds (one commitment broadcast + one share per shape) so the
        // fuzzer has structurally-valid v2 records to mutate, not just v1 ones.
        VssSplit vss = PedersenVss.Split(secret, new SharePolicy(k, n));
        File.WriteAllBytes(Path.Combine(dir, $"seed-{i++:000}.vss-c"), vss.Commitments.Export());
        File.WriteAllBytes(Path.Combine(dir, $"seed-{i++:000}.vss-s"), vss.Shares[0].Export());
    }

    Console.WriteLine($"Wrote {i} seed inputs to {dir}");
}
