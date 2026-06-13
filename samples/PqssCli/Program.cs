using System.Security.Cryptography;
using PostQuantum.SecretSharing;

// pqss — a small, real command-line utility for the .pqss share format.
//
//   pqss split   <secretFile> --k K --n N --out DIR [--sign] [--sk-out FILE]
//   pqss inspect <share.pqss> [<share.pqss> ...]
//   pqss combine <share.pqss> ... --out FILE [--pub dealer.pub]
//
// It is a sample, not a shipped tool — but it is genuinely usable: split a key
// file into shares, inspect a share's metadata without revealing the secret, and
// reconstruct from a quorum (optionally verifying a pinned dealer key).

return Cli.Run(args);

internal static class Cli
{
    public static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return args.Length == 0 ? 1 : 0;
        }

        try
        {
            return args[0] switch
            {
                "split" => Split(args[1..]),
                "inspect" => Inspect(args[1..]),
                "combine" => Combine(args[1..]),
                _ => Fail($"unknown command '{args[0]}'. Run 'pqss --help'.")
            };
        }
        catch (SecretSharingException ex) { return Fail(ex.Message); }            // policy/format/auth/consistency
        catch (FileNotFoundException ex) { return Fail($"file not found: {ex.FileName ?? ex.Message}"); }
        catch (PlatformNotSupportedException ex) { return Fail(ex.Message); }
        catch (Exception ex) when (ex is ArgumentException or FormatException) { return Fail(ex.Message); }
    }

    private static int Split(string[] a)
    {
        var (pos, opts, flags) = Parse(a, flagNames: new() { "sign" });
        if (pos.Count != 1)
            return Fail("usage: pqss split <secretFile> --k K --n N --out DIR [--sign] [--sk-out FILE]");

        int k = int.Parse(Req(opts, "k"));
        int n = int.Parse(Req(opts, "n"));
        string outDir = Req(opts, "out");
        Directory.CreateDirectory(outDir);

        byte[] secret = File.ReadAllBytes(pos[0]);
        SecretShare[] shares;

        if (flags.Contains("sign"))
        {
            if (!MLDsa.IsSupported)
                return Fail("--sign requires ML-DSA-65 (FIPS 204), which is unavailable on this platform.");

            using var dealer = MlDsa65ShareAuthenticator.Generate();
            shares = ShamirSecretSharing.Split(secret, new SharePolicy(k, n), dealer);

            string pub = Path.Combine(outDir, "dealer.pub");
            File.WriteAllBytes(pub, dealer.PublicKey.ToArray());
            string sk = opts.TryGetValue("sk-out", out var p) ? p : Path.Combine(outDir, "dealer.key");
            File.WriteAllBytes(sk, dealer.ExportPrivateKey().ToArray());

            Console.Error.WriteLine($"WARNING: dealer PRIVATE key written to '{sk}'. Protect it (it can mint shares) or destroy it.");
            Console.WriteLine($"dealer public key : {pub}  (fingerprint {Fingerprint(dealer.PublicKey.Span)})");
            Console.WriteLine("  pin this fingerprint out-of-band; pass --pub at combine time to verify.");
        }
        else
        {
            shares = ShamirSecretSharing.Split(secret, new SharePolicy(k, n));
        }

        CryptographicOperations.ZeroMemory(secret);

        foreach (SecretShare s in shares)
            File.WriteAllBytes(Path.Combine(outDir, $"share-{s.ShareIndex}.pqss"), s.Export());

        Console.WriteLine($"split {k}-of-{n}: wrote {shares.Length} shares to '{outDir}'");
        Console.WriteLine($"splitId           : {Hex(shares[0].SplitId.Span)}");
        return 0;
    }

    private static int Inspect(string[] a)
    {
        if (a.Length == 0)
            return Fail("usage: pqss inspect <share.pqss> [<share.pqss> ...]");

        foreach (string file in a)
        {
            SecretShare s = SecretShare.Import(File.ReadAllBytes(file));
            Console.WriteLine($"{Path.GetFileName(file)}:");
            Console.WriteLine($"  threshold (k)  : {s.Threshold}");
            Console.WriteLine($"  total (n)      : {s.TotalShares}");
            Console.WriteLine($"  share index    : {s.ShareIndex}");
            Console.WriteLine($"  secret length  : {s.SecretLength} bytes");
            Console.WriteLine($"  splitId        : {Hex(s.SplitId.Span)}");
            Console.WriteLine($"  authentication : {s.Authentication}");
            if (s.Authentication != ShareAuthenticationKind.None)
                Console.WriteLine($"  dealer key fp  : {Fingerprint(s.DealerPublicKey.Span)}");
            Console.WriteLine();
        }
        return 0;
    }

    private static int Combine(string[] a)
    {
        var (pos, opts, _) = Parse(a, flagNames: new());
        if (pos.Count == 0)
            return Fail("usage: pqss combine <share.pqss> ... --out FILE [--pub dealer.pub]");

        string outFile = Req(opts, "out");
        var shares = pos.Select(f => SecretShare.Import(File.ReadAllBytes(f))).ToList();

        ReadOnlyMemory<byte>? pin = opts.TryGetValue("pub", out var pubFile)
            ? File.ReadAllBytes(pubFile)
            : null;

        using ZeroizingBuffer secret = ShamirSecretSharing.Reconstruct(shares, pin);
        File.WriteAllBytes(outFile, secret.Span.ToArray());

        Console.Error.WriteLine($"WARNING: reconstructed secret written in CLEARTEXT to '{outFile}'. Handle and delete with care.");
        Console.WriteLine($"recovered {secret.Length} bytes from {shares.Count} shares → '{outFile}'"
                          + (pin.HasValue ? "  (dealer key verified)" : ""));
        return 0;
    }

    // --- helpers ---

    private static (List<string> pos, Dictionary<string, string> opts, HashSet<string> flags)
        Parse(string[] a, HashSet<string> flagNames)
    {
        var pos = new List<string>();
        var opts = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < a.Length; i++)
        {
            string t = a[i];
            if (t.StartsWith("--", StringComparison.Ordinal))
            {
                string name = t[2..];
                if (flagNames.Contains(name)) { flags.Add(name); }
                else
                {
                    if (i + 1 >= a.Length) throw new ArgumentException($"option --{name} requires a value");
                    opts[name] = a[++i];
                }
            }
            else { pos.Add(t); }
        }
        return (pos, opts, flags);
    }

    private static string Req(Dictionary<string, string> opts, string key)
        => opts.TryGetValue(key, out var v) ? v : throw new ArgumentException($"missing required option --{key}");

    private static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    private static string Fingerprint(ReadOnlySpan<byte> key)
        => Convert.ToHexString(SHA256.HashData(key)[..8]).ToLowerInvariant();

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        return 1;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
            pqss — Shamir secret sharing for .pqss share files

            USAGE
              pqss split   <secretFile> --k K --n N --out DIR [--sign] [--sk-out FILE]
              pqss inspect <share.pqss> [<share.pqss> ...]
              pqss combine <share.pqss> ... --out FILE [--pub dealer.pub]

            COMMANDS
              split     Split a secret file into N shares (any K reconstruct).
                          --k        threshold K (2..255)
                          --n        total shares N (K..255)
                          --out      output directory for share-<i>.pqss
                          --sign     dealer-sign shares with ML-DSA-65 (net10.0; writes dealer.pub)
                          --sk-out   where to write the dealer PRIVATE key (default DIR/dealer.key)

              inspect   Print a share's metadata. Never reveals the secret or share data.

              combine   Reconstruct the secret from EXACTLY K shares.
                          --out      file to write the recovered secret to (cleartext!)
                          --pub      pin: require every share to verify against this dealer public key

            EXAMPLES
              # Make a 32-byte key and split it 3-of-5, dealer-signed
              pqss split key.bin --k 3 --n 5 --out ./shares --sign --sk-out ./dealer.key

              # Look at a share without exposing anything secret
              pqss inspect ./shares/share-2.pqss

              # Reconstruct from three shares, verifying the dealer
              pqss combine ./shares/share-1.pqss ./shares/share-3.pqss ./shares/share-5.pqss \
                   --out recovered.bin --pub ./shares/dealer.pub

            NOTE
              Do not split low-entropy secrets (passphrases/PINs) directly — the check value
              is an offline guessing oracle. Split a random key and wrap your real secret with
              it (see the EnvelopeRecovery sample).
            """);
    }
}
