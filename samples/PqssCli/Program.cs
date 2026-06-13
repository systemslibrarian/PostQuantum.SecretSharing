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
                "refresh" => Refresh(args[1..]),
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
        var (pos, opts, flags) = Parse(a, flagNames: new() { "sign", "wrap" });
        if (pos.Count != 1)
            return Fail("usage: pqss split <secretFile> --k K --n N --out DIR [--sign] [--sk-out FILE] [--wrap] [--commit-out FILE]");

        int k = int.Parse(Req(opts, "k"));
        int n = int.Parse(Req(opts, "n"));
        string outDir = Req(opts, "out");
        Directory.CreateDirectory(outDir);

        byte[] secret = File.ReadAllBytes(pos[0]);
        var policy = new SharePolicy(k, n);

        // Optional one-time commitment to the real secret (publish out-of-band).
        if (opts.TryGetValue("commit-out", out var commitFile))
        {
            File.WriteAllBytes(commitFile, DealerCommitment.Compute(secret));
            Console.WriteLine($"commitment        : {commitFile}  (fingerprint {Fingerprint(DealerCommitment.Compute(secret))})");
        }

        MlDsa65ShareAuthenticator? dealer = null;
        try
        {
            if (flags.Contains("sign"))
            {
                if (!MLDsa.IsSupported)
                    return Fail("--sign requires ML-DSA-65 (FIPS 204), which is unavailable on this platform.");
                dealer = MlDsa65ShareAuthenticator.Generate();
                string pub = Path.Combine(outDir, "dealer.pub");
                File.WriteAllBytes(pub, dealer.PublicKey.ToArray());
                string sk = opts.TryGetValue("sk-out", out var p) ? p : Path.Combine(outDir, "dealer.key");
                File.WriteAllBytes(sk, dealer.ExportPrivateKey().ToArray());
                Console.Error.WriteLine($"WARNING: dealer PRIVATE key written to '{sk}'. Protect it (it can mint shares) or destroy it.");
                Console.WriteLine($"dealer public key : {pub}  (fingerprint {Fingerprint(dealer.PublicKey.Span)})");
            }

            SecretShare[] shares;
            if (flags.Contains("wrap"))
            {
                // Safe path for low-entropy/large secrets: split a random KEK, store an envelope.
                WrappedSplit w = dealer is null
                    ? WrappedSecret.Split(secret, policy)
                    : WrappedSecret.Split(secret, policy, dealer);
                shares = w.Shares;
                string envPath = Path.Combine(outDir, "envelope.bin");
                File.WriteAllBytes(envPath, w.Envelope);
                Console.WriteLine($"wrapped: envelope written to '{envPath}' (not secret; needed at combine time)");
            }
            else
            {
                shares = dealer is null
                    ? ShamirSecretSharing.Split(secret, policy)
                    : ShamirSecretSharing.Split(secret, policy, dealer);
            }

            foreach (SecretShare s in shares)
                File.WriteAllBytes(Path.Combine(outDir, $"share-{s.ShareIndex}.pqss"), s.Export());

            Console.WriteLine($"split {k}-of-{n}: wrote {shares.Length} shares to '{outDir}'");
            Console.WriteLine($"splitId           : {Hex(shares[0].SplitId.Span)}");
            return 0;
        }
        finally
        {
            dealer?.Dispose();
            CryptographicOperations.ZeroMemory(secret);
        }
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
            return Fail("usage: pqss combine <share.pqss> ... --out FILE [--pub dealer.pub] [--envelope FILE] [--commit FILE]");

        string outFile = Req(opts, "out");
        var shares = pos.Select(f => SecretShare.Import(File.ReadAllBytes(f))).ToList();
        ReadOnlyMemory<byte>? pin = ReadPin(opts);

        using ZeroizingBuffer secret = opts.TryGetValue("envelope", out var envFile)
            ? WrappedSecret.Reconstruct(shares, File.ReadAllBytes(envFile), pin)   // wrapped: KEK shares + envelope
            : ShamirSecretSharing.Reconstruct(shares, pin);

        if (opts.TryGetValue("commit", out var commitFile))
        {
            byte[] commitment = File.ReadAllBytes(commitFile);
            if (!DealerCommitment.Verify(secret, commitment))
                return Fail("recovered secret does NOT match the published commitment — possible inconsistent dealer.");
            Console.WriteLine("commitment verified: recovered secret matches the published value.");
        }

        File.WriteAllBytes(outFile, secret.Span.ToArray());
        Console.Error.WriteLine($"WARNING: reconstructed secret written in CLEARTEXT to '{outFile}'. Handle and delete with care.");
        Console.WriteLine($"recovered {secret.Length} bytes from {shares.Count} shares → '{outFile}'"
                          + (pin.HasValue ? "  (dealer key verified)" : "")
                          + (opts.ContainsKey("envelope") ? "  (unwrapped)" : ""));
        return 0;
    }

    private static int Refresh(string[] a)
    {
        var (pos, opts, flags) = Parse(a, flagNames: new() { "sign" });
        if (pos.Count == 0)
            return Fail("usage: pqss refresh <share.pqss> ... --out DIR [--pub dealer.pub] [--k K --n N] [--sign] [--sk-out FILE]");

        string outDir = Req(opts, "out");
        Directory.CreateDirectory(outDir);

        var shares = pos.Select(f => SecretShare.Import(File.ReadAllBytes(f))).ToList();
        ReadOnlyMemory<byte>? pin = ReadPin(opts);

        SharePolicy? newPolicy = (opts.TryGetValue("k", out var ks) && opts.TryGetValue("n", out var ns))
            ? new SharePolicy(int.Parse(ks), int.Parse(ns))
            : null;

        MlDsa65ShareAuthenticator? newDealer = null;
        try
        {
            if (flags.Contains("sign"))
            {
                if (!MLDsa.IsSupported)
                    return Fail("--sign requires ML-DSA-65 (FIPS 204), which is unavailable on this platform.");
                newDealer = MlDsa65ShareAuthenticator.Generate();
                File.WriteAllBytes(Path.Combine(outDir, "dealer.pub"), newDealer.PublicKey.ToArray());
                string sk = opts.TryGetValue("sk-out", out var p) ? p : Path.Combine(outDir, "dealer.key");
                File.WriteAllBytes(sk, newDealer.ExportPrivateKey().ToArray());
                Console.Error.WriteLine($"WARNING: new dealer PRIVATE key written to '{sk}'. Protect or destroy it.");
            }

            SecretShare[] refreshed = ShamirSecretSharing.Refresh(shares, newPolicy, pin, newDealer);
            foreach (SecretShare s in refreshed)
                File.WriteAllBytes(Path.Combine(outDir, $"share-{s.ShareIndex}.pqss"), s.Export());

            Console.WriteLine($"refreshed: wrote {refreshed.Length} new shares to '{outDir}'");
            Console.WriteLine($"new splitId       : {Hex(refreshed[0].SplitId.Span)}  (old shares no longer interoperate)");
            return 0;
        }
        finally
        {
            newDealer?.Dispose();
        }
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

    /// <summary>Reads the optional --pub pin. Returns a genuine null when absent (not an empty key).</summary>
    private static ReadOnlyMemory<byte>? ReadPin(Dictionary<string, string> opts)
    {
        if (opts.TryGetValue("pub", out var pubFile))
            return File.ReadAllBytes(pubFile);
        return null;
    }

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
              pqss split   <secretFile> --k K --n N --out DIR [--sign] [--sk-out FILE] [--wrap] [--commit-out FILE]
              pqss inspect <share.pqss> [<share.pqss> ...]
              pqss combine <share.pqss> ... --out FILE [--pub dealer.pub] [--envelope FILE] [--commit FILE]
              pqss refresh <share.pqss> ... --out DIR [--pub dealer.pub] [--k K --n N] [--sign] [--sk-out FILE]

            COMMANDS
              split     Split a secret file into N shares (any K reconstruct).
                          --k          threshold K (2..255)
                          --n          total shares N (K..255)
                          --out        output directory for share-<i>.pqss
                          --sign       dealer-sign shares with ML-DSA-65 (net10.0; writes dealer.pub)
                          --sk-out     where to write the dealer PRIVATE key (default DIR/dealer.key)
                          --wrap       safe path for low-entropy/large secrets: split a random KEK
                                       and write an AES-GCM envelope.bin (needed at combine time)
                          --commit-out write a one-time commitment to the secret (publish out-of-band)

              inspect   Print a share's metadata. Never reveals the secret or share data.

              combine   Reconstruct the secret from EXACTLY K shares.
                          --out        file to write the recovered secret to (cleartext!)
                          --pub        pin: require every share to verify against this dealer key
                          --envelope   unwrap: combine KEK shares + envelope.bin from a --wrap split
                          --commit     verify the recovered secret against a published commitment

              refresh   Rotate custody: reconstruct and re-split into fresh shares (new splitId)
                          --out        output directory for the new shares
                          --pub        pin verifying the INCOMING shares
                          --k --n      optional new policy (default: same as input)
                          --sign       authenticate the NEW shares with a new dealer key

            EXAMPLES
              # Make a 32-byte key, split 3-of-5, dealer-signed, with a commitment
              pqss split key.bin --k 3 --n 5 --out ./shares --sign --sk-out ./dealer.key --commit-out ./key.commit

              # Inspect a share (exposes nothing secret)
              pqss inspect ./shares/share-2.pqss

              # Reconstruct from three shares, verifying dealer + commitment
              pqss combine ./shares/share-1.pqss ./shares/share-3.pqss ./shares/share-5.pqss \
                   --out recovered.bin --pub ./shares/dealer.pub --commit ./key.commit

              # Protect a low-entropy passphrase safely (wrap), then recover it
              pqss split pass.txt --k 2 --n 3 --out ./vault --wrap
              pqss combine ./vault/share-1.pqss ./vault/share-2.pqss --out pass.out --envelope ./vault/envelope.bin

              # Rotate custody after a trustee departs (new shares; old ones stop interoperating)
              pqss refresh ./shares/share-1.pqss ./shares/share-3.pqss ./shares/share-5.pqss --out ./shares-v2

            NOTE
              Do not split low-entropy secrets (passphrases/PINs) directly — the check value is
              an offline guessing oracle. Use --wrap (or the WrappedSecret API).
            """);
    }
}
