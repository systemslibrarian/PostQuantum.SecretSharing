using System.Security.Cryptography;
using System.Text;
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
                "verify" => Verify(args[1..]),
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
        var (pos, opts, flags) = Parse(a, flagNames: new() { "sign", "wrap", "armor" });
        if (pos.Count != 1)
            return Fail("usage: pqss split <secretFile> --k K --n N --out DIR [--sign] [--sk-out FILE] [--wrap] [--armor] [--commit-out FILE]");

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

            bool armor = flags.Contains("armor");
            foreach (SecretShare s in shares)
                WriteShare(outDir, s, armor);

            Console.WriteLine($"split {k}-of-{n}: wrote {shares.Length} {(armor ? "armored " : "")}shares to '{outDir}'");
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
        var (pos, _, flags) = Parse(a, flagNames: new() { "json" });
        if (pos.Count == 0)
            return Fail("usage: pqss inspect <share.pqss> [<share.pqss> ...] [--json]");

        var rows = pos.Select(file =>
        {
            SecretShare s = SecretShare.Import(ReadShareBytes(file));
            return (file, s);
        }).ToList();

        if (flags.Contains("json"))
        {
            var sb = new StringBuilder();
            sb.Append('[');
            for (int i = 0; i < rows.Count; i++)
            {
                var (file, s) = rows[i];
                if (i > 0) sb.Append(',');
                sb.Append("\n  {");
                sb.Append($"\"file\":{JsonStr(Path.GetFileName(file))},");
                sb.Append($"\"threshold\":{s.Threshold},\"total\":{s.TotalShares},");
                sb.Append($"\"shareIndex\":{s.ShareIndex},\"secretLength\":{s.SecretLength},");
                sb.Append($"\"splitId\":{JsonStr(Hex(s.SplitId.Span))},");
                sb.Append($"\"authentication\":{JsonStr(s.Authentication.ToString())}");
                if (s.Authentication != ShareAuthenticationKind.None)
                    sb.Append($",\"dealerKeyFingerprint\":{JsonStr(Fingerprint(s.DealerPublicKey.Span))}");
                sb.Append('}');
            }
            sb.Append("\n]");
            Console.WriteLine(sb.ToString());
            return 0;
        }

        foreach (var (file, s) in rows)
        {
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

    private static int Verify(string[] a)
    {
        var (pos, opts, _) = Parse(a, flagNames: new());
        if (pos.Count == 0)
            return Fail("usage: pqss verify <share.pqss> ... [--pub dealer.pub]");

        ReadOnlyMemory<byte>? pin = ReadPin(opts);
        var shares = pos.Select(f => (f, s: SecretShare.Import(ReadShareBytes(f)))).ToList();

        // Cross-share consistency: do they look like one split?
        SecretShare first = shares[0].s;
        bool consistent = shares.All(x =>
            x.s.Threshold == first.Threshold && x.s.TotalShares == first.TotalShares &&
            x.s.SecretLength == first.SecretLength && x.s.SplitId.Span.SequenceEqual(first.SplitId.Span));
        Console.WriteLine($"split consistency : {(consistent ? "OK (same splitId/policy)" : "MISMATCH — shares are not from one split")}");

        int bad = 0;
        foreach (var (f, s) in shares)
        {
            string status;
            if (s.Authentication == ShareAuthenticationKind.None)
                status = pin.HasValue ? "FAIL (unauthenticated, but a pin was given)" : "unauthenticated (nothing to verify)";
            else
                status = s.VerifySignature(pin) ? "OK (signature verified)" : "FAIL (signature/key did not verify)";

            if (status.StartsWith("FAIL")) bad++;
            Console.WriteLine($"  share {s.ShareIndex,-3} {Path.GetFileName(f),-28} {status}");
        }

        if (pin.HasValue && !consistent) bad++;
        return bad == 0 ? 0 : Fail($"{bad} share(s) failed verification.");
    }

    private static int Combine(string[] a)
    {
        var (pos, opts, flags) = Parse(a, flagNames: new() { "dry-run" });
        bool dryRun = flags.Contains("dry-run");
        if (pos.Count == 0)
            return Fail("usage: pqss combine <share.pqss> ... [--out FILE] [--pub dealer.pub] [--envelope FILE] [--commit FILE] [--dry-run]");
        if (!dryRun && !opts.ContainsKey("out"))
            return Fail("combine needs --out FILE (or use --dry-run to rehearse without writing the secret).");

        var shares = pos.Select(f => SecretShare.Import(ReadShareBytes(f))).ToList();
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

        string extras = (pin.HasValue ? "  (dealer key verified)" : "")
                      + (opts.ContainsKey("envelope") ? "  (unwrapped)" : "");

        if (dryRun)
        {
            // Rehearsal: prove reconstruction works and report a fingerprint, but
            // never write the secret to disk.
            Console.WriteLine($"DRY RUN OK: reconstructed {secret.Length} bytes from {shares.Count} shares{extras}");
            Console.WriteLine($"  secret fingerprint (sha256) : {Fingerprint(secret.Span)}  (compare across rehearsals)");
            return 0;
        }

        string outFile = opts["out"];
        File.WriteAllBytes(outFile, secret.Span.ToArray());
        Console.Error.WriteLine($"WARNING: reconstructed secret written in CLEARTEXT to '{outFile}'. Handle and delete with care.");
        Console.WriteLine($"recovered {secret.Length} bytes from {shares.Count} shares → '{outFile}'{extras}");
        return 0;
    }

    private static int Refresh(string[] a)
    {
        var (pos, opts, flags) = Parse(a, flagNames: new() { "sign" });
        if (pos.Count == 0)
            return Fail("usage: pqss refresh <share.pqss> ... --out DIR [--pub dealer.pub] [--k K --n N] [--sign] [--sk-out FILE]");

        string outDir = Req(opts, "out");
        Directory.CreateDirectory(outDir);

        var shares = pos.Select(f => SecretShare.Import(ReadShareBytes(f))).ToList();
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

    private static string JsonStr(string s)
        => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    /// <summary>Writes a share as binary <c>.pqss</c>, or armored ASCII <c>.pqss.txt</c> when requested.</summary>
    private static void WriteShare(string dir, SecretShare s, bool armor)
    {
        byte[] bytes = s.Export();
        if (armor)
            File.WriteAllText(Path.Combine(dir, $"share-{s.ShareIndex}.pqss.txt"), Armor.Encode(bytes));
        else
            File.WriteAllBytes(Path.Combine(dir, $"share-{s.ShareIndex}.pqss"), bytes);
    }

    /// <summary>Reads share bytes from a file, transparently de-armoring ASCII <c>.pqss.txt</c> files.</summary>
    private static byte[] ReadShareBytes(string path)
    {
        byte[] raw = File.ReadAllBytes(path);
        if (raw.Length > Armor.BeginMarker.Length && raw[0] == (byte)'-')
        {
            string text = System.Text.Encoding.UTF8.GetString(raw);
            if (text.Contains(Armor.BeginMarker, StringComparison.Ordinal))
                return Armor.Decode(text);
        }
        return raw;
    }

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
              pqss split   <secretFile> --k K --n N --out DIR [--sign] [--sk-out FILE] [--wrap] [--armor] [--commit-out FILE]
              pqss inspect <share> [<share> ...] [--json]
              pqss verify  <share> ... [--pub dealer.pub]
              pqss combine <share> ... [--out FILE | --dry-run] [--pub dealer.pub] [--envelope FILE] [--commit FILE]
              pqss refresh <share> ... --out DIR [--pub dealer.pub] [--k K --n N] [--sign] [--sk-out FILE]

            Shares may be binary (.pqss) or ASCII-armored (.pqss.txt); all commands auto-detect.

            COMMANDS
              split     Split a secret file into N shares (any K reconstruct).
                          --k          threshold K (2..255)
                          --n          total shares N (K..255)
                          --out        output directory for the shares
                          --sign       dealer-sign shares with ML-DSA-65 (net10.0; writes dealer.pub)
                          --sk-out     where to write the dealer PRIVATE key (default DIR/dealer.key)
                          --wrap       safe path for low-entropy/large secrets: split a random KEK
                                       and write an AES-GCM envelope.bin (needed at combine time)
                          --armor      write ASCII-armored .pqss.txt (printable/email-able) instead of binary
                          --commit-out write a one-time commitment to the secret (publish out-of-band)

              inspect   Print a share's metadata. Never reveals the secret or share data.
                          --json       emit machine-readable JSON

              verify    Check shares individually WITHOUT reconstructing: split consistency, and
                        (for signed shares) each ML-DSA-65 signature.
                          --pub        require each signature to verify against this pinned dealer key

              combine   Reconstruct the secret from EXACTLY K shares.
                          --out        file to write the recovered secret to (cleartext!)
                          --dry-run    rehearse: reconstruct + report a fingerprint, write nothing
                          --pub        pin: require every share to verify against this dealer key
                          --envelope   unwrap: combine KEK shares + envelope.bin from a --wrap split
                          --commit     verify the recovered secret against a published commitment

              refresh   Rotate custody: reconstruct and re-split into fresh shares (new splitId)
                          --out        output directory for the new shares
                          --pub        pin verifying the INCOMING shares
                          --k --n      optional new policy (default: same as input)
                          --sign       authenticate the NEW shares with a new dealer key

            EXAMPLES
              # Split 3-of-5, dealer-signed, ASCII-armored, with a commitment
              pqss split key.bin --k 3 --n 5 --out ./shares --sign --armor --commit-out ./key.commit

              # Verify each trustee's share as they present it (no quorum needed)
              pqss verify ./shares/share-2.pqss.txt --pub ./shares/dealer.pub

              # Rehearse the ceremony without exposing the secret, then do it for real
              pqss combine ./shares/share-1.pqss.txt ./shares/share-3.pqss.txt ./shares/share-5.pqss.txt \
                   --pub ./shares/dealer.pub --commit ./key.commit --dry-run
              pqss combine ./shares/share-1.pqss.txt ./shares/share-3.pqss.txt ./shares/share-5.pqss.txt \
                   --pub ./shares/dealer.pub --commit ./key.commit --out recovered.bin

              # Protect a low-entropy passphrase safely (wrap), then recover it
              pqss split pass.txt --k 2 --n 3 --out ./vault --wrap
              pqss combine ./vault/share-1.pqss ./vault/share-2.pqss --out pass.out --envelope ./vault/envelope.bin

              # Rotate custody after a trustee departs (new shares; old ones stop interoperating)
              pqss refresh ./shares/share-1.pqss.txt ./shares/share-3.pqss.txt ./shares/share-5.pqss.txt --out ./shares-v2

            NOTE
              Do not split low-entropy secrets (passphrases/PINs) directly — the check value is
              an offline guessing oracle. Use --wrap (or the WrappedSecret API).
            """);
    }
}

/// <summary>
/// PEM-style ASCII armor for shares, so they can be printed, pasted into email,
/// or written on paper and typed back. The payload is base64 of the canonical
/// <c>.pqss</c> bytes, wrapped at 64 columns.
/// </summary>
internal static class Armor
{
    internal const string BeginMarker = "-----BEGIN PQSS SHARE-----";
    internal const string EndMarker = "-----END PQSS SHARE-----";

    internal static string Encode(byte[] bytes)
    {
        string b64 = Convert.ToBase64String(bytes);
        var sb = new System.Text.StringBuilder();
        sb.Append(BeginMarker).Append('\n');
        for (int i = 0; i < b64.Length; i += 64)
            sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
        sb.Append(EndMarker).Append('\n');
        return sb.ToString();
    }

    internal static byte[] Decode(string text)
    {
        var sb = new System.Text.StringBuilder();
        bool inBlock = false;
        foreach (string line in text.Split('\n'))
        {
            string t = line.Trim();
            if (t == BeginMarker) { inBlock = true; continue; }
            if (t == EndMarker) break;
            if (inBlock && t.Length > 0) sb.Append(t);
        }
        return Convert.FromBase64String(sb.ToString());
    }
}
