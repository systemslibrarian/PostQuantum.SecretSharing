using System.Security.Cryptography;
using System.Text;
using PostQuantum.SecretSharing;

// EnvelopeRecovery — the "wrap pattern" for protecting arbitrary (even low-entropy)
// data with threshold custody.
//
// You should NOT split a passphrase, PIN, or any guessable secret directly: every
// share carries an HKDF check value that lets a single shareholder brute-force a
// guessable secret offline. The fix is to split a full-entropy key, and let that
// key wrap your real data with authenticated encryption (AES-GCM).
//
// This sample:
//   1. takes a "recovery document" (could be a passphrase, API token, or a file),
//   2. encrypts it under a random 256-bit key-encryption key (KEK),
//   3. splits the KEK 3-of-5 and writes shares + a (non-secret) envelope,
//   4. shows that fewer than 3 shares — and the envelope alone — reveal nothing,
//   5. reconstructs the KEK from a quorum and decrypts.
//
// Runs on net8.0 — no ML-DSA required — to demonstrate the platform-portable core.

Console.WriteLine("PostQuantum.SecretSharing — EnvelopeRecovery sample (wrap pattern)\n");

// The real secret to protect. Deliberately low-entropy to make the point.
const string recoveryDocument =
    "PROD database break-glass passphrase: correct-horse-battery-staple-2026";
byte[] plaintext = Encoding.UTF8.GetBytes(recoveryDocument);
Console.WriteLine($"Protecting a {plaintext.Length}-byte recovery document (low entropy — must be wrapped).\n");

string dir = Path.Combine(AppContext.BaseDirectory, "vault");
Directory.CreateDirectory(dir);

// --- 1. Wrap: encrypt the document under a random KEK with AES-GCM. ---
byte[] kek = RandomNumberGenerator.GetBytes(32);
byte[] envelope = Envelope.Seal(kek, plaintext);
File.WriteAllBytes(Path.Combine(dir, "document.envelope"), envelope);
Console.WriteLine($"Sealed envelope ({envelope.Length} bytes) written: nonce + tag + ciphertext.");
Console.WriteLine("  The envelope is NOT secret — it is useless without the KEK.\n");

// --- 2. Split the high-entropy KEK 3-of-5. ---
SecretShare[] shares = ShamirSecretSharing.Split(kek, new SharePolicy(Threshold: 3, TotalShares: 5));
CryptographicOperations.ZeroMemory(kek);   // forget the KEK; only the shares remain
foreach (SecretShare s in shares)
    File.WriteAllBytes(Path.Combine(dir, $"kek-share-{s.ShareIndex}.pqss"), s.Export());
Console.WriteLine("Split the KEK into 5 shares (any 3 recover it):");
foreach (SecretShare s in shares)
    Console.WriteLine($"  kek-share-{s.ShareIndex}.pqss  (splitId {Convert.ToHexString(s.SplitId.Span)[..8].ToLowerInvariant()}…)");
Console.WriteLine();

// --- 3. Demonstrate that a sub-quorum reveals nothing and is refused. ---
Console.WriteLine("Trying to recover the KEK with only 2 shares (below threshold):");
try
{
    _ = ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[1] });
}
catch (SharePolicyException ex)
{
    Console.WriteLine($"  Refused: {ex.Message}\n");
}

// --- 4. Recover: reconstruct the KEK from a quorum, then decrypt. ---
Console.WriteLine("Quorum convenes with shares 1, 2 and 4. Recovering...");
SecretShare[] quorum =
{
    SecretShare.Import(File.ReadAllBytes(Path.Combine(dir, "kek-share-1.pqss"))),
    SecretShare.Import(File.ReadAllBytes(Path.Combine(dir, "kek-share-2.pqss"))),
    SecretShare.Import(File.ReadAllBytes(Path.Combine(dir, "kek-share-4.pqss"))),
};
byte[] storedEnvelope = File.ReadAllBytes(Path.Combine(dir, "document.envelope"));

using (ZeroizingBuffer recoveredKek = ShamirSecretSharing.Reconstruct(quorum))
{
    byte[] recovered = Envelope.Open(recoveredKek.Span, storedEnvelope);
    string text = Encoding.UTF8.GetString(recovered);
    Console.WriteLine($"  Decrypted document: \"{text}\"");
    Console.WriteLine($"  Matches original:   {text == recoveryDocument}");
    CryptographicOperations.ZeroMemory(recovered);
}

CryptographicOperations.ZeroMemory(plaintext);
Console.WriteLine("\nDone. The real secret never had to be high-entropy — the KEK did. Soli Deo Gloria.");

/// <summary>A minimal AES-256-GCM envelope: layout is [nonce(12)] [tag(16)] [ciphertext].</summary>
internal static class Envelope
{
    private const int NonceLen = 12;
    private const int TagLen = 16;

    internal static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLen);
        byte[] tag = new byte[TagLen];
        byte[] ciphertext = new byte[plaintext.Length];
        using (var aes = new AesGcm(key, TagLen))
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] envelope = new byte[NonceLen + TagLen + ciphertext.Length];
        nonce.CopyTo(envelope.AsSpan(0));
        tag.CopyTo(envelope.AsSpan(NonceLen));
        ciphertext.CopyTo(envelope.AsSpan(NonceLen + TagLen));
        return envelope;
    }

    internal static byte[] Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> envelope)
    {
        ReadOnlySpan<byte> nonce = envelope[..NonceLen];
        ReadOnlySpan<byte> tag = envelope.Slice(NonceLen, TagLen);
        ReadOnlySpan<byte> ciphertext = envelope[(NonceLen + TagLen)..];
        byte[] plaintext = new byte[ciphertext.Length];
        using (var aes = new AesGcm(key, TagLen))
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
