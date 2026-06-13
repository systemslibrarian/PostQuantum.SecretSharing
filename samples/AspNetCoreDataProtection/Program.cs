using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PostQuantum.SecretSharing;

// AspNetCoreDataProtection — protect the ASP.NET Core Data Protection key ring at
// rest behind a K-of-N quorum.
//
// ASP.NET Core Data Protection persists its key ring (the keys that protect auth
// cookies, antiforgery tokens, etc.) to storage, and supports encrypting those
// keys "at rest" via a custom IXmlEncryptor/IXmlDecryptor. Here, the key-
// encryption key (KEK) used for that at-rest encryption is itself split with
// PostQuantum.SecretSharing: the app cannot read its own key ring until a quorum
// of operators unseals the KEK. Lose the box and N−K shares — the key ring on
// disk is inert.
//
// (For sample clarity the unsealed KEK is held in an ambient holder, because the
// Data Protection activator instantiates the decryptor with a parameterless
// constructor. A production app would wire this through DI; the integration point
// — a quorum-reconstructed KEK as the at-rest key — is identical.)

Console.WriteLine("PostQuantum.SecretSharing — ASP.NET Core Data Protection sample\n");

string keyDir = Path.Combine(AppContext.BaseDirectory, "dp-keys");
Directory.CreateDirectory(keyDir);
foreach (string f in Directory.GetFiles(keyDir)) File.Delete(f);   // clean slate for the demo

// ── Provisioning: split the at-rest KEK 3-of-5 (done once by operators) ────────
byte[] kek = RandomNumberGenerator.GetBytes(32);
SecretShare[] shares = ShamirSecretSharing.Split(kek, new SharePolicy(Threshold: 3, TotalShares: 5));
byte[][] shareFiles = shares.Select(s => s.Export()).ToArray();
CryptographicOperations.ZeroMemory(kek);
Console.WriteLine("Provisioned: Data Protection at-rest KEK split 3-of-5 among operators.\n");

// ── App startup #1: unseal with a quorum, protect a payload ───────────────────
Console.WriteLine("App start #1: unsealing the KEK from operators 1, 2, 4 …");
const string payload = "auth-cookie-protected-claim: user=42; role=admin";
string protectedBlob;
Unseal(shareFiles, 1, 2, 4);
using (ServiceProvider sp = BuildDataProtection(keyDir))
{
    IDataProtector protector = sp.GetDataProtectionProvider().CreateProtector("demo.purpose");
    protectedBlob = protector.Protect(payload);
    Console.WriteLine("  protected a payload; key ring written to disk.");
}

// Show the key ring on disk is encrypted at rest (our marker, not raw key material).
string keyXml = Directory.GetFiles(keyDir, "key-*.xml").Select(File.ReadAllText).FirstOrDefault() ?? "";
bool encryptedAtRest = keyXml.Contains("PqssQuorumEncryptedKey", StringComparison.Ordinal);
Console.WriteLine($"  key ring encrypted at rest by the quorum KEK: {encryptedAtRest}\n");

// ── Stolen disk, NO quorum: the key ring is inert ─────────────────────────────
Console.WriteLine("Stolen disk, NO quorum: a fresh process tries to read the key ring …");
AmbientKek.Clear();
using (ServiceProvider sp = BuildDataProtection(keyDir))
{
    try
    {
        sp.GetDataProtectionProvider().CreateProtector("demo.purpose").Unprotect(protectedBlob);
        Console.WriteLine("  (unexpected) it succeeded without a quorum — that would be a bug.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  refused — the key ring cannot be decrypted without the quorum KEK ({ex.GetType().Name}).");
    }
}
Console.WriteLine();

// ── App restart #2: fresh provider; a different quorum unseals the same KEK ────
Console.WriteLine("App start #2 (simulated restart): a DIFFERENT quorum (3, 4, 5) unseals …");
Unseal(shareFiles, 3, 4, 5);
using (ServiceProvider sp = BuildDataProtection(keyDir))
{
    IDataProtector protector = sp.GetDataProtectionProvider().CreateProtector("demo.purpose");
    string recovered = protector.Unprotect(protectedBlob);
    Console.WriteLine($"  unprotected payload: \"{recovered}\"");
    Console.WriteLine($"  matches original: {recovered == payload}\n");
}

AmbientKek.Clear();
Console.WriteLine("Without a quorum, the on-disk key ring cannot be decrypted — so the");
Console.WriteLine("cookies/tokens it protects cannot be forged from a stolen disk alone.");
Console.WriteLine("\nDone. Soli Deo Gloria.");

// ── helpers ───────────────────────────────────────────────────────────────────

// Reconstruct the KEK from exactly k shares (by 1-based index) into the ambient holder.
static void Unseal(byte[][] shareFiles, params int[] indices)
{
    SecretShare[] quorum = indices.Select(i => SecretShare.Import(shareFiles[i - 1])).ToArray();
    using ZeroizingBuffer kek = ShamirSecretSharing.Reconstruct(quorum);
    AmbientKek.Set(kek.Span.ToArray());
}

static ServiceProvider BuildDataProtection(string keyDir)
{
    var services = new ServiceCollection();
    services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keyDir));
    services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(
        new ConfigureOptions<KeyManagementOptions>(o => o.XmlEncryptor = new QuorumXmlEncryptor()));
    return services.BuildServiceProvider();
}

/// <summary>Holds the unsealed at-rest KEK for the current app run.</summary>
internal static class AmbientKek
{
    private static byte[]? _kek;
    public static void Set(byte[] kek) => _kek = kek;
    public static byte[] Require() => _kek ?? throw new InvalidOperationException("KEK is not unsealed.");
    public static void Clear()
    {
        if (_kek is not null) CryptographicOperations.ZeroMemory(_kek);
        _kek = null;
    }
}

/// <summary>Encrypts Data Protection key-ring XML at rest with the quorum KEK (AES-256-GCM).</summary>
internal sealed class QuorumXmlEncryptor : IXmlEncryptor
{
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[plaintext.Length];
        using (var aes = new AesGcm(AmbientKek.Require(), 16))
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] envelope = new byte[12 + 16 + ciphertext.Length];
        nonce.CopyTo(envelope, 0);
        tag.CopyTo(envelope, 12);
        ciphertext.CopyTo(envelope, 28);

        var element = new XElement("PqssQuorumEncryptedKey",
            new XElement("value", Convert.ToBase64String(envelope)));
        return new EncryptedXmlInfo(element, typeof(QuorumXmlDecryptor));
    }
}

/// <summary>Decrypts key-ring XML previously sealed by <see cref="QuorumXmlEncryptor"/>.</summary>
internal sealed class QuorumXmlDecryptor : IXmlDecryptor
{
    public XElement Decrypt(XElement encryptedElement)
    {
        byte[] envelope = Convert.FromBase64String(encryptedElement.Element("value")!.Value);
        ReadOnlySpan<byte> nonce = envelope.AsSpan(0, 12);
        ReadOnlySpan<byte> tag = envelope.AsSpan(12, 16);
        ReadOnlySpan<byte> ciphertext = envelope.AsSpan(28);

        byte[] plaintext = new byte[ciphertext.Length];
        using (var aes = new AesGcm(AmbientKek.Require(), 16))
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return XElement.Parse(Encoding.UTF8.GetString(plaintext));
    }
}
