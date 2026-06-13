using System.Security.Cryptography;
using PostQuantum.SecretSharing;

// SignerCustody — a worked demonstration of quorum custody for a high-value
// signing key. It simulates an ML-DSA-style private key (here just random
// high-entropy bytes), splits it 3-of-5 among "trustees" with dealer
// authentication, persists each share to a .pqss file, then reconstructs the key
// from a quorum of exactly three — verifying the dealer signature against a
// pinned public key.
//
// This sample references the package as a project, not a NuGet dependency, and is
// the only place the suite is "integrated" — per the standalone design rule.

Console.WriteLine("PostQuantum.SecretSharing — SignerCustody sample\n");

if (!System.Security.Cryptography.MLDsa.IsSupported)
{
    Console.WriteLine("ML-DSA-65 is not supported on this platform; this sample needs it for");
    Console.WriteLine("dealer authentication. See the README platform matrix. Exiting.");
    return;
}

// 1) The secret to protect: a simulated 64-byte signing key (high entropy).
byte[] signingKey = RandomNumberGenerator.GetBytes(64);
Console.WriteLine($"Generated a simulated signing key ({signingKey.Length} bytes, high entropy).");

string outDir = Path.Combine(AppContext.BaseDirectory, "shares");
Directory.CreateDirectory(outDir);

// 2) The dealer machine generates an ML-DSA-65 key pair and splits 3-of-5.
using var dealer = MlDsa65ShareAuthenticator.Generate();
byte[] dealerPublicKey = dealer.PublicKey.ToArray();   // pin this out-of-band
Console.WriteLine($"Dealer public key fingerprint: {Fingerprint(dealerPublicKey)}");

SecretShare[] shares = ShamirSecretSharing.Split(signingKey, new SharePolicy(Threshold: 3, TotalShares: 5), dealer);
Console.WriteLine($"Split into {shares.Length} authenticated shares, 3 required to reconstruct.\n");

string[] trustees = { "IT Director", "Sysadmin", "Records Officer", "Offsite Safe", "County Attorney" };
foreach (SecretShare share in shares)
{
    string path = Path.Combine(outDir, $"share-{share.ShareIndex}.pqss");
    File.WriteAllBytes(path, share.Export());
    string splitPrefix = Convert.ToHexString(share.SplitId.Span)[..8].ToLowerInvariant();
    Console.WriteLine($"  share {share.ShareIndex} -> {trustees[share.ShareIndex - 1],-16} " +
                      $"(splitId {splitPrefix}…)  {Path.GetFileName(path)}");
}

// 3) Later: a quorum convenes. Exactly THREE custodians bring their shares.
Console.WriteLine("\nReconstruction ceremony: custodians 1, 3 and 4 convene.");
SecretShare[] quorum =
{
    SecretShare.Import(File.ReadAllBytes(Path.Combine(outDir, "share-1.pqss"))),
    SecretShare.Import(File.ReadAllBytes(Path.Combine(outDir, "share-3.pqss"))),
    SecretShare.Import(File.ReadAllBytes(Path.Combine(outDir, "share-4.pqss"))),
};

using (ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum, dealerPublicKey))
{
    bool match = signingKey.AsSpan().SequenceEqual(recovered.Span);
    Console.WriteLine($"  Signatures verified against the pinned dealer key.");
    Console.WriteLine($"  Reconstructed key matches original: {match}");
    // recovered.Span is zeroed and its pinned buffer wiped when this block exits.
}

// 4) Fewer than the quorum reveals nothing — and is refused.
Console.WriteLine("\nAttempting reconstruction with only TWO shares (below threshold):");
try
{
    _ = ShamirSecretSharing.Reconstruct(new[] { quorum[0], quorum[1] }, dealerPublicKey);
}
catch (SharePolicyException ex)
{
    Console.WriteLine($"  Refused, as expected: {ex.Message}");
}

CryptographicOperations.ZeroMemory(signingKey);
Console.WriteLine("\nDone. Soli Deo Gloria.");

static string Fingerprint(byte[] key)
    => Convert.ToHexString(SHA256.HashData(key))[..16].ToLowerInvariant();
