using System.Security.Cryptography;
using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Vss;

// MaliciousDealerDetected — Verifiable Secret Sharing (Pedersen VSS) in action.
//
// Plain Shamir authenticates shares *against the dealer* but cannot catch a
// *malicious dealer* who hands inconsistent shares to different trustees — so that
// different quorums rebuild different secrets, or some rebuild nothing. VSS closes
// that gap: the dealer publishes public commitments, and every trustee can verify,
// BEFORE any reconstruction, that their share lies on the one committed polynomial.
//
// Secrecy stays information-theoretic / post-quantum (the commitments are perfectly
// hiding); only this dealer-fraud *detection* is computational. Preview package
// (PostQuantum.SecretSharing.Vss) — see docs/VSS-DESIGN.md.

Console.WriteLine("PostQuantum.SecretSharing.Vss — MaliciousDealerDetected sample\n");

byte[] secret = RandomNumberGenerator.GetBytes(32);

// --- 1. An HONEST dealer: split 3-of-5 and publish the commitments. ---
VssSplit honest = PedersenVss.Split(secret, new SharePolicy(Threshold: 3, TotalShares: 5));
VssCommitments commitments = honest.Commitments;   // broadcast / pinned to every trustee

Console.WriteLine("Honest dealer split a 32-byte key 3-of-5 and published commitments.");
Console.WriteLine("Each trustee verifies their own share against those commitments:");
foreach (VssShare s in honest.Shares)
    Console.WriteLine($"  share {s.ShareIndex}: Verify = {s.Verify(commitments)}");

using (ZeroizingBuffer recovered = PedersenVss.Reconstruct(
           new[] { honest.Shares[0], honest.Shares[2], honest.Shares[4] }, commitments))
    Console.WriteLine($"\nQuorum {{1,3,5}} reconstructed the secret correctly: " +
                      $"{recovered.Span.SequenceEqual(secret)}\n");

// --- 2. A MALICIOUS dealer: secretly run a DIFFERENT split, then slip trustee 3 a
//        share from it while still publishing the original commitments. With plain
//        Shamir this is invisible until reconstruction yields garbage. With VSS it
//        is caught the moment trustee 3 verifies. ---
VssSplit shadow = PedersenVss.Split(RandomNumberGenerator.GetBytes(32), new SharePolicy(3, 5));
VssShare forgedForTrustee3 = shadow.Shares[2];     // index 3, but a different polynomial

Console.WriteLine("A malicious dealer slips trustee 3 a share from a DIFFERENT secret,");
Console.WriteLine("while publishing the original commitments. Trustee 3 checks first:");
Console.WriteLine($"  trustee 3: Verify = {forgedForTrustee3.Verify(commitments)}   " +
                  "<- caught before any reconstruction\n");

Console.WriteLine("And if the quorum tried to reconstruct with the bad share anyway,");
Console.WriteLine("reconstruction refuses rather than returning a wrong secret:");
try
{
    using ZeroizingBuffer _ = PedersenVss.Reconstruct(
        new[] { honest.Shares[0], honest.Shares[1], forgedForTrustee3 }, commitments);
    Console.WriteLine("  (unreachable: reconstruction should have thrown)");
}
catch (ShareConsistencyException ex)
{
    Console.WriteLine($"  Refused: {ex.Message}");
}

CryptographicOperations.ZeroMemory(secret);
Console.WriteLine("\nVSS turns \"trust the dealer\" into \"verify the dealer\". Soli Deo Gloria.");
