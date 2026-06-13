# PostQuantum.SecretSharing.Vss

**Opt-in Verifiable Secret Sharing (VSS) for
[PostQuantum.SecretSharing](https://www.nuget.org/packages/PostQuantum.SecretSharing).**
Detect a *malicious dealer* who hands inconsistent shares to different trustees, so
every quorum is guaranteed to reconstruct the same secret.

> **Preview, unaudited new cryptography.** Ships as `2.0.0-preview.x`. See the honest
> tradeoff below and the
> [design doc](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/VSS-DESIGN.md).

## Quick example

```csharp
using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Vss;
using System.Security.Cryptography;

byte[] secret = RandomNumberGenerator.GetBytes(32);

// Dealer splits 3-of-5 and publishes commitments (broadcast/pin them like a dealer key).
VssSplit split = PedersenVss.Split(secret, new SharePolicy(Threshold: 3, TotalShares: 5));
VssCommitments commitments = split.Commitments;

// Each trustee verifies their share BEFORE any reconstruction — a malicious dealer is
// caught here (Verify == false), not after recovering a wrong secret.
foreach (VssShare s in split.Shares)
    Console.WriteLine($"share {s.ShareIndex}: {s.Verify(commitments)}");

// Any K verified shares reconstruct; Reconstruct re-verifies and refuses bad inputs.
using ZeroizingBuffer recovered = PedersenVss.Reconstruct(
    new[] { split.Shares[0], split.Shares[2], split.Shares[4] }, commitments);
```

**▶ Runnable demo:**
[`samples/MaliciousDealerDetected`](https://github.com/systemslibrarian/PostQuantum.SecretSharing/tree/main/samples/MaliciousDealerDetected)
— an honest split where every trustee verifies, then a dealer who slips one trustee an
inconsistent share, caught before reconstruction.

## Why this is a separate package

The core `PostQuantum.SecretSharing` library is **dependency-free** and its secrecy is
**information-theoretic / post-quantum**. VSS needs a prime-order group (NIST P-256 via
a vetted EC dependency), so it lives here — you *opt in* to that dependency and to one
specific tradeoff:

- **Secrecy stays unconditional.** Pedersen commitments are *perfectly hiding*: the
  commitment transcript reveals nothing about the secret, against any adversary,
  including a quantum one. The headline guarantee is untouched.
- **Malicious-dealer *detection* is computational.** Commitment *binding* rests on
  discrete-log hardness. A quantum *dealer* could defeat the consistency check — not
  the secrecy. We document this exactly the way the core documents its ML-DSA layer.

## Documentation

- [VSS design & honest tradeoff](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/VSS-DESIGN.md)
- [VSS test vectors](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/test-vectors-vss.md)
- [Audit kit](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/AUDIT.md)
- [Repository](https://github.com/systemslibrarian/PostQuantum.SecretSharing)

## Status

Pedersen VSS over NIST P-256, with `.pqss` v2 records and a pinned nothing-up-my-sleeve
second generator. Preview-quality: the public API and format may still change, and
ML-DSA-signed commitments are a later preview (for now, pin the commitments out-of-band
like the dealer key).
