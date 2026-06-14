# PostQuantum.SecretSharing.Vss

**Opt-in Verifiable Secret Sharing (VSS) for
[PostQuantum.SecretSharing](https://www.nuget.org/packages/PostQuantum.SecretSharing).**
Detect a *malicious dealer* who hands inconsistent shares to different trustees, so
every quorum is guaranteed to reconstruct the same secret.

> **Unaudited new cryptography.** It has not had an independent audit — but it is built
> to make one cheap (small novel surface, pinned wire format and vectors, reproducible
> evidence; see the
> [audit guide](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/VSS-AUDIT-GUIDE.md)).
> See the honest tradeoff below and the
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

### Optionally: post-quantum dealer-authentication of the broadcast (net10.0)

```csharp
// The dealer signs the commitment broadcast with ML-DSA-65, so trustees can confirm the
// pin they received came from the pinned dealer and was not substituted.
using var dealer = MlDsa65ShareAuthenticator.Generate();
byte[] dealerPin = dealer.PublicKey.ToArray();   // distribute/pin out-of-band, once

VssSplit signed = PedersenVss.Split(secret, new SharePolicy(3, 5), dealer);

// Each trustee checks the broadcast against the pinned dealer key…
bool authentic = signed.Commitments.VerifyDealerSignature(dealerPin);
// …in addition to verifying their own share against the (now-authenticated) commitments.
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
- [VSS audit guide (reviewer kit)](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/VSS-AUDIT-GUIDE.md)
- [Wire format — SPEC §v2](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/SPEC.md)
- [VSS test vectors](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/test-vectors-vss.md)
- [Repository](https://github.com/systemslibrarian/PostQuantum.SecretSharing)

## Status

Pedersen VSS over NIST P-256, with `.pqss` v2 records and a pinned nothing-up-my-sleeve
second generator. The commitment broadcast can be **ML-DSA-65–signed** by the dealer
(optional, net10.0); an unsigned broadcast must be pinned out-of-band like the dealer key.
The wire format is pinned in [SPEC §v2](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/SPEC.md)
and enforced by a worked-vector test, the v2 readers are coverage-fuzzed, and a dedicated
[audit guide](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/VSS-AUDIT-GUIDE.md)
ships with it. The one remaining step to a stable release is an **independent audit**.
