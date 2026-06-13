# PostQuantum.SecretSharing

**Your encrypted system is only as safe as the one key nobody knows where to keep.**

Many systems end up with a single high-value key — a signing key, a root of
trust, or a recovery key — that is too important to leave on one machine or
behind one passphrase, but too sensitive to distribute casually. Any system whose
trust hangs on such a key has a custody problem; one whose break-glass path is a
passphrase has a guessability problem.

PostQuantum.SecretSharing gives you **quorum custody** for that key. It implements
[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
over GF(2⁸) with an authenticated, versioned, strict-canonical-CBOR share file
format (`.pqss`): split any high-entropy secret into *N* shares such that any *K*
can reconstruct it, while any *K−1* reveal **information-theoretically nothing**.
It replaces fragile single-custodian or passphrase-based recovery with something
stronger and information-theoretically sound.

It is a standalone member of the `systemslibrarian` **PostQuantum.\*** family.

> **Standalone by design.** This package has *zero* dependencies on any other
> PostQuantum.\* package, in either direction, and no third-party crypto
> dependencies at all (BCL only). Any integration with the rest of the suite
> happens later through a *sample*, never a reference.

---

## The one unconditional claim — and its precise limit

Shamir's scheme is **information-theoretically secure**: *K−1* shares reveal
nothing about the secret against **any** adversary — classical or quantum, with
unlimited compute. This is a mathematical fact about the scheme, not a
computational-hardness assumption. No future algorithm or machine weakens it.

That guarantee is about the **scheme**. Every *real* risk lives in the
**implementation** — share authentication, side channels, memory hygiene, and the
check-value oracle (see below). We are scrupulous about this distinction and never
let marketing language blur it:

- **The scheme is unconditional.** *K−1* shares = zero information. Full stop.
- **The implementation is where you must trust engineering.** We document every
  one of those trust points honestly, including the ones that make us look worse.

This package is called *post-quantum* for two concrete reasons, neither of which
is "we hardened Shamir":

1. Its core security claim **survives quantum computers as a mathematical fact**.
2. Its authentication layer uses **ML-DSA-65 (FIPS 204)** — a post-quantum
   signature scheme — to authenticate shares against the dealer.

---

## Security layers

| Layer | Mechanism | Guarantee |
|-------|-----------|-----------|
| **Secrecy of the secret** | Shamir over GF(2⁸) | Information-theoretic. *K−1* shares reveal nothing, against any adversary, ever. |
| **Share authenticity** | ML-DSA-65 / FIPS 204 (optional) | Computational (post-quantum). Detects tampered or substituted shares when you pin the dealer key. |
| **Share integrity** | HKDF-SHA256 check value | Detects accidental corruption / mismatched shares at reconstruction. **Caveat:** it is also an offline guessing oracle for *low-entropy* secrets — see below. |

---

## Quick start

### Unauthenticated split (integrity check only)

```csharp
using PostQuantum.SecretSharing;
using System.Security.Cryptography;

byte[] secret = RandomNumberGenerator.GetBytes(32);          // a 256-bit key

// Split 3-of-5.
SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(Threshold: 3, TotalShares: 5));

// Serialize each share to its canonical .pqss bytes for distribution.
byte[][] files = shares.Select(s => s.Export()).ToArray();

// ...later, gather EXACTLY 3 shares and reconstruct:
SecretShare[] quorum = files.Take(3).Select(f => SecretShare.Import(f)).ToArray();
using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum);
// recovered.Span now holds the 32-byte secret; it is zeroed and pinned on Dispose.
```

### Authenticated split (dealer-signed shares, net10.0)

```csharp
using var dealer = MlDsa65ShareAuthenticator.Generate();
ReadOnlyMemory<byte> dealerPubKey = dealer.PublicKey;        // pin this out-of-band

SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5), dealer);

// Reconstruct, REQUIRING every share to be signed by the pinned dealer key:
SecretShare[] quorum = /* import 3 shares */;
using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum, dealerPubKey);
```

---

## Trust model in one paragraph

`expectedDealerPublicKey` **is your pin.** When you supply it, every share must be
authenticated, carry exactly that key, and verify — otherwise reconstruction
throws. When you omit it but the shares carry signatures anyway, the signatures
are still verified against the *embedded* key as defense in depth — but understand
what that is: **embedded-key-only verification is self-attestation, not
authority.** A forged set of shares can embed any key and sign with it. Only a
pin you obtained out-of-band proves the shares came from *your* dealer.

---

## When **NOT** to use this

- **You are splitting a low-entropy secret (a passphrase, a PIN, a short
  password).** The integrity check value travels inside every share and is an
  **offline brute-force oracle** for anything guessable: a single shareholder can
  test guesses of the secret without any quorum. For a 32-byte random key this is
  irrelevant (2²⁵⁶ search). **Split keys, not passwords — or split a random key
  that wraps your real secret.**
- **You have a single custodian.** Secret sharing among one person is pointless
  ceremony; just encrypt the secret.
- **You need verifiable secret sharing (VSS).** A *malicious dealer* can hand
  inconsistent shares to different trustees. v1 authenticates shares *against the
  dealer*; it cannot detect a dealer lying *differently* to different trustees.
  Feldman/Pedersen VSS is explicitly a **v2** concern.
- **You need share refresh / proactive secret sharing.** Rotating shares without
  changing the secret is not in v1.
- **You need a KMS.** This is a primitive, not a key-management service.

---

## Platform matrix

Unlike the rest of the suite, the **core of this package has no platform
blockers**. The Shamir engine, the CBOR codec, the HKDF check value, and
`ZeroizingBuffer` are pure managed code plus SHA-256/HKDF from the BCL — so they
run on **net8.0 everywhere, including macOS, iOS, and Android.** That is a
feature, and we advertise it.

| Component | Windows | Linux | macOS | iOS / Android |
|-----------|:-------:|:-----:|:-----:|:-------------:|
| **Core** (split, reconstruct, `.pqss`, check value, `ZeroizingBuffer`) | ✅ | ✅ | ✅ | ✅ |
| **ML-DSA-65 authenticator** (`MlDsa65ShareAuthenticator`, net10.0) | ✅ | ✅ (OpenSSL ≥ 3.5) | ❌ (upstream) | ❌ |

The ML-DSA-65 authenticator compiles only under `net10.0` and additionally guards
at runtime on `MLDsa.IsSupported`, throwing `PlatformNotSupportedException` (with a
pointer back to this matrix) where FIPS 204 is unavailable. **macOS lacks ML-DSA
support upstream** — the *core* still runs there fully; only the optional signing
layer does not. CI proves this by running the full net8.0 suite on macOS and
letting the ML-DSA tests skip.

---

## Targets

- **`src`** multi-targets **`net8.0;net10.0`**.
- **Tests** multi-target the same pair; ML-DSA test classes skip at runtime on
  platforms without FIPS 204.
- `LangVersion latest`, `nullable enable`, `TreatWarningsAsErrors true`,
  deterministic build, SourceLink, embedded untracked sources, CI build flag.

---

## Design decisions

- **No log/antilog tables in the field math.** Table lookups indexed by
  secret-dependent values are the classic cache-timing leak in Shamir libraries.
  All GF(2⁸) multiplication is branchless, fixed-iteration, table-free.
- **K=1 is banned.** With a threshold of one, every share *is* the secret — that
  is security theater, not sharing. The library refuses it.
- **Strict canonical CBOR we own.** The `.pqss` parser accepts only a tiny,
  fully-canonical subset (definite lengths, shortest-form integers, ascending
  unique integer keys, no trailing bytes, exact type per field). Unknown fields,
  non-canonical encodings, and trailing bytes are rejected. We hand-roll the ~150-
  line reader/writer rather than take a dependency, matching the suite's
  "strict v1 parser we control" philosophy.
- **Exactly-K reconstruction.** Reconstruct requires *exactly* `k` shares, not
  "at least k." Silently using a subset would hide operator errors; we make you
  pick the quorum deliberately.
- **No RNG injection in the public API.** An injectable RNG in a secret-sharing
  library is a foot-gun. Determinism for tests comes from published reference
  vectors, not from a seam an attacker (or a careless caller) could exploit.
- **Pinned, zeroizing secret buffers.** Reconstructed secrets land in a
  `ZeroizingBuffer` allocated on the pinned object heap, so the GC cannot relocate
  (and thus silently copy) the secret, and it is zeroed on dispose.

---

## Fail-closed guarantees

Every parse error, length mismatch, policy violation, or signature failure throws
a **specific** exception **before** any secret-dependent computation runs:

| Exception | Meaning |
|-----------|---------|
| `SecretSharingException` | Abstract base for all of the below. |
| `ShareFormatException` | Malformed / non-canonical `.pqss`, wrong type, unknown field, trailing bytes, presence contradicting the declared mode. |
| `SharePolicyException` | `k`, `n`, secret length, or share index out of range; wrong number of shares at reconstruct. |
| `ShareAuthenticationException` | Signature does not verify, or pinned dealer key mismatch. |
| `ShareConsistencyException` | Well-formed shares that cannot belong to one split (mixed split IDs, metadata, duplicate indices), or a check-value mismatch after interpolation. |

---

## Maturity

This package is **not audited.** It is carefully engineered — constant-time field
math, a strict parser, fail-closed validation, honest documentation — but
*carefully engineered* and *audited* are different claims, and we will not conflate
them. Treat it as a well-built primitive pending independent review. See
[`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) and
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the unvarnished limitations,
and [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for running an actual trustee
ceremony.

---

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — byte-level `.pqss` format specification.
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — in/out of scope, plainly stated.
- [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) — real limitations, including the unflattering ones.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — trustee ceremony guide.
- [`docs/test-vectors.md`](docs/test-vectors.md) — cross-implementation test vectors.
- [`SECURITY.md`](SECURITY.md) — how to report vulnerabilities.

---

*Soli Deo Gloria — 1 Corinthians 10:31*
