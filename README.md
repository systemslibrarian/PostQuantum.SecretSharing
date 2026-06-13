# PostQuantum.SecretSharing

[![CI](https://github.com/systemslibrarian/PostQuantum.SecretSharing/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.SecretSharing/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/PostQuantum.SecretSharing/actions/workflows/codeql.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.SecretSharing/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/systemslibrarian/PostQuantum.SecretSharing/badge)](https://scorecard.dev/viewer/?uri=github.com/systemslibrarian/PostQuantum.SecretSharing)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Your encrypted system is only as safe as the one key nobody knows where to keep.**

Split one high-value secret into *N* shares so that any *K* of them rebuild it —
and any *K−1* reveal **mathematically nothing**. No single person, machine, or
backup is a single point of failure or a single point of compromise.

```text
                                   ┌─ share 1  →  IT Director
                                   ├─ share 2  →  SRE on-call
   master key  ──[ 3-of-5 split ]──┼─ share 3  →  Security lead      any 3 of 5
   (32 bytes)                      ├─ share 4  →  Offsite safe       rebuild it;
                                   └─ share 5  →  Legal/compliance   any 2 reveal
                                                                     nothing
```

```bash
dotnet add package PostQuantum.SecretSharing --version 1.0.0-rc.1
```

```csharp
using PostQuantum.SecretSharing;
using System.Security.Cryptography;

byte[] masterKey = RandomNumberGenerator.GetBytes(32);

// Split 3-of-5 and hand each share to a different custodian.
SecretShare[] shares = ShamirSecretSharing.Split(masterKey, new SharePolicy(Threshold: 3, TotalShares: 5));
foreach (SecretShare s in shares)
    File.WriteAllBytes($"share-{s.ShareIndex}.pqss", s.Export());

// ...later, any three custodians convene and rebuild the key.
SecretShare[] quorum = new[]
{
    SecretShare.Import(File.ReadAllBytes("share-1.pqss")),
    SecretShare.Import(File.ReadAllBytes("share-3.pqss")),
    SecretShare.Import(File.ReadAllBytes("share-5.pqss")),
};
using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum);
// recovered.Span == masterKey, and is wiped from pinned memory on Dispose.
```

That's the whole idea. The rest of this README is about *when you need it* and
*how to use it correctly*.

### Why this over a general-purpose Shamir library?

A textbook Shamir gist — or a general-purpose package like
[SecretSharingDotNet](https://www.nuget.org/packages/SecretSharingDotNet) — splits
a secret and hands you the pieces. The math is the easy 5%. This library is built
around the other 95% — keeping the *share* trustworthy and the *ceremony*
operable:

- **Constant-time, table-free GF(2⁸) math.** No secret-indexed log/antilog table
  lookups — the classic cache-timing leak in Shamir implementations.
- **Authenticated shares (ML-DSA-65 / FIPS 204).** Detect a tampered or
  substituted share, pinned to *your* dealer key. Generic libraries hand back raw
  field points with nothing to verify.
- **A strict, canonical, self-describing share format (`.pqss`).** Versioned,
  fail-closed, fuzzed, and spec'd to the byte — not a bare `BigInteger` or base64
  blob you have to frame, version, and validate yourself.
- **Pinned, zeroizing, page-locked secret memory.** The reconstructed secret lands
  in a `ZeroizingBuffer` the GC can't relocate-and-copy, wiped on dispose — not a
  `string`/`byte[]` left for the collector to scatter.
- **A built-in wrap helper for low-entropy secrets.** `WrappedSecret` splits a
  random KEK and AES-256-GCM-seals your real secret, closing the offline-guessing
  oracle that bites naïve splitting of passphrases.
- **Ceremony tooling and operations docs.** A real `pqss` CLI, five runnable
  samples, and a trustee operations guide — not just a `Split()` you wire up alone.

If all you need is the polynomial math, a generic library is fine. If the secret
is *important enough to split*, the authentication, format, memory hygiene, and
ceremony around it are the actual job — and that is what this package is.

---

## The need: where one key becomes one liability

Almost every secure system eventually has a key that is **too important to lose
and too dangerous to concentrate**. Put it on one machine and that machine is a
single point of failure. Protect it with one passphrase and the passphrase is a
single point of guessing. Hand it to one administrator and that administrator is
a single point of trust.

Secret sharing dissolves that single point. You decide the quorum: "any 3 of
these 5 people," "both of these 2 plus one backup," "5 of 9 board members." Below
the quorum, the shares are useless — not "hard to crack," but provably empty of
information.

### Concrete problems this solves

| You have… | The pain | What this gives you |
|-----------|----------|---------------------|
| A **code / release signing key** | One developer can sign unilaterally — or lose the key and brick releases | `M-of-N` custody: no lone signer, no lone loss |
| A **root CA / trust-anchor private key** | The whole PKI hinges on one file in one HSM/safe | Quorum custody + dealer-authenticated shares (ML-DSA-65) |
| A **database / disk master key (KEK)** | Bus factor of 1; if the one holder is gone, data is gone | Recoverable by any quorum, survivable to lost shares |
| A **cloud KMS / vault unseal/root key** | Break-glass is a sticky note or a shared passphrase | Real `K-of-N` break-glass instead of a guessable secret |
| A **crypto wallet seed / treasury key** | Single seed phrase = single theft or single loss | Threshold custody across people and locations |
| **"God-mode" admin / root credentials** | One person silently holds total access | Require a quorum to assemble the credential |
| **Backup-encryption keys** | Keys escrowed next to the backups they protect | Distribute key shares across departments/sites |

### What you get that a passphrase or a single file does not

- **No single point of compromise.** Stealing one (or any `K−1`) shares yields
  *zero* information about the secret. This is provable, not "computationally
  expensive."
- **No single point of failure.** Lose up to `N−K` shares and you still recover.
- **No guessability.** Unlike a passphrase, shares are full-entropy data; there is
  nothing to brute-force below the quorum.
- **Survives quantum computers.** The secrecy guarantee is information-theoretic —
  it does not rest on any problem a quantum computer could solve (see below).
- **Tamper-evident.** With authenticated mode, a swapped or corrupted share is
  detected and rejected, not silently used.

---

## How it works in 30 seconds

Each byte of your secret becomes the constant term of a random polynomial of
degree `K−1` over the finite field GF(2⁸). A "share" is that polynomial evaluated
at a distinct point `x`. `K` points uniquely determine a degree-`K−1` polynomial
(so `K` shares rebuild the secret); `K−1` points are consistent with *every*
possible constant term equally (so they reveal nothing). That second fact is the
information-theoretic guarantee.

You never need to know the math to use the library — but you should know the one
honest caveat: the *scheme* is unconditionally secure; the *implementation*
(authentication, memory hygiene, the integrity check) is ordinary engineering,
documented plainly here and in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## Quick start

### 1. Unauthenticated split (integrity check only)

Good when shares live in trusted storage and you only need to detect *accidental*
corruption or mixed-up shares.

```csharp
using PostQuantum.SecretSharing;
using System.Security.Cryptography;

byte[] secret = RandomNumberGenerator.GetBytes(32);              // a 256-bit key

SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));
byte[][] files = shares.Select(s => s.Export()).ToArray();       // canonical .pqss bytes
CryptographicOperations.ZeroMemory(secret);                      // done with the plaintext

// Reconstruct from EXACTLY 3 shares (passing more is rejected — see FAQ).
SecretShare[] quorum = files.Take(3).Select(SecretShare.Import).ToArray();
using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum);
Console.WriteLine(recovered.Span.SequenceEqual(secret));         // (if you kept a copy)
```

### 2. Authenticated split (dealer-signed shares — net10.0)

Use this when shares travel through untrusted hands and you must detect a
**tampered or substituted** share. The dealer signs every share with ML-DSA-65
(FIPS 204); reconstruction verifies against a public key you **pin** out-of-band.

```csharp
using PostQuantum.SecretSharing;
using System.Security.Cryptography;

byte[] secret = RandomNumberGenerator.GetBytes(32);

using MlDsa65ShareAuthenticator dealer = MlDsa65ShareAuthenticator.Generate();
ReadOnlyMemory<byte> dealerPublicKey = dealer.PublicKey;         // PIN this (print it, store in config, read it aloud)

SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5), dealer);
CryptographicOperations.ZeroMemory(secret);

// Every share must be signed by the pinned dealer key, or reconstruction throws.
SecretShare[] quorum = /* import any 3 shares */ Array.Empty<SecretShare>();
using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum, dealerPublicKey);
```

> Keep the dealer **private** key with the same care as any signing key — anyone
> who has it can mint shares that pass your pin. Persist it with
> `dealer.ExportPrivateKey()` and reload it later with
> `MlDsa65ShareAuthenticator.ImportPrivateKey(...)`, or destroy it after the
> ceremony if you will never re-split.

### 3. Handling the secret safely

Reconstruction returns a `ZeroizingBuffer`, not a `byte[]`. It is allocated on the
pinned object heap (the GC can't relocate and silently copy it) and is zeroed when
disposed. **Always `using` it**, and don't copy `Span` into a long-lived array.

```csharp
using (ZeroizingBuffer key = ShamirSecretSharing.Reconstruct(quorum))
{
    using var aes = new AesGcm(key.Span, tagSizeInBytes: 16);
    // ...use key.Span for the minimum time needed...
}   // key is wiped here
```

---

## Choosing K and N

| Goal | Suggested policy | Why |
|------|------------------|-----|
| Sensible default | **3-of-5** | Survive losing 2 shares; resist any 2 colluding |
| Two-person rule + a backup | 2-of-3 | Either pair (or the backup) can act |
| High assurance | 5-of-9 | Larger collusion barrier, still tolerant of loss |
| Avoid | 2-of-2 | Lose either share → secret gone forever; no redundancy |
| Forbidden | 1-of-N | Every share *is* the secret — the library rejects `K=1` |

Rules of thumb: pick **K** so no realistically-collusion-prone subset reaches it,
and pick **N − K ≥ 2** so you can lose two shares and still recover. Limits:
`2 ≤ K ≤ N ≤ 255`, secret length `1..65536` bytes. See
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for running an actual ceremony.

---

## Splitting low-entropy secrets safely (the wrap pattern)

**Do not split a passphrase, PIN, or short password directly.** Every share
carries an HKDF check value that lets a *single* shareholder brute-force a
guessable secret offline (see "When NOT to use this"). Instead, split a random
key and let that key wrap your real secret.

The library does this for you with `WrappedSecret`:

```csharp
using PostQuantum.SecretSharing;
using System.Text;

byte[] realSecret = Encoding.UTF8.GetBytes("correct horse battery staple"); // low entropy!

// Generates a random KEK, AES-256-GCM-seals your secret, and splits the KEK.
WrappedSplit w = WrappedSecret.Split(realSecret, new SharePolicy(3, 5));
//   w.Shares   → give to trustees
//   w.Envelope → store anywhere; it is NOT secret

// Recover: any 3 KEK shares + the envelope.
using ZeroizingBuffer recovered = WrappedSecret.Reconstruct(
    new[] { w.Shares[0], w.Shares[2], w.Shares[4] }, w.Envelope);
```

Under the hood that is exactly the pattern below — shown explicitly in case you
want to manage the envelope yourself:

```csharp
using PostQuantum.SecretSharing;
using System.Security.Cryptography;

byte[] realSecret = Encoding.UTF8.GetBytes("correct horse battery staple"); // low entropy!

// 1. Generate a full-entropy key-encryption key and encrypt the real secret.
byte[] kek = RandomNumberGenerator.GetBytes(32);
byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
byte[] ciphertext = new byte[realSecret.Length];
byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
using (var aes = new AesGcm(kek, tag.Length))
    aes.Encrypt(nonce, realSecret, ciphertext, tag);

// 2. Split the KEK (high entropy ⇒ the check-value oracle is harmless), and store
//    nonce + ciphertext + tag alongside the shares (they are not secret).
SecretShare[] shares = ShamirSecretSharing.Split(kek, new SharePolicy(3, 5));
CryptographicOperations.ZeroMemory(kek);

// 3. To recover: reconstruct the KEK, then decrypt.
using ZeroizingBuffer recoveredKek = ShamirSecretSharing.Reconstruct(/* 3 shares */ shares.Take(3).ToList());
byte[] plaintext = new byte[ciphertext.Length];
using (var aes = new AesGcm(recoveredKek.Span, tag.Length))
    aes.Decrypt(nonce, ciphertext, tag, plaintext);
```

---

## API reference

| Member | Purpose |
|--------|---------|
| `SharePolicy(int Threshold, int TotalShares)` | The `K-of-N` policy. `2 ≤ K ≤ N ≤ 255`. |
| `ShamirSecretSharing.Split(secret, policy)` | Split into `N` unauthenticated shares. |
| `ShamirSecretSharing.Split(secret, policy, dealer)` | Split into `N` dealer-signed shares. |
| `ShamirSecretSharing.Reconstruct(shares)` | Rebuild from **exactly K** shares; returns a `ZeroizingBuffer`. |
| `ShamirSecretSharing.Reconstruct(shares, expectedDealerPublicKey)` | As above, but require every share to verify against the pinned key. |
| `ShamirSecretSharing.Refresh(shares, newPolicy?, expectedDealerPublicKey?, newDealer?)` | Rotate custody: re-split the same secret into fresh shares with a new `splitId` (old shares stop interoperating). |
| `WrappedSecret.Split(secret, policy[, dealer])` | Safe path for low-entropy/large secrets: random KEK + AES-256-GCM envelope; splits the KEK. Returns `WrappedSplit { Shares, Envelope }`. |
| `WrappedSecret.Reconstruct(shares, envelope[, expectedDealerPublicKey])` | Reconstruct the KEK and decrypt the envelope; returns a `ZeroizingBuffer`. |
| `DealerCommitment.Compute(secret)` / `.Verify(secret, commitment)` | Publish a one-time commitment to the intended secret; quorums confirm they recovered *that* value (not full VSS — see below). |
| `SecretShare.Export()` | Canonical `.pqss` bytes for distribution/storage. |
| `SecretShare.Import(bytes)` | Strict, fail-closed parse of `.pqss` bytes. |
| `SecretShare.{Threshold, TotalShares, ShareIndex, SecretLength, SplitId, Authentication, DealerPublicKey}` | Public metadata. (Raw `y` data is intentionally **not** exposed.) |
| `ZeroizingBuffer.Span` / `.Length` / `.IsMemoryLocked` / `.Dispose()` | Pinned, page-locked (best-effort), zeroizing access to the recovered secret. |
| `IShareAuthenticator` | Dealer-signer abstraction (`Kind`, `PublicKey`, `Sign`). |
| `MlDsa65ShareAuthenticator` *(net10.0)* | `Generate()`, `ImportPrivateKey()`, `ExportPrivateKey()`, `PublicKey`, `Sign()`. |
| `ShareAuthenticationKind` | `None` (0) or `MlDsa65` (1). |

---

## The one unconditional claim — and its precise limit

Shamir's scheme is **information-theoretically secure**: `K−1` shares reveal
nothing about the secret against **any** adversary — classical or quantum, with
unlimited compute. This is a mathematical fact about the scheme, not a
computational-hardness assumption. No future algorithm or machine weakens it.

That guarantee is about the **scheme**. Every *real* risk lives in the
**implementation** — share authentication, side channels, memory hygiene, and the
check-value oracle. We never let marketing language blur the two:

- **The scheme is unconditional.** `K−1` shares = zero information. Full stop.
- **The implementation is where you must trust engineering.** We document every
  one of those trust points honestly, including the unflattering ones.

This package is called *post-quantum* for two concrete reasons, neither of which
is "we hardened Shamir":

1. Its core security claim **survives quantum computers as a mathematical fact**.
2. Its authentication layer uses **ML-DSA-65 (FIPS 204)** — a post-quantum
   signature scheme — to authenticate shares against the dealer.

### Security layers

| Layer | Mechanism | Guarantee |
|-------|-----------|-----------|
| **Secrecy of the secret** | Shamir over GF(2⁸) | Information-theoretic. `K−1` shares reveal nothing, against any adversary, ever. |
| **Share authenticity** | ML-DSA-65 / FIPS 204 (optional) | Computational (post-quantum). Detects tampered/substituted shares when you pin the dealer key. |
| **Share integrity** | HKDF-SHA256 check value | Detects accidental corruption / mismatched shares at reconstruction. **Caveat:** also an offline guessing oracle for *low-entropy* secrets. |

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

- **You are splitting a low-entropy secret (passphrase, PIN, short password).**
  The integrity check value travels inside every share and is an **offline
  brute-force oracle**: a single shareholder can test guesses without any quorum.
  For a 32-byte random key this is irrelevant (2²⁵⁶ search). **Split keys, not
  passwords** — or use the built-in
  [`WrappedSecret`](#splitting-low-entropy-secrets-safely-the-wrap-pattern) helper,
  which splits a random key and wraps your real secret for you.
- **You have a single custodian.** Sharing among one person is pointless ceremony;
  just encrypt the secret.
- **You need verifiable secret sharing (VSS).** A *malicious dealer* can hand
  inconsistent shares to different trustees. v1 authenticates shares *against the
  dealer* and offers `DealerCommitment` (a one-time published commitment to the
  intended secret), but it cannot *prove* shares are mutually consistent before
  reconstruction. Full Feldman/Pedersen VSS needs a prime/EC group rather than
  GF(2⁸) and is explicitly a **v2** concern.
- **You need *distributed* proactive secret sharing.** `Refresh` rotates shares
  (re-split, new `splitId`) but is quorum-mediated — it briefly reconstructs the
  secret. A protocol that re-randomizes shares across parties *without* any
  reconstruction is out of scope.
- **You need a KMS.** This is a primitive, not a key-management service.

---

## How it compares

Honest positioning. "✅/❌" describe *this library's* choices, not a value judgment
of the alternatives — each tool solves a different problem.

| Capability | This library | Passphrase-encrypt a file | Naive XOR split | Vault's Shamir (unseal) | Typical generic Shamir lib |
|---|:--:|:--:|:--:|:--:|:--:|
| True `K`-of-`N` threshold (`K < N`) | ✅ | ❌ | ❌ (needs *all* parts) | ✅ | ✅ |
| Information-theoretic secrecy below quorum | ✅ | ❌ (brute-forceable) | ✅ | ✅ | usually ✅ |
| Survives quantum adversaries (secrecy) | ✅ | ❌ (KDF/cipher assumptions) | ✅ | ✅ | usually ✅ |
| Constant-time, table-free field math | ✅ | n/a | n/a | — | often ❌ (log tables) |
| Authenticated shares (tamper/substitution) | ✅ ML-DSA-65 | n/a | ❌ | ❌ | usually ❌ |
| Strict, canonical, self-describing share format | ✅ `.pqss` | n/a | ❌ | partial | varies |
| Pinned + zeroized + page-locked secret memory | ✅ | ❌ | ❌ | — | rarely |
| Built-in low-entropy wrap helper | ✅ | n/a | ❌ | n/a | ❌ |
| Ceremony tooling + operations guide | ✅ CLI + docs | ❌ | ❌ | ✅ | ❌ |
| Verifiable Secret Sharing (malicious dealer) | ❌ *(v2)* | n/a | ❌ | ❌ | rarely |
| Independently audited | ❌ *(honest)* | varies | n/a | ✅ | varies |

Where we deliberately **win**: memory hygiene, constant-time field math, a strict
format we control, post-quantum share authentication, and first-class ceremony
support. Where we **don't (yet)**: no VSS, and no independent audit — both stated
plainly rather than glossed over.

---

## Platform matrix

The **core has no platform blockers**. The Shamir engine, the CBOR codec, the
HKDF check value, and `ZeroizingBuffer` are pure managed code plus SHA-256/HKDF
from the BCL — so they run on **net8.0 everywhere, including macOS, iOS, and
Android.**

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

## Fail-closed guarantees

Every parse error, length mismatch, policy violation, or signature failure throws
a **specific** exception **before** any secret-dependent computation runs:

| Exception | Meaning |
|-----------|---------|
| `SecretSharingException` | Abstract base for all of the below. |
| `ShareFormatException` | Malformed / non-canonical `.pqss`, wrong type, unknown field, trailing bytes, presence contradicting the declared mode. |
| `SharePolicyException` | `K`, `N`, secret length, or share index out of range; wrong number of shares at reconstruct. |
| `ShareAuthenticationException` | Signature does not verify, or pinned dealer key mismatch. |
| `ShareConsistencyException` | Well-formed shares that cannot belong to one split (mixed split IDs, metadata, duplicate indices), or a check-value mismatch after interpolation. |

---

## Design decisions

- **No log/antilog tables in the field math.** Table lookups indexed by
  secret-dependent values are the classic cache-timing leak in Shamir libraries.
  All GF(2⁸) multiplication is branchless, fixed-iteration, table-free.
- **K=1 is banned.** With a threshold of one, every share *is* the secret —
  security theater, not sharing. The library refuses it.
- **Strict canonical CBOR we own.** The `.pqss` parser accepts only a tiny,
  fully-canonical subset (definite lengths, shortest-form integers, ascending
  unique integer keys, no trailing bytes, exact type per field). Hand-rolled (~150
  lines each way) rather than taking a dependency.
- **Exactly-K reconstruction.** Reconstruct requires *exactly* `K` shares, not "at
  least K." Silently using a subset would hide operator errors.
- **No RNG injection in the public API.** An injectable RNG in a secret-sharing
  library is a foot-gun. Test determinism comes from published reference vectors.
- **Pinned, zeroizing secret buffers.** Reconstructed secrets land in a
  `ZeroizingBuffer` on the pinned object heap, so the GC cannot relocate (and thus
  silently copy) the secret, and it is zeroed on dispose.

---

## FAQ

**Is this just `XOR`-style splitting?** No. Naive XOR splitting needs *all* shares
to recover. This is true threshold sharing: any `K` of `N`, with `K < N`.

**How is this "post-quantum" if Shamir is from 1979?** The secrecy guarantee is
information-theoretic, so it already survives quantum adversaries — and the
optional authentication layer uses ML-DSA-65 (FIPS 204), a post-quantum signature.

**Why exactly K shares, not "at least K"?** Passing extra shares usually means an
operator mistake (wrong pile, duplicates). Requiring exactly `K` surfaces that
instead of quietly succeeding from a subset.

**Why a `ZeroizingBuffer` instead of a `byte[]`?** So the secret lives in pinned
memory the GC can't copy, and is wiped deterministically on `Dispose`.

**Can I lose a share?** Yes — up to `N − K` of them. Plan `N − K ≥ 2`.

**Can I revoke a share?** Not really. A printed share exists forever. To remove a
trustee, **rotate the secret** and re-split; the old share then unlocks only a
retired secret. See [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

**What does a share look like on disk?** A compact, strictly-canonical CBOR map
(`.pqss`). The byte-level format is fully specified in [`docs/SPEC.md`](docs/SPEC.md).

**Is it fast?** A 3-of-5 split of a 32-byte key is well under a millisecond; a
64 KiB split + reconstruct is tens of milliseconds. It is a primitive, not a
bottleneck.

---

## Maturity

This package is **not audited.** It is carefully engineered — constant-time field
math, a strict parser, fail-closed validation, honest documentation — but
*carefully engineered* and *audited* are different claims, and we will not conflate
them. Treat it as a well-built primitive pending independent review. See
[`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) and
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the unvarnished limitations.

---

## Status & roadmap

**Current release: `1.0.0-rc.1`.** The information-theoretic core and the
engineering around it are feature-complete; the API and the `.pqss` format are
considered stable for the RC line and will not change without a SemVer signal.

| Area | Status |
|------|:------:|
| Shamir split/reconstruct over GF(2⁸), constant-time field math | ✅ Stable |
| Strict canonical `.pqss` format (spec'd, fuzzed, property-tested) | ✅ Stable |
| HKDF-SHA256 integrity check value | ✅ Stable |
| `ZeroizingBuffer` (pinned, zeroizing, best-effort page-lock) | ✅ Stable |
| ML-DSA-65 dealer authentication with key pinning *(net10.0)* | ✅ Stable |
| `WrappedSecret`, `Refresh`, `DealerCommitment`, per-share verify | ✅ Stable |
| `pqss` CLI, five samples, full docs | ✅ Stable |
| Independent security audit | ⏳ Not yet — *honestly stated, not implied* |

**What you can expect next** (intent, not a promise — full detail in
[`ROADMAP.md`](ROADMAP.md)):

- **Toward `1.0.0` stable:** independent review of the GF(2⁸) math and the CBOR
  codec, a written-up real-world dogfooding deployment, and a quiet RC period with
  no format/API churn.
- **`1.x` (additive, non-breaking):** more ecosystem samples (EF Core master key,
  cloud-KMS hybrid), more published cross-implementation test vectors, and an
  optional `…Extensions` package for higher-level ceremony helpers.
- **`v2` (opt-in, in preview now):** Verifiable Secret Sharing to detect a
  *malicious dealer* ships as the separate
  [`PostQuantum.SecretSharing.Vss`](docs/VSS-DESIGN.md) package (`2.0.0-preview.1`) —
  Pedersen VSS over P-256, kept out of the dependency-free core. Secrecy stays
  information-theoretic; only the dealer-fraud *detection* is computational (the
  honest tradeoff, documented). Distributed proactive refresh is still planned. See
  [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) §1.

What this deliberately is **not**, now or planned: a KMS, a way to safely split
low-entropy secrets directly (use `WrappedSecret`), or a defense against power/EM
side channels and process memory dumps.

---

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — byte-level `.pqss` format specification (with a worked, test-pinned hex example).
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — in/out of scope, plainly stated.
- [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) — real limitations, including the unflattering ones.
- [`docs/AUDIT.md`](docs/AUDIT.md) — reviewer's audit kit: scope, repro, ranked risk areas, and a checklist (we want this cheap to audit).
- [`docs/VSS-DESIGN.md`](docs/VSS-DESIGN.md) — design + tradeoffs of the opt-in Verifiable Secret Sharing (Pedersen) preview package, and [`docs/test-vectors-vss.md`](docs/test-vectors-vss.md).
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — trustee ceremony guide.
- [`docs/CASE-STUDY-signing-key.md`](docs/CASE-STUDY-signing-key.md) — a verified, reproducible ceremony protecting a code-signing key (with byte-identical + signature proofs).
- [`docs/test-vectors.md`](docs/test-vectors.md) — cross-implementation test vectors.
- [`samples/`](samples) — five runnable samples: `SignerCustody` (authenticated 3-of-5 custody), `EnvelopeRecovery` (the wrap pattern, net8.0), `VaultUnseal` (Vault-style sealed service), `AspNetCoreDataProtection` (encrypt the DP key ring behind a quorum), and `pqss` (a real split/inspect/verify/combine/refresh CLI).
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — throughput numbers and constant-time evidence (and how to reproduce).
- [`fuzz/`](fuzz) — coverage-guided (SharpFuzz + libFuzzer) fuzzing of the `.pqss` parser; runs in CI.
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) — `.pqss` format-stability and SemVer policy.
- [`docs/SUPPLY-CHAIN.md`](docs/SUPPLY-CHAIN.md) — build provenance, SBOM, reproducible builds, and how to verify a release yourself.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build/test, the API-lock and banned-API gates, and the release ritual.
- [`ROADMAP.md`](ROADMAP.md) — v1 / v1.x / v2 plan. [`CHANGELOG.md`](CHANGELOG.md) — release history.
- [`SECURITY.md`](SECURITY.md) — how to report vulnerabilities.

---

## License

MIT. See [`LICENSE`](LICENSE).

---

*Soli Deo Gloria — 1 Corinthians 10:31*
