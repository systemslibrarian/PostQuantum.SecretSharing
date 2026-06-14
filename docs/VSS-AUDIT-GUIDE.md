# VSS Audit Guide

> **Status:** the opt-in `PostQuantum.SecretSharing.Vss` package is **not** independently
> audited (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §9). This document does not claim
> otherwise. Like the core's [`AUDIT.md`](AUDIT.md), it exists to make a review *cheap*:
> everything an auditor needs is in this repository, the **novel** code is small (~840
> lines, with the error-prone field/curve arithmetic delegated to a vetted library), and
> every security-relevant claim has reproducible in-repo evidence.

This is the VSS-specific companion to [`AUDIT.md`](AUDIT.md) (which covers the core). Read
[`VSS-DESIGN.md`](VSS-DESIGN.md) for the design rationale and [`SPEC.md`](SPEC.md) §v2 for
the byte-level wire format; this guide tells you **what to verify, in what order, and how
to reproduce the evidence**.

---

## 1. The one decision that frames the whole review

This library's headline is **information-theoretic, survives-quantum secrecy**. VSS adds a
*verifiability* layer without weakening that. The two properties have **different standards
of proof** and must be reviewed separately:

| Claim | Type | Quantum adversary? | Where it lives |
|-------|------|--------------------|----------------|
| `K−1` shares + all commitments reveal **nothing** about the secret | **Unconditional** (information-theoretic) | the Pedersen blinding: `p'_k`, the `·H` term in `Commit` |
| A **malicious dealer**'s inconsistent shares are detected | **Computational** (discrete-log binding of Pedersen) | the verification equation in `VssShare.Verify` |
| The **broadcast** came from the pinned dealer (not substituted) | **Computational** (ML-DSA-65 / FIPS 204) | `VssCommitments.VerifyDealerSignature` |

The crucial, must-be-true claim is the first one. **Pedersen commitments are perfectly
hiding**: `C = a·G + b·H` with uniform blinding `b` is a uniformly-distributed group
element regardless of `a`, so the transcript (all commitments + up to `K−1` shares) is
independent of the secret — even against an unbounded/quantum adversary. The second and
third claims are *detection* layers; they rest on discrete-log hardness and so degrade
against a **quantum dealer**. This asymmetry (secrecy unconditional, detection
computational) is the single most important thing to confirm is stated honestly
everywhere. It is — see [`VSS-DESIGN.md`](VSS-DESIGN.md) §2 and the XML docs on
`PedersenVss`.

---

## 2. One-command bootstrap

```bash
git clone https://github.com/systemslibrarian/PostQuantum.SecretSharing
cd PostQuantum.SecretSharing

# Build the VSS package (warnings are errors; a clean build is part of the claim).
dotnet build src/PostQuantum.SecretSharing.Vss/PostQuantum.SecretSharing.Vss.csproj -c Release

# Full VSS suite, both target frameworks.
dotnet test tests/PostQuantum.SecretSharing.Vss.Tests/PostQuantum.SecretSharing.Vss.Tests.csproj -c Release
```

Requires the .NET 8 and .NET 10 SDKs. `net10.0` exercises the ML-DSA-65 broadcast-signing
tests; on macOS those skip (no upstream FIPS 204) and the rest of the suite still passes.

---

## 3. The review surface (what is, and isn't, yours to audit)

The entire package is **~840 lines across 8 files**. The split is deliberate
(audit-readiness): the heavy, error-prone EC and big-integer arithmetic is **delegated to
BouncyCastle**, so what you actually review is a thin, readable protocol layer.

| File | Lines | What it is | Audit weight |
|------|------:|-----------|:------------:|
| `Internal/Secp256r1Group.cs` | 221 | Adapter over BouncyCastle P-256: scalar/point codecs, `Commit`, polynomial eval, Lagrange-at-0, **`H` derivation**, the RNG seam. | **High** |
| `Internal/Vss2Format.cs` | 268 | Strict canonical-CBOR encode/decode of both records (reuses the core's audited reader/writer). | **High** |
| `PedersenVss.cs` | 163 | `Split` (sampling, commitments, optional signing) and `Reconstruct` (re-verify + interpolate). | **High** |
| `VssShare.cs` | 59 | The per-trustee verification equation. | **High** |
| `VssCommitments.cs` | 65 | Broadcast container + `VerifyDealerSignature`. | Medium |
| `Internal/SecretChunking.cs` | 49 | 31-byte secret ↔ field-element encoding. | Medium |
| `VssSplit.cs` / `GlobalUsings.cs` | 11 | Trivial. | Low |

**Trusted base you do _not_ re-derive** (review its *provenance*, not its internals):

- **BouncyCastle.Cryptography 2.5.1** — P-256 curve/field arithmetic (`ECPoint.Multiply`,
  `Add`, `Normalize`, `DecodePoint`) and `BigInteger` modular math (`Mod`, `ModInverse`).
  This is the most-reviewed managed EC implementation available; hand-rolling it would be a
  far larger *novel* attack surface. Pin/verify the version from the `.csproj`.
- **The core's `CanonicalCborWriter` / `StrictCborReader`** — the VSS records use the
  **same single audited parser** as v1 (via `InternalsVisibleTo`); there is no second CBOR
  implementation to review.
- **.NET `System.Security.Cryptography.MLDsa`** (FIPS 204) for broadcast signing —
  identical to the v1 ML-DSA layer already covered in [`AUDIT.md`](AUDIT.md) §3 row 5.

So your *novel-code* budget is roughly the four **High** files: ~700 lines.

---

## 4. Highest-risk components, in priority order

If you only have a day, convince yourself of these, in this order.

| # | Component | The property to verify | In-repo evidence |
|---|-----------|------------------------|------------------|
| 1 | **`Secp256r1Group.Commit` / `OpenLhs` / `CommittedEvaluation`** (the verification equation) | `s·G + t·H == Σ_j i^j·C_j` is implemented exactly; `H` is used consistently; points are normalized before comparison. A wrong RHS would let inconsistent shares pass. | `VssTests` (honest split verifies; tampered share fails), `VssFormatAndMathTests` (point/scalar codecs, Lagrange), `VssSpecExampleTests` (pinned vector verifies). |
| 2 | **`Secp256r1Group.DeriveH`** | `H` is the documented nothing-up-my-sleeve hash-and-increment value, on-curve, `≠ G`, deterministic, and **nobody can know `log_G(H)`** (it is the hash of a fixed string). | `VssFormatAndMathTests.Second_generator_H_is_valid_independent_and_deterministic` pins the compressed `H`; reproduce from the domain string in [`SPEC.md`](SPEC.md) §v2.2. |
| 3 | **`PedersenVss.Split`** | Per chunk: `a_0` = secret chunk, `b_0` = fresh uniform blinding, higher coeffs uniform; commitments `C_j = a_j·G + b_j·H`; share `i` gets `(p(i), p'(i))`. The blinding polynomial `p'` is **independent** per chunk. Coefficient/secret memory is not leaked. | `VssTests` (every quorum reconstructs the same secret), `VssSpecExampleTests` (deterministic vector). |
| 4 | **`Vss2Format` decode** | Both readers accept **only** the canonical subset and **fail closed** (only `SecretSharingException`); every point/scalar is range-checked (`< q`, on-curve, non-identity); blob lengths must match `m`, `k`; auth fields present **iff** `authAlgorithm = 1`. | `VssFormatAndMathTests` (3000-iteration FsCheck mutation/truncation/trailing-byte property tests), coverage-guided fuzzing ([`../fuzz/`](../fuzz)). |
| 5 | **`PedersenVss.Reconstruct`** | Requires exactly `K` shares; rejects null/duplicate-index/foreign-split shares; **re-verifies every share** against the commitments before interpolating; Lagrange-at-0 over GF(q) recovers each chunk; result lands in a `ZeroizingBuffer`; scratch is zeroed. | `VssTests` (exact-`K`, duplicate, cross-split, tamper rejection; leading-zero round-trip). |
| 6 | **`VssCommitments.VerifyDealerSignature` + `Vss2Format` signing payload** | The signature covers the canonical keys-0–10 form (`EncodeCommitmentsSigningPayload`), re-serialized from **parsed** values (never buffer offsets); a wrong pinned key or any tamper fails. | `VssDealerSigningTests` (verify, wrong-key, tamper, round-trip), [`SPEC.md`](SPEC.md) §v2.7. |
| 7 | **`SecretChunking`** | 31-byte chunks are `< q` (injective, no wraparound); leading zeros and the final short chunk are restored exactly using the recorded `secretLength`. | `VssFormatAndMathTests.Chunking_round_trips` (1000-iteration property test), `VssTests.Reconstruct_recovers_secrets_with_leading_zero_bytes`. |

---

## 5. Reproduce every evidence claim yourself

| Evidence | Command / location |
|----------|--------------------|
| Whole VSS suite (both TFMs) | `dotnet test tests/PostQuantum.SecretSharing.Vss.Tests/...csproj -c Release` |
| Fail-closed parsing (property, 3000×) | `--filter "FullyQualifiedName~VssFormatAndMathTests"` |
| `H` nothing-up-my-sleeve vector | `--filter "Second_generator_H"` ; reproduce from [`SPEC.md`](SPEC.md) §v2.2 |
| Pinned worked vector (spec ↔ code) | `--filter "FullyQualifiedName~VssSpecExampleTests"` vs [`test-vectors-vss.md`](test-vectors-vss.md) |
| Malicious-dealer detection (end-to-end) | `--filter "Malicious_or_tampered"` and the [`MaliciousDealerDetected`](../samples/MaliciousDealerDetected) sample |
| Broadcast signing (ML-DSA-65) | `--filter "FullyQualifiedName~VssDealerSigningTests"` (net10.0) |
| Coverage-guided fuzzing of the **v2** readers | [`../fuzz/README.md`](../fuzz/README.md) — `VssShare.Import` / `VssCommitments.Import` are fuzzed alongside v1 |
| Public-API surface lock | `src/PostQuantum.SecretSharing.Vss/PublicAPI.*.txt` — any surface change is a reviewable diff |

The published vectors are derived from a fully-specified **SHA-256 counter stream**
(documented in [`test-vectors-vss.md`](test-vectors-vss.md)), so you can recompute every
byte independently rather than trusting ours.

---

## 6. Cryptographic construction (recap + citations)

- **Scheme:** Pedersen Verifiable Secret Sharing (T. Pedersen, *Non-Interactive and
  Information-Theoretic Secure Verifiable Secret Sharing*, CRYPTO '91). Chosen over Feldman
  VSS specifically because Feldman's `C_0 = a_0·G` leaks the secret to a discrete-log break
  (a quantum adversary), breaking the headline; Pedersen's blinding makes the commitment
  perfectly hiding. See [`VSS-DESIGN.md`](VSS-DESIGN.md) §2 for the rejected-alternatives
  table.
- **Group:** NIST P-256 (secp256r1), cofactor 1, prime order `q`. Scalars are integers
  mod `q`; the secret is carried in the scalar field, 31 bytes per element.
- **Commitment:** `C_{k,j} = a_{k,j}·G + b_{k,j}·H`, perfectly hiding (information-theoretic
  secrecy), computationally binding (discrete log).
- **Verification:** `s_{k,i}·G + t_{k,i}·H == Σ_j (i^j) C_{k,j}` proves share `i` lies on the
  single committed degree-`K−1` polynomial pair, so **every quorum recovers the same
  secret**.

---

## 7. Threat model & honest limitations (don't waste time here)

These are documented decisions, not bugs (full list in [`KNOWN-GAPS.md`](KNOWN-GAPS.md) and
[`THREAT-MODEL.md`](THREAT-MODEL.md)):

1. **Binding is computational/classical** (discrete log). A **quantum dealer** could
   equivocate and defeat *detection* — but **not secrecy**, which stays information-theoretic.
   This is the central, deliberately-accepted tradeoff.
2. **Not constant-time.** The EC/`BigInteger` arithmetic in the VSS path is not
   constant-time. This is *safe here* because secrecy is unconditional — the transcript hides
   the secret perfectly, so timing leaks nothing secret-dependent. The constant-time path is
   the GF(2⁸) core, which this package does not touch.
3. **Commitment size grows with secret length** (`m·k·33` bytes). Recommended pattern: wrap
   a 32-byte KEK with `WrappedSecret` and VSS-split the KEK.
4. **Unsigned broadcasts must be pinned out-of-band.** Broadcast signing (key 9–11) is
   optional; an unsigned broadcast carries the same non-equivocation requirement as the v1
   dealer key.
5. **Not independently audited.** Treat as a carefully-engineered primitive pending review.

---

## 8. Reviewer checklist

Copy into your report and fill in.

| Item | Verdict | Notes |
|------|:-------:|-------|
| Build is clean (warnings-as-errors) on a fresh checkout | ☐ | |
| Secrecy is information-theoretic: blinding `b` is fresh/uniform per chunk; `·H` term correct | ☐ | |
| Verification equation `s·G + t·H == Σ i^j·C_j` is implemented exactly | ☐ | |
| `H` is the pinned nothing-up-my-sleeve value; `log_G(H)` is unknowable | ☐ | |
| `Split` samples correctly and leaks no coefficient/secret memory | ☐ | |
| Both v2 readers reject all non-canonical input and fail closed | ☐ | |
| `Reconstruct` re-verifies, enforces exact-`K`, and rejects dup/foreign/null shares | ☐ | |
| Broadcast signature binds keys 0–10 and is pin-anchored | ☐ | |
| Chunking is injective; leading zeros / short final chunk restored | ☐ | |
| BouncyCastle version is pinned; trusted-base boundary is as documented | ☐ | |
| Published `H` + worked vectors reproduce independently | ☐ | |
| Documented gaps match observed behavior (no undisclosed gaps) | ☐ | |

---

## 9. Reporting findings

Privately, per [`../SECURITY.md`](../SECURITY.md) — please do **not** open a public issue
for a vulnerability. Reviewers who wish to be credited will be, and the result of any
review can be linked from [`KNOWN-GAPS.md`](KNOWN-GAPS.md) so the honesty record stays
current.
