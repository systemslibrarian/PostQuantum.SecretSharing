# Audit Kit

> **Status:** this package is **not** independently audited (see
> [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §9). This document does not claim otherwise.
> It exists to make a review *cheap*: a reviewer should be able to clone, build,
> reproduce every piece of evidence, and know exactly what to look at — in an
> afternoon, not a week.

If you are reviewing this library (paid, volunteer, or for your own due diligence),
start here. Everything you need is in the repository; nothing requires contacting us
except to report a finding privately ([`../SECURITY.md`](../SECURITY.md)).

---

## 1. What this library is (review boundary)

A small Shamir Secret Sharing primitive over GF(2⁸) with a strict canonical share
format (`.pqss`), an optional post-quantum dealer-authentication layer (ML-DSA-65),
and zeroizing secret memory. It is **not** a KMS and stores no keys for you.

The **security claim is deliberately narrow** and split in two — review them
separately, because they have different standards of proof:

| Claim | Type | Where it lives |
|-------|------|----------------|
| `K−1` shares reveal nothing about the secret | **Unconditional** (information-theoretic) | `ShamirCore.cs`, `Gf256.cs` |
| Tamper/substitution detection | **Computational** (ML-DSA-65 / FIPS 204) | `MlDsa65ShareAuthenticator.cs`, `ShareSignatureVerifier.cs` |
| Accidental-corruption / mixed-share detection | Integrity (HKDF-SHA256) | check-value code |
| Memory hygiene | Best-effort engineering | `ZeroizingBuffer.cs`, `MemoryLock.cs` |

The honest limitations are enumerated up front in [`KNOWN-GAPS.md`](KNOWN-GAPS.md)
and [`THREAT-MODEL.md`](THREAT-MODEL.md). **Please read those first** — several
"missing" properties (constant-time CBOR, RNG injection, malicious-dealer defense)
are *intentional* scope decisions, not oversights, and chasing them wastes your time.

---

## 2. One-command bootstrap

```bash
git clone https://github.com/systemslibrarian/PostQuantum.SecretSharing
cd PostQuantum.SecretSharing

# Build everything (warnings are errors; a clean build is part of the claim).
dotnet build PostQuantum.SecretSharing.sln -c Release

# Full functional suite, both target frameworks (skip micro-benchmarks/timing).
dotnet test PostQuantum.SecretSharing.sln -c Release -f net8.0  --filter "Category!=bench&Category!=timing"
dotnet test PostQuantum.SecretSharing.sln -c Release -f net10.0 --filter "Category!=bench&Category!=timing"
```

Requires the .NET 8 and .NET 10 SDKs. `net10.0` exercises the ML-DSA layer; on
macOS those tests skip (no upstream FIPS 204) and the core suite still passes.

---

## 3. Highest-risk components, in priority order

If you only have a day, review these in this order. Each row names the file, the
single property to convince yourself of, and the in-repo evidence to check it
against.

| # | Component | The property to verify | Evidence already in-repo |
|---|-----------|------------------------|--------------------------|
| 1 | **`src/.../Gf256.cs`** | GF(2⁸) multiply/inverse are **branchless, fixed-iteration, table-free** — no secret-indexed memory access (the classic cache-timing leak). | `Gf256Tests.cs`, `ShamirCoreTests.cs`, constant-time evidence in [`BENCHMARKS.md`](BENCHMARKS.md), `BannedSymbols.txt`. |
| 2 | **`src/.../ShamirCore.cs`** | Splitting samples a fresh degree-`K−1` polynomial per byte with the secret as the constant term; reconstruction is exact Lagrange at `x=0`. No secret-dependent branching. | `ShamirCoreTests.cs`, `RoundTripTests.cs`, `TestVectors.cs` (cross-impl vectors). |
| 3 | **`src/.../Cbor/StrictCborReader.cs` + `CanonicalCborWriter.cs`** | The parser accepts **only** the canonical subset (definite lengths, shortest-form ints, ascending unique keys, exact types, no trailing bytes) and **fails closed** on everything else — never a non-library exception. | `FsCheckCborLayerTests.cs` (codec-primitive properties + RFC 8949 boundary vectors), `FsCheckCborTests.cs`, `CborPropertyTests.cs`, `ShareFormatTests.cs`, and coverage-guided fuzzing under [`../fuzz/`](../fuzz). |
| 4 | **`src/.../SecretShare.cs`** | `Import`/`Export` round-trip is byte-identical and canonical; all schema/policy/mode contradictions throw before any crypto. | `ShareFormatTests.cs`, `FeaturesV1Tests.cs`, `SpecExampleTests.cs` (matches [`SPEC.md`](SPEC.md) hex). |
| 5 | **`src/.../ShareSignatureVerifier.cs` + `MlDsa65ShareAuthenticator.cs`** *(net10.0)* | Authenticated reconstruction verifies every share against the **pinned** key; embedded-key-only mode is treated as self-attestation, not authority. | `MlDsaTests.cs`, `FeaturesV1Tests.cs`, trust-model section of [`THREAT-MODEL.md`](THREAT-MODEL.md). |
| 6 | **`src/.../ZeroizingBuffer.cs` + `MemoryLock.cs`** | Backing array is pinned (GC can't relocate-copy), zeroed on dispose; page-lock is best-effort and reports `IsMemoryLocked`. Interop (`LibraryImport`) is sound. | `ZeroizingBufferTests.cs`, KNOWN-GAPS §3–4. |
| 7 | **Check value (HKDF-SHA256)** | Recomputed and compared in constant time at reconstruction; understood to be an offline oracle for *low-entropy* secrets (mitigated by `WrappedSecret`). | `CheckValueTests.cs`, KNOWN-GAPS §2. |

---

## 4. Reproduce every evidence claim yourself

| Evidence | Command / location |
|----------|--------------------|
| Property tests (structured + shrinking) | `dotnet test ... --filter "FullyQualifiedName~FsCheck"` |
| CBOR codec primitive properties | `--filter "FullyQualifiedName~FsCheckCborLayerTests"` |
| Cross-implementation test vectors | [`docs/test-vectors.json`](test-vectors.json) / [`docs/test-vectors.md`](test-vectors.md), exercised by `TestVectors.cs` |
| Spec ↔ code agreement (worked hex example) | [`SPEC.md`](SPEC.md) vs `SpecExampleTests.cs` |
| Coverage-guided fuzzing of the parser | [`../fuzz/README.md`](../fuzz/README.md) (SharpFuzz + libFuzzer) |
| Constant-time evidence | [`BENCHMARKS.md`](BENCHMARKS.md) |
| Reproducible build / provenance / SBOM | [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) |
| Mechanically-enforced crypto hygiene | `BannedSymbols.txt` (no `System.Random`, MD5/SHA-1, DES/3DES/RC2) — build fails on use |
| Public-API surface lock | `PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt` — any surface change is a reviewable diff |

---

## 5. Dependency & provenance surface

The **core library is dependency-free at runtime** — only the BCL plus build-only
analyzers/SourceLink. This is deliberate and keeps the trusted computing base small;
verify it from the `.csproj`:

- `src/PostQuantum.SecretSharing/PostQuantum.SecretSharing.csproj` — runtime deps:
  none. Build-only: `Microsoft.SourceLink.GitHub`, the public-API analyzer, the
  banned-API analyzer (all `PrivateAssets="All"`).
- Test-only deps (not shipped): xUnit, FsCheck, SkippableFact.
- Build authenticity, SBOM, and reproducible-build instructions:
  [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md).

> **VSS package.** The opt-in `PostQuantum.SecretSharing.Vss` package is the *only*
> component permitted a third-party cryptographic dependency (`BouncyCastle.Cryptography`,
> for prime-order group arithmetic). The core stays dependency-free. It has its own
> dedicated, self-contained auditor guide — **[`VSS-AUDIT-GUIDE.md`](VSS-AUDIT-GUIDE.md)** —
> covering its review surface (~840 lines), trusted base, ranked risks, reproducible
> evidence, and a checklist. Review it separately from the core.

---

## 6. Explicitly out of scope for a review

Do not spend time on these — they are documented decisions, not bugs:

- Constant-time CBOR parsing (parses *public* structure only — KNOWN-GAPS §6).
- RNG injection (intentionally absent — KNOWN-GAPS §7).
- Malicious-dealer / VSS in the **core** (deliberately absent — KNOWN-GAPS §1).
  Now shipped in the opt-in `PostQuantum.SecretSharing.Vss` package; review it
  separately against its design spec ([`VSS-DESIGN.md`](VSS-DESIGN.md)).
- Distributed proactive refresh (v2 — KNOWN-GAPS §5).
- Memory-dump / power / EM side channels (out of scope — THREAT-MODEL).
- Splitting low-entropy secrets directly (use `WrappedSecret` — THREAT-MODEL).

---

## 7. Reviewer checklist

Copy this into your report and fill it in.

| Item | Verdict | Notes |
|------|:-------:|-------|
| Build is clean and reproducible on a fresh checkout | ☐ | |
| `Gf256` field math is table-free / no secret-indexed access | ☐ | |
| `ShamirCore` split/reconstruct matches the math and the vectors | ☐ | |
| CBOR reader rejects all non-canonical input, fails closed | ☐ | |
| `SecretShare` round-trips byte-identically; validates before crypto | ☐ | |
| ML-DSA verification is correct and pin-anchored | ☐ | |
| `ZeroizingBuffer` pin/zeroize/lock behave as documented | ☐ | |
| Check-value oracle caveat is correctly bounded | ☐ | |
| No runtime dependencies in the core; provenance verifiable | ☐ | |
| Documented gaps match observed behavior (no undisclosed gaps) | ☐ | |

---

## 8. Reporting findings

Privately, per [`../SECURITY.md`](../SECURITY.md) — please do **not** open a public
issue for a vulnerability. We will credit reviewers who wish to be credited, and the
result of any review (positive, negative, or "found these issues") can be linked from
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) so the honesty record stays current.
