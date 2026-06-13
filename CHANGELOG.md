# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) once it reaches `1.0.0` (see
[COMPATIBILITY.md](docs/COMPATIBILITY.md)).

## [Unreleased]

### Added

- **`PostQuantum.SecretSharing.Vss` (`2.0.0-preview.1`) — opt-in Verifiable Secret
  Sharing.** Pedersen VSS over NIST P-256 detects a *malicious dealer* who hands out
  inconsistent shares: each trustee can `Verify` their share against the dealer's
  public commitments before any reconstruction, and `Reconstruct` re-verifies and
  refuses to return a wrong secret. Secrecy stays information-theoretic /
  post-quantum (commitments are perfectly hiding); only the dealer-fraud *detection*
  is computational (discrete-log binding) — documented exactly like the ML-DSA layer.
  Kept in a **separate package** so the core stays dependency-free; its one vetted
  dependency (BouncyCastle) is isolated there. New `.pqss` v2 records, a pinned
  nothing-up-my-sleeve `H` vector, and a full test suite (round-trip, quorum
  agreement, tamper/malicious-dealer detection, fail-closed parsing, group-math and
  interpolation checks). Preview-quality, unaudited new crypto. See
  [`docs/VSS-DESIGN.md`](docs/VSS-DESIGN.md).
- **CBOR-layer property tests at the codec primitive level**
  (`FsCheckCborLayerTests` + boundary-biased generators): writer∘reader inverse over
  the full integer range, canonical re-encoding, and rejection of non-shortest,
  indefinite, reserved, wrong-type, and truncated encodings — plus RFC 8949
  boundary vectors. Complements the existing `Import`-level properties.
- **Audit kit** ([`docs/AUDIT.md`](docs/AUDIT.md)): a reviewer entry point (scope,
  one-command bootstrap, ranked highest-risk components with evidence, reproduce-each-claim
  table, dependency provenance, time-boxed review paths, checklist) so the codebase
  is cheap to audit.
- **FsCheck property tests with shrinking** over the CBOR layer
  (`FsCheckCborTests` + generators): arbitrary-bytes crash-freedom, structured
  CBOR maps with deliberately-wrong contents, valid-share round-trip, and valid
  shares under 13 kinds of structural mutation — all minimized to small
  reproducers on failure.
- **BenchmarkDotNet project** (`benchmarks/PostQuantum.SecretSharing.Benchmarks`)
  for rigorous, allocation-aware split/reconstruct/export/import numbers;
  documented in `docs/BENCHMARKS.md`.
- **ASP.NET Core Data Protection sample** now also demonstrates the fail-closed
  case: a stolen key ring is inert without a quorum.

## [1.0.0-rc.1] — 2026-06-12

First release candidate. The `.pqss` format is **v1** and considered stable for
the v1 line (see COMPATIBILITY.md).

### Added

- **Core scheme:** Shamir's Secret Sharing over GF(2⁸) with constant-time,
  table-free field math (`ShamirSecretSharing.Split` / `Reconstruct`,
  exactly-`k` reconstruction, `K=1` forbidden).
- **`.pqss` format:** strict, canonical, hand-rolled CBOR reader/writer; fully
  specified in [SPEC.md](docs/SPEC.md) with a test-pinned worked example.
- **Integrity:** HKDF-SHA256 check value, constant-time comparison.
- **Memory hygiene:** `ZeroizingBuffer` — pinned object heap, deterministic
  zeroization, and best-effort page-locking (`VirtualLock`/`mlock`,
  `IsMemoryLocked`).
- **Authentication (net10.0):** optional ML-DSA-65 (FIPS 204) dealer signatures
  via `IShareAuthenticator` / `MlDsa65ShareAuthenticator`, with public-key
  pinning at reconstruction and per-share `SecretShare.VerifySignature`.
- **Helpers:** `WrappedSecret` (KEK-wrap pattern for low-entropy/large secrets),
  `ShamirSecretSharing.Refresh` (quorum-mediated custody rotation),
  `DealerCommitment` (weak commitment to the intended secret).
- **Exceptions:** fail-closed hierarchy (`ShareFormatException`,
  `SharePolicyException`, `ShareAuthenticationException`,
  `ShareConsistencyException`).
- **Verification:** independent Python reference + deterministic cross-impl test
  vectors; fuzz/property tests over the CBOR layer; constant-time timing evidence.
- **Tooling & docs:** the `pqss` CLI (`split`/`inspect`/`verify`/`combine`/
  `refresh`, armored text, `--json`, `--dry-run`); four samples; and the full
  documentation set (SPEC, THREAT-MODEL, KNOWN-GAPS, OPERATIONS, BENCHMARKS,
  test-vectors).

### Security notes

- Not independently audited; carefully engineered. See [KNOWN-GAPS.md](docs/KNOWN-GAPS.md).
- No Verifiable Secret Sharing in v1 (malicious dealer is out of scope; v2 goal).

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.SecretSharing/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/systemslibrarian/PostQuantum.SecretSharing/releases/tag/v1.0.0-rc.1
