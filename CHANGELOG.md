# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) once it reaches `1.0.0` (see
[COMPATIBILITY.md](docs/COMPATIBILITY.md)).

## [Unreleased]

## [2.1.0] — 2026-06-14

**First stable release.** Both packages leave prerelease and move (in lockstep) to
`2.1.0`. The information-theoretic GF(2⁸) core and the opt-in Pedersen VSS package are
considered feature-complete and audit-ready. The remaining open item — an independent
third-party audit — is tracked honestly in [`KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) §9 and
[`ROADMAP.md`](ROADMAP.md); both packages are built to make that review cheap (see
[`AUDIT.md`](docs/AUDIT.md) and [`VSS-AUDIT-GUIDE.md`](docs/VSS-AUDIT-GUIDE.md)). No
breaking public-API change and no `.pqss` **v1** format change; the VSS additions below are
confined to the opt-in `PostQuantum.SecretSharing.Vss` package and its **v2** records.

### Added — VSS package (audit-readiness / path to stable)

- **Post-quantum dealer authentication of the commitment broadcast.**
  `PedersenVss.Split(secret, policy, IShareAuthenticator dealer)` signs the broadcast with
  ML-DSA-65 (FIPS 204); `VssCommitments` gains `IsDealerSigned`, `DealerPublicKey`, and
  `VerifyDealerSignature(pinnedKey)`. This authenticates the *pin itself*, so a trustee can
  confirm the broadcast came from the pinned dealer and was not substituted. The
  `vss-commitments` record gains optional auth fields (keys 9–11), mirroring the v1 share
  format. Secrecy is unchanged (still information-theoretic); this is an additive,
  computational *detection* layer, documented as such.
- **`.pqss` v2 / VSS wire format is now specified and pinned.** New
  [`SPEC.md`](docs/SPEC.md) §v2 (byte-level field tables, signing rule, reader order, group
  and `H` derivation, verification equation), enforced by `VssSpecExampleTests` against a
  reproducible worked vector.
- **Published cross-implementation VSS vectors.** A full worked broadcast + share set,
  derived from a fully-specified SHA-256 counter stream, added to
  [`test-vectors-vss.md`](docs/test-vectors-vss.md) (alongside the pinned `H`).
- **Coverage-guided fuzzing extended to the v2 readers** (`VssShare.Import`,
  `VssCommitments.Import`), with matching v2 seeds.
- **Dedicated reviewer kit:** [`VSS-AUDIT-GUIDE.md`](docs/VSS-AUDIT-GUIDE.md) — review
  surface (~840 lines), trusted base, ranked risks, reproducible evidence, and a checklist.
- Resolved the VSS open design questions (P-256 vs ristretto, optional vs required signing,
  chunking) — now decided and frozen for the stable format. See
  [`VSS-DESIGN.md`](docs/VSS-DESIGN.md) §9.

### Notes

- No change to the GF(2⁸) core or the on-disk **v1** `.pqss` format. The VSS additions are
  confined to the opt-in `PostQuantum.SecretSharing.Vss` package. The remaining gate to a
  stable VSS release is an independent audit (the code/docs are built to make it cheap).

## [2.0.1-preview.1] — 2026-06-13

### Changed

- **Unified (lockstep) versioning across both packages.** The core
  `PostQuantum.SecretSharing` and the opt-in `PostQuantum.SecretSharing.Vss`
  packages now share a single version line, starting at `2.0.1-preview.1`, so
  every release of one has a matching release of the other. The core package
  version moves from `1.0.0-rc.2` to `2.0.1-preview.1` **solely** to adopt this
  shared line — there is **no** breaking public-API change and **no** `.pqss`
  format change. The on-disk core `.pqss` format remains **v1**; the wire format
  and the package/API version are versioned independently (see
  [COMPATIBILITY.md](docs/COMPATIBILITY.md)). Both packages stay prerelease: the
  VSS layer is still preview-quality, unaudited new crypto, and the core has not
  yet completed its path to a stable release (independent review + dogfooding).

## [1.0.0-rc.2] — 2026-06-13

### Changed

- **Packaging / docs links.** Converted the packaged README to absolute GitHub URLs
  so documentation links work on the nuget.org package page (relative links resolved to
  `nuget.org/...` and 404'd). Added `PackageProjectUrl` so the package links back to the
  repository, and switched to the shared **PQ icon** (128×128 PNG). The companion VSS
  package README gained a quick example and a link to the runnable
  `MaliciousDealerDetected` sample. (The opt-in VSS package is versioned separately;
  current `2.0.0-preview.2`.)

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

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.SecretSharing/compare/v2.0.1-preview.1...HEAD
[2.0.1-preview.1]: https://github.com/systemslibrarian/PostQuantum.SecretSharing/compare/v1.0.0-rc.2...v2.0.1-preview.1
[1.0.0-rc.2]: https://github.com/systemslibrarian/PostQuantum.SecretSharing/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/systemslibrarian/PostQuantum.SecretSharing/releases/tag/v1.0.0-rc.1
