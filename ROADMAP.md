# Roadmap

This roadmap states intent, not promises. The guiding principle is the same one
that governs the rest of the project: ship a small, correct, honestly-documented
primitive, and only add scope that can be done to the same standard.

## The core (current line — `2.2.0`)

The core and the opt-in VSS package now share one version line (see
[CHANGELOG.md](CHANGELOG.md)); the on-disk core `.pqss` format stays **v1**. The
information-theoretic core plus the engineering around it is complete:

- Shamir over GF(2⁸) — constant-time, table-free field math.
- Strict canonical CBOR `.pqss` share format (hand-rolled, fail-closed).
- HKDF-SHA256 integrity check value.
- `ZeroizingBuffer` — pinned, zeroizing, best-effort page-locked secret memory.
- Optional ML-DSA-65 (FIPS 204) dealer authentication with key pinning.
- `WrappedSecret` (KEK-wrap pattern), `Refresh` (custody rotation),
  `DealerCommitment` (weak commitment), per-share `VerifySignature`.
- Cross-implementation test vectors, fuzz/property tests, constant-time evidence.
- `pqss` CLI, four samples, full docs (SPEC, THREAT-MODEL, KNOWN-GAPS,
  OPERATIONS, BENCHMARKS).

**Stable `2.1.0` is shipped.** The API and `.pqss` v1 format are frozen under SemVer.
The following remain open as **post-stable hardening** — they sharpen confidence but are
not blockers we are pretending to have met:

- [ ] Independent review of the GF(2⁸) arithmetic and the CBOR parser/serializer
      (the two highest-risk components). *Requires external reviewers.* The
      [`AUDIT.md`](docs/AUDIT.md) kit exists to make this cheap.
- [ ] At least one real-world dogfooding deployment, written up.

## Additive, non-breaking (`2.x`)

- Additional ecosystem integration samples (EF Core master key, cloud-KMS hybrid).
- More published test vectors as other implementations appear.
- **[shipped]** `PostQuantum.SecretSharing.Extensions` — opt-in higher-level ceremony
  helpers, kept out of the core so the core stays dependency-free. First helper:
  distributed proactive refresh (below).

## Larger scope (may bump the `.pqss` format to v2)

The hard problems the core deliberately does **not** solve (see KNOWN-GAPS.md):

- **Verifiable Secret Sharing (Pedersen).** Detect a *malicious dealer* who issues
  inconsistent shares. This needs a prime-order group rather than GF(2⁸), so it is a
  parallel scheme, not a patch to the core. **Shipped** as the opt-in
  [`PostQuantum.SecretSharing.Vss`](docs/VSS-DESIGN.md) package: Pedersen VSS over P-256,
  `.pqss` v2 records, secrecy still information-theoretic, dealer-fraud detection
  computational. The GF(2⁸) core stays dependency-free and unchanged.

  **To reach a stable VSS release:**
  - [x] ML-DSA-65 signing of the commitment broadcast (post-quantum dealer-auth of the pin).
  - [x] `.pqss` v2 wire format pinned in [SPEC.md](docs/SPEC.md) §v2, enforced by `VssSpecExampleTests`.
  - [x] Published cross-implementation vectors (`H` + a full worked record set) in
        [test-vectors-vss.md](docs/test-vectors-vss.md).
  - [x] Coverage-guided fuzzing extended to the v2 readers.
  - [x] `MaliciousDealerDetected` sample.
  - [x] Dedicated reviewer kit — [VSS-AUDIT-GUIDE.md](docs/VSS-AUDIT-GUIDE.md).
  - [ ] Independent review of the protocol glue + the BouncyCastle trusted base.
        *Requires external reviewers.*
  - [ ] No format or public-API changes for a sustained RC period.
- **Distributed proactive secret sharing.** Re-randomize shares across parties
  *without* reconstructing the secret (the core's `Refresh` is quorum-mediated).
  **Shipped** in the opt-in [`PostQuantum.SecretSharing.Extensions`](docs/PROACTIVE-REFRESH.md)
  package (`ProactiveRefresh`) as the honest-but-curious construction. A **verifiable**
  variant (preventing, not just detecting, a malicious contributor) would build on the VSS
  prime-order machinery and is the natural next step.
- Possible additional authenticators behind `IShareAuthenticator` (the
  abstraction is intentionally narrow to allow this without breaking the API).

## Explicitly out of scope (not planned)

- A full key-management service / KMS. This is a primitive.
- Splitting low-entropy secrets directly (use `WrappedSecret`).
- Defenses against power/EM side channels or process memory dumps.
