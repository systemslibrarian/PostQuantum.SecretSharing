# Roadmap

This roadmap states intent, not promises. The guiding principle is the same one
that governs the rest of the project: ship a small, correct, honestly-documented
primitive, and only add scope that can be done to the same standard.

## v1.0 (current line — `1.0.0-rc.x`)

The information-theoretic core plus the engineering around it, complete:

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

**To reach `1.0.0` (stable):**

- [ ] Independent review of the GF(2⁸) arithmetic and the CBOR parser/serializer
      (the two highest-risk components). *Requires external reviewers.*
- [ ] At least one real-world dogfooding deployment, written up.
- [ ] No format or public-API changes for a sustained RC period.

## v1.x (additive, non-breaking)

- Additional ecosystem integration samples (EF Core master key, cloud-KMS hybrid).
- More published test vectors as other implementations appear.
- Optional `PostQuantum.SecretSharing.Extensions` for higher-level ceremony
  helpers, kept out of the core so the core stays dependency-free.

## v2 (may require a format version bump → `.pqss` v2)

The hard problems v1 deliberately does **not** solve (see KNOWN-GAPS.md):

- **Verifiable Secret Sharing (Pedersen).** Detect a *malicious dealer* who issues
  inconsistent shares. This needs a prime-order group rather than GF(2⁸), so it is a
  parallel scheme, not a patch to the core. **Now shipping in preview** as the opt-in
  [`PostQuantum.SecretSharing.Vss`](docs/VSS-DESIGN.md) package (`2.0.0-preview.1`):
  Pedersen VSS over P-256, `.pqss` v2 records, secrecy still information-theoretic,
  dealer-fraud detection computational. Path to stable: ML-DSA-signed commitments,
  published cross-impl vectors, a sample, and review. The GF(2⁸) core stays
  dependency-free and unchanged.
- **Distributed proactive secret sharing.** Re-randomize shares across parties
  *without* reconstructing the secret (v1's `Refresh` is quorum-mediated). Still planned.
- Possible additional authenticators behind `IShareAuthenticator` (the
  abstraction is intentionally narrow to allow this without breaking the API).

## Explicitly out of scope (not planned)

- A full key-management service / KMS. This is a primitive.
- Splitting low-entropy secrets directly (use `WrappedSecret`).
- Defenses against power/EM side channels or process memory dumps.
