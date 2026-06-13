# Threat Model

This document states plainly what PostQuantum.SecretSharing defends against and
what it does not. The unconditional part of the security claim is narrow and
precise; everything outside it is engineering and is listed honestly here,
including the items that make the package look worse.

## The core guarantee

Shamir's scheme over GF(2⁸) is **information-theoretically secure**: any `k−1`
shares reveal *nothing* about the secret, against any adversary — classical or
quantum, with unlimited compute and unlimited time. This is a property of the
*scheme*, proven mathematically, not a computational-hardness assumption.

Every other security property in this package is an *implementation* property and
depends on engineering: share authentication, the absence of side channels,
memory hygiene, and the behavior of the integrity check value.

## In scope (defended)

| Threat | How it is addressed |
|--------|---------------------|
| **Recovering the secret from fewer than k shares** | Information-theoretic: impossible by construction. |
| **Tampered or substituted shares** (authenticated mode) | ML-DSA-65 signature over the canonical share bytes, verified against a **pinned** dealer public key. |
| **Mixing shares from different splits** | Distinct `splitId` per split; reconstruction requires all shares to agree on `splitId` and metadata. |
| **Format-confusion / malformed input** | Strict canonical CBOR parser: definite lengths, shortest-form integers, ascending unique keys, exact types, no trailing bytes, no unknown fields. Fails closed with specific exceptions before any crypto. |
| **Accidental corruption of a share** | HKDF-SHA256 check value recomputed and compared (constant-time) at reconstruction. |
| **Cache-timing on field math** | Mitigated: GF(2⁸) multiplication and inversion are branchless, fixed-iteration, and table-free (no secret-indexed lookups). |
| **GC relocation leaving stale secret copies** | Mitigated: reconstructed secrets land in a pinned-object-heap `ZeroizingBuffer` that the GC cannot move; it is zeroed on dispose. |
| **Wrong-quorum / operator error at reconstruct** | Exactly-`k` shares required; extra shares are rejected rather than silently subset-selected. |

## Out of scope (NOT defended) — stated bluntly

| Threat | Status / rationale |
|--------|--------------------|
| **A malicious dealer** | Out of scope for v1. A dishonest dealer can hand inconsistent shares to different trustees so that different quorums reconstruct different secrets, or distribute shares that do not reconstruct at all. v1 authenticates shares *against the dealer*; it cannot detect the dealer lying *differently* to different trustees. Verifiable Secret Sharing (Feldman/Pedersen VSS) is explicitly a **v2** goal. |
| **Low-entropy secrets (the check-value oracle)** | Out of scope. Each share carries `splitId` + `checkValue`, which together form an **offline guessing oracle**: a single shareholder can test secret guesses without a quorum. Irrelevant for high-entropy keys; fatal for passphrases/PINs. **Split keys, not passwords.** |
| **Memory-dump and swap attackers** | Out of scope. The secret exists in cleartext in process memory while in use. Pinning prevents GC copies but not OS paging to disk (swap). Page-locking (`mlock`/`VirtualLock`) is not implemented in v1. |
| **Side channels beyond cache timing** | Out of scope. Power analysis, electromagnetic emanation, and microarchitectural attacks beyond the table-free mitigation are not addressed. |
| **Trustee collusion of size ≥ k** | Out of scope *by design*. Any `k` cooperating trustees can reconstruct — that is the whole point of a `k`-of-`n` scheme. Choose `k` accordingly. |
| **Availability when too many shares are lost** | Out of scope. If more than `n−k` shares are destroyed, the secret is unrecoverable. Choose `n−k ≥ 2` (see OPERATIONS.md). |
| **Custody of the dealer private key** | Out of scope. Anyone with the dealer's ML-DSA private key can mint shares that pass a pinned-key check. Protect it as you would any signing key. |
| **Constant-time CBOR parsing** | Out of scope and unnecessary: the parser operates on *public* share structure, not secret values. See KNOWN-GAPS.md. |
| **Independent audit** | Not performed. This package is carefully engineered, not audited. |

## Trust anchor: the pin

The only thing that converts "a share that claims to come from the dealer" into
"a share that provably came from *your* dealer" is the
`expectedDealerPublicKey` you supply at reconstruction, obtained out-of-band.
Verification against the key *embedded* in a share is self-attestation: a forged
share set can embed any key and sign with it. **Pin the dealer key.**
