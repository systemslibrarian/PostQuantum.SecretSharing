# Design: Verifiable Secret Sharing (v2)

> **Status: implemented as a preview.** This document is both the design rationale
> and the contract the implementation meets. It is realised in the opt-in
> `PostQuantum.SecretSharing.Vss` package (`2.0.0-preview.1`); the GF(2⁸) core is
> **not** modified. Code: `src/PostQuantum.SecretSharing.Vss/`. Tests:
> `tests/PostQuantum.SecretSharing.Vss.Tests/` (round-trip, quorum agreement, tamper /
> malicious-dealer detection, fail-closed parsing, group-math and interpolation
> checks, pinned `H` vector).

## 1. Problem and goal

v1 authenticates shares *against the dealer* (ML-DSA-65) but cannot detect a
**malicious dealer** who hands inconsistent shares to different trustees, so that
different quorums reconstruct different secrets — or some reconstruct nothing. See
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) §1 and [`THREAT-MODEL.md`](THREAT-MODEL.md).

**Goal:** every trustee can *verify, before any reconstruction*, that their share is
consistent with a single committed degree-`K−1` polynomial — i.e. that all shares lie
on one polynomial and therefore every quorum recovers the same secret. This is
Verifiable Secret Sharing (VSS).

## 2. The decision that constrains everything: keep secrecy unconditional

This library's headline is **information-theoretic, survives-quantum secrecy**. That
rules out the obvious VSS:

| Scheme | Commitment | Secrecy of the secret | Verdict |
|--------|-----------|------------------------|---------|
| **Feldman** | `C_j = a_j·G` | **Computational** — `C_0 = a_0·G` leaks the secret to a discrete-log break (i.e. to a quantum adversary). | ❌ Breaks the headline. Rejected. |
| **Pedersen** | `C_j = a_j·G + b_j·H` | **Information-theoretic** — the blinding `b_j·H` makes `C_j` a perfectly-hiding commitment; the transcript reveals nothing about `a_0`, ever. | ✅ Chosen. |
| Lattice/PQ VSS | SIS/MLWE commitments | Unconditional + PQ binding | ❌ Research-grade, unstandardized, not push-to-NuGet. Revisit post-standardization. |

**Pedersen VSS** is the only classical scheme that preserves the core promise.

### The honest tradeoff (must be documented next to every VSS API)

Pedersen commitments are **perfectly hiding** but only **computationally binding**
(binding rests on discrete-log hardness in the chosen group). Therefore:

- **Secrecy stays unconditional and post-quantum.** A quantum adversary with all
  commitments and `K−1` shares still learns *nothing* about the secret. The headline
  is intact.
- **Malicious-dealer *detection* is classical.** A dealer who could compute
  `log_G(H)` could equivocate (open a commitment two ways) and defeat the
  consistency guarantee. Against a *quantum* dealer, the detection — not the secrecy —
  degrades.

This mirrors how v1 already treats ML-DSA: secrecy is unconditional; the *added*
integrity/authenticity layer is computational and labelled as such. We never let the
two blur.

## 3. Cryptographic construction

### 3.1 Group

A prime-order group `G` of order `q` with a fixed generator `G`, and a second
generator `H` for which **no party knows `log_G(H)`**.

- **Choice: NIST P-256 (secp256r1).** Cofactor 1 (prime order `q ≈ 2²⁵⁶`), ubiquitous,
  well-reviewed, and supported by the chosen dependency. Scalars are integers mod `q`.
- **`H` is nothing-up-my-sleeve:** derived by **hash-and-increment** from the fixed
  ASCII domain string `PostQuantum.SecretSharing/vss/H/secp256r1/v1`: for
  `counter = 0,1,2,…`, take `x = SHA-256(domain ‖ counter_be32)`, skip if `x ≥ p`,
  and otherwise take the even-`y` point with that `x` if one exists. For a *single,
  public, one-time* generator this simple construction is sufficient — the only
  property required is that nobody knows `log_G(H)`, which follows from `H` being the
  hash of a fixed string, independent of which map is used. (We deliberately avoid a
  full RFC 9380 SSWU implementation: it would be a large block of novel,
  constant-time-sensitive code to get right, and constant-time is irrelevant here
  because the derivation is public and one-time — fewer novel lines is the better
  audit-readiness tradeoff.) The derivation is fixed, public, and reproducible;
  `H` is pinned as a test vector (compressed):
  `02C210CA1DD338B122F04B3FF2C7A7F8360D7C43BCFD9647BD022A845B3C33278C`.

### 3.2 Secret representation

The secret is a byte string. VSS shares over the **scalar field `GF(q)`**, not over
bytes, so the secret is encoded as a sequence of field elements:

- Split the secret into 31-byte chunks (248 bits < 256-bit `q`, so each chunk is an
  unambiguous element `< q`; no modular wraparound, encoding is injective). The final
  chunk is length-framed in the share metadata (as v1 frames `secretLength`).
- Each chunk `e_k` is shared by its **own** degree-`K−1` polynomial and has its **own**
  commitment vector. (Independent polynomials per chunk — no cross-chunk structure to
  leak.)

> **Size note (documented limitation):** commitments scale with secret length:
> `m = ceil(len/31)` chunks × `K` commitments × 33 bytes (compressed point). For a
> 32-byte key (`m=2`, `K=3`) that is ~200 bytes of public commitment — trivial. For
> large secrets it grows linearly; the **recommended pattern is unchanged** — wrap a
> 32-byte KEK with [`WrappedSecret`](../README.md) and VSS-split the KEK (`m=2`),
> keeping the envelope public. The wrap helper composes with VSS.

### 3.3 Split (dealer)

For each chunk `e_k`:

1. Sample blinding `r_k ← GF(q)` uniformly (`RandomNumberGenerator`, no injection).
2. Build two degree-`K−1` polynomials with the secret/blinding as constant terms:
   `p_k(x) = e_k + a_{k,1}x + … + a_{k,K−1}x^{K−1}`,
   `p'_k(x) = r_k + b_{k,1}x + … + b_{k,K−1}x^{K−1}`, coefficients uniform in `GF(q)`.
3. Publish commitments `C_{k,j} = a_{k,j}·G + b_{k,j}·H` for `j = 0…K−1`
   (with `a_{k,0}=e_k`, `b_{k,0}=r_k`).
4. Trustee `i ∈ {1…N}` receives share scalars `s_{k,i} = p_k(i)`, `t_{k,i} = p'_k(i)`.

The published `Commitments` are identical for all trustees (broadcast / pinned, like
the dealer key). Optionally the dealer **signs the commitment set with ML-DSA-65** so
the broadcast itself is dealer-authenticated (reuses v1's authenticator).

### 3.4 Verify (each trustee, before trusting the ceremony)

Trustee `i` accepts iff, for every chunk `k`:

`s_{k,i}·G + t_{k,i}·H  ==  Σ_{j=0}^{K−1} (i^j mod q) · C_{k,j}`

If this holds for all chunks, share `i` provably lies on the committed polynomials.
A single failing equation ⇒ the dealer is inconsistent ⇒ **reject the whole ceremony**
(`ShareConsistencyException`).

### 3.5 Reconstruct

Given `K` verified shares and the pinned commitments: re-verify each share against the
commitments (defense in depth), then Lagrange-interpolate `{s_{k,i}}` at `x=0` over
`GF(q)` to recover each `e_k`, and concatenate (trimming to `secretLength`) into a
`ZeroizingBuffer`. Reconstruction additionally checks the recovered `e_k·G + r-free`
consistency against `C_{k,0}` is **not** possible (blinding unknown), so consistency
is enforced at the *share* level in verify, which is the correct VSS guarantee.

## 4. `.pqss` v2 wire format

A new canonical-CBOR container (`version = 2`), same strict reader/writer discipline
as v1 (definite lengths, shortest-form ints, ascending unique integer keys, no
trailing bytes, fail-closed). Two record kinds:

- **`vss-commitments`** (broadcast, public): format tag, version, group id, `K`, `N`,
  `splitId`, `secretLength`, chunk count `m`, the `m·K` compressed commitment points,
  optional dealer auth (alg, dealer key, ML-DSA signature).
- **`vss-share`** (per trustee): format tag, version, group id, `K`, `N`, `index`,
  `splitId`, `secretLength`, the `m` scalar pairs `(s_{k,i}, t_{k,i})` as fixed-width
  big-endian field elements, and a back-reference (`splitId`) tying it to its
  commitment set.

Field numbering, byte widths, and a worked hex example will be pinned in
[`SPEC.md`](SPEC.md) (a new "v2 / VSS" section) with `SpecExampleTests` enforcing it,
exactly as v1 does.

## 5. Public API (as shipped in the `…​.Vss` package)

```csharp
namespace PostQuantum.SecretSharing.Vss;

public static class PedersenVss
{
    public static VssSplit Split(ReadOnlySpan<byte> secret, SharePolicy policy);
    public static ZeroizingBuffer Reconstruct(
        IReadOnlyList<VssShare> shares, VssCommitments commitments);
}

public sealed record VssSplit(VssShare[] Shares, VssCommitments Commitments);

public sealed class VssCommitments               // public broadcast; pin like the dealer key
{
    public int Threshold { get; }
    public int TotalShares { get; }
    public int SecretLength { get; }
    public byte[] Export();
    public static VssCommitments Import(ReadOnlySpan<byte> bytes);
}

public sealed class VssShare
{
    public int ShareIndex { get; }               // raw scalars intentionally not exposed
    public int Threshold { get; }
    public int TotalShares { get; }
    public bool Verify(VssCommitments commitments);     // trustee self-check, pre-reconstruction
    public byte[] Export();
    public static VssShare Import(ReadOnlySpan<byte> bytes);
}
```

Exceptions reuse the v1 hierarchy (`ShareFormatException`, `SharePolicyException`,
`ShareConsistencyException`). `Reconstruct` re-verifies every share against the
commitments and throws `ShareConsistencyException` rather than returning a wrong secret.

> **Deferred to a later preview (documented, not shipped):** ML-DSA-65 signing of the
> commitment broadcast (post-quantum dealer-authentication of the pin) and an optional
> dealer parameter on `Split`. Until then, the commitments must be **pinned / broadcast
> non-equivocably out-of-band**, exactly as the dealer public key is in v1 — the VSS
> guarantee assumes every trustee sees the *same* commitments.

## 6. Dependency & isolation

- The **core stays runtime-dependency-free.** All VSS code and its dependency live
  only in `PostQuantum.SecretSharing.Vss`.
- **Dependency: a vetted EC library** (`BouncyCastle.Cryptography` 2.5.1) for P-256
  point/scalar arithmetic and big-integer modular math. Rationale (audit-readiness):
  the reviewer then audits *our* ~few-hundred lines of protocol glue, while the heavy,
  error-prone field/curve arithmetic is the most-reviewed managed implementation
  available — a far smaller *novel* attack surface than hand-rolling `BigInteger`
  group math. The package's trusted base is documented in [`AUDIT.md`](AUDIT.md) §5.

## 7. Honest limitations (will be added to KNOWN-GAPS on ship)

1. **Binding is computational/classical** (discrete log). Secrecy is not — it stays
   information-theoretic. A quantum *dealer* could defeat consistency detection, not
   secrecy.
2. **Not constant-time.** `BigInteger`/EC scalar arithmetic in the VSS path is not
   constant-time. This is acceptable because secrecy is unconditional (the transcript
   hides `a_0` perfectly); but it is stated, not hidden. The GF(2⁸) core remains the
   constant-time path.
3. **Commitment size grows with secret length** — wrap large secrets (§3.2).
4. **Preview-quality, unaudited new crypto** — ships only as `2.0.0-preview`.

## 8. Test & evidence plan (to match the rest of the project)

- **Unit/known-answer:** `H` derivation vector; commitment/verify equation on fixed
  inputs; round-trip split→verify→reconstruct for `K`/`N`/length matrix.
- **Property (FsCheck + shrinking):** (a) every honestly-split share verifies; (b) any
  tampered share scalar or commitment fails verify; (c) reconstruction from any `K`
  verified shares yields the original secret; (d) a *deliberately inconsistent* dealer
  (one off-curve share) is always detected.
- **Negative/fail-closed:** malformed `.pqss` v2 → only library exceptions (extend the
  fuzz harness to the v2 reader).
- **Cross-impl vectors:** publish v2 vectors (incl. `H`) in `docs/test-vectors*`.
- **Sample:** a `MaliciousDealerDetected` sample showing a tampered ceremony being
  rejected before reconstruction.

## 9. Open questions for review

1. P-256 vs rist255 — P-256 is chosen for tooling/availability; ristretto would give
   a cleaner prime-order group but weaker .NET support. Acceptable?
2. Should VSS commitments be **required** to be ML-DSA-signed (post-quantum
   dealer-auth of the broadcast), or left optional as sketched?
3. 31-byte chunking vs a single large-secret encoding — chunking keeps elements `< q`
   unambiguously; confirm the framing in SPEC.
