# Test Vectors & Conformance Reference

This document, together with [`test-vectors.json`](test-vectors.json), is the
**cross-implementation conformance reference** for PostQuantum.SecretSharing.
Any independent implementation of the scheme — in any language — can validate its
field math, splitting, reconstruction, and check value against these vectors. If
your implementation reproduces every vector here, its core is interoperable with
this one.

The vectors are produced by an **independent** Python reference
(`reference/shamir_reference.py`, deliberately table-based for obvious
correctness) and consumed by the C# test suite (which uses the constant-time,
table-free production code). Two independent implementations agreeing on every
vector is strong evidence both are correct.

## Regenerating (and the drift guard)

```bash
python reference/generate_vectors.py
```

This rewrites `docs/test-vectors.json` deterministically (fixed secrets, fixed
coefficients, sorted keys, LF newlines); re-running must produce byte-identical
output. CI runs the generator and then `git diff --exit-code` to guarantee the
committed vectors never drift from the reference.

---

## The algorithm, precisely (so you can implement against it)

### 1. Field: GF(2⁸)

Elements are bytes. Addition is XOR. Multiplication is carry-less multiplication
modulo the AES reduction polynomial **`x⁸ + x⁴ + x³ + x + 1` = `0x11B`**. The
multiplicative inverse is `a⁻¹ = a²⁵⁴` (the group has order 255).

- **Conformance:** recompute the full 256×256 multiplication table (row-major,
  `table[a*256 + b] = a·b`) and SHA-256 it; it must equal `gf_mul_table_sha256`.
  The inverses of `1..255` must equal `gf_inverses_1_to_255`.

### 2. Split

For a secret of `L` bytes with threshold `k`, each byte `s[j]` (`j = 0..L-1`) is
the constant term of an independent degree-`(k−1)` polynomial over GF(2⁸):

```
p_j(x) = s[j] ⊕ c₁[j]·x ⊕ c₂[j]·x² ⊕ … ⊕ c_{k-1}[j]·x^{k-1}
```

The coefficient `c_r[j]` (for power `r = 1..k−1`) is the byte at row `r−1`,
column `j` of the coefficient matrix. Share `i` (x-coordinate `i ∈ 1..n`) stores
`y_i[j] = p_j(i)` for every byte, evaluated by Horner's method from the highest
coefficient down to the constant term. Per standard Shamir, the top coefficient
of an individual byte may be zero (see [`SPEC.md`](SPEC.md) §6).

- **Conformance:** each `split` vector lists the secret, the exact `coeffRows`
  (so the result is deterministic), and the resulting `shares`
  (`{x, y}` per share). Drive your splitter with those exact coefficients and you
  must reproduce every `y`.

### 3. Reconstruct

Given `k` shares `(xᵢ, yᵢ)`, recover byte `j` by Lagrange interpolation at `x = 0`:

```
secret[j] = Σᵢ  yᵢ[j] · Lᵢ      where   Lᵢ = Πₘ≠ᵢ  xₘ / (xₘ ⊕ xᵢ)
```

The `k` basis coefficients `Lᵢ` depend only on the public x-coordinates, so they
are computed once and applied across all byte columns.

- **Conformance:** each `reconstruct` vector lists a share subset and the
  `expectedSecret`. Interpolating the subset must reproduce it.

### 4. Check value

```
checkValue = HKDF-SHA256(ikm = secret, salt = splitId, info = "PQSS-v1-check", L = 32)
```

`info` is the 13 ASCII bytes `PQSS-v1-check`.

- **Conformance:** each `checkValue` vector lists `(secret, splitId)` and the
  expected 32-byte value.

---

## Contents of `test-vectors.json`

| JSON key | What it is | Consumed by |
|----------|------------|-------------|
| `gf_mul_table_sha256` | SHA-256 of the full 256×256 GF(2⁸) multiplication table | `Gf256Tests.MulTable_FullDigest_MatchesReferenceVector` |
| `gf_inverses_1_to_255` | Inverse of every nonzero element | `Gf256Tests.Inverses_1_To_255_MatchReferenceVector` |
| `split` | 14 fixed-coefficient split vectors — `k/n` from `2/2` to `254/255`, lengths `1..4096` | `ShamirCoreTests.Split_FixedCoefficients_MatchReferenceVectors` |
| `reconstruct` | 10 subset→secret vectors, including non-trivial x-subsets and large quora | `ShamirCoreTests.Reconstruct_MatchesReferenceVectors` |
| `checkValue` | 4 `(secret, splitId) → 32-byte` vectors (zero, mixed, 1-byte, long) | `CheckValueTests.CheckValue_MatchesReferenceVectors` |

### Parameter coverage (split / reconstruct)

| Label | k | n | length | Notes |
|-------|--:|--:|-------:|-------|
| `k2n3_len1` | 2 | 3 | 1 | minimal secret |
| `k2n2_len16` | 2 | 2 | 16 | `n == k` (no redundancy) |
| `k2n3_len32` | 2 | 3 | 32 | 256-bit key |
| `k3n5_len32` | 3 | 5 | 32 | the recommended default |
| `k3n5_len65` | 3 | 5 | 65 | crosses the 64-byte boundary |
| `k5n5_len32` | 5 | 5 | 32 | all shares required |
| `k7n10_len32` | 7 | 10 | 32 | mid-range quorum |
| `k10n10_len8` | 10 | 10 | 8 | all of ten required |
| `k4n7_len200` | 4 | 7 | 200 | non-power-of-two length |
| `k2n255_len1` / `k2n255_len32` | 2 | 255 | 1 / 32 | maximum fan-out |
| `k128n255_len4` | 128 | 255 | 4 | large threshold |
| `k254n255_len16` | 254 | 255 | 16 | maximum threshold (`k = n−1`) |
| `k3n5_len4096` | 3 | 5 | 4096 | large secret |

## Notes

- The reference uses **fixed, listed coefficients** so split outputs are
  reproducible. The production C# code never exposes RNG injection publicly; the
  test drives the engine through an internal `RandomFill` hook (visible only via
  `InternalsVisibleTo`) using exactly those coefficients.
- Authenticated (ML-DSA-65) shares are **not** in the vector set: FIPS 204
  signing is randomized, so signatures are not reproducible fixed vectors. The
  signing *payload* (canonical bytes of keys 0–10) is specified in
  [`SPEC.md`](SPEC.md) §3, and a complete worked `.pqss` byte example (pinned by
  `SpecExampleTests`) is in SPEC.md §7.
