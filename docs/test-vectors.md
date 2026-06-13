# Test Vectors

This package ships cross-implementation test vectors in
[`test-vectors.json`](test-vectors.json). They are produced by an **independent**
Python reference implementation (`reference/shamir_reference.py`, table-based for
obvious correctness) and consumed by the C# test suite (which uses the
constant-time, table-free production code). Agreement between two independent
implementations on every vector is strong evidence both are correct.

## Regenerating

```bash
python reference/generate_vectors.py
```

This rewrites `docs/test-vectors.json` deterministically (fixed secrets, fixed
coefficients, sorted keys, LF newlines). Re-running must produce byte-identical
output. CI runs the generator and then `git diff --exit-code` to guard against
drift between the reference and the committed vectors.

## Contents

| JSON key | What it is | Consumed by |
|----------|------------|-------------|
| `gf_mul_table_sha256` | SHA-256 of the full 256×256 GF(2⁸) multiplication table (row-major) | `Gf256Tests.MulTable_FullDigest_MatchesReferenceVector` recomputes the table via `Gf256.Mul` and compares the digest — one assertion covering every `(a,b)` pair |
| `gf_inverses_1_to_255` | The multiplicative inverse of every nonzero field element | `Gf256Tests.Inverses_1_To_255_MatchReferenceVector` |
| `split` | 6 fixed-coefficient split vectors: `k/n ∈ {2/3, 3/5, 5/5, 2/255, 3/5, 2/3}`, secret lengths `{1, 32, 4096}` | `ShamirCoreTests.Split_FixedCoefficients_MatchReferenceVectors`, driving `ShamirCore` with the same fixed coefficients via the internal RNG hook |
| `reconstruct` | 4 reconstruct vectors (subset of shares → expected secret) | `ShamirCoreTests.Reconstruct_MatchesReferenceVectors` |
| `checkValue` | 2 vectors `(secret, splitId) → 32-byte checkValue` | `CheckValueTests.CheckValue_MatchesReferenceVectors` |

## Determinism notes

- The reference uses **fixed, listed coefficients** so split outputs are
  reproducible. The production C# code never exposes RNG injection publicly; the
  test drives `ShamirCore` through an internal `RandomFill` hook (visible only via
  `InternalsVisibleTo`) using exactly those coefficients.
- Per the construction (see SPEC.md §6), the top coefficient of an individual
  byte may be zero; the vectors include such cases naturally and they are valid.
- The worked byte-level `.pqss` example is specified in [`SPEC.md`](SPEC.md) §7
  and pinned separately by `SpecExampleTests`.
