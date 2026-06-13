# Benchmarks & Constant-Time Evidence

Two separate questions matter for a secret-sharing primitive: **is it fast
enough?** and **is it constant-time with respect to the secret?** This document
covers both, with reproducible commands. All numbers below are illustrative,
machine-dependent samples (a Windows 11 dev box, .NET 10, Release); treat the
*shape* of the results as the claim, not the absolute nanoseconds.

> Reproduce locally:
> ```bash
> # Rigorous numbers (BenchmarkDotNet: split / reconstruct / export / import):
> dotnet run -c Release --project benchmarks/PostQuantum.SecretSharing.Benchmarks
> #   ...or a quick pass:  -- --job short      ...or filter:  -- --filter *Split*
>
> # Quick smoke numbers + constant-time evidence (xUnit traits):
> dotnet test -c Release -f net10.0 --filter "Category=bench"    # throughput
> dotnet test -c Release -f net10.0 --filter "Category=timing"   # constant-time
> ```
> The xUnit `bench`/`timing` trait groups are **excluded from the CI gate**
> (wall-clock numbers are noisy on shared runners); run them explicitly. The
> [BenchmarkDotNet project](../benchmarks/PostQuantum.SecretSharing.Benchmarks)
> produces the authoritative, statistically-rigorous numbers (with
> `[MemoryDiagnoser]` allocation columns).

---

## 1. Throughput

| Operation | Sample | Result |
|-----------|--------|-------:|
| Split, 3-of-5, 32-byte secret | `BenchTests.Split_3of5_32Bytes_IsFast` | ~**0.015 ms/op** (target < 1 ms) |
| Split + reconstruct, 64 KiB, 3-of-5 | `BenchTests.Split_Reconstruct_64KiB_Under250ms` | ~**18 ms** (target < 250 ms) |
| `Gf256.Mul` | `TimingTests` | ~**5.1 ns/op** |
| `Gf256.Inv` (a²⁵⁴) | `TimingTests` | ~**84 ns/op** |

A typical use — splitting or reconstructing a 32-byte key — is sub-millisecond.
The library is a primitive, not a bottleneck; correctness and constant-time
behavior are prioritized over raw speed (e.g. no log/antilog tables).

---

## 2. Constant-time evidence

### The structural guarantee (the real one)

`Gf256.Mul` and `Gf256.Inv` are **branchless and table-free**:

- Multiplication is a fixed 8-iteration Russian-peasant loop using arithmetic
  masks (`-(b & 1)`, `-((a >> 7) & 1)`) instead of `if`s — the same instructions
  execute regardless of operand values.
- Inversion is `a²⁵⁴` via a fixed square-and-multiply pattern over the **public**
  constant exponent 254 — the control flow does not depend on `a`.
- There are **no secret-indexed memory accesses** (the classic log/antilog table
  is deliberately absent), so there is no data-dependent cache-timing channel.

Because the instruction stream and memory-access pattern are independent of the
operand values, timing cannot leak the secret bytes that flow through these
routines during split and reconstruct.

### Empirical corroboration

`TimingTests` measures each primitive across operand classes that would diverge
sharply if the code branched on data or used secret-indexed lookups, and reports
the `max/min` timing ratio (1.0 = perfectly uniform):

| Measurement | Sample result |
|-------------|--------------:|
| `Mul(·, 0x00)` | ~5.1 ns/op |
| `Mul(·, 0xFF)` | ~5.1 ns/op |
| `Mul(·, varying)` | ~5.6 ns/op |
| **Mul max/min ratio** | **~1.09×** |
| `Inv(0x01)` / `Inv(0xFF)` / `Inv(0x53)` | ~84–92 ns/op |
| **Inv max/min ratio** | **~1.1×** |

A ratio near 1.0 is consistent with data-independent execution; a table- or
branch-based implementation would typically diverge far more. The test asserts
the ratio stays below 3× as a regression guard.

### Limits of this evidence (honest scope)

- This is **statistical corroboration**, not a formal constant-time proof.
  Microarchitectural timing depends on the CPU, the JIT, and the surrounding
  code; the structural argument above is the primary guarantee.
- It covers the **field arithmetic** (where secret bytes flow). The CBOR parser
  is intentionally *not* constant-time — it processes public share structure, not
  secret values (see KNOWN-GAPS.md).
- Side channels beyond timing (power, EM) are out of scope (see THREAT-MODEL.md).
