# VSS Test Vectors (`.pqss` v2 / Pedersen VSS)

Cross-implementation vectors for the opt-in `PostQuantum.SecretSharing.Vss` package.
These pin the parts of the scheme that must be byte-stable across implementations and
versions. See [`VSS-DESIGN.md`](VSS-DESIGN.md) for the construction.

## Group

| Item | Value |
|------|-------|
| Group | NIST P-256 (secp256r1), group id `1` |
| Generator `G` | the standard P-256 base point |
| Scalar field | integers mod `q`, the P-256 group order |
| Point encoding | compressed, 33 bytes (`0x02`/`0x03` ‖ 32-byte big-endian x) |
| Scalar encoding | fixed 32-byte big-endian, canonical (must be `< q`) |

## Second generator `H` (nothing-up-my-sleeve)

`H` is derived by hash-and-increment from a fixed ASCII domain string so that no party
knows `log_G(H)`. For `counter = 0, 1, 2, …` (big-endian `uint32`), compute
`x = SHA-256(domain ‖ counter)`; skip while `x ≥ p` (the field prime); otherwise take
the even-`y` point with that `x` if one exists on the curve.

| Item | Value |
|------|-------|
| Domain string (ASCII) | `PostQuantum.SecretSharing/vss/H/secp256r1/v1` |
| `H` (compressed, hex) | `02C210CA1DD338B122F04B3FF2C7A7F8360D7C43BCFD9647BD022A845B3C33278C` |

This vector is enforced by
`VssFormatAndMathTests.Second_generator_H_is_valid_independent_and_deterministic`. Any
implementation that derives a different `H` is not interoperable.

## Verification equation

A share `i` with scalar pair `(s_k, t_k)` for chunk `k` is consistent with the dealer's
commitments `C_{k,0..K-1}` iff, in the group:

```
s_k · G + t_k · H  ==  Σ_{j=0}^{K-1} (i^j mod q) · C_{k,j}
```

## Secret encoding

The secret is split into 31-byte big-endian chunks (each `< q`); chunk `m-1` carries the
trailing `secretLength − 31·(m-1)` bytes. Reconstruction Lagrange-interpolates each
chunk's `s` values at `x = 0` over GF(q) and concatenates, restoring leading zero bytes
and the final short chunk exactly.

> Worked end-to-end record vectors (a full commitment broadcast + share set for a fixed
> secret and fixed randomness) will be added alongside the move from preview to stable,
> once an injectable test-only RNG seam for the VSS package is in place. The `H` vector
> and the equations above are stable now.
