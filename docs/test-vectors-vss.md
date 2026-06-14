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

## Worked example (full records, fixed randomness)

These bytes are reproducible by any implementation. The randomness is a fully-specified
**SHA-256 counter stream** (the test-only seam described in
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) §7; production uses only the system CSPRNG):

```
seed     = SHA-256("PostQuantum.SecretSharing/vss/test-vectors/v1")
block(i) = SHA-256(seed ‖ uint32_be(i))           for i = 0, 1, 2, …
stream   = block(0) ‖ block(1) ‖ block(2) ‖ …      (consumed left-to-right)
```

The dealer draws from `stream` in this order: first the 16-byte `splitId`; then, per
chunk `c = 0..m-1`, the blinding constant `b_{c,0}`, then for `j = 1..k-1` the pair
`a_{c,j}, b_{c,j}` (each a 32-byte rejection-sampled scalar `< q`; retry past any draw
`≥ q`). The secret constants `a_{c,0}` are the secret chunks themselves and are not drawn.

**Inputs:** `k = 2`, `n = 3`, unsigned broadcast, and

```
secret = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F   (32 bytes ⇒ m = 2)
```

**`vss-commitments`** (the public broadcast):

```
AA006A505153532D5653532D43010202010302040305500A932FAE9FD5630126CF712C89B1DA55
0618200702085884021CC34AE98AFE0A80ECB563E7471F7884D07A4117E9AD30501B41F3AFC13B9
D73030663DF9DBE99735ED2841FFAEA3D6F710790043CBA7E14A7B62B62B7C1205048F02BDC3FC5
F2370A240A63AA19377092DEF7E49CCFE566D4D063D43D6FCD308CC7B02FE5394E23860940A3E4E
53D8CA1EEEB93F9DFA5685CC0AD6573888399EF815950900
```

**`vss-share` records** (one per trustee, index 1..3):

```
share 1:
AA006A505153532D5653532D530102020103020403050106500A932FAE9FD5630126CF712C89B1DA
550718200802095880A2DE39EBDACA0B23F92A8C90D2CBC7303ABBD3E4E2C0222FF03F8753368403
991C0FD9915CC8BA0AA71F523AF84DF72AC3826440BAD40A70858AC3BB1950A7BCB93D6E1039DB7C0
2E11A581B72BF9DFF3CC31EFDDBA1E5D5E2401A93340A3326CE99E95C5B4B13BE68D1B33466360BB0
8A9CADB7B10F7D5B49C0C7EBE13D3F66

share 2:
AA006A505153532D5653532D530102020103020403050206500A932FAE9FD5630126CF712C89B1DA
55071820080209588045BC72D6B2901140EB4D10179A8B8152A9809C0A0B5490C4D5AD2AC95588C4
C36C5DB749AACA1490FAF16149E1CC82A1E7A41C9B56AC12A13DAF02D92A42E4B7727ADC2173B6F80
4C234B036E57F3BFEBC9F434E102C2D26D0C66A636BB140DCFA0DC0E6830DF3C01148CC5269EB9A61
CCB6A0078BD087DFE92ED26A2D669C23

share 3:
AA006A505153532D5653532D530102020103020403050306500A932FAE9FD5630126CF712C89B1DA
550718200802095880E89AABC08A56175EDD6F939E624B3B74D52C5EDCDB009DDEAED4990270F0AB3
EBCAB9501F8CB6F174EC37058CB4B0E190BC5D4F5F2841AD1F5D341F73B3521B22BB84A32AD927406
A34F0852583ED9FE3C7B679E44B67477BF4CBA33A3584E9225819871AAD0D3C0B9BFE5706DA129135
1E997A9BF79F3DF94E312257D2CD38F
```

Any `k = 2` of the three shares reconstruct the secret; all three verify against the
broadcast via the §"Verification equation". These records are pinned and re-derived by
`VssSpecExampleTests`, which also confirms they parse, verify, and reconstruct — so the
vectors cannot silently drift from the implementation.

> A **dealer-signed** broadcast (`authAlgorithm = 1`) simply appends keys 9–11 (ML-DSA-65
> public key + signature over keys 0–10; see [`SPEC.md`](SPEC.md) §v2.7). It is not pinned
> as a fixed vector because ML-DSA signing is randomized, so the signature bytes differ per
> run; `VssDealerSigningTests` exercises it round-trip instead.
