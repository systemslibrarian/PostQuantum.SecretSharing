# `.pqss` Share Format — Specification

This document specifies the byte-level format of a PostQuantum.SecretSharing
share. The format is a **strict, canonical CBOR** map. There are no extension
points: any deviation from this document is rejected.

- **Part I — v1** (the dependency-free GF(2⁸) core share format) is below.
- **Part II — v2 / VSS** (the opt-in Pedersen VSS records) is at the end of this
  file. v2 is purely additive; the v1 format is unchanged.

---

## 1. Encoding subset (CBOR)

A `.pqss` share is a single CBOR data item: a **definite-length map** (major
type 5) whose entries use only the following CBOR major types:

| Major type | Meaning | Used for |
|-----------:|---------|----------|
| 0 | unsigned integer | map keys; numeric fields |
| 2 | byte string | binary fields (splitId, shareData, checkValue, key, signature) |
| 3 | text string | the format tag |
| 5 | map | the top-level container |

Everything else is forbidden and rejected with `ShareFormatException`:
negative integers (major 1), arrays (major 4), tags (major 6), floats/simple
values (major 7), indefinite lengths, reserved additional-info values (28–30),
and any nesting other than the single top-level map.

### 1.1 Canonical rules (RFC 8949 §4.2.1)

The encoder emits, and the decoder **requires**, canonical form:

1. **Definite lengths only.** No indefinite-length items.
2. **Shortest-form integer heads.** A value that fits in a smaller head must use
   it. For example, the integer `1` is `0x01`, never `0x18 0x01`. A non-shortest
   head is rejected.
3. **Map keys in ascending order, unique.** Keys are unsigned integers `0..11`,
   each a single byte, so ascending numeric order equals ascending bytewise
   order. Duplicate or out-of-order keys are rejected.
4. **No trailing bytes.** Exactly one top-level item; any byte after it is
   rejected.

---

## 2. Field table

| Key | Name | CBOR type | Constraints |
|----:|------|-----------|-------------|
| 0 | `format` | text string | exactly `"PQSS"` |
| 1 | `version` | uint | exactly `1` |
| 2 | `threshold` (k) | uint | `2..255` |
| 3 | `total` (n) | uint | `k..255` |
| 4 | `shareIndex` (x) | uint | `1..n` |
| 5 | `splitId` | byte string | exactly 16 bytes (random per split) |
| 6 | `secretLength` | uint | `1..65536`; MUST equal `len(shareData)` |
| 7 | `shareData` (y) | byte string | `1..65536` bytes |
| 8 | `checkValue` | byte string | exactly 32 bytes (see §4) |
| 9 | `authAlgorithm` | uint | `0` = none, `1` = ML-DSA-65; others rejected |
| 10 | `dealerPublicKey` | byte string | **absent iff key 9 = 0**; if 1: exactly 1952 bytes |
| 11 | `signature` | byte string | **absent iff key 9 = 0**; if 1: exactly 3309 bytes |

Keys 0–9 are always present. Keys 10 and 11 are present **if and only if**
`authAlgorithm = 1`. A key 10 or 11 present when `authAlgorithm = 0`, or absent
when `authAlgorithm = 1`, is a `ShareFormatException` (the presence of a field
must not contradict the declared mode).

---

## 3. Signing rule

When `authAlgorithm = 1`, the signature in key 11 is an **ML-DSA-65 (FIPS 204)**
signature in **pure mode with an empty context**, computed over the canonical
encoding of the map containing **keys 0–10 only** (signature excluded, dealer
public key included — the signature binds the claimed key).

Note this signed payload is a *different* CBOR item than the full share: it is a
map of 11 entries (header `0xAB`), whereas the exported share is a map of 12
entries (header `0xAC`). The verifier re-serializes keys 0–10 canonically from
the **parsed** field values and verifies against that; it never trusts offsets
into the original buffer.

---

## 4. Integrity check value

```
checkValue = HKDF-SHA256(ikm = secret, salt = splitId, info = "PQSS-v1-check", L = 32)
```

`secret` is the full reconstructed secret; `splitId` is the 16-byte field 5;
`info` is the 13 ASCII bytes of `PQSS-v1-check`. On reconstruction the value is
recomputed from the recovered secret and compared with
`CryptographicOperations.FixedTimeEquals`.

> **Oracle warning.** Every share carries `splitId` and `checkValue`, so a single
> shareholder can test guesses of the secret offline. For high-entropy secrets
> (e.g. 32-byte keys) this is irrelevant; for low-entropy secrets it is a real
> brute-force oracle. See THREAT-MODEL.md and KNOWN-GAPS.md.

---

## 5. Reader order of operations (fail-closed)

A conformant reader performs these steps **in order**, throwing before any
secret-dependent computation:

1. **Parse** with the strict canonical decoder (§1): definite lengths, canonical
   integers, ascending unique keys, exact type per key, no trailing bytes.
   Violations → `ShareFormatException`.
2. **Range-check** every field per §2 (`ShareFormatException` for format/type/size
   problems; `SharePolicyException` for k/n/index range problems).
3. **Length-check** `shareData` against `secretLength`, and the key-9-dependent
   presence and sizes of keys 10–11.
4. Only now is the share eligible for **authentication** (at reconstruction) and
   **reconstruction**.

Error messages identify *what* failed and *where* (an offset), and never echo
share or secret bytes.

---

## 6. Polynomial construction note

Each secret byte `s[j]` is the constant term of an independent degree-`(k−1)`
polynomial over GF(2⁸):

```
p_j(x) = s[j] + c_1[j]·x + c_2[j]·x² + … + c_{k-1}[j]·x^{k-1}
```

Share `i` (x-coordinate `i`, `i ∈ 1..n`) stores `y[j] = p_j(i)` for every byte.
The reduction polynomial is the AES polynomial `x⁸+x⁴+x³+x+1` (0x11B).

Per standard Shamir (and matching HashiCorp Vault and SLIP-0039), the top
coefficient `c_{k-1}[j]` of an *individual byte* is allowed to be zero. The
degree guarantee is per-byte and probabilistic; this is the accepted
construction, not a bug. The secret as a whole is still protected: any `k−1`
shares leave every secret byte information-theoretically undetermined.

---

## 7. Worked example (byte by byte)

A minimal share: `k = 2`, `n = 3`, `shareIndex = 1`, a 4-byte secret,
unauthenticated (`authAlgorithm = 0`). Values for `shareData` and `checkValue`
below are illustrative (in a real share `checkValue` is the HKDF of §4).

Full bytes (hex):

```
aa
00 6450515353
01 01
02 02
03 03
04 01
05 50 000102030405060708090a0b0c0d0e0f
06 04
07 44 aabbccdd
08 5820 909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
09 00
```

Annotated:

| Bytes | Meaning |
|-------|---------|
| `aa` | map, 10 entries (major 5, count 10) |
| `00` | key 0 |
| `64 50 51 53 53` | text(4) = `"PQSS"` (`P=0x50 Q=0x51 S=0x53 S=0x53`) |
| `01` `01` | key 1 → uint 1 (version) |
| `02` `02` | key 2 → uint 2 (k) |
| `03` `03` | key 3 → uint 3 (n) |
| `04` `01` | key 4 → uint 1 (shareIndex) |
| `05` `50 00…0f` | key 5 → bytes(16) splitId |
| `06` `04` | key 6 → uint 4 (secretLength) |
| `07` `44 aabbccdd` | key 7 → bytes(4) shareData |
| `08` `5820 90…af` | key 8 → bytes(32) checkValue (head `0x58 0x20` = bytes, length 32) |
| `09` `00` | key 9 → uint 0 (authAlgorithm = none) |

The complete encoding is 78 bytes. (These exact bytes are pinned by a unit test,
`SpecExampleTests`, so this section cannot drift from the implementation.)

---
---

# `.pqss` v2 / VSS — Specification

This part specifies the two record kinds added by the **opt-in**
`PostQuantum.SecretSharing.Vss` package (Pedersen Verifiable Secret Sharing over
NIST P-256). It is **additive**: the v1 share format above is unchanged, the
GF(2⁸) core is untouched, and a v1 reader rejects a v2 record (different format
tag and version) and vice-versa. Design rationale is in
[`VSS-DESIGN.md`](VSS-DESIGN.md); cross-implementation vectors are in
[`test-vectors-vss.md`](test-vectors-vss.md).

The same strict canonical-CBOR discipline as v1 applies in full (§1 above):
definite lengths, shortest-form integer heads, ascending unique integer keys,
exact type per key, no trailing bytes, fail-closed with `ShareFormatException`.
Both records reuse the **same audited** `CanonicalCborWriter` / `StrictCborReader`
as v1 — there is no second parser.

## v2.1 Group and constants

| Item | Value |
|------|-------|
| Group | NIST P-256 (secp256r1), `group = 1`. Cofactor 1, prime order `q`. |
| `G` | the standard P-256 base point. |
| `H` | second generator, `log_G(H)` unknown to all parties (see v2.2). |
| Point encoding | **compressed**, 33 bytes: `0x02`/`0x03` ‖ 32-byte big-endian `x`. The identity is not a legal encoding. |
| Scalar encoding | fixed **32-byte big-endian**, canonical, MUST be `< q`. |
| ML-DSA-65 public key | 1952 bytes (as v1). |
| ML-DSA-65 signature | 3309 bytes (as v1). |

## v2.2 Second generator `H` (nothing-up-my-sleeve)

`H` is derived by **hash-and-increment** from a fixed ASCII domain string, so the
value is public, reproducible, and known-to-have-no-known-discrete-log. For
`counter = 0, 1, 2, …` as a big-endian `uint32`:

```
x = SHA-256(  "PostQuantum.SecretSharing/vss/H/secp256r1/v1"  ‖  counter )
skip if x ≥ p (the field prime);
otherwise take the point (x, even-y) if it lies on the curve; else continue.
```

| Item | Value |
|------|-------|
| Domain string (ASCII, 45 bytes) | `PostQuantum.SecretSharing/vss/H/secp256r1/v1` |
| `H` (compressed, hex) | `02C210CA1DD338B122F04B3FF2C7A7F8360D7C43BCFD9647BD022A845B3C33278C` |

Any implementation that derives a different `H` is not interoperable. The vector
is pinned by `VssFormatAndMathTests.Second_generator_H_is_valid_independent_and_deterministic`.

## v2.3 Secret encoding (chunking)

The secret is encoded as a sequence of scalar-field elements, **31 bytes per
element** (248 bits `< q`, so each chunk is an unambiguous element `< q` and the
mapping is injective). `m = chunkCount = ceil(secretLength / 31)`. Chunk `m−1`
carries the trailing `secretLength − 31·(m−1)` bytes. Big-endian within a chunk;
leading zero bytes are preserved because the original `secretLength` is recorded
and used to right-align each chunk on reconstruction.

## v2.4 Record: `vss-commitments` (the public broadcast)

The dealer's commitment broadcast. **Public** — it reveals nothing about the
secret (perfectly hiding). Map of **10 entries** when unsigned (`authAlgorithm = 0`,
header `0xAA`) or **12 entries** when dealer-signed (`authAlgorithm = 1`, header
`0xAC`).

| Key | Name | CBOR type | Constraints |
|----:|------|-----------|-------------|
| 0 | `format` | text string | exactly `"PQSS-VSS-C"` |
| 1 | `version` | uint | exactly `2` |
| 2 | `group` | uint | exactly `1` (secp256r1) |
| 3 | `threshold` (k) | uint | `2..255` |
| 4 | `total` (n) | uint | `k..255` |
| 5 | `splitId` | byte string | exactly 16 bytes |
| 6 | `secretLength` | uint | `1..65536` |
| 7 | `chunkCount` (m) | uint | MUST equal `ceil(secretLength/31)` |
| 8 | `commitments` | byte string | exactly `m·k·33` bytes: `m` chunks × `k` compressed points `C_{c,0..k-1}`, chunk-major then coefficient order |
| 9 | `authAlgorithm` | uint | `0` = none, `1` = ML-DSA-65; others rejected |
| 10 | `dealerPublicKey` | byte string | **absent iff key 9 = 0**; if 1: exactly 1952 bytes |
| 11 | `signature` | byte string | **absent iff key 9 = 0**; if 1: exactly 3309 bytes |

Keys 0–9 are always present. Keys 10 and 11 are present **if and only if**
`authAlgorithm = 1`; a contradiction between key 9 and the presence of keys 10/11
is a `ShareFormatException`. Every point in key 8 is decoded and validated to be a
non-identity on-curve point; any failure is a `ShareFormatException`.

## v2.5 Record: `vss-share` (one per trustee)

A trustee's verifiable share. Map of **10 entries** (header `0xAA`). Individual
shares are not separately signed: their authenticity flows from the **signed
broadcast** (a share is only accepted if it verifies against the commitments, and
the commitments can be dealer-signed — see v2.7).

| Key | Name | CBOR type | Constraints |
|----:|------|-----------|-------------|
| 0 | `format` | text string | exactly `"PQSS-VSS-S"` |
| 1 | `version` | uint | exactly `2` |
| 2 | `group` | uint | exactly `1` |
| 3 | `threshold` (k) | uint | `2..255` |
| 4 | `total` (n) | uint | `k..255` |
| 5 | `shareIndex` (i) | uint | `1..n` |
| 6 | `splitId` | byte string | exactly 16 bytes (ties the share to its broadcast) |
| 7 | `secretLength` | uint | `1..65536` |
| 8 | `chunkCount` (m) | uint | MUST equal `ceil(secretLength/31)` |
| 9 | `scalars` | byte string | exactly `m·2·32` bytes: `m` pairs `(s_c, t_c)`, each a canonical 32-byte scalar `< q` |

## v2.6 Verification equation

A share `i` with scalar pair `(s_c, t_c)` for chunk `c` is **consistent** with the
broadcast's commitments `C_{c,0..k-1}` iff, in the group, for every chunk `c`:

```
s_c · G  +  t_c · H   ==   Σ_{j=0}^{k-1} (i^j mod q) · C_{c,j}
```

A trustee accepts the share iff this holds for **all** `m` chunks. A single
failing equation ⇒ inconsistent dealer or tampered share ⇒ reject the ceremony
(`ShareConsistencyException`). Reconstruction re-checks this for every supplied
share before interpolating (defense in depth), then Lagrange-interpolates each
chunk's `s` values at `x = 0` over GF(q) and concatenates, trimming to
`secretLength`.

## v2.7 Signing rule (broadcast authentication)

When `authAlgorithm = 1`, key 11 is an **ML-DSA-65 (FIPS 204)** signature in
**pure mode with an empty context**, over the canonical encoding of the
`vss-commitments` map containing **keys 0–10 only** (signature excluded, dealer
public key included so the signature binds the claimed key).

That signed payload is a *different* CBOR item than the exported record: a map of
**11 entries** (header `0xAB`), whereas the signed export is **12 entries**
(header `0xAC`). The verifier re-serializes keys 0–10 canonically from the
**parsed** field values — never from offsets into the received buffer — and
verifies against that, exactly as v1 does for shares. This authenticates the
*pin itself*: a trustee that has pinned the dealer key out-of-band can confirm the
broadcast came from that dealer and was not substituted. It is **independent of**,
and additional to, the per-share consistency check of v2.6.

## v2.8 Reader order of operations (fail-closed)

Identical discipline to v1 §5: strict canonical parse → range-check every field →
structural length checks (`commitments`/`scalars` blob length against `m`, `k`;
key-9-dependent presence/size of keys 10–11; every point/scalar canonical and
in-range) → only then group-arithmetic verification, signature verification, and
reconstruction. No step that depends on a share scalar runs before the record is
fully validated. Error messages identify what failed, never echoing scalar bytes.

## v2.9 Worked example (pinned)

Fixed inputs: `k = 2`, `n = 3`, secret =
`000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F` (32 bytes ⇒
`m = 2` chunks), unsigned broadcast, randomness from the fully-specified
`DeterministicRng` SHA-256 counter stream documented in
[`test-vectors-vss.md`](test-vectors-vss.md).

`vss-commitments` (170 bytes, header `0xAA`):

```
AA006A505153532D5653532D43010202010302040305500A932FAE9FD5630126CF712C89B1DA55
0618200702085884021CC34AE98AFE0A80ECB563E7471F7884D07A4117E9AD30501B41F3AFC13B9
D73030663DF9DBE99735ED2841FFAEA3D6F710790043CBA7E14A7B62B62B7C1205048F02BDC3FC5
F2370A240A63AA19377092DEF7E49CCFE566D4D063D43D6FCD308CC7B02FE5394E23860940A3E4E
53D8CA1EEEB93F9DFA5685CC0AD6573888399EF815950900
```

`vss-share` (index 1, header `0xAA`):

```
AA006A505153532D5653532D530102020103020403050106500A932FAE9FD5630126CF712C89B1DA
550718200802095880A2DE39EBDACA0B23F92A8C90D2CBC7303ABBD3E4E2C0222FF03F8753368403
991C0FD9915CC8BA0AA71F523AF84DF72AC3826440BAD40A70858AC3BB1950A7BCB93D6E1039DB7C0
2E11A581B72BF9DFF3CC31EFDDBA1E5D5E2401A93340A3326CE99E95C5B4B13BE68D1B33466360BB0
8A9CADB7B10F7D5B49C0C7EBE13D3F66
```

All three shares and the full broadcast are pinned by `VssSpecExampleTests`, which
re-derives them from the secret and the deterministic RNG and also confirms they
parse, verify, and reconstruct — so this section cannot drift from the code.
