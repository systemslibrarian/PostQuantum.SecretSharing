# `.pqss` Share Format — Specification v1

This document specifies the byte-level format of a PostQuantum.SecretSharing
share. The format is a **strict, canonical CBOR** map. There are no extension
points in v1: any deviation from this document is rejected.

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
