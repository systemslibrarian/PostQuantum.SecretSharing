# Case Study — Quorum Custody of a Code-Signing Key

**Goal:** stop a single laptop, HSM, or person from being a single point of
failure *or* a single point of compromise for a code-signing / NuGet
author-signing private key — without a passphrase anyone can guess.

This is the canonical dogfooding target for PostQuantum.SecretSharing: a
high-value, high-entropy key that must survive personnel changes and stolen
hardware, and must never be reconstructable by fewer than a quorum.

> **Status (honesty first).** The transcript below is from a fully **verified,
> reproducible run** ([`scripts/dogfood-signing-ceremony.sh`](../scripts/dogfood-signing-ceremony.sh))
> against a freshly generated EC P-384 key used as a *representative stand-in* for
> a real signing key. The commands and proofs are exactly what you run for the
> real key. It becomes a true production deployment once you run it on your actual
> key with real custodians per [OPERATIONS.md](OPERATIONS.md) — see "Adapting this
> to your real key" below.

## What the ceremony does

1. Signs a release artifact with the **original** key (baseline).
2. Splits the private key **3-of-5**, dealer-signed (ML-DSA-65), ASCII-armored,
   with a published commitment.
3. **Verifies every share** before distribution — no quorum required.
4. **Rehearses** recovery with `--dry-run` (reconstructs, checks the commitment,
   prints a fingerprint, writes nothing).
5. **Recovers** the key from a *different* quorum.
6. **Proves** the result two independent ways.

## Verified transcript (representative key)

```
== 1. Generate a representative EC P-384 signing key and sign an artifact ==
  private key: 167 bytes (high-entropy → safe to split directly)
  signed a release artifact with the ORIGINAL key

== 2. Split 3-of-5 (dealer-signed, ASCII-armored, with a commitment) ==
  commitment        : ./signing-key.commit  (fingerprint 8dd334fe812fddd1)
  dealer public key : ./shares/dealer.pub   (fingerprint 162a70f9e1708a13)
  split 3-of-5: wrote 5 armored shares to './shares'
  splitId           : 92feed68299d90a9169a3d74891ec739

== 3. Verify every share before distribution (no quorum needed) ==
  split consistency : OK (same splitId/policy)
  share 1..5         OK (signature verified)

== 4. Rehearse recovery without exposing the key (dry run) ==
  commitment verified: recovered secret matches the published value.
  DRY RUN OK: reconstructed 167 bytes from 3 shares  (dealer key verified)

== 5. Real recovery from a DIFFERENT quorum (shares 2,4,5) ==
  commitment verified: recovered secret matches the published value.
  recovered 167 bytes from 3 shares  'recovered-key.der'  (dealer key verified)

== 6. Proof ==
  PROOF A: recovered key is BYTE-IDENTICAL to the original
  PROOF B: a NEW signature from the RECOVERED key verifies against the ORIGINAL public key
```

**PROOF A** (`cmp signing-key.der recovered-key.der`) shows reconstruction is
lossless — the recovered key *is* the original, bit for bit. **PROOF B** shows the
recovered key is fully functional: a fresh signature it produces verifies under
the original public key. Below the quorum (any 2 of the 5 shares), the key is
information-theoretically unrecoverable.

## Why this is safe to split directly

An EC/RSA private key is high-entropy key material, so the per-share check-value
"oracle" is irrelevant (guessing it is a ~2¹⁹²⁺ search). If you were instead
protecting a *passphrase* or a small token, you would use `WrappedSecret` (or the
CLI `--wrap`) rather than splitting it directly — see the README.

## Adapting this to your real key

The commands are identical; only the input file and the custody change.

1. **Use your real key file** in place of `signing-key.der`:
   - A NuGet author-signing / Authenticode **PFX** → export the `.pfx` bytes (it
     is already high-entropy; split the file directly).
   - A strong-name key (`.snk`), or a PKCS#8/DER private key → split the file.
2. **Run on an offline dealer machine** (see [OPERATIONS.md](OPERATIONS.md) §2).
3. **Distribute** one armored share per real custodian; fill in the custody log
   (OPERATIONS.md §8). Never give two shares to one person.
4. **Pin** the printed dealer public-key fingerprint out-of-band and **publish**
   the commitment to all custodians.
5. **Decide the dealer private key's fate**: destroy `dealer.key` if you will
   never re-sign shares, or seal it (HSM/offline) if you may re-split.
6. **Securely delete** the plaintext key and the `recovered-*.der` file after the
   immediate signing task; reconstruct again from a quorum next time.
7. **Schedule a recovery rehearsal** (`--dry-run`) so you learn about a lost or
   corrupted share *before* you actually need the key.

When a custodian departs or a share may be exposed, **rotate**: re-key (or
re-split with `pqss refresh`) and retire the old split — see OPERATIONS.md §5,
"revocation always rotates."

## Reproduce it yourself

```bash
bash scripts/dogfood-signing-ceremony.sh
```

Requires `bash`, `openssl >= 3`, and the .NET SDK. It is self-contained, uses a
throwaway temp directory, and cleans up after itself.
