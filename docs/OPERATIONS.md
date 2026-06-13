# Operations Guide — Trustee Ceremonies

This guide covers running a real split-and-custody ceremony with
PostQuantum.SecretSharing: choosing parameters, the dealer machine, distributing
shares, reconstructing, and the reality of "revoking" a share.

Throughout, a running example uses a county library — **Lincoln County Public
Library (LCPL)** — protecting the signing key for its catalog's trust anchor.

---

## 1. Choosing `k` and `n`

- **Default: 3-of-5.** Robust against losing two shares (availability) and
  against any two trustees colluding or being compromised (secrecy). A good
  starting point for most organizations.
- **Avoid 2-of-2.** It is fragile: lose either share and the secret is gone
  forever (no redundancy), and either holder alone is one compromise away from a
  quorum-minus-one. Use 2-of-2 only when you genuinely want "both parties must be
  present and there is a separate backup."
- **Pick `n − k ≥ 2`** so you can lose two shares (a destroyed safe, a departed
  trustee) and still recover.
- **Pick `k` for your collusion tolerance.** Any `k` trustees can reconstruct;
  size `k` so that no realistically-collusion-prone subset reaches it.

**LCPL chooses 3-of-5:** five custodians, any three reconstruct.

---

## 2. The dealer machine

The split happens once, on a **dealer machine**, and that machine briefly holds
the whole secret. Treat the ceremony accordingly:

- Prefer an **offline / air-gapped** machine, booted from known-good media.
- Generate the secret (or import it) on that machine; do not transit it over a
  network.
- In authenticated mode, generate the dealer ML-DSA-65 key pair here. Record the
  **public key** out-of-band (print its fingerprint; read it aloud; store it in
  your config management). This is the **pin** every future reconstruction will
  check against.
- Decide the custody of the dealer **private key** deliberately: destroy it after
  the ceremony if you will never re-sign, or seal it (HSM, offline media) if you
  may need to re-split. Anyone with it can mint shares that pass the pin.
- Wipe the dealer machine's working storage after distributing shares.

---

## 3. Distributing shares

- **One share per custodian.** Never give two shares to one person — that hands
  them extra weight toward a quorum.
- Export each share with `SecretShare.Export()` and write it to its medium
  (`share-1.pqss`, …). Physical media should be **labeled with the `splitId` hex
  prefix** (first 8 hex chars) so quorum members can confirm they hold shares of
  the *same* split before they convene.
- Keep a **custody log** (below). Distribute custodians across people *and*
  locations so no single incident (a fire, a firing) takes out a quorum.

### Custody log template

| Index | Custodian | Location | Date issued | splitId prefix |
|------:|-----------|----------|-------------|----------------|
| 1 | IT Director | HQ office safe | 2026-06-12 | `3515bf20` |
| 2 | Sysadmin | Datacenter cage | 2026-06-12 | `3515bf20` |
| 3 | Records Officer | Records room safe | 2026-06-12 | `3515bf20` |
| 4 | (offsite) | County offsite safe | 2026-06-12 | `3515bf20` |
| 5 | County Attorney | Attorney's office | 2026-06-12 | `3515bf20` |

**LCPL's five custodians:** IT Director, Sysadmin, Records Officer, an offsite
county safe, and the County Attorney. No two are in the same room; any three can
recover.

---

## 4. The reconstruction ceremony

- Decide **who convenes** and under what authority (e.g. "any three of the five,
  with the IT Director or County Attorney present").
- Gather **exactly `k`** shares — the library enforces this; supplying more is
  refused so nobody quietly reconstructs from a larger pile.
- Confirm every share's `splitId` prefix matches before importing.
- Reconstruct with the **pinned dealer public key** so the shares' signatures are
  verified against real authority, not self-attestation.
- Use the recovered secret for the immediate task, then **dispose the
  `ZeroizingBuffer`** (`using`) so it is wiped. Do not write the secret to disk.

```csharp
using ZeroizingBuffer key = ShamirSecretSharing.Reconstruct(quorum, pinnedDealerKey);
// ... use key.Span ...
```

---

## 5. "Revocation" is rotation

**You cannot revoke a share.** A `.pqss` share is data; once printed and handed
out, it exists. If a trustee departs or a share may be compromised:

1. **Re-split** the secret into a new split (new `splitId`, new shares) and
   redistribute to the new custody set.
2. Understand that the **old shares still reconstruct the old secret.** If the
   secret itself has not changed, the departed trustee's old share is still
   dangerous.
3. Therefore, when a trustee departs or a share leaks, **rotate the underlying
   secret** (generate a new signing key / re-wrap the DEK), then split the *new*
   secret. Revocation always rotates.

**LCPL example:** the Sysadmin leaves. LCPL generates a new trust-anchor signing
key, re-splits it 3-of-5 among the new custody set, updates systems to trust the
new key, and retires the old key. The departed Sysadmin's old share now unlocks
only a key nothing trusts anymore.

---

## 6. A concrete ceremony — splitting a code-signing key (3-of-5) with `pqss`

This is a complete, runnable script using the `pqss` sample CLI. Adapt paths and
custodians to your environment. Do it on an **offline dealer machine**.

### Pre-ceremony (preparation)

- [ ] Convene the required people / authority; confirm the quorum policy in writing.
- [ ] Prepare the offline dealer machine (known-good boot media, no network).
- [ ] Prepare labeled, tamper-evident media for each custodian.
- [ ] Have the custody log (template below) ready to fill in.

### Ceremony (split)

```bash
# 1. Place (or generate) the signing key on the dealer machine, e.g. key.bin.

# 2. Split 3-of-5, dealer-signed, ASCII-armored (printable), with a commitment.
pqss split key.bin --k 3 --n 5 --out ./shares \
     --sign --sk-out ./dealer.key --armor --commit-out ./key.commit

# 3. Record the dealer public-key fingerprint and the commitment fingerprint
#    (printed by the command) into the custody log and your config management.
```

- [ ] **Pin the dealer public key fingerprint** out-of-band (read it aloud; record
      it in config management). This is the authority for all future recoveries.
- [ ] **Publish the commitment** (`key.commit`) to every custodian / a broadcast
      channel. It lets any future quorum confirm they recovered the right secret.
- [ ] Decide the fate of the dealer **private key** (`dealer.key`): destroy it if
      you will never re-sign, or seal it (HSM/offline) if you may re-split.

### Verify before distribution

```bash
# Confirm every share is well-formed and correctly signed (no quorum needed).
pqss verify ./shares/share-*.pqss.txt --pub ./shares/dealer.pub
```

- [ ] All shares report `OK (signature verified)` and `split consistency : OK`.

### Distribute

- [ ] Write **one** share per custodian to its labeled medium (never two to one
      person). Fill in the custody log. Have each custodian sign for receipt.
- [ ] Wipe the dealer machine's working storage (key.bin, shares, dealer.key if
      destroying).

### Post-ceremony

- [ ] Store the custody log securely; distribute custodians across people *and*
      locations so no single incident takes out a quorum.
- [ ] Schedule a **recovery rehearsal** (next section).

---

## 7. Rehearse recovery without exposing the secret (dry run)

You should periodically prove a quorum can still recover — *without* materializing
the secret. `pqss combine --dry-run` reconstructs, checks the commitment, prints a
fingerprint, and writes nothing.

```bash
pqss combine ./from-custodian-1.pqss.txt ./from-custodian-3.pqss.txt ./from-custodian-4.pqss.txt \
     --pub ./dealer.pub --commit ./key.commit --dry-run
```

- [ ] Output says `DRY RUN OK` and `commitment verified`.
- [ ] The `secret fingerprint (sha256)` matches previous rehearsals (it is stable
      for the same secret; it does **not** reveal the secret).

When you must recover for real, drop `--dry-run` and add `--out recovered.key`.
Use the key for the immediate task only, then securely delete the file.

---

## 8. Printable templates

### Custody log

```
PostQuantum.SecretSharing — Custody Log
Secret description : ____________________________   Policy: ____-of-____
splitId            : ________________________________________________
Dealer key fp      : ________________   Commitment fp: ________________
Ceremony date      : __________   Conducted by: ____________________

 Idx | Custodian (name)      | Location / medium        | Issued (date) | Received (sign)
-----+-----------------------+--------------------------+---------------+----------------
  1  |                       |                          |               |
  2  |                       |                          |               |
  3  |                       |                          |               |
  4  |                       |                          |               |
  5  |                       |                          |               |
```

### Share medium label

```
+--------------------------------------------------+
|  PQSS SHARE  —  CONFIDENTIAL                      |
|                                                  |
|  Secret : ____________________________________   |
|  Share index : ____  of  ____   (need ____)      |
|  splitId prefix : ________                        |
|  Custodian : ________________________________     |
|  Issued : __________                              |
|                                                  |
|  Do NOT photograph or copy. Report loss at once. |
+--------------------------------------------------+
```
