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
