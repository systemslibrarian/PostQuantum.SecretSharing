# TODO — your move

Everything that can be done in code is done and pushed. These are the items only
**you** (a human) can close to move from "excellent v1" toward gold standard.
Ordered by impact. No rush — pick them up when you're rested.

---

## 1. Dogfood it on a real key (highest impact)

The ceremony is built, scripted, and proven on a representative key. The only
thing left is running it on a **real** high-value key you control (your NuGet /
code-signing key is the obvious first target) with **real** custodians.

- [ ] Pick the key: NuGet author-signing `.pfx`, strong-name `.snk`, or a PKCS#8/DER private key.
- [ ] On an **offline** machine, run the same commands as
      `scripts/dogfood-signing-ceremony.sh` but with your real key file instead of
      the generated one. (Read it first; it's short.)
- [ ] Hand **one** armored share to each of 5 real custodians (different people,
      different locations). Fill in the custody log template in
      `docs/OPERATIONS.md` §8.
- [ ] **Pin** the printed dealer public-key fingerprint somewhere durable (config
      mgmt / password manager) and **publish** the commitment file to all custodians.
- [ ] Decide the dealer private key's fate: destroy `dealer.key` (if you'll never
      re-split) or seal it offline.
- [ ] Securely delete the plaintext key + any `recovered-*.der` after you're done.
- [ ] Schedule a recovery **rehearsal** (`pqss combine ... --dry-run`) ~quarterly.
- [ ] Fill the real `splitId` / fingerprints / date into
      `docs/CASE-STUDY-signing-key.md` so it becomes a true production case study
      (replace the "representative key" note).

> Full step-by-step is already written in `docs/CASE-STUDY-signing-key.md`
> ("Adapting this to your real key") and `docs/OPERATIONS.md`.

---

## 2. Get an independent review (removes the biggest trust gap)

I wrote the code *and* its tests, so that is not independent. Ask 1–2 people you
trust to look at the two highest-risk files:

- [ ] `src/PostQuantum.SecretSharing/Gf256.cs` — constant-time field math.
- [ ] `src/PostQuantum.SecretSharing/Cbor/StrictCborReader.cs` (+ `CanonicalCborWriter.cs`) — the strict parser.
- [ ] Point them at `docs/SPEC.md`, `docs/test-vectors.md`, and the fuzz tests
      (`tests/.../CborPropertyTests.cs`) — those make a reviewer's job fast.
- [ ] (Stretch) Ask in a .NET/crypto community for a second opinion before tagging `1.0.0`.

---

## 3. First release (when 1 + 2 feel done)

- [ ] Tag `v1.0.0-rc.1` on GitHub (CI builds the `.nupkg`).
- [ ] Decide whether to push the package to NuGet.org now (rc) or wait for stable.
      If yes: `dotnet nuget push artifacts/*.nupkg -k <API_KEY> -s https://api.nuget.org/v3/index.json`
      (and protect that NuGet API key — ironically, a great `--wrap` candidate).
- [ ] When ready for stable: update `CHANGELOG.md`, bump version to `1.0.0` in
      `src/PostQuantum.SecretSharing/PostQuantum.SecretSharing.csproj`, tag `v1.0.0`.

---

## 4. Nice-to-haves (no urgency)

- [ ] Enable GitHub private vulnerability reporting (Settings → Security) so
      `SECURITY.md`'s instructions actually work.
- [ ] Turn on branch protection for `main` (require CI green).
- [ ] Add a CI step (or accept the TODO already in `.github/workflows/ci.yml`) for
      reproducible-build attestation later.
- [ ] Consider a short README badge row (build status, NuGet version) once published.

---

## Status snapshot (so you remember where it stands)

- Core + ML-DSA-65 auth + WrappedSecret + Refresh + DealerCommitment: **done**.
- Tests: **108 (net8.0) / 119 (net10.0)** green; fuzz + constant-time evidence: **done**.
- Cross-impl vectors, SPEC, THREAT-MODEL, KNOWN-GAPS, OPERATIONS, BENCHMARKS,
  COMPATIBILITY, ROADMAP, CHANGELOG: **done**.
- 5 samples (incl. `pqss` CLI + ASP.NET Core DP): **done**.
- Everything committed and pushed to `origin/main` (latest: `483c24d`).

Sleep well. None of this is on fire. 🌙
