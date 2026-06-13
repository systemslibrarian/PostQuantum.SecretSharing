# Samples

Three runnable samples, from "see it work" to "actually use it." Each references
the library as a **project**, not a NuGet package — these are the only places the
suite is "integrated," per the standalone design rule.

Run any of them with `dotnet run --project samples/<name>`.

---

## 1. `SignerCustody` — authenticated quorum custody (net10.0)

The headline scenario: a high-value signing key placed under **3-of-5** custody
with **dealer authentication** (ML-DSA-65). It generates a dealer key pair, splits
a simulated signing key, writes a `.pqss` share per trustee, then reconstructs
from exactly three shares while verifying every signature against the pinned
dealer public key — and shows that two shares are refused.

```bash
dotnet run --project samples/SignerCustody
```

Demonstrates: authenticated `Split`, pinning at `Reconstruct`, exactly-`k`
enforcement, a trustee/custodian model with `splitId` labeling.

> Requires ML-DSA-65 (Windows, or Linux with OpenSSL ≥ 3.5). On unsupported
> platforms it prints a notice and exits.

---

## 2. `EnvelopeRecovery` — the wrap pattern (net8.0, runs everywhere)

The **right way to protect low-entropy or large data**. You must not split a
passphrase directly (the check value is an offline guessing oracle). Instead this
sample encrypts a low-entropy recovery document under a random 256-bit KEK with
AES-256-GCM, splits the **KEK** 3-of-5, and stores a non-secret envelope
(`nonce + tag + ciphertext`) beside the shares. Recovery reconstructs the KEK from
a quorum and decrypts.

```bash
dotnet run --project samples/EnvelopeRecovery
```

Demonstrates: the wrap pattern, protecting arbitrary-size secrets, the
core running on net8.0 with **no ML-DSA dependency**, sub-quorum refusal.

---

## 3. `pqss` (PqssCli) — a real command-line utility (net10.0)

A small but genuinely usable CLI over the `.pqss` format: `split`, `inspect`,
`combine`, and `refresh` — with optional dealer signing, the wrap pattern
(`--wrap`/`--envelope`), and dealer commitments (`--commit-out`/`--commit`).

```bash
# Build it once
dotnet build samples/PqssCli -c Release

# 1) Make a 32-byte key and split it 3-of-5, dealer-signed
head -c 32 /dev/urandom > key.bin     # (any secret file works)
dotnet run --project samples/PqssCli -- split key.bin --k 3 --n 5 --out ./shares --sign --sk-out ./dealer.key

# 2) Inspect a share's metadata (never reveals the secret)
dotnet run --project samples/PqssCli -- inspect ./shares/share-2.pqss

# 3) Reconstruct from exactly three shares, verifying the pinned dealer key
dotnet run --project samples/PqssCli -- combine \
    ./shares/share-1.pqss ./shares/share-3.pqss ./shares/share-5.pqss \
    --out recovered.bin --pub ./shares/dealer.pub
```

```bash
# Protect a low-entropy passphrase safely with the wrap pattern, then recover it
echo -n 'correct horse battery staple' > pass.txt
dotnet run --project samples/PqssCli -- split pass.txt --k 2 --n 3 --out ./vault --wrap
dotnet run --project samples/PqssCli -- combine ./vault/share-1.pqss ./vault/share-2.pqss \
    --out pass.out --envelope ./vault/envelope.bin

# Rotate custody after a trustee departs (new splitId; old shares stop interoperating)
dotnet run --project samples/PqssCli -- refresh ./shares/share-1.pqss ./shares/share-3.pqss \
    ./shares/share-5.pqss --out ./shares-v2
```

Demonstrates: file-based split/inspect/combine/refresh, the wrap pattern, dealer
signing + pinning, one-time dealer commitments, friendly fail-closed error
reporting, and metadata inspection that exposes nothing secret.

Run `dotnet run --project samples/PqssCli -- --help` for full usage.

---

## 4. `VaultUnseal` — break-glass for a "sealed" service (net8.0)

An ecosystem-integration pattern: a service holds its sensitive configuration
(e.g. a production DB connection string) encrypted under a master key it does
**not** keep. On startup it is *sealed* — it has the ciphertext but cannot read
it. It becomes *unsealed* only when a quorum of operators presents their shares;
the master key is then reconstructed in memory, the config decrypted and used,
and the key wiped. Mirrors HashiCorp Vault's Shamir unseal, but with
information-theoretic secrecy below the quorum and no ML-DSA dependency.

```bash
dotnet run --project samples/VaultUnseal
```

Demonstrates: the wrap pattern applied to service config, a sealed/unsealed
lifecycle, exactly-`k` unseal, sub-quorum refusal, and key zeroization on re-seal.

---

## 5. `AspNetCoreDataProtection` — encrypt the DP key ring behind a quorum (net8.0)

A real framework integration. ASP.NET Core Data Protection encrypts its key ring
(the keys behind auth cookies, antiforgery tokens, etc.) **at rest** via a custom
`IXmlEncryptor`/`IXmlDecryptor`. Here the key-encryption key used for that at-rest
encryption is itself split with PostQuantum.SecretSharing: the app cannot read its
own key ring until a quorum of operators unseals the KEK. A stolen disk plus fewer
than `K` shares is inert.

```bash
dotnet run --project samples/AspNetCoreDataProtection
```

Demonstrates: a custom DP at-rest encryptor keyed by a quorum-reconstructed KEK,
key-ring encryption verified on disk, and recovery across a simulated restart by a
*different* quorum.
