# Supply-chain security

A cryptographic primitive is only as trustworthy as the pipeline that builds and
ships it. This document states, plainly, what protects the path from source to the
`.nupkg` you install — and how you can verify it yourself rather than take our word.

## What's in place

| Control | Mechanism | Why it matters |
|---|---|---|
| **Pinned build steps** | Every GitHub Actions step is pinned to a full commit **SHA** (with a `# vX.Y.Z` comment), not a mutable tag. | A moved tag can't silently swap build logic under you. |
| **Least-privilege CI** | Workflows default to `permissions: contents: read`; jobs widen only what they need (e.g. `attestations: write` only on `pack`). | Limits blast radius of a compromised step. |
| **Egress audit** | `step-security/harden-runner` (audit mode) on Linux jobs. | Surfaces unexpected network calls during a build. |
| **Build provenance (SLSA)** | `actions/attest-build-provenance` signs the `.nupkg` on push to `main`. | Cryptographic proof the package came from *this* repo's CI, not someone's laptop. |
| **SBOM** | CycloneDX SBOM (`bom.json`) generated and published with each build. | Machine-readable inventory for downstream scanners. |
| **Reproducible build** | A CI job builds the assemblies twice and fails if the bytes differ (deterministic + `ContinuousIntegrationBuild`). | Anyone can rebuild and get the same binary. |
| **Static analysis** | CodeQL (`security-and-quality`) on every push/PR + weekly. | Catches injected or accidental vulnerabilities. |
| **Scorecard** | OpenSSF Scorecard weekly, results published to code scanning + the public badge. | Continuous, independent scoring of these very controls. |
| **Dependency hygiene** | Dependabot (Actions + NuGet) and dependency-review on PRs. | Keeps pins current and blocks risky dependency changes. |
| **Banned APIs** | `BannedSymbols.txt` (weak RNG/hashes/ciphers) fails the build. | Crypto-hygiene regressions can't merge. |
| **Deterministic source** | SourceLink + embedded untracked sources in the package. | Debuggable back to the exact commit. |

The **core library ships with no runtime dependencies** — only build-time analyzers
and SourceLink — so the dependency attack surface a consumer inherits is essentially
just the .NET BCL.

## Verifying a release yourself

**Provenance.** Once a release `.nupkg` is published with an attestation, verify it
with the GitHub CLI:

```bash
gh attestation verify PostQuantum.SecretSharing.<version>.nupkg \
  --repo systemslibrarian/PostQuantum.SecretSharing
```

A pass means the artifact's SHA-256 was signed by this repository's CI via OIDC —
i.e. it was built by the workflow in this repo, not substituted.

**Reproducibility.** Rebuild from the tagged commit and compare:

```bash
git checkout v<version>
dotnet build src/PostQuantum.SecretSharing/PostQuantum.SecretSharing.csproj \
  -c Release -f net8.0 -p:ContinuousIntegrationBuild=true
sha256sum bin/Release/net8.0/PostQuantum.SecretSharing.dll
```

The hash should match the one printed by CI's **Reproducible build** job for that
commit.

## What this does *not* cover

- It does not replace an **independent security audit** of the cryptographic code
  (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §9). Supply-chain integrity proves you got
  *our* bytes faithfully; it says nothing about whether *our* bytes are correct.
- Provenance is only as good as the **pin you trust**: verify against the real
  repository, and for the dealer-authentication layer, pin the dealer key
  out-of-band (see the trust model in the README).
