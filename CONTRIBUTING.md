# Contributing

Thanks for looking. This is a small, security-sensitive primitive, so the bar for
changes is deliberately high and most of that bar is **mechanically enforced** —
the build fails rather than relying on reviewer vigilance.

## Build & test

```bash
dotnet build PostQuantum.SecretSharing.sln -c Release
dotnet test  PostQuantum.SecretSharing.sln -c Release -f net8.0  --filter "Category!=bench&Category!=timing"
dotnet test  PostQuantum.SecretSharing.sln -c Release -f net10.0 --filter "Category!=bench&Category!=timing"
```

`TreatWarningsAsErrors` is on. A warning is a failure.

## Gates you will hit (and how to satisfy them)

### 1. Formatting

```bash
dotnet format PostQuantum.SecretSharing.sln          # fix
dotnet format PostQuantum.SecretSharing.sln --verify-no-changes   # what CI checks
```

### 2. Public API lock (`Microsoft.CodeAnalysis.PublicApiAnalyzers`)

Every public symbol must be declared in
[`src/PostQuantum.SecretSharing/PublicAPI.Shipped.txt`](src/PostQuantum.SecretSharing/PublicAPI.Shipped.txt)
or `PublicAPI.Unshipped.txt`. Adding, removing, or changing a public member without
updating those files is a build error (`RS0016`/`RS0017`). This is intentional: a
public-surface change should be a visible, reviewable diff, and it backs the
"no public-API churn during the RC period" gate in [`ROADMAP.md`](ROADMAP.md).

- **net8.0** surface lives in the root `PublicAPI.*.txt`.
- **net10.0**-only surface (the ML-DSA-65 authenticator) lives in
  `PublicApi/net10.0/PublicAPI.Unshipped.txt`.

To regenerate after an intentional API change, let the analyzer's code fix write the
lines for you:

```bash
dotnet format analyzers src/PostQuantum.SecretSharing/PostQuantum.SecretSharing.csproj \
  --diagnostics RS0016 --severity info
```

**At release time**, move everything from `PublicAPI.Unshipped.txt` into
`PublicAPI.Shipped.txt` (keep the `#nullable enable` header on each). After the first
NuGet publish, set `PackageValidationBaselineVersion` in the `.csproj` so
[package validation](https://learn.microsoft.com/dotnet/fundamentals/apicompat/package-validation/overview)
also diffs against the last shipped `.nupkg`.

### 3. Banned APIs (`Microsoft.CodeAnalysis.BannedApiAnalyzers`)

[`src/PostQuantum.SecretSharing/BannedSymbols.txt`](src/PostQuantum.SecretSharing/BannedSymbols.txt)
makes the project's crypto hygiene a compile error: no `System.Random`, no weak
hashes (MD5/SHA-1), no legacy ciphers (DES/3DES/RC2). If you have a legitimate need
to touch one of these, that is a discussion to have in the PR, not a line to quietly
delete.

## What a good PR looks like

- A focused change with tests. New behavior ships with test vectors or property tests,
  not just example-based tests.
- Honest docs. If a change has a limitation, it goes in
  [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) — we do not gloss.
- No new dependencies in the core library without a strong reason; the core is
  deliberately dependency-free apart from SourceLink/analyzers (build-only).

## Security issues

Please do **not** open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).
