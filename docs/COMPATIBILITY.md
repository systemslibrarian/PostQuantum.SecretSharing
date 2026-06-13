# Versioning & Compatibility Policy

Two things are versioned in this project, and they are **not** the same thing:

1. **The `.pqss` wire format** — what a share looks like on disk.
2. **The .NET API** — the public types and methods.

## The `.pqss` format

- The format carries an explicit `version` field (key 1). v1 shares declare
  `version = 1`.
- The v1 parser is **strict and closed**: it accepts only `version = 1` and
  rejects unknown fields, non-canonical encodings, and trailing bytes. This is by
  design — there are no silent extension points.
- The v1 format is **stable for the entire v1 line.** Shares written by any
  `1.x` release will be readable by any other `1.x` release, byte-for-byte
  canonical. The cross-implementation [test vectors](test-vectors.md) and the
  worked example in [SPEC.md](SPEC.md) pin this.
- A format change that is not backward-compatible will bump the format version
  (`version = 2`) and ship behind a new major library version. v1 readers will
  reject v2 shares with a clear `ShareFormatException` rather than mis-parsing
  them.

## The .NET API (Semantic Versioning)

Once `1.0.0` ships, the public API follows [SemVer](https://semver.org/):

- **MAJOR** — a breaking change to the public API or the `.pqss` format.
- **MINOR** — backward-compatible additions (new methods, new optional
  parameters, new helpers).
- **PATCH** — backward-compatible bug fixes.

Until `1.0.0`, the `1.0.0-rc.x` pre-releases may still adjust the public API in
response to review feedback; the `.pqss` **format**, however, is already treated
as v1-stable (see above).

### What counts as "public API"

Everything in the `PostQuantum.SecretSharing` namespace that is `public`. Types
marked `internal` (the field math, the CBOR codec, the Shamir engine) are
implementation details and may change at any time; they are exposed to the test
project only via `InternalsVisibleTo`.

## Target frameworks

- The library multi-targets `net8.0` and `net10.0`.
- The **core** (split, reconstruct, `.pqss`, check value, `ZeroizingBuffer`) is
  available on both, on all platforms.
- The **ML-DSA-65 authenticator** is `net10.0`-only and additionally requires a
  platform with FIPS 204 support at runtime (see the README platform matrix).
  Dropping or changing a target framework is a MAJOR change.

## Deprecation

Where feasible, public API slated for removal will be marked `[Obsolete]` for at
least one MINOR release before removal in the next MAJOR.

## Reporting

Security issues: see [SECURITY.md](../SECURITY.md). Behavioral or compatibility
bugs: open a GitHub issue with the offending share bytes (hex) where relevant —
never include real secret material.
