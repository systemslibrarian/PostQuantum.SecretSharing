# PostQuantum.SecretSharing — API documentation

Generated reference for the public API surface. For motivation, the trust model,
operational guidance, and worked examples, start with the
[README](https://github.com/systemslibrarian/PostQuantum.SecretSharing#readme).

## Start here

- **[API Reference](api/)** — every public type and member.
- [`ShamirSecretSharing`](api/PostQuantum.SecretSharing.ShamirSecretSharing.html) — split, reconstruct, refresh.
- [`SecretShare`](api/PostQuantum.SecretSharing.SecretShare.html) — the `.pqss` share (export/import).
- [`WrappedSecret`](api/PostQuantum.SecretSharing.WrappedSecret.html) — the low-entropy wrap pattern.
- [`ZeroizingBuffer`](api/PostQuantum.SecretSharing.ZeroizingBuffer.html) — pinned, zeroizing secret memory.

## Key documents

- [Specification](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/SPEC.md) — byte-level `.pqss` format.
- [Threat model](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/THREAT-MODEL.md)
- [Known gaps](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/KNOWN-GAPS.md)
- [Supply chain](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/SUPPLY-CHAIN.md)

> This is a carefully engineered, **not yet independently audited** primitive. Treat
> it accordingly — see Known gaps.
