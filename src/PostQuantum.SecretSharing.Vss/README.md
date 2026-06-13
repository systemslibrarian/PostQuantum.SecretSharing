# PostQuantum.SecretSharing.Vss

**Opt-in Verifiable Secret Sharing (VSS) for
[PostQuantum.SecretSharing](https://www.nuget.org/packages/PostQuantum.SecretSharing).**
Detect a *malicious dealer* who hands inconsistent shares to different trustees, so
every quorum is guaranteed to reconstruct the same secret.

> **Preview, unaudited new cryptography.** Ships as `2.0.0-preview`. See the honest
> tradeoff below and `docs/VSS-DESIGN.md` in the repository.

## Why this is a separate package

The core `PostQuantum.SecretSharing` library is **dependency-free** and its secrecy is
**information-theoretic / post-quantum**. VSS needs a prime-order group (NIST P-256 via
a vetted EC dependency), so it lives here — you *opt in* to that dependency and to one
specific tradeoff:

- **Secrecy stays unconditional.** Pedersen commitments are *perfectly hiding*: the
  commitment transcript reveals nothing about the secret, against any adversary,
  including a quantum one. The headline guarantee is untouched.
- **Malicious-dealer *detection* is computational.** Commitment *binding* rests on
  discrete-log hardness. A quantum *dealer* could defeat the consistency check — not
  the secrecy. We document this exactly the way the core documents its ML-DSA layer.

## Status

Design-complete; implementation in progress. The public API and `.pqss v2` wire format
are specified in `docs/VSS-DESIGN.md` and will be pinned with test vectors before the
preview is published.
