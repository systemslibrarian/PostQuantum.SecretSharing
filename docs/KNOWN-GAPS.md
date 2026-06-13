# Known Gaps

An honest, plainly-stated list of this package's limitations — including the ones
that make it look worse. "Carefully engineered" and "audited" are different
claims; this file is part of keeping that distinction honest.

## 1. No Verifiable Secret Sharing (malicious dealer)

v1 authenticates shares *against the dealer* but cannot detect a **malicious
dealer** who issues inconsistent shares to different trustees (so that different
quorums recover different secrets, or some quorums recover nothing). Defending
against this requires Verifiable Secret Sharing — Feldman or Pedersen VSS — which
is explicitly deferred to **v2**. If your threat model includes a dishonest
dealer, this package is not sufficient on its own.

## 2. Check-value oracle for low-entropy secrets

Every share embeds `splitId` and `checkValue = HKDF-SHA256(secret, splitId, …)`.
Anyone holding **one** share can therefore test guesses of the secret offline,
with no quorum. For a 32-byte random key this is a `2²⁵⁶` search and irrelevant.
For a passphrase, PIN, or any guessable secret, it is a practical brute-force
oracle. **Split keys, not passwords** — or use the built-in `WrappedSecret`
helper, which splits a random KEK and AES-256-GCM-wraps your real secret so the
oracle only ever sees a high-entropy KEK. (Note `DealerCommitment` is a hash of
the secret and carries the *same* oracle caveat — commit to high-entropy values.)

## 3. Memory page-locking is best-effort

`ZeroizingBuffer` pins its backing array on the pinned object heap (so the GC
cannot relocate and silently copy the secret), zeroes on dispose, and now
attempts to lock its pages into RAM (`VirtualLock`/`mlock`) to resist swap —
reporting success via `IsMemoryLocked`. This is **best-effort**: locking can fail
without privileges or when the per-process locked-memory limit is reached, in
which case the buffer still works but is not swap-protected. Locking does **not**
defend against a process memory dump, and the secret necessarily exists in
cleartext in process memory while in use.

## 4. Finalizer zeroization is best-effort

`ZeroizingBuffer` has a finalizer that zeroes the buffer if `Dispose` was never
called. This is a backstop, not a guarantee: the window between last use and
garbage collection is unbounded, and process termination may skip finalizers
entirely. **Always dispose** (`using`).

## 5. Refresh is quorum-mediated, not distributed-proactive

`ShamirSecretSharing.Refresh` rotates custody by re-splitting the secret into a
fresh set of shares with a new `splitId` (old shares no longer interoperate with
new ones). It is **quorum-mediated**: it briefly reconstructs the secret in a
`ZeroizingBuffer` and re-splits. It is *not* proactive secret sharing in the
academic sense — there is no distributed protocol that re-randomizes shares across
parties without ever reconstructing. Also note that, because `Refresh` keeps the
*same* secret, old shares still reconstruct it among themselves; if you are
rotating because a share may be compromised, rotate the underlying secret instead
(see OPERATIONS.md, "revocation always rotates").

## 6. CBOR parsing is not constant-time

The strict CBOR reader is not written to be constant-time. This is intentional
and safe: it parses the **public structure** of a share (lengths, types, field
order), not secret values. The secret-dependent arithmetic (GF field math) *is*
constant-time. Timing of the parser leaks only properties of public data.

## 7. No RNG injection (testability tradeoff)

The public API exposes no way to inject a random number generator; it always uses
`RandomNumberGenerator`. An injectable RNG in a secret-sharing library is a
foot-gun (a caller could supply a weak or replayed source and silently destroy
secrecy). Test determinism comes from published reference vectors and an
internal-only RNG hook exposed solely to the test project via
`InternalsVisibleTo`, never to consumers.

## 8. macOS lacks ML-DSA (upstream)

The `MlDsa65ShareAuthenticator` (net10.0) depends on the platform FIPS 204
backend. macOS does not provide it upstream, so the authenticator throws
`PlatformNotSupportedException` there. The **core** (split, reconstruct, `.pqss`,
check value, `ZeroizingBuffer`) runs on macOS fully — only the optional signing
layer does not. On Linux, ML-DSA requires OpenSSL ≥ 3.5.

## 9. Not independently audited

This package has not undergone an independent security audit. Treat it as a
well-built primitive pending review, not as audited software.
