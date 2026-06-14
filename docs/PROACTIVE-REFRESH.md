# Design: Distributed Proactive Secret Sharing

> **Status: implemented.** Realised in the opt-in `PostQuantum.SecretSharing.Extensions`
> package; the GF(2⁸) core is **not** modified. Code:
> `src/PostQuantum.SecretSharing.Extensions/`. Tests:
> `tests/PostQuantum.SecretSharing.Extensions.Tests/`.

## 1. Problem

A `K`-of-`N` Shamir sharing is static: the same share sits with the same trustee forever.
Against a **mobile adversary** — one that compromises different trustees over time — this is
dangerous. If the adversary captures `j < K` shares in year one and `K − j` more in year
three, it can reconstruct, even though it never held `K` shares *simultaneously*.

The defence is **proactive secret sharing** (Herzberg, Jarecki, Krawczyk, Yung, CRYPTO '95):
periodically **re-randomize** every share so that shares from different epochs are
useless together. An adversary must now compromise `K` trustees *within a single epoch*.

The core ships `ShamirSecretSharing.Refresh`, but it is **quorum-mediated**: it briefly
reconstructs the secret in a `ZeroizingBuffer` and re-splits (see
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) §5). That momentary reconstruction is exactly what a
distributed protocol should avoid.

**Goal:** re-randomize the shares **without ever reconstructing the secret** — not even on
one machine.

## 2. Construction

Shamir shares are points on per-byte polynomials `p_b` with `p_b(0) = secret[b]`. Party `i`
holds `y_i[b] = p_b(i)` (x-coordinate `i = ShareIndex`).

A proactive refresh round:

1. **Contribute.** Each participating party `i` samples, for every secret byte `b`, a fresh
   random degree-`(K−1)` polynomial `δ_{i,b}` with **constant term zero**
   (`δ_{i,b}(0) = 0`). It computes the value `δ_{i,b}(j)` for every recipient `j` and sends
   it to `j` — point-to-point.
2. **Apply.** Each recipient `j` sums (XOR, in GF(2⁸)) the values it received into its own
   share: `y'_j[b] = y_j[b] ⊕ Σ_i δ_{i,b}(j)`.

The shares now lie on `p'_b = p_b + Σ_i δ_{i,b}`. Each `δ_{i,b}` has degree `≤ K−1` and a
zero constant term, so `p'_b` still has degree `≤ K−1` and `p'_b(0) = p_b(0) = secret[b]`.
**The secret is unchanged; the shares are completely re-randomized; the secret never
appeared.**

Because the secret is unchanged, the original `splitId` and `checkValue =
HKDF(secret, splitId)` remain valid — so a refreshed share is a normal, reconstructable
`.pqss` v1 share. (See [`SPEC.md`](SPEC.md).)

## 3. API

```csharp
namespace PostQuantum.SecretSharing.Extensions;

public static class ProactiveRefresh
{
    // Distributed (multi-party) protocol:
    public static IReadOnlyList<RefreshSubShare> CreateContribution(
        int contributorIndex, int threshold, int secretLength, IReadOnlyList<int> recipientIndices);
    public static SecretShare Apply(SecretShare share, IReadOnlyList<RefreshSubShare> subSharesForThisShare);

    // Co-located convenience — runs the whole protocol in-process, still without reconstructing:
    public static SecretShare[] RefreshLocally(IReadOnlyList<SecretShare> shares);
}

public sealed class RefreshSubShare   // one addressed update; deliver point-to-point
{
    public int ContributorIndex { get; }
    public int RecipientIndex { get; }
    public int Threshold { get; }
    public byte[] Export();
    public static RefreshSubShare Import(ReadOnlySpan<byte> bytes);
}
```

`RefreshLocally` is for a trustee ceremony where the shares are briefly on one machine: it
re-randomizes them **without forming the secret**, a strict improvement over the core's
quorum-mediated `Refresh`. The distributed two-step API is for the real multi-party case.

## 4. Trust model and honest limitations

This is the **honest-but-curious** construction. Be precise about what it does and doesn't
guarantee:

1. **Secrecy of the refresh (provided).** Against an adversary controlling a minority of
   parties, the update polynomials hide which old share maps to which new share. A mobile
   adversary holding `< K` shares in the old epoch learns nothing useful in the new one.
   Each `δ` is independent of the secret, so the protocol leaks nothing about the secret.
2. **No proof of a zero constant term (the limitation).** A *malicious* contributor could
   use a non-zero constant term (corrupting the secret) or send inconsistent sub-shares.
   This library does **not** prove `δ(0) = 0`. Doing so requires verifiable proactive secret
   sharing — commitments in a prime-order group — which is a different field from the GF(2⁸)
   core and would belong with the [VSS](VSS-DESIGN.md) scheme, not here.
3. **Corruption is detected, not prevented.** Because the secret is unchanged, the preserved
   `checkValue` still describes it. After a round, **reconstruct once with any quorum**: if a
   contributor cheated, the check value fails (`ShareConsistencyException`) — reject the round
   and keep the old shares. So a malicious contributor can cause a *detected* denial of
   service, never a silent wrong secret and never a secret leak.
4. **All parties must agree on the same contributor set.** If different recipients apply
   different sets of contributions, their refreshed shares lie on different polynomials.
   This too is caught by the check value at the next reconstruction.
5. **Point-to-point delivery is required.** Sub-shares must reach only their intended
   recipient over a confidential channel. Broadcasting them would let an adversary learn the
   whole update and link shares across epochs, defeating proactive security. The sub-shares
   are not secret *about the secret*, but they are secret *for proactive security*.
6. **Refreshed shares are dealer-unauthenticated.** A distributed refresh has no dealer, so
   the result carries `authAlgorithm = 0`. Integrity still rests on the check value.
7. **Refresh the full interoperable set.** Shares you don't include keep the old epoch's
   polynomial and will no longer combine with refreshed ones.

## 5. Evidence

- `ProactiveRefreshTests`: secret preserved for **every** `K`-subset across a `k/n/length`
  matrix; shares genuinely re-randomized; old+new mixing rejected by the check value; the
  distributed `CreateContribution`/`Apply` path (routed through `Export`/`Import`) matches
  `RefreshLocally`; repeated rounds; argument and consistency validation; fail-closed
  sub-share parsing.
- The construction never calls any reconstruction routine — verify by inspection of
  `ProactiveRefresh.cs` (there is no path that forms the secret).

## 6. Relationship to the rest of the project

| | Core `Refresh` | Proactive `RefreshLocally` / distributed |
|--|--|--|
| Reconstructs the secret? | Yes (briefly, in a `ZeroizingBuffer`) | **No** |
| Multi-party, no trusted machine? | No | **Yes** (distributed API) |
| Detects a cheating participant? | n/a (single operator) | Yes, via the check value (after the fact) |
| Dependency | none (core) | none (Extensions composes the core) |

Verifiable proactive refresh (preventing, not just detecting, a malicious contributor) is a
natural future step and would build on the [VSS](VSS-DESIGN.md) prime-order machinery.
