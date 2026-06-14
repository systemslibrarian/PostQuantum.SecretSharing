# PostQuantum.SecretSharing.Extensions

**Opt-in higher-level ceremony helpers for
[PostQuantum.SecretSharing](https://www.nuget.org/packages/PostQuantum.SecretSharing).**
Like the core, this package has **no third-party runtime dependency**.

The first helper is **distributed proactive secret sharing**: re-randomize a `K`-of-`N`
sharing so that shares from an earlier epoch become useless — **without ever reconstructing
the secret**. This defeats a *mobile* adversary that compromises different trustees over
time, and unlike the core's `Refresh` (which briefly reconstructs and re-splits), the secret
is never formed in memory.

## Re-randomize without reconstructing (co-located)

```csharp
using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Extensions;

SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));

// New epoch: shares are re-randomized; the secret never appears in memory.
SecretShare[] refreshed = ProactiveRefresh.RefreshLocally(shares);

// Old shares no longer combine with new ones; any 3 refreshed shares still recover the secret.
```

## Distributed protocol (multi-party, no trusted machine)

```csharp
int[] parties = shares.Select(s => s.ShareIndex).ToArray();

// 1. Each party publishes a contribution (one sub-share per recipient) and delivers each
//    sub-share point-to-point — NOT broadcast.
IReadOnlyList<RefreshSubShare> mine = ProactiveRefresh.CreateContribution(
    contributorIndex: myIndex, threshold: 3, secretLength: secret.Length, recipientIndices: parties);

// 2. Each party applies the sub-shares addressed to it, yielding its refreshed share.
SecretShare refreshedMine = ProactiveRefresh.Apply(myShare, subSharesAddressedToMe);
```

## The honest tradeoff

This is the **honest-but-curious** construction:

- **Secrecy is preserved** against a minority adversary, and the secret is never
  reconstructed.
- It does **not** prove a contributor used a zero constant term, so a *malicious* contributor
  could **corrupt** (never *learn*) the secret. Corruption is **detected**: the secret is
  unchanged, so the preserved check value fails at the next reconstruction — reject the round
  and keep the old shares.

Full design, protocol, and limitations:
[docs/PROACTIVE-REFRESH.md](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/PROACTIVE-REFRESH.md).

## Documentation

- [Proactive refresh design & threat model](https://github.com/systemslibrarian/PostQuantum.SecretSharing/blob/main/docs/PROACTIVE-REFRESH.md)
- [Core library](https://www.nuget.org/packages/PostQuantum.SecretSharing)
- [Repository](https://github.com/systemslibrarian/PostQuantum.SecretSharing)
