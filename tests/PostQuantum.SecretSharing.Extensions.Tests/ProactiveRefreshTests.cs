using System.Security.Cryptography;
using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Extensions;
using Xunit;

namespace PostQuantum.SecretSharing.Extensions.Tests;

/// <summary>
/// Proactive refresh re-randomizes a K-of-N sharing without ever reconstructing the secret:
/// the secret is preserved, every quorum still agrees, old-epoch shares no longer combine
/// with refreshed ones, and the distributed sub-share protocol matches the local helper.
/// </summary>
public class ProactiveRefreshTests
{
    private static byte[] RandomSecret(int len)
    {
        byte[] s = new byte[len];
        RandomNumberGenerator.Fill(s);
        return s;
    }

    private static byte[] Reconstruct(IEnumerable<SecretShare> shares)
    {
        using ZeroizingBuffer b = ShamirSecretSharing.Reconstruct(shares.ToArray());
        return b.Span.ToArray();
    }

    [Theory]
    [InlineData(2, 3, 1)]
    [InlineData(3, 5, 16)]
    [InlineData(3, 5, 32)]
    [InlineData(5, 9, 64)]
    [InlineData(2, 2, 100)]
    public void RefreshLocally_preserves_the_secret_for_every_quorum(int k, int n, int len)
    {
        byte[] secret = RandomSecret(len);
        SecretShare[] original = ShamirSecretSharing.Split(secret, new SharePolicy(k, n));

        SecretShare[] refreshed = ProactiveRefresh.RefreshLocally(original);

        Assert.Equal(n, refreshed.Length);
        // Every k-subset of refreshed shares reconstructs the original secret.
        foreach (int[] combo in Combinations(n, k))
        {
            byte[] recovered = Reconstruct(combo.Select(i => refreshed[i]));
            Assert.Equal(secret, recovered);
        }
    }

    [Fact]
    public void Refresh_actually_rerandomizes_the_share_bytes()
    {
        byte[] secret = RandomSecret(32);
        SecretShare[] original = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));
        SecretShare[] refreshed = ProactiveRefresh.RefreshLocally(original);

        // Same index/splitId, but the exported bytes must differ (new polynomial).
        for (int i = 0; i < original.Length; i++)
        {
            Assert.Equal(original[i].ShareIndex, refreshed[i].ShareIndex);
            Assert.True(original[i].SplitId.Span.SequenceEqual(refreshed[i].SplitId.Span));
            Assert.False(original[i].Export().AsSpan().SequenceEqual(refreshed[i].Export()));
        }
    }

    [Fact]
    public void Mixing_old_and_refreshed_shares_is_caught_by_the_check_value()
    {
        byte[] secret = RandomSecret(32);
        SecretShare[] original = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));
        SecretShare[] refreshed = ProactiveRefresh.RefreshLocally(original);

        // One old + two new shares lie on different polynomials → wrong value → check value fails.
        Assert.Throws<ShareConsistencyException>(() =>
            Reconstruct(new[] { original[0], refreshed[1], refreshed[2] }));
    }

    [Fact]
    public void Refreshed_share_is_dealer_unauthenticated()
    {
        SecretShare[] original = ShamirSecretSharing.Split(RandomSecret(16), new SharePolicy(2, 3));
        SecretShare[] refreshed = ProactiveRefresh.RefreshLocally(original);
        Assert.All(refreshed, s => Assert.Equal(ShareAuthenticationKind.None, s.Authentication));
    }

    [Fact]
    public void Repeated_refresh_still_preserves_the_secret()
    {
        byte[] secret = RandomSecret(48);
        SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));
        for (int round = 0; round < 4; round++)
            shares = ProactiveRefresh.RefreshLocally(shares);
        Assert.Equal(secret, Reconstruct(shares.Take(3)));
    }

    [Fact]
    public void Distributed_protocol_matches_the_local_helper()
    {
        byte[] secret = RandomSecret(40);
        SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));
        int[] indices = shares.Select(s => s.ShareIndex).ToArray();

        // Each party publishes a contribution; each recipient collects the sub-shares
        // addressed to it (routed via Export/Import, as on a real wire) and applies them.
        var inbox = indices.ToDictionary(i => i, _ => new List<RefreshSubShare>());
        foreach (int i in indices)
            foreach (RefreshSubShare sub in ProactiveRefresh.CreateContribution(i, 3, secret.Length, indices))
                inbox[sub.RecipientIndex].Add(RefreshSubShare.Import(sub.Export()));

        SecretShare[] refreshed = shares
            .Select(s => ProactiveRefresh.Apply(s, inbox[s.ShareIndex]))
            .ToArray();

        Assert.Equal(secret, Reconstruct(refreshed.Take(3)));
        // And a partial quorum of the old epoch cannot combine with the new one.
        Assert.Throws<ShareConsistencyException>(() =>
            Reconstruct(new[] { shares[0], refreshed[1], refreshed[2] }));
    }

    [Fact]
    public void Apply_rejects_misaddressed_duplicate_or_mismatched_subshares()
    {
        SecretShare[] shares = ShamirSecretSharing.Split(RandomSecret(16), new SharePolicy(2, 3));
        int[] indices = shares.Select(s => s.ShareIndex).ToArray();
        SecretShare target = shares[0];

        var forIndex1 = ProactiveRefresh.CreateContribution(1, 2, 16, indices).First(s => s.RecipientIndex == target.ShareIndex);
        var forIndex2 = ProactiveRefresh.CreateContribution(1, 2, 16, indices).First(s => s.RecipientIndex != target.ShareIndex);

        // Sub-share addressed to a different recipient.
        Assert.Throws<ShareConsistencyException>(() => ProactiveRefresh.Apply(target, new[] { forIndex2 }));
        // Same contributor twice.
        var dupA = ProactiveRefresh.CreateContribution(7, 2, 16, indices).First(s => s.RecipientIndex == target.ShareIndex);
        var dupB = ProactiveRefresh.CreateContribution(7, 2, 16, indices).First(s => s.RecipientIndex == target.ShareIndex);
        Assert.Throws<ShareConsistencyException>(() => ProactiveRefresh.Apply(target, new[] { dupA, dupB }));
        // Empty contribution set.
        Assert.Throws<ShareConsistencyException>(() => ProactiveRefresh.Apply(target, Array.Empty<RefreshSubShare>()));
    }

    [Fact]
    public void CreateContribution_validates_its_arguments()
    {
        Assert.Throws<SharePolicyException>(() => ProactiveRefresh.CreateContribution(0, 2, 8, new[] { 1, 2 }));
        Assert.Throws<SharePolicyException>(() => ProactiveRefresh.CreateContribution(1, 1, 8, new[] { 1, 2 }));
        Assert.Throws<SharePolicyException>(() => ProactiveRefresh.CreateContribution(1, 2, 0, new[] { 1, 2 }));
        Assert.Throws<ArgumentException>(() => ProactiveRefresh.CreateContribution(1, 2, 8, Array.Empty<int>()));
        Assert.Throws<ArgumentException>(() => ProactiveRefresh.CreateContribution(1, 2, 8, new[] { 1, 1 }));
    }

    [Fact]
    public void RefreshLocally_rejects_inconsistent_share_sets()
    {
        SecretShare[] a = ShamirSecretSharing.Split(RandomSecret(16), new SharePolicy(2, 3));
        SecretShare[] b = ShamirSecretSharing.Split(RandomSecret(16), new SharePolicy(2, 3));
        // Shares from two different splits.
        Assert.Throws<ShareConsistencyException>(() => ProactiveRefresh.RefreshLocally(new[] { a[0], b[1] }));
        // Duplicate index.
        Assert.Throws<ShareConsistencyException>(() => ProactiveRefresh.RefreshLocally(new[] { a[0], a[0] }));
        Assert.Throws<ShareConsistencyException>(() => ProactiveRefresh.RefreshLocally(Array.Empty<SecretShare>()));
    }

    [Fact]
    public void SubShare_round_trips_and_parses_fail_closed()
    {
        var sub = ProactiveRefresh.CreateContribution(1, 3, 32, new[] { 1, 2, 3 })[0];
        byte[] bytes = sub.Export();
        Assert.Equal(bytes, RefreshSubShare.Import(bytes).Export());

        Assert.ThrowsAny<SecretSharingException>(() => RefreshSubShare.Import(Array.Empty<byte>()));
        Assert.ThrowsAny<SecretSharingException>(() => RefreshSubShare.Import(bytes.AsSpan(0, bytes.Length - 1).ToArray()));
        byte[] withTail = new byte[bytes.Length + 1];
        bytes.CopyTo(withTail, 0);
        Assert.ThrowsAny<SecretSharingException>(() => RefreshSubShare.Import(withTail));
    }

    private static IEnumerable<int[]> Combinations(int n, int k)
    {
        int[] idx = Enumerable.Range(0, k).ToArray();
        while (true)
        {
            yield return (int[])idx.Clone();
            int i = k - 1;
            while (i >= 0 && idx[i] == n - k + i) i--;
            if (i < 0) yield break;
            idx[i]++;
            for (int j = i + 1; j < k; j++) idx[j] = idx[j - 1] + 1;
        }
    }
}
