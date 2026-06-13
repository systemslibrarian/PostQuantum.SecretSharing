using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

public class RoundTripTests
{
    public static IEnumerable<object[]> Matrix()
    {
        (int k, int n)[] policies = { (2, 2), (2, 3), (3, 5), (7, 10), (254, 255) };
        int[] lengths = { 1, 31, 32, 33, 1024, 65536 };
        foreach (var (k, n) in policies)
            foreach (int len in lengths)
            {
                // Skip only the combinatorially explosive cells (huge n*len*k) to
                // keep the suite fast; every policy and every length is still
                // covered by at least one cell.
                if ((long)n * len * k > 200_000_000)
                    continue;
                yield return new object[] { k, n, len };
            }
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void Split_Reconstruct_EveryKSubset_RoundTrips(int k, int n, int len)
    {
        byte[] secret = RandomNumberGenerator.GetBytes(len);
        SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(k, n));

        foreach (int[] subset in Subsets(n, k, cap: 50, seed: (k * 31 + n) * 131 + len))
        {
            // Reconstruct directly from the in-memory shares.
            SecretShare[] quorum = subset.Select(i => shares[i]).ToArray();
            using (ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum))
                Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));

            // Reconstruct after Export -> Import (byte-identical persistence).
            SecretShare[] reparsed = subset
                .Select(i => SecretShare.Import(shares[i].Export()))
                .ToArray();
            using (ZeroizingBuffer recovered2 = ShamirSecretSharing.Reconstruct(reparsed))
                Assert.True(secret.AsSpan().SequenceEqual(recovered2.Span));
        }
    }

    [Fact]
    public void Export_Then_Import_PreservesPublicMetadata()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(48);
        SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));

        foreach (SecretShare s in shares)
        {
            SecretShare r = SecretShare.Import(s.Export());
            Assert.Equal(s.Threshold, r.Threshold);
            Assert.Equal(s.TotalShares, r.TotalShares);
            Assert.Equal(s.ShareIndex, r.ShareIndex);
            Assert.Equal(s.SecretLength, r.SecretLength);
            Assert.Equal(s.Authentication, r.Authentication);
            Assert.True(s.SplitId.Span.SequenceEqual(r.SplitId.Span));
            // Re-export must be byte-identical (canonical round trip).
            Assert.Equal(s.Export(), r.Export());
        }
    }

    /// <summary>
    /// Yields up to <paramref name="cap"/> k-subsets of the indices 0..n-1. If the
    /// total number of subsets is small it enumerates all of them; otherwise it
    /// samples distinct random subsets with a fixed seed for determinism.
    /// </summary>
    private static IEnumerable<int[]> Subsets(int n, int k, int cap, int seed)
    {
        long total = Binomial(n, k);
        if (total <= cap)
            return AllCombinations(n, k);

        var rng = new Random(seed);
        var seen = new HashSet<string>();
        var result = new List<int[]>();
        int guard = 0;
        while (result.Count < cap && guard++ < cap * 50)
        {
            var pick = new SortedSet<int>();
            while (pick.Count < k)
                pick.Add(rng.Next(n));
            int[] arr = pick.ToArray();
            string key = string.Join(",", arr);
            if (seen.Add(key))
                result.Add(arr);
        }
        return result;
    }

    private static IEnumerable<int[]> AllCombinations(int n, int k)
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

    private static long Binomial(int n, int k)
    {
        if (k < 0 || k > n) return 0;
        k = Math.Min(k, n - k);
        long result = 1;
        for (int i = 0; i < k; i++)
        {
            result = result * (n - i) / (i + 1);
            if (result > 1_000_000) return result; // saturate; we only compare against small caps
        }
        return result;
    }
}
