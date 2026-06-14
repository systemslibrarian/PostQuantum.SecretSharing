using System.Security.Cryptography;

namespace PostQuantum.SecretSharing.Extensions;

/// <summary>
/// Distributed <b>proactive</b> secret sharing (Herzberg et al., 1995) for the GF(2⁸)
/// core shares: re-randomize a <c>K</c>-of-<c>N</c> sharing so that shares from an earlier
/// epoch become useless, <b>without ever reconstructing the secret</b>.
/// </summary>
/// <remarks>
/// <para>
/// Each participating party samples a fresh random degree-<c>(k-1)</c> polynomial per secret
/// byte with a <b>zero constant term</b>, and hands every other party that polynomial's value
/// at the other party's x-coordinate. Each party adds (XOR, in GF(2⁸)) the values it receives
/// to its own share. The shares now lie on a new polynomial <c>p' = p + Σ δᵢ</c>; because every
/// <c>δᵢ(0) = 0</c>, the secret <c>p'(0) = p(0)</c> is unchanged, yet the shares are completely
/// re-randomized. A <em>mobile</em> adversary who held fewer than <c>k</c> shares in the old
/// epoch learns nothing that helps in the new one.
/// </para>
/// <para>
/// <b>This differs from the core's <c>ShamirSecretSharing.Refresh</c>,</b> which is
/// quorum-mediated: it briefly reconstructs the secret in memory and re-splits. Proactive
/// refresh never forms the secret — not even on a single machine (see
/// <see cref="RefreshLocally"/>).
/// </para>
/// <para>
/// <b>Trust model (read <c>docs/PROACTIVE-REFRESH.md</c>).</b> This is the honest-but-curious
/// construction: it provides <em>secrecy</em> of the refresh against a minority adversary, but
/// does <b>not</b> by itself prove a contributor used a zero constant term. A malicious
/// contributor can therefore <em>corrupt</em> (not learn) the secret. Such corruption is
/// <b>detected</b> — the secret is unchanged, so the preserved check value fails at the next
/// reconstruction — at which point the round is rejected and the old shares are kept. All
/// parties must also agree on the <em>same</em> contributor set, or their refreshed shares will
/// be mutually inconsistent (also caught by the check value).
/// </para>
/// </remarks>
public static class ProactiveRefresh
{
    /// <summary>
    /// Produces one party's refresh contribution: a sub-share addressed to each recipient
    /// x-coordinate, being the value at that x of a fresh zero-constant-term degree-<c>(k-1)</c>
    /// polynomial (independent per secret byte). Deliver each sub-share point-to-point to its
    /// recipient over a confidential channel — do not broadcast them.
    /// </summary>
    /// <param name="contributorIndex">This party's own 1-based x-coordinate (1..255).</param>
    /// <param name="threshold">The threshold <c>k</c> of the sharing (2..255).</param>
    /// <param name="secretLength">The secret length in bytes (1..65536).</param>
    /// <param name="recipientIndices">The distinct 1-based x-coordinates that will hold refreshed shares.</param>
    /// <exception cref="SharePolicyException">If any index or <paramref name="threshold"/> is out of range.</exception>
    /// <exception cref="ArgumentException">If <paramref name="recipientIndices"/> is empty or has duplicates.</exception>
    public static IReadOnlyList<RefreshSubShare> CreateContribution(
        int contributorIndex, int threshold, int secretLength, IReadOnlyList<int> recipientIndices)
    {
        ArgumentNullException.ThrowIfNull(recipientIndices);
        if (contributorIndex < 1 || contributorIndex > 255)
            throw new SharePolicyException("contributorIndex must be in 1..255.");
        if (threshold < 2 || threshold > 255)
            throw new SharePolicyException("threshold must be in 2..255.");
        if (secretLength < 1 || secretLength > RefreshSubShare.MaxSecretLength)
            throw new SharePolicyException($"secretLength must be in 1..{RefreshSubShare.MaxSecretLength}.");
        if (recipientIndices.Count == 0)
            throw new ArgumentException("At least one recipient is required.", nameof(recipientIndices));

        var seen = new HashSet<int>();
        foreach (int j in recipientIndices)
        {
            if (j < 1 || j > 255)
                throw new SharePolicyException("Every recipient index must be in 1..255.");
            if (!seen.Add(j))
                throw new ArgumentException($"Duplicate recipient index {j}.", nameof(recipientIndices));
        }

        // (k-1) random coefficients per secret byte; the constant term is fixed to zero.
        // This material is sensitive for proactive security and is zeroized below.
        byte[] coeffs = RandomNumberGenerator.GetBytes((threshold - 1) * secretLength);
        try
        {
            var subShares = new List<RefreshSubShare>(recipientIndices.Count);
            foreach (int j in recipientIndices)
            {
                byte x = (byte)j;
                byte[] delta = new byte[secretLength];
                for (int b = 0; b < secretLength; b++)
                    delta[b] = EvalZeroConstPoly(coeffs, threshold, secretLength, b, x);
                subShares.Add(new RefreshSubShare(contributorIndex, j, threshold, delta));
            }
            return subShares;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(coeffs);
        }
    }

    /// <summary>
    /// Applies the contributions a party received to its own share, yielding the refreshed
    /// share for the new epoch. The secret is never reconstructed. The result keeps the same
    /// <c>splitId</c> and integrity check value (the secret is unchanged) and is, by
    /// construction, <b>dealer-unauthenticated</b> (a distributed refresh has no dealer).
    /// </summary>
    /// <param name="share">The party's current share.</param>
    /// <param name="subSharesForThisShare">
    /// One sub-share from each contributor in the agreed group, all addressed to
    /// <paramref name="share"/>'s index.
    /// </param>
    /// <exception cref="ShareConsistencyException">
    /// If a sub-share targets a different index, threshold, or secret length, or if a
    /// contributor appears twice.
    /// </exception>
    public static SecretShare Apply(SecretShare share, IReadOnlyList<RefreshSubShare> subSharesForThisShare)
    {
        ArgumentNullException.ThrowIfNull(share);
        ArgumentNullException.ThrowIfNull(subSharesForThisShare);
        if (subSharesForThisShare.Count == 0)
            throw new ShareConsistencyException("At least one contribution is required to refresh a share.");

        int len = share.SecretLength;
        byte[] newY = share.ShareData.ToArray();   // copy; never mutate the input share
        var contributors = new HashSet<int>();
        try
        {
            foreach (RefreshSubShare sub in subSharesForThisShare)
            {
                if (sub is null)
                    throw new ShareConsistencyException("A null sub-share was supplied.");
                if (sub.RecipientIndex != share.ShareIndex)
                    throw new ShareConsistencyException(
                        $"Sub-share is addressed to index {sub.RecipientIndex}, not this share's index {share.ShareIndex}.");
                if (sub.Threshold != share.Threshold)
                    throw new ShareConsistencyException("Sub-share threshold does not match the share's threshold.");
                if (sub.Delta.Length != len)
                    throw new ShareConsistencyException("Sub-share delta length does not match the secret length.");
                if (!contributors.Add(sub.ContributorIndex))
                    throw new ShareConsistencyException($"Contributor {sub.ContributorIndex} appears more than once.");

                ReadOnlySpan<byte> d = sub.Delta;
                for (int b = 0; b < len; b++)
                    newY[b] = Gf256.Add(newY[b], d[b]);   // GF(2⁸) add = XOR
            }

            return new SecretShare(
                share.Threshold, share.TotalShares, share.ShareIndex,
                share.SplitIdSpan.ToArray(), len, newY, share.CheckValue.ToArray(),
                ShareAuthenticationKind.None, Array.Empty<byte>(), Array.Empty<byte>());
        }
        catch
        {
            CryptographicOperations.ZeroMemory(newY);   // don't leak a half-updated share on failure
            throw;
        }
    }

    /// <summary>
    /// Convenience for a <em>co-located</em> set of shares (e.g. a trustee ceremony where the
    /// shares are briefly on one machine): runs the full multi-party refresh internally and
    /// returns the re-randomized share set — <b>still without ever reconstructing the
    /// secret</b>. Pass every share you want to remain mutually interoperable; shares not
    /// included keep the old epoch's polynomial and will no longer combine with the refreshed
    /// ones.
    /// </summary>
    /// <param name="shares">Shares from a single split (same <c>splitId</c>, <c>k</c>, <c>n</c>, length; distinct indices).</param>
    /// <exception cref="ShareConsistencyException">If the shares are not a consistent set from one split.</exception>
    public static SecretShare[] RefreshLocally(IReadOnlyList<SecretShare> shares)
    {
        ArgumentNullException.ThrowIfNull(shares);
        if (shares.Count == 0)
            throw new ShareConsistencyException("At least one share is required.");

        SecretShare first = shares[0] ?? throw new ShareConsistencyException("A null share was supplied.");
        int k = first.Threshold, n = first.TotalShares, len = first.SecretLength;
        var indices = new List<int>(shares.Count);
        var seenIndices = new HashSet<int>();

        foreach (SecretShare s in shares)
        {
            if (s is null)
                throw new ShareConsistencyException("A null share was supplied.");
            if (s.Threshold != k || s.TotalShares != n || s.SecretLength != len
                || !s.SplitIdSpan.SequenceEqual(first.SplitIdSpan))
                throw new ShareConsistencyException("Shares are not all from the same split.");
            if (!seenIndices.Add(s.ShareIndex))
                throw new ShareConsistencyException($"Duplicate share index {s.ShareIndex}.");
            indices.Add(s.ShareIndex);
        }

        // Every present party contributes a zero-sharing; every present party is a recipient.
        // Bucket the sub-shares by recipient, then apply.
        var inbox = new Dictionary<int, List<RefreshSubShare>>();
        foreach (int j in indices)
            inbox[j] = new List<RefreshSubShare>(indices.Count);

        var allSubShares = new List<RefreshSubShare>(indices.Count * indices.Count);
        foreach (int i in indices)
        {
            IReadOnlyList<RefreshSubShare> contribution = CreateContribution(i, k, len, indices);
            foreach (RefreshSubShare sub in contribution)
            {
                inbox[sub.RecipientIndex].Add(sub);
                allSubShares.Add(sub);
            }
        }

        try
        {
            var refreshed = new SecretShare[shares.Count];
            for (int idx = 0; idx < shares.Count; idx++)
                refreshed[idx] = Apply(shares[idx], inbox[shares[idx].ShareIndex]);
            return refreshed;
        }
        finally
        {
            // The transient update material is sensitive for proactive security; wipe it.
            foreach (RefreshSubShare sub in allSubShares)
                sub.ZeroizeDelta();
        }
    }

    // delta(x) = Σ_{t=1}^{k-1} c_t·xᵗ  with c_t = coeffs[(t-1)·len + b]  (constant term fixed to 0).
    // Factored Horner: delta(x) = x · ( c_{k-1}·x^{k-2} + … + c_1 ), all over GF(2⁸).
    private static byte EvalZeroConstPoly(ReadOnlySpan<byte> coeffs, int k, int len, int b, byte x)
    {
        byte acc = coeffs[(k - 2) * len + b];               // c_{k-1}
        for (int t = k - 2; t >= 1; t--)
            acc = Gf256.Add(Gf256.Mul(acc, x), coeffs[(t - 1) * len + b]);  // · x, + c_t
        return Gf256.Mul(acc, x);                            // the implicit x¹ factor (c_0 = 0)
    }
}
