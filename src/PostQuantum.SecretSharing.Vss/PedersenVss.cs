using System.Security.Cryptography;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PostQuantum.SecretSharing.Vss.Internal;

namespace PostQuantum.SecretSharing.Vss;

/// <summary>
/// Pedersen Verifiable Secret Sharing over NIST P-256: a <c>K</c>-of-<c>N</c> split in
/// which every trustee can prove their share is consistent with a single committed
/// polynomial, defeating a <b>malicious dealer</b> who would otherwise hand out
/// inconsistent shares.
/// </summary>
/// <remarks>
/// <para>
/// <b>Secrecy is unconditional.</b> The commitments are perfectly hiding, so the
/// transcript reveals nothing about the secret — the information-theoretic,
/// post-quantum guarantee of the core library is preserved.
/// </para>
/// <para>
/// <b>Dealer-fraud detection is computational.</b> Commitment <em>binding</em> rests on
/// the discrete-log hardness of the group; a quantum adversary could in principle
/// equivocate. This is the one tradeoff of adding verifiability, documented here and in
/// <c>docs/VSS-DESIGN.md</c> §2 — exactly as the core documents its ML-DSA layer.
/// </para>
/// </remarks>
public static class PedersenVss
{
    /// <summary>
    /// Verifiably splits <paramref name="secret"/> into <c>policy.TotalShares</c> shares
    /// with threshold <c>policy.Threshold</c>, returning the shares and the public
    /// commitment broadcast to distribute alongside them.
    /// </summary>
    /// <exception cref="SharePolicyException">If the secret length is out of range.</exception>
    public static VssSplit Split(ReadOnlySpan<byte> secret, SharePolicy policy) =>
        Split(secret, policy, dealer: null);

    /// <summary>
    /// Verifiably splits <paramref name="secret"/> and, when <paramref name="dealer"/> is
    /// supplied, signs the commitment broadcast with the dealer's key (ML-DSA-65) so the
    /// pin itself is post-quantum dealer-authenticated. The signature binds the entire
    /// broadcast (group, <c>K</c>, <c>N</c>, <c>splitId</c>, secret length, and every
    /// commitment point), letting any trustee confirm the broadcast came from the pinned
    /// dealer and was not substituted. Verify it with
    /// <see cref="VssCommitments.VerifyDealerSignature(ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="secret">The secret bytes to split (1..65536 bytes).</param>
    /// <param name="policy">The threshold policy (<c>K</c>-of-<c>N</c>).</param>
    /// <param name="dealer">
    /// The dealer signer, or <see langword="null"/> for an unsigned broadcast (which must
    /// then be pinned out-of-band, exactly like the dealer key in v1).
    /// </param>
    /// <exception cref="SharePolicyException">If the secret length is out of range.</exception>
    /// <exception cref="ShareAuthenticationException">If <paramref name="dealer"/> is not an ML-DSA-65 signer.</exception>
    public static VssSplit Split(ReadOnlySpan<byte> secret, SharePolicy policy, IShareAuthenticator? dealer)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (secret.Length < 1 || secret.Length > Vss2Format.MaxSecretLength)
            throw new SharePolicyException($"Secret length must be 1..{Vss2Format.MaxSecretLength} bytes.");
        if (dealer is not null && dealer.Kind != ShareAuthenticationKind.MlDsa65)
            throw new ShareAuthenticationException(
                $"VSS dealer authentication supports only ML-DSA-65; got {dealer.Kind}.");

        int k = policy.Threshold;
        int n = policy.TotalShares;

        BigInteger[] elements = SecretChunking.ToElements(secret);
        int m = elements.Length;
        byte[] splitId = Secp256r1Group.RandomBytes(Vss2Format.SplitIdLength);

        // Per-chunk: a secret-carrying polynomial p, a blinding polynomial p', and the
        // commitments C_j = a_j·G + b_j·H to each coefficient pair.
        var aPoly = new BigInteger[m][];
        var bPoly = new BigInteger[m][];
        var commitments = new ECPoint[m][];
        for (int c = 0; c < m; c++)
        {
            var a = new BigInteger[k];
            var b = new BigInteger[k];
            a[0] = elements[c];                       // constant term = secret chunk
            b[0] = Secp256r1Group.RandomScalar();     // constant term = blinding
            for (int j = 1; j < k; j++)
            {
                a[j] = Secp256r1Group.RandomScalar();
                b[j] = Secp256r1Group.RandomScalar();
            }
            var cj = new ECPoint[k];
            for (int j = 0; j < k; j++)
                cj[j] = Secp256r1Group.Commit(a[j], b[j]);
            aPoly[c] = a;
            bPoly[c] = b;
            commitments[c] = cj;
        }

        var commitmentsData = new CommitmentsData(k, n, splitId, secret.Length, commitments);
        if (dealer is not null)
        {
            byte[] dealerKey = dealer.PublicKey.ToArray();
            byte[] payload = Vss2Format.EncodeCommitmentsSigningPayload(commitmentsData, dealerKey);
            byte[] signature = dealer.Sign(payload);
            commitmentsData = commitmentsData with
            {
                AuthKind = ShareAuthenticationKind.MlDsa65,
                DealerPublicKey = dealerKey,
                Signature = signature,
            };
        }
        var broadcast = new VssCommitments(commitmentsData, Vss2Format.EncodeCommitments(commitmentsData));

        var shares = new VssShare[n];
        for (int i = 1; i <= n; i++)
        {
            BigInteger x = BigInteger.ValueOf(i);
            var s = new BigInteger[m];
            var t = new BigInteger[m];
            for (int c = 0; c < m; c++)
            {
                s[c] = Secp256r1Group.Evaluate(aPoly[c], x);
                t[c] = Secp256r1Group.Evaluate(bPoly[c], x);
            }
            var data = new ShareData(k, n, i, splitId, secret.Length, s, t);
            shares[i - 1] = new VssShare(data, Vss2Format.EncodeShare(data));
        }

        return new VssSplit(shares, broadcast);
    }

    /// <summary>
    /// Reconstructs the secret from <b>exactly</b> <c>K</c> shares, re-verifying every
    /// share against <paramref name="commitments"/> first. Throws rather than returning a
    /// wrong secret if any share is inconsistent, from a different split, or duplicated.
    /// </summary>
    /// <exception cref="SharePolicyException">If the share count is not exactly <c>K</c>.</exception>
    /// <exception cref="ShareConsistencyException">If a share is null, mismatched, duplicated, or fails verification.</exception>
    public static ZeroizingBuffer Reconstruct(IReadOnlyList<VssShare> shares, VssCommitments commitments)
    {
        ArgumentNullException.ThrowIfNull(shares);
        ArgumentNullException.ThrowIfNull(commitments);

        CommitmentsData c = commitments.Data;
        int k = c.K;
        int m = c.Points.Length;
        if (shares.Count != k)
            throw new SharePolicyException($"Reconstruction requires exactly k = {k} shares; received {shares.Count}.");

        var seenIndices = new HashSet<int>();
        var xs = new BigInteger[k];
        var perChunkY = new BigInteger[m][];
        for (int ci = 0; ci < m; ci++)
            perChunkY[ci] = new BigInteger[k];

        for (int slot = 0; slot < k; slot++)
        {
            VssShare share = shares[slot] ?? throw new ShareConsistencyException("A null share was supplied.");
            ShareData s = share.Data;

            if (!c.SplitId.AsSpan().SequenceEqual(s.SplitId))
                throw new ShareConsistencyException("Shares are from different splits (splitId mismatch).");
            if (!seenIndices.Add(s.Index))
                throw new ShareConsistencyException($"Duplicate share index {s.Index}.");
            if (!share.Verify(commitments))
                throw new ShareConsistencyException(
                    $"Share {s.Index} does not verify against the commitments (inconsistent dealer or tampered share).");

            xs[slot] = BigInteger.ValueOf(s.Index);
            for (int ci = 0; ci < m; ci++)
                perChunkY[ci][slot] = s.S[ci];
        }

        var elements = new BigInteger[m];
        for (int ci = 0; ci < m; ci++)
            elements[ci] = Secp256r1Group.InterpolateAtZero(xs, perChunkY[ci]);

        byte[] secret = SecretChunking.FromElements(elements, c.SecretLength);
        var buffer = new ZeroizingBuffer(secret.Length);
        secret.CopyTo(buffer.Span);
        CryptographicOperations.ZeroMemory(secret);
        return buffer;
    }
}
