using System.Security.Cryptography;

namespace PostQuantum.SecretSharing;

/// <summary>
/// The public facade for Shamir's Secret Sharing over GF(2⁸) with strict-CBOR
/// <c>.pqss</c> shares. Provides splitting (with or without dealer
/// authentication) and exactly-<c>k</c> reconstruction.
/// </summary>
public static class ShamirSecretSharing
{
    private const string CheckValueInfo = "PQSS-v1-check";

    /// <summary>
    /// Splits <paramref name="secret"/> into <c>policy.TotalShares</c> shares with
    /// threshold <c>policy.Threshold</c>, with no dealer authentication. Integrity
    /// rests on the HKDF check value embedded in each share.
    /// </summary>
    /// <exception cref="SharePolicyException">If the policy or secret length is out of range.</exception>
    public static SecretShare[] Split(ReadOnlySpan<byte> secret, SharePolicy policy)
        => SplitInternal(secret, policy, dealer: null);

    /// <summary>
    /// Splits <paramref name="secret"/> and authenticates every share with the
    /// given dealer: each share embeds the dealer public key and a signature over
    /// its canonical bytes (keys 0–10).
    /// </summary>
    /// <exception cref="SharePolicyException">If the policy or secret length is out of range.</exception>
    /// <exception cref="ArgumentNullException">If <paramref name="dealer"/> is null.</exception>
    public static SecretShare[] Split(ReadOnlySpan<byte> secret, SharePolicy policy, IShareAuthenticator dealer)
    {
        ArgumentNullException.ThrowIfNull(dealer);
        return SplitInternal(secret, policy, dealer);
    }

    private static SecretShare[] SplitInternal(ReadOnlySpan<byte> secret, SharePolicy policy, IShareAuthenticator? dealer)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ValidatePolicy(policy.Threshold, policy.TotalShares);
        ValidateSecretLength(secret.Length);

        int k = policy.Threshold;
        int n = policy.TotalShares;

        byte[] splitId = new byte[SecretShare.SplitIdLength];
        RandomNumberGenerator.Fill(splitId);

        // Integrity check value over the whole secret, salted by the split id.
        byte[] checkValue = ComputeCheckValue(secret, splitId);

        ShareAuthenticationKind kind = ShareAuthenticationKind.None;
        byte[] dealerPubKey = Array.Empty<byte>();
        if (dealer is not null)
        {
            if (dealer.Kind != ShareAuthenticationKind.MlDsa65)
                throw new SharePolicyException($"Unsupported authenticator kind {dealer.Kind}; v1 supports ML-DSA-65 only.");
            kind = dealer.Kind;
            dealerPubKey = dealer.PublicKey.ToArray();
            if (dealerPubKey.Length != SecretShare.MlDsa65PublicKeyLength)
                throw new SharePolicyException(
                    $"Dealer public key must be {SecretShare.MlDsa65PublicKeyLength} bytes for ML-DSA-65; got {dealerPubKey.Length}.");
        }

        byte[][] yRows = ShamirCore.Split(secret, k, n, RandomNumberGenerator.Fill);

        var shares = new SecretShare[n];
        for (int i = 0; i < n; i++)
        {
            int index = i + 1;
            byte[] y = yRows[i];

            byte[] signature = Array.Empty<byte>();
            if (dealer is not null)
            {
                byte[] payload = SecretShare.EncodeForSigning(
                    k, n, index, splitId, secret.Length, y, checkValue, kind, dealerPubKey);
                signature = dealer.Sign(payload);
                if (signature.Length != SecretShare.MlDsa65SignatureLength)
                    throw new SharePolicyException(
                        $"Dealer produced a {signature.Length}-byte signature; ML-DSA-65 signatures are {SecretShare.MlDsa65SignatureLength} bytes.");
            }

            shares[i] = new SecretShare(
                k, n, index, splitId, secret.Length, y, checkValue, kind, dealerPubKey, signature);
        }
        return shares;
    }

    /// <summary>
    /// Reconstructs the secret from exactly <c>k</c> shares.
    /// </summary>
    /// <param name="shares">
    /// Exactly <c>k</c> distinct shares from one split. Supplying more than <c>k</c>
    /// is rejected so operator errors are not silently masked by quietly choosing a
    /// subset.
    /// </param>
    /// <param name="expectedDealerPublicKey">
    /// If supplied, <b>every</b> share must be authenticated (authAlgorithm ≠ 0),
    /// carry exactly this key, and verify — otherwise
    /// <see cref="ShareAuthenticationException"/>. This is your <em>pin</em>: it is
    /// the only thing that proves the shares came from your dealer.
    /// <para>
    /// If null and the shares nonetheless carry signatures, those signatures are
    /// still verified against the <em>embedded</em> dealer key as defense in depth.
    /// <b>Be warned:</b> embedded-key-only verification is self-attestation, not
    /// authority — a forged share set can embed and sign with any key. Pass the pin
    /// to get a real authenticity guarantee.
    /// </para>
    /// </param>
    /// <returns>A <see cref="ZeroizingBuffer"/> holding the reconstructed secret.</returns>
    /// <exception cref="SharePolicyException">If the share count is not exactly k, or indices are out of range.</exception>
    /// <exception cref="ShareConsistencyException">If the shares cannot belong to one split, or the check value mismatches.</exception>
    /// <exception cref="ShareAuthenticationException">If authentication is required or present and fails.</exception>
    public static ZeroizingBuffer Reconstruct(
        IReadOnlyList<SecretShare> shares,
        ReadOnlyMemory<byte>? expectedDealerPublicKey = null)
    {
        ArgumentNullException.ThrowIfNull(shares);
        if (shares.Count == 0)
            throw new SharePolicyException("No shares supplied.");

        SecretShare first = shares[0]
            ?? throw new ShareConsistencyException("A supplied share was null.");
        int k = first.Threshold;

        // --- Pre-flight: exactly k shares ---
        if (shares.Count != k)
            throw new SharePolicyException(
                $"Reconstruction requires exactly k={k} shares; {shares.Count} were supplied. " +
                "Pick exactly the quorum — passing extra shares is rejected so operator errors are not masked.");

        // --- Pre-flight: consistent metadata across all shares ---
        var seenIndices = new HashSet<int>();
        for (int i = 0; i < shares.Count; i++)
        {
            SecretShare s = shares[i] ?? throw new ShareConsistencyException("A supplied share was null.");
            if (s.Threshold != first.Threshold || s.TotalShares != first.TotalShares ||
                s.SecretLength != first.SecretLength || s.Authentication != first.Authentication)
                throw new ShareConsistencyException(
                    "Shares disagree on (threshold, total, secretLength, authAlgorithm); they are not from one split.");
            if (!s.SplitIdSpan.SequenceEqual(first.SplitIdSpan))
                throw new ShareConsistencyException("Shares have differing split identifiers; they are not from one split.");
            if (s.Authentication != ShareAuthenticationKind.None &&
                !s.DealerPublicKey.Span.SequenceEqual(first.DealerPublicKey.Span))
                throw new ShareConsistencyException("Authenticated shares embed differing dealer public keys.");
            if (s.ShareIndex < 1 || s.ShareIndex > s.TotalShares)
                throw new SharePolicyException($"Share index {s.ShareIndex} is outside 1..{s.TotalShares}.");
            if (!seenIndices.Add(s.ShareIndex))
                throw new ShareConsistencyException($"Duplicate share index {s.ShareIndex}; reconstruction needs k distinct shares.");
        }

        // --- Authentication (before any field math) ---
        VerifyAuthentication(shares, first, expectedDealerPublicKey);

        // --- Interpolate into a pinned, zeroizing buffer ---
        int len = first.SecretLength;
        var xs = new byte[k];
        var ys = new byte[k][];
        var buffer = new ZeroizingBuffer(len);
        try
        {
            for (int i = 0; i < k; i++)
            {
                xs[i] = (byte)shares[i].ShareIndex;
                ys[i] = shares[i].ShareData.ToArray();
            }

            ShamirCore.Reconstruct(xs, ys, buffer.Span);

            // --- Check value: recompute and compare in constant time ---
            byte[] recomputed = ComputeCheckValue(buffer.Span, first.SplitIdSpan);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(recomputed, first.CheckValue))
                    throw new ShareConsistencyException(
                        "Reconstructed secret failed its integrity check. One or more shares are corrupt or " +
                        "do not belong to this split. In unauthenticated mode the specific bad share cannot be " +
                        "identified — use authenticated mode (a pinned dealer key) to pinpoint tampering.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(recomputed);
            }
            return buffer;
        }
        catch
        {
            // Never hand back a buffer that may hold a wrong/partial secret.
            buffer.Dispose();
            throw;
        }
        finally
        {
            foreach (byte[] y in ys)
            {
                if (y is not null)
                    CryptographicOperations.ZeroMemory(y);
            }
        }
    }

    /// <summary>
    /// Re-splits the secret into a brand-new set of shares (with a new
    /// <c>splitId</c>), so that shares from the previous split can no longer be
    /// combined with the new ones. Use this to rotate custody — e.g. when a
    /// trustee departs — without changing the underlying secret.
    /// </summary>
    /// <param name="shares">Exactly <c>k</c> shares of the current split.</param>
    /// <param name="newPolicy">The policy for the new split; defaults to the current <c>(k, n)</c>.</param>
    /// <param name="expectedDealerPublicKey">Optional pin verified against the <em>incoming</em> shares.</param>
    /// <param name="newDealer">If supplied, the <em>new</em> shares are authenticated by this dealer.</param>
    /// <remarks>
    /// <para>
    /// This is quorum-mediated refresh: the secret is briefly reconstructed in a
    /// <see cref="ZeroizingBuffer"/> (wiped before return) and re-split. It is not
    /// <em>proactive</em> secret sharing (which re-randomizes shares across parties
    /// without ever reconstructing) — that distributed protocol is out of scope.
    /// </para>
    /// <para>
    /// Because the secret is unchanged, old shares still reconstruct it among
    /// themselves. If you are rotating because a share may be compromised, rotate
    /// the underlying secret instead (see OPERATIONS.md, "revocation always
    /// rotates").
    /// </para>
    /// </remarks>
    public static SecretShare[] Refresh(
        IReadOnlyList<SecretShare> shares,
        SharePolicy? newPolicy = null,
        ReadOnlyMemory<byte>? expectedDealerPublicKey = null,
        IShareAuthenticator? newDealer = null)
    {
        ArgumentNullException.ThrowIfNull(shares);
        if (shares.Count == 0)
            throw new SharePolicyException("No shares supplied.");

        SecretShare first = shares[0] ?? throw new ShareConsistencyException("A supplied share was null.");
        SharePolicy policy = newPolicy ?? new SharePolicy(first.Threshold, first.TotalShares);

        using ZeroizingBuffer secret = Reconstruct(shares, expectedDealerPublicKey);
        return newDealer is null
            ? Split(secret.Span, policy)
            : Split(secret.Span, policy, newDealer);
    }

    private static void VerifyAuthentication(
        IReadOnlyList<SecretShare> shares, SecretShare first, ReadOnlyMemory<byte>? expectedDealerPublicKey)
    {
        bool pinned = expectedDealerPublicKey.HasValue;

        if (pinned)
        {
            ReadOnlySpan<byte> pin = expectedDealerPublicKey!.Value.Span;
            foreach (SecretShare s in shares)
            {
                if (s.Authentication == ShareAuthenticationKind.None)
                    throw new ShareAuthenticationException(
                        "A dealer public key was pinned but a share is unauthenticated (authAlgorithm = 0).");
                if (!s.DealerPublicKey.Span.SequenceEqual(pin))
                    throw new ShareAuthenticationException("A share's embedded dealer key does not match the pinned dealer key.");
            }
        }

        // Verify signatures whenever shares carry them (required when pinned;
        // defense-in-depth self-attestation otherwise).
        if (first.Authentication == ShareAuthenticationKind.None)
            return;

        foreach (SecretShare s in shares)
        {
            byte[] payload = s.GetSignedPayload();
            bool ok = ShareSignatureVerifier.Verify(s.Authentication, s.DealerPublicKey.Span, payload, s.Signature);
            if (!ok)
                throw new ShareAuthenticationException(
                    $"Signature verification failed for share index {s.ShareIndex}.");
        }
    }

    internal static byte[] ComputeCheckValue(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> splitId)
    {
        Span<byte> info = stackalloc byte[CheckValueInfo.Length];
        for (int i = 0; i < CheckValueInfo.Length; i++)
            info[i] = (byte)CheckValueInfo[i];

        byte[] output = new byte[SecretShare.CheckValueLength];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, output, salt: splitId, info: info);
        return output;
    }

    private static void ValidatePolicy(int k, int n)
    {
        if (k == 1)
            throw new SharePolicyException(
                "Threshold k=1 is forbidden: every share would equal the secret (security theater, not secret sharing).");
        if (k < 2 || k > 255)
            throw new SharePolicyException($"Threshold k must be in 2..255; got {k}.");
        if (n < k || n > 255)
            throw new SharePolicyException($"Total shares n must be in k..255; got n={n}, k={k}.");
    }

    private static void ValidateSecretLength(int length)
    {
        if (length < 1 || length > SecretShare.MaxSecretLength)
            throw new SharePolicyException($"Secret length must be in 1..{SecretShare.MaxSecretLength} bytes; got {length}.");
    }
}
