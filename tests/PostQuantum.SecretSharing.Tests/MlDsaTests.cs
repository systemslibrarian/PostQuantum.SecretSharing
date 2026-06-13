#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// ML-DSA-65 authentication tests. They run only on net10.0 and skip at runtime
/// where FIPS 204 is unavailable (e.g. macOS), proving the core suite passes
/// everywhere while the optional signing layer is exercised where supported.
/// </summary>
public class MlDsaTests
{
    private static byte[] Secret => Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    [SkippableFact]
    public void AuthenticatedSplit_Reconstruct_WithPin_Succeeds()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] shares = ShamirSecretSharing.Split(Secret, new SharePolicy(3, 5), dealer);

        Assert.All(shares, s => Assert.Equal(ShareAuthenticationKind.MlDsa65, s.Authentication));

        SecretShare[] quorum = { shares[0], shares[2], shares[4] };
        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum, dealer.PublicKey);
        Assert.True(Secret.AsSpan().SequenceEqual(recovered.Span));
    }

    [SkippableFact]
    public void Authenticated_ExportImport_RoundTrips()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] shares = ShamirSecretSharing.Split(Secret, new SharePolicy(2, 3), dealer);

        SecretShare[] quorum =
        {
            SecretShare.Import(shares[0].Export()),
            SecretShare.Import(shares[1].Export()),
        };
        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(quorum, dealer.PublicKey);
        Assert.True(Secret.AsSpan().SequenceEqual(recovered.Span));
    }

    [SkippableFact]
    public void WrongPinnedKey_Rejected()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        using var other = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] shares = ShamirSecretSharing.Split(Secret, new SharePolicy(2, 3), dealer);

        Assert.Throws<ShareAuthenticationException>(
            () => ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[1] }, other.PublicKey));
    }

    [SkippableFact]
    public void TamperedShareData_FailsSignatureVerification()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] shares = ShamirSecretSharing.Split(Secret, new SharePolicy(2, 3), dealer);

        SecretShare tampered = TamperShareData(shares[1]);
        Assert.Throws<ShareAuthenticationException>(
            () => ShamirSecretSharing.Reconstruct(new[] { shares[0], tampered }, dealer.PublicKey));
    }

    [SkippableFact]
    public void TamperedSignature_FailsVerification_EvenWithoutPin()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] shares = ShamirSecretSharing.Split(Secret, new SharePolicy(2, 3), dealer);

        // Flip a signature bit; embedded-key verification (defense in depth) must still fail.
        byte[] badSig = shares[1].Signature.ToArray();
        badSig[0] ^= 0x01;
        SecretShare tampered = new(
            shares[1].Threshold, shares[1].TotalShares, shares[1].ShareIndex, shares[1].SplitId.ToArray(),
            shares[1].SecretLength, shares[1].ShareData.ToArray(), shares[1].CheckValue.ToArray(),
            shares[1].Authentication, shares[1].DealerPublicKey.ToArray(), badSig);

        Assert.Throws<ShareAuthenticationException>(
            () => ShamirSecretSharing.Reconstruct(new[] { shares[0], tampered }));
    }

    [SkippableFact]
    public void ForgedShare_EmbeddingPinnedKey_ButSignedByForeignDealer_Rejected()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] good = ShamirSecretSharing.Split(Secret, new SharePolicy(2, 3), dealer);

        // The realistic forgery: an attacker without the dealer's private key embeds
        // the (pinned) real dealer public key so the share passes the consistency
        // check, but cannot produce a valid signature — they sign with their own key.
        using var foreign = MlDsa65ShareAuthenticator.Generate();
        SecretShare victim = good[1];
        byte[] payload = victim.GetSignedPayload();          // binds the REAL dealer key
        byte[] foreignSig = foreign.Sign(payload);           // but signed by the attacker
        SecretShare forged = new(
            victim.Threshold, victim.TotalShares, victim.ShareIndex, victim.SplitId.ToArray(),
            victim.SecretLength, victim.ShareData.ToArray(), victim.CheckValue.ToArray(),
            victim.Authentication, victim.DealerPublicKey.ToArray(), foreignSig);

        Assert.Throws<ShareAuthenticationException>(
            () => ShamirSecretSharing.Reconstruct(new[] { good[0], forged }, dealer.PublicKey));
    }

    [SkippableFact]
    public void GenerateImportExport_PrivateKey_RoundTrips()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        byte[] sk = dealer.ExportPrivateKey().ToArray();

        using var imported = MlDsa65ShareAuthenticator.ImportPrivateKey(sk);
        Assert.True(dealer.PublicKey.Span.SequenceEqual(imported.PublicKey.Span));

        // A signature from the imported key verifies against the original public key.
        byte[] payload = { 1, 2, 3, 4, 5 };
        byte[] sig = imported.Sign(payload);
        Assert.True(ShareSignatureVerifier.Verify(
            ShareAuthenticationKind.MlDsa65, dealer.PublicKey.Span, payload, sig));
    }

    [SkippableFact]
    public void PublicKey_And_Signature_HaveExpectedSizes()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        Assert.Equal(SecretShare.MlDsa65PublicKeyLength, dealer.PublicKey.Length);
        Assert.Equal(SecretShare.MlDsa65SignatureLength, dealer.Sign(new byte[] { 9 }).Length);
    }

    [SkippableFact]
    public void WrappedSplit_Authenticated_RoundTrips_WithPin()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        byte[] doc = Encoding.UTF8.GetBytes("low-entropy break-glass code: 4242");
        WrappedSplit w = WrappedSecret.Split(doc, new SharePolicy(2, 3), dealer);

        Assert.All(w.Shares, s => Assert.Equal(ShareAuthenticationKind.MlDsa65, s.Authentication));

        using ZeroizingBuffer recovered = WrappedSecret.Reconstruct(
            new[] { w.Shares[0], w.Shares[2] }, w.Envelope, dealer.PublicKey);
        Assert.True(doc.AsSpan().SequenceEqual(recovered.Span));
    }

    [SkippableFact]
    public void Refresh_WithNewDealer_ReauthenticatesShares()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var oldDealer = MlDsa65ShareAuthenticator.Generate();
        byte[] secret = Secret;
        SecretShare[] original = ShamirSecretSharing.Split(secret, new SharePolicy(2, 3), oldDealer);

        using var newDealer = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] refreshed = ShamirSecretSharing.Refresh(
            new[] { original[0], original[1] },
            newPolicy: null,
            expectedDealerPublicKey: oldDealer.PublicKey,
            newDealer: newDealer);

        // New shares verify under the NEW dealer, not the old one.
        using ZeroizingBuffer ok = ShamirSecretSharing.Reconstruct(new[] { refreshed[0], refreshed[2] }, newDealer.PublicKey);
        Assert.True(secret.AsSpan().SequenceEqual(ok.Span));
        Assert.Throws<ShareAuthenticationException>(
            () => ShamirSecretSharing.Reconstruct(new[] { refreshed[0], refreshed[2] }, oldDealer.PublicKey));
    }

    [SkippableFact]
    public void VerifySignature_PerShare_Behaves()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 not supported on this platform.");

        using var dealer = MlDsa65ShareAuthenticator.Generate();
        using var other = MlDsa65ShareAuthenticator.Generate();
        SecretShare[] shares = ShamirSecretSharing.Split(Secret, new SharePolicy(2, 3), dealer);

        // Valid against the correct pin, and against the embedded key (self-attestation).
        Assert.True(shares[0].VerifySignature(dealer.PublicKey));
        Assert.True(shares[0].VerifySignature());
        // Wrong pin rejected.
        Assert.False(shares[0].VerifySignature(other.PublicKey));
        // Tampered share rejected.
        Assert.False(TamperShareData(shares[0]).VerifySignature(dealer.PublicKey));
    }

    private static SecretShare TamperShareData(SecretShare s)
    {
        byte[] badY = s.ShareData.ToArray();
        badY[0] ^= 0x01;
        return new SecretShare(
            s.Threshold, s.TotalShares, s.ShareIndex, s.SplitId.ToArray(), s.SecretLength,
            badY, s.CheckValue.ToArray(), s.Authentication, s.DealerPublicKey.ToArray(), s.Signature.ToArray());
    }
}
#endif
