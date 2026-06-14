using System.Security.Cryptography;
using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Vss;
using PostQuantum.SecretSharing.Vss.Internal;
using Xunit;

namespace PostQuantum.SecretSharing.Vss.Tests;

/// <summary>
/// Post-quantum dealer authentication of the commitment broadcast (ML-DSA-65): a signed
/// broadcast lets a trustee confirm the pin it received came from the pinned dealer and
/// was not substituted. Secrecy and per-share consistency are unaffected — this layer
/// authenticates the <em>broadcast</em>, exactly as v1 authenticates a share.
/// </summary>
public class VssDealerSigningTests
{
    private static byte[] RandomSecret(int len)
    {
        byte[] s = new byte[len];
        RandomNumberGenerator.Fill(s);
        return s;
    }

    [Fact]
    public void Unsigned_broadcast_reports_unsigned_and_does_not_verify()
    {
        VssSplit split = PedersenVss.Split(RandomSecret(32), new SharePolicy(3, 5));
        Assert.False(split.Commitments.IsDealerSigned);
        Assert.True(split.Commitments.DealerPublicKey.IsEmpty);
        Assert.False(split.Commitments.VerifyDealerSignature(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Non_mldsa_dealer_is_rejected()
    {
        Assert.Throws<ShareAuthenticationException>(() =>
            PedersenVss.Split(RandomSecret(32), new SharePolicy(3, 5), new NoneAuthenticator()));
    }

#if NET10_0_OR_GREATER
    [SkippableFact]
    public void Signed_broadcast_verifies_against_the_pinned_dealer_key()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 unavailable on this platform.");
        using var dealer = MlDsa65ShareAuthenticator.Generate();
        byte[] pin = dealer.PublicKey.ToArray();

        VssSplit split = PedersenVss.Split(RandomSecret(40), new SharePolicy(3, 5), dealer);

        Assert.True(split.Commitments.IsDealerSigned);
        Assert.Equal(pin, split.Commitments.DealerPublicKey.ToArray());
        Assert.True(split.Commitments.VerifyDealerSignature(pin));

        // Shares still verify and reconstruct exactly as before; signing is additive.
        Assert.All(split.Shares, s => Assert.True(s.Verify(split.Commitments)));
        using ZeroizingBuffer r = PedersenVss.Reconstruct(split.Shares.Take(3).ToArray(), split.Commitments);
        Assert.Equal(40, r.Length);
    }

    [SkippableFact]
    public void Signed_broadcast_fails_against_a_different_pinned_key()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 unavailable on this platform.");
        using var dealer = MlDsa65ShareAuthenticator.Generate();
        using var other = MlDsa65ShareAuthenticator.Generate();

        VssSplit split = PedersenVss.Split(RandomSecret(40), new SharePolicy(3, 5), dealer);

        // Right signature, wrong pinned key — a substituted dealer is caught.
        Assert.False(split.Commitments.VerifyDealerSignature(other.PublicKey.Span));
    }

    [SkippableFact]
    public void Tampering_a_signed_broadcast_breaks_the_signature()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 unavailable on this platform.");
        using var dealer = MlDsa65ShareAuthenticator.Generate();
        byte[] pin = dealer.PublicKey.ToArray();

        VssSplit split = PedersenVss.Split(RandomSecret(40), new SharePolicy(3, 5), dealer);

        // Re-sign a *different* commitment set under the same key, then graft this dealer's
        // signature/key onto it: the signature no longer matches the tampered content.
        CommitmentsData good = split.Commitments.Data;
        var tamperedPoints = good.Points.Select(chunk => chunk.ToArray()).ToArray();
        tamperedPoints[0][0] = Secp256r1Group.Commit(Secp256r1Group.RandomScalar(), Secp256r1Group.RandomScalar());
        var tampered = good with { Points = tamperedPoints };
        VssCommitments forged = VssCommitments.Import(Vss2Format.EncodeCommitments(tampered));

        Assert.True(forged.IsDealerSigned);
        Assert.False(forged.VerifyDealerSignature(pin));
    }

    [SkippableFact]
    public void Signed_broadcast_round_trips_export_import_and_still_verifies()
    {
        Skip.IfNot(MLDsa.IsSupported, "ML-DSA-65 unavailable on this platform.");
        using var dealer = MlDsa65ShareAuthenticator.Generate();
        byte[] pin = dealer.PublicKey.ToArray();

        VssSplit split = PedersenVss.Split(RandomSecret(50), new SharePolicy(3, 5), dealer);
        byte[] bytes = split.Commitments.Export();

        VssCommitments reimported = VssCommitments.Import(bytes);
        Assert.Equal(bytes, reimported.Export());                 // byte-identical
        Assert.True(reimported.IsDealerSigned);
        Assert.True(reimported.VerifyDealerSignature(pin));
    }
#endif

    /// <summary>A stand-in signer that reports an unsupported kind, to exercise the guard.</summary>
    private sealed class NoneAuthenticator : IShareAuthenticator
    {
        public ShareAuthenticationKind Kind => ShareAuthenticationKind.None;
        public ReadOnlyMemory<byte> PublicKey => ReadOnlyMemory<byte>.Empty;
        public byte[] Sign(ReadOnlySpan<byte> canonicalShareBytes) => Array.Empty<byte>();
    }
}
