#if NET10_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace PostQuantum.SecretSharing;

/// <summary>
/// Verifies share signatures. ML-DSA-65 verification requires FIPS 204, which is
/// available only on net10.0 with a supporting backend; on net8.0 (or where
/// <c>MLDsa.IsSupported</c> is false) authenticated reconstruction throws
/// <see cref="PlatformNotSupportedException"/> pointing at the README platform
/// matrix. Unauthenticated reconstruction never reaches this code and runs on all
/// targets.
/// </summary>
internal static class ShareSignatureVerifier
{
    internal const string PlatformMessage =
        "ML-DSA-65 (FIPS 204) is not available on this target/platform, so authenticated " +
        "shares cannot be verified here. The core (unauthenticated) functionality runs " +
        "everywhere; the ML-DSA layer requires net10.0 with a supporting backend " +
        "(Windows, or Linux with OpenSSL >= 3.5; macOS is unsupported upstream). " +
        "See the README platform matrix.";

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="payload"/> with
    /// <paramref name="publicKey"/> under the given algorithm. ML-DSA-65 uses pure
    /// mode with an empty context.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">If the algorithm is unavailable on this target/platform.</exception>
    internal static bool Verify(
        ShareAuthenticationKind kind,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature)
    {
        if (kind != ShareAuthenticationKind.MlDsa65)
            throw new ShareAuthenticationException($"Unsupported authentication kind {kind}.");

#if NET10_0_OR_GREATER
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException(PlatformMessage);

        using MLDsa verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey);
        return verifier.VerifyData(payload, signature);
#else
        throw new PlatformNotSupportedException(PlatformMessage);
#endif
    }
}
