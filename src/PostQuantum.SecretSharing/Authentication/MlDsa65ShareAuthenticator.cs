#if NET10_0_OR_GREATER
using System.Security.Cryptography;

namespace PostQuantum.SecretSharing;

/// <summary>
/// A dealer-side <see cref="IShareAuthenticator"/> that signs shares with
/// ML-DSA-65 (FIPS 204), pure mode, empty context.
/// </summary>
/// <remarks>
/// <para>
/// Available only on net10.0, and only where <see cref="MLDsa.IsSupported"/> is
/// true (Windows, or Linux with OpenSSL ≥ 3.5; macOS is unsupported upstream).
/// Construction throws <see cref="PlatformNotSupportedException"/> otherwise.
/// </para>
/// <para>
/// <b>Custody is yours.</b> The private key produced by <see cref="Generate"/> is
/// the dealer's signing authority. Anyone with it can mint shares that verify
/// against your pinned public key. <see cref="ExportPrivateKey"/> hands you the
/// raw private key — protecting it (HSM, offline media, sealed storage) is the
/// caller's responsibility, not this library's.
/// </para>
/// </remarks>
public sealed class MlDsa65ShareAuthenticator : IShareAuthenticator, IDisposable
{
    private readonly MLDsa _key;
    private readonly byte[] _publicKey;
    private bool _disposed;

    private MlDsa65ShareAuthenticator(MLDsa key)
    {
        _key = key;
        _publicKey = key.ExportMLDsaPublicKey();
    }

    /// <inheritdoc/>
    public ShareAuthenticationKind Kind => ShareAuthenticationKind.MlDsa65;

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    /// <summary>Generates a fresh ML-DSA-65 dealer key pair.</summary>
    /// <exception cref="PlatformNotSupportedException">If ML-DSA is unavailable on this platform.</exception>
    public static MlDsa65ShareAuthenticator Generate()
    {
        EnsureSupported();
        return new MlDsa65ShareAuthenticator(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65));
    }

    /// <summary>Imports an existing ML-DSA-65 dealer private key.</summary>
    /// <param name="privateKey">The raw ML-DSA-65 private key bytes.</param>
    /// <exception cref="PlatformNotSupportedException">If ML-DSA is unavailable on this platform.</exception>
    public static MlDsa65ShareAuthenticator ImportPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        EnsureSupported();
        return new MlDsa65ShareAuthenticator(MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, privateKey));
    }

    /// <summary>
    /// Exports the raw ML-DSA-65 private key. <b>This is the dealer's signing
    /// authority</b> — store it as carefully as any signing key; this library does
    /// not manage its custody.
    /// </summary>
    public ReadOnlyMemory<byte> ExportPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key.ExportMLDsaPrivateKey();
    }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> canonicalShareBytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _key.SignData(canonicalShareBytes.ToArray());
    }

    /// <summary>Disposes the underlying key material.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _key.Dispose();
        _disposed = true;
    }

    private static void EnsureSupported()
    {
        if (!MLDsa.IsSupported)
            throw new PlatformNotSupportedException(ShareSignatureVerifier.PlatformMessage);
    }
}
#endif
