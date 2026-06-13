using System.Security.Cryptography;

namespace PostQuantum.SecretSharing;

/// <summary>
/// The result of a wrapped split: the shares of the random key-encryption key
/// (KEK), plus the non-secret <see cref="Envelope"/> (the AES-256-GCM ciphertext
/// of your real secret). Distribute the shares to trustees and store the envelope
/// anywhere — it is useless without a quorum.
/// </summary>
public sealed class WrappedSplit
{
    internal WrappedSplit(SecretShare[] shares, byte[] envelope)
    {
        Shares = shares;
        Envelope = envelope;
    }

    /// <summary>Shares of the random KEK. Any <c>k</c> reconstruct it.</summary>
    public SecretShare[] Shares { get; }

    /// <summary>The sealed envelope: <c>nonce ‖ tag ‖ ciphertext</c>. Not secret.</summary>
    public byte[] Envelope { get; }
}

/// <summary>
/// Helpers for the <b>wrap pattern</b>: the correct way to apply threshold custody
/// to data that may be low-entropy (passphrases, PINs) or large.
/// </summary>
/// <remarks>
/// Splitting a low-entropy secret directly is unsafe — the per-share check value
/// is an offline guessing oracle (see THREAT-MODEL.md). These helpers instead
/// generate a random 256-bit KEK, seal your real secret under it with
/// AES-256-GCM, and split <em>the KEK</em> (which is always high-entropy, so the
/// oracle is harmless). The sealed envelope is not secret and can be stored beside
/// the shares.
/// </remarks>
public static class WrappedSecret
{
    private const int KekLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    /// <summary>Wrap-splits <paramref name="secret"/> with no dealer authentication.</summary>
    public static WrappedSplit Split(ReadOnlySpan<byte> secret, SharePolicy policy)
        => SplitCore(secret, policy, dealer: null);

    /// <summary>Wrap-splits <paramref name="secret"/> and dealer-signs the KEK shares.</summary>
    public static WrappedSplit Split(ReadOnlySpan<byte> secret, SharePolicy policy, IShareAuthenticator dealer)
    {
        ArgumentNullException.ThrowIfNull(dealer);
        return SplitCore(secret, policy, dealer);
    }

    private static WrappedSplit SplitCore(ReadOnlySpan<byte> secret, SharePolicy policy, IShareAuthenticator? dealer)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (secret.Length < 1)
            throw new SharePolicyException("Secret must be at least 1 byte.");

        byte[] kek = new byte[KekLength];
        try
        {
            RandomNumberGenerator.Fill(kek);
            byte[] envelope = Seal(kek, secret);
            SecretShare[] shares = dealer is null
                ? ShamirSecretSharing.Split(kek, policy)
                : ShamirSecretSharing.Split(kek, policy, dealer);
            return new WrappedSplit(shares, envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// Reconstructs the KEK from exactly <c>k</c> shares, then decrypts and
    /// authenticates the <paramref name="envelope"/>, returning the original
    /// secret in a <see cref="ZeroizingBuffer"/>.
    /// </summary>
    /// <exception cref="ShareConsistencyException">If the envelope is malformed or fails authentication (tampered or wrong KEK).</exception>
    public static ZeroizingBuffer Reconstruct(
        IReadOnlyList<SecretShare> shares,
        ReadOnlyMemory<byte> envelope,
        ReadOnlyMemory<byte>? expectedDealerPublicKey = null)
    {
        ArgumentNullException.ThrowIfNull(shares);
        ReadOnlySpan<byte> env = envelope.Span;
        if (env.Length < NonceLength + TagLength)
            throw new ShareConsistencyException(
                $"Envelope is too short ({env.Length} bytes); expected at least {NonceLength + TagLength}.");

        using ZeroizingBuffer kek = ShamirSecretSharing.Reconstruct(shares, expectedDealerPublicKey);

        ReadOnlySpan<byte> nonce = env[..NonceLength];
        ReadOnlySpan<byte> tag = env.Slice(NonceLength, TagLength);
        ReadOnlySpan<byte> ciphertext = env[(NonceLength + TagLength)..];

        var plaintext = new ZeroizingBuffer(ciphertext.Length);
        try
        {
            using var aes = new AesGcm(kek.Span, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext.Span);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException ex)
        {
            plaintext.Dispose();
            throw new ShareConsistencyException(
                "Envelope authentication failed: the ciphertext was tampered with, or the reconstructed " +
                "KEK is wrong (shares do not belong to this envelope).", ex);
        }
        catch
        {
            plaintext.Dispose();
            throw;
        }
    }

    private static byte[] Seal(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> plaintext)
    {
        byte[] envelope = new byte[NonceLength + TagLength + plaintext.Length];
        Span<byte> nonce = envelope.AsSpan(0, NonceLength);
        Span<byte> tag = envelope.AsSpan(NonceLength, TagLength);
        Span<byte> ciphertext = envelope.AsSpan(NonceLength + TagLength);

        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(kek, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return envelope;
    }
}
