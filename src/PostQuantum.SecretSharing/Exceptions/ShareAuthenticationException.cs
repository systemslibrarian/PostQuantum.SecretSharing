namespace PostQuantum.SecretSharing;

/// <summary>
/// Thrown when share authentication fails: an ML-DSA-65 signature does not
/// verify, a share's embedded dealer key does not match the pinned
/// <c>expectedDealerPublicKey</c>, or authenticated reconstruction was
/// requested but a share carries no signature.
/// </summary>
public sealed class ShareAuthenticationException : SecretSharingException
{
    /// <inheritdoc cref="SecretSharingException(string)"/>
    public ShareAuthenticationException(string message) : base(message) { }

    /// <inheritdoc cref="SecretSharingException(string, Exception)"/>
    public ShareAuthenticationException(string message, Exception innerException)
        : base(message, innerException) { }
}
