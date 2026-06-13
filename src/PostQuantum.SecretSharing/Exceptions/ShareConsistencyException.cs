namespace PostQuantum.SecretSharing;

/// <summary>
/// Thrown when a set of shares is individually well-formed but cannot belong to
/// one coherent split: mismatched split identifiers, differing
/// <c>(k, n, secretLength)</c> or authentication metadata, duplicate share
/// indices, or — after interpolation — a reconstructed secret whose HKDF check
/// value does not match.
/// </summary>
/// <remarks>
/// In unauthenticated mode a check-value mismatch cannot identify <em>which</em>
/// share lied; the message says so and points to authenticated mode.
/// </remarks>
public sealed class ShareConsistencyException : SecretSharingException
{
    /// <inheritdoc cref="SecretSharingException(string)"/>
    public ShareConsistencyException(string message) : base(message) { }

    /// <inheritdoc cref="SecretSharingException(string, Exception)"/>
    public ShareConsistencyException(string message, Exception innerException)
        : base(message, innerException) { }
}
