namespace PostQuantum.SecretSharing;

/// <summary>
/// Thrown when share bytes are not a valid, strictly-canonical v1 <c>.pqss</c>
/// encoding: malformed CBOR, non-canonical encoding (indefinite lengths,
/// non-shortest integers, out-of-order or duplicate keys), trailing bytes,
/// wrong CBOR major type for a field, unknown keys, or a field whose presence
/// contradicts the declared authentication mode.
/// </summary>
public sealed class ShareFormatException : SecretSharingException
{
    /// <inheritdoc cref="SecretSharingException(string)"/>
    public ShareFormatException(string message) : base(message) { }

    /// <inheritdoc cref="SecretSharingException(string, Exception)"/>
    public ShareFormatException(string message, Exception innerException)
        : base(message, innerException) { }
}
