namespace PostQuantum.SecretSharing;

/// <summary>
/// Thrown when a threshold policy is invalid or violated: <c>k &lt; 2</c>
/// (including the banned <c>k = 1</c>), <c>k &gt; n</c>, <c>n &gt; 255</c>,
/// secret length out of range, a share index outside <c>1..n</c>, or a
/// reconstruct call given a number of shares not equal to <c>k</c>.
/// </summary>
public sealed class SharePolicyException : SecretSharingException
{
    /// <inheritdoc cref="SecretSharingException(string)"/>
    public SharePolicyException(string message) : base(message) { }

    /// <inheritdoc cref="SecretSharingException(string, Exception)"/>
    public SharePolicyException(string message, Exception innerException)
        : base(message, innerException) { }
}
