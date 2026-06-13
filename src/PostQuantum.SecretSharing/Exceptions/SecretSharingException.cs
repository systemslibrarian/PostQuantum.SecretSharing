namespace PostQuantum.SecretSharing;

/// <summary>
/// Abstract base for every exception thrown by PostQuantum.SecretSharing.
/// Catch this to handle any library-originated failure uniformly.
/// </summary>
/// <remarks>
/// By contract, no exception message ever echoes secret material or raw share
/// bytes. Messages describe <em>what</em> failed and <em>where</em>, never the
/// content that failed.
/// </remarks>
public abstract class SecretSharingException : Exception
{
    /// <summary>Creates the exception with a human-readable message.</summary>
    protected SecretSharingException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    protected SecretSharingException(string message, Exception innerException)
        : base(message, innerException) { }
}
