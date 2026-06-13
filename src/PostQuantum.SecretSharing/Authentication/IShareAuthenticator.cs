namespace PostQuantum.SecretSharing;

/// <summary>
/// Identifies the algorithm used to authenticate a share, mirroring the
/// <c>authAlgorithm</c> field (key 9) of the <c>.pqss</c> format.
/// </summary>
public enum ShareAuthenticationKind
{
    /// <summary>No dealer authentication; integrity rests on the HKDF check value only (authAlgorithm = 0).</summary>
    None = 0,

    /// <summary>Shares are signed by the dealer with ML-DSA-65 (FIPS 204), authAlgorithm = 1.</summary>
    MlDsa65 = 1,
}

/// <summary>
/// A dealer-side signer that authenticates the canonical bytes of a share.
/// </summary>
/// <remarks>
/// The signature binds the dealer's public key together with all share metadata
/// (keys 0–10 of the format), so a verifier with the pinned public key can
/// detect any tampering or substitution. v1 ships one implementation,
/// <c>MlDsa65ShareAuthenticator</c> (net10.0).
/// </remarks>
public interface IShareAuthenticator
{
    /// <summary>The authentication algorithm this signer represents.</summary>
    ShareAuthenticationKind Kind { get; }

    /// <summary>The dealer public key embedded in, and bound by, every signed share.</summary>
    ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>
    /// Signs the canonical encoding of a share's keys 0–10 (signature excluded,
    /// dealer key included) and returns the raw signature bytes.
    /// </summary>
    byte[] Sign(ReadOnlySpan<byte> canonicalShareBytes);
}
