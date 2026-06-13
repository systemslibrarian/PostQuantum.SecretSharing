using PostQuantum.SecretSharing.Cbor;

namespace PostQuantum.SecretSharing;

/// <summary>
/// One parsed <c>.pqss</c> share: its public metadata plus the (deliberately
/// non-public) y-coordinate data and integrity material. Construct shares with
/// <see cref="ShamirSecretSharing.Split(ReadOnlySpan{byte}, SharePolicy)"/>,
/// serialize with <see cref="Export"/>, and parse with <see cref="Import"/>.
/// </summary>
/// <remarks>
/// The raw share data (the polynomial y-values) is intentionally not exposed as
/// a public property: a caller has no legitimate reason to read it, and exposing
/// it only widens the attack surface for misuse. Reconstruction reads it through
/// internal channels.
/// </remarks>
public sealed class SecretShare
{
    /// <summary>The fixed format tag carried in key 0.</summary>
    internal const string FormatTag = "PQSS";

    /// <summary>The only supported format version (key 1).</summary>
    internal const uint FormatVersion = 1;

    internal const int SplitIdLength = 16;
    internal const int CheckValueLength = 32;
    internal const int MlDsa65PublicKeyLength = 1952;
    internal const int MlDsa65SignatureLength = 3309;
    internal const int MaxSecretLength = 65536;

    private readonly byte[] _splitId;
    private readonly byte[] _shareData;
    private readonly byte[] _checkValue;
    private readonly byte[] _dealerPublicKey;
    private readonly byte[] _signature;

    internal SecretShare(
        int threshold, int totalShares, int shareIndex,
        byte[] splitId, int secretLength, byte[] shareData, byte[] checkValue,
        ShareAuthenticationKind authentication, byte[] dealerPublicKey, byte[] signature)
    {
        Threshold = threshold;
        TotalShares = totalShares;
        ShareIndex = shareIndex;
        _splitId = splitId;
        SecretLength = secretLength;
        _shareData = shareData;
        _checkValue = checkValue;
        Authentication = authentication;
        _dealerPublicKey = dealerPublicKey;
        _signature = signature;
    }

    /// <summary>The quorum size <c>k</c> required to reconstruct.</summary>
    public int Threshold { get; }

    /// <summary>The total number of shares <c>n</c> issued in this split.</summary>
    public int TotalShares { get; }

    /// <summary>This share's x-coordinate, in <c>1..n</c>.</summary>
    public int ShareIndex { get; }

    /// <summary>The 16-byte random identifier shared by every share of one split.</summary>
    public ReadOnlyMemory<byte> SplitId => _splitId;

    /// <summary>The secret length in bytes, equal to the share data length.</summary>
    public int SecretLength { get; }

    /// <summary>How this share is authenticated.</summary>
    public ShareAuthenticationKind Authentication { get; }

    /// <summary>The embedded dealer public key, or empty if <see cref="Authentication"/> is <see cref="ShareAuthenticationKind.None"/>.</summary>
    public ReadOnlyMemory<byte> DealerPublicKey => _dealerPublicKey;

    // --- Internal accessors for the reconstruction / authentication path -------

    internal ReadOnlySpan<byte> ShareData => _shareData;
    internal ReadOnlySpan<byte> CheckValue => _checkValue;
    internal ReadOnlySpan<byte> Signature => _signature;
    internal ReadOnlySpan<byte> SplitIdSpan => _splitId;

    /// <summary>
    /// The canonical bytes covered by the dealer signature: keys 0–10 (signature
    /// excluded, dealer key included). Used both when signing at split time and
    /// when verifying at reconstruction.
    /// </summary>
    internal byte[] GetSignedPayload() => EncodeCore(
        Threshold, TotalShares, ShareIndex, _splitId, SecretLength, _shareData,
        _checkValue, Authentication, _dealerPublicKey, signature: null, includeSignature: false);

    /// <summary>
    /// Computes the canonical signing payload (keys 0–10) for the given field
    /// values, before a signature exists. Used by the authenticated split path.
    /// </summary>
    internal static byte[] EncodeForSigning(
        int threshold, int totalShares, int shareIndex, byte[] splitId, int secretLength,
        byte[] shareData, byte[] checkValue, ShareAuthenticationKind authentication, byte[] dealerPublicKey)
        => EncodeCore(threshold, totalShares, shareIndex, splitId, secretLength, shareData,
            checkValue, authentication, dealerPublicKey, signature: null, includeSignature: false);

    /// <summary>
    /// Serializes this share to its canonical <c>.pqss</c> byte encoding (all keys,
    /// including the signature when present).
    /// </summary>
    public byte[] Export() => EncodeCore(
        Threshold, TotalShares, ShareIndex, _splitId, SecretLength, _shareData,
        _checkValue, Authentication, _dealerPublicKey, _signature, includeSignature: true);

    /// <summary>
    /// Verifies this single share's dealer signature, <em>without</em> reconstructing
    /// anything — useful for checking shares one at a time (e.g. as trustees present
    /// them) before a quorum exists.
    /// </summary>
    /// <param name="expectedDealerPublicKey">
    /// If supplied, the share's embedded dealer key must equal it (your pin). If
    /// omitted, the signature is checked against the <em>embedded</em> key, which is
    /// self-attestation, not authority — pass the pin for a real guarantee.
    /// </param>
    /// <returns>
    /// <c>true</c> if the share is ML-DSA-65-authenticated, matches the pinned key
    /// (when given), and its signature verifies; <c>false</c> for an unauthenticated
    /// share, a key mismatch, or a bad signature.
    /// </returns>
    /// <exception cref="PlatformNotSupportedException">Where ML-DSA-65 is unavailable (net8.0 / unsupported platforms).</exception>
    public bool VerifySignature(ReadOnlyMemory<byte>? expectedDealerPublicKey = null)
    {
        if (Authentication == ShareAuthenticationKind.None)
            return false;
        if (expectedDealerPublicKey.HasValue &&
            !_dealerPublicKey.AsSpan().SequenceEqual(expectedDealerPublicKey.Value.Span))
            return false;
        return ShareSignatureVerifier.Verify(Authentication, _dealerPublicKey, GetSignedPayload(), _signature);
    }

    private static byte[] EncodeCore(
        int threshold, int totalShares, int shareIndex, byte[] splitId, int secretLength,
        byte[] shareData, byte[] checkValue, ShareAuthenticationKind authentication,
        byte[] dealerPublicKey, byte[]? signature, bool includeSignature)
    {
        bool authed = authentication != ShareAuthenticationKind.None;

        var w = new CanonicalCborWriter();
        int count = 10;                       // keys 0..9 are always present
        if (authed) count++;                  // key 10 (dealer public key)
        if (authed && includeSignature) count++; // key 11 (signature)
        w.WriteMapHeader(count);

        w.WriteUInt(0); w.WriteTextString(FormatTag);
        w.WriteUInt(1); w.WriteUInt(FormatVersion);
        w.WriteUInt(2); w.WriteUInt((ulong)threshold);
        w.WriteUInt(3); w.WriteUInt((ulong)totalShares);
        w.WriteUInt(4); w.WriteUInt((ulong)shareIndex);
        w.WriteUInt(5); w.WriteByteString(splitId);
        w.WriteUInt(6); w.WriteUInt((ulong)secretLength);
        w.WriteUInt(7); w.WriteByteString(shareData);
        w.WriteUInt(8); w.WriteByteString(checkValue);
        w.WriteUInt(9); w.WriteUInt((ulong)authentication);
        if (authed)
        {
            w.WriteUInt(10); w.WriteByteString(dealerPublicKey);
            if (includeSignature)
            {
                w.WriteUInt(11); w.WriteByteString(signature ?? Array.Empty<byte>());
            }
        }
        return w.ToArray();
    }

    /// <summary>
    /// Strictly parses <paramref name="pqssBytes"/> into a <see cref="SecretShare"/>,
    /// rejecting any non-canonical encoding, unknown field, type mismatch, range
    /// violation, length inconsistency, or field whose presence contradicts the
    /// declared authentication mode. Does <em>not</em> verify the signature —
    /// authentication happens at reconstruction.
    /// </summary>
    /// <exception cref="ShareFormatException">Malformed, non-canonical, or internally inconsistent encoding.</exception>
    /// <exception cref="SharePolicyException">A policy field (k, n, or index) is out of its allowed range.</exception>
    public static SecretShare Import(ReadOnlySpan<byte> pqssBytes)
    {
        var reader = new StrictCborReader(pqssBytes);

        int count = reader.ReadMapHeader();

        // Track presence and values; keys must appear in strictly ascending order.
        string? format = null;
        ulong? version = null, threshold = null, total = null, index = null, secretLength = null, authAlg = null;
        byte[]? splitId = null, shareData = null, checkValue = null, dealerKey = null, signature = null;

        long lastKey = -1;
        for (int e = 0; e < count; e++)
        {
            ulong key = reader.ReadUInt();
            if ((long)key <= lastKey)
                throw new ShareFormatException(
                    $"Map keys must be unique and in ascending order; key {key} violates ordering near offset {reader.Position}.");
            lastKey = (long)key;

            switch (key)
            {
                case 0: format = reader.ReadTextString(); break;
                case 1: version = reader.ReadUInt(); break;
                case 2: threshold = reader.ReadUInt(); break;
                case 3: total = reader.ReadUInt(); break;
                case 4: index = reader.ReadUInt(); break;
                case 5: splitId = reader.ReadByteString(); break;
                case 6: secretLength = reader.ReadUInt(); break;
                case 7: shareData = reader.ReadByteString(); break;
                case 8: checkValue = reader.ReadByteString(); break;
                case 9: authAlg = reader.ReadUInt(); break;
                case 10: dealerKey = reader.ReadByteString(); break;
                case 11: signature = reader.ReadByteString(); break;
                default:
                    throw new ShareFormatException($"Unknown map key {key} (v1 defines keys 0..11 only).");
            }
        }
        reader.EnsureEnd();

        // --- Mandatory presence (keys 0..9) ---
        if (format is null || version is null || threshold is null || total is null ||
            index is null || splitId is null || secretLength is null || shareData is null ||
            checkValue is null || authAlg is null)
            throw new ShareFormatException("Missing one or more required fields (keys 0..9).");

        // --- Format / version ---
        if (format != FormatTag)
            throw new ShareFormatException("Field 0 (format) must be exactly \"PQSS\".");
        if (version.Value != FormatVersion)
            throw new ShareFormatException($"Unsupported version {version.Value}; this build accepts version {FormatVersion} only.");

        // --- Policy ranges (k, n, index) ---
        if (threshold.Value == 1)
            throw new SharePolicyException(
                "Threshold k=1 is forbidden: every share would equal the secret (security theater, not secret sharing).");
        if (threshold.Value < 2 || threshold.Value > 255)
            throw new SharePolicyException($"Threshold k must be in 2..255; got {threshold.Value}.");
        if (total.Value < threshold.Value || total.Value > 255)
            throw new SharePolicyException($"Total shares n must be in k..255; got n={total.Value}, k={threshold.Value}.");
        if (index.Value < 1 || index.Value > total.Value)
            throw new SharePolicyException($"Share index must be in 1..n; got {index.Value} (n={total.Value}).");

        // --- Fixed-size byte fields ---
        if (splitId.Length != SplitIdLength)
            throw new ShareFormatException($"Field 5 (splitId) must be exactly {SplitIdLength} bytes; got {splitId.Length}.");
        if (checkValue.Length != CheckValueLength)
            throw new ShareFormatException($"Field 8 (checkValue) must be exactly {CheckValueLength} bytes; got {checkValue.Length}.");

        // --- Secret length / share data consistency ---
        if (secretLength.Value < 1 || secretLength.Value > MaxSecretLength)
            throw new ShareFormatException($"Field 6 (secretLength) must be in 1..{MaxSecretLength}; got {secretLength.Value}.");
        if ((ulong)shareData.Length != secretLength.Value)
            throw new ShareFormatException(
                $"Field 7 (shareData) length {shareData.Length} does not equal declared secretLength {secretLength.Value}.");

        // --- Authentication mode and conditional fields (keys 10, 11) ---
        if (authAlg.Value != 0 && authAlg.Value != 1)
            throw new ShareFormatException($"Field 9 (authAlgorithm) must be 0 or 1; got {authAlg.Value}.");

        ShareAuthenticationKind kind = authAlg.Value == 0
            ? ShareAuthenticationKind.None
            : ShareAuthenticationKind.MlDsa65;

        if (kind == ShareAuthenticationKind.None)
        {
            if (dealerKey is not null)
                throw new ShareFormatException("Field 10 (dealerPublicKey) must be absent when authAlgorithm = 0.");
            if (signature is not null)
                throw new ShareFormatException("Field 11 (signature) must be absent when authAlgorithm = 0.");
            dealerKey = Array.Empty<byte>();
            signature = Array.Empty<byte>();
        }
        else
        {
            if (dealerKey is null)
                throw new ShareFormatException("Field 10 (dealerPublicKey) is required when authAlgorithm = 1.");
            if (signature is null)
                throw new ShareFormatException("Field 11 (signature) is required when authAlgorithm = 1.");
            if (dealerKey.Length != MlDsa65PublicKeyLength)
                throw new ShareFormatException(
                    $"Field 10 (dealerPublicKey) must be exactly {MlDsa65PublicKeyLength} bytes for ML-DSA-65; got {dealerKey.Length}.");
            if (signature.Length != MlDsa65SignatureLength)
                throw new ShareFormatException(
                    $"Field 11 (signature) must be exactly {MlDsa65SignatureLength} bytes for ML-DSA-65; got {signature.Length}.");
        }

        return new SecretShare(
            (int)threshold.Value, (int)total.Value, (int)index.Value,
            splitId, (int)secretLength.Value, shareData, checkValue,
            kind, dealerKey, signature);
    }
}
