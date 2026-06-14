using PostQuantum.SecretSharing.Cbor;

namespace PostQuantum.SecretSharing.Extensions;

/// <summary>
/// One contributor's update sub-share for a single recipient in a distributed
/// <see cref="ProactiveRefresh"/> round: the evaluation, at the recipient's x-coordinate,
/// of a fresh random degree-<c>(k-1)</c> polynomial whose constant term is <b>zero</b>.
/// </summary>
/// <remarks>
/// <para>
/// A sub-share reveals <b>nothing about the secret</b> (its polynomial is independent of
/// the secret). It is, however, sensitive for <em>proactive</em> security: an adversary who
/// collected every contributor's sub-share for the same recipient could reconstruct the
/// update applied to that share and link the share across epochs. <b>Deliver each sub-share
/// point-to-point over a confidential channel to its intended recipient</b>, exactly as you
/// would a fresh share — do not broadcast them.
/// </para>
/// <para>
/// Each recipient collects one sub-share from every contributor in the agreed group and
/// passes them to <see cref="ProactiveRefresh.Apply"/>.
/// </para>
/// </remarks>
public sealed class RefreshSubShare
{
    internal const string FormatTag = "PQSS-REFRESH-SUB";
    internal const uint FormatVersion = 1;
    internal const int MaxSecretLength = 65536;

    private readonly byte[] _delta;

    internal RefreshSubShare(int contributorIndex, int recipientIndex, int threshold, byte[] delta)
    {
        ContributorIndex = contributorIndex;
        RecipientIndex = recipientIndex;
        Threshold = threshold;
        _delta = delta;
    }

    /// <summary>The 1-based x-coordinate of the party that produced this sub-share.</summary>
    public int ContributorIndex { get; }

    /// <summary>The 1-based x-coordinate of the share this sub-share must be applied to.</summary>
    public int RecipientIndex { get; }

    /// <summary>The threshold <c>k</c> this refresh round targets (must match the share's).</summary>
    public int Threshold { get; }

    /// <summary>The per-byte update (length equals the secret length); not secret-revealing.</summary>
    internal ReadOnlySpan<byte> Delta => _delta;

    /// <summary>Wipes the transient update material once it has been applied.</summary>
    internal void ZeroizeDelta() => System.Security.Cryptography.CryptographicOperations.ZeroMemory(_delta);

    /// <summary>Canonical, strict-CBOR bytes for point-to-point delivery to the recipient.</summary>
    public byte[] Export()
    {
        var w = new CanonicalCborWriter();
        w.WriteMapHeader(7);
        w.WriteUInt(0); w.WriteTextString(FormatTag);
        w.WriteUInt(1); w.WriteUInt(FormatVersion);
        w.WriteUInt(2); w.WriteUInt((ulong)ContributorIndex);
        w.WriteUInt(3); w.WriteUInt((ulong)RecipientIndex);
        w.WriteUInt(4); w.WriteUInt((ulong)Threshold);
        w.WriteUInt(5); w.WriteUInt((ulong)_delta.Length);
        w.WriteUInt(6); w.WriteByteString(_delta);
        return w.ToArray();
    }

    /// <summary>Strict, fail-closed parse of a sub-share.</summary>
    /// <exception cref="ShareFormatException">If the bytes are not a canonical, valid sub-share record.</exception>
    public static RefreshSubShare Import(ReadOnlySpan<byte> bytes)
    {
        var r = new StrictCborReader(bytes);
        if (r.ReadMapHeader() != 7)
            throw new ShareFormatException("A refresh sub-share is a 7-entry map.");

        ExpectKey(r, 0);
        if (r.ReadTextString() != FormatTag)
            throw new ShareFormatException("Unexpected format tag (expected PQSS-REFRESH-SUB).");
        ExpectKey(r, 1);
        if (r.ReadUInt() != FormatVersion)
            throw new ShareFormatException("Unsupported refresh sub-share version.");
        ExpectKey(r, 2); int contributor = ReadIndex(r, "contributorIndex");
        ExpectKey(r, 3); int recipient = ReadIndex(r, "recipientIndex");
        ExpectKey(r, 4); int threshold = ReadThreshold(r);
        ExpectKey(r, 5); int secretLength = ReadSecretLength(r);
        ExpectKey(r, 6); byte[] delta = r.ReadByteString();
        r.EnsureEnd();

        if (delta.Length != secretLength)
            throw new ShareFormatException("Sub-share delta length does not match the declared secret length.");
        return new RefreshSubShare(contributor, recipient, threshold, delta);
    }

    private static void ExpectKey(StrictCborReader r, int expected)
    {
        if (r.ReadUInt() != (ulong)expected)
            throw new ShareFormatException($"Expected map key {expected} (keys must be canonical and in order).");
    }

    private static int ReadIndex(StrictCborReader r, string field)
    {
        ulong v = r.ReadUInt();
        if (v < 1 || v > 255)
            throw new ShareFormatException($"{field} must be in 1..255.");
        return (int)v;
    }

    private static int ReadThreshold(StrictCborReader r)
    {
        ulong v = r.ReadUInt();
        if (v < 2 || v > 255)
            throw new ShareFormatException("threshold must be in 2..255.");
        return (int)v;
    }

    private static int ReadSecretLength(StrictCborReader r)
    {
        ulong v = r.ReadUInt();
        if (v < 1 || v > MaxSecretLength)
            throw new ShareFormatException($"secretLength must be in 1..{MaxSecretLength}.");
        return (int)v;
    }
}
