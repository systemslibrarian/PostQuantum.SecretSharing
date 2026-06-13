using System.Text;
using PostQuantum.SecretSharing.Cbor;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// Test-only helpers for crafting both well-formed and deliberately-malformed
/// <c>.pqss</c> byte sequences.
/// </summary>
internal static class CborCorpus
{
    /// <summary>
    /// Builds a canonically-encoded share map. Keys 0..9 are always present (with
    /// defaults producing a structurally valid, importable unauthenticated share);
    /// keys 10 and 11 are included iff their argument is non-null. The caller
    /// overrides individual fields to construct invalid-by-one-thing inputs.
    /// </summary>
    internal static byte[] BuildShare(
        string format = "PQSS",
        ulong version = 1,
        ulong k = 2,
        ulong n = 3,
        ulong index = 1,
        byte[]? splitId = null,
        ulong secretLength = 2,
        byte[]? shareData = null,
        byte[]? checkValue = null,
        ulong authAlg = 0,
        byte[]? dealerKey = null,
        byte[]? signature = null)
    {
        splitId ??= new byte[16];
        shareData ??= new byte[] { 0x00, 0x01 };
        checkValue ??= new byte[32];

        var w = new CanonicalCborWriter();
        int count = 10 + (dealerKey is not null ? 1 : 0) + (signature is not null ? 1 : 0);
        w.WriteMapHeader(count);
        w.WriteUInt(0); w.WriteTextString(format);
        w.WriteUInt(1); w.WriteUInt(version);
        w.WriteUInt(2); w.WriteUInt(k);
        w.WriteUInt(3); w.WriteUInt(n);
        w.WriteUInt(4); w.WriteUInt(index);
        w.WriteUInt(5); w.WriteByteString(splitId);
        w.WriteUInt(6); w.WriteUInt(secretLength);
        w.WriteUInt(7); w.WriteByteString(shareData);
        w.WriteUInt(8); w.WriteByteString(checkValue);
        w.WriteUInt(9); w.WriteUInt(authAlg);
        if (dealerKey is not null) { w.WriteUInt(10); w.WriteByteString(dealerKey); }
        if (signature is not null) { w.WriteUInt(11); w.WriteByteString(signature); }
        return w.ToArray();
    }
}

/// <summary>
/// A low-level CBOR writer with knobs for emitting non-canonical and malformed
/// encodings (forced additional-info bytes, indefinite lengths, arbitrary major
/// types). Used only to exercise the strict reader's rejection paths.
/// </summary>
internal sealed class RawCbor
{
    private readonly List<byte> _b = new();

    internal void Raw(params byte[] bytes) => _b.AddRange(bytes);

    /// <summary>
    /// Writes a CBOR head. <paramref name="forceAi"/> &gt;= 0 forces a specific
    /// additional-info value (e.g. 24/25/26/27 to force non-shortest form, 31 for
    /// indefinite), ignoring the natural shortest encoding of <paramref name="arg"/>.
    /// </summary>
    internal void Head(int major, ulong arg, int forceAi = -1)
    {
        int m = major << 5;
        int ai = forceAi >= 0
            ? forceAi
            : arg < 24 ? (int)arg
            : arg <= byte.MaxValue ? 24
            : arg <= ushort.MaxValue ? 25
            : arg <= uint.MaxValue ? 26 : 27;

        if (ai < 24) { _b.Add((byte)(m | ai)); return; }

        _b.Add((byte)(m | ai));
        switch (ai)
        {
            case 24: _b.Add((byte)arg); break;
            case 25: _b.Add((byte)(arg >> 8)); _b.Add((byte)arg); break;
            case 26: for (int i = 3; i >= 0; i--) _b.Add((byte)(arg >> (8 * i))); break;
            case 27: for (int i = 7; i >= 0; i--) _b.Add((byte)(arg >> (8 * i))); break;
            case 31: break; // indefinite: no following length bytes
        }
    }

    internal void MapHeader(int count, int forceAi = -1) => Head(5, (ulong)count, forceAi);
    internal void UInt(ulong v, int forceAi = -1) => Head(0, v, forceAi);

    internal void Bytes(byte[] v, int forceAi = -1)
    {
        Head(2, (ulong)v.Length, forceAi);
        _b.AddRange(v);
    }

    internal void Text(string s, int forceAi = -1)
    {
        byte[] u = Encoding.UTF8.GetBytes(s);
        Head(3, (ulong)u.Length, forceAi);
        _b.AddRange(u);
    }

    internal byte[] ToArray() => _b.ToArray();
}
