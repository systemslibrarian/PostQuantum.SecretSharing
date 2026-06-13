using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using PostQuantum.SecretSharing.Cbor;

namespace PostQuantum.SecretSharing.Vss.Internal;

/// <summary>Decoded Pedersen commitment broadcast (public). <c>Points[k][j]</c> = C_{k,j}.</summary>
internal sealed record CommitmentsData(
    int K, int N, byte[] SplitId, int SecretLength, ECPoint[][] Points);

/// <summary>Decoded per-trustee VSS share. <c>S[k]</c>, <c>T[k]</c> are the scalar pair for chunk k.</summary>
internal sealed record ShareData(
    int K, int N, int Index, byte[] SplitId, int SecretLength, BigInteger[] S, BigInteger[] T);

/// <summary>
/// Strict, canonical <c>.pqss</c> v2 encoding for VSS records, built on the core's single
/// audited <see cref="CanonicalCborWriter"/>/<see cref="StrictCborReader"/> (definite
/// lengths, shortest-form integers, ascending unique integer keys, exact types, no
/// trailing bytes, fail-closed). See <c>docs/VSS-DESIGN.md</c> §4.
/// </summary>
internal static class Vss2Format
{
    internal const int Version = 2;
    internal const string CommitmentsTag = "PQSS-VSS-C";
    internal const string ShareTag = "PQSS-VSS-S";

    internal const int SplitIdLength = 16;
    internal const int MaxSecretLength = 65536;

    // ── Commitments ───────────────────────────────────────────────────────────

    internal static byte[] EncodeCommitments(CommitmentsData d)
    {
        int m = d.Points.Length;
        var blob = new byte[m * d.K * Secp256r1Group.PointLength];
        int o = 0;
        foreach (ECPoint[] chunk in d.Points)
            foreach (ECPoint c in chunk)
            {
                Secp256r1Group.EncodePoint(c).CopyTo(blob, o);
                o += Secp256r1Group.PointLength;
            }

        var w = new CanonicalCborWriter();
        w.WriteMapHeader(9);
        w.WriteUInt(0); w.WriteTextString(CommitmentsTag);
        w.WriteUInt(1); w.WriteUInt(Version);
        w.WriteUInt(2); w.WriteUInt((ulong)Secp256r1Group.GroupId);
        w.WriteUInt(3); w.WriteUInt((ulong)d.K);
        w.WriteUInt(4); w.WriteUInt((ulong)d.N);
        w.WriteUInt(5); w.WriteByteString(d.SplitId);
        w.WriteUInt(6); w.WriteUInt((ulong)d.SecretLength);
        w.WriteUInt(7); w.WriteUInt((ulong)m);
        w.WriteUInt(8); w.WriteByteString(blob);
        return w.ToArray();
    }

    internal static CommitmentsData DecodeCommitments(ReadOnlySpan<byte> bytes)
    {
        var r = new StrictCborReader(bytes);
        ExpectCount(r.ReadMapHeader(), 9);

        ExpectKey(r, 0); ExpectTag(r.ReadTextString(), CommitmentsTag);
        ExpectKey(r, 1); ExpectVersion(r.ReadUInt());
        ExpectKey(r, 2); ExpectGroup(r.ReadUInt());
        ExpectKey(r, 3); int k = ReadCount(r);
        ExpectKey(r, 4); int n = ReadCount(r);
        ExpectKey(r, 5); byte[] splitId = ReadSplitId(r);
        ExpectKey(r, 6); int secretLength = ReadSecretLength(r);
        ExpectKey(r, 7); int m = ReadCount(r);
        ExpectKey(r, 8); byte[] blob = r.ReadByteString();
        r.EnsureEnd();

        ValidatePolicy(k, n);
        if (m != SecretChunking.ChunkCount(secretLength))
            throw new ShareFormatException("Commitment chunk count does not match secret length.");
        if (blob.Length != m * k * Secp256r1Group.PointLength)
            throw new ShareFormatException("Commitment blob length does not match k × chunk count.");

        var points = new ECPoint[m][];
        int o = 0;
        for (int ck = 0; ck < m; ck++)
        {
            points[ck] = new ECPoint[k];
            for (int j = 0; j < k; j++)
            {
                if (!Secp256r1Group.TryDecodePoint(blob.AsSpan(o, Secp256r1Group.PointLength), out ECPoint p))
                    throw new ShareFormatException("Commitment contains an invalid curve point.");
                points[ck][j] = p;
                o += Secp256r1Group.PointLength;
            }
        }
        return new CommitmentsData(k, n, splitId, secretLength, points);
    }

    // ── Share ─────────────────────────────────────────────────────────────────

    internal static byte[] EncodeShare(ShareData d)
    {
        int m = d.S.Length;
        var blob = new byte[m * 2 * Secp256r1Group.ScalarLength];
        int o = 0;
        for (int k = 0; k < m; k++)
        {
            Secp256r1Group.EncodeScalar(d.S[k]).CopyTo(blob, o); o += Secp256r1Group.ScalarLength;
            Secp256r1Group.EncodeScalar(d.T[k]).CopyTo(blob, o); o += Secp256r1Group.ScalarLength;
        }

        var w = new CanonicalCborWriter();
        w.WriteMapHeader(10);
        w.WriteUInt(0); w.WriteTextString(ShareTag);
        w.WriteUInt(1); w.WriteUInt(Version);
        w.WriteUInt(2); w.WriteUInt((ulong)Secp256r1Group.GroupId);
        w.WriteUInt(3); w.WriteUInt((ulong)d.K);
        w.WriteUInt(4); w.WriteUInt((ulong)d.N);
        w.WriteUInt(5); w.WriteUInt((ulong)d.Index);
        w.WriteUInt(6); w.WriteByteString(d.SplitId);
        w.WriteUInt(7); w.WriteUInt((ulong)d.SecretLength);
        w.WriteUInt(8); w.WriteUInt((ulong)m);
        w.WriteUInt(9); w.WriteByteString(blob);
        return w.ToArray();
    }

    internal static ShareData DecodeShare(ReadOnlySpan<byte> bytes)
    {
        var r = new StrictCborReader(bytes);
        ExpectCount(r.ReadMapHeader(), 10);

        ExpectKey(r, 0); ExpectTag(r.ReadTextString(), ShareTag);
        ExpectKey(r, 1); ExpectVersion(r.ReadUInt());
        ExpectKey(r, 2); ExpectGroup(r.ReadUInt());
        ExpectKey(r, 3); int k = ReadCount(r);
        ExpectKey(r, 4); int n = ReadCount(r);
        ExpectKey(r, 5); int index = ReadCount(r);
        ExpectKey(r, 6); byte[] splitId = ReadSplitId(r);
        ExpectKey(r, 7); int secretLength = ReadSecretLength(r);
        ExpectKey(r, 8); int m = ReadCount(r);
        ExpectKey(r, 9); byte[] blob = r.ReadByteString();
        r.EnsureEnd();

        ValidatePolicy(k, n);
        if (index < 1 || index > n)
            throw new ShareFormatException("Share index is outside 1..N.");
        if (m != SecretChunking.ChunkCount(secretLength))
            throw new ShareFormatException("Share chunk count does not match secret length.");
        if (blob.Length != m * 2 * Secp256r1Group.ScalarLength)
            throw new ShareFormatException("Share scalar blob length does not match chunk count.");

        var s = new BigInteger[m];
        var t = new BigInteger[m];
        int o = 0;
        for (int kk = 0; kk < m; kk++)
        {
            if (!Secp256r1Group.TryDecodeScalar(blob.AsSpan(o, Secp256r1Group.ScalarLength), out s[kk]))
                throw new ShareFormatException("Share contains a non-canonical scalar.");
            o += Secp256r1Group.ScalarLength;
            if (!Secp256r1Group.TryDecodeScalar(blob.AsSpan(o, Secp256r1Group.ScalarLength), out t[kk]))
                throw new ShareFormatException("Share contains a non-canonical scalar.");
            o += Secp256r1Group.ScalarLength;
        }
        return new ShareData(k, n, index, splitId, secretLength, s, t);
    }

    // ── Strict field readers / validators ─────────────────────────────────────

    private static void ExpectCount(int actual, int expected)
    {
        if (actual != expected)
            throw new ShareFormatException($"Expected a {expected}-entry map but found {actual}.");
    }

    private static void ExpectKey(StrictCborReader r, int expected)
    {
        if (r.ReadUInt() != (ulong)expected)
            throw new ShareFormatException($"Expected map key {expected} (keys must be canonical and in order).");
    }

    private static void ExpectTag(string actual, string expected)
    {
        if (actual != expected)
            throw new ShareFormatException($"Unexpected format tag '{actual}'.");
    }

    private static void ExpectVersion(ulong v)
    {
        if (v != Version)
            throw new ShareFormatException($"Unsupported VSS format version {v}.");
    }

    private static void ExpectGroup(ulong g)
    {
        if (g != (ulong)Secp256r1Group.GroupId)
            throw new ShareFormatException($"Unsupported group identifier {g}.");
    }

    private static int ReadCount(StrictCborReader r)
    {
        ulong v = r.ReadUInt();
        if (v > int.MaxValue)
            throw new ShareFormatException("Numeric field too large.");
        return (int)v;
    }

    private static byte[] ReadSplitId(StrictCborReader r)
    {
        byte[] id = r.ReadByteString();
        if (id.Length != SplitIdLength)
            throw new ShareFormatException($"splitId must be exactly {SplitIdLength} bytes.");
        return id;
    }

    private static int ReadSecretLength(StrictCborReader r)
    {
        int len = ReadCount(r);
        if (len < 1 || len > MaxSecretLength)
            throw new ShareFormatException($"secretLength must be 1..{MaxSecretLength}.");
        return len;
    }

    private static void ValidatePolicy(int k, int n)
    {
        if (k < 2 || n > 255 || k > n)
            throw new ShareFormatException("Invalid k/n: require 2 ≤ k ≤ n ≤ 255.");
    }
}
