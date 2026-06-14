using FsCheck;
using FsCheck.Fluent;

namespace PostQuantum.SecretSharing.Tests;

// ── Valid shares ──────────────────────────────────────────────────────────────

/// <summary>A canonically-valid share plus the parameters that produced it.</summary>
public sealed record ValidShare(int K, int N, int Index, int Length, bool Authenticated, byte[] Bytes);

public static class ValidShareArbitrary
{
    public static Arbitrary<ValidShare> Shares()
    {
        Gen<ValidShare> gen =
            from k in Gen.Choose(2, 255)
            from n in Gen.Choose(k, 255)
            from index in Gen.Choose(1, n)
            from len in Gen.Choose(1, 64)
            from authed in Gen.Elements(new[] { false, true })
            select Build(k, n, index, len, authed);
        return Arb.From(gen, Shrink);
    }

    internal static ValidShare Build(int k, int n, int index, int len, bool authed)
    {
        byte[] bytes = CborCorpus.BuildShare(
            k: (ulong)k, n: (ulong)n, index: (ulong)index,
            splitId: new byte[16], secretLength: (ulong)len,
            shareData: new byte[len], checkValue: new byte[32],
            authAlg: authed ? 1u : 0u,
            dealerKey: authed ? new byte[1952] : null,
            signature: authed ? new byte[3309] : null);
        return new ValidShare(k, n, index, len, authed, bytes);
    }

    private static IEnumerable<ValidShare> Shrink(ValidShare s)
    {
        if (s.Authenticated) yield return Build(s.K, s.N, s.Index, s.Length, false);
        if (s.Length > 1) yield return Build(s.K, s.N, s.Index, s.Length - 1, s.Authenticated);
        if (s.Index > 1) yield return Build(s.K, s.N, s.Index - 1, s.Length, s.Authenticated);
        if (s.N > s.K) yield return Build(s.K, s.N - 1, Math.Min(s.Index, s.N - 1), s.Length, s.Authenticated);
        if (s.K > 2) yield return Build(s.K - 1, s.N, s.Index, s.Length, s.Authenticated);
    }
}

// ── Mutated valid shares (targeted structural mutations) ──────────────────────

public sealed record MutatedShare(byte[] Bytes);

public static class MutatedShareArbitrary
{
    private const int KindCount = 13;

    public static Arbitrary<MutatedShare> Shares()
    {
        Gen<MutatedShare> gen =
            from k in Gen.Choose(2, 12)
            from n in Gen.Choose(k, 16)
            from index in Gen.Choose(1, n)
            from len in Gen.Choose(1, 48)
            from authed in Gen.Elements(new[] { false, true })
            from kind in Gen.Choose(0, KindCount - 1)
            from pos in Gen.Choose(0, 8192)
            from val in Gen.Choose(0, 255)
            select new MutatedShare(Mutate(
                ValidShareArbitrary.Build(k, n, index, len, authed).Bytes, kind, pos, (byte)val));
        return Arb.From(gen, Shrink);
    }

    private static IEnumerable<MutatedShare> Shrink(MutatedShare m)
    {
        byte[] b = m.Bytes;
        if (b.Length > 1) yield return new MutatedShare(b[..(b.Length - 1)]);          // drop last byte
        if (b.Length > 2) yield return new MutatedShare(b[..(b.Length / 2)]);          // halve
    }

    /// <summary>Applies one of many structural mutations to a valid share's bytes.</summary>
    private static byte[] Mutate(byte[] src, int kind, int pos, byte val)
    {
        if (src.Length == 0) return src;
        int p = pos % src.Length;
        var b = (byte[])src.Clone();
        switch (kind)
        {
            case 0: b[p] ^= (byte)(1 << (pos & 7)); return b;                          // flip a bit
            case 1: b[p] = val; return b;                                              // overwrite a byte
            case 2: return Remove(b, p);                                               // delete a byte
            case 3: return Insert(b, p, val);                                          // insert a byte
            case 4: return b[..p];                                                     // truncate tail
            case 5: return b[p..];                                                     // truncate head
            case 6: return Insert(b, p, b[p]);                                         // duplicate a byte
            case 7: if (p + 1 < b.Length) (b[p], b[p + 1]) = (b[p + 1], b[p]); return b; // swap adjacent
            case 8: return Concat(b, new[] { val });                                   // append junk
            case 9: return Concat(new[] { val }, b);                                   // prepend junk
            case 10: { int e = Math.Min(b.Length, p + 8); for (int i = p; i < e; i++) b[i] = 0x00; return b; } // zero run
            case 11: { int e = Math.Min(b.Length, p + 8); for (int i = p; i < e; i++) b[i] = 0xFF; return b; } // 0xFF run
            case 12: { int e = Math.Min(b.Length, p + 6); Array.Reverse(b, p, e - p); return b; }              // reverse window
            default: return b;
        }
    }

    private static byte[] Remove(byte[] b, int i) => Concat(b[..i], b[(i + 1)..]);
    private static byte[] Insert(byte[] b, int i, byte v) => Concat(Concat(b[..i], new[] { v }), b[i..]);
    private static byte[] Concat(byte[] a, byte[] c) { var r = new byte[a.Length + c.Length]; a.CopyTo(r, 0); c.CopyTo(r, a.Length); return r; }
}

// ── Structured CBOR maps (deliberately wrong contents) ────────────────────────

public abstract record CborVal;
public sealed record VUInt(ulong V, int ForceAi) : CborVal;   // ForceAi: -1 canonical, 24/25/26/27 forced (non-shortest)
public sealed record VBytes(int Length) : CborVal;
public sealed record VText(int Length) : CborVal;

public sealed record CborEntry(int Key, CborVal Value);

/// <summary>
/// A model of a top-level CBOR map whose header count, key order/uniqueness, value
/// types, integer canonicity, field sizes, and trailing bytes are all free to be
/// wrong — to drive the strict reader through its rejection paths.
/// </summary>
public sealed record CborModel(int HeaderCount, bool Indefinite, CborEntry[] Entries, byte[] Trailing)
{
    public byte[] Encode()
    {
        var w = new RawCbor();
        w.MapHeader(HeaderCount, Indefinite ? 31 : -1);
        foreach (CborEntry e in Entries)
        {
            w.UInt((ulong)e.Key);
            switch (e.Value)
            {
                case VUInt u: w.UInt(u.V, u.ForceAi); break;
                case VBytes by: w.Bytes(new byte[by.Length]); break;
                case VText t: w.Text(new string('P', t.Length)); break;
            }
        }
        if (Trailing.Length > 0) w.Raw(Trailing);
        return w.ToArray();
    }
}

public static class CborModelArbitrary
{
    public static Arbitrary<CborModel> Models()
    {
        Gen<CborVal> valGen = Gen.OneOf(new[]
        {
            from v in Gen.Choose(0, 70000) from ai in Gen.Elements(new[] { -1, -1, -1, -1, 24, 25, 26 }) select (CborVal)new VUInt((ulong)v, ai),
            from n in Gen.Choose(0, 40) select (CborVal)new VBytes(n),
            from n in Gen.Choose(0, 6) select (CborVal)new VText(n),
        });

        Gen<CborEntry> entryGen =
            from key in Gen.Choose(0, 13)     // 0..11 valid, 12/13 unknown
            from v in valGen
            select new CborEntry(key, v);

        Gen<CborModel> gen =
            from entries in Gen.ArrayOf(entryGen)
            from countMode in Gen.Choose(0, 9)
            from indef in Gen.Elements(new[] { false, false, false, false, false, false, false, false, false, true })
            from trailing in Gen.Elements(new[] { Array.Empty<byte>(), new byte[] { 0x00 }, new byte[] { 0xFF, 0xFF } })
            select new CborModel(DeclaredCount(entries.Length, countMode), indef, entries, trailing);

        return Arb.From(gen, Shrink);
    }

    private static int DeclaredCount(int actual, int mode)
        => mode < 7 ? actual : mode == 7 ? actual + 1 : Math.Max(0, actual - 1);

    private static IEnumerable<CborModel> Shrink(CborModel m)
    {
        for (int i = 0; i < m.Entries.Length; i++)
        {
            var reduced = m.Entries.Where((_, idx) => idx != i).ToArray();
            yield return m with { Entries = reduced, HeaderCount = Math.Min(m.HeaderCount, reduced.Length) };
        }
        if (m.Trailing.Length > 0) yield return m with { Trailing = Array.Empty<byte>() };
        if (m.Indefinite) yield return m with { Indefinite = false };
    }
}

// ── CBOR primitive values (direct reader/writer round-trip + rejection) ───────

/// <summary>
/// A single CBOR unsigned integer, biased toward the values that straddle every
/// shortest-form width boundary (inline / 1 / 2 / 4 / 8 bytes) — the exact places
/// a non-canonical-integer bug hides. Shrinks toward 0 and toward each boundary.
/// </summary>
public sealed record CborUInt(ulong Value);

public static class CborUIntArbitrary
{
    /// <summary>Values one step on either side of every CBOR integer-width boundary.</summary>
    internal static readonly ulong[] Boundaries =
    {
        0, 1, 22, 23, 24, 25, 254, 255, 256, 257,
        65534, 65535, 65536, 65537,
        uint.MaxValue - 1, uint.MaxValue, (ulong)uint.MaxValue + 1,
        ulong.MaxValue - 1, ulong.MaxValue,
    };

    /// <summary>Full-range generator: mostly random ulongs, sometimes a boundary value.</summary>
    internal static readonly Gen<ulong> UInt =
        Gen.Frequency(new[]
        {
            (1, Gen.Elements(Boundaries)),
            (3, RandomUInt()),
        });

    public static Arbitrary<CborUInt> UInts() =>
        Arb.From(UInt.Select(v => new CborUInt(v)), Shrink);

    private static Gen<ulong> RandomUInt() =>
        from b0 in Gen.Choose(0, 255)
        from b1 in Gen.Choose(0, 255)
        from b2 in Gen.Choose(0, 255)
        from b3 in Gen.Choose(0, 255)
        from b4 in Gen.Choose(0, 255)
        from b5 in Gen.Choose(0, 255)
        from b6 in Gen.Choose(0, 255)
        from b7 in Gen.Choose(0, 255)
        select ((ulong)(uint)b0 << 56) | ((ulong)(uint)b1 << 48) | ((ulong)(uint)b2 << 40) | ((ulong)(uint)b3 << 32)
             | ((ulong)(uint)b4 << 24) | ((ulong)(uint)b5 << 16) | ((ulong)(uint)b6 << 8) | (ulong)(uint)b7;

    private static IEnumerable<CborUInt> Shrink(CborUInt u)
    {
        ulong v = u.Value;
        foreach (ulong c in new ulong[] { 0, 1, 23, 24, 255, 256, 65535, 65536, uint.MaxValue })
            if (c < v) yield return new CborUInt(c);
        if (v > 1) yield return new CborUInt(v / 2);
        if (v > 0) yield return new CborUInt(v - 1);
    }
}

// ── Sequences of mixed CBOR primitives (composition round-trip) ───────────────

public abstract record CborPrim;
public sealed record PUInt(ulong V) : CborPrim;
public sealed record PBytes(byte[] B) : CborPrim;
public sealed record PText(string S) : CborPrim;

/// <summary>An ordered run of primitives, to verify they read back in the same order.</summary>
public sealed record CborSequence(CborPrim[] Items);

public static class CborSequenceArbitrary
{
    // Only well-formed-UTF-8 characters (no lone surrogates), so text round-trips
    // byte-identically through the lenient writer and the strict reader.
    private static readonly char[] SafeChars = { 'a', 'Z', '9', ' ', '_', 'é', '€', '中', 'π', '✓' };

    public static Arbitrary<CborSequence> Sequences()
    {
        Gen<string> text = Gen.ArrayOf(Gen.Elements(SafeChars)).Select(cs => new string(cs));
        Gen<byte[]> bytes = Gen.ArrayOf(Gen.Choose(0, 255)).Select(a => a.Select(x => (byte)x).ToArray());
        Gen<CborPrim> prim = Gen.OneOf(new[]
        {
            CborUIntArbitrary.UInt.Select(v => (CborPrim)new PUInt(v)),
            bytes.Select(b => (CborPrim)new PBytes(b)),
            text.Select(s => (CborPrim)new PText(s)),
        });
        Gen<CborSequence> gen = Gen.ArrayOf(prim).Select(items => new CborSequence(items));
        return Arb.From(gen, Shrink);
    }

    private static IEnumerable<CborSequence> Shrink(CborSequence s)
    {
        for (int i = 0; i < s.Items.Length; i++)
            yield return new CborSequence(s.Items.Where((_, idx) => idx != i).ToArray());
    }
}
