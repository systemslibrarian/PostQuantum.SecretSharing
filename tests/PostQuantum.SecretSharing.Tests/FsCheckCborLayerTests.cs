using System.Text;
using FsCheck;
using FsCheck.Xunit;
using PostQuantum.SecretSharing.Cbor;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// Property-based tests that exercise the CBOR codec <em>primitives</em> directly —
/// <see cref="CanonicalCborWriter"/> and <see cref="StrictCborReader"/> — rather than
/// only the end-to-end <see cref="SecretShare.Import"/> path (covered by
/// <see cref="FsCheckCborTests"/>). These pin the two contracts the whole format
/// rests on:
/// <list type="number">
///   <item><b>Inverse:</b> writer ∘ reader is the identity over the full value space.</item>
///   <item><b>Canonicity:</b> the writer only ever emits shortest-form, and the reader
///   rejects every non-shortest / indefinite / wrong-type / truncated encoding.</item>
/// </list>
/// FsCheck shrinks any counterexample to a minimal reproducer, and the integer
/// generator is biased toward the width boundaries (23/24, 255/256, 65535/65536,
/// 2³²−1/2³²) where non-canonical-encoding bugs actually live.
/// </summary>
public class FsCheckCborLayerTests
{
    // ── Round-trip (writer ∘ reader = identity) ───────────────────────────────

    /// <summary>
    /// PROPERTY: any <c>ulong</c> survives WriteUInt → ReadUInt unchanged, consumes
    /// exactly its bytes, and re-encodes to the identical bytes (i.e. the writer's
    /// output is already in shortest form — there is no second valid encoding).
    /// </summary>
    [Property(MaxTest = 2000, Arbitrary = new[] { typeof(CborUIntArbitrary) })]
    public void UInt_round_trips_and_is_canonical(CborUInt u)
    {
        var w = new CanonicalCborWriter();
        w.WriteUInt(u.Value);
        byte[] bytes = w.ToArray();

        var r = new StrictCborReader(bytes);
        Assert.Equal(u.Value, r.ReadUInt());
        Assert.True(r.AtEnd);
        r.EnsureEnd();

        var w2 = new CanonicalCborWriter();
        w2.WriteUInt(u.Value);
        Assert.Equal(bytes, w2.ToArray());
    }

    /// <summary>PROPERTY: any byte payload round-trips through WriteByteString → ReadByteString.</summary>
    [Property(MaxTest = 2000)]
    public void ByteString_round_trips(byte[]? payload)
    {
        payload ??= Array.Empty<byte>();
        var w = new CanonicalCborWriter();
        w.WriteByteString(payload);

        var r = new StrictCborReader(w.ToArray());
        Assert.Equal(payload, r.ReadByteString());
        Assert.True(r.AtEnd);
    }

    /// <summary>
    /// PROPERTY: any well-formed-UTF-8 string round-trips through WriteTextString →
    /// ReadTextString. (The writer is lenient and replaces lone surrogates, so we
    /// only assert byte-identity for inputs that already survive a UTF-8 round-trip;
    /// malformed input is the rejection-path test's job, not this one's.)
    /// </summary>
    [Property(MaxTest = 2000)]
    public void TextString_round_trips_when_utf8_safe(NonNull<string> s)
    {
        string value = s.Get;
        if (Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(value)) != value)
            return; // not well-formed UTF-8 (lone surrogate) — out of scope here

        var w = new CanonicalCborWriter();
        w.WriteTextString(value);

        var r = new StrictCborReader(w.ToArray());
        Assert.Equal(value, r.ReadTextString());
        Assert.True(r.AtEnd);
    }

    /// <summary>PROPERTY: any non-negative entry count round-trips through the map header.</summary>
    [Property(MaxTest = 1000)]
    public void MapHeader_round_trips(NonNegativeInt count)
    {
        var w = new CanonicalCborWriter();
        w.WriteMapHeader(count.Get);

        var r = new StrictCborReader(w.ToArray());
        Assert.Equal(count.Get, r.ReadMapHeader());
    }

    /// <summary>
    /// PROPERTY: a mixed run of uints / byte strings / text strings reads back in the
    /// same order with the same values, then lands exactly at end-of-input. This is
    /// the property the <c>.pqss</c> map relies on — every field decodes to what was
    /// written, with no drift in framing between adjacent items.
    /// </summary>
    [Property(MaxTest = 1000, Arbitrary = new[] { typeof(CborSequenceArbitrary) })]
    public void Mixed_sequence_round_trips_in_order(CborSequence seq)
    {
        var w = new CanonicalCborWriter();
        foreach (CborPrim p in seq.Items)
            switch (p)
            {
                case PUInt u: w.WriteUInt(u.V); break;
                case PBytes b: w.WriteByteString(b.B); break;
                case PText t: w.WriteTextString(t.S); break;
            }

        var r = new StrictCborReader(w.ToArray());
        foreach (CborPrim p in seq.Items)
            switch (p)
            {
                case PUInt u: Assert.Equal(u.V, r.ReadUInt()); break;
                case PBytes b: Assert.Equal(b.B, r.ReadByteString()); break;
                case PText t: Assert.Equal(t.S, r.ReadTextString()); break;
            }

        Assert.True(r.AtEnd);
        r.EnsureEnd();
    }

    // ── Canonicity / rejection paths ──────────────────────────────────────────

    /// <summary>
    /// PROPERTY: for every value, encoding it in a <em>wider-than-necessary</em>
    /// integer head (the classic CBOR malleability) is rejected with
    /// <see cref="ShareFormatException"/>. This is the inverse of the round-trip
    /// property: not only does the writer emit shortest form, the reader actively
    /// refuses everything that is not.
    /// </summary>
    [Property(MaxTest = 2000, Arbitrary = new[] { typeof(CborUIntArbitrary) })]
    public void NonShortest_uint_encodings_are_rejected(CborUInt u)
    {
        int minAi = MinimalAdditionalInfo(u.Value);
        foreach (int ai in new[] { 24, 25, 26, 27 })
        {
            if (ai <= minAi)
                continue; // ai == minAi is canonical; ai < minAi would truncate the value

            var raw = new RawCbor();
            raw.UInt(u.Value, forceAi: ai);
            var r = new StrictCborReader(raw.ToArray());
            Assert.Throws<ShareFormatException>(() => r.ReadUInt());
        }
    }

    /// <summary>
    /// PROPERTY: reading any value with the wrong expected major type is rejected. A
    /// uint head (major 0) must not satisfy a byte-string, text-string, or map read.
    /// </summary>
    [Property(MaxTest = 1000, Arbitrary = new[] { typeof(CborUIntArbitrary) })]
    public void Wrong_major_type_is_rejected(CborUInt u)
    {
        byte[] uintBytes = Encode(u.Value);

        Assert.Throws<ShareFormatException>(() => new StrictCborReader(uintBytes).ReadByteString());
        Assert.Throws<ShareFormatException>(() => new StrictCborReader(uintBytes).ReadTextString());
        Assert.Throws<ShareFormatException>(() => new StrictCborReader(uintBytes).ReadMapHeader());
    }

    /// <summary>
    /// PROPERTY: any strict prefix of a valid encoding (a truncated stream) only ever
    /// throws a library <see cref="SecretSharingException"/> — never an
    /// <see cref="IndexOutOfRangeException"/> or other crash. This is the reader-level
    /// fail-closed guarantee, exercised directly on framing rather than through Import.
    /// </summary>
    [Property(MaxTest = 1000, Arbitrary = new[] { typeof(CborSequenceArbitrary) })]
    public void Truncated_stream_only_throws_library_exceptions(CborSequence seq, NonNegativeInt cut)
    {
        var w = new CanonicalCborWriter();
        foreach (CborPrim p in seq.Items)
            switch (p)
            {
                case PUInt u: w.WriteUInt(u.V); break;
                case PBytes b: w.WriteByteString(b.B); break;
                case PText t: w.WriteTextString(t.S); break;
            }
        byte[] full = w.ToArray();
        if (full.Length == 0)
            return;

        byte[] truncated = full[..(cut.Get % full.Length)]; // a strict prefix
        var r = new StrictCborReader(truncated);
        try
        {
            foreach (CborPrim p in seq.Items)
                switch (p)
                {
                    case PUInt: r.ReadUInt(); break;
                    case PBytes: r.ReadByteString(); break;
                    case PText: r.ReadTextString(); break;
                }
            r.EnsureEnd();
        }
        catch (SecretSharingException)
        {
            // Expected: truncation is reported, not crashed on. Any other exception escapes.
        }
    }

    /// <summary>
    /// An indefinite-length head (additional-info 31) is rejected for every major type
    /// the reader supports, as are the reserved additional-info values 28/29/30.
    /// </summary>
    [Fact]
    public void Indefinite_and_reserved_heads_are_rejected()
    {
        foreach (int ai in new[] { 28, 29, 30, 31 })
        {
            Assert.Throws<ShareFormatException>(() => ReadHead(major: 0, ai, r => r.ReadUInt()));
            Assert.Throws<ShareFormatException>(() => ReadHead(major: 2, ai, r => r.ReadByteString()));
            Assert.Throws<ShareFormatException>(() => ReadHead(major: 3, ai, r => r.ReadTextString()));
            Assert.Throws<ShareFormatException>(() => ReadHead(major: 5, ai, r => r.ReadMapHeader()));
        }

        static void ReadHead(int major, int ai, Action<StrictCborReader> read)
        {
            var raw = new RawCbor();
            raw.Head(major, 0, forceAi: ai);
            read(new StrictCborReader(raw.ToArray()));
        }
    }

    // ── Deterministic boundary vectors (RFC 8949 §3 unsigned-integer encodings) ─

    /// <summary>
    /// Pins the exact canonical bytes at every integer-width boundary, both
    /// directions. The property tests prove the round-trip holds; this proves the
    /// concrete encoding is the RFC-correct one (catching a self-consistent but
    /// wrong endianness/width that a round-trip alone would miss).
    /// </summary>
    [Fact]
    public void Canonical_uint_encodings_match_rfc8949_boundaries()
    {
        (ulong value, byte[] encoding)[] vectors =
        {
            (0UL, new byte[] { 0x00 }),
            (23UL, new byte[] { 0x17 }),
            (24UL, new byte[] { 0x18, 0x18 }),
            (255UL, new byte[] { 0x18, 0xFF }),
            (256UL, new byte[] { 0x19, 0x01, 0x00 }),
            (65535UL, new byte[] { 0x19, 0xFF, 0xFF }),
            (65536UL, new byte[] { 0x1A, 0x00, 0x01, 0x00, 0x00 }),
            (4294967295UL, new byte[] { 0x1A, 0xFF, 0xFF, 0xFF, 0xFF }),
            (4294967296UL, new byte[] { 0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }),
            (ulong.MaxValue, new byte[] { 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),
        };

        foreach ((ulong value, byte[] encoding) in vectors)
        {
            Assert.Equal(encoding, Encode(value));

            var r = new StrictCborReader(encoding);
            Assert.Equal(value, r.ReadUInt());
            Assert.True(r.AtEnd);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] Encode(ulong value)
    {
        var w = new CanonicalCborWriter();
        w.WriteUInt(value);
        return w.ToArray();
    }

    /// <summary>The additional-info value of the shortest-form head for <paramref name="value"/>.</summary>
    private static int MinimalAdditionalInfo(ulong value) =>
        value < 24 ? 0
        : value <= byte.MaxValue ? 24
        : value <= ushort.MaxValue ? 25
        : value <= uint.MaxValue ? 26
        : 27;
}
