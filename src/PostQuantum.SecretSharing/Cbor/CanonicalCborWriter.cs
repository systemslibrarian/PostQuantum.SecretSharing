using System.Buffers.Binary;
using System.Text;

namespace PostQuantum.SecretSharing.Cbor;

/// <summary>
/// A minimal, write-only CBOR encoder that emits <em>only</em> the strict
/// canonical subset used by the <c>.pqss</c> format (RFC 8949 §4.2.1):
/// definite-length maps (major type 5), unsigned integers (major type 0),
/// byte strings (major type 2), and text strings (major type 3). Every integer
/// head is written in shortest form.
/// </summary>
/// <remarks>
/// Callers must write map entries with integer keys in ascending order; for the
/// fixed <c>.pqss</c> key set (0..11, all single-byte) ascending numeric order
/// is exactly canonical bytewise order. There is no support for arrays, tags,
/// floats, simple values, negative integers, indefinite lengths, or nesting:
/// the format does not use them, so the encoder cannot emit them.
/// </remarks>
internal sealed class CanonicalCborWriter
{
    private readonly List<byte> _buffer = new(64);

    /// <summary>Writes a definite-length map header for <paramref name="count"/> entries (major type 5).</summary>
    internal void WriteMapHeader(int count) => WriteHead(5, (ulong)count);

    /// <summary>Writes an unsigned integer in shortest form (major type 0).</summary>
    internal void WriteUInt(ulong value) => WriteHead(0, value);

    /// <summary>Writes a definite-length byte string (major type 2).</summary>
    internal void WriteByteString(ReadOnlySpan<byte> value)
    {
        WriteHead(2, (ulong)value.Length);
        foreach (byte b in value)
            _buffer.Add(b);
    }

    /// <summary>Writes a definite-length UTF-8 text string (major type 3).</summary>
    internal void WriteTextString(string value)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(value);
        WriteHead(3, (ulong)utf8.Length);
        _buffer.AddRange(utf8);
    }

    /// <summary>Returns the encoded bytes.</summary>
    internal byte[] ToArray() => _buffer.ToArray();

    /// <summary>
    /// Writes a CBOR head: the major type in the high three bits followed by the
    /// shortest-form encoding of <paramref name="argument"/>.
    /// </summary>
    private void WriteHead(int majorType, ulong argument)
    {
        int m = majorType << 5;
        if (argument < 24)
        {
            _buffer.Add((byte)(m | (int)argument));
        }
        else if (argument <= byte.MaxValue)
        {
            _buffer.Add((byte)(m | 24));
            _buffer.Add((byte)argument);
        }
        else if (argument <= ushort.MaxValue)
        {
            _buffer.Add((byte)(m | 25));
            Span<byte> tmp = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(tmp, (ushort)argument);
            _buffer.AddRange(tmp.ToArray());
        }
        else if (argument <= uint.MaxValue)
        {
            _buffer.Add((byte)(m | 26));
            Span<byte> tmp = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(tmp, (uint)argument);
            _buffer.AddRange(tmp.ToArray());
        }
        else
        {
            _buffer.Add((byte)(m | 27));
            Span<byte> tmp = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(tmp, argument);
            _buffer.AddRange(tmp.ToArray());
        }
    }
}
