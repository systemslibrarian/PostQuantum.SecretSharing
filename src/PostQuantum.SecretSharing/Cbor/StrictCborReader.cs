using System.Buffers.Binary;
using System.Text;

namespace PostQuantum.SecretSharing.Cbor;

/// <summary>
/// A minimal, read-only CBOR decoder that accepts <em>only</em> the strict
/// canonical subset used by the <c>.pqss</c> format: definite-length maps
/// (major type 5), unsigned integers (major type 0), byte strings (major type
/// 2), and text strings (major type 3).
/// </summary>
/// <remarks>
/// Every deviation from RFC 8949 §4.2.1 canonical form is rejected with
/// <see cref="ShareFormatException"/>: indefinite lengths, non-shortest integer
/// heads, reserved additional-info values, truncation, and any disallowed major
/// type (negative integers, arrays, tags, floats, simple values). Map-key
/// ordering and the schema itself are enforced by the caller; this reader
/// provides only validated, canonical primitive reads plus end-of-input
/// checking.
/// </remarks>
internal sealed class StrictCborReader
{
    private readonly ReadOnlyMemory<byte> _data;
    private int _pos;

    internal StrictCborReader(ReadOnlySpan<byte> data)
    {
        _data = data.ToArray();
        _pos = 0;
    }

    /// <summary>Current read offset, for diagnostic messages (never echoes content).</summary>
    internal int Position => _pos;

    /// <summary>True if all input has been consumed.</summary>
    internal bool AtEnd => _pos >= _data.Length;

    /// <summary>Reads a definite-length map header and returns its entry count.</summary>
    internal int ReadMapHeader()
    {
        ulong arg = ReadHead(expectedMajor: 5);
        if (arg > int.MaxValue)
            throw new ShareFormatException($"Map length too large at offset {_pos}.");
        return (int)arg;
    }

    /// <summary>Reads a canonical unsigned integer (major type 0).</summary>
    internal ulong ReadUInt() => ReadHead(expectedMajor: 0);

    /// <summary>Reads a definite-length byte string (major type 2).</summary>
    internal byte[] ReadByteString()
    {
        ulong len = ReadHead(expectedMajor: 2);
        return ReadBytes(len);
    }

    /// <summary>Reads a definite-length UTF-8 text string (major type 3).</summary>
    internal string ReadTextString()
    {
        ulong len = ReadHead(expectedMajor: 3);
        byte[] raw = ReadBytes(len);
        try
        {
            // Reject overlong/invalid UTF-8 by using a strict decoder.
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(raw);
        }
        catch (DecoderFallbackException ex)
        {
            throw new ShareFormatException($"Invalid UTF-8 in text string ending at offset {_pos}.", ex);
        }
    }

    /// <summary>Throws unless every input byte has been consumed (no trailing data).</summary>
    internal void EnsureEnd()
    {
        if (!AtEnd)
            throw new ShareFormatException(
                $"Trailing bytes after top-level value: {_data.Length - _pos} unexpected byte(s) at offset {_pos}.");
    }

    /// <summary>
    /// Reads and validates a CBOR head, enforcing the expected major type,
    /// definite length, and shortest-form encoding. Returns the head argument.
    /// </summary>
    private ulong ReadHead(int expectedMajor)
    {
        if (_pos >= _data.Length)
            throw new ShareFormatException($"Unexpected end of input at offset {_pos}.");

        byte ib = _data.Span[_pos++];
        int major = ib >> 5;
        int ai = ib & 0x1F;

        if (major != expectedMajor)
            throw new ShareFormatException(
                $"Expected CBOR major type {expectedMajor} but found {major} at offset {_pos - 1}.");

        if (ai < 24)
            return (ulong)ai; // single-byte head is always shortest form

        switch (ai)
        {
            case 24:
            {
                byte v = ReadRaw(1)[0];
                if (v < 24)
                    throw NonShortest();
                return v;
            }
            case 25:
            {
                ushort v = BinaryPrimitives.ReadUInt16BigEndian(ReadRaw(2));
                if (v <= byte.MaxValue)
                    throw NonShortest();
                return v;
            }
            case 26:
            {
                uint v = BinaryPrimitives.ReadUInt32BigEndian(ReadRaw(4));
                if (v <= ushort.MaxValue)
                    throw NonShortest();
                return v;
            }
            case 27:
            {
                ulong v = BinaryPrimitives.ReadUInt64BigEndian(ReadRaw(8));
                if (v <= uint.MaxValue)
                    throw NonShortest();
                return v;
            }
            case 31:
                throw new ShareFormatException(
                    $"Indefinite-length encoding is not allowed at offset {_pos - 1}.");
            default: // 28, 29, 30 are reserved
                throw new ShareFormatException(
                    $"Reserved CBOR additional-info value {ai} at offset {_pos - 1}.");
        }

        ShareFormatException NonShortest() => new(
            $"Non-canonical integer: value is not encoded in shortest form at offset {_pos}.");
    }

    private ReadOnlySpan<byte> ReadRaw(int count)
    {
        if (_pos + count > _data.Length)
            throw new ShareFormatException($"Unexpected end of input reading {count} byte(s) at offset {_pos}.");
        var slice = _data.Span.Slice(_pos, count);
        _pos += count;
        return slice;
    }

    private byte[] ReadBytes(ulong len)
    {
        if (len > int.MaxValue || _pos + (int)len > _data.Length)
            throw new ShareFormatException($"String length exceeds available input at offset {_pos}.");
        byte[] result = _data.Span.Slice(_pos, (int)len).ToArray();
        _pos += (int)len;
        return result;
    }
}
