using System.Security.Cryptography;
using PostQuantum.SecretSharing.Vss.Internal;

namespace PostQuantum.SecretSharing.Vss.Tests;

/// <summary>
/// A deterministic, fully-specified byte stream used ONLY to produce the published
/// reference vectors (docs/test-vectors-vss.md, docs/SPEC.md §v2). It is a SHA-256
/// counter stream so any third party can reproduce the exact vector bytes:
/// <code>
///   seed       = SHA-256("PostQuantum.SecretSharing/vss/test-vectors/v1")
///   block(i)   = SHA-256(seed || be32(i))      // i = 0, 1, 2, …
///   stream     = block(0) ‖ block(1) ‖ block(2) ‖ …
/// </code>
/// Bytes are consumed left-to-right across every <see cref="Fill"/> call in draw order.
/// This is a TEST artifact; production uses only the system CSPRNG (KNOWN-GAPS §7).
/// </summary>
internal sealed class DeterministicRng
{
    private readonly byte[] _seed;
    private byte[] _block = Array.Empty<byte>();
    private uint _blockIndex;
    private int _offset;

    internal DeterministicRng()
    {
        _seed = SHA256.HashData(
            System.Text.Encoding.ASCII.GetBytes("PostQuantum.SecretSharing/vss/test-vectors/v1"));
        _offset = _block.Length; // force first block on first use
    }

    internal void Fill(Span<byte> destination)
    {
        Span<byte> ctr = stackalloc byte[4];
        for (int i = 0; i < destination.Length; i++)
        {
            if (_offset >= _block.Length)
            {
                BinaryPrimitivesWriteBe(ctr, _blockIndex++);
                _block = SHA256.HashData(Concat(_seed, ctr));
                _offset = 0;
            }
            destination[i] = _block[_offset++];
        }
    }

    /// <summary>Installs this RNG as the VSS seam, runs <paramref name="body"/>, then restores the CSPRNG.</summary>
    internal static T With<T>(Func<T> body)
    {
        var rng = new DeterministicRng();
        Secp256r1Group.RandomFill previous = Secp256r1Group.FillRandom;
        Secp256r1Group.FillRandom = rng.Fill;
        try { return body(); }
        finally { Secp256r1Group.FillRandom = previous; }
    }

    private static void BinaryPrimitivesWriteBe(Span<byte> dst, uint value)
    {
        dst[0] = (byte)(value >> 24);
        dst[1] = (byte)(value >> 16);
        dst[2] = (byte)(value >> 8);
        dst[3] = (byte)value;
    }

    private static byte[] Concat(byte[] a, ReadOnlySpan<byte> b)
    {
        byte[] r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r.AsSpan(a.Length));
        return r;
    }
}
