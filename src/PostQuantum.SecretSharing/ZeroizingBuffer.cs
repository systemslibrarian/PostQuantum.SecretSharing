using System.Security.Cryptography;

namespace PostQuantum.SecretSharing;

/// <summary>
/// A fixed-size byte buffer for secret material that is zeroed on disposal and
/// is allocated on the pinned object heap so the garbage collector can never
/// relocate (and thus silently copy) the secret elsewhere in memory.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why pinned allocation.</b> A normal managed array can be moved by a
/// compacting GC, leaving a stale copy of the secret in the old location that
/// <see cref="CryptographicOperations.ZeroMemory"/> on the live array will never
/// reach. <see cref="GC.AllocateArray{T}(int, bool)"/> with <c>pinned: true</c>
/// places the backing array on the pinned object heap, which is never compacted,
/// so the bytes we zero are the only copy the GC ever made.
/// </para>
/// <para>
/// <b>Out of scope.</b> Pinning prevents GC copies; it does not prevent the OS
/// from paging the buffer to disk (swap), nor does it defend against a process
/// memory dump. Page-locking (<c>mlock</c>/<c>VirtualLock</c>) is not implemented
/// in v1 — see KNOWN-GAPS.md. The secret necessarily exists in cleartext in
/// process memory while it is in use.
/// </para>
/// </remarks>
public sealed class ZeroizingBuffer : IDisposable
{
    private readonly byte[] _buffer;
    private bool _disposed;

    /// <summary>
    /// Allocates a pinned, zero-initialized buffer of the given length.
    /// </summary>
    /// <param name="length">Buffer length in bytes; must be non-negative.</param>
    /// <exception cref="ArgumentOutOfRangeException">If <paramref name="length"/> is negative.</exception>
    public ZeroizingBuffer(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        _buffer = GC.AllocateArray<byte>(length, pinned: true);
    }

    /// <summary>The buffer length in bytes. Remains valid after disposal.</summary>
    public int Length => _buffer.Length;

    /// <summary>
    /// A writable view over the secret bytes.
    /// </summary>
    /// <exception cref="ObjectDisposedException">If the buffer has been disposed.</exception>
    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    /// <summary>
    /// Internal accessor used only by tests (via <c>InternalsVisibleTo</c>) to
    /// assert the backing array is zeroed after disposal.
    /// </summary>
    internal byte[] UnsafeBackingArray => _buffer;

    /// <summary>
    /// Zeroes the buffer and marks it disposed. Idempotent: calling more than
    /// once is safe and does nothing after the first call.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        CryptographicOperations.ZeroMemory(_buffer);
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Best-effort finalizer backstop: if a caller forgets to dispose, zero the
    /// buffer when the object is collected. This is not a substitute for explicit
    /// disposal (the window between last use and collection is unbounded) and is
    /// documented as best-effort in KNOWN-GAPS.md.
    /// </summary>
    ~ZeroizingBuffer()
    {
        if (!_disposed)
            CryptographicOperations.ZeroMemory(_buffer);
    }
}
