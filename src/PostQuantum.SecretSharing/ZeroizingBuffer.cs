using System.Runtime.InteropServices;
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
/// <b>Best-effort page-locking.</b> On construction the buffer is locked into RAM
/// (<c>VirtualLock</c> on Windows, <c>mlock</c> on Linux/macOS) to resist being
/// paged to swap, and unlocked on disposal. This is best-effort:
/// <see cref="IsMemoryLocked"/> reports whether it succeeded — it can fail without
/// privileges or when the per-process locked-memory limit is reached, in which
/// case the buffer still works, just unlocked.
/// </para>
/// <para>
/// <b>Still out of scope.</b> Locking resists swap but does not defend against a
/// process memory dump. The secret necessarily exists in cleartext in process
/// memory while it is in use. See KNOWN-GAPS.md.
/// </para>
/// </remarks>
public sealed class ZeroizingBuffer : IDisposable
{
    private readonly byte[] _buffer;
    private GCHandle _pin;
    private readonly bool _locked;
    private bool _disposed;

    /// <summary>
    /// Allocates a pinned, zero-initialized buffer of the given length and attempts
    /// to lock it into RAM (best-effort; see <see cref="IsMemoryLocked"/>).
    /// </summary>
    /// <param name="length">Buffer length in bytes; must be non-negative.</param>
    /// <exception cref="ArgumentOutOfRangeException">If <paramref name="length"/> is negative.</exception>
    public ZeroizingBuffer(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        _buffer = GC.AllocateArray<byte>(length, pinned: true);
        if (length > 0)
        {
            // The array is already pinned on the POH; this handle just yields a
            // stable address for the lock/unlock calls.
            _pin = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
            _locked = MemoryLock.TryLock(_pin.AddrOfPinnedObject(), (nuint)length);
        }
    }

    /// <summary>
    /// Whether the backing pages were successfully locked into RAM. False is not an
    /// error — the buffer is fully functional, just not protected from swap.
    /// </summary>
    public bool IsMemoryLocked => _locked;

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
        ReleaseUnmanaged();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Best-effort finalizer backstop: if a caller forgets to dispose, zero and
    /// unlock the buffer when the object is collected. This is not a substitute for
    /// explicit disposal (the window between last use and collection is unbounded)
    /// and is documented as best-effort in KNOWN-GAPS.md.
    /// </summary>
    ~ZeroizingBuffer()
    {
        if (!_disposed)
            ReleaseUnmanaged();
    }

    /// <summary>Zeroes the buffer, unlocks the pages, and frees the pinning handle.</summary>
    private void ReleaseUnmanaged()
    {
        CryptographicOperations.ZeroMemory(_buffer);   // wipe while still locked
        if (_pin.IsAllocated)
        {
            if (_locked)
                MemoryLock.Unlock(_pin.AddrOfPinnedObject(), (nuint)_buffer.Length);
            _pin.Free();
        }
    }
}
