using System.Runtime.InteropServices;

namespace PostQuantum.SecretSharing;

/// <summary>
/// Best-effort OS page-locking so a secret buffer is not written to swap. Locking
/// can fail without privileges or when the per-process locked-memory limit is
/// exceeded; callers treat failure as non-fatal and simply continue unlocked.
/// </summary>
internal static partial class MemoryLock
{
    /// <summary>Attempts to lock the given region into RAM. Returns true on success.</summary>
    internal static bool TryLock(IntPtr address, nuint length)
    {
        if (length == 0)
            return false;
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return VirtualLock(address, length) != 0;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return mlock(address, length) == 0;
        }
        catch (DllNotFoundException) { /* fall through: unsupported */ }
        catch (EntryPointNotFoundException) { /* fall through: unsupported */ }
        return false;
    }

    /// <summary>Unlocks a previously locked region (best-effort).</summary>
    internal static void Unlock(IntPtr address, nuint length)
    {
        if (length == 0)
            return;
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                _ = VirtualUnlock(address, length);
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                _ = munlock(address, length);
        }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int VirtualLock(IntPtr address, nuint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int VirtualUnlock(IntPtr address, nuint size);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int mlock(IntPtr address, nuint length);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int munlock(IntPtr address, nuint length);
}
