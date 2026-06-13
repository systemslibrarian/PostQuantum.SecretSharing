using PostQuantum.SecretSharing.Cbor;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// Property-based and fuzz tests for the strict CBOR layer. The core invariant of
/// a fail-closed parser: <em>no</em> input — however malformed — may produce an
/// exception other than a <see cref="SecretSharingException"/>, and a canonical
/// encoding must round-trip byte-identically.
/// </summary>
public class CborPropertyTests
{
    // Deterministic so any failure is reproducible; the failing input is printed.
    private const int Seed = 0x50_51_53_53;

    /// <summary>
    /// FUZZ: arbitrary byte sequences fed to <see cref="SecretShare.Import"/> must
    /// only ever throw a library exception (never a crash like
    /// <see cref="IndexOutOfRangeException"/>, <see cref="OverflowException"/>, …).
    /// </summary>
    [Fact]
    public void Import_OfArbitraryBytes_OnlyThrowsLibraryExceptions()
    {
        var rng = new Random(Seed);
        for (int iter = 0; iter < 50_000; iter++)
        {
            int len = rng.Next(0, 256);
            byte[] input = new byte[len];
            rng.NextBytes(input);
            AssertImportNeverCrashes(input, iter);
        }
    }

    /// <summary>
    /// FUZZ: a few CBOR-shaped maps with random key counts, keys, and value types —
    /// closer to the real format, so it exercises deeper code paths than pure noise.
    /// </summary>
    [Fact]
    public void Import_OfRandomCborMaps_OnlyThrowsLibraryExceptions()
    {
        var rng = new Random(Seed + 1);
        for (int iter = 0; iter < 30_000; iter++)
        {
            var w = new RawCbor();
            int count = rng.Next(0, 16);
            w.MapHeader(count);
            for (int e = 0; e < count; e++)
            {
                w.UInt((ulong)rng.Next(0, 20));        // key (maybe out of range / unordered)
                switch (rng.Next(0, 4))
                {
                    case 0: w.UInt((ulong)rng.Next(0, 1000)); break;
                    case 1: w.Bytes(RandomBytes(rng, rng.Next(0, 40))); break;
                    case 2: w.Text(RandomAscii(rng, rng.Next(0, 8))); break;
                    case 3: w.UInt((ulong)rng.Next(0, 300), forceAi: 24); break; // sometimes non-canonical
                }
            }
            AssertImportNeverCrashes(w.ToArray(), iter);
        }
    }

    /// <summary>
    /// FUZZ: take a valid canonical share and flip/insert/delete a few bytes. The
    /// result must either parse (rarely) or throw a library exception — never crash.
    /// </summary>
    [Fact]
    public void Import_OfMutatedValidShare_OnlyThrowsLibraryExceptions()
    {
        var rng = new Random(Seed + 2);
        byte[] valid = CborCorpus.BuildShare(
            k: 3, n: 5, index: 2, secretLength: 16, shareData: RandomBytes(rng, 16));

        for (int iter = 0; iter < 30_000; iter++)
        {
            byte[] m = (byte[])valid.Clone();
            int mutations = rng.Next(1, 4);
            for (int x = 0; x < mutations && m.Length > 0; x++)
                m[rng.Next(m.Length)] ^= (byte)(1 << rng.Next(8));
            AssertImportNeverCrashes(m, iter);
        }
    }

    /// <summary>
    /// FUZZ: drive the low-level reader with a random sequence of typed reads over
    /// random bytes. It must only ever throw <see cref="ShareFormatException"/>.
    /// </summary>
    [Fact]
    public void StrictReader_OnRandomBytes_OnlyThrowsShareFormatException()
    {
        var rng = new Random(Seed + 3);
        for (int iter = 0; iter < 50_000; iter++)
        {
            byte[] input = RandomBytes(rng, rng.Next(0, 64));
            var reader = new StrictCborReader(input);
            try
            {
                int ops = rng.Next(1, 6);
                for (int o = 0; o < ops; o++)
                {
                    switch (rng.Next(0, 5))
                    {
                        case 0: reader.ReadMapHeader(); break;
                        case 1: reader.ReadUInt(); break;
                        case 2: reader.ReadByteString(); break;
                        case 3: reader.ReadTextString(); break;
                        case 4: reader.EnsureEnd(); break;
                    }
                }
            }
            catch (ShareFormatException) { /* the only permitted failure */ }
            catch (Exception ex)
            {
                Assert.Fail($"[iter {iter}] StrictCborReader threw {ex.GetType().Name} on " +
                            $"{Convert.ToHexString(input)}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// PROPERTY: any canonically-built share round-trips byte-identically through
    /// Import → Export, and a re-Import is stable. Covers unauthenticated and
    /// authenticated (correctly-sized) shares across many random valid parameters.
    /// </summary>
    [Fact]
    public void CanonicalShare_RoundTrips_ByteIdentically()
    {
        var rng = new Random(Seed + 4);
        for (int iter = 0; iter < 2_000; iter++)
        {
            int k = rng.Next(2, 256);
            int n = rng.Next(k, 256);
            int index = rng.Next(1, n + 1);
            int secretLen = rng.Next(1, 65);
            bool authed = rng.Next(0, 2) == 1;

            byte[] bytes = CborCorpus.BuildShare(
                k: (ulong)k, n: (ulong)n, index: (ulong)index,
                splitId: RandomBytes(rng, 16),
                secretLength: (ulong)secretLen,
                shareData: RandomBytes(rng, secretLen),
                checkValue: RandomBytes(rng, 32),
                authAlg: authed ? 1u : 0u,
                dealerKey: authed ? RandomBytes(rng, 1952) : null,
                signature: authed ? RandomBytes(rng, 3309) : null);

            SecretShare s = SecretShare.Import(bytes);
            byte[] exported = s.Export();
            Assert.True(bytes.AsSpan().SequenceEqual(exported),
                $"[iter {iter}] Export differed from canonical input for k={k} n={n} idx={index} len={secretLen} auth={authed}");

            // Re-import the export: stable.
            byte[] exported2 = SecretShare.Import(exported).Export();
            Assert.Equal(exported, exported2);
        }
    }

    private static void AssertImportNeverCrashes(byte[] input, int iter)
    {
        try
        {
            SecretShare.Import(input);
        }
        catch (SecretSharingException) { /* ShareFormatException / SharePolicyException are expected */ }
        catch (Exception ex)
        {
            Assert.Fail($"[iter {iter}] Import threw non-library {ex.GetType().Name} on " +
                        $"{Convert.ToHexString(input)}: {ex.Message}");
        }
    }

    private static byte[] RandomBytes(Random rng, int len)
    {
        byte[] b = new byte[len];
        rng.NextBytes(b);
        return b;
    }

    private static string RandomAscii(Random rng, int len)
    {
        char[] c = new char[len];
        for (int i = 0; i < len; i++) c[i] = (char)rng.Next(0x20, 0x7F);
        return new string(c);
    }
}
