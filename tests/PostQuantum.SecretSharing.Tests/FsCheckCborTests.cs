using FsCheck;
using FsCheck.Xunit;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// Property-based tests for the CBOR layer using FsCheck, which adds automatic
/// <b>shrinking</b>: when a property fails, FsCheck minimizes the offending input
/// to the smallest reproducer rather than dumping a giant random blob. These
/// complement the deterministic loops in <see cref="CborPropertyTests"/>.
/// </summary>
public class FsCheckCborTests
{
    /// <summary>
    /// The core fail-closed invariant: <see cref="SecretShare.Import"/> may throw a
    /// <see cref="SecretSharingException"/> on any input, but never a non-library
    /// exception (no crash). FsCheck shrinks any counterexample to a minimal byte
    /// array. <c>byte[]</c> has a built-in generator and shrinker.
    /// </summary>
    [Property(MaxTest = 5000)]
    public void Import_of_arbitrary_bytes_only_throws_library_exceptions(byte[] input)
    {
        try
        {
            SecretShare.Import(input);
        }
        catch (SecretSharingException)
        {
            // ShareFormatException / SharePolicyException are the contract.
        }
        // Any other exception escapes → FsCheck records and shrinks it.
    }

    /// <summary>
    /// Same invariant, but inputs are biased toward <em>well-formed CBOR maps with
    /// deliberately wrong contents</em> (bad key order, duplicate keys, wrong types,
    /// non-canonical integers, out-of-range fields, mode contradictions, trailing
    /// bytes, indefinite headers). The model carries a shrinker, so failures
    /// minimize to a small map.
    /// </summary>
    [Property(MaxTest = 5000, Arbitrary = new[] { typeof(CborModelArbitrary) })]
    public void Import_of_structured_cbor_only_throws_library_exceptions(CborModel model)
    {
        byte[] bytes = model.Encode();
        try
        {
            SecretShare.Import(bytes);
        }
        catch (SecretSharingException)
        {
        }
    }

    /// <summary>
    /// PROPERTY: any canonically-built valid share round-trips byte-identically
    /// through Import → Export, across the full parameter space. Shrinking on the
    /// k/n/index/length parameters pinpoints any failing shape.
    /// </summary>
    [Property(MaxTest = 1000, Arbitrary = new[] { typeof(ValidShareArbitrary) })]
    public void Valid_share_round_trips_byte_identically(ValidShare share)
    {
        SecretShare imported = SecretShare.Import(share.Bytes);
        Assert.Equal(share.Bytes, imported.Export());
    }

    /// <summary>
    /// PROPERTY: a valid share with one structural mutation applied either still
    /// imports (rare) or throws a library exception — never crashes. The mutation
    /// kind/position/value are FsCheck-generated and shrink.
    /// </summary>
    [Property(MaxTest = 5000, Arbitrary = new[] { typeof(MutatedShareArbitrary) })]
    public void Mutated_valid_share_only_throws_library_exceptions(MutatedShare m)
    {
        try
        {
            SecretShare.Import(m.Bytes);
        }
        catch (SecretSharingException)
        {
        }
    }
}
