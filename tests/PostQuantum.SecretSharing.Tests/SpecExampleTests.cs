using Xunit;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// Pins the worked hex example documented in docs/SPEC.md: a minimal k=2, n=3,
/// 4-byte-secret, unauthenticated share. If this test fails, the SPEC example is
/// wrong and must be updated.
/// </summary>
public class SpecExampleTests
{
    // The exact canonical bytes annotated in docs/SPEC.md.
    public const string SpecHex =
        "aa" +                                   // map(10)
        "00" + "6450515353" +                    // 0: "PQSS"
        "01" + "01" +                            // 1: version 1
        "02" + "02" +                            // 2: k = 2
        "03" + "03" +                            // 3: n = 3
        "04" + "01" +                            // 4: index = 1
        "05" + "50" + "000102030405060708090a0b0c0d0e0f" + // 5: splitId (16 bytes)
        "06" + "04" +                            // 6: secretLength = 4
        "07" + "44" + "aabbccdd" +               // 7: shareData (4 bytes)
        "08" + "5820" + "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf" + // 8: checkValue (32 bytes)
        "09" + "00";                             // 9: authAlgorithm = 0 (none)

    [Fact]
    public void SpecWorkedExample_Imports_WithExpectedFields()
    {
        byte[] bytes = Convert.FromHexString(SpecHex);
        SecretShare s = SecretShare.Import(bytes);

        Assert.Equal(2, s.Threshold);
        Assert.Equal(3, s.TotalShares);
        Assert.Equal(1, s.ShareIndex);
        Assert.Equal(4, s.SecretLength);
        Assert.Equal(ShareAuthenticationKind.None, s.Authentication);
        Assert.True(s.DealerPublicKey.IsEmpty);
        Assert.Equal(
            Convert.FromHexString("000102030405060708090a0b0c0d0e0f"),
            s.SplitId.ToArray());

        // Re-export must be byte-identical to the documented bytes (canonical).
        Assert.Equal(bytes, s.Export());
    }
}
