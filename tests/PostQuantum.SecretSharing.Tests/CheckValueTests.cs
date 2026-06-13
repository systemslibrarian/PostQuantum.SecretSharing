using Xunit;

namespace PostQuantum.SecretSharing.Tests;

public class CheckValueTests
{
    [Fact]
    public void CheckValue_MatchesReferenceVectors()
    {
        foreach (CheckValueVector v in Vectors.File.CheckValue)
        {
            byte[] secret = Vectors.Hex(v.Secret);
            byte[] splitId = Vectors.Hex(v.SplitId);
            byte[] expected = Vectors.Hex(v.CheckValue);

            byte[] actual = ShamirSecretSharing.ComputeCheckValue(secret, splitId);
            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void CheckValue_Is32Bytes_AndDeterministic()
    {
        byte[] secret = Convert.FromHexString("00112233445566778899aabbccddeeff");
        byte[] salt = new byte[16];
        byte[] a = ShamirSecretSharing.ComputeCheckValue(secret, salt);
        byte[] b = ShamirSecretSharing.ComputeCheckValue(secret, salt);
        Assert.Equal(32, a.Length);
        Assert.Equal(a, b);
    }
}
