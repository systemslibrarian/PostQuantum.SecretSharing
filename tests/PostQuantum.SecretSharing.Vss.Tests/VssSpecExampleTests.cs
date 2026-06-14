using PostQuantum.SecretSharing;
using PostQuantum.SecretSharing.Vss;
using Xunit;

namespace PostQuantum.SecretSharing.Vss.Tests;

/// <summary>
/// Pins the byte-exact <c>.pqss</c> v2 / VSS wire format published in
/// <c>docs/SPEC.md</c> (§ v2) and <c>docs/test-vectors-vss.md</c>. Anyone can reproduce
/// these bytes from the fixed secret and the fully-specified <see cref="DeterministicRng"/>
/// (a SHA-256 counter stream). If this test fails, the wire format changed — that is a
/// breaking change and the spec/vectors must change with it.
/// </summary>
public class VssSpecExampleTests
{
    // Fixed inputs (see docs/test-vectors-vss.md "Worked example").
    private const int K = 2, N = 3;
    private const string SecretHex =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

    // Expected canonical records (unsigned broadcast). 32-byte secret ⇒ m=2 chunks.
    private const string CommitmentsHex =
        "AA006A505153532D5653532D43010202010302040305500A932FAE9FD5630126CF712C89B1DA550618" +
        "200702085884021CC34AE98AFE0A80ECB563E7471F7884D07A4117E9AD30501B41F3AFC13B9D730306" +
        "3DF9DBE99735ED2841FFAEA3D6F710790043CBA7E14A7B62B62B7C1205048F02BDC3FC5F2370A240A63" +
        "AA19377092DEF7E49CCFE566D4D063D43D6FCD308CC7B02FE5394E23860940A3E4E53D8CA1EEEB93F9D" +
        "FA5685CC0AD6573888399EF815950900";

    private static readonly string[] ShareHex =
    {
        // SHARE 1
        "AA006A505153532D5653532D530102020103020403050106500A932FAE9FD5630126CF712C89B1DA5507" +
        "18200802095880A2DE39EBDACA0B23F92A8C90D2CBC7303ABBD3E4E2C0222FF03F8753368403991C0FD9" +
        "915CC8BA0AA71F523AF84DF72AC3826440BAD40A70858AC3BB1950A7BCB93D6E1039DB7C02E11A581B72" +
        "BF9DFF3CC31EFDDBA1E5D5E2401A93340A3326CE99E95C5B4B13BE68D1B33466360BB08A9CADB7B10F7D" +
        "5B49C0C7EBE13D3F66",
        // SHARE 2
        "AA006A505153532D5653532D530102020103020403050206500A932FAE9FD5630126CF712C89B1DA5507" +
        "1820080209588045BC72D6B2901140EB4D10179A8B8152A9809C0A0B5490C4D5AD2AC95588C4C36C5DB7" +
        "49AACA1490FAF16149E1CC82A1E7A41C9B56AC12A13DAF02D92A42E4B7727ADC2173B6F804C234B036E5" +
        "7F3BFEBC9F434E102C2D26D0C66A636BB140DCFA0DC0E6830DF3C01148CC5269EB9A61CCB6A0078BD087" +
        "DFE92ED26A2D669C23",
        // SHARE 3
        "AA006A505153532D5653532D530102020103020403050306500A932FAE9FD5630126CF712C89B1DA5507" +
        "18200802095880E89AABC08A56175EDD6F939E624B3B74D52C5EDCDB009DDEAED4990270F0AB3EBCAB95" +
        "01F8CB6F174EC37058CB4B0E190BC5D4F5F2841AD1F5D341F73B3521B22BB84A32AD927406A34F085258" +
        "3ED9FE3C7B679E44B67477BF4CBA33A3584E9225819871AAD0D3C0B9BFE5706DA1291351E997A9BF79F3" +
        "DF94E312257D2CD38F",
    };

    [Fact]
    public void Deterministic_split_matches_the_published_vector()
    {
        byte[] secret = Convert.FromHexString(SecretHex);

        VssSplit split = DeterministicRng.With(() =>
            PedersenVss.Split(secret, new SharePolicy(K, N)));

        Assert.Equal(CommitmentsHex, Convert.ToHexString(split.Commitments.Export()));
        Assert.Equal(N, split.Shares.Length);
        for (int i = 0; i < N; i++)
            Assert.Equal(ShareHex[i], Convert.ToHexString(split.Shares[i].Export()));
    }

    [Fact]
    public void Published_vector_records_parse_verify_and_reconstruct()
    {
        byte[] secret = Convert.FromHexString(SecretHex);
        VssCommitments commitments = VssCommitments.Import(Convert.FromHexString(CommitmentsHex));
        VssShare[] shares = ShareHex.Select(h => VssShare.Import(Convert.FromHexString(h))).ToArray();

        Assert.Equal(K, commitments.Threshold);
        Assert.Equal(N, commitments.TotalShares);
        Assert.False(commitments.IsDealerSigned);
        Assert.All(shares, s => Assert.True(s.Verify(commitments)));

        using ZeroizingBuffer recovered = PedersenVss.Reconstruct(shares.Take(K).ToArray(), commitments);
        Assert.True(recovered.Span.SequenceEqual(secret));
    }
}
