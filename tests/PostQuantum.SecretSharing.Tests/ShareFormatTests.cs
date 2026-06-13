using Xunit;

namespace PostQuantum.SecretSharing.Tests;

/// <summary>
/// The malicious-input corpus for <see cref="SecretShare.Import"/>: each crafted
/// input must be rejected with the specific exception type, before any
/// cryptography runs.
/// </summary>
public class ShareFormatTests
{
    [Fact]
    public void Baseline_ValidUnauthenticatedShare_Imports()
    {
        byte[] bytes = CborCorpus.BuildShare();
        SecretShare s = SecretShare.Import(bytes);
        Assert.Equal(2, s.Threshold);
        Assert.Equal(3, s.TotalShares);
        Assert.Equal(ShareAuthenticationKind.None, s.Authentication);
    }

    // --- Truncation at every length, plus trailing bytes ---

    [Fact]
    public void Truncated_AtEveryLength_Throws()
    {
        byte[] full = CborCorpus.BuildShare();
        for (int len = 0; len < full.Length; len++)
        {
            byte[] cut = full.AsSpan(0, len).ToArray();
            Assert.ThrowsAny<ShareFormatException>(() => SecretShare.Import(cut));
        }
    }

    [Fact]
    public void TrailingByte_Throws()
    {
        byte[] full = CborCorpus.BuildShare();
        byte[] withTrailer = new byte[full.Length + 1];
        full.CopyTo(withTrailer, 0);
        withTrailer[^1] = 0x00;
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(withTrailer));
    }

    // --- Canonicity violations ---

    [Fact]
    public void IndefiniteLengthMap_Throws()
    {
        var w = new RawCbor();
        w.MapHeader(10, forceAi: 31); // indefinite map header
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
    }

    [Fact]
    public void NonAscendingKeys_Throws()
    {
        // Write key 1 before key 0.
        var w = new RawCbor();
        w.MapHeader(10);
        w.UInt(1); w.UInt(1);
        w.UInt(0); w.Text("PQSS");
        // remaining keys (don't matter; rejection happens at key 0)
        w.UInt(2); w.UInt(2);
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
    }

    [Fact]
    public void DuplicateKeys_Throws()
    {
        var w = new RawCbor();
        w.MapHeader(11);
        w.UInt(0); w.Text("PQSS");
        w.UInt(0); w.Text("PQSS"); // duplicate key 0
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
    }

    [Fact]
    public void NonShortestFormInteger_Throws()
    {
        // Encode the version value 1 using a forced 1-byte argument (0x18 0x01)
        // instead of the canonical single-byte 0x01.
        var w = new RawCbor();
        w.MapHeader(10);
        w.UInt(0); w.Text("PQSS");
        w.UInt(1); w.UInt(1, forceAi: 24); // non-shortest
        w.UInt(2); w.UInt(2);
        w.UInt(3); w.UInt(3);
        w.UInt(4); w.UInt(1);
        w.UInt(5); w.Bytes(new byte[16]);
        w.UInt(6); w.UInt(2);
        w.UInt(7); w.Bytes(new byte[] { 0, 1 });
        w.UInt(8); w.Bytes(new byte[32]);
        w.UInt(9); w.UInt(0);
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
    }

    [Fact]
    public void UnknownKey12_Throws()
    {
        byte[] bytes = CborCorpus.BuildShare();
        // Re-build with an extra trailing key 12.
        var w = new RawCbor();
        w.MapHeader(11);
        w.UInt(0); w.Text("PQSS");
        w.UInt(1); w.UInt(1);
        w.UInt(2); w.UInt(2);
        w.UInt(3); w.UInt(3);
        w.UInt(4); w.UInt(1);
        w.UInt(5); w.Bytes(new byte[16]);
        w.UInt(6); w.UInt(2);
        w.UInt(7); w.Bytes(new byte[] { 0, 1 });
        w.UInt(8); w.Bytes(new byte[32]);
        w.UInt(9); w.UInt(0);
        w.UInt(12); w.UInt(0); // unknown key
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
        _ = bytes;
    }

    [Fact]
    public void WrongType_FormatAsUint_Throws()
    {
        var w = new RawCbor();
        w.MapHeader(10);
        w.UInt(0); w.UInt(1234); // format must be text, encoded as uint
        w.UInt(1); w.UInt(1);
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
    }

    [Fact]
    public void WrongType_ThresholdAsBytes_Throws()
    {
        var w = new RawCbor();
        w.MapHeader(10);
        w.UInt(0); w.Text("PQSS");
        w.UInt(1); w.UInt(1);
        w.UInt(2); w.Bytes(new byte[] { 2 }); // threshold must be uint
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
    }

    [Fact]
    public void MissingRequiredKey_Throws()
    {
        // Omit key 6 (secretLength): declare 9 entries, keys 0..5,7,8,9.
        var w = new RawCbor();
        w.MapHeader(9);
        w.UInt(0); w.Text("PQSS");
        w.UInt(1); w.UInt(1);
        w.UInt(2); w.UInt(2);
        w.UInt(3); w.UInt(3);
        w.UInt(4); w.UInt(1);
        w.UInt(5); w.Bytes(new byte[16]);
        w.UInt(7); w.Bytes(new byte[] { 0, 1 });
        w.UInt(8); w.Bytes(new byte[32]);
        w.UInt(9); w.UInt(0);
        Assert.Throws<ShareFormatException>(() => SecretShare.Import(w.ToArray()));
    }

    // --- Field-value / range violations ---

    [Fact]
    public void Format_NotPqss_Throws()
        => Assert.Throws<ShareFormatException>(() => SecretShare.Import(CborCorpus.BuildShare(format: "PQS!")));

    [Fact]
    public void Version2_Throws()
        => Assert.Throws<ShareFormatException>(() => SecretShare.Import(CborCorpus.BuildShare(version: 2)));

    [Fact]
    public void ThresholdOne_Throws_Policy()
        => Assert.Throws<SharePolicyException>(() => SecretShare.Import(CborCorpus.BuildShare(k: 1, n: 3)));

    [Fact]
    public void ThresholdGreaterThanTotal_Throws_Policy()
        => Assert.Throws<SharePolicyException>(() => SecretShare.Import(CborCorpus.BuildShare(k: 4, n: 3)));

    [Fact]
    public void IndexZero_Throws_Policy()
        => Assert.Throws<SharePolicyException>(() => SecretShare.Import(CborCorpus.BuildShare(index: 0)));

    [Fact]
    public void IndexGreaterThanTotal_Throws_Policy()
        => Assert.Throws<SharePolicyException>(() => SecretShare.Import(CborCorpus.BuildShare(index: 9, n: 3)));

    [Fact]
    public void SplitId15Bytes_Throws()
        => Assert.Throws<ShareFormatException>(() => SecretShare.Import(CborCorpus.BuildShare(splitId: new byte[15])));

    [Fact]
    public void SplitId17Bytes_Throws()
        => Assert.Throws<ShareFormatException>(() => SecretShare.Import(CborCorpus.BuildShare(splitId: new byte[17])));

    [Fact]
    public void SecretLengthMismatch_Throws()
        => Assert.Throws<ShareFormatException>(() =>
            SecretShare.Import(CborCorpus.BuildShare(secretLength: 3, shareData: new byte[] { 0, 1 })));

    [Fact]
    public void CheckValueWrongLength_Throws()
        => Assert.Throws<ShareFormatException>(() => SecretShare.Import(CborCorpus.BuildShare(checkValue: new byte[31])));

    [Fact]
    public void AuthAlgorithm2_Throws()
        => Assert.Throws<ShareFormatException>(() => SecretShare.Import(CborCorpus.BuildShare(authAlg: 2)));

    // --- Authentication-mode presence contradictions ---

    [Fact]
    public void AuthNone_WithDealerKeyPresent_Throws()
        => Assert.Throws<ShareFormatException>(() =>
            SecretShare.Import(CborCorpus.BuildShare(authAlg: 0, dealerKey: new byte[1952], signature: new byte[3309])));

    [Fact]
    public void AuthMlDsa_MissingDealerKey_Throws()
        => Assert.Throws<ShareFormatException>(() =>
            SecretShare.Import(CborCorpus.BuildShare(authAlg: 1, dealerKey: null, signature: new byte[3309])));

    [Fact]
    public void AuthMlDsa_MissingSignature_Throws()
        => Assert.Throws<ShareFormatException>(() =>
            SecretShare.Import(CborCorpus.BuildShare(authAlg: 1, dealerKey: new byte[1952], signature: null)));

    [Fact]
    public void AuthMlDsa_ShortDealerKey_Throws()
        => Assert.Throws<ShareFormatException>(() =>
            SecretShare.Import(CborCorpus.BuildShare(authAlg: 1, dealerKey: new byte[1951], signature: new byte[3309])));

    [Fact]
    public void AuthMlDsa_ShortSignature_Throws()
        => Assert.Throws<ShareFormatException>(() =>
            SecretShare.Import(CborCorpus.BuildShare(authAlg: 1, dealerKey: new byte[1952], signature: new byte[3308])));
}
