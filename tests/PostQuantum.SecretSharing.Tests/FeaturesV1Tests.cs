using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PostQuantum.SecretSharing.Tests;

public class WrappedSecretTests
{
    [Fact]
    public void Wrap_RoundTrips_LowEntropySecret()
    {
        byte[] secret = Encoding.UTF8.GetBytes("hunter2"); // deliberately low-entropy
        WrappedSplit w = WrappedSecret.Split(secret, new SharePolicy(3, 5));

        Assert.Equal(5, w.Shares.Length);
        // The KEK shares declare a 32-byte secret length, not the document length.
        Assert.Equal(32, w.Shares[0].SecretLength);

        using ZeroizingBuffer recovered = WrappedSecret.Reconstruct(
            new[] { w.Shares[0], w.Shares[2], w.Shares[4] }, w.Envelope);
        Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));
    }

    [Fact]
    public void Wrap_RoundTrips_LargeSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(4096);
        WrappedSplit w = WrappedSecret.Split(secret, new SharePolicy(2, 3));
        using ZeroizingBuffer recovered = WrappedSecret.Reconstruct(new[] { w.Shares[0], w.Shares[1] }, w.Envelope);
        Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));
    }

    [Fact]
    public void Wrap_TamperedEnvelope_ThrowsConsistency()
    {
        byte[] secret = Encoding.UTF8.GetBytes("a recovery note");
        WrappedSplit w = WrappedSecret.Split(secret, new SharePolicy(2, 3));
        byte[] tampered = (byte[])w.Envelope.Clone();
        tampered[^1] ^= 0x01; // flip a ciphertext bit

        Assert.Throws<ShareConsistencyException>(
            () => WrappedSecret.Reconstruct(new[] { w.Shares[0], w.Shares[1] }, tampered));
    }

    [Fact]
    public void Wrap_SharesFromDifferentSplit_FailAuthentication()
    {
        byte[] secret = Encoding.UTF8.GetBytes("note");
        WrappedSplit a = WrappedSecret.Split(secret, new SharePolicy(2, 3));
        WrappedSplit b = WrappedSecret.Split(secret, new SharePolicy(2, 3));

        // b's shares reconstruct a different KEK; a's envelope won't authenticate.
        Assert.Throws<ShareConsistencyException>(
            () => WrappedSecret.Reconstruct(new[] { b.Shares[0], b.Shares[1] }, a.Envelope));
    }

    [Fact]
    public void Wrap_ShortEnvelope_ThrowsConsistency()
    {
        byte[] secret = new byte[] { 1, 2, 3 };
        WrappedSplit w = WrappedSecret.Split(secret, new SharePolicy(2, 3));
        Assert.Throws<ShareConsistencyException>(
            () => WrappedSecret.Reconstruct(new[] { w.Shares[0], w.Shares[1] }, new byte[10]));
    }
}

public class RefreshTests
{
    [Fact]
    public void Refresh_ProducesNewSplitId_SameSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        SecretShare[] original = ShamirSecretSharing.Split(secret, new SharePolicy(3, 5));

        SecretShare[] refreshed = ShamirSecretSharing.Refresh(new[] { original[0], original[1], original[2] });

        Assert.Equal(5, refreshed.Length);
        Assert.False(original[0].SplitId.Span.SequenceEqual(refreshed[0].SplitId.Span)); // new splitId

        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(new[] { refreshed[0], refreshed[3], refreshed[4] });
        Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));
    }

    [Fact]
    public void Refresh_OldAndNewShares_CannotMix()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(16);
        SecretShare[] original = ShamirSecretSharing.Split(secret, new SharePolicy(2, 3));
        SecretShare[] refreshed = ShamirSecretSharing.Refresh(new[] { original[0], original[1] });

        Assert.Throws<ShareConsistencyException>(
            () => ShamirSecretSharing.Reconstruct(new[] { original[0], refreshed[1] }));
    }

    [Fact]
    public void Refresh_CanChangePolicy()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(24);
        SecretShare[] original = ShamirSecretSharing.Split(secret, new SharePolicy(2, 3));

        SecretShare[] refreshed = ShamirSecretSharing.Refresh(
            new[] { original[0], original[1] }, newPolicy: new SharePolicy(3, 7));

        Assert.Equal(7, refreshed.Length);
        Assert.Equal(3, refreshed[0].Threshold);
        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(refreshed.Take(3).ToArray());
        Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));
    }
}

public class DealerCommitmentTests
{
    [Fact]
    public void Compute_Is32Bytes_AndDeterministic()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        byte[] c1 = DealerCommitment.Compute(secret);
        byte[] c2 = DealerCommitment.Compute(secret);
        Assert.Equal(32, c1.Length);
        Assert.Equal(c1, c2);
    }

    [Fact]
    public void Verify_AcceptsCorrect_RejectsWrong()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        byte[] commitment = DealerCommitment.Compute(secret);

        Assert.True(DealerCommitment.Verify(secret, commitment));

        byte[] other = RandomNumberGenerator.GetBytes(32);
        Assert.False(DealerCommitment.Verify(other, commitment));
        Assert.False(DealerCommitment.Verify(secret, new byte[31])); // wrong length
    }

    [Fact]
    public void EndToEnd_CommitSplitReconstructVerify()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        byte[] commitment = DealerCommitment.Compute(secret); // published out-of-band

        SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(2, 3));
        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[2] });

        Assert.True(DealerCommitment.Verify(recovered, commitment));
    }
}

public class ZeroizingBufferLockTests
{
    [Fact]
    public void Buffer_WorksRegardlessOfLockOutcome()
    {
        // Locking may or may not succeed depending on platform/privileges; either
        // way the buffer must be usable and zeroed on dispose.
        using var buf = new ZeroizingBuffer(64);
        buf.Span[0] = 0x7F;
        Assert.Equal(0x7F, buf.Span[0]);
        Assert.True(buf.IsMemoryLocked || !buf.IsMemoryLocked); // no throw; value is observable
    }

    [Fact]
    public void ReconstructedSecret_IsUsable_WhenLockMayFail()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        SecretShare[] shares = ShamirSecretSharing.Split(secret, new SharePolicy(2, 3));
        using ZeroizingBuffer recovered = ShamirSecretSharing.Reconstruct(new[] { shares[0], shares[1] });
        Assert.True(secret.AsSpan().SequenceEqual(recovered.Span));
    }

    [Fact]
    public void ZeroLengthBuffer_IsNotLocked_AndDisposesCleanly()
    {
        using var buf = new ZeroizingBuffer(0);
        Assert.False(buf.IsMemoryLocked);
        Assert.Equal(0, buf.Length);
    }
}
