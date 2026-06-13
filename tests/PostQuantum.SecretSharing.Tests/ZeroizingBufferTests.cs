using Xunit;

namespace PostQuantum.SecretSharing.Tests;

public class ZeroizingBufferTests
{
    [Fact]
    public void Span_AfterDispose_Throws()
    {
        var buf = new ZeroizingBuffer(16);
        buf.Span[0] = 1;
        buf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = buf.Span; });
    }

    [Fact]
    public void DoubleDispose_IsSafe()
    {
        var buf = new ZeroizingBuffer(8);
        buf.Dispose();
        buf.Dispose(); // must not throw
    }

    [Fact]
    public void Length_RemainsValid_AfterDispose()
    {
        var buf = new ZeroizingBuffer(20);
        buf.Dispose();
        Assert.Equal(20, buf.Length);
    }

    [Fact]
    public void Dispose_ZeroesBackingArray()
    {
        var buf = new ZeroizingBuffer(64);
        for (int i = 0; i < buf.Length; i++)
            buf.Span[i] = 0xAB;

        // Capture the pinned backing array (internal accessor) before disposal.
        byte[] backing = buf.UnsafeBackingArray;
        Assert.Contains((byte)0xAB, backing);

        buf.Dispose();
        Assert.All(backing, b => Assert.Equal(0, b));
    }

    [Fact]
    public void NegativeLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ZeroizingBuffer(-1));
    }
}
