using System;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class LevelRefreshPolicyTests
{
    [Fact]
    public void ChangedData_SendsThreeIdenticalFramesThenKeepAlive()
    {
        var time = new FakeTimeProvider();
        var policy = new LevelRefreshPolicy(time);
        var levels = new byte[] { 1, 2, 3 };

        // The change and two repeats: three identical frames in total
        Assert.True(policy.ShouldSend(1, levels));
        Assert.True(policy.ShouldSend(1, levels));
        Assert.True(policy.ShouldSend(1, levels));

        // Then idle until the 1 Hz keep-alive
        time.Advance(TimeSpan.FromMilliseconds(500));
        Assert.False(policy.ShouldSend(1, levels));
        time.Advance(TimeSpan.FromMilliseconds(499));
        Assert.False(policy.ShouldSend(1, levels));
        time.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(policy.ShouldSend(1, levels));
        Assert.False(policy.ShouldSend(1, levels));
    }

    [Fact]
    public void AnyChange_IsSentAndRestartsTheRepeats()
    {
        var time = new FakeTimeProvider();
        var policy = new LevelRefreshPolicy(time);

        policy.ShouldSend(1, new byte[] { 1 });
        policy.ShouldSend(1, new byte[] { 1 });
        policy.ShouldSend(1, new byte[] { 1 });
        Assert.False(policy.ShouldSend(1, new byte[] { 1 }));

        Assert.True(policy.ShouldSend(1, new byte[] { 2 }));
        Assert.True(policy.ShouldSend(1, new byte[] { 2 }));
        Assert.True(policy.ShouldSend(1, new byte[] { 2 }));
        Assert.False(policy.ShouldSend(1, new byte[] { 2 }));

        // A priority change counts as a change
        Assert.True(policy.ShouldSend(1, new byte[] { 2 }, 150));
    }

    [Fact]
    public void Universes_AreIndependent()
    {
        var policy = new LevelRefreshPolicy(new FakeTimeProvider());

        for (int i = 0; i < 3; i++)
            policy.ShouldSend(1, new byte[] { 1 });

        Assert.False(policy.ShouldSend(1, new byte[] { 1 }));
        Assert.True(policy.ShouldSend(2, new byte[] { 1 }));

        policy.Forget(1);
        Assert.True(policy.ShouldSend(1, new byte[] { 1 }));
    }
}
