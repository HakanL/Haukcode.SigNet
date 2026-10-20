using System;
using Haukcode.SigNet.Security;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class ReplayProtectionTests
{
    private static readonly Tuid deviceA = new(0x0744, 1);
    private static readonly Tuid deviceB = new(0x0744, 2);

    private static FreshnessResult Accept(ReplayProtection table, SenderId senderId, uint session, uint sequence)
    {
        var result = table.Evaluate(senderId, session, sequence);
        if (result is FreshnessResult.Fresh or FreshnessResult.Bootstrap)
            Assert.True(table.Commit(senderId, session, sequence));

        return result;
    }

    [Fact]
    public void FirstPacket_Bootstraps_ThenForwardOnly()
    {
        var table = new ReplayProtection();
        var lane = new SenderId(deviceA, 1);

        Assert.Equal(FreshnessResult.Bootstrap, Accept(table, lane, 10, 500));
        Assert.Equal(FreshnessResult.Fresh, Accept(table, lane, 10, 501));
        Assert.Equal(FreshnessResult.SequenceReplay, Accept(table, lane, 10, 501));
        Assert.Equal(FreshnessResult.SequenceReplay, Accept(table, lane, 10, 400));
        Assert.Equal(FreshnessResult.Fresh, Accept(table, lane, 10, 900));
    }

    [Fact]
    public void Evaluate_DoesNotChangeState()
    {
        var table = new ReplayProtection();
        var lane = new SenderId(deviceA, 1);

        // A packet that would bootstrap but then fails its HMAC is never committed
        Assert.Equal(FreshnessResult.Bootstrap, table.Evaluate(lane, 10, 500));
        Assert.Equal(FreshnessResult.Bootstrap, table.Evaluate(lane, 1, 1));
        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void LowerSession_IsEpochRegression_HigherSessionResetsSequence()
    {
        var table = new ReplayProtection();
        var lane = new SenderId(deviceA, 1);

        Accept(table, lane, 10, 500);

        Assert.Equal(FreshnessResult.EpochRegression, Accept(table, lane, 9, 99999));
        Assert.Equal(FreshnessResult.Fresh, Accept(table, lane, 11, 1));
        Assert.Equal(FreshnessResult.Fresh, Accept(table, lane, 11, 2));
        Assert.Equal(FreshnessResult.EpochRegression, Accept(table, lane, 10, 501));
    }

    [Fact]
    public void Lanes_AreIndependentButShareTheSession()
    {
        var table = new ReplayProtection();
        var universe1 = new SenderId(deviceA, 1);
        var universe2 = new SenderId(deviceA, 2);

        Accept(table, universe1, 10, 1000);

        // Another lane of the same device has its own sequence window
        Assert.Equal(FreshnessResult.Fresh, Accept(table, universe2, 10, 5));
        Assert.Equal(FreshnessResult.Fresh, Accept(table, universe1, 10, 1001));

        // A new session on one lane makes the old session stale on every lane
        Accept(table, universe2, 11, 1);
        Assert.Equal(FreshnessResult.EpochRegression, Accept(table, universe1, 10, 1002));
        Assert.Equal(FreshnessResult.Fresh, Accept(table, universe1, 11, 1));
    }

    [Fact]
    public void FullTable_IsSaturatedUntilTheOldestEntryIsAnHourOld()
    {
        var time = new FakeTimeProvider();
        var table = new ReplayProtection(ReplayProtection.MinimumCapacity, time);

        for (ushort i = 1; i <= ReplayProtection.MinimumCapacity; i++)
        {
            Accept(table, new SenderId(deviceA, i), 1, 1);
            time.Advance(TimeSpan.FromSeconds(1));
        }

        var newcomer = new SenderId(deviceB, 1);
        Assert.Equal(FreshnessResult.TableSaturated, table.Evaluate(newcomer, 1, 1));

        // Known senders still pass
        Assert.Equal(FreshnessResult.Fresh, Accept(table, new SenderId(deviceA, 5), 1, 2));

        // Lane 1 has now been silent for an hour; it is the LRU entry and can go
        time.Advance(ReplayProtection.EvictionAge - TimeSpan.FromSeconds(ReplayProtection.MinimumCapacity) + TimeSpan.FromSeconds(1));
        Assert.Equal(FreshnessResult.Bootstrap, Accept(table, newcomer, 1, 1));
        Assert.Equal(ReplayProtection.MinimumCapacity, table.Count);

        // Lane 1 was evicted, so it bootstraps from scratch (device A still has other lanes)
        Assert.Equal(FreshnessResult.Fresh, table.Evaluate(new SenderId(deviceA, 1), 1, 1));
    }

    [Fact]
    public void Forget_DropsEveryLaneOfTheDevice()
    {
        var table = new ReplayProtection();
        Accept(table, new SenderId(deviceA, 1), 100, 1);
        Accept(table, new SenderId(deviceA, 2), 100, 1);
        Accept(table, new SenderId(deviceB, 1), 5, 1);

        Assert.True(table.Forget(deviceA));

        Assert.Equal(1, table.Count);
        // The recovered device starts again from session 0
        Assert.Equal(FreshnessResult.Bootstrap, table.Evaluate(new SenderId(deviceA, 1), 0, 1));
        Assert.False(table.Forget(deviceA));
    }

    [Fact]
    public void Capacity_HasTheSpecMinimum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ReplayProtection(31));
        Assert.Equal(1000, new ReplayProtection(1000).Capacity);
    }
}
