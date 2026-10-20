using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Haukcode.SigNet.Model;
using Haukcode.SigNet.Security;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class SigNetClientTests
{
    internal static List<(ushort Tid, byte[] Value)> ReadTlvs(ReadOnlyMemory<byte> payload)
    {
        var result = new List<(ushort, byte[])>();
        var reader = new TlvReader(payload.Span);
        while (reader.TryRead(out ushort tid, out var value))
            result.Add((tid, value.ToArray()));

        return result;
    }

    [Fact]
    public void Constructor_IncrementsAndSavesSessionIdBeforeSending()
    {
        var store = new MemorySessionIdStore(41);
        using var client = new TestClient(store: store);

        Assert.Equal(42U, store.SessionId);
        Assert.Equal(1, store.Saves);
        Assert.Equal(42U, client.Client.SessionId);
    }

    [Fact]
    public void Constructor_RefusesExhaustedSessionId()
    {
        Assert.Throws<SessionIdExhaustedException>(() => new TestClient(store: new MemorySessionIdStore(0xFFFFFFFE)));
        Assert.Throws<SessionIdExhaustedException>(() => new TestClient(store: new MemorySessionIdStore(0xFFFFFFFF)));
    }

    [Fact]
    public async Task SendLevels_UnicastToSelf_IsVerifiedAndDelivered()
    {
        using var test = new TestClient();
        test.Client.JoinUniverse(7);

        await test.Client.SendLevels(7, new byte[] { 1, 2, 3, 255 }, priority: 150, destination: IPAddress.Loopback);

        var frame = await Wait.For(test.Received, p => p.Kind == ReceiveDataKind.Levels);
        Assert.Equal(7, frame.Universe);
        Assert.Equal(new byte[] { 1, 2, 3, 255 }, frame.Levels.ToArray());
        Assert.Equal(150, frame.Priority);
        Assert.True(frame.HasPriority);
        Assert.Equal(new SenderId(test.Tuid, 7), frame.SenderId);
        Assert.Equal(42U, frame.SessionId);
        Assert.Equal(1U, frame.SequenceNumber);
        Assert.False(frame.Synchronized);
        Assert.Equal(IPAddress.Loopback, frame.Destination?.Address);
    }

    [Fact]
    public async Task SendLevels_PacksPriorityBeforeLevelOnTheUniverseLane()
    {
        using var test = new TestClient();

        await test.Client.SendLevels(110, new byte[] { 9 }, priority: 50);

        var (destination, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(IPAddress.Parse("239.254.0.1")));
        Assert.Equal(test.Port, destination.Port);

        var (path, packet) = test.Decode(datagram);
        Assert.Equal(SigNetPath.Level("local", 110), path);
        Assert.Equal(new SenderId(test.Tuid, 110), packet.SenderId);

        var tlvs = ReadTlvs(packet.Payload);
        Assert.Equal(new[] { Tid.Priority, Tid.Level }, tlvs.Select(t => t.Tid));
        Assert.Equal(new byte[] { 50 }, tlvs[0].Value);
    }

    [Fact]
    public async Task SendLevels_WithoutPriority_SendsOnlyLevel_AndReceiverDefaultsTo100()
    {
        using var test = new TestClient();
        test.Client.JoinUniverse(3);

        await test.Client.SendLevels(3, new byte[512], destination: IPAddress.Loopback);

        var frame = await Wait.For(test.Received);
        Assert.Equal(100, frame.Priority);
        Assert.False(frame.HasPriority);
        Assert.Equal(512, frame.Levels.Length);
    }

    [Fact]
    public async Task ReceivedPriority_PersistsForLaterFramesWithoutIt()
    {
        using var test = new TestClient();
        test.Client.JoinUniverse(3);

        await test.Client.SendLevels(3, new byte[] { 1 }, priority: 180, destination: IPAddress.Loopback);
        await Wait.For(test.Received);
        await test.Client.SendLevels(3, new byte[] { 2 }, destination: IPAddress.Loopback);

        var frame = await Wait.For(test.Received);
        Assert.Equal(180, frame.Priority);
        Assert.True(frame.HasPriority);
    }

    [Fact]
    public async Task SlotPriorities_UseTheFirstByteAsUniversePriority()
    {
        using var test = new TestClient();
        test.Client.JoinUniverse(3);

        await test.Client.SendLevels(3, new byte[] { 1, 2 }, slotPriorities: new byte[] { 120, 0, 200 }, destination: IPAddress.Loopback);

        Assert.Equal(120, (await Wait.For(test.Received)).Priority);
    }

    [Fact]
    public async Task UnjoinedUniverse_IsDiscardedByUri()
    {
        using var test = new TestClient();
        test.Client.JoinUniverse(1);

        // Universe 110 shares 239.254.0.1 with universe 1 but is not joined
        await test.Client.SendLevels(110, new byte[] { 1 }, destination: IPAddress.Loopback);
        await test.Client.SendLevels(1, new byte[] { 2 }, destination: IPAddress.Loopback);

        var frame = await Wait.For(test.Received);
        Assert.Equal(1, frame.Universe);
        Assert.True(test.Received.IsEmpty);
    }

    [Fact]
    public async Task ReplayedDatagram_IsRejectedAndReported()
    {
        using var test = new TestClient();
        var securityEvents = new ConcurrentQueue<SecurityEvent>();
        using var subscription = test.Client.OnSecurityEvent.Subscribe(securityEvents.Enqueue);
        test.Client.JoinUniverse(5);

        await test.Client.SendLevels(5, new byte[] { 42 }, destination: IPAddress.Loopback);
        await Wait.For(test.Received);
        var (_, original) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(IPAddress.Loopback));

        // An attacker replays the captured packet
        test.Inject(original);

        var securityEvent = await Wait.For(securityEvents);
        Assert.Equal(SecurityEventCode.SequenceViolation, securityEvent.Code);
        Assert.Equal(IPAddress.Loopback, securityEvent.SourceAddress);
        Assert.Equal(1, test.Client.GetVerifyCounts()[VerifyResult.SequenceReplay]);
        Assert.True(test.Received.IsEmpty);

        // And it is reported on the network as TID_DG_SECURITY_EVENT signed with Kc
        var (_, report) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend) && ReadTlvs(test.Decode(s.Datagram).Packet.Payload).Any(t => t.Tid == Tid.DgSecurityEvent));
        var tlv = ReadTlvs(test.Decode(report).Packet.Payload).Single();
        Assert.Equal(SecurityEventCode.SequenceViolation, SecurityEvent.Read(tlv.Value).Code);
    }

    [Fact]
    public async Task ForgedDatagram_FailsHmac_ReportsAreRateLimited()
    {
        using var test = new TestClient();
        var securityEvents = new ConcurrentQueue<SecurityEvent>();
        using var subscription = test.Client.OnSecurityEvent.Subscribe(securityEvents.Enqueue);
        test.Client.JoinUniverse(5);

        await test.Client.SendLevels(5, new byte[] { 42 }, destination: IPAddress.Loopback);
        await Wait.For(test.Received);
        var (_, original) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(IPAddress.Loopback));

        for (int i = 0; i < 3; i++)
        {
            // Change the level and bump the sequence number so freshness passes and only the HMAC fails
            var forged = (byte[])original.Clone();
            forged[^1] = (byte)(100 + i);
            int sequenceEnd = forged.Length - 6 - 1 - SigNetHmac.TagLength - 3;
            forged[sequenceEnd - 1] = (byte)(10 + i);
            test.Inject(forged);
        }

        await Wait.Until(() => securityEvents.Count == 3);
        Assert.All(securityEvents, e => Assert.Equal(SecurityEventCode.HmacFailure, e.Code));
        Assert.Equal(3U, securityEvents.Last().Count);
        Assert.Equal(3, test.Client.GetVerifyCounts()[VerifyResult.HmacFailure]);
        Assert.True(test.Received.IsEmpty);

        // One network report per second per code (spec 10.9.3)
        await Task.Delay(200, TestContext.Current.CancellationToken);
        int reports = test.Sent.Count(s => s.Destination.Address.Equals(SigNetMulticast.NodeSend) && ReadTlvs(test.Decode(s.Datagram).Packet.Payload).Any(t => t.Tid == Tid.DgSecurityEvent));
        Assert.Equal(1, reports);
    }

    [Fact]
    public async Task FirstFrame_AnnouncesUniverse_StopUniverseLeaves()
    {
        using var test = new TestClient();

        await test.Client.SendLevels(12, new byte[] { 1 });
        await test.Client.SendLevels(12, new byte[] { 2 });
        test.Client.StopUniverse(12);

        var announcements = new List<UniverseAnnouncement>();
        await Wait.Until(() =>
        {
            while (test.Sent.TryDequeue(out var sent))
            {
                var (path, packet) = test.Decode(sent.Datagram);
                if (path.Resource == SigNetResource.Node)
                {
                    announcements.AddRange(ReadTlvs(packet.Payload).Where(t => t.Tid == Tid.Universe).Select(t => UniverseAnnouncement.Read(t.Value)));
                    Assert.Equal(new SenderId(test.Tuid, 0), packet.SenderId);
                }
            }

            return announcements.Count >= 2;
        });

        Assert.Equal(new UniverseAnnouncement(12, UniverseCommand.Join, null, 12), announcements[0]);
        Assert.Equal(new UniverseAnnouncement(12, UniverseCommand.Leave, null, 12), announcements[1]);
        Assert.Empty(test.Client.ActiveUniverses);
    }

    [Fact]
    public async Task OnBootNotification_IsSentWithKcInSpecOrder()
    {
        using var test = new TestClient(new SigNetDeviceInfo(SoemCode.Create(0x0744, 0x0002), "Model", "Label") { Roles = SigNetRoles.Sender | SigNetRoles.Node, Endpoints = [new SigNetEndpointInfo(1, "In 1")] });

        var (destination, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend), timeoutMS: 2500);
        var (path, packet) = test.Decode(datagram);

        Assert.Equal(SigNetPath.Node("local", test.Tuid, 0), path);
        var tlvs = ReadTlvs(packet.Payload);
        Assert.Equal(new[] { Tid.PollReply, Tid.RtProtocolVersion, Tid.RtRoleCapability, Tid.RtEndpointCount, Tid.RtMultOverride }, tlvs.Select(t => t.Tid));
        Assert.Equal(new PollReply(test.Tuid, 0x07440002, 0), PollReply.Read(tlvs[0].Value));
        Assert.Equal(new byte[] { 0, 0, 0, 3 }, tlvs[2].Value);
        Assert.Equal(new byte[] { 0, 1 }, tlvs[3].Value);
    }

    [Fact]
    public async Task LaneWrap_AdvancesAndPersistsTheSession()
    {
        using var test = new TestClient();
        test.Client.JoinUniverse(2);
        test.Client.SetLaneSequenceForTest(2, 0xFFFFFFFD);

        await test.Client.SendLevels(2, new byte[] { 1 }, destination: IPAddress.Loopback);
        await test.Client.SendLevels(2, new byte[] { 2 }, destination: IPAddress.Loopback);

        var first = await Wait.For(test.Received);
        var second = await Wait.For(test.Received);
        Assert.Equal((42U, 0xFFFFFFFEU), (first.SessionId, first.SequenceNumber));
        Assert.Equal((43U, 1U), (second.SessionId, second.SequenceNumber));
        Assert.Equal(43U, test.Store.SessionId);
    }

    [Fact]
    public async Task SyncHoldsFramesUntilTheNextSync_AndTimesOut()
    {
        using var test = new TestClient();
        test.Client.JoinUniverse(1);
        test.Client.JoinUniverse(2);

        // Not yet synchronized: applied at once
        await test.Client.SendLevels(1, new byte[] { 10 }, destination: IPAddress.Loopback);
        Assert.False((await Wait.For(test.Received)).Synchronized);

        // The first sync switches the sender to SYNC_ACTIVE
        await test.Client.SendSync(IPAddress.Loopback);
        Assert.Equal(ReceiveDataKind.Sync, (await Wait.For(test.Received)).Kind);

        // Now frames are held...
        await test.Client.SendLevels(1, new byte[] { 11 }, destination: IPAddress.Loopback);
        await test.Client.SendLevels(2, new byte[] { 21 }, destination: IPAddress.Loopback);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.True(test.Received.IsEmpty);

        // ...and released together by the next sync, before the sync itself
        await test.Client.SendSync(IPAddress.Loopback);
        var released = new List<ReceiveDataPacket> { await Wait.For(test.Received), await Wait.For(test.Received) };
        Assert.All(released, p => Assert.True(p.Synchronized));
        Assert.Equal(new[] { (ushort)1, (ushort)2 }, released.Select(p => p.Universe).Order());
        Assert.Equal(ReceiveDataKind.Sync, (await Wait.For(test.Received)).Kind);

        // No sync for 250 ms: the held frame is flushed and the sender is asynchronous again
        await test.Client.SendLevels(1, new byte[] { 12 }, destination: IPAddress.Loopback);
        var flushed = await Wait.For(test.Received, timeoutMS: 1000);
        Assert.Equal(new byte[] { 12 }, flushed.Levels.ToArray());
        Assert.True(flushed.Synchronized);

        await test.Client.SendLevels(1, new byte[] { 13 }, destination: IPAddress.Loopback);
        Assert.False((await Wait.For(test.Received)).Synchronized);
    }

    [Fact]
    public async Task SendSync_WaitsFiveMillisecondsAfterTheLastLevel()
    {
        using var test = new TestClient();
        var sent = new ConcurrentQueue<(long, IPEndPoint)>();
        test.Client.SendInterceptor = (destination, _) =>
        {
            sent.Enqueue((System.Diagnostics.Stopwatch.GetTimestamp(), destination));

            return true;
        };

        await test.Client.SendLevels(1, new byte[] { 1 });
        await test.Client.SendSync();

        await Wait.Until(() => sent.Any(s => s.Item2.Address.Equals(SigNetMulticast.Time)));
        var level = sent.First(s => s.Item2.Address.Equals(IPAddress.Parse("239.254.0.1"))).Item1;
        var sync = sent.First(s => s.Item2.Address.Equals(SigNetMulticast.Time)).Item1;
        double gapMS = (sync - level) * 1000.0 / System.Diagnostics.Stopwatch.Frequency;
        Assert.True(gapMS >= 5, $"Sync {gapMS} ms after level");
    }

    [Fact]
    public async Task UniverseLost_IsReportedAfterThreeSeconds()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var test = new TestClient(timeProvider: time);
        var lost = new ConcurrentQueue<UniverseLostEvent>();
        using var subscription = test.Client.OnUniverseLost.Subscribe(lost.Enqueue);
        test.Client.JoinUniverse(9);

        await test.Client.SendLevels(9, new byte[] { 1 }, destination: IPAddress.Loopback);
        await Wait.For(test.Received);

        time.Advance(TimeSpan.FromSeconds(2.9));
        Assert.True(lost.IsEmpty);

        time.Advance(TimeSpan.FromSeconds(0.2));
        var item = await Wait.For(lost);
        Assert.Equal(new UniverseLostEvent(9, new SenderId(test.Tuid, 9)), item);
    }

    [Fact]
    public void JoinAndDrop_FollowSubscriptionRules()
    {
        using var test = new TestClient();

        test.Client.JoinUniverse(1);
        test.Client.JoinUniverse(110);
        Assert.Throws<InvalidOperationException>(() => test.Client.JoinUniverse(1));
        Assert.Throws<InvalidOperationException>(() => test.Client.DropUniverse(2));
        Assert.Throws<ArgumentOutOfRangeException>(() => test.Client.JoinUniverse(0));

        test.Client.DropUniverse(1);
        Assert.False(test.Client.IsJoined(1));
        Assert.True(test.Client.IsJoined(110));
    }

    [Fact]
    public async Task SendLevels_ValidatesArguments()
    {
        using var test = new TestClient();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => test.Client.SendLevels(0, new byte[1]));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => test.Client.SendLevels(64000, new byte[1]));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => test.Client.SendLevels(1, new byte[513]));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => test.Client.SendLevels(1, ReadOnlyMemory<byte>.Empty));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => test.Client.SendLevels(1, new byte[1], priority: 201));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => test.Client.SendLevels(1, new byte[1], slotPriorities: new byte[] { 201 }));
    }
}
