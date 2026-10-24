using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Haukcode.SigNet.Model;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class DiscoveryTests
{
    private static readonly Tuid managerTuid = new(0x5379, 0x80000001);
    private uint managerSequence;

    private static SigNetDeviceInfo NodeInfo => new(SoemCode.Create(0x0744, 0x0010), "DMX Core 100", "Rack 1")
    {
        Roles = SigNetRoles.Sender | SigNetRoles.Node,
        FirmwareVersionId = 0x01020300,
        FirmwareVersion = "1.2.3",
        Endpoints =
        [
            new SigNetEndpointInfo(1, "Input 1"),
            new SigNetEndpointInfo(200, "Input 2") { MaxMergeSources = 8 }
        ]
    };

    private byte[] ManagerPacket(TestClient test, SigNetPath path, byte[] payload)
    {
        var header = new SigNetSecurityHeader(SecurityMode.HmacSha256, new SenderId(managerTuid, 0), 0, 7, ++this.managerSequence);
        var buffer = new byte[1500];
        int length = SigNetPacketWriter.Write(buffer, 1, path, header, payload, test.Keys.GetKey(path.KeyRole));

        return buffer[..length];
    }

    private static byte[] PollPayload(Tuid low, Tuid high, ushort endpoint, QueryLevel level)
    {
        var payload = new byte[4 + PollRequest.Length];
        var writer = new TlvWriter(payload);
        new PollRequest(managerTuid, 0x53790001, low, high, endpoint, level).WriteTo(writer.Reserve(Tid.Poll, PollRequest.Length));

        return payload;
    }

    private static Task<(IPEndPoint Destination, byte[] Datagram)> NextReply(TestClient test, ushort endpoint, Func<ushort[], bool>? match = null, int timeoutMS = 3000)
    {
        return Wait.For(test.Sent, s =>
        {
            if (!s.Destination.Address.Equals(SigNetMulticast.NodeSend))
                return false;

            var (path, packet) = test.Decode(s.Datagram);
            if (path.Endpoint != endpoint)
                return false;

            var tids = SigNetClientTests.ReadTlvs(packet.Payload).Select(t => t.Tid).ToArray();

            return tids.Length > 0 && tids[0] == Tid.PollReply && (match == null || match(tids));
        }, timeoutMS);
    }

    [Fact]
    public async Task TargetedHeartbeatPoll_IsAnsweredAtOnceWithTheHeartbeatSet()
    {
        using var test = new TestClient(NodeInfo);
        // Let the on-boot notification go first
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend), timeoutMS: 2500);

        var started = DateTime.UtcNow;
        test.Inject(ManagerPacket(test, SigNetPath.Poll("local"), PollPayload(test.Tuid, test.Tuid, 0, QueryLevel.Heartbeat)));

        var (_, datagram) = await NextReply(test, 0, tids => tids.Contains(Tid.RtEndpointCount));
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromMilliseconds(500));

        var (path, packet) = test.Decode(datagram);
        Assert.Equal(SigNetPath.Node("local", test.Tuid, 0), path);
        Assert.Equal(new SenderId(test.Tuid, 0), packet.SenderId);

        var tlvs = SigNetClientTests.ReadTlvs(packet.Payload);
        Assert.Equal(new[] { Tid.PollReply, Tid.RtEndpointCount, Tid.RtMultOverride }, tlvs.Select(t => t.Tid));
        Assert.Equal(new PollReply(test.Tuid, 0x07440010, 0), PollReply.Read(tlvs[0].Value));
        Assert.Equal(new byte[] { 0, 2 }, tlvs[1].Value);
    }

    [Fact]
    public async Task RangeFullPollForAllEndpoints_RepliesPerEndpointAfterBackoff()
    {
        using var test = new TestClient(NodeInfo);

        test.Inject(ManagerPacket(test, SigNetPath.Poll("local"), PollPayload(default, Tuid.FromValue(0xFFFFFFFFFFFF), PollRequest.AllEndpoints, QueryLevel.Full)));

        var (_, root) = await NextReply(test, 0, tids => tids.Contains(Tid.RtModelName));
        var rootTlvs = SigNetClientTests.ReadTlvs(test.Decode(root).Packet.Payload);
        Assert.Equal(
            new[] { Tid.PollReply, Tid.RtEndpointCount, Tid.RtMultOverride, Tid.RtDeviceLabel, Tid.RtIdentify, Tid.RtStatus, Tid.RtSupportedTids, Tid.RtProtocolVersion, Tid.RtFirmwareVersion, Tid.RtRoleCapability, Tid.RtModelName },
            rootTlvs.Select(t => t.Tid));
        Assert.Equal("Rack 1", TextPayload.ReadLabel(rootTlvs[3].Value));
        Assert.Equal("DMX Core 100", TextPayload.ReadLabel(rootTlvs[10].Value));
        Assert.Equal(new byte[] { 1, 2, 3, 0, (byte)'1', (byte)'.', (byte)'2', (byte)'.', (byte)'3' }, rootTlvs[8].Value);

        var (_, second) = await NextReply(test, 2, tids => tids.Contains(Tid.EpUniverse));
        var (path, packet) = test.Decode(second);
        // A data endpoint replies on its own lane
        Assert.Equal(new SenderId(test.Tuid, 2), packet.SenderId);
        var tlvs = SigNetClientTests.ReadTlvs(packet.Payload);
        Assert.Equal(Tid.PollReply, tlvs[0].Tid);
        Assert.Equal(new byte[] { 0, 200 }, tlvs.Single(t => t.Tid == Tid.EpUniverse).Value);
        // Consumes levels, Constrained Node Fallback (bit 5 clear), 8 merge sources
        Assert.Equal(new byte[] { 0, 0, 0, 1, 0, 8 }, tlvs.Single(t => t.Tid == Tid.EpCapability).Value);
        Assert.DoesNotContain(tlvs, t => t.Tid == Tid.RtModelName);
    }

    [Fact]
    public async Task ExtendedPoll_IncludesOneSecurityEventPerCode()
    {
        using var test = new TestClient(NodeInfo);

        test.Inject(ManagerPacket(test, SigNetPath.Poll("local"), PollPayload(test.Tuid, test.Tuid, 0, QueryLevel.Extended)));

        var (_, datagram) = await NextReply(test, 0, tids => tids.Contains(Tid.DgSecurityEvent));
        var events = SigNetClientTests.ReadTlvs(test.Decode(datagram).Packet.Payload).Where(t => t.Tid == Tid.DgSecurityEvent).Select(t => SecurityEvent.Read(t.Value)).ToList();
        Assert.Equal(Enumerable.Range(1, 8), events.Select(e => (int)e.Code));
    }

    [Fact]
    public async Task PollOutsideTuidRange_IsIgnored()
    {
        using var test = new TestClient(NodeInfo);
        var other = new Tuid(0x0744, 0x00000043);

        test.Inject(ManagerPacket(test, SigNetPath.Poll("local"), PollPayload(other, other, 0, QueryLevel.Heartbeat)));

        await Wait.Until(() => test.Client.GetVerifyCounts()[Security.VerifyResult.Accepted] == 1);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.DoesNotContain(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend) && SigNetClientTests.ReadTlvs(test.Decode(s.Datagram).Packet.Payload).Count == 3);
    }

    [Fact]
    public async Task Get_IsAnsweredReadOnly_ChangingSetIsRefusedWithoutReply()
    {
        using var test = new TestClient(NodeInfo);
        // Past the 2 s post-link-up window, so the SET is refused for being a SET
        await Task.Delay(Security.SigNetPacketVerifier.BootstrapWindow, TestContext.Current.CancellationToken);
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        test.Sent.Clear();

        // GET TID_EP_LABEL and TID_EP_UNIVERSE on endpoint 1, signed with this node's Km_local
        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("09020000" + "09010000")));

        var (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        var (path, packet) = test.Decode(datagram);
        Assert.Equal(SigNetPath.Node("local", test.Tuid, 1), path);
        var tlvs = SigNetClientTests.ReadTlvs(packet.Payload);
        Assert.Equal(new[] { Tid.EpUniverse, Tid.EpLabel }, tlvs.Select(t => t.Tid));
        Assert.Equal("Input 1", TextPayload.ReadLabel(tlvs[1].Value));

        // SET TID_EP_LABEL: verified, but no reply and nothing changes
        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("09020004" + "00414243")));
        await Wait.Until(() => test.Client.GetVerifyCounts()[Security.VerifyResult.Accepted] == 2);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.Empty(test.Sent);
        Assert.Equal("Input 1", test.Client.DeviceInfo.Endpoints[0].Label);
    }

    // TID_EP_LABEL "Input 1": encoding byte 0x00, then the ASCII text
    private const string InputOneLabelTlv = "09020008" + "00496E7075742031";

    [Fact]
    public async Task SameValueSet_IsEchoedWithATrailingSetReply()
    {
        using var test = new TestClient(NodeInfo);
        await Task.Delay(Security.SigNetPacketVerifier.BootstrapWindow, TestContext.Current.CancellationToken);
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        test.Sent.Clear();

        // SET TID_EP_LABEL to its current value (spec 10.4.2 "Valid SET with no State Change")
        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString(InputOneLabelTlv)));

        var (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        var (path, packet) = test.Decode(datagram);
        Assert.Equal(SigNetPath.Node("local", test.Tuid, 1), path);
        var tlvs = SigNetClientTests.ReadTlvs(packet.Payload);
        Assert.Equal(new[] { Tid.EpLabel, Tid.SetReply }, tlvs.Select(t => t.Tid));
        Assert.Equal("Input 1", TextPayload.ReadLabel(tlvs[0].Value));

        // Reserved flags, then the CHANGE_COUNT, unchanged
        Assert.Equal(new byte[] { 0x00, 0x00, 0x00 }, tlvs[1].Value);
        Assert.Equal(0, test.Client.DeviceInfo.ChangeCount);
    }

    [Fact]
    public async Task NonAsciiLabel_IsReportedAsUtf8_AndASameValueUtf8SetIsEchoed()
    {
        var info = NodeInfo with { Endpoints = [new SigNetEndpointInfo(1, "Scène")] };
        using var test = new TestClient(info);
        await Task.Delay(Security.SigNetPacketVerifier.BootstrapWindow, TestContext.Current.CancellationToken);
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        test.Sent.Clear();

        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("09020000")));

        var (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        var tlvs = SigNetClientTests.ReadTlvs(test.Decode(datagram).Packet.Payload);
        // Encoding 0x01 (spec 11.7.2, V1.15), then "Scène" in UTF-8
        Assert.Equal(Convert.FromHexString("01" + "5363C3A86E65"), tlvs.Single().Value);
        test.Sent.Clear();

        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("09020007" + "01" + "5363C3A86E65")));

        (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        tlvs = SigNetClientTests.ReadTlvs(test.Decode(datagram).Packet.Payload);
        Assert.Equal(new[] { Tid.EpLabel, Tid.SetReply }, tlvs.Select(t => t.Tid));
    }

    [Fact]
    public async Task EpCapability_NeverReportsTheDeprecatedBit3()
    {
        // Bit 3 was "Can Supply RDM" until V1.14 and is reserved since V1.15 (spec 11.7.4)
        var info = NodeInfo with { Endpoints = [new SigNetEndpointInfo(1, "Input 1") { Capabilities = EndpointCapabilities.ConsumeLevel | EndpointCapabilities.ConsumeRdm | (EndpointCapabilities)0x08 }] };
        using var test = new TestClient(info);
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend), timeoutMS: 2500);
        test.Sent.Clear();

        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("09040000")));

        var (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        var tlvs = SigNetClientTests.ReadTlvs(test.Decode(datagram).Packet.Payload);
        Assert.Equal(new byte[] { 0, 0, 0, 0x05, 0, 4 }, tlvs.Single().Value);
    }

    private static async Task<(SigNetPath Path, System.Collections.Generic.List<(ushort Tid, byte[] Value)> Tlvs)> Get(DiscoveryTests owner, TestClient test, ushort endpoint, string tlvs)
    {
        test.Sent.Clear();
        test.Inject(owner.ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, endpoint), Convert.FromHexString(tlvs)));

        // The reply carries the first requested TID; skip anything else sent meanwhile
        ushort first = Convert.ToUInt16(tlvs[..4], 16);
        var (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend) && SigNetClientTests.ReadTlvs(test.Decode(s.Datagram).Packet.Payload).Any(t => t.Tid == first));
        var (path, packet) = test.Decode(datagram);

        return (path, SigNetClientTests.ReadTlvs(packet.Payload));
    }

    private static async Task<ushort[]> GetSupportedTids(DiscoveryTests owner, TestClient test)
    {
        var (_, tlvs) = await Get(owner, test, 0, "06010000");
        var value = tlvs.Single().Value;

        return Enumerable.Range(0, value.Length / 2).Select(i => (ushort)((value[i * 2] << 8) | value[i * 2 + 1])).ToArray();
    }

    [Fact]
    public async Task LevelFoldback_WithoutAProvider_IsNotAdvertisedOrAnswered()
    {
        using var test = new TestClient(NodeInfo);
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend), timeoutMS: 2500);

        Assert.DoesNotContain(Tid.DgLevelFoldback, await GetSupportedTids(this, test));

        test.Sent.Clear();
        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("FF030000")));
        await Wait.Until(() => test.Client.GetVerifyCounts()[Security.VerifyResult.Accepted] == 2);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.DoesNotContain(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
    }

    [Fact]
    public async Task LevelFoldback_IsAnsweredFromTheProvider()
    {
        using var test = new TestClient(NodeInfo);
        var asked = new System.Collections.Concurrent.ConcurrentQueue<ushort>();
        test.Client.LevelFoldback = (endpoint, levels) =>
        {
            asked.Enqueue(endpoint);
            if (endpoint == 2)
                return 0;

            levels[0] = 0xFF;
            levels[2] = 0x80;

            return 3;
        };
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend), timeoutMS: 2500);

        Assert.Contains(Tid.DgLevelFoldback, await GetSupportedTids(this, test));

        // GET on data endpoint 1, replied on that endpoint (spec 11.8.3)
        var (path, tlvs) = await Get(this, test, 1, "FF030000");
        Assert.Equal(SigNetPath.Node("local", test.Tuid, 1), path);
        Assert.Equal(Tid.DgLevelFoldback, tlvs.Single().Tid);
        Assert.Equal(new byte[] { 0xFF, 0x00, 0x80 }, tlvs.Single().Value);

        // Nothing to report yet: length 1, data 0, never zero length
        (_, tlvs) = await Get(this, test, 2, "FF030000");
        Assert.Equal(new byte[] { 0x00 }, tlvs.Single().Value);
        Assert.Equal(new ushort[] { 1, 2 }, asked.ToArray());
    }

    [Fact]
    public async Task LevelFoldback_IsNotInPollRepliesAndCannotBeSet()
    {
        using var test = new TestClient(NodeInfo);
        test.Client.LevelFoldback = (_, levels) =>
        {
            levels[0] = 1;

            return 1;
        };
        await Task.Delay(Security.SigNetPacketVerifier.BootstrapWindow, TestContext.Current.CancellationToken);
        test.Sent.Clear();

        // Get Only: no QUERY_LEVEL includes it (spec 11.9)
        test.Inject(ManagerPacket(test, SigNetPath.Poll("local"), PollPayload(test.Tuid, test.Tuid, 1, QueryLevel.Extended)));
        var (_, datagram) = await NextReply(test, 1);
        var tids = SigNetClientTests.ReadTlvs(test.Decode(datagram).Packet.Payload).Select(t => t.Tid).ToArray();
        Assert.DoesNotContain(Tid.DgLevelFoldback, tids);
        Assert.DoesNotContain(Tid.DgSource, tids);

        // A SET with the current value is still refused
        test.Sent.Clear();
        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("FF030001" + "01")));
        await Wait.Until(() => test.Client.GetVerifyCounts()[Security.VerifyResult.Accepted] == 2);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.DoesNotContain(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
    }

    [Fact]
    public async Task DgSource_ReportsEachActiveSourceOfTheEndpoint()
    {
        var info = NodeInfo with
        {
            Endpoints =
            [
                new SigNetEndpointInfo(5, "Input 1"),
                new SigNetEndpointInfo(6, "Input 2")
            ]
        };
        using var test = new TestClient(info);
        test.Client.JoinUniverse(5);
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend), timeoutMS: 2500);

        Assert.Contains(Tid.DgSource, await GetSupportedTids(this, test));

        // This client sends universe 5 to itself at priority 120
        await test.Client.SendLevels(5, new byte[] { 1, 2, 3 }, priority: 120, destination: IPAddress.Loopback);
        await Wait.For(test.Received);

        var (path, tlvs) = await Get(this, test, 1, "FF040000");
        Assert.Equal(SigNetPath.Node("local", test.Tuid, 1), path);
        var source = tlvs.Single();
        Assert.Equal(Tid.DgSource, source.Tid);
        // Sender-ID (TUID and lane 5), priority, packets per second, IPv4 address: 15 bytes (spec 11.8.4)
        Assert.Equal(15, source.Value.Length);
        Assert.Equal(new SenderId(test.Tuid, 5), SenderId.Read(source.Value));
        Assert.Equal(120, source.Value[8]);
        Assert.True(((source.Value[9] << 8) | source.Value[10]) >= 1);
        Assert.Equal(IPAddress.Loopback, new IPAddress(source.Value.AsSpan(11, 4)));

        // No active source on endpoint 2: length 1, data 0
        (_, tlvs) = await Get(this, test, 2, "FF040000");
        Assert.Equal(new byte[] { 0x00 }, tlvs.Single().Value);
    }

    [Fact]
    public async Task DgSource_ReportsThePacketRate_AndDropsTimedOutSources()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var test = new TestClient(NodeInfo with { Endpoints = [new SigNetEndpointInfo(9, "Input 1")] }, timeProvider: time);
        test.Client.JoinUniverse(9);

        async Task SendFrames(int count)
        {
            for (int i = 0; i < count; i++)
            {
                await test.Client.SendLevels(9, new byte[] { (byte)(test.Received.Count + 1) }, destination: IPAddress.Loopback);
                await Wait.For(test.Received);
            }
        }

        static int Rate(byte[] value) => (value[9] << 8) | value[10];

        // 4 packets in the first half second: the rate so far, over at least one second
        await SendFrames(4);
        time.Advance(TimeSpan.FromSeconds(0.5));
        var (_, tlvs) = await Get(this, test, 1, "FF040000");
        Assert.Equal(4, Rate(tlvs.Single().Value));

        // 2 more after 1.1 s close the window: 6 packets in 1.1 s
        await SendFrames(1);
        time.Advance(TimeSpan.FromSeconds(0.6));
        await SendFrames(1);
        (_, tlvs) = await Get(this, test, 1, "FF040000");
        Assert.Equal(5, Rate(tlvs.Single().Value));

        // Gone for <universe_lost_timeout>: no longer a source (spec 11.8.4)
        time.Advance(SigNetClient.UniverseLostTimeout);
        (_, tlvs) = await Get(this, test, 1, "FF040000");
        Assert.Equal(new byte[] { 0x00 }, tlvs.Single().Value);
    }

    [Fact]
    public async Task SetWithOneChangingValue_IsRefusedAsAWhole()
    {
        using var test = new TestClient(NodeInfo);
        await Task.Delay(Security.SigNetPacketVerifier.BootstrapWindow, TestContext.Current.CancellationToken);
        await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        test.Sent.Clear();

        // The same label plus a new universe: the universe would change, so nothing is answered
        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString(InputOneLabelTlv + "09010002" + "0007")));
        // And a root TID sent to a data endpoint is not a parameter of that endpoint
        test.Inject(ManagerPacket(test, SigNetPath.Manager("local", test.Tuid, 1), Convert.FromHexString("06070001" + "00")));

        await Wait.Until(() => test.Client.GetVerifyCounts()[Security.VerifyResult.Accepted] == 2);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.Empty(test.Sent);
    }

    [Fact]
    public async Task Node_EntersLostModeWithoutPolls_AndLeavesItOnAPoll()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var test = new TestClient(NodeInfo, timeProvider: time);

        time.Advance(TimeSpan.FromSeconds(8.9));
        Assert.False(test.Client.IsInLostMode);

        time.Advance(TimeSpan.FromSeconds(0.2));
        Assert.True(test.Client.IsInLostMode);

        var (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeLost));
        var (path, packet) = test.Decode(datagram);
        Assert.Equal(SigNetPath.NodeLost("local", test.Tuid), path);
        Assert.Equal(new[] { Tid.PollReply, Tid.RtProtocolVersion, Tid.RtRoleCapability, Tid.RtEndpointCount, Tid.RtMultOverride },
            SigNetClientTests.ReadTlvs(packet.Payload).Select(t => t.Tid));

        test.Inject(ManagerPacket(test, SigNetPath.Poll("local"), PollPayload(test.Tuid, test.Tuid, 0, QueryLevel.Heartbeat)));
        await Wait.Until(() => test.Client.GetVerifyCounts()[Security.VerifyResult.Accepted] == 1);
        time.Advance(TimeSpan.FromMilliseconds(100));
        Assert.False(test.Client.IsInLostMode);
    }

    [Fact]
    public async Task PureSender_NeverEntersLostMode()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var test = new TestClient(timeProvider: time);

        time.Advance(TimeSpan.FromSeconds(20));

        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.False(test.Client.IsInLostMode);
        Assert.DoesNotContain(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeLost));
    }

    [Fact]
    public async Task ActiveUniverses_AreReannouncedEveryFiveSeconds()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var test = new TestClient(timeProvider: time);

        await test.Client.SendLevels(1, new byte[] { 1 });
        await test.Client.SendLevels(2, new byte[] { 1 });
        await Wait.Until(() => test.Sent.Count(s => s.Destination.Address.Equals(SigNetMulticast.NodeSend)) >= 2);
        test.Sent.Clear();

        time.Advance(TimeSpan.FromSeconds(5.1));

        var (_, datagram) = await Wait.For(test.Sent, s => s.Destination.Address.Equals(SigNetMulticast.NodeSend));
        var announcements = SigNetClientTests.ReadTlvs(test.Decode(datagram).Packet.Payload).Select(t => UniverseAnnouncement.Read(t.Value)).ToList();
        Assert.Equal(new ushort[] { 1, 2 }, announcements.Select(a => a.Universe).Order());
        Assert.All(announcements, a => Assert.Equal(UniverseCommand.Join, a.Command));
    }
}
