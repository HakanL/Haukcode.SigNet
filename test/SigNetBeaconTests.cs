using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using Haukcode.SigNet.Model;
using Haukcode.SigNet.Security;
using Haukcode.SigNet.Keys;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class SigNetBeaconTests
{
    private static readonly Tuid tuid = new(0x0744, 0x00ABCDEF);

    private static SigNetDeviceInfo Info => new(SoemCode.Create(0x0744, 100), "DMX Core 100", "Stage left")
    {
        Roles = SigNetRoles.Sender | SigNetRoles.Node,
        Endpoints = [new SigNetEndpointInfo(1, "In 1"), new SigNetEndpointInfo(2, "In 2")]
    };

    [Fact]
    public void Beacon_FollowsSpec10_2_1()
    {
        var buffer = new byte[1500];
        int length = SigNetBeacon.WriteBeacon(buffer, 7, tuid, Info);

        var packet = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(buffer.AsMemory(0, length), packet));

        // Unauthenticated, endpoint 0, every counter zero, empty Auth
        Assert.Equal(new SigNetSecurityHeader(SecurityMode.Beacon, new SenderId(tuid, 0), 0, 0, 0), packet.Header);
        Assert.True(packet.HasAuth);
        Assert.True(packet.Auth.IsEmpty);

        // Always on the local scope, to <mult_node_beacon>
        Assert.Equal(SigNetUriParseResult.Ok, SigNetUri.TryParsePath(packet, null, out var path));
        Assert.Equal(SigNetPath.NodeBeacon(tuid), path);
        Assert.Equal("/sig-net/v1/local/node_beacon/074400ABCDEF/0", path.ToString());
        Assert.Equal(IPAddress.Parse("239.254.255.255"), SigNetMulticast.GetAddress(path));

        var tlvs = SigNetClientTests.ReadTlvs(packet.Payload);
        Assert.Equal(new[] { Tid.PollReply, Tid.RtDeviceLabel, Tid.RtRoleCapability, Tid.RtEndpointCount }, tlvs.Select(t => t.Tid));
        Assert.Equal(new PollReply(tuid, 0x07440064, 0), PollReply.Read(tlvs[0].Value));
        Assert.Equal("Stage left", TextPayload.ReadLabel(tlvs[1].Value));
        Assert.Equal(new byte[] { 0, 0, 0, 3 }, tlvs[2].Value);
        Assert.Equal(new byte[] { 0, 2 }, tlvs[3].Value);
    }

    [Fact]
    public void Beacon_IsRecognizedButNeverActedOnByAnOnboardedDevice()
    {
        var buffer = new byte[1500];
        int length = SigNetBeacon.WriteBeacon(buffer, 7, tuid, Info);

        using var keys = SigNetKeys.FromRootKey(new byte[32].Select((_, i) => (byte)i).ToArray(), new Tuid(0x0744, 1));
        var verifier = new SigNetPacketVerifier(keys, "local", new Tuid(0x0744, 1), new ReplayProtection());

        Assert.Equal(VerifyResult.Beacon, verifier.Verify(buffer.AsMemory(0, length), new SigNetPacket(), out _));
    }

    [Fact]
    public void Beacons_GoOutAtStartThenEveryFiveSeconds()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var sent = new ConcurrentQueue<(IPEndPoint Destination, byte[] Datagram)>();
        using var beacon = new SigNetBeacon(tuid, Info, IPAddress.Loopback, timeProvider: time);
        beacon.SendInterceptor = (destination, datagram) =>
        {
            sent.Enqueue((destination, datagram));

            return true;
        };

        // The interceptor is set after the constructor, so trigger the first period explicitly
        time.Advance(SigNetBeacon.Interval);
        int afterFirst = sent.Count;
        Assert.True(afterFirst >= 1);

        time.Advance(SigNetBeacon.Interval - TimeSpan.FromMilliseconds(1));
        Assert.Equal(afterFirst, sent.Count);

        time.Advance(TimeSpan.FromMilliseconds(1));
        Assert.Equal(afterFirst + 1, sent.Count);

        Assert.All(sent, s => Assert.Equal(new IPEndPoint(SigNetMulticast.NodeBeacon, SigNetClient.DefaultPort), s.Destination));
    }

    [Fact]
    public void LabelChanges_AppearInTheNextBeacon()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var sent = new ConcurrentQueue<byte[]>();
        using var beacon = new SigNetBeacon(tuid, Info, IPAddress.Loopback, timeProvider: time);
        beacon.SendInterceptor = (_, datagram) =>
        {
            sent.Enqueue(datagram);

            return true;
        };

        beacon.DeviceInfo = Info with { DeviceLabel = "Renamed" };
        time.Advance(SigNetBeacon.Interval);

        var packet = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(sent.Last(), packet));
        Assert.Equal("Renamed", TextPayload.ReadLabel(SigNetClientTests.ReadTlvs(packet.Payload)[1].Value));
    }

    [Fact]
    public void Dispose_StopsTheBeacons()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        int count = 0;
        var beacon = new SigNetBeacon(tuid, Info, IPAddress.Loopback, timeProvider: time);
        beacon.SendInterceptor = (_, _) =>
        {
            count++;

            return true;
        };

        beacon.Dispose();
        time.Advance(SigNetBeacon.Interval * 3);

        Assert.Equal(0, count);
    }
}
