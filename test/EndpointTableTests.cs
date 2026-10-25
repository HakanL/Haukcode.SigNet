using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Haukcode.SigNet.Model;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class EndpointTableTests
{
    private static ushort[] Universes(SigNetEndpointTable table) => table.Endpoints.Select(e => e.Info.Universe).ToArray();

    [Fact]
    public void SparseUniverses_AreNumberedWithoutGaps()
    {
        var table = SigNetEndpointTable.Create(
        [
            SigNetEndpointInfo.Output(60000, "C"),
            SigNetEndpointInfo.Output(1, "A"),
            SigNetEndpointInfo.Output(2000, "B")
        ]);

        Assert.Equal(3, table.Count);
        Assert.Equal(new ushort[] { 1, 2000, 60000 }, Universes(table));
        Assert.Equal(new ushort[] { 1, 2, 3 }, table.Endpoints.Select(e => e.Number));
        Assert.True(table.TryGetOutputEndpoint(60000, out ushort endpoint));
        Assert.Equal(3, endpoint);
    }

    [Fact]
    public void Outputs_ComeFirst_ThenInputs_EachSortedByUniverse()
    {
        var table = SigNetEndpointTable.Create(
        [
            SigNetEndpointInfo.Input(9, "In 9"),
            SigNetEndpointInfo.Output(5, "Out 5"),
            SigNetEndpointInfo.Input(5, "In 5"),
            SigNetEndpointInfo.Output(3, "Out 3")
        ]);

        Assert.Equal(new[] { "Out 3", "Out 5", "In 5", "In 9" }, table.Endpoints.Select(e => e.Info.Label));
        Assert.Equal(new[] { true, true, false, false }, table.Endpoints.Select(e => e.Info.IsOutput));

        // An input and an output on universe 5 are two endpoints; only the output is a lane for sending
        Assert.True(table.TryGetOutputEndpoint(5, out ushort endpoint));
        Assert.Equal(2, endpoint);
        Assert.False(table.TryGetOutputEndpoint(9, out _));
        Assert.Equal("In 5", table.Get(3)!.Label);
        Assert.Null(table.Get(0));
        Assert.Null(table.Get(5));
    }

    [Fact]
    public void EqualInputUniverses_KeepDeclarationOrder()
    {
        var table = SigNetEndpointTable.Create([SigNetEndpointInfo.Input(4, "Port B"), SigNetEndpointInfo.Input(4, "Port A"), SigNetEndpointInfo.Input(1, "Port C")]);

        Assert.Equal(new[] { "Port C", "Port B", "Port A" }, table.Endpoints.Select(e => e.Info.Label));
    }

    [Fact]
    public void DuplicateOutputUniverse_Throws()
    {
        Assert.Throws<ArgumentException>(() => SigNetEndpointTable.Create([SigNetEndpointInfo.Output(7, "A"), SigNetEndpointInfo.Output(7, "B")]));
    }

    [Fact]
    public void UndeclaredOutputs_FollowTheDeclaredEndpoints()
    {
        var table = SigNetEndpointTable.Create([SigNetEndpointInfo.Output(10, "Out"), SigNetEndpointInfo.Input(1, "In")], undeclaredOutputs: [300, 10, 200]);

        // 10 is already declared, so only 300 and 200 are added, in that order
        Assert.Equal(new ushort[] { 10, 1, 300, 200 }, Universes(table));
        Assert.Equal(new ushort[] { 300, 200 }, table.UndeclaredOutputs);
        Assert.Equal(EndpointDirection.Supplier, table.Get(3)!.Direction);
        Assert.Equal(EndpointCapabilities.SupplyLevel, table.Get(3)!.Capabilities);
    }

    [Fact]
    public void ExistingInputOnlyDeviceInfo_KeepsItsNumbering()
    {
        // Hosts that only list inputs with the constructor see the same endpoints as before
        var table = SigNetEndpointTable.Create([new SigNetEndpointInfo(1, "Input 1"), new SigNetEndpointInfo(200, "Input 2")]);

        Assert.Equal(new ushort[] { 1, 200 }, Universes(table));
        Assert.All(table.Endpoints, e => Assert.False(e.Info.IsOutput));
    }

    [Fact]
    public async Task SendLevels_UsesTheDeclaredOutputEndpointAsLane()
    {
        var info = new SigNetDeviceInfo(SoemCode.Create(0x0744, 0x0001), "Model", "Label")
        {
            Endpoints = [SigNetEndpointInfo.Output(1, "A"), SigNetEndpointInfo.Output(2000, "B"), SigNetEndpointInfo.Output(60000, "C")]
        };
        using var test = new TestClient(info);

        await test.Client.SendLevels(60000, new byte[] { 1 });

        // The Join goes out before the first level packet
        var announcement = await NextAnnouncement(test);
        Assert.Equal(new UniverseAnnouncement(60000, UniverseCommand.Join, null, 3), announcement);

        var (_, datagram) = await Wait.For(test.Sent, s => test.Decode(s.Datagram).Path.Resource == SigNetResource.Level);
        Assert.Equal(new SenderId(test.Tuid, 3), test.Decode(datagram).Packet.SenderId);
    }

    [Fact]
    public async Task InputAndOutputOnTheSameUniverse_DoNotShareALane()
    {
        var info = new SigNetDeviceInfo(SoemCode.Create(0x0744, 0x0001), "Model", "Label")
        {
            Roles = SigNetRoles.Sender | SigNetRoles.Node,
            Endpoints = [SigNetEndpointInfo.Input(5, "In 5"), SigNetEndpointInfo.Output(5, "Out 5")]
        };
        using var test = new TestClient(info);
        test.Client.JoinUniverse(5);

        await test.Client.SendLevels(5, new byte[] { 42 }, destination: IPAddress.Loopback);

        // The output is endpoint 1, the input endpoint 2
        var frame = await Wait.For(test.Received);
        Assert.Equal(new SenderId(test.Tuid, 1), frame.SenderId);
        Assert.Equal(new[] { true, false }, test.Client.Endpoints.Endpoints.Select(e => e.Info.IsOutput));
    }

    [Fact]
    public async Task UndeclaredUniverse_GetsTheNextFreeEndpointOnFirstSend()
    {
        var info = new SigNetDeviceInfo(SoemCode.Create(0x0744, 0x0001), "Model", "Label")
        {
            Roles = SigNetRoles.Sender | SigNetRoles.Node,
            Endpoints = [SigNetEndpointInfo.Output(1, "Out 1"), SigNetEndpointInfo.Input(10, "In 10")]
        };
        using var test = new TestClient(info);

        await test.Client.SendLevels(7, new byte[] { 1 });
        await test.Client.SendLevels(1, new byte[] { 1 });
        await test.Client.SendLevels(8, new byte[] { 1 });

        var lanes = new Dictionary<ushort, ushort>();
        await Wait.Until(() =>
        {
            while (test.Sent.TryDequeue(out var sent))
            {
                var (path, packet) = test.Decode(sent.Datagram);
                if (path.Resource == SigNetResource.Level)
                    lanes[path.Index] = packet.SenderId.Endpoint;
            }

            return lanes.Count == 3;
        });

        Assert.Equal(new Dictionary<ushort, ushort> { [1] = 1, [7] = 3, [8] = 4 }, lanes);
        Assert.Equal(4, test.Client.Endpoints.Count);
        Assert.Equal(new ushort[] { 7, 8 }, test.Client.Endpoints.UndeclaredOutputs);
    }

    [Fact]
    public async Task ReplacingDeviceInfo_RenumbersAndReannouncesMovedOutputs()
    {
        var info = new SigNetDeviceInfo(SoemCode.Create(0x0744, 0x0001), "Model", "Label") { Endpoints = [SigNetEndpointInfo.Output(20, "Out 20")] };
        using var test = new TestClient(info);
        test.Client.JoinUniverse(20);

        await test.Client.SendLevels(20, new byte[] { 1 }, destination: IPAddress.Loopback);
        Assert.Equal(new SenderId(test.Tuid, 1), (await Wait.For(test.Received)).SenderId);
        Assert.Equal(new UniverseAnnouncement(20, UniverseCommand.Join, null, 1), await NextAnnouncement(test));

        // A new output on a lower universe takes endpoint 1, so universe 20 moves to endpoint 2
        test.Client.DeviceInfo = info with { Endpoints = [SigNetEndpointInfo.Output(20, "Out 20"), SigNetEndpointInfo.Output(10, "Out 10")] };

        Assert.Equal(new UniverseAnnouncement(20, UniverseCommand.Leave, null, 1), await NextAnnouncement(test));
        Assert.Equal(new UniverseAnnouncement(20, UniverseCommand.Join, null, 2), await NextAnnouncement(test));

        await test.Client.SendLevels(20, new byte[] { 2 }, destination: IPAddress.Loopback);
        var frame = await Wait.For(test.Received);
        Assert.Equal(new SenderId(test.Tuid, 2), frame.SenderId);
        Assert.Equal(1U, frame.SequenceNumber);
        Assert.Equal(new ushort[] { 10, 20 }, test.Client.Endpoints.Endpoints.Select(e => e.Info.Universe));
    }

    [Fact]
    public async Task ReplacingDeviceInfo_KeepsAnActiveUndeclaredOutput()
    {
        var info = new SigNetDeviceInfo(SoemCode.Create(0x0744, 0x0001), "Model", "Label") { Endpoints = [SigNetEndpointInfo.Output(20, "Out 20")] };
        using var test = new TestClient(info);

        await test.Client.SendLevels(20, new byte[] { 1 });
        await test.Client.SendLevels(30, new byte[] { 1 });

        // Universe 20 is dropped from the list but still being sent: it keeps an endpoint after the declared ones
        test.Client.DeviceInfo = info with { Endpoints = [SigNetEndpointInfo.Output(5, "Out 5")] };

        Assert.Equal(new ushort[] { 5, 20, 30 }, test.Client.Endpoints.Endpoints.Select(e => e.Info.Universe));
        Assert.Throws<ArgumentException>(() => test.Client.DeviceInfo = info with { Endpoints = [SigNetEndpointInfo.Output(5, "A"), SigNetEndpointInfo.Output(5, "B")] });
        Assert.Equal(3, test.Client.Endpoints.Count);
    }

    private static async Task<UniverseAnnouncement> NextAnnouncement(TestClient test)
    {
        var (_, datagram) = await Wait.For(test.Sent, s =>
        {
            var (path, packet) = test.Decode(s.Datagram);

            return path.Resource == SigNetResource.Node && SigNetClientTests.ReadTlvs(packet.Payload).Any(t => t.Tid == Tid.Universe);
        });

        return UniverseAnnouncement.Read(SigNetClientTests.ReadTlvs(test.Decode(datagram).Packet.Payload).Single(t => t.Tid == Tid.Universe).Value);
    }
}
