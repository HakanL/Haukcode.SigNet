using System;
using System.Net;
using Haukcode.SigNet.Keys;
using Haukcode.SigNet.Model;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class SigNetPathTests
{
    private static SigNetPacket Parse(SigNetPath path)
    {
        var buffer = new byte[256];
        var header = new SigNetSecurityHeader(SecurityMode.HmacSha256, new SenderId(new Tuid(0x0744, 1), 0), 0, 1, 1);
        int length = SigNetPacketWriter.Write(buffer, 1, path, header, ReadOnlySpan<byte>.Empty, new byte[32]);

        var packet = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(buffer.AsMemory(0, length), packet));

        return packet;
    }

    private static SigNetPacket ParseRaw(params string[] segments)
    {
        // Build a message with arbitrary Uri-Path segments and the minimal security options
        var bytes = new System.Collections.Generic.List<byte> { 0x50, 0x02, 0x00, 0x01 };
        int previous = 0;
        foreach (string segment in segments)
        {
            bytes.Add((byte)(((11 - previous) << 4) | segment.Length));
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(segment));
            previous = 11;
        }

        bytes.AddRange(Convert.FromHexString("E1070400" + "D8130744000000010000" + "D2130000" + "D41300000001" + "D41300000001" + "DD1313" + new string('0', 64)));

        var packet = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(bytes.ToArray(), packet));

        return packet;
    }

    [Theory]
    [InlineData(1, "/sig-net/v1/local/level/1")]
    [InlineData(63999, "/sig-net/v1/local/level/63999")]
    public void Level_RoundTrips(int universe, string expected)
    {
        var path = SigNetPath.Level("local", (ushort)universe);

        Assert.Equal(expected, path.ToString());
        Assert.Equal(SigNetKeyRole.Sender, path.KeyRole);

        Assert.Equal(SigNetUriParseResult.Ok, SigNetUri.TryParsePath(Parse(path), "local", out var parsed));
        Assert.Equal(path, parsed);
    }

    [Fact]
    public void TargetedPaths_UseUppercaseHexTuid()
    {
        var tuid = Tuid.Parse("123456789ABC");

        Assert.Equal("/sig-net/v1/Hall_A/node/123456789ABC/0", SigNetPath.Node("Hall_A", tuid, 0).ToString());
        Assert.Equal("/sig-net/v1/local/manager/123456789ABC/5", SigNetPath.Manager("local", tuid, 5).ToString());
        Assert.Equal("/sig-net/v1/local/node_beacon/123456789ABC/0", SigNetPath.NodeBeacon(tuid).ToString());

        var path = SigNetPath.Node("Hall_A", tuid, 3);
        Assert.Equal(SigNetUriParseResult.Ok, SigNetUri.TryParsePath(Parse(path), null, out var parsed));
        Assert.Equal(path, parsed);
        Assert.Equal(SigNetKeyRole.Citizen, parsed.KeyRole);
    }

    [Fact]
    public void KeyRoles_FollowAppendixA()
    {
        Assert.Equal(SigNetKeyRole.ManagerGlobal, SigNetPath.Poll("local").KeyRole);
        Assert.Equal(SigNetKeyRole.ManagerLocal, SigNetPath.Manager("local", default, 0).KeyRole);
        Assert.Equal(SigNetKeyRole.Sender, SigNetPath.Sync("local").KeyRole);
        Assert.Equal(SigNetKeyRole.Citizen, SigNetPath.NodeLost("local", default).KeyRole);
        Assert.Equal(SigNetKeyRole.None, SigNetPath.NodeBeacon(default).KeyRole);
    }

    [Fact]
    public void Parse_RejectsWrongScopeVersionAndMalformedNumbers()
    {
        Assert.Equal(SigNetUriParseResult.WrongScope, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "other", "level", "1"), "local", out _));
        Assert.Equal(SigNetUriParseResult.UnsupportedVersion, SigNetUri.TryParsePath(ParseRaw("sig-net", "v2", "local", "level", "1"), "local", out _));
        Assert.Equal(SigNetUriParseResult.NotSigNet, SigNetUri.TryParsePath(ParseRaw("foo", "v1", "local", "level", "1"), "local", out _));
        Assert.Equal(SigNetUriParseResult.UnknownResource, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "local", "levels", "1"), "local", out _));
        Assert.Equal(SigNetUriParseResult.Malformed, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "local", "level", "01"), "local", out _));
        Assert.Equal(SigNetUriParseResult.Malformed, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "local", "level", "0"), "local", out _));
        Assert.Equal(SigNetUriParseResult.Malformed, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "local", "level", "64000"), "local", out _));
        Assert.Equal(SigNetUriParseResult.Malformed, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "local", "level"), "local", out _));
        Assert.Equal(SigNetUriParseResult.Malformed, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "local", "node", "123456789abc", "0"), "local", out _));
        Assert.Equal(SigNetUriParseResult.Malformed, SigNetUri.TryParsePath(ParseRaw("sig-net", "v1", "local", "sync", "1"), "local", out _));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(109, 109)]
    [InlineData(110, 1)]
    [InlineData(218, 109)]
    [InlineData(219, 1)]
    [InlineData(63999, 16)]
    public void MulticastFolding_Uses109Groups(int universe, int expectedIndex)
    {
        Assert.Equal(expectedIndex, SigNetMulticast.GetFoldingIndex((ushort)universe));
        Assert.Equal(IPAddress.Parse($"239.254.0.{expectedIndex}"), SigNetMulticast.GetAddress(SigNetPath.Level("local", (ushort)universe)));
    }

    [Fact]
    public void AdministrativeGroups_FollowAppendixA()
    {
        var tuid = new Tuid(0x0744, 1);

        Assert.Equal(IPAddress.Parse("239.254.255.255"), SigNetMulticast.GetAddress(SigNetPath.NodeBeacon(tuid)));
        Assert.Equal(IPAddress.Parse("239.254.255.254"), SigNetMulticast.GetAddress(SigNetPath.NodeLost("local", tuid)));
        Assert.Equal(IPAddress.Parse("239.254.255.253"), SigNetMulticast.GetAddress(SigNetPath.Node("local", tuid, 0)));
        Assert.Equal(IPAddress.Parse("239.254.255.252"), SigNetMulticast.GetAddress(SigNetPath.Poll("local")));
        Assert.Equal(IPAddress.Parse("239.254.255.251"), SigNetMulticast.GetAddress(SigNetPath.Manager("local", tuid, 1)));
        Assert.Equal(IPAddress.Parse("239.254.255.250"), SigNetMulticast.GetAddress(SigNetPath.Sync("local")));
        Assert.Equal(IPAddress.Parse("239.254.255.250"), SigNetMulticast.GetAddress(SigNetPath.Timecode("local", 1)));
        Assert.Equal(IPAddress.Parse("239.254.255.249"), SigNetMulticast.GetAddress(SigNetPath.Preview("local", 1)));
        Assert.Equal(IPAddress.Parse("239.254.255.248"), SigNetMulticast.GetAddress(SigNetPath.Aux("local", tuid, 1)));
    }

    [Theory]
    [InlineData("239.254.0.1", true)]
    [InlineData("239.255.0.1", true)]
    [InlineData("224.0.0.1", true)]
    [InlineData("192.168.1.10", false)]
    [InlineData("127.0.0.1", false)]
    // Haukcode.Network before 1.1 matched only 239.255.0.0/16, which misclassified Sig-Net groups
    public void IsMulticast_CoversTheWholeRange(string address, bool expected)
    {
        Assert.Equal(expected, Haukcode.Network.Utils.IsMulticast(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("local", true)]
    [InlineData("Hall_A-2.x~", true)]
    [InlineData("", false)]
    [InlineData("has space", false)]
    [InlineData("slash/", false)]
    [InlineData("0123456789012345678901234567890123", false)]
    public void Scope_Validation(string scope, bool valid)
    {
        Assert.Equal(valid, SigNetUri.IsValidScope(scope));
    }
}
