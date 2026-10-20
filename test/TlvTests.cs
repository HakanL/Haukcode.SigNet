using System;
using System.Linq;
using System.Net;
using Haukcode.SigNet.Model;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class TlvTests
{
    [Fact]
    public void Writer_WritesBigEndianHeaders()
    {
        var buffer = new byte[32];
        var writer = new TlvWriter(buffer);

        writer.WriteByte(Tid.Priority, 150);
        writer.Write(Tid.Level, new byte[] { 0xFF, 0x80, 0x00 });
        writer.WriteEmpty(Tid.Sync);

        Assert.Equal(Convert.FromHexString("0102000196" + "01010003FF8000" + "02010000"), writer.Written.ToArray());
    }

    [Fact]
    public void Reader_WalksAllTlvs()
    {
        var payload = Convert.FromHexString("0102000196" + "01010003FF8000");

        Assert.Equal(TlvValidationResult.Ok, TlvReader.Validate(payload));

        var reader = new TlvReader(payload);
        Assert.True(reader.TryRead(out ushort tid, out var value));
        Assert.Equal(Tid.Priority, tid);
        Assert.Equal(new byte[] { 150 }, value.ToArray());
        Assert.True(reader.TryRead(out tid, out value));
        Assert.Equal(Tid.Level, tid);
        Assert.Equal(3, value.Length);
        Assert.False(reader.TryRead(out _, out _));
    }

    [Fact]
    public void Validate_SkipsUnknownAndManufacturerTids()
    {
        // Unknown standard TID 0x7777 with 3 bytes, manufacturer TID 0x8001 with 2 bytes, then a level
        var payload = Convert.FromHexString("77770003AABBCC" + "80010002BEEF" + "0101000100");

        Assert.Equal(TlvValidationResult.Ok, TlvReader.Validate(payload));
    }

    [Theory]
    // Header cut short
    [InlineData("010100", TlvValidationResult.Truncated)]
    // Value longer than the payload
    [InlineData("01010004FF80", TlvValidationResult.Truncated)]
    // TID_LEVEL with 0 bytes (not queryable, so not a GET either)
    [InlineData("01010000", TlvValidationResult.InvalidLength)]
    // TID_SYNC carries nothing
    [InlineData("0201000100", TlvValidationResult.InvalidLength)]
    // TID_POLL is exactly 25 bytes
    [InlineData("0001000100", TlvValidationResult.InvalidLength)]
    // TID_RT_SUPPORTED_TIDS must be a multiple of 2
    [InlineData("06010003010101", TlvValidationResult.InvalidLength)]
    // TID_DG_SECURITY_EVENT is 7, 11 or 23 bytes
    [InlineData("FF010008" + "0001000000010000", TlvValidationResult.InvalidLength)]
    public void Validate_RejectsMalformed(string hex, TlvValidationResult expected)
    {
        Assert.Equal(expected, TlvReader.Validate(Convert.FromHexString(hex)));
    }

    [Fact]
    public void Validate_AcceptsLevelOf512AndRejects513()
    {
        var ok = new byte[4 + 512];
        ok[0] = 0x01; ok[1] = 0x01; ok[2] = 0x02; ok[3] = 0x00;
        Assert.Equal(TlvValidationResult.Ok, TlvReader.Validate(ok));

        var tooLong = new byte[4 + 513];
        tooLong[0] = 0x01; tooLong[1] = 0x01; tooLong[2] = 0x02; tooLong[3] = 0x01;
        Assert.Equal(TlvValidationResult.InvalidLength, TlvReader.Validate(tooLong));
    }

    [Fact]
    public void Validate_AllowsZeroLengthGetOnQueryableTids()
    {
        Assert.Equal(TlvValidationResult.Ok, TlvReader.Validate(Convert.FromHexString("06050000" + "09040000")));
    }

    [Fact]
    public void EpCapability_AcceptsLegacyLength4()
    {
        Assert.Equal(TlvValidationResult.Ok, TlvReader.Validate(Convert.FromHexString("0904000400000001")));
        Assert.Equal(TlvValidationResult.Ok, TlvReader.Validate(Convert.FromHexString("09040006000000010004")));
        Assert.Equal(TlvValidationResult.InvalidLength, TlvReader.Validate(Convert.FromHexString("090400050000000100")));
    }

    [Fact]
    public void Writer_ThrowsWhenFull()
    {
        var buffer = new byte[6];
        var writer = new TlvWriter(buffer);
        writer.WriteByte(Tid.Priority, 1);

        bool threw = false;
        try
        {
            writer.WriteByte(Tid.Priority, 1);
        }
        catch (InvalidOperationException)
        {
            threw = true;
        }

        Assert.True(threw);
    }

    [Fact]
    public void Catalogue_CoversSection11AndHasUniqueNames()
    {
        Assert.Equal(55, TidCatalogue.All.Count);
        Assert.Equal(TidCatalogue.All.Count, TidCatalogue.All.Select(t => t.Name).Distinct().Count());
        Assert.True(TidCatalogue.TryGet(Tid.Universe, out var universe));
        Assert.Equal(9, universe.MinLength);
        Assert.False(TidCatalogue.TryGet(0x060C, out _));
    }

    [Fact]
    public void Poll_RoundTrips()
    {
        var poll = new PollRequest(new Tuid(0x5379, 1), 0x53790001, new Tuid(0, 0), new Tuid(0xFFFF, 0xFFFFFFFF), PollRequest.AllEndpoints, QueryLevel.Full);
        var buffer = new byte[PollRequest.Length];

        poll.WriteTo(buffer);

        Assert.Equal(poll, PollRequest.Read(buffer));
        Assert.True(poll.Includes(new Tuid(0x0744, 5)));
        Assert.False(poll.IsTargeted);
    }

    [Fact]
    public void Universe_RoundTripsWithDefaultGroup()
    {
        var announcement = new UniverseAnnouncement(110, UniverseCommand.Join, null, 110);
        var buffer = new byte[UniverseAnnouncement.Length];

        announcement.WriteTo(buffer);

        Assert.Equal(Convert.FromHexString("006E" + "01" + "00000000" + "006E"), buffer);
        Assert.Equal(announcement, UniverseAnnouncement.Read(buffer));
    }

    [Fact]
    public void SecurityEvent_LengthFollowsAddress()
    {
        var withIpv4 = new SecurityEvent(SecurityEventCode.HmacFailure, 3, IPAddress.Parse("10.0.0.5"));
        var buffer = new byte[23];

        withIpv4.WriteTo(buffer);

        Assert.Equal(11, withIpv4.Length);
        Assert.Equal(Convert.FromHexString("0001" + "00000003" + "01" + "0A000005"), buffer[..11]);
        Assert.Equal(withIpv4, SecurityEvent.Read(buffer.AsSpan(0, 11)));
        Assert.Equal(7, new SecurityEvent(SecurityEventCode.ReplayDetected, 1, null).Length);
        Assert.Equal(23, new SecurityEvent(SecurityEventCode.ReplayDetected, 1, IPAddress.IPv6Loopback).Length);
    }
}
