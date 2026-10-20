using System;
using System.Linq;
using System.Text;
using Haukcode.SigNet.Model;
using Haukcode.SigNet.Security;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class CoapCodecTests
{
    // Spec Appendix G section 21.4
    internal const string AppendixGHmacInput = "2f7369672d6e65742f76312f6c6f63616c2f6c6576656c2f3100123456789abc0001000000000005000000a201010003ff8000";
    internal const string AppendixGTag = "c7126005fb474564dc7ce4c122e3e60d4b13dedeb8c6ad1e8daa51e5c66a8225";
    internal static readonly byte[] AppendixGPayload = Convert.FromHexString("01010003FF8000");
    internal static readonly SigNetSecurityHeader AppendixGHeader = new(SecurityMode.HmacSha256, SenderId.FromValue(0x123456789ABC0001), 0x0000, 5, 0xA2);

    internal static byte[] WriteAppendixGPacket(ushort messageId = 0x1234)
    {
        var buffer = new byte[SigNetPacketWriter.GetMaxLength(AppendixGPayload.Length)];
        int length = SigNetPacketWriter.Write(buffer, messageId, SigNetPath.Level("local", 1), AppendixGHeader, AppendixGPayload, Convert.FromHexString(KeyDerivationTests.AppendixGSenderKey));

        return buffer[..length];
    }

    [Fact]
    public void HmacInput_MatchesAppendixG()
    {
        var uri = Encoding.ASCII.GetBytes("/sig-net/v1/local/level/1");
        var input = new byte[SigNetHmac.GetInputLength(uri.Length, AppendixGPayload.Length)];

        int length = SigNetHmac.BuildInput(uri, AppendixGHeader, AppendixGPayload, input);

        Assert.Equal(51, length);
        Assert.Equal(AppendixGHmacInput, Convert.ToHexStringLower(input));
    }

    [Fact]
    public void Packet_MatchesAppendixGValuesAndCoapEncoding()
    {
        var expected = Convert.FromHexString(
            "50021234" +                    // Ver 1, NON, TKL 0, POST, Message ID 0x1234
            "B7" + "7369672D6E6574" +       // Uri-Path (delta 11) "sig-net"
            "02" + "7631" +                 // Uri-Path (delta 0) "v1"
            "05" + "6C6F63616C" +           // "local"
            "05" + "6C6576656C" +           // "level"
            "01" + "31" +                   // "1"
            "E10704" + "00" +               // Security-Mode: delta 2065 = 269 + 0x0704, length 1
            "D813" + "123456789ABC0001" +   // Sender-ID: delta 32 = 13 + 0x13, length 8
            "D213" + "0000" +               // Mfg-Code
            "D413" + "00000005" +           // Session-ID
            "D413" + "000000A2" +           // Seq-Num
            "DD1313" + AppendixGTag +       // Auth: delta 32, length 32 (both extended)
            "FF" + "01010003FF8000");       // Payload marker, TID_LEVEL TLV

        Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(WriteAppendixGPacket()));
    }

    [Fact]
    public void Packet_ParsesBackAndVerifies()
    {
        var packet = new SigNetPacket();

        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(WriteAppendixGPacket(), packet));

        Assert.Equal(Coap.TypeNonConfirmable, packet.CoapType);
        Assert.Equal(0x1234, packet.MessageId);
        Assert.Equal(AppendixGHeader, packet.Header);
        Assert.Equal(5, packet.UriSegmentCount);
        Assert.Equal(AppendixGPayload, packet.Payload.ToArray());
        Assert.Equal(AppendixGTag, Convert.ToHexStringLower(packet.Auth.Span));

        var uri = new byte[128];
        Assert.Equal("/sig-net/v1/local/level/1", Encoding.ASCII.GetString(uri, 0, packet.WriteUriString(uri)));

        Assert.True(SigNetHmac.Verify(Convert.FromHexString(KeyDerivationTests.AppendixGSenderKey), packet));
        Assert.False(SigNetHmac.Verify(Convert.FromHexString(KeyDerivationTests.AppendixGCitizenKey), packet));
    }

    [Fact]
    public void Packet_WithEmptyPayload_OmitsMarker()
    {
        var buffer = new byte[256];
        var header = AppendixGHeader with { SequenceNumber = 7 };
        int length = SigNetPacketWriter.Write(buffer, 1, SigNetPath.Sync("local"), header, ReadOnlySpan<byte>.Empty, new byte[32]);

        var packet = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(buffer.AsMemory(0, length), packet));
        Assert.True(packet.Payload.IsEmpty);
        Assert.DoesNotContain(Coap.PayloadMarker, buffer[(length - SigNetHmac.TagLength - 3)..(length - SigNetHmac.TagLength)]);
        Assert.True(SigNetHmac.Verify(new byte[32], packet));
    }

    [Fact]
    public void Beacon_HasZeroLengthAuthAndNeedsNoKey()
    {
        var buffer = new byte[256];
        var header = new SigNetSecurityHeader(SecurityMode.Beacon, new SenderId(new Tuid(0x0744, 1), 0), 0, 0, 0);
        int length = SigNetPacketWriter.Write(buffer, 1, SigNetPath.NodeBeacon(new Tuid(0x0744, 1)), header, new byte[] { 0, 2, 0, 0 }, ReadOnlySpan<byte>.Empty);

        var packet = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(buffer.AsMemory(0, length), packet));
        Assert.True(packet.HasAuth);
        Assert.True(packet.Auth.IsEmpty);
    }

    [Fact]
    public void Parser_SkipsToken()
    {
        var packet = WriteAppendixGPacket().ToList();
        packet[0] = 0x52;                          // TKL 2
        packet.InsertRange(4, new byte[] { 0xAB, 0xCD });

        var parsed = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(packet.ToArray(), parsed));
        Assert.Equal(2, parsed.TokenLength);
        Assert.True(SigNetHmac.Verify(Convert.FromHexString(KeyDerivationTests.AppendixGSenderKey), parsed));
    }

    [Fact]
    public void Parser_IgnoresUnknownElectiveOptionButRejectsCritical()
    {
        // Insert option 2238 (elective, delta 2 after Auth) and 2239 (critical) before the payload marker
        var packet = WriteAppendixGPacket();
        int marker = packet.Length - AppendixGPayload.Length - 1;

        var elective = packet[..marker].Concat(new byte[] { 0x21, 0x99 }).Concat(packet[marker..]).ToArray();
        var critical = packet[..marker].Concat(new byte[] { 0x31, 0x99 }).Concat(packet[marker..]).ToArray();

        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(elective, new SigNetPacket()));
        Assert.Equal(SigNetParseResult.UnsupportedCriticalOption, SigNetPacketParser.TryParse(critical, new SigNetPacket()));
    }

    [Fact]
    public void Parser_RejectsMalformedMessages()
    {
        var good = WriteAppendixGPacket();
        var packet = new SigNetPacket();

        Assert.Equal(SigNetParseResult.TooShort, SigNetPacketParser.TryParse(good[..3], packet));

        var wrongVersion = (byte[])good.Clone();
        wrongVersion[0] = 0x90;
        Assert.Equal(SigNetParseResult.UnsupportedCoapVersion, SigNetPacketParser.TryParse(wrongVersion, packet));

        var badTokenLength = (byte[])good.Clone();
        badTokenLength[0] = 0x59;
        Assert.Equal(SigNetParseResult.InvalidTokenLength, SigNetPacketParser.TryParse(badTokenLength, packet));

        var get = (byte[])good.Clone();
        get[1] = 0x01;
        Assert.Equal(SigNetParseResult.NotPost, SigNetPacketParser.TryParse(get, packet));

        var reservedNibble = (byte[])good.Clone();
        reservedNibble[4] = 0xF7;
        Assert.Equal(SigNetParseResult.MalformedOption, SigNetPacketParser.TryParse(reservedNibble, packet));

        // Cut inside the Auth option
        Assert.Equal(SigNetParseResult.MalformedOption, SigNetPacketParser.TryParse(good[..(good.Length - 20)], packet));

        // Marker with nothing after it
        int marker = good.Length - AppendixGPayload.Length;
        Assert.Equal(SigNetParseResult.EmptyPayloadAfterMarker, SigNetPacketParser.TryParse(good[..marker], packet));

        // Security-Mode with length 2 (shift the rest of the message along)
        int modeOption = Array.IndexOf(good, (byte)0xE1);
        var wideMode = good[..modeOption].Concat(new byte[] { 0xE2, 0x07, 0x04, 0x00, 0x00 }).Concat(good[(modeOption + 4)..]).ToArray();
        Assert.Equal(SigNetParseResult.InvalidOptionLength, SigNetPacketParser.TryParse(wideMode, packet));
    }

    [Fact]
    public void Parser_RequiresAllSecurityOptions()
    {
        // Only a Uri-Path and the Security-Mode
        var packet = Convert.FromHexString("50020001" + "B7" + "7369672D6E6574" + "E10704" + "00");

        Assert.Equal(SigNetParseResult.MissingSecurityOption, SigNetPacketParser.TryParse(packet, new SigNetPacket()));
    }

    [Fact]
    public void Parser_RejectsDuplicateSecurityOption()
    {
        var good = WriteAppendixGPacket();
        int modeOption = Array.IndexOf(good, (byte)0xE1);
        // A second Security-Mode right after the first (delta 0)
        var duplicate = good[..(modeOption + 4)].Concat(new byte[] { 0x01, 0x00 }).Concat(good[(modeOption + 4)..]).ToArray();

        Assert.Equal(SigNetParseResult.DuplicateOption, SigNetPacketParser.TryParse(duplicate, new SigNetPacket()));
    }

    [Fact]
    public void Parser_RequiresHmacLengthAuthInSecureMode()
    {
        var good = WriteAppendixGPacket();
        int authOption = good.Length - AppendixGPayload.Length - 1 - SigNetHmac.TagLength - 3;
        Assert.Equal(0xDD, good[authOption]);

        // Auth with 16 bytes
        var shortAuth = good[..authOption].Concat(new byte[] { 0xDD, 0x13, 0x03 }).Concat(new byte[16]).Concat(good[^(AppendixGPayload.Length + 1)..]).ToArray();

        Assert.Equal(SigNetParseResult.InvalidOptionLength, SigNetPacketParser.TryParse(shortAuth, new SigNetPacket()));
    }

    [Fact]
    public void Writer_EnforcesPayloadAndMessageCaps()
    {
        var buffer = new byte[4096];

        Assert.Throws<ArgumentException>(() => SigNetPacketWriter.Write(buffer, 1, SigNetPath.Level("local", 1), AppendixGHeader, new byte[Coap.MaxPayloadLength + 1], new byte[32]));

        int length = SigNetPacketWriter.Write(buffer, 1, SigNetPath.Level("local", 63999), AppendixGHeader, new byte[Coap.MaxPayloadLength], new byte[32]);
        Assert.True(length <= Coap.MaxMessageLength);
    }

    [Fact]
    public void Writer_RequiresKeyForSecureMode()
    {
        Assert.Throws<ArgumentException>(() => SigNetPacketWriter.Write(new byte[256], 1, SigNetPath.Sync("local"), AppendixGHeader, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void UriString_PercentEncodesOutsidePathCharacters()
    {
        // A Uri-Path "a b" and a Uri-Query "x&y"
        var message = Convert.FromHexString("50020001" + "B3" + "612062" + "43" + "782679");
        var packet = new SigNetPacket();
        SigNetPacketParser.TryParse(message, packet);

        var uri = new byte[64];
        Assert.Equal("/a%20b?x%26y", Encoding.ASCII.GetString(uri, 0, packet.WriteUriString(uri)));
    }
}
