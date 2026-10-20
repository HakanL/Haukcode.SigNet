using System;
using Haukcode.SigNet.Keys;
using Haukcode.SigNet.Model;
using Haukcode.SigNet.Security;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class PacketVerifierTests : IDisposable
{
    private static readonly Tuid ownTuid = new(0x0744, 0x00000042);
    private static readonly Tuid senderTuid = Tuid.Parse("123456789ABC");

    private readonly SigNetKeys keys = SigNetKeys.FromRootKey(Convert.FromHexString(KeyDerivationTests.AppendixGRootKey), ownTuid);
    private readonly FakeTimeProvider time = new();
    private readonly SigNetPacketVerifier verifier;
    private readonly SigNetPacket packet = new();

    public PacketVerifierTests()
    {
        this.verifier = new SigNetPacketVerifier(this.keys, "local", ownTuid, new ReplayProtection(timeProvider: this.time), this.time);
        // Past the post-link-up window unless a test rewinds it
        this.time.Advance(TimeSpan.FromSeconds(3));
    }

    public void Dispose()
    {
        this.keys.Dispose();
    }

    private byte[] Build(SigNetPath path, uint session, uint sequence, byte[]? payload = null, SigNetKeyRole? keyRole = null, ushort endpoint = 1, byte mode = SecurityMode.HmacSha256)
    {
        var header = new SigNetSecurityHeader(mode, new SenderId(senderTuid, endpoint), 0, session, sequence);
        var buffer = new byte[1500];
        int length = SigNetPacketWriter.Write(buffer, 1, path, header, payload ?? CoapCodecTests.AppendixGPayload, this.keys.GetKey(keyRole ?? path.KeyRole));

        return buffer[..length];
    }

    private VerifyResult Verify(byte[] datagram) => this.verifier.Verify(datagram, this.packet, out _);

    [Fact]
    public void ValidLevelPacket_IsAccepted()
    {
        var datagram = Build(SigNetPath.Level("local", 1), 5, 0xA2);

        Assert.Equal(VerifyResult.Accepted, this.verifier.Verify(datagram, this.packet, out var path));
        Assert.Equal(SigNetResource.Level, path.Resource);
        Assert.Equal(1, path.Index);
    }

    [Fact]
    public void AppendixGPacket_IsAccepted()
    {
        // Sender 123456789ABC/1, session 5, sequence 0xA2, signed with the Appendix G Ks
        Assert.Equal(VerifyResult.Accepted, Verify(CoapCodecTests.WriteAppendixGPacket()));
    }

    [Fact]
    public void SamePacketTwice_IsRejectedAsReplay()
    {
        var datagram = Build(SigNetPath.Level("local", 1), 5, 100);

        Assert.Equal(VerifyResult.Accepted, Verify(datagram));
        Assert.Equal(VerifyResult.SequenceReplay, Verify(datagram));
        Assert.Equal(VerifyResult.SequenceReplay, Verify(Build(SigNetPath.Level("local", 1), 5, 99)));
        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Level("local", 1), 5, 101)));
    }

    [Fact]
    public void OlderSession_IsRejectedAsEpochRegression()
    {
        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Level("local", 1), 5, 100)));
        Assert.Equal(VerifyResult.EpochRegression, Verify(Build(SigNetPath.Level("local", 1), 4, 1000)));
        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Level("local", 1), 6, 1)));
    }

    [Fact]
    public void TamperedPayload_FailsHmac_AndDoesNotMoveTheWindow()
    {
        var datagram = Build(SigNetPath.Level("local", 1), 5, 100);
        datagram[^1] ^= 0x01;

        Assert.Equal(VerifyResult.HmacFailure, Verify(datagram));

        // The forged packet never committed sequence 100, so the genuine one still passes
        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Level("local", 1), 5, 100)));
    }

    [Fact]
    public void TamperedSequenceNumber_FailsHmac()
    {
        var datagram = Build(SigNetPath.Level("local", 1), 5, 100);
        Assert.Equal(VerifyResult.Accepted, Verify(datagram));

        // Bump the sequence number in the option (last byte before the Auth option header)
        int sequenceEnd = datagram.Length - CoapCodecTests.AppendixGPayload.Length - 1 - SigNetHmac.TagLength - 3;
        datagram[sequenceEnd - 1]++;

        Assert.Equal(VerifyResult.HmacFailure, Verify(datagram));
    }

    [Fact]
    public void WrongKeyForTheUri_FailsHmac()
    {
        // Level traffic signed with Kc instead of Ks (Appendix A picks the key by URI)
        Assert.Equal(VerifyResult.HmacFailure, Verify(Build(SigNetPath.Level("local", 1), 5, 1, keyRole: SigNetKeyRole.Citizen)));
    }

    [Fact]
    public void ScopeVersionAndTarget_AreCheckedBeforeCrypto()
    {
        Assert.Equal(VerifyResult.WrongScope, Verify(Build(SigNetPath.Level("Hall_B", 1), 5, 1)));
        Assert.Equal(VerifyResult.NotForThisDevice, Verify(Build(SigNetPath.Manager("local", new Tuid(0x0744, 7), 0), 5, 1, Convert.FromHexString("06050000"), SigNetKeyRole.ManagerGlobal)));
    }

    [Fact]
    public void PollSignedWithManagerGlobal_IsAccepted()
    {
        var poll = new byte[4 + PollRequest.Length];
        poll[0] = 0x00; poll[1] = 0x01; poll[3] = PollRequest.Length;
        new PollRequest(senderTuid, 0x53790001, default, Tuid.FromValue(0xFFFFFFFFFFFF), 0, QueryLevel.Heartbeat).WriteTo(poll.AsSpan(4));

        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Poll("local"), 5, 1, poll, endpoint: 0)));
    }

    [Fact]
    public void ManagerCommandWithoutManagerLocalKey_IsNoKey()
    {
        using var guestKeys = SigNetKeys.FromDerivedKeys(this.keys.SenderKey, this.keys.CitizenKey, this.keys.ManagerGlobalKey);
        var guestVerifier = new SigNetPacketVerifier(guestKeys, "local", ownTuid, new ReplayProtection(), this.time);

        var datagram = Build(SigNetPath.Manager("local", ownTuid, 0), 5, 1, Convert.FromHexString("06050000"), endpoint: 0);

        Assert.Equal(VerifyResult.NoKey, guestVerifier.Verify(datagram, this.packet, out _));
        Assert.Equal(VerifyResult.Accepted, Verify(datagram));
    }

    [Fact]
    public void ManagerSet_IsLockedOutDuringBootstrapWindow_GetIsNot()
    {
        this.verifier.SignalLinkUp();
        var set = Convert.FromHexString("0605000300" + "4142");
        var get = Convert.FromHexString("06050000");

        Assert.True(this.verifier.InBootstrapWindow);
        Assert.Equal(VerifyResult.ConfigurationLockout, Verify(Build(SigNetPath.Manager("local", ownTuid, 0), 5, 1, set, endpoint: 0)));
        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Manager("local", ownTuid, 0), 5, 2, get, endpoint: 0)));

        this.time.Advance(SigNetPacketVerifier.BootstrapWindow);
        Assert.False(this.verifier.InBootstrapWindow);
        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Manager("local", ownTuid, 0), 5, 3, set, endpoint: 0)));
    }

    [Fact]
    public void AuthenticatedButMalformedTlv_IsDroppedWithoutStateChange()
    {
        // TID_LEVEL claiming 4 bytes with 3 present
        var malformed = Convert.FromHexString("01010004FF8000");

        Assert.Equal(VerifyResult.MalformedPayload, Verify(Build(SigNetPath.Level("local", 1), 5, 100, malformed)));
        Assert.Equal(VerifyResult.Accepted, Verify(Build(SigNetPath.Level("local", 1), 5, 100)));
    }

    [Fact]
    public void BeaconsAndOpenMode_AreNotProcessed()
    {
        var header = new SigNetSecurityHeader(SecurityMode.Beacon, new SenderId(senderTuid, 0), 0, 0, 0);
        var buffer = new byte[256];
        int length = SigNetPacketWriter.Write(buffer, 1, SigNetPath.NodeBeacon(senderTuid), header, Convert.FromHexString("0002000C" + "123456789ABC537900010000"), default);
        Assert.Equal(VerifyResult.Beacon, Verify(buffer[..length]));

        header = header with { SecurityMode = SecurityMode.Open };
        length = SigNetPacketWriter.Write(buffer, 1, SigNetPath.Level("local", 1), header, CoapCodecTests.AppendixGPayload, default);
        Assert.Equal(VerifyResult.OpenModeRejected, Verify(buffer[..length]));
    }

    [Fact]
    public void NetworkshopOpenModePoll_WithoutSessionAndSequence_IsOpenModeRejected()
    {
        // Captured from NETworkshop v0.11: an Open Mode poll that omits Session-ID and Seq-Num
        var datagram = Convert.FromHexString("5002000ab77369672d6e6574027631056c6f63616c04706f6c6ce1070401d8135379e3c2311e0000d2130000d053ff000100195379e3c2311e53790001000000000000ffffffffffffffff03");

        Assert.Equal(VerifyResult.OpenModeRejected, Verify(datagram));
    }

    [Fact]
    public void SecureModeWithoutSessionAndSequence_IsMalformed()
    {
        var datagram = Convert.FromHexString("5002000ab77369672d6e6574027631056c6f63616c04706f6c6ce1070400d8135379e3c2311e0000d2130000d053ff000100195379e3c2311e53790001000000000000ffffffffffffffff03");

        Assert.Equal(VerifyResult.Malformed, Verify(datagram));
    }

    [Fact]
    public void UnknownSecurityMode_IsDropped()
    {
        var datagram = Build(SigNetPath.Level("local", 1), 5, 1);
        int mode = Array.IndexOf(datagram, (byte)0xE1) + 3;
        datagram[mode] = 0x02;

        Assert.Equal(VerifyResult.UnsupportedSecurityMode, Verify(datagram));
    }
}
