using Haukcode.SigNet.Keys;
using Haukcode.SigNet.Model;

namespace Haukcode.SigNet.Security;

public enum VerifyResult
{
    Accepted = 0,

    /// <summary>Not a well-formed Sig-Net CoAP message.</summary>
    Malformed,

    /// <summary>A Security-Mode this implementation does not know (spec 8.6 step 1a).</summary>
    UnsupportedSecurityMode,

    /// <summary>An offboarded beacon (0xFF); never verified or acted on (step 1b).</summary>
    Beacon,

    /// <summary>An Open Mode packet (0x01), dropped by a device in Secure Mode (step 1d).</summary>
    OpenModeRejected,

    /// <summary>Not a /sig-net path, or an unknown resource.</summary>
    NotSigNet,

    /// <summary>A URI version other than v1 (step 5, spec 12.2).</summary>
    UnsupportedVersion,

    /// <summary>A different scope (step 6a).</summary>
    WrongScope,

    /// <summary>A targeted URI for another device's TUID (step 6b).</summary>
    NotForThisDevice,

    /// <summary>This device does not hold the key the URI requires (Km_local in a guest key set).</summary>
    NoKey,

    EpochRegression,

    SequenceReplay,

    TableSaturated,

    /// <summary>HMAC mismatch (step 9).</summary>
    HmacFailure,

    /// <summary>Authenticated, but a TLV is truncated or has an illegal length (spec 10.1.3).</summary>
    MalformedPayload,

    /// <summary>A SET on /manager inside the post-link-up bootstrap window (spec 8.6.4).</summary>
    ConfigurationLockout
}

/// <summary>
/// The receive processing order of spec 8.6: security mode pre-check, CoAP checks (in the
/// parser), URI version, scope and target, freshness, HMAC with the key the URI selects, then the
/// state commit. TLV structure is validated after the HMAC and before the commit, so a malformed
/// payload changes no state (spec 10.1.3).
/// </summary>
public sealed class SigNetPacketVerifier
{
    /// <summary>
    /// &lt;first_packet_bootstrap_window&gt; (spec Appendix B).
    /// </summary>
    public static readonly TimeSpan BootstrapWindow = TimeSpan.FromMilliseconds(2000);

    private readonly SigNetKeys keys;
    private readonly ReplayProtection replayProtection;
    private readonly TimeProvider timeProvider;
    private long linkUpTimestamp;

    public SigNetPacketVerifier(SigNetKeys keys, string scope, Tuid tuid, ReplayProtection replayProtection, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(replayProtection);
        SigNetUri.CheckScope(scope);

        this.keys = keys;
        Scope = scope;
        Tuid = tuid;
        this.replayProtection = replayProtection;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.linkUpTimestamp = this.timeProvider.GetTimestamp();
    }

    public string Scope { get; }

    public Tuid Tuid { get; }

    public ReplayProtection ReplayProtection => this.replayProtection;

    /// <summary>
    /// Restart the bootstrap window, for a host that sees the network link come up (spec 8.6.4
    /// starts it on link-up; the constructor starts it at creation).
    /// </summary>
    public void SignalLinkUp()
    {
        this.linkUpTimestamp = this.timeProvider.GetTimestamp();
    }

    public bool InBootstrapWindow => this.timeProvider.GetElapsedTime(this.linkUpTimestamp) < BootstrapWindow;

    public VerifyResult Verify(ReadOnlyMemory<byte> datagram, SigNetPacket packet, out SigNetPath path)
    {
        path = default;

        if (SigNetPacketParser.TryParse(datagram, packet) != SigNetParseResult.Ok)
            return VerifyResult.Malformed;

        // Step 1
        switch (packet.SecurityMode)
        {
            case SecurityMode.HmacSha256:
                break;

            case SecurityMode.Beacon:
                return VerifyResult.Beacon;

            case SecurityMode.Open:
                // This device always runs in Secure Mode, so Open Mode traffic is a downgrade attempt
                return VerifyResult.OpenModeRejected;

            default:
                return VerifyResult.UnsupportedSecurityMode;
        }

        // Steps 5 and 6
        switch (SigNetUri.TryParsePath(packet, Scope, out path))
        {
            case SigNetUriParseResult.Ok:
                break;

            case SigNetUriParseResult.UnsupportedVersion:
                return VerifyResult.UnsupportedVersion;

            case SigNetUriParseResult.WrongScope:
                return VerifyResult.WrongScope;

            case SigNetUriParseResult.Malformed:
                return VerifyResult.Malformed;

            default:
                return VerifyResult.NotSigNet;
        }

        if (path.IsTargeted && path.Target != Tuid)
            return VerifyResult.NotForThisDevice;

        var key = this.keys.GetKey(path.KeyRole);
        if (key.IsEmpty)
            return VerifyResult.NoKey;

        // Steps 7 and 8
        var header = packet.Header;
        switch (this.replayProtection.Evaluate(header.SenderId, header.SessionId, header.SequenceNumber))
        {
            case FreshnessResult.EpochRegression:
                return VerifyResult.EpochRegression;

            case FreshnessResult.SequenceReplay:
                return VerifyResult.SequenceReplay;

            case FreshnessResult.TableSaturated:
                return VerifyResult.TableSaturated;
        }

        // Step 9
        if (!SigNetHmac.Verify(key, packet))
            return VerifyResult.HmacFailure;

        var payload = packet.Payload.Span;
        if (TlvReader.Validate(payload) != TlvValidationResult.Ok)
            return VerifyResult.MalformedPayload;

        if (path.Resource == SigNetResource.Manager && InBootstrapWindow && ContainsSet(payload))
            return VerifyResult.ConfigurationLockout;

        // Step 10
        if (!this.replayProtection.Commit(header.SenderId, header.SessionId, header.SequenceNumber))
            return VerifyResult.TableSaturated;

        return VerifyResult.Accepted;
    }

    // A TLV with a value is a SET or command; zero length is a GET (spec 10.4.2, 10.4.3)
    private static bool ContainsSet(ReadOnlySpan<byte> payload)
    {
        var reader = new TlvReader(payload);
        while (reader.TryRead(out _, out var value))
        {
            if (!value.IsEmpty)
                return true;
        }

        return false;
    }
}
