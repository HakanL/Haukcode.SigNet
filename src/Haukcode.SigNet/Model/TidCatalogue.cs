namespace Haukcode.SigNet.Model;

[Flags]
public enum TidTarget
{
    Root = 1,

    Data = 2,

    RootAndData = Root | Data
}

/// <summary>
/// One TID's definition: where it applies, whether and at which poll level it is reported, and
/// which value lengths are legal (spec 10.1.3: anything else makes the whole packet malformed).
/// </summary>
public sealed record TidInfo(
    ushort Value,
    string Name,
    TidTarget Target,
    bool Queryable,
    QueryLevel? PollLevel,
    int MinLength,
    int MaxLength,
    int LengthMultiple = 1,
    int[]? ExactLengths = null)
{
    /// <summary>
    /// A zero-length value is a Parameter Query (GET) and only legal for queryable TIDs (spec 10.4.3).
    /// </summary>
    public bool IsValidLength(int length)
    {
        if (length == 0)
            return Queryable || MinLength == 0;

        if (ExactLengths != null)
            return Array.IndexOf(ExactLengths, length) >= 0;

        return length >= MinLength && length <= MaxLength && length % LengthMultiple == 0;
    }
}

/// <summary>
/// The TID dictionary, hand-written from spec section 11 and Appendix C (V1.14). Section 11 wins
/// where the two disagree; the differences are listed in docs/implementation-notes.md.
/// </summary>
public static class TidCatalogue
{
    private static readonly Dictionary<ushort, TidInfo> tids = Create();

    public static IReadOnlyCollection<TidInfo> All => tids.Values;

    public static bool TryGet(ushort tid, out TidInfo info)
    {
        return tids.TryGetValue(tid, out info!);
    }

    private static Dictionary<ushort, TidInfo> Create()
    {
        // TODO (spec Appendix C): the definitive JSON lives in the Sig-Net GitHub repository but is
        // not published there yet, and the PDF copy does not survive text extraction intact.
        // Regenerate this table from that JSON once it is available.
        var list = new[]
        {
            // 11.1
            new TidInfo(Tid.Poll, "TID_POLL", TidTarget.RootAndData, false, null, 25, 25),
            // TODO (spec 11.9 vs Appendix C): Appendix C targets TID_POLL_REPLY at Root only, 11.1.2 and 11.9 at Root & Data
            new TidInfo(Tid.PollReply, "TID_POLL_REPLY", TidTarget.RootAndData, false, QueryLevel.Heartbeat, 12, 12),
            new TidInfo(Tid.SetReply, "TID_SET_REPLY", TidTarget.RootAndData, false, null, 3, 3),

            // 11.2
            new TidInfo(Tid.Level, "TID_LEVEL", TidTarget.Data, false, null, 1, 512),
            new TidInfo(Tid.Priority, "TID_PRIORITY", TidTarget.Data, false, null, 1, 512),
            new TidInfo(Tid.Preview, "TID_PREVIEW", TidTarget.Data, false, null, 1, 512),
            new TidInfo(Tid.Sync, "TID_SYNC", TidTarget.Data, false, null, 0, 0),
            new TidInfo(Tid.Timecode, "TID_TIMECODE", TidTarget.Data, false, null, 5, 5),
            new TidInfo(Tid.Universe, "TID_UNIVERSE", TidTarget.Data, false, null, 9, 9),
            // TODO (spec 11.2.7 vs Appendix C): 11.2.7 says "Variable", Appendix C says 1 to 255
            new TidInfo(Tid.Osc, "TID_OSC", TidTarget.RootAndData, false, null, 1, Coap.MaxPayloadLength - 4),

            // 11.3
            // TODO (spec 11.3 vs Appendix C): Appendix C targets the RDM command and response at Data only, 11.3.1 and 11.3.2 at Root & Data
            new TidInfo(Tid.RdmCommand, "TID_RDM_COMMAND", TidTarget.RootAndData, false, null, 26, 257),
            new TidInfo(Tid.RdmResponse, "TID_RDM_RESPONSE", TidTarget.RootAndData, false, null, 26, 257),
            new TidInfo(Tid.RdmTodControl, "TID_RDM_TOD_CONTROL", TidTarget.Data, false, null, 1, 1),
            new TidInfo(Tid.RdmTodData, "TID_RDM_TOD_DATA", TidTarget.Data, false, null, 2, Coap.MaxPayloadLength - 4),
            new TidInfo(Tid.RdmEpConfig, "TID_RDM_EP_CONFIG", TidTarget.Data, true, QueryLevel.Config, 1, 1),
            new TidInfo(Tid.RdmFlowControl, "TID_RDM_FLOW_CONTROL", TidTarget.Data, true, QueryLevel.Config, 2, 2),

            // 11.4
            new TidInfo(Tid.RtOffboard, "TID_RT_OFFBOARD", TidTarget.Root, false, null, 4, 4),

            // 11.5
            new TidInfo(Tid.NwMacAddress, "TID_NW_MAC_ADDRESS", TidTarget.Root, true, QueryLevel.Full, 6, 6),
            new TidInfo(Tid.NwIpv4Mode, "TID_NW_IPV4_MODE", TidTarget.Root, true, QueryLevel.Full, 1, 1),
            new TidInfo(Tid.NwIpv4Address, "TID_NW_IPV4_ADDRESS", TidTarget.Root, true, QueryLevel.Full, 4, 4),
            new TidInfo(Tid.NwIpv4Netmask, "TID_NW_IPV4_NETMASK", TidTarget.Root, true, QueryLevel.Full, 4, 4),
            new TidInfo(Tid.NwIpv4Gateway, "TID_NW_IPV4_GATEWAY", TidTarget.Root, true, QueryLevel.Full, 4, 4),
            new TidInfo(Tid.NwIpv4Current, "TID_NW_IPV4_CURRENT", TidTarget.Root, true, QueryLevel.Full, 12, 12),
            new TidInfo(Tid.NwIpv6Mode, "TID_NW_IPV6_MODE", TidTarget.Root, true, QueryLevel.Full, 1, 1),
            new TidInfo(Tid.NwIpv6Address, "TID_NW_IPV6_ADDRESS", TidTarget.Root, true, QueryLevel.Full, 16, 16),
            new TidInfo(Tid.NwIpv6Prefix, "TID_NW_IPV6_PREFIX", TidTarget.Root, true, QueryLevel.Full, 1, 1),
            new TidInfo(Tid.NwIpv6Gateway, "TID_NW_IPV6_GATEWAY", TidTarget.Root, true, QueryLevel.Full, 16, 16),
            new TidInfo(Tid.NwIpv6Current, "TID_NW_IPV6_CURRENT", TidTarget.Root, true, QueryLevel.Full, 33, 33),

            // 11.6
            new TidInfo(Tid.RtSupportedTids, "TID_RT_SUPPORTED_TIDS", TidTarget.Root, true, QueryLevel.Full, 2, Coap.MaxPayloadLength, LengthMultiple: 2),
            new TidInfo(Tid.RtEndpointCount, "TID_RT_ENDPOINT_COUNT", TidTarget.Root, true, QueryLevel.Heartbeat, 2, 2),
            new TidInfo(Tid.RtProtocolVersion, "TID_RT_PROTOCOL_VERSION", TidTarget.Root, true, QueryLevel.Full, 1, 1),
            new TidInfo(Tid.RtFirmwareVersion, "TID_RT_FIRMWARE_VERSION", TidTarget.Root, true, QueryLevel.Full, 4, 68),
            new TidInfo(Tid.RtDeviceLabel, "TID_RT_DEVICE_LABEL", TidTarget.Root, true, QueryLevel.Config, 1, 65),
            new TidInfo(Tid.RtMultOverride, "TID_RT_MULT_OVERRIDE", TidTarget.Root, true, QueryLevel.Heartbeat, 1, 1),
            new TidInfo(Tid.RtIdentify, "TID_RT_IDENTIFY", TidTarget.Root, true, QueryLevel.Config, 1, 1),
            new TidInfo(Tid.RtStatus, "TID_RT_STATUS", TidTarget.Root, true, QueryLevel.Config, 4, 4),
            new TidInfo(Tid.RtRoleCapability, "TID_RT_ROLE_CAPABILITY", TidTarget.Root, true, QueryLevel.Full, 4, 4),
            new TidInfo(Tid.RtReboot, "TID_RT_REBOOT", TidTarget.Root, false, null, 5, 5),
            new TidInfo(Tid.RtModelName, "TID_RT_MODEL_NAME", TidTarget.Root, true, QueryLevel.Full, 1, 65),
            // TODO (spec): the SDK defines TID_RT_SCOPE (0x060C), V1.14 does not; left out until the spec defines it
            new TidInfo(Tid.RtOtwCapability, "TID_RT_OTW_CAPABILITY", TidTarget.Root, true, QueryLevel.Full, 3, 3),

            // 11.7
            new TidInfo(Tid.EpUniverse, "TID_EP_UNIVERSE", TidTarget.Data, true, QueryLevel.Config, 2, 2),
            new TidInfo(Tid.EpLabel, "TID_EP_LABEL", TidTarget.Data, true, QueryLevel.Config, 1, 65),
            new TidInfo(Tid.EpMultOverride, "TID_EP_MULT_OVERRIDE", TidTarget.Data, true, QueryLevel.Config, 4, 4),
            // Length 4 is the pre-V1.11 form, still to be accepted (spec 11.7.4 note)
            new TidInfo(Tid.EpCapability, "TID_EP_CAPABILITY", TidTarget.Data, true, QueryLevel.Config, 4, 6, ExactLengths: [4, 6]),
            new TidInfo(Tid.EpDirection, "TID_EP_DIRECTION", TidTarget.Data, true, QueryLevel.Config, 1, 1),
            new TidInfo(Tid.EpInputPriority, "TID_EP_INPUT_PRIORITY", TidTarget.Data, true, QueryLevel.Config, 1, 512),
            new TidInfo(Tid.EpStatus, "TID_EP_STATUS", TidTarget.Data, true, QueryLevel.Config, 4, 4),
            new TidInfo(Tid.EpFailover, "TID_EP_FAILOVER", TidTarget.Data, true, QueryLevel.Config, 3, 3),
            new TidInfo(Tid.EpDmxTiming, "TID_EP_DMX_TIMING", TidTarget.Data, true, QueryLevel.Config, 2, 2),
            new TidInfo(Tid.EpRefreshCapability, "TID_EP_REFRESH_CAPABILITY", TidTarget.Data, true, QueryLevel.Config, 1, 1),
            new TidInfo(Tid.EpProtocol, "TID_EP_PROTOCOL", TidTarget.Data, true, QueryLevel.Config, 1, 1),
            new TidInfo(Tid.EpIdentify, "TID_EP_IDENTIFY", TidTarget.Data, true, QueryLevel.Config, 1, 1),

            // 11.8
            new TidInfo(Tid.DgSecurityEvent, "TID_DG_SECURITY_EVENT", TidTarget.Root, true, QueryLevel.Extended, 7, 23, ExactLengths: [7, 11, 23]),
            // TODO (spec 11.9 vs Appendix C): 11.9 targets TID_DG_MESSAGE at Root & Data, 11.8.2 and Appendix C at Root
            new TidInfo(Tid.DgMessage, "TID_DG_MESSAGE", TidTarget.RootAndData, true, QueryLevel.Extended, 1, 64),
            new TidInfo(Tid.DgLevelFoldback, "TID_DG_LEVEL_FOLDBACK", TidTarget.Data, true, null, 1, 512),
        };

        var result = new Dictionary<ushort, TidInfo>(list.Length);
        foreach (var info in list)
            result.Add(info.Value, info);

        return result;
    }
}
