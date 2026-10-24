namespace Haukcode.SigNet.Model;

/// <summary>
/// Type Identifiers of spec section 11 (V1.16). 0x8000 to 0xFF00 is the manufacturer range,
/// interpreted only in the context of the Sig-Net-Mfg-Code option (spec 10.1.2); 0xFF01 to 0xFFFF
/// are the standard diagnostic and system TIDs (spec 11).
/// </summary>
public static class Tid
{
    // 11.1 Node discovery
    public const ushort Poll = 0x0001;
    public const ushort PollReply = 0x0002;
    public const ushort SetReply = 0x0003;

    // 11.2 Sender
    public const ushort Level = 0x0101;
    public const ushort Priority = 0x0102;
    public const ushort Preview = 0x0103;
    public const ushort Sync = 0x0201;
    public const ushort Timecode = 0x0202;
    public const ushort Universe = 0x0203;
    public const ushort Osc = 0x0204;

    // 11.3 RDM
    public const ushort RdmCommand = 0x0301;
    public const ushort RdmResponse = 0x0302;
    public const ushort RdmTodControl = 0x0303;
    public const ushort RdmTodData = 0x0304;
    public const ushort RdmEpConfig = 0x0305;
    public const ushort RdmFlowControl = 0x0306;

    // 11.4 Offboarding
    public const ushort RtOffboard = 0x0401;

    // 11.5 Network configuration
    public const ushort NwMacAddress = 0x0501;
    public const ushort NwIpv4Mode = 0x0502;
    public const ushort NwIpv4Address = 0x0503;
    public const ushort NwIpv4Netmask = 0x0504;
    public const ushort NwIpv4Gateway = 0x0505;
    public const ushort NwIpv4Current = 0x0506;
    public const ushort NwIpv6Mode = 0x0581;
    public const ushort NwIpv6Address = 0x0582;
    public const ushort NwIpv6Prefix = 0x0583;
    public const ushort NwIpv6Gateway = 0x0584;
    public const ushort NwIpv6Current = 0x0585;

    // 11.6 Root endpoint
    public const ushort RtSupportedTids = 0x0601;
    public const ushort RtEndpointCount = 0x0602;
    public const ushort RtProtocolVersion = 0x0603;
    public const ushort RtFirmwareVersion = 0x0604;
    public const ushort RtDeviceLabel = 0x0605;
    public const ushort RtMultOverride = 0x0606;
    public const ushort RtIdentify = 0x0607;
    public const ushort RtStatus = 0x0608;
    public const ushort RtRoleCapability = 0x0609;
    public const ushort RtReboot = 0x060A;
    public const ushort RtModelName = 0x060B;
    public const ushort RtOtwCapability = 0x060D;

    // 11.7 Data endpoint
    public const ushort EpUniverse = 0x0901;
    public const ushort EpLabel = 0x0902;
    public const ushort EpMultOverride = 0x0903;
    public const ushort EpCapability = 0x0904;
    public const ushort EpDirection = 0x0905;
    public const ushort EpInputPriority = 0x0906;
    public const ushort EpStatus = 0x0907;
    public const ushort EpFailover = 0x0908;
    public const ushort EpDmxTiming = 0x0909;
    public const ushort EpRefreshCapability = 0x090A;
    public const ushort EpProtocol = 0x090B;
    public const ushort EpIdentify = 0x090C;

    // 11.8 Diagnostics
    public const ushort DgSecurityEvent = 0xFF01;
    public const ushort DgMessage = 0xFF02;
    public const ushort DgLevelFoldback = 0xFF03;
    public const ushort DgSource = 0xFF04;

    public const ushort FirstManufacturerTid = 0x8000;
    public const ushort LastManufacturerTid = 0xFF00;

    public static bool IsManufacturerTid(ushort tid) => tid >= FirstManufacturerTid && tid <= LastManufacturerTid;
}

/// <summary>
/// TID_POLL QUERY_LEVEL values (spec 10.2.3, 11.9). Each level includes the ones below it.
/// </summary>
public enum QueryLevel : byte
{
    Heartbeat = 0x00,

    Config = 0x01,

    Full = 0x02,

    Extended = 0x03
}
