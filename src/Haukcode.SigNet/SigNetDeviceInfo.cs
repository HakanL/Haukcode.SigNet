namespace Haukcode.SigNet;

/// <summary>
/// TID_RT_ROLE_CAPABILITY bits (spec 11.6.9).
/// </summary>
[Flags]
public enum SigNetRoles : uint
{
    None = 0,

    Node = 0x01,

    Sender = 0x02,

    Manager = 0x04,

    Visualiser = 0x08,

    RootFirmwareSupport = 0x40,

    OpenModeSupported = 0x80
}

/// <summary>
/// TID_EP_CAPABILITY bits (spec 11.7.4).
/// </summary>
[Flags]
public enum EndpointCapabilities : uint
{
    None = 0,

    ConsumeLevel = 0x01,

    SupplyLevel = 0x02,

    ConsumeRdm = 0x04,

    /// <summary>
    /// Bit 3, "Can Supply RDM" until V1.14. Reserved (deprecated) since V1.15 and never reported:
    /// the library clears it in TID_EP_CAPABILITY replies.
    /// </summary>
    [Obsolete("TID_EP_CAPABILITY bit 3 is reserved (deprecated) since Sig-Net V1.15 and is never reported")]
    SupplyRdm = 0x08,

    /// <summary>
    /// The endpoint terminates inside the Device rather than at a physical [DMX512] port. Since
    /// V1.15 it hosts an RDM responder only when <see cref="ConsumeRdm"/> is set too (spec 6.8.2).
    /// </summary>
    Virtual = 0x10,

    /// <summary>
    /// Full per-slot priority merge. Clear when using the Constrained Node Fallback (first
    /// priority byte as universe priority), which is what this library reports by default.
    /// </summary>
    PerSlotPriority = 0x20
}

/// <summary>
/// TID_EP_DIRECTION direction bits (spec 11.7.5).
/// </summary>
public enum EndpointDirection : byte
{
    Disabled = 0,

    Consumer = 1,

    Supplier = 2,

    Fallback = 3
}

/// <summary>
/// A data endpoint as reported, read-only, to Managers (spec 11.7): an input (a universe this
/// device receives) or, with <see cref="EndpointDirection.Supplier"/>, an output (a universe it
/// sends). The client numbers them, see <see cref="SigNetEndpointTable"/>. The library does not
/// accept SET commands, so these are fixed for the life of the client unless the host replaces
/// <see cref="SigNetClient.DeviceInfo"/>.
/// </summary>
public sealed record SigNetEndpointInfo
{
    /// <summary>
    /// An input endpoint: consumes TID_LEVEL, <see cref="EndpointDirection.Consumer"/>.
    /// </summary>
    public SigNetEndpointInfo(ushort universe, string label)
    {
        Universe = universe;
        Label = label;
    }

    /// <summary>
    /// An input endpoint: a universe this device receives.
    /// </summary>
    public static SigNetEndpointInfo Input(ushort universe, string label) => new(universe, label);

    /// <summary>
    /// An output endpoint: a universe this device sends, <see cref="EndpointDirection.Supplier"/>
    /// with <see cref="EndpointCapabilities.SupplyLevel"/>.
    /// </summary>
    public static SigNetEndpointInfo Output(ushort universe, string label) => new(universe, label)
    {
        Capabilities = EndpointCapabilities.SupplyLevel,
        Direction = EndpointDirection.Supplier,
        MaxMergeSources = 0
    };

    /// <summary>
    /// True for an output (<see cref="EndpointDirection.Supplier"/>): its universe's level stream
    /// is sent on this endpoint's lane.
    /// </summary>
    public bool IsOutput => Direction == EndpointDirection.Supplier;

    /// <summary>
    /// TID_EP_UNIVERSE: 1 to 63,999, or 0 when not patched.
    /// </summary>
    public ushort Universe { get; init; }

    /// <summary>
    /// TID_EP_LABEL, up to 64 bytes: sent as ASCII, or as UTF-8 when it has non-ASCII characters.
    /// </summary>
    public string Label { get; init; }

    public EndpointCapabilities Capabilities { get; init; } = EndpointCapabilities.ConsumeLevel;

    /// <summary>
    /// TID_EP_CAPABILITY bytes 4-5; at least 4 for an endpoint that consumes levels (spec 10.6),
    /// reported as 0 for one that does not.
    /// </summary>
    public ushort MaxMergeSources { get; init; } = 4;

    public EndpointDirection Direction { get; init; } = EndpointDirection.Consumer;

    /// <summary>
    /// TID_EP_REFRESH_CAPABILITY in frames per second; never below 44.
    /// </summary>
    public byte RefreshCapability { get; init; } = 44;

    /// <summary>
    /// TID_EP_FAILOVER mode byte: 0 hold last state, 1 blackout, 2 full, 3 scene, 4 stop.
    /// </summary>
    public byte FailoverMode { get; init; }

    public ushort FailoverScene { get; init; }
}

/// <summary>
/// What the device reports about itself in discovery replies and announcements (spec 10.2, 11.6).
/// </summary>
public sealed record SigNetDeviceInfo
{
    public SigNetDeviceInfo(uint soemCode, string modelName, string deviceLabel)
    {
        if (soemCode == 0)
            throw new ArgumentException("SoemCode 0x00000000 is reserved; use the ESTA manufacturer id << 16 | product variant", nameof(soemCode));

        SoemCode = soemCode;
        ModelName = modelName ?? throw new ArgumentNullException(nameof(modelName));
        DeviceLabel = deviceLabel ?? throw new ArgumentNullException(nameof(deviceLabel));
    }

    /// <summary>
    /// The product's SoemCode (spec 6.5). Reporting it correctly is a license condition, and each
    /// distinct product (hardware model, endpoint configuration or architecture) has its own.
    /// </summary>
    public uint SoemCode { get; }

    /// <summary>
    /// TID_RT_MODEL_NAME, up to 64 bytes: sent as ASCII, or as UTF-8 when it has non-ASCII characters.
    /// </summary>
    public string ModelName { get; init; }

    /// <summary>
    /// TID_RT_DEVICE_LABEL, up to 64 bytes: sent as ASCII, or as UTF-8 when it has non-ASCII characters.
    /// </summary>
    public string DeviceLabel { get; init; }

    /// <summary>
    /// TID_RT_FIRMWARE_VERSION machine version, RDM convention.
    /// </summary>
    public uint FirmwareVersionId { get; init; }

    /// <summary>
    /// TID_RT_FIRMWARE_VERSION text, up to 64 ASCII characters.
    /// </summary>
    public string FirmwareVersion { get; init; } = string.Empty;

    public SigNetRoles Roles { get; init; } = SigNetRoles.Sender;

    /// <summary>
    /// TID_RT_STATUS bits (spec 11.6.8).
    /// </summary>
    public uint Status { get; init; }

    /// <summary>
    /// CHANGE_COUNT reported in TID_POLL_REPLY (spec 10.4.4). Persistent, owned by the host:
    /// increment and save it when a persistent parameter such as the device label changes.
    /// </summary>
    public ushort ChangeCount { get; init; }

    /// <summary>
    /// The declared data endpoints, inputs and outputs, in any order. The client numbers them 1
    /// to N (outputs by universe, then inputs by universe, see <see cref="SigNetEndpointTable"/>)
    /// and reports N in TID_RT_ENDPOINT_COUNT (spec 6.8). An output universe sent without being
    /// declared here is numbered on first use, after these. All are TID_LEVEL endpoints; a
    /// timecode or OSC endpoint would be numbered from N+1.
    /// </summary>
    public IReadOnlyList<SigNetEndpointInfo> Endpoints { get; init; } = [];
}
