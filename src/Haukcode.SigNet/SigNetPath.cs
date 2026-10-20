using System.Text;
using Haukcode.SigNet.Keys;

namespace Haukcode.SigNet;

/// <summary>
/// The resource part of a Sig-Net URI-Path, after /sig-net/v1/{scope} (spec 8.2, Appendix A).
/// </summary>
public enum SigNetResource
{
    Unknown = 0,

    /// <summary>/level/{universe}: TID_LEVEL and TID_PRIORITY.</summary>
    Level,

    /// <summary>/preview/{universe}: TID_PREVIEW.</summary>
    Preview,

    /// <summary>/sync: TID_SYNC.</summary>
    Sync,

    /// <summary>/timecode/{stream}: TID_TIMECODE.</summary>
    Timecode,

    /// <summary>/poll: TID_POLL from Managers.</summary>
    Poll,

    /// <summary>/node/{tuid}/{endpoint}: replies, announcements, TID_UNIVERSE.</summary>
    Node,

    /// <summary>/node_lost/{tuid}/0: Lost Mode announcements.</summary>
    NodeLost,

    /// <summary>/node_beacon/{tuid}/0: offboarded beacons.</summary>
    NodeBeacon,

    /// <summary>/manager/{tuid}/{endpoint}: SET and GET commands to one device.</summary>
    Manager,

    /// <summary>/aux/{tuid}/{endpoint}: TID_OSC triggers.</summary>
    Aux
}

/// <summary>
/// A Sig-Net URI-Path: scope plus resource and its index or target. Renders the Uri-Path option
/// segments and the URI string the HMAC covers (spec 8.5 item 1).
/// </summary>
public readonly record struct SigNetPath
{
    private SigNetPath(SigNetResource resource, string scope, ushort index, Tuid target, ushort endpoint)
    {
        Resource = resource;
        Scope = scope;
        Index = index;
        Target = target;
        Endpoint = endpoint;
    }

    public SigNetResource Resource { get; }

    public string Scope { get; }

    /// <summary>
    /// The universe for Level and Preview, the stream for Timecode, otherwise 0.
    /// </summary>
    public ushort Index { get; }

    /// <summary>
    /// The addressed device for the targeted resources (Node, NodeLost, NodeBeacon, Manager, Aux).
    /// </summary>
    public Tuid Target { get; }

    /// <summary>
    /// The endpoint for the targeted resources.
    /// </summary>
    public ushort Endpoint { get; }

    public bool IsTargeted => IsTargetedResource(Resource);

    /// <summary>
    /// The key that signs and verifies this URI (spec Appendix A, 11 "Cryptographic Verification").
    /// </summary>
    public SigNetKeyRole KeyRole => GetKeyRole(Resource);

    public static SigNetPath Level(string scope, ushort universe)
    {
        SigNetMulticast.CheckUniverse(universe);

        return new SigNetPath(SigNetResource.Level, CheckedScope(scope), universe, default, 0);
    }

    public static SigNetPath Preview(string scope, ushort universe)
    {
        SigNetMulticast.CheckUniverse(universe);

        return new SigNetPath(SigNetResource.Preview, CheckedScope(scope), universe, default, 0);
    }

    public static SigNetPath Timecode(string scope, byte stream)
    {
        if (stream < 1)
            throw new ArgumentOutOfRangeException(nameof(stream), stream, "Timecode stream must be 1-255");

        return new SigNetPath(SigNetResource.Timecode, CheckedScope(scope), stream, default, 0);
    }

    public static SigNetPath Sync(string scope) => new(SigNetResource.Sync, CheckedScope(scope), 0, default, 0);

    public static SigNetPath Poll(string scope) => new(SigNetResource.Poll, CheckedScope(scope), 0, default, 0);

    public static SigNetPath Node(string scope, Tuid tuid, ushort endpoint) => new(SigNetResource.Node, CheckedScope(scope), 0, tuid, endpoint);

    public static SigNetPath NodeLost(string scope, Tuid tuid) => new(SigNetResource.NodeLost, CheckedScope(scope), 0, tuid, 0);

    /// <summary>
    /// Beacons always use the local scope (spec 10.2.1).
    /// </summary>
    public static SigNetPath NodeBeacon(Tuid tuid) => new(SigNetResource.NodeBeacon, SigNetUri.DefaultScope, 0, tuid, 0);

    public static SigNetPath Manager(string scope, Tuid tuid, ushort endpoint) => new(SigNetResource.Manager, CheckedScope(scope), 0, tuid, endpoint);

    public static SigNetPath Aux(string scope, Tuid tuid, ushort endpoint) => new(SigNetResource.Aux, CheckedScope(scope), 0, tuid, endpoint);

    internal static SigNetPath CreateUnchecked(SigNetResource resource, string scope, ushort index, Tuid target, ushort endpoint) => new(resource, scope, index, target, endpoint);

    public static SigNetKeyRole GetKeyRole(SigNetResource resource)
    {
        return resource switch
        {
            SigNetResource.Level => SigNetKeyRole.Sender,
            SigNetResource.Preview => SigNetKeyRole.Sender,
            SigNetResource.Sync => SigNetKeyRole.Sender,
            SigNetResource.Timecode => SigNetKeyRole.Sender,
            SigNetResource.Aux => SigNetKeyRole.Sender,
            SigNetResource.Node => SigNetKeyRole.Citizen,
            SigNetResource.NodeLost => SigNetKeyRole.Citizen,
            SigNetResource.Poll => SigNetKeyRole.ManagerGlobal,
            SigNetResource.Manager => SigNetKeyRole.ManagerLocal,
            _ => SigNetKeyRole.None
        };
    }

    public static string? GetResourceName(SigNetResource resource)
    {
        return resource switch
        {
            SigNetResource.Level => "level",
            SigNetResource.Preview => "preview",
            SigNetResource.Sync => "sync",
            SigNetResource.Timecode => "timecode",
            SigNetResource.Poll => "poll",
            SigNetResource.Node => "node",
            SigNetResource.NodeLost => "node_lost",
            SigNetResource.NodeBeacon => "node_beacon",
            SigNetResource.Manager => "manager",
            SigNetResource.Aux => "aux",
            _ => null
        };
    }

    internal static bool IsTargetedResource(SigNetResource resource)
    {
        return resource is SigNetResource.Node or SigNetResource.NodeLost or SigNetResource.NodeBeacon or SigNetResource.Manager or SigNetResource.Aux;
    }

    internal static bool IsIndexedResource(SigNetResource resource)
    {
        return resource is SigNetResource.Level or SigNetResource.Preview or SigNetResource.Timecode;
    }

    /// <summary>
    /// Number of Uri-Path segments: sig-net, version, scope, resource, then index or tuid and endpoint.
    /// </summary>
    public int SegmentCount => 4 + (IsTargeted ? 2 : IsIndexedResource(Resource) ? 1 : 0);

    /// <summary>
    /// Write one Uri-Path segment as ASCII. Returns the byte count.
    /// </summary>
    public int WriteSegment(int index, Span<byte> destination)
    {
        int written;
        switch (index)
        {
            case 0:
                return Encoding.ASCII.GetBytes(SigNetUri.Prefix, destination);

            case 1:
                return Encoding.ASCII.GetBytes(SigNetUri.Version, destination);

            case 2:
                return Encoding.ASCII.GetBytes(Scope, destination);

            case 3:
                return Encoding.ASCII.GetBytes(GetResourceName(Resource) ?? throw new InvalidOperationException("Unknown resource"), destination);

            case 4 when IsTargeted:
                return Encoding.ASCII.GetBytes(Target.ToHexString(), destination);

            case 4:
                // Decimal without leading zeros (spec 8.2)
                Index.TryFormat(destination, out written);

                return written;

            case 5 when IsTargeted:
                Endpoint.TryFormat(destination, out written);

                return written;

            default:
                throw new ArgumentOutOfRangeException(nameof(index));
        }
    }

    /// <summary>
    /// The URI string covered by the HMAC: "/" before every segment, no scheme, authority or
    /// terminator (spec 8.5 item 1). Returns the byte count.
    /// </summary>
    public int WriteUriString(Span<byte> destination)
    {
        int length = 0;
        int count = SegmentCount;
        for (int i = 0; i < count; i++)
        {
            destination[length++] = (byte)'/';
            length += WriteSegment(i, destination[length..]);
        }

        return length;
    }

    public override string ToString()
    {
        Span<byte> buffer = stackalloc byte[SigNetUri.MaxUriStringLength];

        return Encoding.ASCII.GetString(buffer[..WriteUriString(buffer)]);
    }

    private static string CheckedScope(string scope)
    {
        SigNetUri.CheckScope(scope);

        return scope;
    }
}
