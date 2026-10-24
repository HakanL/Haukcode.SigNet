using System.Net;
using System.Net.Sockets;

namespace Haukcode.SigNet;

/// <summary>
/// Multicast addresses of spec Appendix A and the default Multicast Folding of spec 9.2.3. The
/// fields are the IPv4 groups; <see cref="ToIpv6"/> and the <see cref="AddressFamily"/> overloads
/// give the IPv6 groups added in V1.15.
/// </summary>
public static class SigNetMulticast
{
    /// <summary>
    /// Size of the default universe pool, 239.254.0.1 to 239.254.0.109. Prime so repeating patch
    /// patterns do not cluster.
    /// </summary>
    // The reference SDK README still says 100; spec section 9.2.3 says 109 and the SDK code agrees
    public const int FoldingGroupCount = 109;

    /// <summary>&lt;mult_node_beacon&gt;: offboarded beacons, /node_beacon/{tuid}/0.</summary>
    public static readonly IPAddress NodeBeacon = IPAddress.Parse("239.254.255.255");

    /// <summary>&lt;mult_node_lost&gt;: /node_lost/{tuid}/0.</summary>
    public static readonly IPAddress NodeLost = IPAddress.Parse("239.254.255.254");

    /// <summary>&lt;mult_node_send&gt;: replies and announcements, /node/{tuid}/{endpoint}.</summary>
    public static readonly IPAddress NodeSend = IPAddress.Parse("239.254.255.253");

    /// <summary>&lt;mult_manager_poll&gt;: discovery, /poll.</summary>
    public static readonly IPAddress ManagerPoll = IPAddress.Parse("239.254.255.252");

    /// <summary>&lt;mult_manager_send&gt;: multicast commands, /manager/{tuid}/{endpoint}.</summary>
    public static readonly IPAddress ManagerSend = IPAddress.Parse("239.254.255.251");

    /// <summary>&lt;mult_time&gt;: /sync and /timecode/{stream} (spec 9.2.6).</summary>
    public static readonly IPAddress Time = IPAddress.Parse("239.254.255.250");

    /// <summary>&lt;mult_preview&gt;: /preview/{universe}.</summary>
    public static readonly IPAddress Preview = IPAddress.Parse("239.254.255.249");

    /// <summary>&lt;mult_aux&gt;: /aux/{tuid}/{endpoint}.</summary>
    public static readonly IPAddress Aux = IPAddress.Parse("239.254.255.248");

    private static readonly IPAddress[] universeGroups = CreateUniverseGroups();
    private static readonly IPAddress[] universeGroupsV6 = Array.ConvertAll(universeGroups, group => group == null ? null! : ToIpv6(group));

    /// <summary>
    /// The last octet of a universe's default group: ((universe - 1) % 109) + 1.
    /// </summary>
    public static int GetFoldingIndex(ushort universe)
    {
        CheckUniverse(universe);

        return ((universe - 1) % FoldingGroupCount) + 1;
    }

    /// <summary>
    /// The default (folded) multicast group for a universe, 239.254.0.1 to 239.254.0.109.
    /// </summary>
    public static IPAddress GetUniverseAddress(ushort universe)
    {
        return universeGroups[GetFoldingIndex(universe)];
    }

    /// <summary>
    /// The default (folded) multicast group for a universe in the given address family: IPv4
    /// 239.254.0.1 to 239.254.0.109, IPv6 FF18::7369:1 to FF18::7369:6D (spec 9.2.3).
    /// </summary>
    public static IPAddress GetUniverseAddress(ushort universe, AddressFamily family)
    {
        return family == AddressFamily.InterNetworkV6 ? universeGroupsV6[GetFoldingIndex(universe)] : GetUniverseAddress(universe);
    }

    /// <summary>
    /// The multicast group a path is transmitted to in the given address family.
    /// </summary>
    public static IPAddress GetAddress(in SigNetPath path, AddressFamily family)
    {
        var address = GetAddress(path);

        return family == AddressFamily.InterNetworkV6 ? ToIpv6(address) : address;
    }

    /// <summary>
    /// The IPv6 group of a Sig-Net IPv4 group: 239.254.X.Y becomes the Organization-Local
    /// FF18::7369:XXYY, so the fixed groups are FF18::7369:FFF8 to FF18::7369:FFFF and the
    /// universe pool FF18::7369:1 to FF18::7369:6D (spec 9.2.3, Appendix A note 2).
    /// </summary>
    public static IPAddress ToIpv6(IPAddress ipv4Group)
    {
        ArgumentNullException.ThrowIfNull(ipv4Group);

        Span<byte> v4 = stackalloc byte[4];
        if (ipv4Group.AddressFamily != AddressFamily.InterNetwork || !ipv4Group.TryWriteBytes(v4, out _) || v4[0] != 239 || v4[1] != 254)
            throw new ArgumentException("Not a Sig-Net IPv4 group (239.254.0.0/16)", nameof(ipv4Group));

        Span<byte> v6 = stackalloc byte[16];
        v6[0] = 0xFF;
        v6[1] = 0x18;
        v6[12] = 0x73;
        v6[13] = 0x69;
        v6[14] = v4[2];
        v6[15] = v4[3];

        return new IPAddress(v6);
    }

    /// <summary>
    /// The multicast group a path is transmitted to (spec 9.2.1: the URI decides the address).
    /// </summary>
    public static IPAddress GetAddress(in SigNetPath path)
    {
        return path.Resource switch
        {
            SigNetResource.Level => GetUniverseAddress(path.Index),
            SigNetResource.Preview => Preview,
            SigNetResource.Sync => Time,
            SigNetResource.Timecode => Time,
            SigNetResource.Poll => ManagerPoll,
            SigNetResource.Node => NodeSend,
            SigNetResource.NodeLost => NodeLost,
            SigNetResource.NodeBeacon => NodeBeacon,
            SigNetResource.Manager => ManagerSend,
            SigNetResource.Aux => Aux,
            _ => throw new ArgumentException($"No multicast address for {path.Resource}", nameof(path))
        };
    }

    internal static void CheckUniverse(ushort universe)
    {
        if (universe < SigNetUri.MinUniverse || universe > SigNetUri.MaxUniverse)
            throw new ArgumentOutOfRangeException(nameof(universe), universe, $"Universe must be {SigNetUri.MinUniverse}-{SigNetUri.MaxUniverse}");
    }

    private static IPAddress[] CreateUniverseGroups()
    {
        var groups = new IPAddress[FoldingGroupCount + 1];
        for (int i = 1; i <= FoldingGroupCount; i++)
            groups[i] = new IPAddress(new byte[] { 239, 254, 0, (byte)i });

        return groups;
    }
}
