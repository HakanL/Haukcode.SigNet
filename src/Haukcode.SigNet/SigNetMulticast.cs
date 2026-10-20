using System.Net;

namespace Haukcode.SigNet;

/// <summary>
/// Multicast addresses of spec Appendix A and the default Multicast Folding of spec 9.2.3.
/// </summary>
public static class SigNetMulticast
{
    /// <summary>
    /// Size of the default universe pool, 239.254.0.1 to 239.254.0.109. Prime so repeating patch
    /// patterns do not cluster.
    /// </summary>
    // The reference SDK README still says 100; spec V1.14 section 9.2.3 says 109 and the SDK code agrees
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

    /// <summary>
    /// True for an IPv4 multicast address, 224.0.0.0/4. (Haukcode.Network's IsMulticast only
    /// matches sACN's 239.255.0.0/16.)
    /// </summary>
    public static bool IsMulticast(IPAddress address)
    {
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return address.IsIPv6Multicast;

        Span<byte> bytes = stackalloc byte[4];

        return address.TryWriteBytes(bytes, out _) && (bytes[0] & 0xF0) == 0xE0;
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
