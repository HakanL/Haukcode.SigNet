using System.Linq;

namespace Haukcode.SigNet;

/// <summary>
/// A data endpoint and the number the client gave it.
/// </summary>
public readonly record struct SigNetEndpoint(ushort Number, SigNetEndpointInfo Info);

/// <summary>
/// The Device's TID_LEVEL data endpoints, numbered 1 to N without gaps (spec 6.8, 8.6.2). N is
/// TID_RT_ENDPOINT_COUNT, and each output universe's level stream uses its endpoint as the
/// Sender-ID endpoint and sequence lane.
///
/// Numbering is deterministic: the declared outputs sorted by universe, then the declared inputs
/// sorted by universe (each sort keeps declaration order for equal universes), then outputs that
/// were sent with <see cref="SigNetClient.SendLevels(ushort, ReadOnlyMemory{byte}, byte?, System.Net.IPAddress?, bool)"/>
/// without being declared, in order of first use. An input and an output on the same universe
/// are two endpoints with their own lanes.
///
/// Timecode and OSC streams would take endpoints N+1 onwards (spec 8.6.2); the library sends
/// neither, so the table holds only TID_LEVEL endpoints.
/// </summary>
public sealed class SigNetEndpointTable
{
    /// <summary>
    /// The highest Sender Endpoint ID (spec 8.6.2).
    /// </summary>
    public const ushort MaxEndpoint = 0xFF00;

    public static readonly SigNetEndpointTable Empty = new([], [], 0);

    private readonly SigNetEndpoint[] endpoints;
    private readonly Dictionary<ushort, ushort> outputs;
    private readonly int declaredCount;

    private SigNetEndpointTable(SigNetEndpoint[] endpoints, Dictionary<ushort, ushort> outputs, int declaredCount)
    {
        this.endpoints = endpoints;
        this.outputs = outputs;
        this.declaredCount = declaredCount;
    }

    /// <summary>
    /// N, the number of data endpoints, as reported in TID_RT_ENDPOINT_COUNT.
    /// </summary>
    public int Count => this.endpoints.Length;

    /// <summary>
    /// Every endpoint in number order: <c>Endpoints[i].Number == i + 1</c>.
    /// </summary>
    public IReadOnlyList<SigNetEndpoint> Endpoints => this.endpoints;

    /// <summary>
    /// The output universes added on first send because they were not declared, in endpoint order.
    /// </summary>
    public IEnumerable<ushort> UndeclaredOutputs
    {
        get
        {
            for (int i = this.declaredCount; i < this.endpoints.Length; i++)
                yield return this.endpoints[i].Info.Universe;
        }
    }

    /// <summary>
    /// Number the declared endpoints (outputs have <see cref="EndpointDirection.Supplier"/>, every
    /// other direction is an input), then append <paramref name="undeclaredOutputs"/> that are not
    /// declared outputs. Throws if two outputs share a universe or there are more than
    /// <see cref="MaxEndpoint"/> endpoints.
    /// </summary>
    public static SigNetEndpointTable Create(IReadOnlyList<SigNetEndpointInfo> declared, IEnumerable<ushort>? undeclaredOutputs = null)
    {
        ArgumentNullException.ThrowIfNull(declared);

        foreach (var info in declared)
            ArgumentNullException.ThrowIfNull(info, nameof(declared));

        // OrderBy is a stable sort, so equal universes keep their declaration order
        var sorted = declared.Where(e => e.IsOutput).OrderBy(e => e.Universe)
            .Concat(declared.Where(e => !e.IsOutput).OrderBy(e => e.Universe))
            .ToList();
        int outputCount = declared.Count(e => e.IsOutput);

        var outputs = new Dictionary<ushort, ushort>();
        for (int i = 0; i < outputCount; i++)
        {
            ushort universe = sorted[i].Universe;
            if (universe != 0 && !outputs.TryAdd(universe, (ushort)(i + 1)))
                throw new ArgumentException($"Output universe {universe} is declared twice", nameof(declared));
        }

        int declaredCount = sorted.Count;
        if (undeclaredOutputs != null)
        {
            foreach (ushort universe in undeclaredOutputs)
            {
                if (universe != 0 && !outputs.ContainsKey(universe))
                {
                    sorted.Add(CreateUndeclaredOutput(universe));
                    outputs.Add(universe, (ushort)sorted.Count);
                }
            }
        }

        if (sorted.Count > MaxEndpoint)
            throw new ArgumentException($"At most {MaxEndpoint} data endpoints", nameof(declared));

        var endpoints = new SigNetEndpoint[sorted.Count];
        for (int i = 0; i < endpoints.Length; i++)
            endpoints[i] = new SigNetEndpoint((ushort)(i + 1), sorted[i]);

        return new SigNetEndpointTable(endpoints, outputs, declaredCount);
    }

    /// <summary>
    /// The endpoint with this number, or null outside 1 to N.
    /// </summary>
    public SigNetEndpointInfo? Get(ushort number)
    {
        return number >= 1 && number <= this.endpoints.Length ? this.endpoints[number - 1].Info : null;
    }

    /// <summary>
    /// The endpoint an output universe's level stream uses.
    /// </summary>
    public bool TryGetOutputEndpoint(ushort universe, out ushort endpoint)
    {
        return this.outputs.TryGetValue(universe, out endpoint);
    }

    /// <summary>
    /// This table with an undeclared output universe appended at N+1.
    /// </summary>
    internal SigNetEndpointTable WithUndeclaredOutput(ushort universe)
    {
        if (this.endpoints.Length >= MaxEndpoint)
            throw new InvalidOperationException($"At most {MaxEndpoint} data endpoints");

        var endpoints = new SigNetEndpoint[this.endpoints.Length + 1];
        this.endpoints.CopyTo(endpoints, 0);
        endpoints[^1] = new SigNetEndpoint((ushort)endpoints.Length, CreateUndeclaredOutput(universe));

        var outputs = new Dictionary<ushort, ushort>(this.outputs) { [universe] = (ushort)endpoints.Length };

        return new SigNetEndpointTable(endpoints, outputs, this.declaredCount);
    }

    private static SigNetEndpointInfo CreateUndeclaredOutput(ushort universe)
    {
        return SigNetEndpointInfo.Output(universe, $"Universe {universe}");
    }
}
