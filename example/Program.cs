using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using Haukcode.SigNet.Keys;
using Haukcode.SigNet.Model;

namespace Haukcode.SigNet.ConsoleExample;

/// <summary>
/// Sends a moving pattern on a universe and prints the frames it receives, its own included.
///
///   ConsoleExample --passphrase "SigNetT3stVector1!" [--scope local] [--interface 192.168.1.10]
///                  [--universe 1] [--manufacturer 0x7FF0] [--sync] [--listen-only] [--seconds 0]
///
/// The manufacturer id defaults to 0x7FF0, from the ESTA prototype range; a product uses its own
/// ESTA id. The TUID and session id are kept in signet-example.state in the working directory,
/// standing in for the non-volatile storage a real device has.
/// </summary>
public class Program
{
    private const string StateFile = "signet-example.state";

    public static async Task<int> Main(string[] args)
    {
        if (args.Contains("--beacon"))
            return await RunBeaconAsync(args);

        string? passphrase = GetArgument(args, "--passphrase");
        if (passphrase == null)
        {
            Console.WriteLine("Usage: ConsoleExample --passphrase <passphrase> [--scope local] [--interface <ip>] [--universe 1] [--manufacturer 0x7FF0] [--sync] [--listen-only] [--seconds 0]");
            Console.WriteLine("       ConsoleExample --beacon [--interface <ip>] [--manufacturer 0x7FF0] [--seconds 0]");

            return 1;
        }

        var check = PassphraseValidator.Validate(passphrase);
        if (check != PassphraseValidationResult.Valid)
        {
            Console.WriteLine($"Passphrase rejected: {PassphraseValidator.GetMessage(check)}");

            return 1;
        }

        string scope = GetArgument(args, "--scope") ?? SigNetUri.DefaultScope;
        ushort universe = ushort.Parse(GetArgument(args, "--universe") ?? "1", CultureInfo.InvariantCulture);
        ushort manufacturer = ParseHex16(GetArgument(args, "--manufacturer") ?? "0x7FF0");
        var localAddress = GetArgument(args, "--interface") is string address
            ? IPAddress.Parse(address)
            : Haukcode.Network.Utils.GetFirstBindAddress().IPAddress ?? IPAddress.Loopback;
        bool sync = args.Contains("--sync");
        bool listenOnly = args.Contains("--listen-only");
        int seconds = int.Parse(GetArgument(args, "--seconds") ?? "0", CultureInfo.InvariantCulture);

        var store = new FileStateStore(StateFile, manufacturer);
        var tuid = store.Tuid;

        Console.WriteLine($"TUID {tuid}, scope '{scope}', interface {localAddress}, universe {universe}");
        Console.WriteLine("Deriving keys (PBKDF2, 100,000 iterations)...");
        using var keys = SigNetKeys.FromPassphrase(passphrase, tuid);

        var deviceInfo = new SigNetDeviceInfo(SoemCode.Create(manufacturer, 0x0001), "Haukcode.SigNet example", Environment.MachineName)
        {
            Roles = SigNetRoles.Sender | SigNetRoles.Node,
            FirmwareVersionId = 0x00010000,
            FirmwareVersion = typeof(SigNetClient).Assembly.GetName().Version?.ToString() ?? "0.0",
            // Numbered by the client: the output is endpoint 1, the input endpoint 2
            Endpoints =
            [
                SigNetEndpointInfo.Output(universe, $"Universe {universe} out"),
                SigNetEndpointInfo.Input(universe, $"Universe {universe} in")
            ]
        };

        var frames = new ConcurrentDictionary<(SenderId, ushort), (long Count, ReceiveDataPacket Last)>();
        long syncCount = 0;

        using var client = new SigNetClient(
            keys,
            tuid,
            deviceInfo,
            store,
            localAddress,
            channelWriter: packet =>
            {
                if (packet.Kind == ReceiveDataKind.Sync)
                    Interlocked.Increment(ref syncCount);
                else
                    frames.AddOrUpdate((packet.SenderId, packet.Universe), _ => (1, packet.Clone()), (_, old) => (old.Count + 1, packet.Clone()));

                return Task.CompletedTask;
            },
            scope: scope,
            multicastLoopback: true);

        Console.WriteLine($"Session id {client.SessionId}, kernel receive timestamps: {client.KernelReceiveTimestampsActive}");

        using var errors = client.OnError.Subscribe(e => Console.WriteLine($"Error: {e.Message}"));
        using var lost = client.OnUniverseLost.Subscribe(e => Console.WriteLine($"Universe {e.Universe} lost from {e.SenderId}"));
        using var security = client.OnSecurityEvent.Subscribe(e => Console.WriteLine($"Security event {e.Code} #{e.Count} from {e.SourceAddress}"));

        client.JoinUniverse(universe);

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        if (seconds > 0)
            cts.CancelAfter(TimeSpan.FromSeconds(seconds));

        var sender = listenOnly ? Task.CompletedTask : SendPatternAsync(client, universe, sync, cts.Token);

        Console.WriteLine("Running, Ctrl+C to stop");
        while (!cts.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            foreach (var ((senderId, frameUniverse), (count, last)) in frames.OrderBy(f => f.Key.Item2))
            {
                string own = senderId.Tuid == tuid ? " (own)" : string.Empty;
                Console.WriteLine($"u{frameUniverse} from {senderId}{own} via {last.Source.Address}: {count} frames, seq {last.SequenceNumber}, priority {last.Priority}{(last.Synchronized ? ", synced" : string.Empty)}, {Describe(last.Levels.Span)}");
            }

            if (syncCount > 0)
                Console.WriteLine($"{syncCount} syncs");

            var counts = client.GetVerifyCounts().Where(kv => kv.Value > 0 && kv.Key != Security.VerifyResult.Accepted);
            if (counts.Any())
                Console.WriteLine("Rejected: " + string.Join(", ", counts.Select(kv => $"{kv.Key} {kv.Value}")));
        }

        await sender;
        client.StopUniverse(universe);
        await Task.Delay(100);

        return 0;
    }

    /// <summary>
    /// Beacon Mode: what a device without keys sends, an unauthenticated presence beacon every 5 s
    /// that Managers list as offboarded.
    /// </summary>
    private static async Task<int> RunBeaconAsync(string[] args)
    {
        ushort manufacturer = ParseHex16(GetArgument(args, "--manufacturer") ?? "0x7FF0");
        var localAddress = GetArgument(args, "--interface") is string address
            ? IPAddress.Parse(address)
            : Haukcode.Network.Utils.GetFirstBindAddress().IPAddress ?? IPAddress.Loopback;
        int seconds = int.Parse(GetArgument(args, "--seconds") ?? "0", CultureInfo.InvariantCulture);
        var tuid = Tuid.CreateDynamic(manufacturer);

        var deviceInfo = new SigNetDeviceInfo(SoemCode.Create(manufacturer, 0x0001), "Haukcode.SigNet example", Environment.MachineName)
        {
            Roles = SigNetRoles.Sender | SigNetRoles.Node
        };

        using var beacon = new SigNetBeacon(tuid, deviceInfo, localAddress, multicastLoopback: true);
        beacon.SendFailed += (_, e) => Console.WriteLine($"Beacon failed: {e.Message}");
        Console.WriteLine($"Beaconing as offboarded device {tuid} from {localAddress} every {SigNetBeacon.Interval.TotalSeconds} s, Ctrl+C to stop");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        if (seconds > 0)
            cts.CancelAfter(TimeSpan.FromSeconds(seconds));

        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token);
        }
        catch (OperationCanceledException)
        {
        }

        return 0;
    }

    /// <summary>
    /// A chase across the universe at 44 Hz, through LevelRefreshPolicy so an unchanging frame
    /// would drop to the 1 Hz keep-alive.
    /// </summary>
    private static async Task SendPatternAsync(SigNetClient client, ushort universe, bool sync, CancellationToken cancellationToken)
    {
        var policy = new LevelRefreshPolicy();
        var levels = new byte[512];
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(1000.0 / 44));
        int position = 0;

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                Array.Clear(levels);
                for (int i = 0; i < 8; i++)
                    levels[(position + i) % levels.Length] = (byte)(255 - i * 32);
                position = (position + 1) % levels.Length;

                if (policy.ShouldSend(universe, levels, 100))
                {
                    await client.SendLevels(universe, levels, priority: 100);
                    if (sync)
                        await client.SendSync();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static string Describe(ReadOnlySpan<byte> levels)
    {
        int peak = 0;
        for (int i = 1; i < levels.Length; i++)
        {
            if (levels[i] > levels[peak])
                peak = i;
        }

        return $"{levels.Length} slots, peak {levels[peak]} at slot {peak + 1}";
    }

    private static string? GetArgument(string[] args, string name)
    {
        int index = Array.IndexOf(args, name);

        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static ushort ParseHex16(string text)
    {
        return ushort.Parse(text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text[2..] : text, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// The example's stand-in for non-volatile storage: a dynamic TUID created on first run and
    /// the session id, in a small text file.
    /// </summary>
    private sealed class FileStateStore : ISessionIdStore
    {
        private readonly string path;
        private uint sessionId;

        public FileStateStore(string path, ushort manufacturerId)
        {
            this.path = path;

            if (File.Exists(path))
            {
                var parts = File.ReadAllText(path).Split(' ', StringSplitOptions.RemoveEmptyEntries);
                Tuid = Tuid.Parse(parts[0]);
                this.sessionId = uint.Parse(parts[1], CultureInfo.InvariantCulture);
            }

            if (Tuid.ManufacturerId != manufacturerId || !Tuid.IsDynamic)
            {
                Tuid = Tuid.CreateDynamic(manufacturerId);
                this.sessionId = 0;
                Write();
            }
        }

        public Tuid Tuid { get; }

        public uint LoadSessionId() => this.sessionId;

        public void SaveSessionId(uint sessionId)
        {
            this.sessionId = sessionId;
            Write();
        }

        private void Write()
        {
            // Write and flush before returning: the session id must be durable before use
            using var stream = new FileStream(this.path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            using var writer = new StreamWriter(stream);
            writer.Write($"{Tuid.ToHexString()} {this.sessionId}");
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }
    }
}
