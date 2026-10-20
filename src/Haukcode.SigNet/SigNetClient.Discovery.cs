using System.Buffers.Binary;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Haukcode.SigNet.Model;

namespace Haukcode.SigNet;

// Discovery and announcements: on-boot notification, poll replies, read-only GET replies,
// TID_UNIVERSE, security events and Lost Mode
public partial class SigNetClient
{
    /// <summary>
    /// &lt;poll_backoff_max&gt;: upper bound of the random delay before a reply to a range poll and
    /// before the on-boot notification (spec 10.2.3, 10.2.5).
    /// </summary>
    public static readonly TimeSpan PollBackoffMax = TimeSpan.FromMilliseconds(1000);

    /// <summary>
    /// &lt;universe_announce_interval&gt; (spec 11.2.6).
    /// </summary>
    public static readonly TimeSpan UniverseAnnounceInterval = TimeSpan.FromSeconds(5);

    /// <summary>
    /// &lt;poll_time&gt; (spec Appendix B).
    /// </summary>
    public static readonly TimeSpan PollTime = TimeSpan.FromSeconds(3);

    /// <summary>
    /// &lt;node_lost_timeout&gt; poll cycles without a poll before a Node enters Lost Mode (spec 10.2.6).
    /// </summary>
    public const int NodeLostPollCycles = 3;

    /// <summary>
    /// &lt;endpoint_spacing_delay&gt; between per-endpoint replies to an all-endpoints poll (spec 10.2.3).
    /// </summary>
    public static readonly TimeSpan EndpointSpacingDelay = TimeSpan.FromMilliseconds(1);

    private static readonly TimeSpan HousekeepingInterval = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan SecurityEventInterval = TimeSpan.FromSeconds(1);

    private static readonly ushort[] rootTids =
    [
        Tid.RtEndpointCount, Tid.RtMultOverride,
        Tid.RtDeviceLabel, Tid.RtIdentify, Tid.RtStatus,
        Tid.RtSupportedTids, Tid.RtProtocolVersion, Tid.RtFirmwareVersion, Tid.RtRoleCapability, Tid.RtModelName,
        Tid.DgSecurityEvent
    ];

    private static readonly ushort[] dataTids =
    [
        Tid.EpUniverse, Tid.EpLabel, Tid.EpMultOverride, Tid.EpCapability, Tid.EpDirection,
        Tid.EpStatus, Tid.EpFailover, Tid.EpRefreshCapability, Tid.EpProtocol, Tid.EpIdentify
    ];

    // Security event state (spec 10.9): counter, last offending address and last transmission per code
    private readonly object securityLock = new();
    private readonly uint[] securityEventCounts = new uint[9];
    private readonly IPAddress?[] securityEventSources = new IPAddress?[9];
    private readonly long[] securityEventSent = new long[9];

    private CancellationTokenSource? pendingReplyCts;
    private readonly object replyLock = new();
    private long lastPollTimestamp;
    private long lastAnnounceTimestamp;
    private long lastNodeLostTimestamp;
    private bool lostMode;

    /// <summary>
    /// True while a Node has gone <see cref="NodeLostPollCycles"/> poll cycles without a valid poll
    /// and is announcing itself on /node_lost (spec 10.2.6).
    /// </summary>
    public bool IsInLostMode => this.lostMode;

    private void Housekeeping()
    {
        try
        {
            CheckReceiveTimeouts();

            if (this.timeProvider.GetElapsedTime(Interlocked.Read(ref this.lastAnnounceTimestamp)) >= UniverseAnnounceInterval)
            {
                Interlocked.Exchange(ref this.lastAnnounceTimestamp, this.timeProvider.GetTimestamp());
                AnnounceActiveUniverses();
            }

            CheckLostMode();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            this.errorSubject.OnNext(ex);
        }
    }

    /// <summary>
    /// Re-announce every active universe (spec 11.2.6), packed into as few packets as fit.
    /// </summary>
    private void AnnounceActiveUniverses()
    {
        lock (this.sendLock)
        {
            if (this.activeUniverses.Count == 0 || !IsOperational)
                return;

            var announcements = new List<UniverseAnnouncement>(this.activeUniverses.Count);
            foreach (ushort universe in this.activeUniverses)
                announcements.Add(new UniverseAnnouncement(universe, UniverseCommand.Join, null, universe));

            QueueUniverseAnnouncementLocked(announcements);
        }
    }

    // TID_UNIVERSE to /node/{tuid}/0, signed with Kc. Called under sendLock.
    private void QueueUniverseAnnouncementLocked(IReadOnlyList<UniverseAnnouncement> announcements)
    {
        const int perPacket = Coap.MaxPayloadLength / (TlvReader.HeaderLength + UniverseAnnouncement.Length);

        for (int start = 0; start < announcements.Count; start += perPacket)
        {
            int count = Math.Min(perPacket, announcements.Count - start);
            var payload = new byte[count * (TlvReader.HeaderLength + UniverseAnnouncement.Length)];
            var writer = new TlvWriter(payload);
            for (int i = 0; i < count; i++)
                announcements[start + i].WriteTo(writer.Reserve(Tid.Universe, UniverseAnnouncement.Length));

            QueueSignedLocked(SigNetPath.Node(Scope, Tuid, 0), AdminLane, payload);
        }
    }

    /// <summary>
    /// Spec 10.2.5: after a random 0 to 1,000 ms, one packet to /node/{tuid}/0 signed with Kc.
    /// </summary>
    private void ScheduleOnBootNotification()
    {
        var delay = TimeSpan.FromMilliseconds(Random.Shared.Next((int)PollBackoffMax.TotalMilliseconds + 1));
        var token = this.lifetimeCts.Token;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay, this.timeProvider, token).ConfigureAwait(false);
                QueueSigned(SigNetPath.Node(Scope, Tuid, 0), AdminLane, BuildAnnouncementPayload());
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                this.errorSubject.OnNext(ex);
            }
        }, token);
    }

    // On-boot and node_lost payload, in the order spec 10.2.5 and 10.2.6 require
    private byte[] BuildAnnouncementPayload()
    {
        var info = this.deviceInfo;
        var buffer = new byte[Coap.MaxPayloadLength];
        var writer = new TlvWriter(buffer);

        WritePollReply(ref writer, info);
        writer.WriteByte(Tid.RtProtocolVersion, SigNetUri.ProtocolVersion);
        writer.WriteUInt32(Tid.RtRoleCapability, (uint)info.Roles);
        writer.WriteUInt16(Tid.RtEndpointCount, (ushort)info.Endpoints.Count);
        writer.WriteByte(Tid.RtMultOverride, 0x00);

        return writer.Written.ToArray();
    }

    private void CheckLostMode()
    {
        if (!this.deviceInfo.Roles.HasFlag(SigNetRoles.Node))
            return;

        bool lost = this.timeProvider.GetElapsedTime(Interlocked.Read(ref this.lastPollTimestamp)) >= PollTime * NodeLostPollCycles;
        this.lostMode = lost;

        if (lost && this.timeProvider.GetElapsedTime(Interlocked.Read(ref this.lastNodeLostTimestamp)) >= PollTime)
        {
            Interlocked.Exchange(ref this.lastNodeLostTimestamp, this.timeProvider.GetTimestamp());
            QueueSigned(SigNetPath.NodeLost(Scope, Tuid), AdminLane, BuildAnnouncementPayload());
        }
    }

    /// <summary>
    /// A verified TID_POLL on /poll (spec 10.2.3).
    /// </summary>
    private void ReceivePoll(ReadOnlySpan<byte> payload)
    {
        PollRequest? request = null;
        var reader = new TlvReader(payload);
        while (reader.TryRead(out ushort tid, out var value))
        {
            if (tid == Tid.Poll)
                request = PollRequest.Read(value);
        }

        if (request is not { } poll || !poll.Includes(Tuid))
            return;

        // Any valid poll ends Lost Mode, whichever Manager sent it (spec 10.2.6)
        Interlocked.Exchange(ref this.lastPollTimestamp, this.timeProvider.GetTimestamp());

        var endpoints = GetReplyEndpoints(poll.Endpoint);
        if (endpoints.Count == 0)
            return;

        // A targeted poll is answered at once, a range poll after a random backoff
        var delay = poll.IsTargeted ? TimeSpan.Zero : TimeSpan.FromMilliseconds(Random.Shared.Next((int)PollBackoffMax.TotalMilliseconds + 1));

        StartReply(async token =>
        {
            if (delay > TimeSpan.Zero)
                await Task.Delay(delay, this.timeProvider, token).ConfigureAwait(false);

            for (int i = 0; i < endpoints.Count; i++)
            {
                if (i > 0)
                    await Task.Delay(EndpointSpacingDelay, this.timeProvider, token).ConfigureAwait(false);

                token.ThrowIfCancellationRequested();
                SendEndpointReply(endpoints[i], tid => TidCatalogue.TryGet(tid, out var info) && info.PollLevel <= poll.QueryLevel, startWithPollReply: true);
            }
        });
    }

    /// <summary>
    /// A verified packet on /manager/{tuid}/{endpoint}. Parameter Queries (all TLVs zero length)
    /// are answered from the same read-only state as polls. Any SET is refused as a whole with no
    /// reply, since this library exposes no settable parameters (spec 10.1.3, 10.4.2).
    /// </summary>
    // TODO (spec 11 "Mandated" vs 10.1.3): section 11 says a Node "shall silently ignore the
    // invalid parameter update while continuing to accurately report its fixed state", while
    // 10.1.3 says an unsupported SET rejects the transaction with no reply. The no-reply reading
    // is used.
    private void ReceiveManagerCommand(ushort endpoint, ReadOnlySpan<byte> payload)
    {
        var requested = new HashSet<ushort>();
        var reader = new TlvReader(payload);
        while (reader.TryRead(out ushort tid, out var value))
        {
            if (!value.IsEmpty)
                return;

            requested.Add(tid);
        }

        var endpoints = GetReplyEndpoints(endpoint);
        if (requested.Count == 0 || endpoints.Count == 0)
            return;

        StartReply(async token =>
        {
            for (int i = 0; i < endpoints.Count; i++)
            {
                if (i > 0)
                    await Task.Delay(EndpointSpacingDelay, this.timeProvider, token).ConfigureAwait(false);

                token.ThrowIfCancellationRequested();
                SendEndpointReply(endpoints[i], requested.Contains, startWithPollReply: false);
            }
        });
    }

    private List<ushort> GetReplyEndpoints(ushort endpoint)
    {
        int count = this.deviceInfo.Endpoints.Count;
        var result = new List<ushort>();

        if (endpoint == PollRequest.AllEndpoints)
        {
            for (int i = 0; i <= count; i++)
                result.Add((ushort)i);
        }
        else if (endpoint <= count)
        {
            result.Add(endpoint);
        }

        return result;
    }

    /// <summary>
    /// Run a reply sequence, aborting any previous one still in progress (spec 10.2.3 "Reply
    /// Supersession").
    /// </summary>
    private void StartReply(Func<CancellationToken, Task> reply)
    {
        CancellationTokenSource cts;
        lock (this.replyLock)
        {
            this.pendingReplyCts?.Cancel();
            this.pendingReplyCts?.Dispose();
            cts = CancellationTokenSource.CreateLinkedTokenSource(this.lifetimeCts.Token);
            this.pendingReplyCts = cts;
        }

        var token = cts.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                await reply(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                this.errorSubject.OnNext(ex);
            }
        }, token);
    }

    /// <summary>
    /// The reply for one endpoint to /node/{tuid}/{endpoint}, split into packets of at most 1,200
    /// payload bytes, each a valid payload on its own (spec 10.2.4). Poll replies start every
    /// packet with TID_POLL_REPLY (spec 10.2.3).
    /// </summary>
    private void SendEndpointReply(ushort endpoint, Func<ushort, bool> include, bool startWithPollReply)
    {
        var info = this.deviceInfo;
        var items = new List<(ushort Tid, byte[] Value)>();
        foreach (ushort tid in endpoint == 0 ? rootTids : dataTids)
        {
            if (include(tid))
                AddTlvs(items, tid, endpoint, info);
        }

        if (items.Count == 0 && !startWithPollReply)
            return;

        var path = SigNetPath.Node(Scope, Tuid, endpoint);
        var buffer = new byte[Coap.MaxPayloadLength];
        int index = 0;
        do
        {
            var writer = new TlvWriter(buffer);
            if (startWithPollReply)
                WritePollReply(ref writer, info);

            while (index < items.Count && writer.CanWrite(items[index].Value.Length))
            {
                writer.Write(items[index].Tid, items[index].Value);
                index++;
            }

            if (writer.Length == 0)
                break;

            // Replies from a data endpoint use that endpoint as their lane (spec 8.6.2)
            QueueSigned(path, endpoint, writer.Written.ToArray());
        }
        while (index < items.Count);
    }

    private void WritePollReply(ref TlvWriter writer, SigNetDeviceInfo info)
    {
        new PollReply(Tuid, info.SoemCode, info.ChangeCount).WriteTo(writer.Reserve(Tid.PollReply, PollReply.Length));
    }

    private void AddTlvs(List<(ushort, byte[])> items, ushort tid, ushort endpoint, SigNetDeviceInfo info)
    {
        var endpointInfo = endpoint > 0 && endpoint <= info.Endpoints.Count ? info.Endpoints[endpoint - 1] : null;

        switch (tid)
        {
            case Tid.RtEndpointCount:
                // TODO (spec 6.8.2 vs 8.6.2): data endpoints are numbered 1..N, while a Sender's
                // level lanes use endpoints 1..63999 (the universe here). The count reports only
                // the Node endpoints from SigNetDeviceInfo, so a pure Sender reports 0, and a Node
                // endpoint n shares its sequence lane with universe n's level stream.
                items.Add((tid, UInt16Bytes((ushort)info.Endpoints.Count)));
                break;

            case Tid.RtMultOverride:
                // Always the default folded mapping; TID_EP_MULT_OVERRIDE is not supported
                items.Add((tid, [0x00]));
                break;

            case Tid.RtDeviceLabel:
                items.Add((tid, LabelBytes(info.DeviceLabel)));
                break;

            case Tid.RtIdentify:
                items.Add((tid, [0x00]));
                break;

            case Tid.RtStatus:
                items.Add((tid, UInt32Bytes(info.Status)));
                break;

            case Tid.RtSupportedTids:
                items.Add((tid, GetSupportedTids(info)));
                break;

            case Tid.RtProtocolVersion:
                items.Add((tid, [SigNetUri.ProtocolVersion]));
                break;

            case Tid.RtFirmwareVersion:
            {
                var text = Ascii(info.FirmwareVersion);
                var value = new byte[4 + text.Length];
                BinaryPrimitives.WriteUInt32BigEndian(value, info.FirmwareVersionId);
                text.CopyTo(value, 4);
                items.Add((tid, value));
                break;
            }

            case Tid.RtRoleCapability:
                items.Add((tid, UInt32Bytes((uint)info.Roles)));
                break;

            case Tid.RtModelName:
                items.Add((tid, LabelBytes(info.ModelName)));
                break;

            case Tid.DgSecurityEvent:
                lock (this.securityLock)
                {
                    // One TLV per tracked event code (spec 11.8.1)
                    for (int code = 1; code < this.securityEventCounts.Length; code++)
                    {
                        var securityEvent = new SecurityEvent((SecurityEventCode)code, this.securityEventCounts[code], this.securityEventSources[code]);
                        var value = new byte[securityEvent.Length];
                        securityEvent.WriteTo(value);
                        items.Add((tid, value));
                    }
                }
                break;

            case Tid.EpUniverse when endpointInfo != null:
                items.Add((tid, UInt16Bytes(endpointInfo.Universe)));
                break;

            case Tid.EpLabel when endpointInfo != null:
                items.Add((tid, LabelBytes(endpointInfo.Label)));
                break;

            case Tid.EpMultOverride when endpointInfo != null:
                items.Add((tid, new byte[4]));
                break;

            case Tid.EpCapability when endpointInfo != null:
            {
                var value = new byte[6];
                BinaryPrimitives.WriteUInt32BigEndian(value, (uint)endpointInfo.Capabilities);
                bool consumes = endpointInfo.Capabilities.HasFlag(EndpointCapabilities.ConsumeLevel);
                BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), consumes ? Math.Max((ushort)4, endpointInfo.MaxMergeSources) : (ushort)0);
                items.Add((tid, value));
                break;
            }

            case Tid.EpDirection when endpointInfo != null:
                items.Add((tid, [(byte)endpointInfo.Direction]));
                break;

            case Tid.EpStatus when endpointInfo != null:
                items.Add((tid, UInt32Bytes(GetEndpointStatus(endpointInfo.Universe))));
                break;

            case Tid.EpFailover when endpointInfo != null:
            {
                var value = new byte[3];
                value[0] = endpointInfo.FailoverMode;
                BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(1), endpointInfo.FailoverScene);
                items.Add((tid, value));
                break;
            }

            case Tid.EpRefreshCapability when endpointInfo != null:
                items.Add((tid, [Math.Max((byte)44, endpointInfo.RefreshCapability)]));
                break;

            case Tid.EpProtocol when endpointInfo != null:
                items.Add((tid, [0x00]));
                break;

            case Tid.EpIdentify when endpointInfo != null:
                items.Add((tid, [0x00]));
                break;
        }
    }

    private static byte[] GetSupportedTids(SigNetDeviceInfo info)
    {
        var tids = new List<ushort> { Tid.Poll, Tid.PollReply, Tid.Level, Tid.Priority, Tid.Sync, Tid.Universe };
        tids.AddRange(rootTids);
        if (info.Endpoints.Count > 0)
            tids.AddRange(dataTids);

        var value = new byte[tids.Count * 2];
        for (int i = 0; i < tids.Count; i++)
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(i * 2), tids[i]);

        return value;
    }

    /// <summary>
    /// Count a security event and multicast TID_DG_SECURITY_EVENT to /node/{tuid}/0, at most once
    /// per second per code; the counter keeps counting while reports are suppressed (spec 10.9).
    /// </summary>
    private void RaiseSecurityEvent(SecurityEventCode code, IPAddress? source)
    {
        int index = (int)code;
        SecurityEvent securityEvent;
        bool send = false;

        lock (this.securityLock)
        {
            this.securityEventCounts[index]++;
            this.securityEventSources[index] = source;
            securityEvent = new SecurityEvent(code, this.securityEventCounts[index], source);

            long now = this.timeProvider.GetTimestamp();
            if (this.securityEventSent[index] == 0 || this.timeProvider.GetElapsedTime(this.securityEventSent[index], now) >= SecurityEventInterval)
            {
                this.securityEventSent[index] = now;
                send = true;
            }
        }

        this.securityEventSubject.OnNext(securityEvent);

        if (send)
        {
            var payload = new byte[TlvReader.HeaderLength + securityEvent.Length];
            var writer = new TlvWriter(payload);
            securityEvent.WriteTo(writer.Reserve(Tid.DgSecurityEvent, securityEvent.Length));

            try
            {
                QueueSigned(SigNetPath.Node(Scope, Tuid, 0), AdminLane, payload);
            }
            catch (SessionIdExhaustedException)
            {
            }
        }
    }

    private static byte[] UInt16Bytes(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);

        return bytes;
    }

    private static byte[] UInt32Bytes(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);

        return bytes;
    }

    // Encoding byte 0x00 (ASCII) then the text, at most 64 bytes, not null-terminated
    private static byte[] LabelBytes(string text)
    {
        var ascii = Ascii(text);
        var value = new byte[1 + ascii.Length];
        ascii.CopyTo(value, 1);

        return value;
    }

    private static byte[] Ascii(string text)
    {
        int length = Math.Min(text.Length, TextPayload.MaxTextLength);
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
            bytes[i] = text[i] < 0x80 ? (byte)text[i] : (byte)'?';

        return bytes;
    }
}
