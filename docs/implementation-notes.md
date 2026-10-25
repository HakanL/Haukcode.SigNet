# Implementation Notes

Decisions and open spec questions for Haukcode.SigNet 0.1, written against
the Sig-Net Protocol Framework V1.14 (2026-10-17) and brought up to V1.16
(2026-10-23), which includes the V1.15 peer-review release (2026-10-21).
Layer 1 of [sig-net-plan.md](sig-net-plan.md).

## What is implemented

| Area | Spec | Where |
|------|------|-------|
| Passphrase rules, ported from the SDK reference routine | 7.2.3 | `Keys/PassphraseValidator.cs` |
| PBKDF2 K0, HKDF-Expand role keys | 7.2.3, 7.3 | `Keys/KeyDerivation.cs`, `Keys/SigNetKeys.cs` |
| `.equalkeys` and `.guestkeys` files | 7.5, 7.5.1 | `Keys/KeyFiles.cs` |
| TUID, Sender-ID, SoemCode | 6.5, 6.6, 8.3 | `Tuid.cs`, `SenderId.cs`, `SoemCode.cs` |
| CoAP writer and parser | 8.1 to 8.4, 10.2.4 | `Model/SigNetPacketWriter.cs`, `Model/SigNetPacketParser.cs` |
| URI routing, key per URI, multicast mapping | 8.2, 9.2, Appendix A | `SigNetPath.cs`, `SigNetUri.cs`, `SigNetMulticast.cs` |
| TLV codec, TID catalogue | 10.1, 11, Appendix C | `Model/Tlv.cs`, `Model/Tid.cs`, `Model/TidCatalogue.cs` |
| Packet HMAC | 8.5 | `Security/SigNetHmac.cs` |
| Receive pipeline, anti-replay | 8.6, 8.6.3, 8.6.4 | `Security/SigNetPacketVerifier.cs`, `Security/ReplayProtection.cs` |
| Sender role | 10.6, 10.7, 11.2.6 | `SigNetClient.Send.cs`, `LevelRefreshPolicy.cs` |
| Discovery, announcements, security events, Lost Mode | 10.2, 10.9 | `SigNetClient.Discovery.cs` |
| Receive side of the Node role | 10.6, 10.6.4, 10.7.2 | `SigNetClient.Receive.cs` |
| TID_DG_LEVEL_FOLDBACK, TID_DG_SOURCE | 11.8.3, 11.8.4 | `SigNetClient.Discovery.cs`, `SigNetClient.Receive.cs`, `LevelFoldbackProvider.cs` |
| ASCII and UTF-8 labels | 11.6.5, 11.6.11, 11.7.2 | `Model/Payloads.cs` (`TextPayload`) |
| Data endpoint numbering 1..N, endpoint lanes | 6.8, 8.6.2, 11.6.2 | `SigNetEndpointTable.cs`, `SigNetClient.Send.cs` |
| IPv6 multicast mapping, IPv6 TLV forms | 9.2.3, 11.2.6, 11.7.3, Appendix A | `SigNetMulticast.cs`, `Model/Payloads.cs`, `Model/TidCatalogue.cs` |
| Beacon Mode for an offboarded device | 7.2.2, 10.2.1 | `SigNetBeacon.cs` |

Out of scope for this version, with room left for them: RDM TIDs,
TID_TIMECODE, TID_OSC, TID_PREVIEW sending, the Manager role, Open Mode,
SNOW, SET handling, and an IPv6 transport (the sockets are IPv4 only). The TID catalogue already has every TID, the parser
routes every URI resource, `SigNetPath` builds every URI, and
`SigNetPacketVerifier` selects the key for every resource, so new roles add
handlers rather than reshape the client.

## Verification

- Unit tests (197, net10.0) include the Appendix G vectors: K0, Ks, Kc,
  Km_global, Km_local, the 51-byte HMAC input and the HMAC tag. Appendix G
  has no complete datagram, so `CoapCodecTests` checks a hand-assembled
  CoAP encoding of the Appendix G packet as well. The SDK README's second
  vector (`Ge2p$E$4*A`) is also tested.
- Loopback client tests cover HMAC failure, replay rejection, epoch
  regression, sync hold-and-release with the 250 ms timeout, the 5 ms sync
  gap, lane wrap and session persistence, polls, GETs, Lost Mode, and
  universe announcements.
- Interop on 2026-10-20 against NETworkshop v0.11 on the same host, both
  onboarded with the SDK test passphrase, scope `local`:
  - NETworkshop discovered the example as a Node|Sender with all root TIDs
    (poll reply, protocol version, role, 27 supported TIDs, firmware, label,
    model) and its endpoint, so it verified our Kc-signed replies to its
    Km_global polls.
  - NETworkshop's receive bargraph showed our universe 1 chase, about 44
    secure packets a second, 0 errors.
  - The example received and verified NETworkshop's universe 1 transmit
    (priority 101) and reported the universe lost 3 s after it stopped.
  - NETworkshop's Stream Integrity Test reports FAIL for our stream because
    it expects its own test pattern in the levels; it counted every packet
    as secure.
- Wireshark with the public dissector (`sig-net.lua` 1.3.0) on a capture of
  that session: our level, reply, announcement and node_lost packets decode
  with no expert errors. The only errors were on NETworkshop's Open Mode
  polls (below).

## Decisions

- **Keys.** `SigNetKeys` holds Ks, Kc, Km_global and, when derived from K0,
  this device's Km_local. K0 and the passphrase are zeroed after derivation.
  The library never stores keys; the host persists the derived keys
  (spec 7.6) and must keep them out of backups.
- **Session id.** The host implements `ISessionIdStore`. The constructor
  loads, increments and saves before anything is sent and throws
  `SessionIdExhaustedException` at the limit. A lane wrap advances and
  persists the session the same way.
- **Endpoints.** One table numbers every TID_LEVEL data endpoint 1 to N
  with no gaps (spec 6.8, 8.6.2), inputs and outputs alike, and
  TID_RT_ENDPOINT_COUNT reports N. The host declares both in
  `SigNetDeviceInfo.Endpoints`: `SigNetEndpointInfo.Output(universe, label)`
  for a universe it sends (`EndpointDirection.Supplier`,
  `EndpointCapabilities.SupplyLevel`), `SigNetEndpointInfo.Input(universe,
  label)` or the constructor for one it receives. `SigNetEndpointTable`
  numbers the outputs sorted by universe first, then the inputs sorted by
  universe (equal universes keep their declaration order), so universes 1,
  2000 and 60000 are endpoints 1, 2 and 3. Outputs first keeps a console's
  numbering independent of its inputs. A universe passed to `SendLevels`
  that was not declared as an output takes the next free endpoint, N+1, on
  first use, so an incomplete list never stops sending. Two outputs on one
  universe are rejected; an input and an output on the same universe are two
  endpoints. `SigNetClient.Endpoints` is the current table.
- **Renumbering.** Replacing `SigNetClient.DeviceInfo` rebuilds the table.
  Outputs that are still being sent but no longer declared keep an endpoint
  after the declared ones, in their previous order; stopped ones are
  dropped. An active output whose endpoint changes is announced as a
  TID_UNIVERSE Leave on the old endpoint and a Join on the new one. Sequence
  counters belong to the endpoint number, not the universe, so each
  Sender-ID's sequence keeps rising across a renumbering.
- **Lanes.** Lane 0 carries poll replies, announcements, security events and
  sync. Each output universe's levels use its endpoint as the Sender
  endpoint, and TID_UNIVERSE carries that endpoint as the originating Sender
  Endpoint. A data endpoint's poll and GET replies use that endpoint number
  too. Packets are sharded by lane, so each lane stays ordered on the wire
  with several sender threads. Timecode and OSC streams would take
  endpoints N+1 onwards (8.6.2); the library sends neither.
- **Sync spacing.** TID_SYNC is a HighPerfComm barrier packet, and the
  sender thread holds it until 5 ms after the last level datagram was handed
  to a socket, so the gap holds on the wire, not just at queue time.
- **Receive priority.** The Constrained Node Fallback: the first
  TID_PRIORITY byte is the universe priority, remembered per Sender-ID and
  universe until it changes or the session changes, default 100.
  `TID_EP_CAPABILITY` bit 5 is reported clear.
- **Sync hold.** Per sender TUID (see the open question below). Held frames
  are delivered just before the sync packet that releases them, flagged
  `Synchronized`. A timeout flush is also flagged `Synchronized`.
- **Subscriptions** mirror Haukcode.sACN: `JoinUniverse`/`DropUniverse` for
  input (a second join throws), `JoinUniverseForTrigger`/`DropUniverseForTrigger`
  for triggers (idempotent), `DropAllInputUniverses`/`DropAllTriggerUniverses`,
  and `SubscribeMode` on each received frame, so a MagnusEngine stream can
  follow `AcnStream`. Groups are reference counted across both modes.
- **Stopping.** `StopAllUniverses` sends one TID_UNIVERSE Leave for every
  active universe; `Dispose` sends nothing, so call it first.
- **Merging** is left to the application: frames carry the Sender-ID,
  priority and timestamps it needs. Stream loss after 3 s is an event only.
- **Level foldback.** TID_DG_LEVEL_FOLDBACK is mandated for a Node with
  data endpoints, but the merged output lives in the application, so the
  host sets `SigNetClient.LevelFoldback` (a `LevelFoldbackProvider`, called
  with the endpoint number and its universe) to copy an input endpoint's
  current levels. Output endpoints do not answer it. Without a provider the TID is neither
  advertised in TID_RT_SUPPORTED_TIDS nor answered. A provider returning 0
  slots is answered with a single 0, never a zero-length value.
- **Sources.** TID_DG_SOURCE is answered on input endpoints by the library
  from its receive state: every Sender-ID streaming the endpoint's universe that has not timed
  out (3 s), with its universe priority (the Constrained Node Fallback, so
  slot 1's priority), its level packets per second over the last one-second
  window (the rate so far, over at least a second, until the first window
  closes), and its source address (15 bytes for IPv4, 27 for IPv6). The
  library does not merge, so every live stream counts as a source; a host
  merging fewer than all of them reports more sources than it uses. A
  universe with no source is answered with a single 0.
- **Diagnostic GETs.** TID_DG_LEVEL_FOLDBACK and TID_DG_SOURCE are Get Only
  (11.9 "None"): never in a poll reply, and a SET of either is rejected
  with no reply, even with an unchanged value.
- **Labels.** TID_RT_DEVICE_LABEL, TID_RT_MODEL_NAME and TID_EP_LABEL are
  sent with encoding 0x00 (ASCII) when the text is ASCII, otherwise as
  UTF-8 with encoding 0x01 (V1.15), cut to 64 bytes on a character
  boundary. On receive 0x01 is decoded as UTF-8 and anything else as
  ASCII. TID_DG_MESSAGE and the firmware version text stay ASCII, as V1.16
  defines no encoding byte for them.
- **IPv6.** `SigNetMulticast.ToIpv6` and the `AddressFamily` overloads give
  the V1.15 FF18::7369: groups (239.254.X.Y maps to FF18::7369:XXYY). The
  TLV codecs accept the IPv6 forms of TID_UNIVERSE (21 bytes) and
  TID_EP_MULT_OVERRIDE (16 bytes), and `UniverseAnnouncement` reads and
  writes both. The client itself still binds IPv4 sockets, so it sends the
  IPv4 forms only.
- **Endpoint capability.** TID_EP_CAPABILITY bit 3 ("Can Supply RDM") is
  reserved since V1.15; `EndpointCapabilities.SupplyRdm` is obsolete and the
  bit is cleared in replies.
- **Discovery levels.** Poll replies follow the 11.9 QUERY_LEVEL table: the
  heartbeat set is TID_POLL_REPLY, TID_RT_ENDPOINT_COUNT and
  TID_RT_MULT_OVERRIDE. The plan listed a larger heartbeat set; the spec
  table wins.
- **SET.** Every SET on /manager is refused without a reply. GETs are
  answered read-only from `SigNetDeviceInfo`.
- **Multicast detection.** Haukcode.Network 1.0.x's `Utils.IsMulticast`
  only matched 239.255.0.0/16 (sACN) and misclassified Sig-Net's
  239.254.x.x groups as unicast. Fixed in Haukcode.Network 1.1.30 (it now
  checks 224.0.0.0/4 and IPv6 multicast), which this library requires.
- **IGMP cap.** On Linux, memberships live on separate sockets (as in
  SACNClient) and a new membership socket is opened when one hits
  `igmp_max_memberships`. A refused join still leaves the universe joined
  for unicast and rethrows the SocketException.
- **Send faults.** HighPerfComm backs off 100 ms after a failed send. A host
  that cannot send multicast on the bound interface (for example a socket
  bound to 127.0.0.1 on Windows) therefore delays and ages out unicast
  level packets too. The tests intercept multicast sends for that reason.
- **Appendix C.** The TID catalogue is hand-written: the PDF's JSON does
  not survive text extraction, and the GitHub copy the spec mentions is not
  published yet.

## Changes from V1.14 to V1.16

What each change in the V1.15 and V1.16 revision history means here:

| Change | Wire | What the library does |
|--------|------|-----------------------|
| [UTF-8] reference, encoding 0x01 for TID_RT_DEVICE_LABEL, TID_RT_MODEL_NAME, TID_EP_LABEL (2.1, 11.6.5, 11.6.11, 11.7.2) | Yes | Sends UTF-8 for non-ASCII text, reads both (Labels above) |
| Virtual Endpoints need an RDM responder only when they support RDM (6.8.2, 11.7.4) | No | Documented on `EndpointCapabilities.Virtual`; RDM is not implemented |
| TID_EP_CAPABILITY bit 3 deprecated (11.7.4) | Yes | Bit never reported, `SupplyRdm` obsolete |
| Key export prohibition scoped to Nodes, Senders, Visualisers; Equal Managers exempt (7.6) | No | No change: the library never exports derived keys; `KeyFiles` handles the Equal Manager and Guest Key files the exemption covers |
| IPv6 multicast FF18::7369:, folding, MLD (9.2.3, 9.5, Appendix A) | Yes | Address mapping only; the transport is IPv4 |
| TID_UNIVERSE 9 or 21 bytes (11.2.6) | Yes | Both lengths valid and decoded; the IPv4 form is sent |
| TID_EP_MULT_OVERRIDE 4 or 16 bytes (11.7.3) | Yes | Both lengths valid; the 4-byte form is reported |
| Sender Endpoint IDs 0x0001 to 0xFF00, timecode and OSC streams from N+1 (8.6.2) | Clarification | Level streams use their output endpoint 1..N (Endpoints above); no timecode or OSC streams |
| Proprietary TIDs 0x8000 to 0xFF00, 0xFF01 to 0xFFFF standard diagnostics (10.1.2, 11) | Yes | Already so: `Tid.IsManufacturerTid` stops at 0xFF00 |
| `<timecode_lost_timeout>` 3 s, `<node_lost_timeout>` in poll cycles (10.8.2, Appendix B) | Timing | Timecode is not implemented; Lost Mode already counts 3 poll cycles of 3 s |
| HMAC note: leading slash in the reconstructed URI, big-endian TIDs (21.4) | No | Already so; the Appendix G vectors cover both |
| TID_DG_LEVEL_FOLDBACK reports an endpoint, not a universe (11.8.3) | No | Answered per endpoint from `LevelFoldback` |
| TID_DG_SOURCE 0xFF04, one TLV per active source (11.8.4) | Yes | Answered from the receive state (Sources above) |
| V1.16: TID_RT_ENDPOINT_COUNT counts only the TID_LEVEL endpoints 1..N, contiguous on every Device; other data endpoints from N+1 (6.8, 6.8.1, 6.8.2, 8.6.2, 11.6.2) | Clarification | One table of input and output endpoints, N reported (Endpoints above; open question 6 resolved) |
| V1.16: SoemCode unique per product (6.5) | No | Documented on `SigNetDeviceInfo.SoemCode` |
| V1.16: TID_RDM_TOD_DATA is sent by Nodes only (11.3.4) | No | RDM is not implemented |

Noticed while diffing: the 11.10 summary table lists TID_DG_LEVEL_FOLDBACK
but not TID_DG_SOURCE; 11.8.4 makes it mandated for a Node whose data
endpoint consumes TID_LEVEL, which is what the library follows.

## Open spec questions

Each one is also a `TODO (spec x.y)` comment in the code. Checked against
the reference C++ SDK (v0.7) and the Sig-Net Discord (#spec-feedback and
#snactest) in October 2026; what those show is noted per question.
Re-checked against V1.16: it resolves question 6, and the sections behind
the others are unchanged. The SDK
has no TID_SYNC handling, bootstrap window, idle-repeat logic or
TID_UNIVERSE, so questions 1, 8, 9 and 13 cannot be checked against it, and
none of the four has come up on the Discord.

1. **Sync matching (10.7.2).** Sync is matched to the active sender by the
   full 8-byte Sender-ID, but every universe is its own lane and a TID_SYNC
   carries one Sender-ID, so a full match could cover only one universe.
   Implemented as a match on the sender TUID, with sync sent on lane 0.
2. **Sequence wrap (8.3).** "When the counter reaches 0xFFFFFFFF" is read as
   0xFFFFFFFF never being sent: the session advances and every lane
   restarts at 1. The SDK applications do the same. Its bare
   `IncrementSequence` helper sends 0xFFFFFFFF before wrapping to 1, as the
   Rust port does.
3. **Open Mode option values (8.3).** Open Mode and beacons "shall transmit
   0x00000000" for Session-ID and Seq-Num, but NETworkshop v0.11 omits both
   options in its Open Mode polls (the dissector flags them as malformed).
   The parser tolerates the omission for modes 0x01 and 0xFF only. The SDK
   parser requires both options, 4 bytes each, in every mode, so a sender
   must not omit them; this library always writes them.
4. **Beacon Auth option (10.2.1 vs Appendix A).** 10.2.1 says Sig-Net-Auth
   is omitted, Appendix A note 1 says zero length, and 8.3 also says 32 zero
   bytes (reported on the Discord by Vari-Lite, August 2026). Written as zero
   length, which the SDK parser requires (it rejects any other length for
   modes 0x01 and 0xFF); omitted and zero length are both accepted on
   receive.
5. **Unsupported SET (11 vs 10.1.3).** Section 11 says a Node silently
   ignores an update it cannot apply while reporting its fixed state; 10.1.3
   and 10.4.2 say the whole transaction is rejected with no reply. The
   library's parameters are read-only: a SET that would change one, or names
   a TID the endpoint does not report, is rejected with no reply, as the SDK
   node does. A SET whose values all equal the current state is the 10.4.2
   "Valid SET with no State Change" path and is echoed with a trailing
   TID_SET_REPLY carrying the unchanged CHANGE_COUNT; SNACtest test 1348
   checks exactly that on TID_RT_DEVICE_LABEL.
6. **Endpoint numbering (6.8.2 vs 8.6.2). Resolved by V1.16.** Data
   endpoints were 1..N while a Sender's level lanes used the universe
   (1..63999), so a pure Sender reported 0 and Node endpoint n shared a lane
   with universe n's level stream. V1.16 makes TID_LEVEL data endpoints 1..N
   on every Device, has each TID_LEVEL stream use its Data Endpoint, and
   reports N in TID_RT_ENDPOINT_COUNT. The library now numbers inputs and
   outputs in one table and sends each output universe on its endpoint's
   lane (Endpoints, Renumbering and Lanes above).
7. **Security event codes (11.8.1).** 0x0002 "Replay Attack Detected"
   overlaps 0x0005, 0x0006 and 0x0007. The SDK defines only 0x0001 to
   0x0004 and reports every freshness failure, including a full replay
   table, as 0x0002. The library reports the specific code and 0x0002 as
   well, so managers built on either reading see the event. Asked on the
   Discord by NETworkshop's developer in July 2026, unanswered.
8. **Link-up (8.6.4).** The bootstrap window starts on link-up. The library
   starts it at construction; hosts that see link state call `SignalLinkUp`.
9. **Idle repeats (10.6.3).** "Three identical packets containing the final
   state" is read as three in total, including the one that carried the
   change (`LevelRefreshPolicy`).
10. **Passphrase characters (7.2.3).** The reference routine accepts any
    byte; the spec says ASCII. Non-printable or non-ASCII characters are
    rejected, the one deliberate difference from the reference.
11. **Key file names (7.5).** The PDF renders `"sig - net_equal_keys"`; taken
    as `sig-net_equal_keys` and `sig-net_guest_keys`.
12. **Appendix C vs section 11.** The TID_POLL_REPLY and TID_DG_MESSAGE
    targets, TID_OSC's length (Variable vs 1 to 255), and the TID_RDM_COMMAND
    and TID_RDM_RESPONSE targets (Appendix C: Data; 11.3.1 and 11.3.2: Root
    and Data, Root limited to firmware updates) differ between the two;
    section 11 is used. RDM is not implemented yet, so the RDM targets have
    no effect today.
13. **TID_UNIVERSE target.** Listed as Target Endpoint "Data" but sent to
    /node/{tuid}/0. Sent as specified, on lane 0.
14. **Replay table size (8.6 step 10c vs 8.6.2).** A Node must track at least
    32 Sender-ID records, but every universe is its own sender lane, so one
    console sending 100 universes needs 100 records and a 32-record table
    saturates (and drops the rest as event 0x0005). The library default is the
    spec minimum; a recorder or router consuming many universes passes a
    larger `replayTableCapacity` (MagnusEngine's SigNetStream uses 8,192).
    The SDK uses the same model (session per TUID, sequence per Sender-ID,
    32 entries, reuse after an hour idle) and does not address the
    many-universes case.
15. **TID_RT_SCOPE (0x060C).** The SDK defines it (Operational URI scope, a
    UTF-8 string of up to 32 bytes) but V1.14 to V1.16 do not, and Appendix C skips
    0x060C. Is it a TID the next spec version adds, or an SDK leftover? Until
    the spec defines it, the catalogue leaves it out and it is skipped as an
    unknown TID. The SDK node holds it internally ("local") but never
    advertises it in TID_RT_SUPPORTED_TIDS, never sends it, ignores GETs and
    rejects SETs, which looks like a leftover or a future TID.
16. **Leaving Lost Mode (10.2.6).** What ends Lost Mode: only a Manager
    addressing this Node (a poll whose TUID range includes it, or a command
    to it), or any verified Manager traffic? The second means verifying
    every Manager packet even when it is for another device. The library
    leaves Lost Mode on a verified poll that includes its TUID. Asked on the
    Discord by Vari-Lite in August 2026 (SNACtest runs pushed their node into
    Lost Mode), unanswered.

## Reference implementation notes

- The SDK README (V0.6 notes) still says 100 folding groups and TTL 16; its
  code and the spec use 109 and 32.
- The SDK defines `TID_RT_SCOPE` (0x060C), which is not in the spec up to
  V1.16 (open question 15).
- The Rust port (Pixout-Lighting/sig-net, crate `sig-net` 0.8.0, last
  commit 2026-05-13) targets spec V1.0 and is a packet toolkit, not a
  device: CoAP and TLV encoders, a CoAP parser, key derivation, the
  passphrase rules and HMAC helpers, plus packet builders for levels,
  announcements, polls, beacons, node_lost, timecode, preview and manager
  commands, and a C FFI. It has no anti-replay logic (its receiver state
  structs are unused), no TLV length validation, no sync packet builder,
  no priority in its level builder, and no discovery, sync or stream-loss
  state machines. It still writes the 7-byte pre-V1.07 TID_UNIVERSE (9
  bytes since V1.07, 9 or 21 since V1.15), so strict receivers, this
  library included, drop those packets as malformed. It also has no TID_SET_REPLY
  and no Appendix G vectors. Its sequence counter sends 0xFFFFFFFF before
  wrapping to 1, unlike this library's reading of open question 2. Its
  option encoding (fixed-width opaque values) and 109-group folding match.
