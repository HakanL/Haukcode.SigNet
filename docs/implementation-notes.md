# Implementation Notes

Decisions and open spec questions for Haukcode.SigNet 0.1, written against
the Sig-Net Protocol Framework V1.14 (2026-10-17). Layer 1 of
[sig-net-plan.md](sig-net-plan.md).

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

Out of scope for this version, with room left for them: RDM TIDs,
TID_TIMECODE, TID_OSC, TID_PREVIEW sending, the Manager role, Open Mode,
SNOW, and SET handling. The TID catalogue already has every TID, the parser
routes every URI resource, `SigNetPath` builds every URI, and
`SigNetPacketVerifier` selects the key for every resource, so new roles add
handlers rather than reshape the client.

## Verification

- Unit tests (146, net10.0) include the Appendix G vectors: K0, Ks, Kc,
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
- **Lanes.** Lane 0 carries poll replies, announcements, security events and
  sync. Each universe's levels use the universe number as the Sender
  endpoint. A data endpoint's poll and GET replies use that endpoint number.
  Packets are sharded by lane, so each lane stays ordered on the wire with
  several sender threads.
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
- **Merging** is left to the application: frames carry the Sender-ID,
  priority and timestamps it needs. Stream loss after 3 s is an event only.
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

## Open spec questions

Each one is also a `TODO (spec x.y)` comment in the code.

1. **Sync matching (10.7.2).** Sync is matched to the active sender by the
   full 8-byte Sender-ID, but every universe is its own lane and a TID_SYNC
   carries one Sender-ID, so a full match could cover only one universe.
   Implemented as a match on the sender TUID, with sync sent on lane 0.
2. **Sequence wrap (8.3).** "When the counter reaches 0xFFFFFFFF" is read as
   0xFFFFFFFF never being sent: the session advances and every lane
   restarts at 1.
3. **Open Mode option values (8.3).** Open Mode and beacons "shall transmit
   0x00000000" for Session-ID and Seq-Num, but NETworkshop v0.11 omits both
   options in its Open Mode polls (the dissector flags them as malformed).
   The parser tolerates the omission for modes 0x01 and 0xFF only.
4. **Beacon Auth option (10.2.1 vs Appendix A).** 10.2.1 says Sig-Net-Auth
   is omitted, Appendix A note 1 says zero length. Written as zero length,
   which the SDK parser requires; both are accepted on receive.
5. **Unsupported SET (11 vs 10.1.3).** Section 11 says a Node silently
   ignores an update it cannot apply while reporting its fixed state; 10.1.3
   says the whole transaction is rejected with no reply. No reply is sent.
6. **Endpoint numbering (6.8.2 vs 8.6.2).** Data endpoints are 1..N, Sender
   lanes 1..63999. TID_RT_ENDPOINT_COUNT reports only the Node endpoints, so
   a pure Sender reports 0, and Node endpoint n shares a sequence lane with
   universe n's level stream.
7. **Security event codes (11.8.1).** 0x0002 "Replay Attack Detected"
   overlaps 0x0006 and 0x0007. The specific codes are reported.
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
12. **Appendix C vs section 11.** TID_POLL_REPLY and TID_DG_MESSAGE targets,
    and TID_OSC's length (Variable vs 1 to 255), differ between the two;
    section 11 is used.
13. **TID_UNIVERSE target.** Listed as Target Endpoint "Data" but sent to
    /node/{tuid}/0. Sent as specified, on lane 0.

## Reference implementation notes

- The SDK README (V0.6 notes) still says 100 folding groups and TTL 16; its
  code and the spec use 109 and 32.
- The SDK defines `TID_RT_SCOPE` (0x060C), which is not in the V1.14 spec;
  the catalogue leaves it out, so it is skipped as an unknown TID.
- The Rust port (Pixout-Lighting/sig-net, crate `sig-net` 0.8.0, last
  commit 2026-05-13) targets spec V1.0 and is a packet toolkit, not a
  device: CoAP and TLV encoders, a CoAP parser, key derivation, the
  passphrase rules and HMAC helpers, plus packet builders for levels,
  announcements, polls, beacons, node_lost, timecode, preview and manager
  commands, and a C FFI. It has no anti-replay logic (its receiver state
  structs are unused), no TLV length validation, no sync packet builder,
  no priority in its level builder, and no discovery, sync or stream-loss
  state machines. Against V1.14 it still writes the 7-byte pre-V1.07
  TID_UNIVERSE (V1.14 is 9 bytes), so strict V1.14 receivers, this library
  included, drop those packets as malformed. It also has no TID_SET_REPLY
  and no Appendix G vectors. Its sequence counter sends 0xFFFFFFFF before
  wrapping to 1, unlike this library's reading of open question 2. Its
  option encoding (fixed-width opaque values) and 109-group folding match.
