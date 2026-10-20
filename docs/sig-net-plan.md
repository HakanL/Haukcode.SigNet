# Sig-Net Send and Receive Support

Status: assessment only, nothing built. Written 2026-10-20 against the
Sig-Net Protocol Framework V1.14 (2026-10-17).

File paths under `src/` and `docs/` below refer to the DMX Core 100 repo
(`DMXCore/DmxCore100-Software`); `MagnusEngine/` paths refer to its sibling
engine repo. This document lives in the library repo because the library
is the first deliverable.

## What Sig-Net is, in one paragraph

Sig-Net is Wayne Howell's (Art-Net author, Singularity UK Ltd) successor to
Art-Net and sACN, built to be defensible under the EU Cyber Resilience Act.
Every packet is a CoAP NON POST over UDP 5683 carrying custom CoAP options
(security mode, 8-byte sender id, manufacturer code, session id, sequence
number, HMAC-SHA256 tag) and a TLV payload. Universes go to multicast groups
239.254.0.1 to 239.254.0.109 by "Multicast Folding" (`((universe-1) % 109)+1`),
so large rigs do not exhaust switch IGMP tables. Administrative traffic uses
eight fixed groups in 239.254.255.248 to .255. Payloads are not encrypted;
the security is authentication plus anti-replay, using keys derived by HKDF
from a 256-bit root key that is entered once per device as a passphrase.
Spec, SDK and Wireshark dissector: https://sig-net.net/resources/.

**SNOW is not an alternative to Sig-Net.** SNOW (Sig-Net Over Wire, V1.03)
is an optional extension that lets a Manager push derived keys to an
unprovisioned device through a DTLS tunnel instead of someone typing the
passphrase on each device. It only matters for onboarding. The library
below is `Haukcode.SigNet`; SNOW is a possible later add-on inside it.

## Scope decision: which Sig-Net roles DMX Core 100 plays

Sig-Net defines four roles. The recommendation for rev 1:

| Role | What it means | Rev 1 |
|------|---------------|-------|
| Sender | Streams TID_LEVEL/TID_PRIORITY/TID_SYNC, answers polls | **Yes.** This is "Sig-Net output" |
| Node | Consumes universes on data endpoints, is patched by a Manager, proxies RDM | **Receive-only subset.** Consume TID_LEVEL into internal universes for recording and routing. No RDM, no Manager-driven patching |
| Visualiser | Passive subscriber to levels, preview and patch | Not declared. Our receive side behaves like one but we output DMX, so the honest declaration is Node |
| Manager | Onboards, polls, configures and runs RDM on other devices | **No.** Consoles do this. Possible later feature for the device monitor |

The Node role as the spec defines it is the biggest open design question.
A full Node exposes one data endpoint per consumed universe and lets a
console change its universe patch (TID_EP_UNIVERSE), label, failover, and
answer per-endpoint capability queries. Our input mapping is user-configured
in the web UI, not console-patched. Rev 1 should declare the Node role bit
with `TID_RT_ENDPOINT_COUNT` = number of input-mapped universes, answer the
endpoint capability TIDs read-only, and reject SET from Managers. That is
spec-legal ("the Node shall silently ignore the invalid parameter update
while continuing to accurately report its fixed state"). Full Manager
patching of DMX Core inputs is a rev 2 item if a customer asks for it.

Per-slot priority (ETC 0xDD) merge is mandatory for Nodes that consume
levels, but the spec allows the "Constrained Node Fallback": use the first
priority byte as a universe priority and clear bit 5 of
`TID_EP_CAPABILITY`. That matches our router, which merges on a universe
priority today (`StreamRouter.cs:445`). Use the fallback in rev 1.

## Three layers of work

Decision: the protocol library lives in its own repo beside
`D:\Projects\OpenSource\Haukcode-sACN`, `Haukcode-ArtNet` and `Haukcode-KiNet`,
and the Core wires it up through MagnusEngine like the others.

### Layer 1: `Haukcode.SigNet` library (new repo, MIT, nuget.org)

Mirror the sACN repo layout: `src/Haukcode.SigNet`, `test`, `example`,
`version.json`, same GitHub Actions. Target net8.0 to net10.0. Depend on
`Haukcode.HighPerfComm` (sharded sender threads, kernel receive timestamps,
`QueueBarrierPacket` for sync) and `Haukcode.Network` (bind address helpers).
No CoAP package: Sig-Net uses a fixed subset of CoAP and a hand-written
codec is smaller than any dependency.

Components, with the spec sections that define them:

1. **CoAP codec** (8.1 to 8.4). 4-byte header, skip token, options with
   extended delta encoding (Uri-Path 11, then 2076, 2108, 2140, 2172, 2204,
   2236), 0xFF payload marker omitted when payload is empty. Options are
   "opaque", fixed width, zero padded; the spec notes real-world CoAP
   libraries got the uint minimum-width rule wrong, which is why it is
   opaque. Max 1,400 bytes per datagram, 1,200 bytes of TLVs.
2. **TLV codec and TID catalogue** (10.1, 11, Appendix C). 2-byte TID,
   2-byte length, value. Unknown TIDs are skipped; malformed TLVs drop the
   whole packet silently. Appendix C is a JSON TID dictionary that can seed
   a generated constants file.
3. **Key material** (7). `Rfc2898DeriveBytes.Pbkdf2` (already used in
   `src/Common/PasswordHasher.cs`) with 100,000 iterations and the fixed
   salt `Sig-Net-K0-Salt-v1` turns a passphrase into K0.
   `System.Security.Cryptography.HKDF.Expand` derives Ks, Kc, Km_global and
   Km_local (`"Sig-Net-Manager-v1-" + TUID`). Port the normative passphrase
   validator (10 to 64 chars, 3 of 4 classes, no "aaa", no "abcd") from the
   reference C in Howell's SDK. Appendix G has normative test vectors for
   the whole chain, so this layer is unit-testable on day one.
4. **HMAC and anti-replay** (8.5, 8.6). HMAC-SHA256 over URI string plus
   the five option values plus payload; `CryptographicOperations.FixedTimeEquals`.
   Receive state table keyed by sender TUID (session id) and 8-byte
   Sender-ID (sequence), RAM only, 32-entry minimum with the 1-hour LRU
   rule, first-packet bootstrapping, 2 s post-link-up lockout for SET.
   The key to verify with is chosen by URI (Appendix A), not by TID.
5. **`SigNetClient : Client<SendData, ReceivePacket>`** on HighPerfComm.
   Shard by universe like `SACNClient`. One receive socket on 5683 bound
   to the chosen NIC, membership socket for the folded groups of mapped
   universes plus `<mult_time>` (sync) and `<mult_manager_poll>`,
   `<mult_manager_send>` (to answer polls and reject SETs). Per-lane
   sequence counters: endpoint 0 for admin, one lane per universe. The
   host must supply a **session-id store** because the session id must be
   incremented and persisted before the first packet of every run (8.3)
   and lives in non-volatile storage, not in the library.
6. **Sender duties** (10.6.3, 10.7, 11.2.6, 10.2.5): levels at 44 Hz
   default or the configured output frequency, three identical frames on
   transition to idle then 1 Hz keep-alive (the existing `OptimizeSend`
   path already does the repeat-then-idle dance for sACN), `TID_SYNC` 5 ms
   after the last level packet of a frame, `TID_UNIVERSE` join/leave plus
   a 5 s re-announce, on-boot notification to `/node/{tuid}/0` signed with
   Kc, and answering `TID_POLL` with the heartbeat set
   (`TID_POLL_REPLY`, then `TID_RT_PROTOCOL_VERSION`, `FIRMWARE_VERSION`,
   `MODEL_NAME`, `STATUS`, `SUPPORTED_TIDS`, `MULT_OVERRIDE`,
   `ROLE_CAPABILITY`, `ENDPOINT_COUNT`, `DEVICE_LABEL`) after a random
   0 to 1,000 ms backoff. `TID_DG_SECURITY_EVENT` rate-limited to one per
   second per code.
7. **Receiver duties** (10.6, 10.7.2, 10.6.4): verify, parse
   `TID_PRIORITY` before `TID_LEVEL`, hand up (universe, 512 bytes,
   priority, 8-byte sender id, sync flag, timestamp). Hold levels in a
   buffer while `SYNC_ACTIVE` and release on `TID_SYNC` from the same
   sender, with the 250 ms sync timeout. Universe lost after 3 s.
8. **Identity**: TUID = 16-bit ESTA manufacturer id plus 32-bit device id.
   DMX Pro Sales, LLC holds ESTA id **0x0744** (verified in the ESTA
   manufacturer list on 2026-10-20). Hardware units use a static id with
   the top bit clear, derived from the unit serial; Windows and Mac builds
   use a random id with the top bit set, persisted on first run.
   `SoemCode` = `0x0744 << 16 | product variant`.
9. Out of rev 1 but designed for: `TID_RDM_*` (we have Art-Net RDM
   controller code only), `TID_TIMECODE` (MTC-shaped, maps onto the
   existing `IHasArtTimeCode` consumer path), `TID_OSC` on the aux URI,
   Manager role, SNOW onboarding, Open Mode (0x01).

Size: the sACN library is 1,870 lines with no crypto and a simpler packet
format. Expect 3,000 to 4,000 lines plus tests for Sig-Net. The
cryptographic and codec parts are mechanical; the replay table, poll
backoff and sync state machine are where the bugs will be.

### Layer 2: `SigNetStream` in MagnusEngine

Model it on `MagnusEngine/StreamIO/AcnStream.cs` (663 lines): implement
`IDmxCommunicationSync` and `IDmxRecorder`, wrap `SigNetClient`, pump
received frames through `ReceiveQueue` into `writer.WriteDmxData` as
`RawDmxData`. Specific points:

- `StreamPortTypes.SigNet` in `MagnusEngine.Contract/StreamPortTypes.cs`.
- `SendDmx` maps `priority` to a one-byte `TID_PRIORITY` packed before
  `TID_LEVEL` in the same datagram; `SendSync` queues a barrier packet
  like `AcnStream.SendSync` so sync leaves after all shards.
- `RawDmxData` has `AcnSourceId` (Guid) and `Source` (IP) but no field for
  an 8-byte Sig-Net sender id. `StreamRouter.SourceKey` keys external
  sources by CID or by protocol plus IP, with an 8-source cap. Add a
  `SigNetSenderId` (ulong) to `RawDmxData` and a third `SourceKey` form, or
  pack the sender id into a synthesized Guid. The second is less code but
  leaks into the pcap writer, which stores `AcnSourceId` as the CID in
  recordings (`PCapAcnFileWriter.cs:109`). A synthesized Guid is actually a
  reasonable CID for a re-encoded sACN recording, so this is a judgment
  call, not a blocker.
- Recordings stay sACN pcap `.cap` files whatever the input protocol, as
  with Art-Net today. Sig-Net and sACN share the 1 to 63,999 universe
  range, so no clamping is needed when re-encoding.
- Input loss: `RouterPlayer` applies `InputLossTimeoutMS`; the Sig-Net
  3 s `<universe_lost_timeout>` can be the stream's default.
- `OutputManager.GetInputStream` picks the newest stream of a port type,
  and `PortOperationManager.CreateInputPipeline` creates one
  `OutputProcessor` per protocol. Nothing protocol-specific there.
- Routing loop guard `RecomputeRoutingConflicts` compares destinations;
  Sig-Net needs the folded multicast group plus universe, same shape as
  sACN.
- The IGMP membership cap handling in `AcnStream.StartRecord` (423 to
  449) must be copied. Sig-Net needs at most 109 universe groups plus 3
  admin groups, fewer than sACN's one-per-universe, so this is easier.

Size: 600 to 800 lines plus tests modeled on `AcnReceivePathTests.cs`.

### Layer 3: Core wiring (DmxCore100-Software)

Everything below was located by reading the current sACN and Art-Net
plumbing; file references are to the current tree.

Output:
- `ConfigManager.InitializeOutputsCore` (`src/Shared/Services/ConfigManager.cs`
  744 to 853): add a `TryCreateNetworkOutput` call and a port constant
  (5683) next to the sACN/Art-Net ones; `OutputPortConflicts.cs` picks it
  up.
- `Output.OutputType` enum value `SIGNET` (uppercase string on the wire
  per house rule), `StreamPortOutput.GetMaxUniverseId` = 63,999.
- `StorageManager.UpdateOutputManagerCore` (2913 to 3005) passes
  `SendPriority` only for sACN; extend to Sig-Net.
- `WebsiteController.Outputs.cs` `/outputtypes` and `/porttypes`.
- `OutputDetails.vue` hard-codes per-type field visibility at lines 147,
  169 and 175 (destination, sendSync, sendPriority). Sig-Net gets sync and
  priority but **no destination field** (multicast folding is
  deterministic; unicast is discouraged by the spec).
- `OutputMonitor.vue` status row.

Input:
- `InputMappingDetails.vue` lines 35 to 37 hard-code SACN, ARTNET and
  DMXSERIAL; add SIGNET. `InputMapping.FindTargetOverlap` and
  `SaveInputMapping` need no change.
- `OutputConfig.InputPortType` (record protocol) gains SIGNET.

Host configuration and secrets (the part that is new for the Core):
- `HostConfig` gets a `SigNet` section: `Scope` (default `local`),
  `Passphrase` or the derived keys, `DeviceId` (the 32-bit TUID part),
  `DeviceLabel`, `SessionId`. Mark the secret fields `[NotLogged]` and add
  them to `HostConfigSnapshotAllowlist.Secrets`
  (`src/Shared/ConfigSnapshot/HostConfigSnapshotAllowlist.cs:78`).
- A "Sig-Net" section in `WebsiteController.Settings.cs` with the
  passphrase validator's **specific** error messages (the spec forbids a
  generic "weak passphrase" message) and no hex entry field (manual hex
  entry is prohibited). A touchscreen entry page is optional; the web UI
  counts as the device's local user interface for a wall controller, but
  note the plain-HTTP LAN exposure of the passphrase on entry.
- Spec 7.6 "Key Extraction Prohibition": backups and config exports must
  exclude the derived keys. `BackupManager` needs a strip step, and the
  help-agent snapshot is covered by the allowlist. Store derived keys, not
  the passphrase, since we are not a Manager; the spec says Nodes and
  Senders "shall immediately and permanently discard K0 and any source
  passphrase after successful derivation".
- Keys at rest: the spec wants hardware-protected storage, with a
  documented legacy-hardware exception (14.1.2) that fits the CM4/CM5
  SD-card reality. `host-config.json` already holds `JwtKey` and the MQTT
  password in plaintext, so Sig-Net keys would follow the same model.
  Encrypting them with a machine-bound key is a modest improvement worth
  doing at the same time, and it is the kind of thing a CRA risk
  assessment will ask about.
- Session id: increment and save `HostConfig.SigNet.SessionId` before the
  stream's first packet on every start. On the 0xFFFFFFFF edge the device
  must stop sending until re-onboarded; log it as a ConfigIssue.
- Offboarding (7.7): a "Forget Sig-Net keys" action in settings, and the
  spec requires a physical out-of-band way to reach the offboarded state;
  the touchscreen qualifies, the web UI arguably does.
- Product identity: `SoemCode`, model name, firmware version from the
  existing version stamp, `TID_RT_DEVICE_LABEL` from the host name. Demo
  mode (`--demo`) should use a dynamic TUID and the `dmxcore-demo` label.

Docs and release:
- docs.dmxcore.com page for Sig-Net (onboarding, scope, universe mapping,
  the attribution the license demands), release notes, and the
  "Sig-Net Designed by and Copyright Singularity (UK) Ltd" credit on both
  About pages. That credit is a license condition, as is reporting a
  correct SoemCode.

Size: the Core side is wide but shallow. The settings page, backup
exclusion and the two Vue type lists are the real work; the rest is
one-line additions in the places listed.

## Verification plan

1. Unit tests from Appendix G vectors (keys, HMAC digest for a given
   packet) in the library repo.
2. Howell's Wireshark dissector (`public-sig-net-wireshark`) on a capture
   from the dev unit, the same tshark recipe used for sACN timing checks.
3. NETworkshop (free, Windows) from Singularity acts as a Manager, Sender
   and Node for interop. Confirm a console-shaped Manager discovers the
   unit, that NETworkshop receives our universes, and that the unit
   records a NETworkshop-sent universe.
4. SNACtest, the automated conformance tester, is a paid annual
   subscription (£395 to £2,145 depending on license type; the Manufacturer
   license asks for the ESTA code at checkout). Budget for it before
   claiming conformance publicly. There is no certification body; the
   spec says conformance claims are the manufacturer's responsibility.
5. Throughput on the CM4 against the 800 universes at 40 Hz baseline.
   HMAC-SHA256 per packet is new CPU load: at 600 universes and 60 Hz that
   is 36,000 hashes per second of about 600 bytes. The BCM2711 (CM4) has
   no ARMv8 crypto extensions, so expect a measurable but not blocking
   cost on one core; the CM5 has them. Measure, do not assume.

## Risks and open questions

- **The wire is still moving.** V1.11 (September 2026) and V1.08 both
  carry "wire break" notes, and V1.14 landed on 2026-10-17. Howell's own
  SDK README still describes 100 folding groups where the spec now says
  109, and its version table disagrees with itself. Expect at least one
  more break before products are SNACtest-certified. Building the codec
  with the version in the URI and the TID catalogue generated from
  Appendix C limits the blast radius.
- **No shipping counterpart yet.** Partner logos are promises; LSC's
  Nexen gateway was shown as the first certified gateway at PLASA 2026.
  Until a console sends Sig-Net, the feature is a tick box and interop can
  only be proven against NETworkshop and the open-source SDKs.
- **Node role depth.** See the scope section. Declaring Node with
  read-only endpoints is legal but a Manager will show our input universes
  as "cannot patch". Decide whether that is acceptable or whether input
  mappings should become console-patchable.
- **Open Mode** must never be the default and may only be enabled by a
  local physical action or an authenticated out-of-band channel. Offer it
  from the touchscreen and the authenticated web session, not from the
  integration API.
- **Multicast on Balena.** 109 plus 3 groups per interface, IGMPv2
  minimum, and the kernel membership cap that `AcnStream` already works
  around. The start scripts in `deploy/Balena/*/scripts/start.sh` already
  touch `igmp_max_memberships`; verify the value covers Sig-Net.
- **Licensing.** Royalty-free and irrevocable, but with attribution,
  SoemCode and trademark-guideline conditions. The library can stay MIT;
  the conditions bind the product, so the README must state them.
- **ESTA id.** 0x0744 belongs to DMX Pro Sales, LLC. Use that in both the
  Sig-Net TUID and any future RDM UID (the spec wants them to be the same
  48-bit value for native RDM responders).

## Rough effort

| Piece | Estimate |
|-------|----------|
| Haukcode.SigNet library, with tests and NETworkshop interop | 2 to 3 weeks |
| MagnusEngine `SigNetStream` plus router source-key change | 1 week |
| Core wiring, settings, backup exclusion, Vue, docs | 1 week |
| Device verification on CM4 and CM5, throughput, Wireshark | 3 to 5 days |

Call it five to six weeks of focused work for Sender plus receive-only
Node, before SNACtest. RDM, timecode, Manager role and SNOW are each a
separate later milestone.

## Recommendation

Build it, but as a protocol library first and a Core feature second. The
library is the part with lasting value (it will be the only .NET Sig-Net
implementation and the user already maintains the sACN and Art-Net ones),
and it can track spec revisions without touching the Core. Wire the Core
once a second implementation exists to talk to, which today means
NETworkshop or a partner console at the next PlugFest.
