# Haukcode.SigNet [![NuGet Version](http://img.shields.io/nuget/v/Haukcode.SigNet.svg?style=flat)](https://www.nuget.org/packages/Haukcode.SigNet/)

A cross-platform .NET library for the Sig-Net lighting control protocol.

**Status: 0.1, early.** Implements the Sender role and the receive side of
the Node role against Sig-Net V1.16, verified against the spec's Appendix G
test vectors and against NETworkshop. Decisions and open spec questions are
in [docs/implementation-notes.md](docs/implementation-notes.md), the original
plan in [docs/sig-net-plan.md](docs/sig-net-plan.md). This repo is the sibling
of [Haukcode.sACN](https://github.com/HakanL/Haukcode.sACN),
[Haukcode.ArtNet](https://github.com/HakanL/Haukcode.ArtNet) and
[Haukcode.KiNet](https://github.com/HakanL/Haukcode.KiNet) with the same
layout, build and NuGet publishing.

## What is Sig-Net?

Sig-Net is a secure, multicast-based protocol for DMX512 lighting control
over IP, designed by Wayne Howell (the author of Art-Net) at Singularity (UK)
Ltd as a response to the EU Cyber Resilience Act. Every packet is a CoAP
(RFC 7252) NON POST over UDP port 5683, authenticated with HMAC-SHA256 and
protected against replay by a per-device session id and per-stream sequence
number. Keys are derived with HKDF from a 256-bit root key that is onboarded
once per device. Payloads are not encrypted by design.

Universes map to multicast groups 239.254.0.1 to 239.254.0.109 (IPv6
FF18::7369:1 to FF18::7369:6D) by "Multicast Folding" so that large rigs do
not exhaust switch IGMP or MLD tables.
The protocol also carries per-slot priority (ETC 0xDD style merging),
sync, timecode, RDM and firmware upload.

- Protocol site and documents: https://sig-net.net/
- Specification (V1.16, 2026-10-23, at the time of writing):
  https://singularity-uk.com/Downloads-for-customers/Sig-Net%20Protocol%20Framework.pdf
- Reference SDK (C++): https://github.com/WayneHowell/public-sig-net-sdk
- Wireshark dissector: https://github.com/WayneHowell/public-sig-net-wireshark

## Scope

Implemented:

1. Key material: the passphrase rules (ported from the SDK's reference
   routine), PBKDF2 K0, HKDF role keys, `.equalkeys` and `.guestkeys` files.
2. CoAP and TLV codecs, the full V1.16 TID catalogue, URI routing and the
   Appendix A multicast and key mapping.
3. HMAC-SHA256 signing and verification, and RAM-only anti-replay with
   first-packet bootstrapping and the 32-entry LRU rule.
4. Sender role: levels with universe or per-slot priority, sync,
   TID_UNIVERSE announcements, on-boot notification, poll replies,
   security events.
5. Node role, receive only: verified levels with the universe priority
   (Constrained Node Fallback), sync hold-and-release, stream loss events,
   one 1..N table of input and output data endpoints with a lane per output
   universe, read-only replies about them, TID_DG_SOURCE, TID_DG_LEVEL_FOLDBACK
   (levels supplied by the host through `LevelFoldback`), Lost Mode.
6. Beacon Mode: `SigNetBeacon` announces a device that has no keys yet, so
   Managers can list it for onboarding.

Not yet: RDM, timecode, OSC, the Manager role, Open Mode, SNOW, SET
commands, IPv6 transport (the IPv6 multicast mapping and TLV forms are
there, the sockets are IPv4).

Built on [Haukcode.HighPerfComm](https://github.com/HakanL/Haukcode.HighPerfComm)
for sharded sending and kernel receive timestamps, like the sibling libraries.

## Usage

```csharp
using Haukcode.SigNet;
using Haukcode.SigNet.Keys;
using System.Net;

// Identity comes from the product: your ESTA manufacturer id, a static device
// id for hardware or a persisted dynamic one for software
var tuid = Tuid.CreateDynamic(manufacturerId: 0x7FF0);
// Data endpoints are numbered 1..N by the client: outputs by universe, then inputs by universe
var deviceInfo = new SigNetDeviceInfo(SoemCode.Create(0x7FF0, 0x0001), "My Product", "Stage left")
{
    Roles = SigNetRoles.Sender | SigNetRoles.Node,
    Endpoints =
    [
        SigNetEndpointInfo.Output(universe: 1, label: "Output 1"),
        SigNetEndpointInfo.Input(universe: 1, label: "Input 1")
    ]
};

// Derive once at onboarding, store the derived keys securely, discard the passphrase
using var keys = SigNetKeys.FromPassphrase(passphrase, tuid);

// ISessionIdStore is yours: the session id must survive reboots (spec 8.3)
using var client = new SigNetClient(keys, tuid, deviceInfo, sessionIdStore, IPAddress.Parse("192.168.1.10"),
    channelWriter: packet =>
    {
        // Reused after return: process here or keep packet.Clone()
        if (packet.Kind == ReceiveDataKind.Levels)
            Console.WriteLine($"u{packet.Universe} from {packet.SenderId}, priority {packet.Priority}");

        return Task.CompletedTask;
    });

client.JoinUniverse(1);

// TID_DG_LEVEL_FOLDBACK, mandated for a Node with data endpoints: copy the endpoint's merged
// output (up to 512 slots) and return the slot count, or 0 if it has none yet
client.LevelFoldback = (endpoint, universe, levels) => myOutput.CopyMergedLevels(universe, levels);

// Send at up to 44 Hz; LevelRefreshPolicy handles the repeat and keep-alive rules
await client.SendLevels(1, dmxData, priority: 100);
await client.SendSync();
```

The [example](example/Program.cs) sends a moving pattern and prints what it
receives, its own universe included:

```
ConsoleExample --passphrase "<passphrase>" [--scope local] [--interface <ip>] [--universe 1] [--sync]
```

## Sig-Net license conditions

Sig-Net is a proprietary protocol owned by Singularity (UK) Ltd and licensed
royalty-free for implementation. Products built with this library must
comply with the conditions in the specification, which at V1.16 are:

- Attribution in the product's manual, About screen or technical
  documentation: "Sig-Net® Designed by and Copyright Singularity (UK) Ltd."
- A unique SoemCode per product (ESTA manufacturer id in the upper 16 bits),
  reported correctly during discovery.
- Sig-Net® and Multicast Folding™ are trademarks of Singularity (UK) Ltd;
  marketing use follows the branding guidelines at https://sig-net.net/.

This library itself is MIT licensed (see [LICENSE](LICENSE)). The library
is not affiliated with or endorsed by Singularity (UK) Ltd.

## Used in production

This library is used in [DMX Core 100](https://dmxcore.com), a DMX lighting controller for permanent installations that runs on Windows, macOS and Linux, or on its own touchscreen hardware. There it sends, receives, records and routes Sig-Net, and onboards each unit from the network passphrase. Sig-Net support is an experimental feature in DMX Core 100 for now.

## License

MIT. Copyright (c) 2026 Hakan Lindestaf.
