# Haukcode.SigNet

A cross-platform .NET library for Sig-Net, the secure CoAP-based protocol for DMX512 lighting
control over IP: the Sender role and the receive side of the Node role.

## What is Sig-Net?

Sig-Net carries DMX512 universes as CoAP NON POST messages over UDP 5683. Every packet is
authenticated with HMAC-SHA256 using keys derived from a 256-bit root key, and protected
against replay by a per-device session id and per-stream sequence numbers. Universes are
folded onto 109 multicast groups (239.254.0.1 to 239.254.0.109).

## Features

- Passphrase validation, PBKDF2 root key and HKDF role keys, verified against the spec's
  Appendix G test vectors
- Levels with universe or per-slot priority, sync, universe announcements
- Discovery: on-boot notification, poll replies, security event reports
- Verified receive with anti-replay, sync hold-and-release, stream loss events
- Sharded sending and kernel receive timestamps through Haukcode.HighPerfComm
- .NET 8.0, 9.0 and 10.0

## Quick Start

```csharp
using Haukcode.SigNet;
using Haukcode.SigNet.Keys;
using System.Net;

var tuid = Tuid.CreateDynamic(manufacturerId: 0x7FF0);
var deviceInfo = new SigNetDeviceInfo(SoemCode.Create(0x7FF0, 0x0001), "My Product", "Stage left");

using var keys = SigNetKeys.FromPassphrase(passphrase, tuid);

// sessionIdStore: your ISessionIdStore; the session id must be persisted (spec 8.3)
using var client = new SigNetClient(keys, tuid, deviceInfo, sessionIdStore, IPAddress.Parse("192.168.1.10"),
    channelWriter: packet =>
    {
        Console.WriteLine($"u{packet.Universe} from {packet.SenderId}");

        return Task.CompletedTask;
    });

client.JoinUniverse(1);
await client.SendLevels(1, new byte[512], priority: 100);
await client.SendSync();
```

Received packets are reused once the writer returns; keep `packet.Clone()` if you queue them.

## Key Methods

- `SendLevels()` / `SendSync()`: transmit; the first frame for a universe announces it
- `StopUniverse()` / `StopAllUniverses()`: announce TID_UNIVERSE Leave
- `JoinUniverse()` / `DropUniverse()`: receive a universe as input
- `JoinUniverseForTrigger()` / `DropUniverseForTrigger()`: receive a universe for triggers
- `OnUniverseLost`, `OnSecurityEvent`, `GetVerifyCounts()`: monitoring
- `SigNetEndpointInfo.Output()` / `Input()` in `SigNetDeviceInfo.Endpoints`: declare the
  universes you send and receive; `Endpoints` shows how they are numbered 1..N
- `LevelFoldback`: supplies each endpoint's merged levels for TID_DG_LEVEL_FOLDBACK
- `LevelRefreshPolicy`: the spec 10.6.3 repeat and 1 Hz keep-alive rules
- `SigNetBeacon`: Beacon Mode for a device that is not onboarded yet

## License conditions

Sig-Net is owned by Singularity (UK) Ltd and licensed royalty-free. Products built with this
library must include the attribution "Sig-Net® Designed by and Copyright Singularity (UK) Ltd.",
report a correct SoemCode (your ESTA manufacturer id in the upper 16 bits), and follow the
trademark guidelines at https://sig-net.net/. This library is MIT licensed and not affiliated
with or endorsed by Singularity (UK) Ltd.

## Documentation

- [GitHub repository](https://github.com/HakanL/Haukcode.SigNet), with implementation notes
  and open spec questions
- [Sig-Net specification](https://singularity-uk.com/Downloads-for-customers/Sig-Net%20Protocol%20Framework.pdf)
