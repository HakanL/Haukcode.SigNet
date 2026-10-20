# Haukcode.SigNet

A cross-platform .NET library for the Sig-Net lighting control protocol.

**Status: planning.** No code yet. The assessment and implementation plan is
in [docs/sig-net-plan.md](docs/sig-net-plan.md). This repo is the sibling of
[Haukcode.sACN](https://github.com/HakanL/Haukcode.sACN),
[Haukcode.ArtNet](https://github.com/HakanL/Haukcode.ArtNet) and
[Haukcode.KiNet](https://github.com/HakanL/Haukcode.KiNet) and will follow
the same layout, build and NuGet publishing.

## What is Sig-Net?

Sig-Net is a secure, multicast-based protocol for DMX512 lighting control
over IP, designed by Wayne Howell (the author of Art-Net) at Singularity (UK)
Ltd as a response to the EU Cyber Resilience Act. Every packet is a CoAP
(RFC 7252) NON POST over UDP port 5683, authenticated with HMAC-SHA256 and
protected against replay by a per-device session id and per-stream sequence
number. Keys are derived with HKDF from a 256-bit root key that is onboarded
once per device. Payloads are not encrypted by design.

Universes map to multicast groups 239.254.0.1 to 239.254.0.109 by
"Multicast Folding" so that large rigs do not exhaust switch IGMP tables.
The protocol also carries per-slot priority (ETC 0xDD style merging),
sync, timecode, RDM and firmware upload.

- Protocol site and documents: https://sig-net.net/
- Specification (V1.14 at the time of writing):
  https://singularity-uk.com/Downloads-for-customers/Sig-Net%20Protocol%20Framework.pdf
- Reference SDK (C++): https://github.com/WayneHowell/public-sig-net-sdk
- Wireshark dissector: https://github.com/WayneHowell/public-sig-net-wireshark

## Planned scope

1. Sender role: stream levels, priority and sync, answer discovery polls.
2. Node role (receive): consume universes with priority merge and sync.
3. Later: RDM, timecode, Manager role, SNOW over-the-wire onboarding.

Built on [Haukcode.HighPerfComm](https://github.com/HakanL/Haukcode.HighPerfComm)
for sharded sending and kernel receive timestamps, like the sibling libraries.

## Sig-Net license conditions

Sig-Net is a proprietary protocol owned by Singularity (UK) Ltd and licensed
royalty-free for implementation. Products built with this library must
comply with the conditions in the specification, which at V1.14 are:

- Attribution in the product's manual, About screen or technical
  documentation: "Sig-Net® Designed by and Copyright Singularity (UK) Ltd."
- A unique SoemCode per product (ESTA manufacturer id in the upper 16 bits),
  reported correctly during discovery.
- Sig-Net® and Multicast Folding™ are trademarks of Singularity (UK) Ltd;
  marketing use follows the branding guidelines at https://sig-net.net/.

This library itself is MIT licensed (see [LICENSE](LICENSE)). The library
is not affiliated with or endorsed by Singularity (UK) Ltd.

## License

MIT. Copyright (c) 2026 Hakan Lindestaf.
