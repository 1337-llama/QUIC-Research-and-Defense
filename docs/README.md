# QUIC Research for Defenders

This documentation explains how the QUIC protocol works, how attackers abuse it for command and control (C2) and data hiding, and what defenders can do about it.

## Contents

1. [How QUIC works](01-quic-protocol-overview.md): packets, headers, the handshake, encryption, connection IDs, streams, migration, HTTP/3
2. [What the network can see](02-network-visibility.md): exactly what a passive sensor has to work with, and why QUIC is hard to inspect
3. [Threat landscape](03-threat-landscape.md): real-world QUIC C2 (Merlin, Salat Stealer, QUICAgent, KUKURAT) and research on hiding data inside QUIC
4. [Detection guide](04-detection-guide.md): tools, ranked detections, starter Zeek and Suricata content, and how to test them
5. [Mitigations and policy](05-mitigations-and-policy.md): blocking, browser policies, proxies, migration controls and known blind spots
6. [References](references.md)

## Key takeaways

- **Only the first packet is readable.** QUIC's Initial packets can be decrypted by anyone on the path, which exposes the ClientHello (SNI, ALPN, JA4). Everything after that, including the server certificate, is encrypted.
- **Real-world QUIC C2 is ordinary HTTP/3 over UDP.** It's mostly written in Go with the quic-go library, and it falls back to TCP when QUIC is blocked.
- **Many QUIC fields are chosen by the sender.** Research has shown they can carry hidden data, and once that data is encrypted it's very hard to spot statistically.
- **Context beats packet statistics.** The strongest detections ask which process is using QUIC, where it's going, whether QUIC should be allowed at all, and how long the connection lasts.

*Research current as of November 2026.*
