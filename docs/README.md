# QUIC Research for Defenders

This documentation explains how the QUIC protocol works, how attackers abuse it for command and control (C2) and data hiding, and what defenders can do about it. It also documents the repository's detection lab, which lets you measure your detections against labeled QUIC C2-like traffic.

## Research

1. [How QUIC works](01-quic-protocol-overview.md): packets, headers, the handshake, encryption, connection IDs, streams, migration, HTTP/3
2. [What the network can see](02-network-visibility.md): exactly what a passive sensor has to work with, and why QUIC is hard to inspect
3. [Threat landscape](03-threat-landscape.md): real-world QUIC C2 (Merlin, Salat Stealer, QUICAgent, KUKURAT) and research on hiding data inside QUIC
4. [Detection guide](04-detection-guide.md): tools, ranked detections, starter content and how to test it
5. [Mitigations and policy](05-mitigations-and-policy.md): blocking, browser policies, proxies, migration controls and known blind spots

## Lab

6. [The beacon simulator](06-beacon-simulator.md): labeled QUIC C2-like traffic with no capability, on the same Go stack real threats use
7. [The detection lab](07-detection-lab.md): capture, Zeek, Suricata and precision/recall scoring in Docker
8. [Emulating Merlin in a lab](08-merlin-lab-guide.md): validating detections against a real public framework, safely
9. [Architecture and testing](09-architecture-and-testing.md): module design and test strategy
10. [Analyst exercises and results dashboard](10-analyst-exercises.md): hunting with the answers held back, grading, and nightly precision/recall over time

[References](references.md)

## Key takeaways

- **Only the first packet is readable.** QUIC's Initial packets can be decrypted by anyone on the path, which exposes the ClientHello (SNI, ALPN, JA4). Everything after that, including the server certificate, is encrypted.
- **Real-world QUIC C2 is ordinary HTTP/3 over UDP.** It's mostly written in Go with the quic-go library, and it falls back to TCP when QUIC is blocked.
- **Many QUIC fields are chosen by the sender.** Research has shown they can carry hidden data, and once that data is encrypted it's very hard to spot statistically.
- **Context beats packet statistics.** The strongest detections ask which process is using QUIC, where it's going, whether QUIC should be allowed at all, and how long the connection lasts.
- **Measure detections against ground truth.** The lab turns "it fired once" into a precision and recall table you can gate in CI.

*Research current as of November 2026.*
