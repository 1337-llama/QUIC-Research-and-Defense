# 3. Threat Landscape: How Attackers Abuse QUIC

Attackers abuse QUIC in two broad ways:

- **As an opaque, under-inspected transport.** They run ordinary C2 over HTTP/3 because many networks can't see inside it. This is what real-world malware does today.
- **As a hiding place for data inside the protocol itself.** They put data in fields the protocol leaves to the sender's discretion, or in the timing and behavior of the connection. This is well documented in academic research and proofs of concept. As of November 2026 there was no public reporting of it in in-the-wild malware.

## 3.1 Real-world QUIC C2 (as of November 2026)

| Threat | Stack | Reported | How it uses QUIC | Published detection hooks |
|---|---|---|---|---|
| **Merlin** (open-source C2 framework) | Go, [quic-go](https://github.com/quic-go/quic-go) | QUIC support since July 2018 | HTTP/3 (earlier gQUIC) as a C2 transport, with message padding and jitter | Salesforce CYU fingerprints (gQUIC era). Active Countermeasures: one connection held for nearly 24 hours, ~15-second client cadence, abbreviated Zeek `history` strings, client idle timeout of 30,000 ms |
| **Salat Stealer** (RAT / infostealer) | Go, quic-go + gorilla/websocket | 2025-2026 (Dark Atlas) | Probes several transports, prefers WebSocket and HTTP/3, falls back to HTTP/2. Blockchain-hosted fallback infrastructure | Go TLS/QUIC fingerprints, transport-fallback behavior |
| **QUICAgent**, "Operation QUICSILVER" (China-nexus actor targeting Myanmar diplomats) | Go | Reported Aug 2026 (Seqrite) | Resolves its C2 host through a Cloudflare Workers endpoint, then beacons with HTTP/3 POST requests carrying RC4-encrypted JSON over UDP/443 | A Workers lookup followed by QUIC to a non-CDN IP |
| **PerfectPioneer RAT → KUKURAT** (TGR-STA-0049, Southeast Asian governments) | KUKURAT: modular C++ | Active since Jul 2025, KUKURAT since Mar 2026. Reported Nov 2026 (Unit 42) | HTTP/3 over UDP/443 as primary C2, falling back to HTTP/2 if QUIC fails | See the Unit 42 report |

**Patterns across these cases:**

- **Go and quic-go dominate.** Detection content built around Go QUIC client fingerprints and behaviors maps directly to the threats seen so far.
- **The QUIC traffic is ordinary HTTP/3.** The evasion comes from where it's carried (UDP, which is often uninspected), not from protocol tricks.
- **Fallback is standard.** Implants try QUIC first and drop to HTTP/2 or WebSocket over TCP when it's blocked. Blocking QUIC doesn't stop them. It pushes them onto channels you're better at inspecting.

## 3.2 Why QUIC appeals to attackers

1. **Inspection gaps.** Many security stacks can't decrypt QUIC, and some don't log UDP flows in detail.
2. **Blending in.** A large share of legitimate web traffic is QUIC to big CDNs and SaaS providers, so a beacon on UDP/443 doesn't stand out by port.
3. **Less metadata.** Encrypted transport headers, no passive server certificate, and (with ECH) no SNI.
4. **Connection migration.** Connections can move between addresses, which confuses 4-tuple-based tracking.
5. **Long-lived, multiplexed sessions.** One QUIC connection can carry many streams for hours, a natural fit for interactive C2.

## 3.3 Categories of in-protocol abuse (research)

Academic work has catalogued many ways to hide data within QUIC itself. The most thorough is the 2026 *Journal of Universal Computer Science* paper "Steganography in the QUIC Communication Protocol," which identifies 20 previously undescribed hiding techniques. This section groups them at a high level so defenders know where to look. It deliberately doesn't describe how to build them.

| Category | Where the data lives | Can a passive observer see the carrier? | What helps defenders |
|---|---|---|---|
| **Cleartext header fields** | Fields the sender chooses freely that travel unencrypted: connection IDs, tokens, version-related fields, header bits | ✅ Yes | Statistical baselines (entropy, length, structure) vs. known client stacks. Normalizing gateways |
| **Handshake contents** | Sender-chosen parts of the decryptable client Initial: ClientHello fields, transport parameters, padding | ✅ Yes, after decrypting the Initial | Fingerprinting (JA4), checking padding and parameters against what real clients send |
| **Encrypted frame fields** | Values inside post-handshake frames, such as flow-control limits, stream identifiers, path-validation data and error codes | ❌ No, only at endpoints or a terminating proxy | Endpoint instrumentation or HTTP/3-aware proxies. The research found these very hard to tell apart from normal traffic |
| **Timing and rate** | When packets, ACKs or keep-alives are sent | ✅ Yes (metadata) | Inter-arrival-time analysis, traffic normalization (re-timing) |
| **Connection-behavior abuse** | Misusing migration or path validation, e.g. disguising exfiltration as a migrated connection to a new address | ✅ Partly | Disabling migration where possible, flagging handshake-less flows to new destinations |
| **Tunneling** | Carrying another protocol inside HTTP/3 or DATAGRAM frames, including MASQUE-style proxying | Only metadata | Destination reputation, volume and duration profiling, proxy termination |

**Notable published work:**

- **QUIC-Exfil** (2025) disguises exfiltration as QUIC connection migration, mimicking real flows' connection IDs, sizes and timing. The authors' best ML detector reached an F1 score of only about 0.2-0.5 on the malicious class. None of the five firewall vendors they surveyed could reliably identify migrations.
- **Latency spin-bit channel** (Sudhan & Kulkarni, COMSNETS 2024) is a low-rate channel in the cleartext spin bit.
- **QuicCourier** and **QuicCC-SMD** (2025) shape real browsing or video-streaming traffic to carry hidden data within normal-looking traffic patterns.
- **TS-Morph** (2025) uses a generative time-series model to make covert timing look like benign traffic.

**The lesson for defenders:** published detection results get worse the more an attacker encrypts and mimics. Hidden data that looks like random bytes in a field that is supposed to be random can't be told apart by entropy alone. Detection has to lean on **context**, meaning which process, which destination, whether QUIC is allowed at all, and how long the connection lasts, rather than on statistical tests of individual fields.

---

**Previous:** [2. Network visibility](02-network-visibility.md) · **Next:** [4. Detection guide](04-detection-guide.md)
