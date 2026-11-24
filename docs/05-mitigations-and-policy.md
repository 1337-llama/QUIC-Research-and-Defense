# 5. Mitigations and Policy

Detection is only half the job. These controls reduce the room attackers have to hide in QUIC in the first place, roughly from cheapest to most involved.

## 5.1 Decide whether QUIC is allowed

Most security vendors (including Palo Alto Networks, Fortinet, Cisco, Zscaler and Netskope) recommend **blocking QUIC** unless your stack can inspect it. Browsers then fall back to HTTP/2 over TCP, where TLS inspection, URL filtering and DLP work.

- Block **UDP/443 and UDP/80** outbound, and use a **reject** action rather than a silent drop so browsers fall back quickly.
- Port blocks aren't enough. QUIC runs on any UDP port. Prefer **default-deny egress UDP**, with explicit allows for DNS to your resolvers, NTP, your VPN and approved conferencing services, plus application-aware QUIC identification on all ports where your firewall supports it.

## 5.2 Turn QUIC off in managed browsers

Removing legitimate QUIC from your baseline makes any remaining QUIC stand out.

| Browser | Setting |
|---|---|
| Google Chrome | Policy `QuicAllowed` = `0` (Windows: `HKLM\SOFTWARE\Policies\Google\Chrome`) |
| Microsoft Edge | Policy `QuicAllowed` = `0` (Windows: `HKLM\SOFTWARE\Policies\Microsoft\Edge`) |
| Mozilla Firefox | `network.http.http3.enable` = `false` (deploy through enterprise policies). Some vendor guides spell it `network.http.http3.enabled`, so check which name your Firefox version uses |
| Safari | No enterprise policy switch. Cloudflare documents a per-device toggle under Develop > Experimental Features, and Bitdefender reports it can't be disabled. Rely on network controls |

## 5.3 If you must allow QUIC

- **Allowlist destinations.** Permit QUIC only to the CDN and SaaS networks your users need, by ASN or published IP ranges.
- **Use an HTTP/3-aware, TLS-terminating proxy** for everything else. A proxy that terminates QUIC and re-originates its own connections strips every transport-level hiding place: connection IDs, tokens, header bits, transport parameters, timing quirks. Only the HTTP content gets through, and your existing HTTP and DLP controls can inspect it. Check your vendor's support carefully, since browser HTTP/3 inspection still has gaps in some products.
- **Normalize** at gateways that support it: drop unsupported versions, discard malformed or padded-out Initial data, and re-time traffic where performance allows.

## 5.4 Reduce migration-based cover

- On services you run, set `disable_active_migration` and don't advertise a preferred address unless you need them. Then any migration toward your infrastructure is anomalous.
- Treat handshake-less QUIC flows to new external destinations as suspicious, especially when the destination isn't in a major cloud or CDN range.

## 5.5 Plan for fallback

Current implants (KUKURAT, Salat Stealer and others) **fall back to HTTP/2 or WebSocket over TCP** when QUIC is blocked. Blocking QUIC doesn't stop them. It moves them onto channels you can inspect, so make sure those controls are ready:

- TLS inspection on TCP/443, with JA4/JA4S/JA4X fingerprinting.
- Beacon analytics on HTTPS flows.
- Alerts for the same non-browser processes making TCP/443 connections to the same unusual destinations.

## 5.6 Endpoint controls

- Alert on, or block, non-approved processes that open UDP sockets to the internet.
- Application allowlisting, so unknown Go, Rust or C++ binaries don't run in the first place.
- Correlate process, destination and protocol in your EDR. This is the combination attackers find hardest to disguise.

## 5.7 Know your blind spots

State these openly in your detection program:

- **ECH** hides SNI in the ClientHello.
- **Server certificates** are never passively visible over QUIC.
- **Post-handshake transport fields** can't be inspected without terminating the connection.
- **Mimicry** (traffic shaped to match benign patterns) defeats statistical detectors. Published results show low detection rates.
- **Encrypted data in fields meant to be random** can't be told apart by entropy tests.

The answer to all of these is the same. Control *whether* QUIC is used and *by whom*, rather than trying to read every field.

---

**Previous:** [4. Detection guide](04-detection-guide.md) · **Next:** [References](references.md)
