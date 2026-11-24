# 1. How QUIC Works

QUIC is an encrypted, multiplexed transport protocol that runs over UDP, almost always on UDP/443. It combines the jobs of TCP (reliable, ordered delivery and congestion control) and TLS 1.3 (encryption and authentication) into one protocol. Unlike TCP+TLS, it also encrypts most of its own **transport control information**, not just the application payload. HTTP/3 is HTTP mapped onto QUIC.

For defenders, that last point matters most. With TCP+TLS you can see sequence numbers, window sizes, flags and the server's certificate. With QUIC, almost all of that is hidden after the first packet.

## 1.1 The specification set

| RFC | What it defines | Why defenders care |
|---|---|---|
| [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) | Version-independent "invariants": the only fields guaranteed stable across QUIC versions | Parsers that assume v1 layouts break on other versions |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC v1 transport: packets, frames, streams, flow control, connection IDs, migration | The core wire format |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS 1.3 to secure QUIC; packet and header protection | Explains why the first packet is readable by anyone and nothing after it is |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | Loss detection and congestion control | Explains normal ACK and retransmission timing |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | The application layer most QUIC traffic carries |
| [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) | Unreliable DATAGRAM frames | Used for media and for tunnels/VPNs |
| [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287) | Greasing the QUIC bit | Makes one header bit variable so middleboxes can't depend on it |
| [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) / [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) | MASQUE: proxying UDP and IP over HTTP | Standardized tunneling that looks like ordinary HTTP/3 |
| [RFC 9312](https://www.rfc-editor.org/rfc/rfc9312) | Manageability of QUIC | The IETF's own guide to what network operators can observe |
| [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368) / [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) | Compatible version negotiation; QUIC version 2 | v2 changes version number, packet-type bits and key-derivation salt |
| [draft-ietf-quic-load-balancers](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/) | QUIC-LB: routable connection IDs | A legitimate reason connection IDs contain encoded routing data |

## 1.2 Packets, datagrams and frames

- A **UDP datagram** carries one or more **QUIC packets**. Packets from different handshake stages can be coalesced into one datagram.
- Each packet carries one or more **frames**: STREAM (application data), ACK, CRYPTO (TLS handshake bytes), flow-control updates, and so on.
- A client's first datagram must be **at least 1,200 bytes**, padded if necessary. Servers discard smaller first datagrams. This limits reflection and amplification attacks, and so does a rule that a server may send no more than 3x what it received before the client's address is validated.

## 1.3 Two header formats

**Long headers** are used during connection setup. They carry, in cleartext:

- A header-form bit (long) and a "fixed bit" (normally 1)
- The packet type: Initial, 0-RTT, Handshake or Retry
- The 32-bit **version**
- The **destination and source connection IDs** (each 0-20 bytes in v1), with explicit lengths
- For Initial packets, a **token** field (usually empty)

The low bits of the first byte (reserved bits and packet-number length) and the **packet number** are hidden by header protection (see §1.5).

Two special long-header packets exist:

- **Version Negotiation** is sent by a server that doesn't support the client's version. It lists the versions the server supports and has no cryptographic protection at all.
- **Retry** is sent by a server that wants the client to prove its address. It carries an opaque **token** that the client must echo in its next Initial packet.

**Short headers** are used for all data after the handshake. They carry in cleartext only:

- The header-form bit (short) and the fixed bit
- The **latency spin bit** (§1.10)
- The **destination connection ID**, *without* a length field. The receiver already knows the length, but a middlebox only knows it if it saw the handshake.

Everything else, including the packet number, key-phase bit and all frames, is protected.

## 1.4 The handshake

```
Client                                              Server
  | Initial: ClientHello (SNI, ALPN, transport params)  |
  |  + padding to >= 1200 bytes ----------------------> |
  |                                                     |
  | <------------- (optional) Retry with token          |
  |                                                     |
  | <-------------------- Initial: ServerHello          |
  | <----- Handshake: EncryptedExtensions (server       |
  |        transport params), Certificate, Finished     |
  |                                                     |
  | Handshake: client Finished ----------------------> |
  | 1-RTT (short header) application data <==========> |
  | <---------------------------- HANDSHAKE_DONE        |
```

- Normally the handshake completes in **one round trip**. Returning clients can send **0-RTT** data in their first flight using a resumption ticket.
- The client's **transport parameters** (flow-control limits, idle timeout and more) travel inside the ClientHello. The server's travel in EncryptedExtensions.
- The server can give the client a **NEW_TOKEN** for faster future connections. The client presents it in the Token field of a later Initial packet.

## 1.5 Encryption and header protection

QUIC uses three sets of keys:

| Packet type | Keys derived from | Who can decrypt |
|---|---|---|
| **Initial** | A public, version-specific salt plus the client's destination connection ID, which is in cleartext in the same packet | **Anyone on the path.** RFC 9001 treats Initial packets as having no real confidentiality |
| **Handshake** | TLS 1.3 handshake secrets | Only the endpoints |
| **1-RTT** | TLS 1.3 application secrets | Only the endpoints |

Two consequences:

1. **The ClientHello is readable.** Network tools can extract SNI, ALPN, cipher suites, TLS extensions and the client's transport parameters from the first packet. This is what makes JA4 fingerprinting and Zeek/Suricata QUIC logging possible.
2. **The server certificate is not readable.** It's sent in Handshake packets. Certificate-based detections that work for TLS over TCP don't work passively for QUIC.

**Header protection** applies a mask to the packet number and the low bits of the first byte, using a sample of the encrypted payload. The header-form bit, fixed bit, spin bit, version and connection IDs are left in cleartext.

## 1.6 Connection IDs

Connection IDs (CIDs), not the IP/port 4-tuple, identify a QUIC connection.

- **Each endpoint chooses the CIDs its peer uses to address it.** The client picks the CIDs the server puts on server-to-client packets, and vice versa.
- The client's first destination CID must be **random and at least 8 bytes**.
- The RFC says CIDs must not contain information an outside observer could use to link them together. In practice, well-behaved CIDs look random.
- Endpoints issue additional CIDs with NEW_CONNECTION_ID frames (each paired with a 16-byte stateless reset token) and retire old ones. Rotating CIDs, for example when changing networks, prevents observers from linking a user's activity across paths.
- **Legitimate structured CIDs exist.** Large providers use QUIC-LB or similar schemes to encode server-routing information in CIDs, usually encrypted or obfuscated so they still look random.

## 1.7 Streams and flow control

- A connection carries many independent **streams**. Stream IDs are 62-bit numbers. The low two bits say who opened the stream and whether it's bidirectional.
- **Flow control** limits how much a peer may send, per stream and per connection, with MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS frames. Limits only ever increase.
- Because streams are independent, losing one packet doesn't stall the others. This fixes TCP's head-of-line blocking problem.

## 1.8 Variable-length integers and greasing

- Most integers on the wire use a **variable-length encoding** (1, 2, 4 or 8 bytes, up to 2^62-1). Except for frame types, values don't have to use the shortest encoding.
- QUIC and HTTP/3 deliberately reserve "**grease**" values: transport parameter IDs, versions, HTTP/3 frame types and settings that carry no meaning. Implementations send them at random so that peers and middleboxes learn to ignore unknown values. This keeps the protocol extensible, but it also means unknown values in traffic are expected, not suspicious in themselves.

## 1.9 Connection migration

- Because CIDs identify a connection, a client can change IP address or port (Wi-Fi to cellular, NAT rebinding) without reconnecting.
- A new path is checked with **PATH_CHALLENGE / PATH_RESPONSE** frames. Each carries 8 random bytes that the peer echoes back.
- A server can advertise a **preferred address** (encrypted) to move clients to a different server address after the handshake. The `disable_active_migration` transport parameter tells clients not to migrate.
- **To a middlebox, a migrated connection looks like short-header packets on a new 4-tuple with no handshake in front of them.** Many tools can't tie this traffic to the original connection.

## 1.10 The latency spin bit

The spin bit is an optional cleartext bit that lets passive observers measure round-trip time. When it's in use, the client inverts the value it last received and the server reflects it. The result is a square wave whose period equals the RTT.

Endpoints must disable it on at least 1 in 16 connections or paths, and when it's disabled they may set it to any value, randomly if they choose. Real-world use is mixed, so you can't read much into a spin bit on its own.

## 1.11 QUIC version 2

[RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) defines QUIC v2. It is functionally identical to v1, but it uses version number `0x6b3343cf`, different long-header type bits and a different Initial salt. These changes exist to stop middleboxes from hard-coding v1 details. **A parser that only understands v1 will fail to decode v2 traffic.**

## 1.12 HTTP/3 and MASQUE

- **HTTP/3** runs HTTP requests on QUIC streams and adds its own control stream, SETTINGS, and the QPACK header-compression streams. It also reserves grease frame types and settings.
- **MASQUE** uses HTTP/3 Extended CONNECT to tunnel UDP (CONNECT-UDP) or IP (CONNECT-IP) through an HTTP server. Apple iCloud Private Relay and Cloudflare WARP use it. On the network, a MASQUE tunnel is indistinguishable from other HTTP/3 to the same server.

---

**Next:** [2. What the network can see](02-network-visibility.md)
