# 2. What the Network Can and Cannot See

QUIC was designed to minimize what on-path devices can observe, partly to protect user privacy and partly to stop middleboxes from ossifying the protocol. This chapter maps exactly what a passive observer (an IDS, NDR sensor, firewall or packet capture) has to work with.

## 2.1 Visibility matrix

| Item | Passively visible? | Notes |
|---|---|---|
| UDP 4-tuple, datagram sizes, timing, direction, byte counts | ✅ | Always available |
| Header form, fixed bit, long-header packet type | ✅ | Type bits differ between v1 and v2 |
| Version (long headers) | ✅ | Includes Version Negotiation packets, which are fully unprotected |
| Connection IDs in long headers | ✅ | Integrity-protected but readable |
| Destination CID in short headers | ✅ (with context) | Length isn't encoded; you need the handshake to parse it |
| Retry packets and their tokens; Token field in Initial packets | ✅ | Tokens are opaque bytes |
| Latency spin bit | ✅ | Cleartext by design |
| Client Initial contents: ClientHello (SNI, ALPN, ciphers, extensions, client transport parameters) and padding | ✅ (after decrypting with public keys) | The basis of JA4 `q` fingerprints. SNI disappears if Encrypted Client Hello (ECH) is used |
| Packet numbers and reserved bits | ⚠️ Initial packets only | Header-protected otherwise |
| Server certificate, server transport parameters | ❌ | Sent in encrypted Handshake packets |
| All post-handshake frames: application data, flow control, connection ID updates, path validation, close reasons, HTTP/3 | ❌ | Visible only to the endpoints or a TLS-terminating proxy |
| Server's preferred-address (migration) instructions | ❌ | Encrypted |

## 2.2 The three things a passive defender has

1. **Cleartext header fields:** versions, connection IDs, tokens, the spin bit, packet types.
2. **The decryptable client Initial:** everything in the ClientHello, plus the client's transport parameters and padding.
3. **Metadata:** who talked to whom, when, for how long, how much, and in what rhythm.

Everything else needs either **endpoint telemetry** (which process opened the socket) or an **HTTP/3-aware proxy that terminates TLS**.

## 2.3 Why this matters for C2 detection

- **TLS inspection doesn't work on QUIC by default.** Most secure web gateways and next-generation firewalls inspect TLS over TCP. Many can't decrypt QUIC at all, so vendor guidance is to block QUIC and force browsers back to TCP.
- **No passive certificate visibility.** Detections built on certificate subjects, issuers or JA4X fingerprints for TLS over TCP don't carry over.
- **Fields an endpoint chooses can't be trusted to mean what the RFC intends.** Connection IDs, tokens, version lists, the spin bit, padding and grease values are all chosen by the sender. The RFCs say what they *should* contain, but nothing on the network enforces it. If an attacker controls both ends of a connection, these fields are only as trustworthy as the attacker.
- **Migration breaks flow tracking.** Tools that key on the 4-tuple can lose a connection when it moves, or mistake migrated packets for a new, handshake-less flow.
- **UDP gets less scrutiny.** In many environments UDP/443 egress is open and under-logged compared with TCP/443.

## 2.4 What the IETF says operators should rely on

[RFC 9312](https://www.rfc-editor.org/rfc/rfc9312) (QUIC manageability) is explicit that only the invariants are stable across versions. Operators should rely on as little of the wire image as possible, and they shouldn't assume they can see or alter anything else. Its guidance boils down to:

- Identify QUIC from the handshake (long headers, version, the decryptable Initial), not from port numbers alone.
- Expect connection IDs to change and connections to migrate.
- Use the spin bit for RTT only where endpoints choose to expose it.
- Don't build controls that depend on v1-specific details. QUIC v2 and grease exist to break exactly those.

---

**Previous:** [1. How QUIC works](01-quic-protocol-overview.md) · **Next:** [3. Threat landscape](03-threat-landscape.md)
