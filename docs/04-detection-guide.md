# 4. Detecting QUIC Abuse

This chapter covers the tools that give you QUIC visibility and a ranked set of detections. The ranking reflects one hard-won lesson from the research: **context beats packet statistics.** Which process opened the connection, where it went, and whether QUIC should be there at all catch far more than field-level anomaly tests, which skilled attackers can defeat.

## 4.1 Visibility tooling

| Tool | What it gives you |
|---|---|
| **EDR / endpoint telemetry** | The single most valuable signal: which process opened a UDP/443 (or other QUIC) socket. Browsers, conferencing apps and some OS services are expected. Anything else is a lead |
| **[Zeek](https://docs.zeek.org/en/master/scripts/base/protocols/quic/main.zeek.html)** (6.1+, built-in QUIC analyzer) | `quic.log` with version, client initial DCID, client and server SCIDs, SNI (`server_name`), ALPN (`client_protocol`), and a `history` string summarizing the handshake. Plus `conn.log` for durations and bytes. The analyzer is registered on UDP/443 by default. Add other ports to its port set (see the analyzer's `main.zeek`) |
| **[Suricata](https://docs.suricata.io/en/latest/rules/quic-keywords.html)** (7.x/8.x) | QUIC app-layer parsing (enable it under `app-layer.protocols.quic`), rule keywords such as `quic.version` and `ja4.hash`, and EVE logging of version, SNI and JA4 |
| **[JA4+](https://github.com/FoxIO-LLC/ja4)** | Client fingerprints for QUIC start with `q` (vs. `t` for TCP). Go, Rust, Python and browser QUIC stacks produce different fingerprints |
| **Wireshark** | Decrypts client Initial packets automatically and the rest with an SSLKEYLOGFILE (lab use). Flags migrated traffic it can't tie to a handshake |
| **[RITA](https://github.com/activecm/rita)** or other beacon analytics | Long-connection and beacon scoring that works on QUIC flows |
| **HTTP/3-aware proxy** (e.g. Cloudflare Gateway UDP proxy, vendor HTTP/3 inspection) | The only way to see inside QUIC sessions: HTTP/3 requests, and transport behavior after the handshake |

## 4.2 Detections, ranked

### Tier 1: Context (highest fidelity, lowest effort)

1. **Non-browser process using QUIC.** Alert when a process outside your allowlist (browsers, Teams/Zoom/Webex, known agents) sends UDP to port 443, or any flow your NDR classifies as QUIC. This is the detection most likely to catch Go- or C++-based QUIC implants, whatever they do inside the protocol.
2. **QUIC to destinations outside your baseline.** Legitimate QUIC overwhelmingly goes to a small set of large CDN and SaaS networks. QUIC to a VPS provider, a newly registered domain, or a server with no SNI deserves review.
3. **QUIC on unexpected ports.** Anything other than UDP/443 (and UDP/853 for DNS-over-QUIC, where you use it).
4. **Any QUIC at all, if you've disabled it.** If browsers are set to `QuicAllowed = 0` (see [chapter 5](05-mitigations-and-policy.md)), remaining QUIC traffic is already suspicious.

### Tier 2: Handshake (from the decryptable client Initial)

5. **JA4 `q` fingerprints outside the browser baseline.** Build an inventory of JA4 QUIC fingerprints in your environment and hunt the rare ones. Go's quic-go stack is the most relevant for current threats.
6. **SNI and ALPN anomalies.** Missing SNI, SNI that doesn't match the destination's owner (e.g. a big-brand name on a small VPS), or ALPN `h3` from software that isn't a browser.
7. **Unusual client transport parameters.** Compare idle timeout, flow-control windows, connection-ID limits and datagram support against what common browsers send. For example, Active Countermeasures found Merlin's client advertised a 30,000 ms idle timeout.
8. **Malformed or unusual Initial contents.** Padding that isn't all zeros, unparseable data coalesced after the Initial, or unexpected tokens on a first contact.
9. **Version anomalies.** Versions other than v1 (`0x00000001`), v2 (`0x6b3343cf`) and grease, or Version Negotiation exchanges that your normal traffic never produces.

### Tier 3: Connection behavior and metadata

10. **Long-lived connections.** In Active Countermeasures' representative trace, only 9 of 6,423 QUIC connections (0.14%) lasted more than an hour, and the longest ran 4 h 11 min. Merlin held a single connection for almost 24 hours. Also add up cumulative duration per host pair to catch implants that reconnect every few hours.
11. **Beaconing.** A regular client-to-server send rhythm, even inside one long connection. Measure from packet timing, since flow logs alone can hide intra-connection cadence.
12. **Odd byte ratios and sizes.** Sustained upload-heavy sessions to an unknown server, streams of small constant-size packets, or many short-lived connections with tiny transfers.
13. **Connection-ID anomalies.** CIDs with lengths outside your baseline, CIDs that are printable text or low-entropy, or frequent CID changes with no address change. Remember that QUIC-LB and similar schemes produce legitimately structured CIDs, so baseline against known providers.
14. **Handshake-less flows to new destinations.** Short-header packets to an IP that never completed a handshake from that host may be migration abuse (as in QUIC-Exfil). If your own services disable migration, this is a stronger signal.
15. **Spin-bit behavior.** Genuine spinning flips roughly once per round trip. On its own this is a weak signal, because random values are allowed, but it's useful as a feature in scoring.

### Tier 4: Inside the session (needs a terminating proxy or endpoint instrumentation)

16. **HTTP/3 request patterns.** Periodic POSTs with encrypted or encoded bodies, as QUICAgent sends, unusual paths, missing or odd headers.
17. **Transport behavior that real stacks don't produce.** Flow-control limits that go down or jump in strange increments, stream IDs that skip wildly, non-empty connection-close reason text, or path validation with no migration.

## 4.3 Starter detection content

> These are starting points. Test them against your own traffic and tune them before you rely on them.

**Zeek: flag long-lived QUIC connections**

```zeek
@load base/frameworks/notice
@load base/protocols/conn

module QUICHunt;

export {
    redef enum Notice::Type += { Long_QUIC_Connection };
    const long_threshold = 1 hr &redef;
}

event connection_state_remove(c: connection)
    {
    if ( c$duration < long_threshold )
        return;

    for ( s in c$service )
        {
        if ( to_lower(s) == "quic" )
            {
            NOTICE([$note=Long_QUIC_Connection, $conn=c,
                    $msg=fmt("QUIC connection lasted %s", c$duration),
                    $identifier=cat(c$id$orig_h, c$id$resp_h)]);
            return;
            }
        }
    }
```

**Suricata: alert on a known-bad JA4 over QUIC** (replace the placeholder hash with one from your threat intel, and check keyword support on your Suricata version)

```
alert quic any any -> any any (msg:"QUIC client with suspicious JA4"; \
    ja4.hash; content:"q13d0000h3_000000000000_000000000000"; \
    classtype:trojan-activity; sid:9000001; rev:1;)
```

**Suricata: alert on uncommon QUIC versions** (v1 and v2 are excluded)

```
alert quic any any -> any any (msg:"Uncommon QUIC version"; \
    quic.version; content:!"|00 00 00 01|"; content:!"|6b 33 43 cf|"; \
    classtype:policy-violation; sid:9000002; rev:1;)
```

**Hunting query logic (any SIEM)**

```
QUIC flows (Zeek quic.log joined to conn.log)
  WHERE destination ASN NOT IN (approved CDN/SaaS ASNs)
    AND (duration > 1h OR flows_per_day_to_dest > N OR server_name IS NULL)
  JOIN EDR network events ON host + time + 4-tuple
  WHERE process NOT IN (approved QUIC clients)
```

## 4.4 Testing your detections

- **Emulate the real threats.** Most in-the-wild QUIC C2 is Go and quic-go, so test with Go-based tooling. Merlin is the best-known public red-team framework with HTTP/3 support. Run it only in an isolated lab.
- **Capture with keys.** Record pcaps alongside an SSLKEYLOGFILE so analysts can see both the encrypted view your sensors get and the decrypted truth.
- **Keep ground truth.** Label which flows are malicious so you can measure precision and recall, not just "it fired once."
- **Mix in realistic background traffic.** Detections that look perfect against a quiet lab often fall apart against real browser QUIC. QUIC-Exfil's results show that class imbalance can make a weak detector look accurate.
- **Don't write production JA4 rules from lab fingerprints alone.** Fingerprints vary with library version and build settings. Use lab fingerprints to understand the method, and threat intel for the rules.

---

**Previous:** [3. Threat landscape](03-threat-landscape.md) · **Next:** [5. Mitigations and policy](05-mitigations-and-policy.md)
