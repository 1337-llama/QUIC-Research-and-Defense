# 6. The Beacon Simulator

`beaconsim` generates QUIC traffic that **looks like** C2 on the network, so you can test detections against it. It reproduces the observable behavior of real QUIC C2 families: timing, connection reuse, request sizes, transport settings and the Go QUIC stack's handshake. It has none of their capability.

It's written in Go on [quic-go](https://github.com/quic-go/quic-go), the same library behind Merlin, Salat Stealer and QUICAgent (see [chapter 3](03-threat-landscape.md)). That keeps its handshake close to what you'll see in the wild.

## 6.1 What it does and doesn't do

| It does | It doesn't |
|---|---|
| Open HTTP/3 connections to a lab server on a schedule | Execute commands, transfer files, or act on anything the server sends |
| Send POST beacons with benign, self-identifying JSON (`"sim": "quic-research/beaconsim"`) and random padding | Hide data in QUIC fields or implement covert channels |
| Reuse or rotate connections the way the modeled family does | Contact non-lab addresses unless you pass `-allow-public-targets` |
| Advertise the profile's QUIC transport settings (idle timeout, keep-alive, flow-control windows) | Persist, escalate, or hide on the host |
| Write **ground truth** for every connection and request | |
| Optionally write TLS secrets for Wireshark (`-keylog`) | |

The lab server, `beaconsrv`, acknowledges beacons with the same run ID and sequence number, and serves a static page for GET requests. A unit test pins the acknowledgement to exactly four fields, so a tasking field can't be added by accident.

## 6.2 Profiles

```text
$ beaconsim -list-profiles
NAME              LABEL      INTERVAL  CONNECTIONS  DESCRIPTION
browser-like      benign     20s       per-beacon   Bursty GET requests (exponential gaps) on short-lived connections
low-and-slow      malicious  15m0s     per-beacon   Infrequent beacons, 50% jitter: hard for periodicity detections
merlin-like       malicious  30s       persistent   One long-lived connection with keep-alives (Merlin, per Active Countermeasures)
quicagent-like    malicious  1m0s      per-beacon   A fresh connection per jittered POST beacon (QUICAgent, per Seqrite)
rotating-session  malicious  20s       rotate       Periodic beacons on a connection replaced every 10 minutes
```

Each profile controls:

- **Schedule.** `jitter` draws uniformly from interval × (1 ± jitter), the classic C2 sleep. `exponential` draws memoryless gaps with the given mean, which is how human browsing looks.
- **Connection mode.** `persistent` keeps one connection for the whole run, `per-beacon` opens a fresh one for every request, and `rotate` replaces the connection once it reaches `rotate_after`.
- **Request.** Method, path, User-Agent and a body-size range.
- **QUIC settings.** Handshake and idle timeouts, keep-alive period, initial flow-control windows, and datagram support. These appear in the client's transport parameters, which sensors can read from the Initial packet.

Custom profiles are JSON files. Unknown fields are rejected, so typos fail loudly:

```json
{
  "name": "my-profile",
  "label": "malicious",
  "schedule": {"distribution": "jitter", "interval": "45s", "jitter": 0.3},
  "connection": {"mode": "rotate", "rotate_after": "5m"},
  "request": {"method": "POST", "path": "/telemetry", "min_body_bytes": 200, "max_body_bytes": 900},
  "quic": {"max_idle_timeout": "60s", "keep_alive_period": "20s"}
}
```

```sh
beaconsim -profile-file my-profile.json -target c2:443 -ca c2.pem
```

## 6.3 Running it

Start a lab server. It generates a fresh certificate and publishes only the certificate, never the key:

```sh
beaconsrv -listen :443 -hosts c2,10.0.0.10 -cert-out /shared/c2.pem
```

Run a profile against it:

```sh
beaconsim -profile merlin-like -target c2:443 -ca /shared/c2.pem \
  -duration 30m -truth truth.jsonl -keylog keys.log
```

Useful flags:

| Flag | Purpose |
|---|---|
| `-interval`, `-jitter` | Override the profile's timing, e.g. to shorten a lab run |
| `-duration`, `-max-beacons` | Stop conditions (both optional) |
| `-seed` | Make a run's timing and sizes reproducible |
| `-run-id` | Label the run in ground truth and server logs |
| `-ca-wait` | Wait for the server's certificate to appear (used in containers) |
| `-allow-public-targets` | Allow non-lab destinations. Only use it for infrastructure you own |

Certificate verification is always on. The client trusts only the certificate passed with `-ca`.

## 6.4 Ground truth

Ground truth is JSON Lines. Each request produces a `beacon` record, and each connection produces a `session` record when it closes:

```json
{"kind":"session","run_id":"merlin","profile":"merlin-like","label":"malicious","session_id":1,
 "local":"172.28.0.30:41876","remote":"172.28.0.10:443",
 "start":"2026-11-23T12:00:01.2Z","end":"2026-11-23T12:06:01.4Z","beacons":12}
```

The simulator binds each connection's UDP socket to the concrete source address the kernel routes from. The `local`/`remote` pair is therefore exactly the 4-tuple Zeek and Suricata log, and the scorer can match alerts to sessions without guessing. The integration tests check this against the addresses the server actually sees.

## 6.5 Safety design

- **Lab-only destinations by default.** Targets must resolve to loopback, RFC 1918, RFC 6598 (shared address space) or IPv6 ULA addresses. If *any* address a name resolves to is public, the run is refused. That refusal is treated as permanent, so the simulator doesn't retry.
- **No instruction channel.** The protocol has no field for tasks, and the client only checks that the server's acknowledgement echoes its run ID and sequence number.
- **Self-identifying traffic.** Anyone who decrypts the traffic (with `-keylog`) sees the simulator marker in every request.
- **Isolated lab network.** The Docker harness ([chapter 7](07-detection-lab.md)) runs on an `internal` network with no route to the internet.

---

**Previous:** [5. Mitigations and policy](05-mitigations-and-policy.md) · **Next:** [7. The detection lab](07-detection-lab.md)
