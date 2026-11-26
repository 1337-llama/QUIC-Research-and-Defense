# 8. Emulating Merlin in a Lab

The beacon simulator ([chapter 6](06-beacon-simulator.md)) reproduces QUIC C2 *behavior* with no capability. Sometimes a team also wants to validate detections against a **real, public C2 framework**. [Merlin](https://github.com/Ne0nd0g/merlin) is the obvious choice for QUIC. It's open-source, written in Go on quic-go, has supported HTTP/3 since 2018, and is the framework Active Countermeasures used for its QUIC threat-hunting research.

This chapter covers how to do that **safely**, and how to collect and analyze the traffic. It doesn't repeat Merlin's own setup instructions; follow the project's documentation for those.

> Merlin is a real post-exploitation framework. Run it only on isolated lab infrastructure you own, with your security team's written approval, and never on production or shared networks.

## 8.1 Lab design

| Component | Recommendation |
|---|---|
| **Network** | A dedicated, isolated segment (a hypervisor host-only network, or a Docker `internal` network) with **no route to the internet or corporate networks** |
| **Agent host** | A disposable VM built for the exercise, snapshotted before and reverted after |
| **Server host** | A separate disposable VM or container on the same isolated segment |
| **Sensor** | A Zeek and Suricata sensor on a SPAN/mirror port or the virtual switch, or a capture on the server host to analyze offline |
| **Decryption** | Have the lab TLS secrets ready (key log) so analysts can compare the encrypted view with ground truth |
| **Record keeping** | Note the agent's start and stop times and its IP address/port so you can label the capture afterwards |

The Docker harness from [chapter 7](07-detection-lab.md) already gives you the isolated network, the capture and the analysis pipeline. A common pattern is to run the Merlin server and agent in two extra containers attached to the same `labnet`, then reuse `run.sh`'s Zeek, Suricata and `detscore` steps on the capture.

## 8.2 What to configure

Stick to settings that change **network behavior**, since that's what you're testing:

- **Listener protocol:** HTTP/3, so the agent uses QUIC.
- **Sleep and skew (jitter):** try Merlin's defaults first, then longer sleeps to test low-and-slow detection.
- **Padding:** Merlin can pad messages to defeat size-based beacon detection. Run with and without it.
- **Agent restarts:** restart the agent periodically to test cumulative-duration detection, not just single long connections.

Don't task the agent with anything beyond trivial, harmless commands. The network signal you're after comes from check-ins, not from post-exploitation activity.

## 8.3 Ground truth for a Merlin run

`detscore` can score a Merlin capture just like a simulator run. Because the agent runs on a dedicated lab host, `detscore label` can build the ground truth from Zeek's `conn.log` by labeling every QUIC/TLS connection from that host:

```sh
detscore label -conn zeek/conn.log -host 172.28.0.50 \
  -label malicious -profile merlin -run-id merlin-real-1 -out truth-merlin.jsonl
```

Label any background-traffic hosts as `benign` the same way, so that precision means something. This only works if the labeled hosts generate nothing except the traffic you're labeling.

## 8.4 What to look for

Compare your sensor output with the published Merlin indicators (Active Countermeasures, summarized in [chapter 3](03-threat-landscape.md)):

| Indicator | Where to look |
|---|---|
| One QUIC connection lasting hours | Zeek `conn.log` duration, RITA long connections, `detscore` `long-connection` |
| Regular client-to-server packet cadence inside that connection | `detscore cadence -pcap` (Zeek logs don't keep per-packet timing) |
| Client `max_idle_timeout` of 30,000 ms | Client transport parameters in the decrypted Initial packet (Wireshark: `quic.tp.max_idle_timeout`) |
| Abbreviated Zeek `history` strings | `quic.log` `history` field |
| Go/quic-go JA4 `q` fingerprint | Suricata JA4, `detscore ja4`, or the FoxIO JA4 tooling |
| QUIC to a destination with no business reason | `detscore` `unapproved-destination`, or the Zeek `Unapproved_QUIC_Destination` notice |

Then score your detections:

```sh
go run ./cmd/detscore score -truth merlin-truth.jsonl -notice zeek/notice.log -eve suricata/eve.json
```

## 8.5 Simulator vs. Merlin

| | Beacon simulator | Merlin |
|---|---|---|
| Capability | None | Full post-exploitation framework |
| Risk | Low: benign payloads, lab-only by default | High: isolate and approve |
| Ground truth | Automatic and exact | Written by hand |
| Repeatable in CI | Yes (the lab workflow runs nightly) | Not recommended |
| Fingerprint realism | quic-go stack, simulator's own settings | Exactly Merlin's |
| Best for | Regression-testing detections, training analysts | Periodic validation against a real framework |

Use the simulator for everyday detection engineering, and check against Merlin occasionally to make sure the simulator hasn't drifted from reality.

---

**Previous:** [7. The detection lab](07-detection-lab.md) · **Next:** [9. Architecture and testing](09-architecture-and-testing.md)
