# 10. Analyst Exercises and Results Dashboard

The detection lab scores *detections*. This chapter is about scoring *people*: exercises where an analyst hunts through a capture with the answers held back, and a dashboard that tracks how the reference detections do night after night.

## 10.1 How an exercise works

An exercise is an ordinary lab run ([chapter 7](07-detection-lab.md)) in exercise mode. Three things change:

- **Client addresses are shuffled.** Each simulator and the Chromium container get a random address in `172.28.0.100–249`, so nobody can read the answers off `compose.yaml`.
- **Seeds are random.** Every simulator's timing and sizes differ from the last exercise.
- **The C2 names don't announce themselves.** The servers are called `updates.corp-tools.lab` and `sync.corp-tools.lab` instead of `c2` and `c2-tcp`. Override them with `LAB_C2_NAME` and `LAB_C2TCP_NAME`.

At the end, `package-exercise.sh` splits the output in two:

| Archive | Contents | Who gets it |
|---|---|---|
| `exercise.tar.gz` | `lab.pcap`, Zeek's protocol logs (without `notice.log`), a briefing `README.md` and an `answers.txt` template | The analyst |
| `answer-key.tar.gz` | Ground truth, TLS key logs, Suricata output and JA4 summary, Zeek notices, reference-detector alerts, the scored report and the container logs | The instructor |

Everything the script doesn't explicitly hand to the analyst goes to the answer key, so a new output file can't leak by default. As a last check, it refuses to package an exercise whose files mention a profile name or a label.

## 10.2 Running one

On a Linux Docker host:

```sh
make lab-exercise          # or: LAB_EXERCISE=1 lab/harness/run.sh
```

Without Docker, use CI: run the **Lab end-to-end** workflow manually with **exercise** ticked. It uploads `exercise` and `answer-key` as separate artifacts, and never the full output directory, which would contain both. In exercise mode the run log doesn't print anything that maps clients to profiles, but anyone who can download the repository's artifacts can download the answer key too. For a graded session, fetch both artifacts and share only the exercise.

## 10.3 The briefing

The analyst's `README.md` sets the scene. A sensor on an office segment captured some traffic. Some hosts are beaconing over QUIC, or over HTTPS when QUIC doesn't get through, and the rest are browsing. `cdn` (`172.28.0.20`) is the approved CDN. The analyst has the capture and the Zeek logs, but no TLS keys, IDS alerts or endpoint data. Their task is to list the client IPs of every infected host.

The briefing also carries optional hints, one per lab scenario: a single long-lived connection, slow and irregular beacons, short-lived rotating connections, the TCP fallback, and the difference between a browser's handshake and a Go program's.

## 10.4 Grading

```sh
detscore grade -truth 'answer-key/truth-*.jsonl' -answers answers.txt
```

```text
score: 80/100  (precision 1.000, recall 0.667, F1 0.800)
found 4 of 6 beaconing hosts; 0 benign hosts flagged

CLIENT         YOU      TRUTH      RESULT  SESSIONS  PROFILES
172.28.0.117   flagged  malicious  TP      1         merlin-like
172.28.0.140   -        benign     TN      20        browser-like
172.28.0.188   -        malicious  FN      3         low-and-slow
...
```

Grading is per **host**: a client is malicious if any of its sessions is. That matches how analysts report findings, and it means flagging every connection of a noisy host separately earns nothing. The score is the F1 of the analyst's host list. Addresses that aren't clients in the exercise, such as a C2 server's address, are listed as "not graded" and don't count either way.

Use `-reveal=false` to print only the score. That way an analyst can revise their answers and try again without seeing the debrief. Use `-format json` to feed a leaderboard.

## 10.5 Suggested sessions

| Session | Material | Goal |
|---|---|---|
| Warm-up | `conn.log` only | Find the hosts talking to unapproved destinations. This catches everything here; ask *why* that won't hold in production (C2 behind a CDN or cloud provider) |
| Behavior | `conn.log` and `quic.log`, with the destination column hidden | Find beacons by timing and duration alone: the persistent session, the periodic connections, the rotating sessions |
| Fallback | The capture | Find the host that gave up on QUIC and beacons over TLS on TCP |
| Fingerprints | The capture plus the answer key's `ja4.txt` after grading | See why every simulator, benign or not, shares one JA4, while the real browser has its own |

After grading, walk through the answer key's `report.txt`. Comparing what the analyst found with what the reference detections found is usually the most useful part of the session.

## 10.6 Results dashboard

Every scheduled lab run on `main` publishes its results to the [`lab-results`](https://github.com/1337-llama/QUIC-Research-and-Defense/tree/lab-results) branch. It holds three files:

- `history.jsonl`: one line per run, with the commit, the workflow run, whether the gates passed, the session counts, and each detector's precision, recall and F1.
- `README.md`: the latest results, with each detector's change in recall since the previous run, and a table of recent runs.
- `trend.svg`: one small panel per detector, with recall and precision over the last 60 runs.

`detscore trend` builds all three. The workflow appends the night's `report.json` to the history and re-renders the page. A night whose gates fail is still published, marked **failed**, because a regression is exactly what the dashboard is for. A run that produced no report at all isn't published.

To render a dashboard from your own runs:

```sh
detscore trend -history history.jsonl -report lab/harness/out/report.json \
  -commit "$(git rev-parse HEAD)" -passed -out-dir dashboard/
```

The `lab-results` branch is written only by the workflow. GitHub Pages isn't needed, because the branch's README renders on GitHub as it is.

---

**Previous:** [9. Architecture and testing](09-architecture-and-testing.md) · **Next:** [References](references.md)
