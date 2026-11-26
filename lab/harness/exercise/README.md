# QUIC beaconing exercise

You are a SOC analyst. A sensor on an office network segment captured the
traffic in `lab.pcap`, and Zeek processed it into the logs in `zeek/`.

Some of the hosts on this segment are infected and beaconing to an attacker
over QUIC, or over HTTPS when QUIC doesn't get through. The rest are people
browsing. **Your task: list the client IP addresses of every infected host.**

## What you know

- The segment is `172.28.0.0/24`.
- `cdn` (`172.28.0.20`) is the company's approved CDN. Everything else on
  UDP/443 or TCP/443 is unapproved.
- You do **not** have TLS keys, IDS alerts or endpoint data. Work from the
  capture and the Zeek logs.

## How to answer

Write one client IP per line in `answers.txt`. Anything after `#` is a note,
so record what gave each host away:

```text
172.28.0.123   # steady 30s bursts inside one long QUIC connection
```

Hand the file to your instructor, who grades it with:

```sh
detscore grade -truth 'answer-key/truth-*.jsonl' -answers answers.txt
```

The score is the F1 of your host list: finding every infected host and
flagging no clean ones scores 100.

## Hints, if you want them

1. Start with `conn.log`: who talks to what, how often, and for how long?
2. Not every beacon opens a new connection. Some keep one connection open
   for the whole capture.
3. Not every beacon is fast or regular. Some go quiet for minutes, and some
   replace their connection before it looks long.
4. Blocking QUIC doesn't stop an implant that can fall back to TCP.
5. A real browser and a Go program don't make the same TLS handshake.
   Zeek's `ssl.log` and `quic.log`, or JA4 from the capture, can tell them
   apart.

Chapters 2 and 4 of the project docs describe what each of these looks like
on the wire.
