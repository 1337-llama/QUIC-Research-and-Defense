# SIEM Hunting Queries

Ready-to-adapt versions of the detection guide's queries for Splunk (SPL) and Elastic (ES|QL). Field names assume common defaults: Sysmon via the Splunk Add-on for Sysmon, Zeek via the Splunk Add-on for Zeek / Corelight, and Elastic's Endpoint and Zeek integrations. Adjust index and field names to your environment.

The [Sigma rules](../sigma/) are the portable source of truth for the single-event detections. CI checks that they're valid and that they convert to Splunk and Elasticsearch queries. The aggregation queries below (beaconing, long-lived connections over time) go beyond what Sigma expresses.

## Non-browser process using QUIC (endpoint)

The highest-fidelity detection: which process opened a UDP/443 connection.

### Splunk

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
  Protocol=udp DestinationPort=443 Initiated=true
  NOT Image IN ("*\\chrome.exe", "*\\msedge.exe", "*\\firefox.exe", "*\\brave.exe", "*\\ms-teams.exe", "*\\Zoom.exe")
| stats count min(_time) AS first_seen max(_time) AS last_seen dc(DestinationIp) AS destinations values(DestinationIp) AS dest_ips BY host Image
| sort - count
```

### Elastic

```esql
FROM logs-endpoint.events.network-*
| WHERE network.transport == "udp" AND destination.port == 443 AND network.direction == "egress"
  AND NOT process.name IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "ms-teams.exe", "Zoom.exe")
| STATS events = COUNT(*), destinations = COUNT_DISTINCT(destination.ip), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name, process.executable
| SORT events DESC
```

## QUIC to destinations outside your baseline (Zeek)

Replace the CIDRs with the CDN and SaaS ranges you approve.

### Splunk

```spl
index=zeek sourcetype=zeek:conn service="*quic*"
  NOT (cidrmatch("203.0.113.0/24", 'id.resp_h') OR cidrmatch("198.51.100.0/24", 'id.resp_h'))
| stats count sum(duration) AS total_seconds values('id.resp_p') AS ports BY 'id.orig_h' 'id.resp_h'
| sort - total_seconds
```

### Elastic

```esql
FROM logs-zeek.connection-*
| WHERE network.protocol == "quic"
  AND NOT CIDR_MATCH(destination.ip, "203.0.113.0/24", "198.51.100.0/24")
| STATS connections = COUNT(*), total_ns = SUM(event.duration) BY source.ip, destination.ip
| SORT total_ns DESC
```

## Long-lived QUIC connections, including reconnects (Zeek)

Flags single long connections, and host pairs whose *cumulative* QUIC time is high, which catches implants that reconnect every few hours.

### Splunk

```spl
index=zeek sourcetype=zeek:conn service="*quic*"
| stats max(duration) AS longest sum(duration) AS cumulative count BY 'id.orig_h' 'id.resp_h'
| where longest >= 3600 OR cumulative >= 4*3600
| sort - cumulative
```

### Elastic

```esql
FROM logs-zeek.connection-*
| WHERE network.protocol == "quic"
| STATS longest_ns = MAX(event.duration), cumulative_ns = SUM(event.duration), connections = COUNT(*) BY source.ip, destination.ip
| WHERE longest_ns >= 3600000000000 OR cumulative_ns >= 14400000000000
| SORT cumulative_ns DESC
```

## Periodic QUIC connections (Zeek)

The same logic as `detscore detect`'s `periodic-connections`: regular gaps between connection starts (coefficient of variation ≤ 0.35 over at least five connections). Human browsing has a CV near 1.

### Splunk

```spl
index=zeek sourcetype=zeek:conn service="*quic*"
| sort 0 _time
| streamstats current=f last(_time) AS prev BY 'id.orig_h' 'id.resp_h' 'id.resp_p'
| eval gap = _time - prev
| stats count avg(gap) AS mean_gap stdev(gap) AS sd_gap BY 'id.orig_h' 'id.resp_h' 'id.resp_p'
| where count >= 5 AND mean_gap > 0 AND sd_gap / mean_gap <= 0.35
| eval cv = round(sd_gap / mean_gap, 2)
```

### Elastic

ES|QL has no per-group lag function. Run this as an Elastic transform or a scheduled notebook, or export conn.log and use `detscore detect -periodic-min 5 -periodic-max-cv 0.35`.

## Beaconing inside one connection

A single persistent QUIC connection shows no periodicity in flow logs. Detecting it needs packet timing, which most SIEMs don't keep. Run `detscore cadence -pcap capture.pcap` on full-packet captures from your sensors, or apply the same burst-interval method in your NDR platform. See [chapter 7](../../docs/07-detection-lab.md#75-reference-detectors).
