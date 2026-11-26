#!/usr/bin/env bash
# Runs the detection lab end to end:
#   1. build the lab image and start the lab servers and packet capture
#   2. run the malicious and benign traffic profiles for LAB_DURATION
#   3. analyze the capture with Zeek and Suricata
#   4. run the reference detectors and score every detection against
#      ground truth
#
# Extra arguments are passed to `detscore score`, e.g. CI gates:
#   lab/harness/run.sh -require '(any):recall>=0.95'
#
# Environment:
#   LAB_DURATION  how long each simulator runs (default 6m)
#   LAB_OUT       output directory (default lab/harness/out)
#   LAB_KEEP      set to 1 to leave containers running for inspection
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

export LAB_DURATION="${LAB_DURATION:-6m}"
export LAB_OUT="${LAB_OUT:-$here/out}"
LAB_UID="$(id -u)"
LAB_GID="$(id -g)"
export LAB_UID LAB_GID

# The browser loop needs the duration in seconds; the simulators take Go
# durations. Accept the simple forms (90s, 6m, 1h).
case "$LAB_DURATION" in
  *[0-9]s) LAB_SECONDS="${LAB_DURATION%s}" ;;
  *[0-9]m) LAB_SECONDS="$(( ${LAB_DURATION%m} * 60 ))" ;;
  *[0-9]h) LAB_SECONDS="$(( ${LAB_DURATION%h} * 3600 ))" ;;
  *) echo "LAB_DURATION must look like 90s, 6m or 1h (got $LAB_DURATION)" >&2; exit 2 ;;
esac
export LAB_SECONDS

sims=(sim-merlin sim-quicagent sim-fallback sim-lowslow sim-rotating bg-browser-1 bg-browser-2 bg-chromium)

compose() { docker compose -f "$here/compose.yaml" --profile analyze "$@"; }
log() { printf '\n==> %s\n' "$*"; }

cleanup() {
  if [[ "${LAB_KEEP:-0}" != 1 ]]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$(uname -s)" != Linux ]]; then
  echo "run.sh needs a Linux Docker host: the capture sniffs the lab bridge from the host network namespace." >&2
  exit 1
fi

rm -rf "$LAB_OUT"
mkdir -p "$LAB_OUT/zeek" "$LAB_OUT/suricata" "$LAB_OUT/shared"

# On failure, show the container logs inline (CI job logs are often easier
# to reach than uploaded artifacts).
show_logs() {
  echo "---- lab server logs (last 40 lines) ----" >&2
  compose logs --no-log-prefix --tail 40 c2 c2-tcp cdn >&2 || true
  echo "---- simulator logs (last 60 lines) ----" >&2
  tail -n 60 "$LAB_OUT/simulators.log" >&2 || true
  echo "---- browser logs (last 60 lines) ----" >&2
  compose logs --no-log-prefix --tail 60 bg-chromium >&2 || true
}

log "Building the lab image"
compose build tools

log "Starting lab servers and capture"
compose up -d c2 c2-tcp cdn capture
for file in c2.pem c2-tcp.pem cdn.spki cdn.pem; do
  for _ in $(seq 1 30); do
    [[ -s "$LAB_OUT/shared/$file" ]] && break
    sleep 1
  done
  if [[ ! -s "$LAB_OUT/shared/$file" ]]; then
    echo "lab server did not publish $file" >&2
    show_logs
    exit 1
  fi
done

log "Running traffic profiles for $LAB_DURATION"
compose up --no-deps --no-log-prefix "${sims[@]}" >"$LAB_OUT/simulators.log" 2>&1
for s in "${sims[@]}"; do
  id="$(compose ps -aq "$s")"
  code="$(docker inspect -f '{{.State.ExitCode}}' "$id")"
  if [[ "$code" != 0 ]]; then
    echo "$s exited with status $code; see $LAB_OUT/simulators.log" >&2
    show_logs
    exit 1
  fi
done

log "Stopping capture"
sleep 2
compose stop capture
compose logs c2 c2-tcp cdn >"$LAB_OUT/servers.log" 2>&1
if [[ ! -s "$LAB_OUT/lab.pcap" ]]; then
  echo "capture is empty" >&2
  exit 1
fi

log "Analyzing with Zeek"
compose run --rm zeek

log "Analyzing with Suricata"
compose run --rm suricata

log "Labeling the real browser's connections from conn.log"
# Chromium writes no ground truth, but everything it sends goes to the CDN
# from its own address, so its conn.log entries are its sessions.
compose run --rm tools detscore label -conn /out/zeek/conn.log -host 172.28.0.50 \
  -label benign -profile chromium -run-id chromium -out /out/truth-chromium.jsonl
chromium_sessions="$(wc -l <"$LAB_OUT/truth-chromium.jsonl")"
echo "chromium sessions: $chromium_sessions"
if [[ "$chromium_sessions" -eq 0 ]]; then
  echo "the browser produced no QUIC or TLS connections; the scenario is broken" >&2
  compose logs --no-log-prefix --tail 40 bg-chromium cdn >&2 || true
  exit 1
fi

log "Running reference detectors"
# -include-tls: the fallback profile beacons over HTTPS on TCP, and the
# connection detectors must follow it there.
compose run --rm tools detscore detect \
  -conn /out/zeek/conn.log -quic /out/zeek/quic.log -include-tls \
  -long-connection 3m -approved 172.28.0.20/32 -out /out/alerts.jsonl

log "Detecting beaconing inside single connections (packet timing)"
compose run --rm tools detscore cadence -pcap /out/lab.pcap -out /out/cadence.jsonl

truth_args=()
for f in "$LAB_OUT"/truth-*.jsonl; do
  truth_args+=(-truth "/out/$(basename "$f")")
done

log "JA4 fingerprints by client"
compose run --rm tools detscore ja4 -eve /out/suricata/eve.json "${truth_args[@]}" -out /out/ja4.txt
cat "$LAB_OUT/ja4.txt"
notice_args=()
if [[ -f "$LAB_OUT/zeek/notice.log" ]]; then
  notice_args=(-notice /out/zeek/notice.log)
fi

log "Scoring detections against ground truth"
compose run --rm tools detscore score "${truth_args[@]}" \
  -alerts /out/alerts.jsonl -alerts /out/cadence.jsonl -eve /out/suricata/eve.json "${notice_args[@]}" \
  -out /out/report.txt
cat "$LAB_OUT/report.txt"

# The JSON report also applies any gates passed to this script (exit 3 if
# one fails), after the human-readable report has been printed.
compose run --rm tools detscore score "${truth_args[@]}" \
  -alerts /out/alerts.jsonl -alerts /out/cadence.jsonl -eve /out/suricata/eve.json "${notice_args[@]}" \
  -format json -out /out/report.json "$@"

log "Done. Capture, TLS key logs, sensor logs and reports are in $LAB_OUT"
