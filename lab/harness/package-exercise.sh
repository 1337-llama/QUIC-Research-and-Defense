#!/usr/bin/env bash
# Splits a finished exercise-mode lab run (LAB_EXERCISE=1 run.sh) into:
#   exercise/    what the analyst gets: the capture and Zeek's protocol logs
#   answer-key/  what the instructor keeps: ground truth, TLS keys, detector
#                output, Suricata alerts and fingerprints, Zeek notices,
#                container logs and the scored report
# and archives each one. Anything not explicitly handed to the analyst goes
# to the answer key, so a new output file can't leak by default.
#
# Usage: package-exercise.sh <lab output directory>
set -euo pipefail

out="${1:?usage: package-exercise.sh <lab output directory>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ex="$out/exercise"
key="$out/answer-key"

rm -rf "$ex" "$key" "$out/exercise.tar.gz" "$out/answer-key.tar.gz"
mkdir -p "$ex/zeek" "$key"

# The analyst's material: the packet capture, and Zeek's protocol logs minus
# its notices (those are detections; finding the beacons is the exercise).
cp "$out/lab.pcap" "$ex/"
for f in "$out"/zeek/*.log; do
  case "$(basename "$f")" in
    notice.log | loaded_scripts.log | packet_filter.log | reporter.log) ;;
    *) cp "$f" "$ex/zeek/" ;;
  esac
done
cp "$here/exercise/README.md" "$ex/README.md"
cat >"$ex/answers.txt" <<'TEMPLATE'
# One client IP per line. Anything after '#' is a note to yourself.
# Example:
# 172.28.0.123   # describe what gave it away
TEMPLATE

# Everything else is the answer key.
shopt -s nullglob
for f in "$out"/*; do
  case "$(basename "$f")" in
    exercise | answer-key | shared | lab.pcap) ;;
    zeek) mkdir -p "$key/zeek" && cp "$f"/notice.log "$key/zeek/" 2>/dev/null || true ;;
    *) cp -r "$f" "$key/" ;;
  esac
done

# Self-check: nothing in the exercise may name a profile, a run or a label.
if grep -r -l -E 'merlin|quicagent|low-and-slow|rotating-session|browser-like|beaconsim|malicious' "$ex" \
  --exclude=lab.pcap --exclude=README.md --exclude=answers.txt; then
  echo "package-exercise.sh: the files above leak the answers" >&2
  exit 1
fi

tar -C "$out" -czf "$out/exercise.tar.gz" exercise
tar -C "$out" -czf "$out/answer-key.tar.gz" answer-key
echo "exercise:   $out/exercise.tar.gz ($(find "$ex" -type f | wc -l) files)"
echo "answer key: $out/answer-key.tar.gz ($(find "$key" -type f | wc -l) files)"
