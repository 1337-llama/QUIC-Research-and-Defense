#!/bin/sh
# Benign background traffic from a real browser: headless Chromium loads the
# lab CDN page over QUIC, then waits a random 1-45 s, until LAB_SECONDS have
# passed. Each load is a fresh browser process, so a fresh QUIC connection
# with Chromium's own handshake (and JA4) rather than quic-go's.
#
# Chromium only trusts the CDN's self-signed certificate through its SPKI
# hash, which the server publishes next to the certificate.
#
# Current headless-shell builds load the page but do not always exit after
# --dump-dom, so each load is given a fixed lifetime and then stopped. Whether
# the loads worked is checked from the sensor's side instead: run.sh labels
# this container's connections from Zeek's conn.log and fails if there are
# none.
set -eu

seconds="${LAB_SECONDS:-360}"
spki_file=/shared/cdn.spki

i=0
while [ ! -s "$spki_file" ]; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "browse.sh: $spki_file did not appear" >&2
    exit 1
  fi
  sleep 1
done
spki="$(cat "$spki_file")"

end=$(($(date +%s) + seconds))
loads=0
while [ "$(date +%s)" -lt "$end" ]; do
  # --user-data-dir is required for --ignore-certificate-errors-spki-list to
  # take effect. The resolver rule pins the CDN's address so name resolution
  # inside the browser can't be why a load fails.
  timeout 12 /headless-shell/headless-shell \
    --no-sandbox --headless --disable-gpu --no-first-run --disable-dev-shm-usage \
    --user-data-dir="/tmp/chromium-$loads" \
    --host-resolver-rules="MAP cdn 172.28.0.20" \
    --enable-quic --origin-to-force-quic-on=cdn:443 \
    --ignore-certificate-errors-spki-list="$spki" \
    --dump-dom https://cdn/ >/dev/null 2>&1 || true
  rm -rf "/tmp/chromium-$loads"
  loads=$((loads + 1))
  sleep "$(shuf -i 1-45 -n 1)"
done

echo "browse.sh: started $loads page loads"
