#!/bin/sh
# Benign background traffic from a real browser: headless Chromium loads the
# lab CDN page over QUIC, then waits a random 1-45 s, until LAB_SECONDS have
# passed. Each load is a fresh browser process, so a fresh QUIC connection
# with Chromium's own handshake (and JA4) rather than quic-go's.
#
# Chromium only trusts the CDN's self-signed certificate through its SPKI
# hash, which the server publishes next to the certificate.
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
failures=0
while [ "$(date +%s)" -lt "$end" ]; do
  # --user-data-dir is required for --ignore-certificate-errors-spki-list
  # to take effect.
  if timeout 30 /headless-shell/headless-shell \
    --no-sandbox --headless --disable-gpu --no-first-run \
    --user-data-dir=/tmp/chromium-profile \
    --enable-quic --origin-to-force-quic-on=cdn:443 \
    --ignore-certificate-errors-spki-list="$spki" \
    --dump-dom https://cdn/ 2>/dev/null | grep -q "lab server"; then
    loads=$((loads + 1))
  else
    failures=$((failures + 1))
  fi
  sleep "$(shuf -i 1-45 -n 1)"
done

echo "browse.sh: $loads page loads, $failures failures"
# A browser that never managed a load means the scenario is broken, not
# that the network was quiet.
[ "$loads" -gt 0 ]
