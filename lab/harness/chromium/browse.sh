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
  # The resolver rule pins the CDN's address, so name resolution inside the
  # browser can't be the reason a load fails.
  if timeout 30 /headless-shell/headless-shell \
    --no-sandbox --headless --disable-gpu --no-first-run \
    --user-data-dir=/tmp/chromium-profile \
    --host-resolver-rules="MAP cdn 172.28.0.20" \
    --enable-quic --origin-to-force-quic-on=cdn:443 \
    --ignore-certificate-errors-spki-list="$spki" \
    --dump-dom https://cdn/ >/tmp/page.html 2>/tmp/chromium.err &&
    grep -q "lab server" /tmp/page.html; then
    loads=$((loads + 1))
  else
    failures=$((failures + 1))
    # Show why the first couple of loads failed; after that it's noise.
    if [ "$failures" -le 2 ]; then
      echo "browse.sh: load failed; page:" >&2
      head -c 400 /tmp/page.html >&2 || true
      echo "browse.sh: chromium stderr:" >&2
      tail -n 15 /tmp/chromium.err >&2 || true
    fi
  fi
  sleep "$(shuf -i 1-45 -n 1)"
done

echo "browse.sh: $loads page loads, $failures failures"
# A browser that never managed a load means the scenario is broken, not
# that the network was quiet.
[ "$loads" -gt 0 ]
