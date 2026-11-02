#!/bin/sh
# Runs at the start of the proxy container (nginx image: /docker-entrypoint.d). Watches the
# certificate files and reloads nginx when they change: the app's renewal of the self-signed certificate, or an own
# certificate replaced in TLS_SOURCE. A broken new file is not loaded (nginx -t first); the running one stays.
# A change counts as done only after a successful reload: a failed check or reload (half-written files, a key that does
# not fit yet) is tried again at the next round – said once per state, not every minute.
set -eu
files="/etc/nginx/tls/cobe.crt /etc/nginx/tls/cobe.key"
sum() { cat $files 2>/dev/null | md5sum; }
(
  last="$(sum)"
  told=""
  while sleep "${NEWS_CERT_WATCH_S:-60}"; do
    now="$(sum)"
    [ "$now" = "$last" ] && continue
    if nginx -t -q 2>/dev/null && nginx -s reload; then
      echo "cobe-news: certificate changed – nginx reloaded"
      last="$now"
      told=""
    elif [ "$told" != "$now" ]; then
      echo "cobe-news: new certificate files do not load (nginx -t / reload) – keeping the running one, trying again"
      told="$now"
    fi
  done
) &
