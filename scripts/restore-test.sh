#!/bin/sh
# Cobe News – the restore test from the host's cron (docs/BETRIEB.md: Rücksicherungs-Test; Handbuch: Sicherung → Rücksicherungs-Test).
# Restores the newest backup into the throwaway database (never into the app's) and checks it; the outcome appears on
# the page Sicherung & Export and in /metrics. Exit code 0: passed, 1: failed, 2: wrong use.
#
#   scripts/restore-test.sh                          the app's BACKUP_PASSPHRASE (or an unencrypted backup)
#   scripts/restore-test.sh --passphrase-file FILE   the passphrase from FILE (read here, handed over on standard input –
#                                                    it never lands on a command line, in the container or in a log)
#
# Example line for /etc/cron.d/cobe-news (Sunday 04:30, after the daily backup – never in the backup's minutes; adjust the paths):
#   30 4 * * 0 root /opt/cobe-news/scripts/restore-test.sh --passphrase-file /root/.cobe-news-backup-pass >>/var/log/cobe-news-restore-test.log 2>&1
set -eu
cd "$(dirname "$0")/.."
passfile=""
if [ "$#" -gt 0 ]; then
  if [ "$1" != "--passphrase-file" ] || [ "$#" -ne 2 ]; then
    echo "usage: $0 [--passphrase-file FILE]" >&2
    exit 2
  fi
  passfile="$2"
  if [ ! -r "$passfile" ]; then
    echo "restore-test: cannot read $passfile" >&2
    exit 2
  fi
  case "$(ls -l "$passfile" | cut -c5-10)" in
    ------) ;;
    *) echo "restore-test: warning – $passfile is readable by others (chmod 600)" >&2 ;;
  esac
fi
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') restore test starts"
if [ -n "$passfile" ]; then
  nice -n 19 docker compose exec -T app python -m app.cli restore-test --passphrase-file - <"$passfile" && rc=0 || rc=$?
else
  nice -n 19 docker compose exec -T app python -m app.cli restore-test </dev/null && rc=0 || rc=$?
fi
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') restore test ends (exit $rc)"
[ "$rc" -eq 0 ] || exit 1
