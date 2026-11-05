#!/bin/sh
# Cobe News – the app's own database role (docs/BETRIEB.md: PostgreSQL, Rollen). Run by cobe-news-db.sh, the entrypoint
# of the database image, at every start of the database – as the superuser (POSTGRES_USER), before the container counts
# as healthy and so before the app starts – and harmless again: creates the role cobe_news_app if it is missing, sets
# its password from POSTGRES_APP_PASSWORD and makes it the owner of the database and of every table – the app then
# works without superuser rights. With POSTGRES_RESTORE_PASSWORD also the restore test's throwaway database and its own
# role (restore-role.sql). The connection (PGHOST, PGUSER, PGDATABASE …) comes from cobe-news-db.sh.
set -eu
here=$(dirname "$0")
app_pw="${POSTGRES_APP_PASSWORD:-}"
if [ "${#app_pw}" -lt 16 ]; then
  echo "db-init: POSTGRES_APP_PASSWORD missing or shorter than 16 characters – run scripts/setup-env.sh once, or set it under the stack's environment variables (docs/BETRIEB.md)" >&2
  exit 1
fi
psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 -f "$here/app-role.sql"
restore_pw="${POSTGRES_RESTORE_PASSWORD:-}"
if [ -z "$restore_pw" ]; then
  echo "db-init: POSTGRES_RESTORE_PASSWORD not set – no restore test database (docs/BETRIEB.md: Rücksicherungs-Test)"
  exit 0
fi
if [ "${#restore_pw}" -lt 16 ]; then
  echo "db-init: POSTGRES_RESTORE_PASSWORD shorter than 16 characters – run scripts/setup-env.sh (docs/BETRIEB.md)" >&2
  exit 1
fi
exec psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 -f "$here/restore-role.sql"
