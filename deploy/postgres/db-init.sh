#!/bin/sh
# Cobe News – the app's own database role (service db-init in docker-compose.yml; docs/BETRIEB.md: PostgreSQL, Rollen).
# Runs as the superuser (POSTGRES_USER of the db service) at every `docker compose up`, before the app starts, and is
# harmless again: creates the role cobe_news_app if it is missing, sets its password from POSTGRES_APP_PASSWORD and makes
# it the owner of the database and of every table – the app then works without superuser rights.
# With POSTGRES_RESTORE_PASSWORD also the restore test's throwaway database and its own role (restore-role.sql).
set -eu
if [ "${#POSTGRES_APP_PASSWORD}" -lt 16 ]; then
  echo "db-init: POSTGRES_APP_PASSWORD missing or shorter than 16 characters – run scripts/setup-env.sh once (docs/BETRIEB.md)" >&2
  exit 1
fi
psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 -f /init/app-role.sql
restore_pw="${POSTGRES_RESTORE_PASSWORD:-}"
if [ -z "$restore_pw" ]; then
  echo "db-init: POSTGRES_RESTORE_PASSWORD not set – no restore test database (docs/BETRIEB.md: Rücksicherungs-Test)"
  exit 0
fi
if [ "${#restore_pw}" -lt 16 ]; then
  echo "db-init: POSTGRES_RESTORE_PASSWORD shorter than 16 characters – run scripts/setup-env.sh (docs/BETRIEB.md)" >&2
  exit 1
fi
exec psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 -f /init/restore-role.sql
