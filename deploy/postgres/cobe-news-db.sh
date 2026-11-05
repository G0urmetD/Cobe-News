#!/bin/bash
# Cobe News – entrypoint of the database image (deploy/postgres/Dockerfile, ghcr.io/g0urmetd/cobe-news-db). PID 1 of
# the container: starts PostgreSQL through the official entrypoint (docker-entrypoint.sh: data folder, first initdb,
# then PostgreSQL as the user postgres), waits until the real server takes connections, sets up the app's own role
# (db-init.sh: cobe_news_app as owner of the database, no superuser; with POSTGRES_RESTORE_PASSWORD the restore test's
# role and throwaway database) – at every start, harmless again, also re-setting the passwords – and only then marks
# the container ready: the healthcheck is pg_isready AND the marker below, on the tmpfs /var/run/postgresql (gone at
# every start, removed here as well), so the app never starts against a database without its role. Up to 0.1.48 the
# one-shot service db-init did this; the superuser's password stays in this container, the app never gets it.
# Root only for a moment: as root it prepares the data folder exactly as the official entrypoint does (its own functions,
# sourced: docker_setup_env, docker_create_db_directories) and then runs itself again as the user postgres (gosu) – PID 1
# is postgres from then on, without any capability; PostgreSQL, the role set-up and the signals all run as that user.
# Signals: `docker stop` (SIGINT, the image's STOPSIGNAL) or SIGTERM → PostgreSQL's fast shutdown (SIGINT): open
# transactions rolled back, a checkpoint, exit 0; SIGHUP → reload of the configuration (as with the official image;
# one that comes during the first start is passed on once the server is up).
# A failed role set-up stops PostgreSQL and exits 1 – the restart policy tries again; the container never runs healthy
# without the role (docs/BETRIEB.md: PostgreSQL, Rollen). PostgreSQL ending on its own (kill -9 …) ends the container.
# bash, not sh: it reaps the finished PostgreSQL at once (its /proc entry goes) and `wait` still knows its exit status.
set -eu

# options only (command: ["-c", "…"]): for postgres – as the official entrypoint does
if [ "${1:-}" != "${1#-}" ]; then
    set -- postgres "$@"
fi
if [ "$(id -u)" = 0 ] && [ "${1:-}" = postgres ]; then
    # the data folder (and its owner) as the official entrypoint makes it – in a subshell: its `set -Eeo pipefail` and
    # its variables stay there; only then the switch to postgres (the capabilities are gone with it)
    (
        set +u
        # shellcheck disable=SC1091
        source docker-entrypoint.sh
        docker_setup_env
        docker_create_db_directories
    )
    exec gosu postgres "$0" "$@"
fi

ready=/var/run/postgresql/.cobe-news-ready
here=$(dirname "$0")
rm -f "$ready"

docker-entrypoint.sh "$@" &
pg=$!
stopping=""
alive() { [ -e "/proc/$pg" ]; }
signal() { kill -INT "$pg" 2>/dev/null || true; }
stop() {
    stopping=1
    signal
}
trap stop INT TERM
# SIGHUP (reload) only to the running server: during the first initdb the official entrypoint would die of it – kept
# until the server is up, then passed on
hup=""
trap 'hup=1' HUP

# PostgreSQL's exit status once it has ended (a trapped signal interrupts `wait`: wait again) – or $1 instead
finish() {
    set +e
    while :; do
        wait "$pg"
        rc=$?
        alive || break
    done
    exit "${1:-$rc}"
}

# the real server: TCP on 127.0.0.1 – the temporary server of the first initdb listens on the socket only
until [ -n "$stopping" ] || pg_isready -q -h 127.0.0.1 -p "${PGPORT:-5432}" -U "${POSTGRES_USER:-postgres}"; do
    alive || finish
    sleep 1
done
if [ -n "$stopping" ]; then
    # asked to stop while starting: during the first initdb the official entrypoint ignores SIGINT – ask again until
    # PostgreSQL itself runs and shuts down
    while alive; do
        signal
        sleep 1
    done
    finish
fi
trap 'kill -HUP "$pg" 2>/dev/null || true' HUP
if [ -n "$hup" ]; then
    kill -HUP "$pg" 2>/dev/null || true
fi

# over the socket, as the superuser POSTGRES_USER (with its password, should pg_hba ask for it)
if PGHOST=/var/run/postgresql PGPORT="${PGPORT:-5432}" PGUSER="${POSTGRES_USER:-postgres}" \
    PGDATABASE="${POSTGRES_DB:-${POSTGRES_USER:-postgres}}" PGAPPNAME=cobe-news-db-init PGPASSWORD="${POSTGRES_PASSWORD:-}" \
    sh "$here/db-init.sh"; then
    : >"$ready"
    echo "db-init: done – the database is ready for the app"
elif [ -z "$stopping" ]; then
    echo "db-init: FAILED – stopping PostgreSQL; the container exits and its restart policy tries again (docs/BETRIEB.md: PostgreSQL, Rollen)" >&2
    stop
    finish 1
fi
finish
