# Cobe News – the database image (ghcr.io/g0urmetd/cobe-news-db, locally cobe-news-db:latest): PostgreSQL 18 as
# published, plus the set-up of the app's own role at every start (cobe-news-db.sh → db-init.sh → app-role.sql,
# audit-lock.sql, restore-role.sql) – no one-shot db-init container any more (up to 0.1.48). Build context: this folder only
# (.dockerignore lets nothing else in). docs/BETRIEB.md: PostgreSQL, Rollen.
# base image pinned by digest (the tag for the reader; update with the others – docs/BETRIEB.md: Entwicklung, Basis-Images)
FROM postgres:18-alpine@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395
# the Alpine security updates published since the pinned base image (the release pipeline's scan fails on a fixable
# high or critical finding – docs/SICHERHEIT-SCANS.md). The switch to the user postgres: su-exec from Alpine (C, a few
# lines, updated with Alpine) instead of the image's gosu – gosu 1.19 is built with Go 1.24.6, whose standard library
# carries high and critical CVEs fixed only in newer Go releases (no new gosu build). The name gosu stays as a link
# (/usr/bin, on the PATH) for the official docker-entrypoint.sh when it is started as root by hand (same arguments: user,
# command); cobe-news-db.sh calls su-exec itself. Both checked here: the build fails if either cannot switch the user
RUN apk upgrade --no-cache \
 && apk add --no-cache su-exec \
 && rm /usr/local/bin/gosu \
 && ln -s /sbin/su-exec /usr/bin/gosu \
 && test "$(su-exec postgres id -u)" = "$(id -u postgres)" \
 && test "$(gosu nobody id -un)" = nobody
# the scripts first: that COPY creates the folder (with their mode, 0755 – the SQL files' 0644 would leave it closed)
COPY --chmod=0755 cobe-news-db.sh db-init.sh /usr/local/share/cobe-news/
COPY --chmod=0644 app-role.sql audit-lock.sql restore-role.sql /usr/local/share/cobe-news/
# PostgreSQL's fast shutdown on `docker stop` (as the official image; cobe-news-db.sh passes it on)
STOPSIGNAL SIGINT
# healthy only after the role set-up of this start (the marker on the tmpfs /var/run/postgresql) – docker-compose.yml
# repeats it with the user and database of the installation
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --retries=20 \
  CMD test -f /var/run/postgresql/.cobe-news-ready && pg_isready -q -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"
ENTRYPOINT ["/usr/local/share/cobe-news/cobe-news-db.sh"]
CMD ["postgres"]
