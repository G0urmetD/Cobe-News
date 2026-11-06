# Cobe News – the database image (ghcr.io/g0urmetd/cobe-news-db, locally cobe-news-db:latest): PostgreSQL 18 as
# published, plus the set-up of the app's own role at every start (cobe-news-db.sh → db-init.sh → app-role.sql,
# audit-lock.sql, restore-role.sql) – no one-shot db-init container any more (up to 0.1.48). Build context: this folder only
# (.dockerignore lets nothing else in). docs/BETRIEB.md: PostgreSQL, Rollen.
# base image pinned by digest (the tag for the reader; update with the others – docs/BETRIEB.md: Entwicklung, Basis-Images)
FROM postgres:18-alpine@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5
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
