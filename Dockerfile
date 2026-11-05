# ---- 1: the web UI (React + Vite) -------------------------------------------------------------
# base images pinned by digest (the tag for the reader; update both together – docs/BETRIEB.md: Entwicklung, Basis-Images)
# built once on the build machine's platform: the result is static files, the same for amd64 and arm64
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2: runtime (FastAPI + the built UI + background jobs, one process; nginx in front) --------
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data STATIC_DIR=/srv/static TLS_PATH=/tls
WORKDIR /srv
# pg_dump / pg_restore / psql of PostgreSQL 18 for backups (app/backup.py) – a pg_dump older than the server refuses to
# dump it, and Debian trixie ships 17: from the PostgreSQL project's own repository (apt.postgresql.org), its signing
# key pinned by checksum (fingerprint B97B 0AFC AA1A 47F0 44F2 44A0 7FCC 7D46 ACCC 4CF8)
ADD --checksum=sha256:0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76 https://www.postgresql.org/media/keys/ACCC4CF8.asc /usr/share/keyrings/pgdg.asc
RUN chmod 644 /usr/share/keyrings/pgdg.asc \
 && echo "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt trixie-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client-18 \
 && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
 && useradd -r -u 10001 -d /srv cobenews \
 && mkdir -p /data /tls && chown cobenews /data /tls
COPY backend/app ./app
# the notes the "Version & Changelog" page shows – from the same build as the version (app/changelog.py)
COPY CHANGELOG.md ./CHANGELOG.md
# the handbook the "Dokumentation" page shows – Markdown per chapter and language (app/docs.py, docs/handbuch/README.md)
COPY docs/handbuch/de ./handbuch/de
COPY docs/handbuch/en ./handbuch/en
COPY --from=ui /ui/dist ./static
USER cobenews
EXPOSE 8000
VOLUME ["/data", "/tls"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"
# one worker: the background loop, the rate limits and the sign-in throttle live in this process
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-server-header", "--no-access-log", "--no-proxy-headers"]
