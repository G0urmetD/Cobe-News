# ---- 1: the web UI (React + Vite) -------------------------------------------------------------
# base images pinned by digest (the tag for the reader; update both together – docs/BETRIEB.md: Entwicklung, Basis-Images)
# built once on the build machine's platform: the result is static files, the same for amd64 and arm64 – nothing of this
# stage but dist/ reaches the image (so no system updates here)
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2: runtime (FastAPI + the built UI + background jobs, one process; nginx in front) --------
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data STATIC_DIR=/srv/static TLS_PATH=/tls
WORKDIR /srv
# pg_dump / pg_restore / psql of PostgreSQL 18 for backups (app/backup.py) – a pg_dump older than the server refuses to
# dump it, and Debian trixie ships 17: from the PostgreSQL project's own repository (apt.postgresql.org), its signing
# key pinned by checksum (fingerprint B97B 0AFC AA1A 47F0 44F2 44A0 7FCC 7D46 ACCC 4CF8). Kept in the repository
# (keys/), not downloaded: a reset connection to www.postgresql.org once failed a release build (0.1.53).
# apt-get upgrade: the Debian security updates published since the pinned base image (apt, zlib … – the release pipeline's
# scan fails on a fixable high or critical finding, docs/SICHERHEIT-SCANS.md)
COPY keys/pgdg-ACCC4CF8.asc /usr/share/keyrings/pgdg.asc
RUN echo "0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76  /usr/share/keyrings/pgdg.asc" | sha256sum -c - \
 && chmod 644 /usr/share/keyrings/pgdg.asc \
 && echo "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt trixie-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-client-18 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
# pip only for this step: the app never needs it at runtime, so it leaves the image afterwards (with its vendored
# libraries – urllib3, msgpack, setuptools' pkg_resources – that scanners report). The base image has no setuptools or
# wheel since Python 3.12; ensurepip's bundled wheel goes too (no `python -m venv` with pip in the container) – the build
# fails if there is none to remove (a changed layout of the base image), or if pip is still importable
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
 && pip uninstall -y pip \
 && bundled="$(ls -d /usr/local/lib/python3*/ensurepip/_bundled)" \
 && rm -rf $bundled \
 && ! python -c "import pip" 2>/dev/null \
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
