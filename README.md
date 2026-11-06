# Cobe News

**Self-hosted security news and vendor advisories – matched to the products and versions you actually run.**

[![Container image](https://img.shields.io/badge/ghcr.io-g0urmetd%2Fcobe--news-2496ED?logo=docker&logoColor=white)](https://github.com/G0urmetD/Cobe-News/pkgs/container/cobe-news)

Cobe News is a self-hosted tool for security teams. It collects security news from BSI, CISA, vendors and the trade
press, checks vendor advisories against your exact products and versions, rates urgency with CISA KEV and EPSS, and
notifies teams and people by e-mail, Microsoft Teams, push or webhook.

![Vendor News: followed products with the version that fixes all known vulnerabilities, ordered by urgency](docs/images/vendor-news.png)

## Features

- **News** – 46 built-in feeds (CERTs and authorities, vendor PSIRTs, trade press, research, KEV/EUVD catalogues),
  each story once, with severity, topics (exploited, zero-day, ransomware …) and CVEs; your own feeds can be added.
- **Vendor News** – follow products from a curated catalogue or by CPE, enter your installed versions and see exactly
  which vulnerabilities affect them, the version that fixes them and when support ends.
- **Urgency** – findings ranked by CVSS, CISA KEV and FIRST EPSS, so actively exploited issues come first.
- **Watched CVEs** – follow single CVEs and get notified when a fix appears, they land in CISA KEV or their EPSS jumps.
- **Teams and routing** – teams from AD or Entra ID groups, products per team, notifications to the people responsible.
- **Notifications** – e-mail, Microsoft Teams, Slack, Discord, Mattermost, Telegram, ntfy, Gotify, signed generic
  webhooks and desktop push, with rules per severity, source and team.
- **Sign-in** – local accounts, Active Directory (LDAP) and Entra ID (OIDC), with TOTP and passkeys.
- **Operations** – audit log, read-only REST API and Prometheus metrics, encrypted backups with an automatic restore
  test, HTTPS out of the box.
- **German and English** UI, light and dark theme, built-in handbook.

![News: stories from all sources with severity, topics and CVEs](docs/images/news.png)

## Quick start

Requirements: Docker with Docker Compose v2.

```bash
git clone https://github.com/G0urmetD/Cobe-News.git cobe-news
cd cobe-news
scripts/setup-env.sh              # creates .env with generated database passwords; on Linux hands data/ to the app (UID 10001)
docker compose up -d --build      # app, PostgreSQL 18 and nginx (HTTPS)
docker compose logs app | grep -A1 "Setup token"
```

On Linux as a user without sudo rights the script prints the one command to run instead (`sudo chown -R 10001:10001 data`).

Open **<https://localhost:8095>** (the self-signed certificate triggers a browser warning on first use), enter the
one-time setup token from the log (valid for 60 minutes) and create the first admin account with an authenticator app
(TOTP). Then switch on the sources under *Settings → Integrations → News* and follow your products under *Vendor News*.

By default the app listens on this machine only. Address, port, certificate, reverse proxy and outbound proxy are set
in `.env` – see [`.env.example`](.env.example). Behind a reverse proxy of your own on the same host (nginx, Traefik …):
`PROXY_ENABLED=0` is the only switch – point the proxy at `http://127.0.0.1:8096`
([`docs/BETRIEB.md`](docs/BETRIEB.md#https), section 3).

Three containers, all built locally: the app, the database (PostgreSQL 18 that sets up the app's own role at every
start) and the proxy (nginx). Instead of building you can run the released, signed images
`ghcr.io/g0urmetd/cobe-news`, `…/cobe-news-db` and `…/cobe-news-proxy`: set
`COMPOSE_FILE=docker-compose.yml:docker-compose.image.yml` and `COBE_NEWS_VERSION=<version>` in `.env`, then
`docker compose pull && docker compose up -d` – how to verify the signatures with cosign:
[`docs/BETRIEB.md`](docs/BETRIEB.md#veröffentlichtes-image-statt-lokalem-build). Without these two lines nothing changes.

With Portainer (no checkout): paste [`docker-compose.portainer.yml`](docker-compose.portainer.yml) into the stack web
editor and enter one of the two blocks of environment variables at its top (with or without your own reverse proxy:
passwords, `BASE_URL` and one switch) – see [`docs/BETRIEB.md`](docs/BETRIEB.md#portainer-stack-editor).

## Documentation

- **Handbook in the app** – user menu → *Documentation* (`/docs`), German and English: setup, sign-in, channels and
  rules, Vendor News, backups, API and FAQ. The source lives in [`docs/handbuch/`](docs/handbuch/README.md).
- **Operations reference** – [`docs/BETRIEB.md`](docs/BETRIEB.md) (German): configuration, HTTPS, network, PostgreSQL,
  backup and restore, catalogue maintenance, development and tests.
- **Changes** – [`CHANGELOG.md`](CHANGELOG.md).

## Security

Please do not report vulnerabilities in public issues. Report them privately through
[GitHub Security Advisories](https://github.com/G0urmetD/Cobe-News/security/advisories/new) of this repository.

## License

[MIT](LICENSE)
