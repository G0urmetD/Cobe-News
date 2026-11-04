---
title: Operations
summary: Settings in the .env, start and stop, updates, HTTPS, your own reverse proxy, the address on the network, logs, server commands and the database.
audience: admin
---

## .env reference {#env-referenz}

Everything about the installation itself (address, certificate, network, database) is in the
[.env](term:envfile) in the install folder. Everything else you set in the web interface; it is kept in the database.

- The template is `.env.example`; `scripts/setup-env.sh` creates the `.env` from it once (readable by its owner only).
- A line starting with `#` is off – the default from the table applies.
- After every change run `docker compose up -d`. It recreates the affected containers with the new values.
  `docker compose restart` is **not** enough: the containers keep their old values.
- The `.env` holds passwords. Never pass it on, never commit it to the repository (Git ignores it).

### Address and port {#env-adresse}

| Variable | Meaning | Default |
|---|---|---|
| `PORT` | https port on the host (the bundled nginx) | `8095` |
| `BIND` | which host address the port listens on. `0.0.0.0` opens it to the network ([Address for colleagues](#adresse)) | `127.0.0.1` (this machine only) |
| `BASE_URL` | the address people type in the browser – for links in notifications, the Entra redirect URI, the push contact address and the names in the certificate | `https://localhost:8095` |
| `NEWS_HOSTNAME` | [FQDN](term:fqdn) for the self-signed certificate (besides `localhost` and `127.0.0.1`) | empty |
| `TLS_NAMES` | more names or IP addresses for the self-signed certificate, comma separated. nginx answers only to the names from `BASE_URL`, `NEWS_HOSTNAME`, `TLS_NAMES` and `localhost` ([Known names only](#host-namen)) | empty |
| `APP_PORT` | http port of the app, always bound to `127.0.0.1`: for the health check, Prometheus on the same host ([Metrics](/docs/api#prometheus-konfiguration)) and your own reverse proxy on the same host | `8096` |
| `COMPOSE_FILE` | `docker-compose.yml:docker-compose.http.yml` switches on the redirect from http to https ([HTTPS](#http-umleitung)) | not set |
| `HTTP_PORT` | http port that only redirects to https (only with `COMPOSE_FILE` as above) | `8094` |
| `COBE_NEWS_IMAGE` | the released, signed image instead of the local build, e.g. `ghcr.io/g0urmetd/cobe-news:0.1.46` – only with `COMPOSE_FILE=docker-compose.yml:docker-compose.image.yml`; verify the signature with cosign first (docs/BETRIEB.md) | not set (local build) |

### Certificate {#env-zertifikat}

| Variable | Meaning | Default |
|---|---|---|
| `TLS_MODE` | `selfsigned` (the app creates and renews the certificate), `own` (your certificate), `external` (TLS ends at your own proxy) | `selfsigned` |
| `TLS_SOURCE` | with `own`: folder with `cobe.crt` and `cobe.key`, e.g. `./deploy/certs` | the Docker volume `tls` |
| `HSTS` | `1` sends [HSTS](term:hsts) with the self-signed certificate too. With `own` and `external` HSTS is always sent – to host names only, never to `localhost` or IP addresses ([HSTS](#hsts)) | `0` |

### Own proxy and client addresses {#env-proxy}

| Variable | Meaning | Default |
|---|---|---|
| `PROXY_ENABLED` | `0`: the bundled nginx does not start – for your own [reverse proxy](term:reverseproxy) in front | `1` |
| `TRUSTED_PROXIES` | addresses or networks ([CIDR](term:cidr)) whose `X-Forwarded-For` the app believes – only your own proxy's address, e.g. `172.31.250.1/32` for a proxy on the host ([which address?](#trusted-proxies)) | empty |
| `SHARED_ADDRESSES` | addresses or networks many people share (e.g. an office NAT): never blocked, failed attempts through them are only slowed down | empty |
| `COOKIE_SECURE` | cookies over https only. Do not change – `0` is meant only for development without https | `1` |

### Secrets and outbound connections {#env-ausgehend}

| Variable | Meaning | Default |
|---|---|---|
| `SECRET_KEY` | [master key](term:masterkey) for stored secrets (webhook URLs, SMTP and LDAP password, Entra secret, TOTP of local accounts). At least 32 random characters, e.g. from `openssl rand -base64 32` – a shorter one (or one of only a few different characters) starts, but logs a warning at the start and shows a notice under *Settings → HTTPS & certificate*. Do not change it once secrets are stored | empty: key file `./data/secret.key` |
| `WEBHOOK_HOSTS` | more allowed hosts for Teams and Slack channels (besides the Microsoft and Slack hosts), e.g. `chat.corp.example` | empty |
| `WEBHOOK_PRIVATE_NETS` | private addresses or networks notification channels may post to (e.g. an n8n in the company network), e.g. `10.20.0.0/16,192.168.10.5`; also the own Docker networks and the Docker host by its address. Loopback, link-local (`169.254.169.254`), "any" and multicast stay blocked always ([Allowed targets](/docs/benachrichtigungen#webhook-ziele)) | empty: public targets only |
| `SMTP_ALLOW_INTERNAL` | address of an [SMTP](term:smtp) relay that would otherwise be refused as internal (e.g. on the Docker host behind the gateway `172.31.250.1`; then also by a name like `host.docker.internal`). Loopback, link-local, "any" and multicast stay blocked always | empty |
| `HTTPS_PROXY` | proxy for all outbound requests, e.g. `http://proxy.corp.example:3128` | empty |
| `CA_FILE` | path **inside the container** to your own CA bundle (PEM), e.g. for a proxy that inspects TLS. The folder `./data` is mounted as `/data`: put the file at e.g. `./data/ca.pem` and set `CA_FILE=/data/ca.pem` | empty |
| `ALLOW_PRIVATE_FEEDS` | `1` allows own feeds at private addresses (company network) | `0` |

### Web Push {#env-push}

| Variable | Meaning | Default |
|---|---|---|
| `WEB_PUSH` | `0` switches off desktop notifications with the tab closed for everyone – then no request goes to the browsers' push services. The open tab still notifies | `1` |
| `PUSH_CONTACT` | contact address for the push services (`mailto:` or `https:`), e.g. `mailto:secops@corp.example` | empty: `BASE_URL` |

More: [Web Push](/docs/integrationen#web-push), key [VAPID](term:vapid).

### Database and backups {#env-datenbank}

| Variable | Meaning | Default |
|---|---|---|
| `POSTGRES_PASSWORD` | password of the database superuser `cobe_news` (only `db-init` uses it). **Never change it** ([Database](#datenbank)) | generated by `setup-env.sh` |
| `POSTGRES_APP_PASSWORD` | password of the app's role `cobe_news_app`, at least 16 characters. May change – `db-init` sets it at every start | generated by `setup-env.sh` |
| `POSTGRES_RESTORE_PASSWORD` | password of the role `cobe_news_restore` for the [restore test](/docs/sicherung#ruecksicherungs-test), at least 16 characters. May change – `db-init` sets it at every start. Empty: no restore test | generated by `setup-env.sh` |
| `DB_MEM` | memory limit of the database container | `512m` |
| `BACKUP_PASSPHRASE` | backups encrypted and with the key, at least 12 characters. Better passed only to the [cron](term:cron) job ([Encryption](/docs/sicherung#verschluesselung)) | empty: not encrypted, without the key |
| `SQLITE_IMPORT` | `0`: do not move an old SQLite file (`data/news.db`, up to version 0.1.15) into an empty database at the start ([Database](#datenbank)) | `1`: import on |

### Resources and networks {#env-ressourcen}

| Variable | Meaning | Default |
|---|---|---|
| `APP_MEM` | memory limit of the app container | `512m` |
| `EDGE_SUBNET` | subnet of the Docker network `edge` between nginx and the app – change it only if it collides with one of your networks | `172.31.250.0/24` |
| `EDGE_RANGE` | range within it for dynamic addresses (the proxy's fixed address lies outside) | `172.31.250.128/25` |
| `PROXY_IP` | fixed address of the bundled nginx in the network `edge`; only from it (and from `TRUSTED_PROXIES`) does the app take the client address. Must lie in `EDGE_SUBNET` and outside `EDGE_RANGE` | `172.31.250.10` |
| `MAX_BODY_BYTES` | largest request the app itself takes, in bytes (16 KiB to 64 MiB) – behind nginx, which refuses at 1 MB already; larger ones get `413` (`body_too_large`). Only needed for your own proxy that lets more through; no endpoint needs more | `1048576` (1 MiB) |

Fixed in `docker-compose.yml` and not settable through the `.env`: the app's `TLS_PATH`, `POSTGRES_HOST` and
`POSTGRES_USER`. Other variables the code knows (e.g. `BACKUP_DIR`, `DATABASE_URL`) are not passed to the container
by `docker-compose.yml` – they have no effect in the `.env`.

## Start and stop {#start-stopp}

Cobe News consists of four containers:

| Container | Job | Port |
|---|---|---|
| `cobe-news-proxy` | nginx: HTTPS, forwards to the app | `PORT` (8095), https |
| `cobe-news-app` | web interface, API and background jobs (fetching, notifications, certificate, directory sync) | `127.0.0.1:8096`, http, health check only |
| `cobe-news-db` | PostgreSQL 18 with all data | none (internal network) |
| `cobe-news-db-init` | runs briefly before the app at every start and sets up its database role | none |

### First start {#erster-start}

```bash
cd /opt/cobe-news
scripts/setup-env.sh
docker compose up -d --build
docker compose logs app | grep -A1 "Setup token"
```

1. Get the repository into `/opt/cobe-news` and change into it.
2. Run `scripts/setup-env.sh`. It creates the `.env` and generates both database passwords. Running it again does no
   harm – it changes nothing that is already set.
3. Adjust the `.env` if needed. Leave `BIND` at `127.0.0.1` for now.
4. Build and start with `docker compose up -d --build`.
5. Copy the **setup token** from the log (last line above). It is valid for 60 minutes and only once. Until the setup
   is done, every restart writes a new one to the log; you get one by hand with
   `docker compose exec app python -m app.cli new-setup-token`.
6. Open `https://localhost:8095` on the server. Without a browser on the server, use an SSH tunnel, e.g.
   `ssh -L 8095:127.0.0.1:8095 admin@news.corp.example`, then `https://localhost:8095` on your own computer.
7. The browser warns about the self-signed certificate – that is normal at the first start ([HTTPS](#https)).
8. The wizard asks for the token, creates the first account (password at least 12 characters) and sets up
   [TOTP](term:totp). This account is the [emergency admin](/docs/anmeldung#notfall-admin).

Only then open the address to colleagues ([Address for colleagues](#adresse)).

### Start, stop, status {#starten-stoppen}

| Command | Effect |
|---|---|
| `docker compose up -d` | start, or apply changes to the `.env` |
| `docker compose up -d --build` | rebuild and start (after an update) |
| `docker compose stop` | stop, the containers stay |
| `docker compose start` | start stopped containers again |
| `docker compose restart app` | restart only the app (does **not** apply changes to the `.env`) |
| `docker compose down` | stop and remove the containers – the data stays |
| `docker compose ps -a` | status of all containers |

Run all commands in the install folder (`cd /opt/cobe-news`). The containers start again by themselves after the
server reboots, as long as they were not stopped by hand.

In `docker compose ps -a` the app shows as `healthy` when it runs and reaches the database. `cobe-news-db-init` shows
as finished with `Exited (0)` – that is correct, it only runs briefly at the start.

> [!WARNING]
> `docker compose down -v` also deletes the volumes – that is, the whole database and the certificate. Use it only if
> you really want to start over, and only with a [backup](/docs/sicherung#jetzt-sichern).

### Where the data lives {#daten-ablage}

| Place | Content |
|---|---|
| Volume `cobe-news_db18` | the database: stories, sources, users, sessions, channels, rules, Vendor News, settings |
| `./data/secret.key` | key for stored secrets (when `SECRET_KEY` is empty) |
| `./data/backups/` | the backups ([Backup](/docs/sicherung#ueberblick)) |
| `./data/vendor_catalog.json` | the most recently rebuilt Vendor News catalogue |
| Volume `cobe-news_tls` | the self-signed certificate (with `TLS_MODE=own` the folder from `TLS_SOURCE` instead) |
| `.env` | this installation's settings with the database passwords |

Only the app's process can read `./data` and the files in it.

### With Portainer {#portainer}

If you manage Docker with Portainer, you need no checkout: the file `docker-compose.portainer.yml` from the repository
goes as a whole into Portainer's web editor (*Stacks → Add stack → Web editor*), the values of the `.env` become the
stack's *Environment variables* – `POSTGRES_PASSWORD` and `POSTGRES_APP_PASSWORD` are required. It runs the released
image from version 0.1.48 on and is hardened just like the normal installation. The containers are named after the
stack (e.g. `news-app-1`), the data lives in named volumes (`news_data`, `news_db18`, `news_tls`). An update: set
`COBE_NEWS_IMAGE` to the new version and *Update the stack*. Backup, restore test and restore run there with
`docker exec` or a throwaway container instead of `docker compose` – all steps, variables and limits: docs/BETRIEB.md,
section "Portainer (Stack-Editor)". Docker Standalone environments only, not Swarm: `docker stack deploy` ignores the
start order and parts of the hardening and restarts the short copy service over and over. Next to a local
installation on the same host, `PORT`, `APP_PORT`, `EDGE_SUBNET`, `EDGE_RANGE` and `PROXY_IP` need other values.

## Update {#update}

Cobe News is updated with Git and Docker Compose. The app brings the database to the new version's state by itself at
the start (migrations) – nothing to do by hand.

### Update step by step {#update-schritte}

1. **Make a backup** – in *Settings → Backup & export* with "Back up now", or by command (below). If the passphrase
   is not in the `.env`, pass it as for the [cron job](/docs/sicherung#cron).
2. **Keep the running image** – that gives you a quick way back.
3. **Get the new version** and read the "Betrieb" (operations) sections of the new versions in `CHANGELOG.md`: they
   say what to watch out for when updating.
4. Run **`scripts/setup-env.sh`** again. It adds values a new version needs and leaves everything existing unchanged.
5. **Build and start.**
6. **Check**: the containers' status, the app's log, and the new number under *Version & changelog* in the user menu.

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli backup
docker tag cobe-news:latest cobe-news:before-update
git pull
scripts/setup-env.sh
docker compose up -d --build
docker compose ps -a
docker compose logs --tail 50 app
```

The first line after the start names version and address: `Cobe News 0.1.x – data in /data, https://…`. If the app
does not come up, the reason is in the log of `app` or `db-init` ([Logs](#logs)).

### Update notice {#update-hinweis}

Admins see a small notice in the top bar as soon as a newer version is published: **“Version 0.1.48 available –
changelog”**. The link opens the release page on GitHub; the **×** closes the notice for you and this version – when an
even newer one appears, it comes back. Readers see nothing.

- **Where from:** GitHub's public release API (`api.github.com/repos/G0urmetD/Cobe-News/releases/latest`), without
  sign-in, at most every 12 hours – also after an error –, conditional (`ETag`: unchanged does not count against
  GitHub's limit of 60 requests an hour), with a short timeout and a size limit, through the same hardening as every
  fetch. Only the request itself is sent, with the user agent `Cobe/<version>` – nothing about your installation.
- **What counts:** only a final `x.y.z` version higher than the running one. Drafts, pre-releases (`0.1.48-rc1`) and
  other tags are skipped.
- **Switch off:** in the user menu *Version & changelog*, switch **“Check for new versions”** (on by default). Off: no
  request, no notice. That page also shows the latest known version, when it was last checked and an error.
- **Monitoring:** `/metrics` reports `cobe_news_update_available` ([Metrics](/docs/api#metriken)).

The notice does not replace the update – that stays your step ([Update step by step](#update-schritte)).

### Back to the old version {#update-zurueck}

```bash
cd /opt/cobe-news
git log --oneline
git checkout <commit-of-the-old-version>
docker tag cobe-news:before-update cobe-news:latest
docker compose up -d --no-build
```

1. Find the old version in the Git history: `git log --oneline` shows every version as "Version 0.1.x: …".
2. Check out that state, set the kept image back to `latest` and start without a rebuild (commands above).
3. If the update migrated the database, the old version does not fit the new schema. Then restore the backup from
   step 1 with the old version: stop the app, restore, start the app
   ([Restore](/docs/sicherung#wiederherstellung)).
4. To move forward again later: `git checkout main`, then as above.

## HTTPS and certificate {#https}

Cobe News always runs over HTTPS. Which certificate the bundled nginx serves is set by `TLS_MODE` in the `.env`.
*Settings → HTTPS & certificate* shows the state: mode, "Valid until", "Valid for" (the names in the certificate), issuer,
fingerprint (SHA-256) and whether HSTS is sent. Problems appear there as a hint, e.g. when the certificate does not
cover the name from `BASE_URL` or expires soon.

nginx notices new certificate files within a minute and loads them without interruption. It does not load a broken
file – the running certificate stays.

### Self-signed (default) {#tls-selbstsigniert}

With `TLS_MODE=selfsigned` the app creates a certificate at the start (valid for 180 days) for `NEWS_HOSTNAME`, the
name from `BASE_URL`, `localhost`, `127.0.0.1` and the entries from `TLS_NAMES`. It renews it by itself 30 days before
it ends, and at once when the names change. It never overwrites a certificate it did not create itself.

Browsers warn about this certificate until the computer trusts it. Desktop notifications with the tab closed only work
from then on ([Desktop](/docs/benachrichtigungen#desktop)).

### Distributing the self-signed certificate {#zertifikat-verteilen}

1. Open *Settings → HTTPS & certificate* and choose "Download certificate". The file holds only the public part.
2. Mark the certificate as trusted on the computers – in a company most easily by group policy under "Trusted Root
   Certification Authorities".
3. **Repeat after every renewal** – that is, about every five months, and whenever `NEWS_HOSTNAME`, `TLS_NAMES` or
   `BASE_URL` change.

Without distributing it: compare the fingerprint in the browser's warning with the one in the settings before you go
on. For the long run, a certificate from your own CA is more convenient.

### Own certificate {#eigenes-zertifikat}

To run under e.g. `news.corp.example` with a certificate from your internal CA:

1. Have a certificate issued for the FQDN (server authentication, the FQDN as Subject Alternative Name, [SAN](term:san); a wildcard
   certificate like `*.corp.example` works too).
2. Put the files into `deploy/certs/` (Git ignores the folder):
   - `cobe.crt` – PEM, first the server certificate, then the intermediate certificates (not the root)
   - `cobe.key` – PEM, without a password, readable by its owner only: `chmod 600 deploy/certs/cobe.key`
3. Set the values from the example below in the `.env`.
4. `docker compose up -d`.

```
TLS_MODE=own
TLS_SOURCE=./deploy/certs
NEWS_HOSTNAME=news.corp.example
BASE_URL=https://news.corp.example:8095
```

The app never writes to this folder. It only shows the remaining validity and warns 30 days before the end. To
replace the certificate, replace both files – nginx loads them within a minute.

### From a PFX file {#pfx-umwandeln}

If your CA delivers a [PFX or PKCS#12 file](term:pfx), convert it like this (you are asked for the PFX password):

```bash
cd /opt/cobe-news
openssl pkcs12 -in news.pfx -clcerts -nokeys -out deploy/certs/cobe.crt
openssl pkcs12 -in news.pfx -cacerts -nokeys >> deploy/certs/cobe.crt
openssl pkcs12 -in news.pfx -nocerts -nodes -out deploy/certs/cobe.key
chmod 600 deploy/certs/cobe.key
```

### HSTS {#hsts}

[HSTS](term:hsts) tells the browser to open the site only over HTTPS for one year and not to let anyone skip
certificate errors.

- With `TLS_MODE=own` and `TLS_MODE=external` Cobe News always sends HSTS – with `external` on every request that
  came over HTTPS: your proxy must be in `TRUSTED_PROXIES` and send `X-Forwarded-Proto https` (see
  [example](#proxy-nginx-beispiel)). Your proxy may also set the header itself.
- Not with the self-signed certificate – otherwise nobody could "continue anyway". And after every renewal (about every
  150 days, a new certificate) computers that trusted the old one could not get in at all. Set `HSTS=1` only once it is
  trusted on all computers and handed out again after every renewal.
- Only to a host name (e.g. `news.corp.example`), never to `localhost`, `*.localhost` or an IP address. HSTS holds for a
  host across all ports: HSTS for `localhost` would turn the emergency access `http://localhost:8096` into https for a
  year, where nothing answers. Browsers ignore HSTS for IP addresses anyway.
- Without `includeSubDomains` and without `preload`: it only concerns the name of Cobe News, no other services of the
  domain.
- With HSTS the browser also opens `http://news.corp.example:8094` (the [redirect](#http-umleitung)) over https on the
  same port right away – only http answers there. Use the https address with its port (bookmark).

### Redirect from http to https {#http-umleitung}

Out of the box there is no http port. To have `http://…` redirect to the https address, put this in the `.env`:

```
COMPOSE_FILE=docker-compose.yml:docker-compose.http.yml
HTTP_PORT=8094
```

Then `docker compose up -d`. The port only redirects, it serves no content. It listens on the same address as `BIND`.

Even without this port: whoever sends `http://…` to the https port (e.g. `http://news.corp.example:8095`) is redirected
to `https://` instead of seeing nginx's error page "plain HTTP request was sent to HTTPS port".

### Known names only {#host-namen}

The bundled nginx serves Cobe News only under the names that belong to the installation:

- the name from `BASE_URL`,
- `NEWS_HOSTNAME` and every entry of `TLS_NAMES` (names and IP addresses),
- `localhost`, `127.0.0.1` and `[::1]` – access on the server itself always works.

A request with another name in the `Host` header – someone scanning address ranges, or a foreign DNS name pointing at
your server – gets no page: over https only the line "Unbekannter Hostname – in .env BASE_URL oder TLS_NAMES
eintragen. / Unknown host name – add it to BASE_URL or TLS_NAMES in .env." (HTTP 421), over http nothing (nginx closes
the connection, code 444 in the proxy's log). If someone opens the page by a further name or an IP address, put it
into `TLS_NAMES` and run `docker compose up -d` – with the self-signed certificate it then goes into the certificate as
well. Which names apply is in the log at the start: `docker compose logs proxy | grep "answering to"`. When Cobe News
is opened to the network (`BIND=0.0.0.0`) while `BASE_URL` still names `localhost`, a warning is there as well.

> **Upgrading to 0.1.47:** earlier versions answered to any name. If you open Cobe News by an IP address or a name that
> is not in `BASE_URL`, `NEWS_HOSTNAME` or `TLS_NAMES`, the browser shows "Unknown host name" after the update. Before
> it, put the address from the address bar into `TLS_NAMES` (or set `BASE_URL` correctly), then `docker compose up -d`. Enter names with umlauts in their `xn--` form; an entry with
characters other than letters, digits, `.`, `-`, `:`, `[`, `]` (and a leading `*.`) is skipped and named in the log.

## Own reverse proxy {#reverse-proxy}

If the server already runs an nginx, Traefik or similar with a certificate, it can serve Cobe News. The bundled nginx
then stays off.

### Settings {#proxy-einstellungen}

```
PROXY_ENABLED=0
TLS_MODE=external
BASE_URL=https://news.corp.example
TRUSTED_PROXIES=172.31.250.1/32
```

1. Put the values above into the `.env`.
2. `docker compose up -d`. The container `cobe-news-proxy` no longer starts.
3. Point your proxy at `http://127.0.0.1:8096` (`APP_PORT`). This port is always bound to `127.0.0.1` – so your own
   proxy must run on the same host.
4. Check which address the requests arrive from and put exactly that into `TRUSTED_PROXIES` ([below](#trusted-proxies)).

You manage the certificate at your proxy. *Settings → HTTPS & certificate* then shows "External reverse proxy".

### nginx example {#proxy-nginx-beispiel}

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name news.corp.example;
    ssl_certificate     /etc/ssl/news/fullchain.pem;
    ssl_certificate_key /etc/ssl/news/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8096;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

What matters is `X-Forwarded-For $remote_addr`: the proxy sets the client's real address and **replaces** one the
client sent itself. Do not use `$proxy_add_x_forwarded_for` – with it anyone could choose their own address.

### Which address goes into TRUSTED_PROXIES? {#trusted-proxies}

The app believes `X-Forwarded-For` only from addresses in `TRUSTED_PROXIES`. Without a matching entry every request
looks as if it came from the proxy – then everyone shares one address for lockouts and throttling.

1. Open the page once through your own proxy.
2. Run `docker compose logs --tail 20 app`. The access lines start with the address the request came from. With a
   proxy on the same host this is usually the gateway of the Docker network `edge`, `172.31.250.1` out of the box.
3. Enter exactly that address with `/32` and run `docker compose up -d`.

Good to know:

- The app sits in the Docker network `edge` (`172.31.250.0/24`), not in Docker's default network. `172.17.0.1` (the
  default network's gateway) is therefore **not** the right address.
- If your proxy itself runs as a container in the network `edge`, give it a fixed address there below `.128` – that
  is, outside `EDGE_RANGE`, e.g. `172.31.250.20` – and enter exactly that: `TRUSTED_PROXIES=172.31.250.20/32`. A
  dynamic address could go to another container after a restart. Seen from outside, the network is called
  `cobe-news_edge`; the proxy reaches the app there at `http://cobe-news-app:8000`.

> [!WARNING]
> With the **bundled** nginx (`PROXY_ENABLED=1`) never put the Docker gateway into `TRUSTED_PROXIES`. Under Docker
> Desktop all clients arrive there – anyone could then choose their own address via `X-Forwarded-For` and get around
> lockouts. With your own proxy the gateway is fine only because the app port can be reached on the server itself
> (`127.0.0.1`) and nowhere else.

## Address for colleagues {#adresse}

Out of the box Cobe News can only be reached on the server itself (`BIND=127.0.0.1`). That way a new installation is
not on the network before it is secured.

### Opening it to colleagues on the network {#fuer-kollegen}

Done beforehand:

- the first admin is created (setup token) and has set up TOTP,
- a trusted certificate is in place – your own, or the self-signed one distributed to all computers.

Then:

```
BIND=0.0.0.0
BASE_URL=https://news.corp.example:8095
NEWS_HOSTNAME=news.corp.example
TLS_NAMES=10.0.0.5
```

1. Create a DNS record, e.g. `news.corp.example`, pointing to the server's address.
2. Put the values above into the `.env`. `TLS_NAMES` only if someone also opens the page by its IP address – then it is
   needed, though: nginx answers only to known names ([Known names only](#host-namen)). If the
   address should have no port: `PORT=443` and `BASE_URL=https://news.corp.example`.
3. In the server's firewall open the port from `PORT` (8095 out of the box, TCP) to the company network – with the
   http redirect also `HTTP_PORT`.
4. `docker compose up -d`.
5. Check *Settings → HTTPS & certificate*: no hint that the certificate does not cover the name. With the self-signed
   certificate, the certificate changed along with the names – distribute it again.
6. If Entra ID is used: update the redirect URI in the app registration ([below](#was-base-url-steuert)).

### What BASE_URL controls {#was-base-url-steuert}

The current address of this installation: {{base_url}}

| Where | Effect |
|---|---|
| Notifications | links in email, Teams, Slack, Discord, Telegram and webhook point to this address |
| Entra ID | the [redirect URI](term:redirecturi) is `BASE_URL` plus `/api/auth/oidc/callback` |
| Web Push | contact address for the push services, as long as `PUSH_CONTACT` is empty |
| Self-signed certificate | the name from `BASE_URL` is always in it |
| *HTTPS & certificate* | warns when the certificate does not cover this name or the address starts with `http://` |

This installation's redirect URI, exactly as it must be entered in Entra – without a trailing slash:

```
{{redirect_uri}}
```

When `BASE_URL` changes, the redirect URI changes with it. Without updating it in Entra, signing in with Microsoft
fails ([Redirect URI](/docs/anmeldung#entra-redirect-uri)).

### Docker Desktop (Mac, Windows) {#docker-desktop}

Under Docker Desktop (and Colima) the real client addresses are already lost in Docker's port forwarding. All requests
come from the Docker gateway, e.g. `172.31.250.1`.

- **What you see:** in the app's log and under *Users & roles* (last sign-in) everyone has the same address.
- **What Cobe News does:** the gateway counts as a shared address. It is never blocked, failed attempts through it
  are only slowed down; lockouts of single accounts still apply. The limit for Microsoft sign-in starts applies to
  everyone together there.
- **What to do:** for production use a Linux server with Docker – there nginx sees the real addresses. Put a gateway
  that Cobe News does not detect by itself into `SHARED_ADDRESSES`. **Never** into `TRUSTED_PROXIES`.

More on lockouts and shared addresses: [Sessions](/docs/anmeldung#sitzungen).

## Logs {#logs}

Every container writes its own log. Docker keeps up to 3 files of 20 MB per container.

### Reading logs {#logs-lesen}

```bash
cd /opt/cobe-news
docker compose logs -f app
docker compose logs --since 1h app
docker compose logs db-init
docker compose logs proxy
docker compose logs db
```

| Container | When to look |
|---|---|
| `app` | almost always: start (version, address), certificate (`tls:`), fetching (`news:`), notifications (`notify:`, `push:`), source health, directory sync, requests (address, method, path, status, duration); warnings about anything suspicious: `SECRET_KEY is short` (at the start), `csrf check failed` (at most one line per address and minute), `emergency admin: … failed sign-in checks` (at most one an hour) |
| `db-init` | when the app does not start – usually a problem with the database passwords |
| `proxy` | certificate reloaded ("certificate changed – nginx reloaded"), the names nginx answers to ("answering to …"), or nginx does not start |
| `db` | errors of the database itself, e.g. too little memory |

`-f` follows the log continuously (stop with Ctrl+C), `--since 1h` shows only the last hour, `--tail 100` the last 100
lines. Before passing a log on, remove setup tokens and temporary passwords.

### Health check {#health}

On the server itself, the app answers a simple query telling whether it runs and reaches the database:

```bash
curl -s http://127.0.0.1:8096/api/health
```

Normal answer: `{"ok":true,"version":"{{version}}"}`. Docker uses the same query for the status `healthy` in
`docker compose ps`; only then does the proxy start. This query does not appear in the access log.

More than "it runs" – the state of the sources, pending deliveries, the age of the last backup, the result of the
restore test – comes from `/metrics` for Prometheus, with a token of its own: [Metrics](/docs/api#metriken).

## Server commands {#cli}

Some tasks can only be done on the server, with the command `python -m app.cli` in the app's container:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli reset-emergency
```

For scripts and cron use `exec -T` (no terminal). Without a command, or with an unknown one, `app.cli` shows its help.

| Command | Effect |
|---|---|
| `reset-emergency` | new temporary password for the emergency admin; its TOTP and passkeys are removed, its sessions end, a lockout is lifted |
| `new-setup-token` | a new setup token – only as long as there is no emergency admin yet |
| `rotate-vapid` | a new key pair for Web Push (e.g. after a leak); browsers subscribe again by themselves on their next visit |
| `migrate` | bring the database schema to this version's state (the app also does this at every start) |
| `migrate-sqlite FILE` | move a SQLite file of version 0.1.15 (`/data/news.db`) into the empty database; the file stays unchanged |
| `backup` | make a backup now – with `BACKUP_PASSPHRASE` encrypted and with the key |
| `restore FILE` | restore a backup, only with the app stopped ([Restore](/docs/sicherung#wiederherstellung)); options `--yes`, `--use-backup-key`, `--ignore-key`, `--allow-unsigned` |
| `restore-test` | restore the newest backup on trial into the throwaway database and check it – never into the app's database ([Restore test](/docs/sicherung#ruecksicherungs-test)); exit code 0 passed, 1 failed. From the host: `scripts/restore-test.sh` |
| `export` | rules, channels, sources, followed products and users without secrets; `--format json` or `csv`, `--out FILE` (without: JSON to the output) |

With `backup`, `restore` and `restore-test`, `--passphrase-file F` reads the passphrase from a file instead of
`BACKUP_PASSPHRASE`; `--passphrase-file -` reads it from standard input (this is what `scripts/restore-test.sh` does).
Paths like `FILE` are paths **inside the container** – `./data` on the host is `/data` there.

A restore runs with the app stopped, in a container of its own:

```bash
cd /opt/cobe-news
docker compose stop app
docker compose run --rm --no-deps app python -m app.cli restore /data/backups/<file>
docker compose start app
```

## Database {#datenbank}

All data is in PostgreSQL 18 in the container `cobe-news-db`. It is only on the internal network with the app: no port
to the outside, no connection to the internet. The data lives in the volume `cobe-news_db18`.

### Roles and passwords {#db-rollen}

| Role | For | Password |
|---|---|---|
| `cobe_news_app` | the app, backup and restore – owner of the database, but without superuser rights | `POSTGRES_APP_PASSWORD` |
| `cobe_news_restore` | only the [restore test](/docs/sicherung#ruecksicherungs-test) – owner of the throwaway database `cobe_news_restore_test`, no superuser, may not create databases or roles or connect to the app's database | `POSTGRES_RESTORE_PASSWORD` |
| `cobe_news` | the container's superuser – only the short service `db-init` uses it | `POSTGRES_PASSWORD` |

- **Never change** `POSTGRES_PASSWORD`: the database was created with it. A different password in the `.env` locks
  `db-init` out, and the app does not start. Then put the old password back into the `.env`.
- `POSTGRES_APP_PASSWORD` may change (at least 16 characters): `db-init` sets it again at every start.
- So may `POSTGRES_RESTORE_PASSWORD`. When it is set, `db-init` also creates the role `cobe_news_restore` and the
  throwaway database at every start, or checks their rights (log: `cobe_news_restore ready`).
- If `db-init` fails, the app does not start – the reason is in `docker compose logs db-init`.

The schema comes from migrations and is brought to the app's version at every start. The container's memory limit is
set by `DB_MEM` (`512m` out of the box); with a great many stories and Vendor News data, more helps.

### A look inside {#db-zugriff}

```bash
cd /opt/cobe-news
docker compose exec db psql -U cobe_news cobe_news
```

This opens `psql` as the superuser. Only read (e.g. `\dt` for the tables, `\q` to quit) – changes by hand bypass the
app's checks. For backups always use the built-in ones ([Backup](/docs/sicherung#ueberblick)), not a `pg_dump` of
your own. Moving from older versions (SQLite up to 0.1.15, roles from 0.1.22) is described in the repository's operations
reference (`docs/BETRIEB.md`, German), section "PostgreSQL".

## Audit log {#protokoll}

**Settings → Audit log** (admins only) shows who changed what in Cobe News and when: who (the account with its name at
the time – or the system, the directory sync, the command line), what, when, from which address and on what. A click on
an entry shows the changed fields with before and after. You can filter by area, person, time range and free text
(name, target, address).

An entry is written in the same transaction as the change itself: if the change is refused (for instance because another
admin saved in between), no entry is made either. Entries can neither be edited nor deleted one by one – not by admins
either.

### What is logged {#protokoll-inhalt}

- **Accounts & roles:** account created, changed, deleted, switched on and off, blocked and unblocked, password or TOTP
  reset, sign-in lock lifted, role changed; one's own password and TOTP; [passkeys](/docs/anmeldung#passkeys) added,
  renamed and removed (by their owner or by an admin, with the passkey's name and the number of sessions it ended) and
  a passkey whose counter went back (a possible clone, [What is checked](/docs/anmeldung#passkeys-pruefung)); ended
  sessions – also under [My sessions](/docs/anmeldung#meine-sitzungen) and by an admin, with the scope (one, all others,
  all) and the number.
- **Sign-in:** changes to AD/LDAP, Entra ID (also the [MFA proof](/docs/anmeldung#entra-mfa-nachweis) and the
  authentication context), [Second factor for everyone](/docs/anmeldung#zweiter-faktor-alle) and the session limits,
  group mappings, the setup, sign-ins of **admins**
  with the method (password, password and TOTP, AD/LDAP, passkey, Entra ID, Entra ID and TOTP), account locks and address blocks after
  failed attempts – also after refused passkey sign-ins –, and when the failed attempts of the
  [emergency admin](/docs/anmeldung#notfall-admin) exceed the hourly budget.
- **API tokens:** created and revoked (name, scopes, validity).
- **Channels & rules, teams, sources & products:** created, changed, deleted; for teams also groups, members, products,
  assignment, weekly review and absences. For channels also ntfy, Gotify and Mattermost (topic and tokens as "changed"
  only) and every [resend](/docs/benachrichtigungen#erneut-senden) from the delivery log (channel, delivery, whether it
  worked).
- **Versions and suggestions:** [versions confirmed](/docs/vendor-news#versionen-pruefen) – one at a time or all of a
  product or team (with the number), by admins and by readers in the product's team; answers to
  [product suggestions](/docs/vendor-news#vorschlaege-beantworten): accepted, rejected, duplicate (with the product and
  the answer, cut to 200 characters).
- **Settings:** news, Vendor News (including the "review versions" interval), e-mail delivery, teams, passkeys on/off,
  backup, restore test, audit log.
- **Backup & export:** backup made, old backups removed, backup restored (command line), restore test started, export
  downloaded, audit log exported.
- **Directory sync:** what AD or Entra ID change about access – accounts switched off or on again, roles from the group
  mapping, a team load (one summary per run).

Failed sign-ins are not logged one by one – with a password or with a passkey: anyone can send them from outside, and a
password typed into the name field would otherwise end up in the log. The lock they cause is logged instead
([Failed attempts and lockouts](/docs/anmeldung#sperren)). Sign-ins of readers are only kept as "last signed in" on the
account. Not logged either: a rule's dry run (it changes nothing), a reader's new product suggestion (only the answer to
it) and reading the audit log itself – exporting it is.

### What is never in it {#protokoll-geheimnisse}

No secret value – only that it changed: passwords (local, bind password, SMTP), the Entra ID client secret, webhook
addresses (their token is in the path), bot tokens, ntfy topics and tokens, Gotify tokens, HMAC secrets and header
values, the NVD API key, TOTP keys, API
tokens (not even their beginning), the hashes of earlier passwords ([password rules](/docs/anmeldung#benutzer-anlegen))
and the backup passphrase. Addresses appear as scheme and host only
(`https://hooks.example.com/…`), overlong texts are cut. One central check in the server decides this for every field; a
test fails as soon as a new field looks secret and would not be redacted.

### Retention {#protokoll-aufbewahrung}

By default entries are kept for **365 days**, adjustable from 90 to 3650 days under **Audit log → Retention**. The app
deletes older entries hourly. A shorter period needs a fresh confirmation – older entries then go with the next
clean-up. The audit log is part of every [backup](/docs/sicherung#ueberblick); a restored backup brings its audit log
with it (entries after its time are then missing), and the restore itself is recorded as a new entry afterwards.

### Export {#protokoll-export}

**Export CSV** downloads the entries with the chosen filters (UTF-8, newest first, at most 100,000 rows – narrow the
time range for older ones). Cells starting with `=`, `+`, `-` or `@` get an apostrophe in front so that a spreadsheet
does not run them as a formula. The details are in the last column as JSON. For counts without names, `/metrics` gives
the number of entries per area ([Metrics](/docs/api#metriken)).
