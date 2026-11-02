---
title: Backup & restore
summary: Back up the database, encrypt it, copy it off the host daily by cron, test-restore the backup automatically, restore it – also on a new server – and export the settings without secrets.
audience: admin
---

## Overview {#ueberblick}

A backup is **one file** with the whole database: sources, stories, users, channels, rules, Vendor News, settings. It
is made with "Back up now" in the app or by command (e.g. daily by [cron](term:cron)). The page for it: *Settings →
Backup & export* (group "Operations", [open directly](/settings/backup)).

### What a backup contains {#inhalt}

- `db.dump` – the database as a `pg_dump` in custom format,
- `manifest.json` – app version, schema revision, rows per table, checksums and the fingerprint of the key. Counts and
  dump come from the same state of the database,
- `manifest.sig` – the signature (see [Signature](#signatur)),
- only in encrypted backups: the [master key](term:masterkey) (see [Encryption](#verschluesselung)).

| File | When |
|---|---|
| `cobe-news-YYYYMMDD-HHMMSS.tar` | without a passphrase – not encrypted, **without** the key |
| `cobe-news-YYYYMMDD-HHMMSS.tar.enc` | with `BACKUP_PASSPHRASE` – encrypted, **with** the key |
| `…-pre-restore.tar` or `.tar.enc` | automatically, right before a restore |

The time in the name is UTC.

**Where:** in the container under `/data/backups`, on the server in the installation folder under `data/backups/`,
i.e. `/opt/cobe-news/data/backups/`. Only the app process can read the files (folder 0700, files 0600).

### Retention {#aufbewahrung}

**"Retention"** sets how many backups stay on the server: the last 3, 7, 14, 30 or 90 (default: 7). When a new backup
is done, the oldest beyond that are deleted – **also those made by cron**.

- Keeping fewer deletes older backups **at once**. The page asks first ("Delete older backups?" – "Delete and save")
  and requires you to [confirm your identity again](/docs/anmeldung#erneut-bestaetigen).
- Backups made before a restore (`…-pre-restore…`) do not count; they stay 30 days.

> [!WARNING]
> A backup on the same server does not help when the server fails. Also copy the files to another system – see
> [cron](#cron).

## Back up now {#jetzt-sichern}

1. Open *Settings → Backup & export*.
2. Click **"Back up now"**.

The backup goes on in the background, even for a big database. The page says "Backup running …", the button reads
"Backing up …" with "Running since …", and the page asks every 2 seconds. When it is done, "Backup … created" or an
error message appears. Only **one** backup runs at a time – one started by cron or command locks the button too.

The head of the section shows the state:

| Shown | Meaning |
|---|---|
| Backed up | last backup succeeded, less than 7 days old |
| Older than 7 days | the last successful backup is older – back up soon |
| Last backup failed | the last attempt failed |
| No backup yet | there has been none |

**"Last backup"** names file, time, size and rows – or for a failure "Failed on …" with the reason and the technical
message. Common reasons:

| Message | Fix |
|---|---|
| The passphrase (BACKUP_PASSPHRASE) is too short | use at least 12 characters |
| pg_dump did not answer in time | check database and memory, try again |
| pg_dump failed | read the technical message and `docker compose logs app` |

Below is the list of backups on the server (file, created, size, key – "Encrypted, with key" or "Without key"), the
newest 10, all with "Show all". Next to it are the commands to restore the newest backup, with the button "Copy the
restore commands".

By command on the server (same result, same retention):

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli backup
```

The output names file, size, rows, duration and whether it is encrypted. Exit code 0 means backed up.

## Encryption and key {#verschluesselung}

Cobe News stores secrets (webhook URLs, SMTP and LDAP passwords, the Entra secret, the NVD key, TOTP of local accounts)
encrypted in the database. The **master key** for that is `SECRET_KEY` in the [.env](term:envfile) or, if that is
empty, the file `data/secret.key`.

| | without a passphrase (`.tar`) | with `BACKUP_PASSPHRASE` (`.tar.enc`) |
|---|---|---|
| File encrypted | no | yes, the whole file |
| Master key included | no – secrets stay encrypted with it | yes |
| Needed to restore | file **and** this installation's master key | file **and** passphrase |
| Authenticity | signature | passphrase (a changed file cannot be decrypted) |

**Passphrase:** at least 12 characters, otherwise nothing is backed up. Encryption uses scrypt and AES-256-GCM in
blocks – a changed, reordered or truncated file is noticed when decrypting.

- If `BACKUP_PASSPHRASE` is in the `.env`, every backup is encrypted, also "Back up now". The page then says "Backups
  are encrypted with BACKUP_PASSPHRASE …".
- **Better:** do **not** put the passphrase into the `.env`, hand it only to the cron job (see [cron](#cron)). Then the
  cron backups are encrypted, and "Back up now" makes a backup without the key.
- Keep the passphrase away from the server, e.g. in a password manager. Without it a `.tar.enc` cannot be opened.

**Keep the master key separately:** `SECRET_KEY` (or a copy of `data/secret.key`) does not belong with the backups but
in another safe place. Without it the secrets of a `.tar` backup cannot be read – webhook URLs, passwords, the Entra
secret and TOTP then have to be set up again.

> [!NOTE]
> During a backup or restore the dump and (when encrypting) the key lie unencrypted for a moment in
> `data/.backup-work/` – next to `data/backups/`, not in it. Leftovers of a run that was killed are removed by the next
> backup, restore or app start once they are older than 6 hours.

### Signature {#signatur}

Every backup is signed (`manifest.sig`, [HMAC](term:hmac)-SHA256 with a key derived from the master key). This lets the
restore tell that an unencrypted file comes from **this** installation and was not changed afterwards. The checksums in
the manifest alone do not prove that – they are in the same file.

## Daily backup by cron {#cron}

Example: an encrypted backup every night at 2:30, then copied to another system.

**1. Create a passphrase** – at least 12 characters, store it in a password manager.

**2. Put the passphrase on the server** – in a file only root can read, without showing it and without shell history:

```bash
sudo bash -c 'umask 077; read -rsp "Passphrase: " P; echo; printf "%s\n" "$P" > /root/.cobe-news-backup-pass'
sudo chown root:root /root/.cobe-news-backup-pass
sudo chmod 600 /root/.cobe-news-backup-pass
```

**3. Create the cron file** – `/etc/cron.d/cobe-news-backup` with one line:

```
30 2 * * * root cd /opt/cobe-news && docker compose exec -T -e BACKUP_PASSPHRASE="$(cat /root/.cobe-news-backup-pass)" app python -m app.cli backup >>/var/log/cobe-news-backup.log 2>&1 && rsync -a --exclude='.*' --exclude='*.partial' data/backups/ backup-host.corp.example:/srv/cobe-news/
```

**4. Test** – run the command once by hand as root and check `/var/log/cobe-news-backup.log`. Afterwards the page shows
"Backed up", and the file is in the list with "Encrypted, with key".

Notes:

- Without a passphrase: leave out `-e BACKUP_PASSPHRASE=…` – then be sure to keep the master key separately.
- `rsync` needs SSH access from root to the target system (`backup-host.corp.example` is an example). It only copies
  when the backup worked (`&&`). `--exclude` keeps half-written files from being copied.
- Never write the passphrase into a log, the `.env`, tickets or chats.
- The retention in the app only applies to the server; how long the target system keeps the copies is up to you there.

## Restore {#wiederherstellung}

A restore **replaces the whole database** with the state of the backup. It only works on the server, by command, with
the app stopped – never from the browser.

**1. Stop the app** – in the installation folder; the database keeps running:

```bash
cd /opt/cobe-news
docker compose stop app
```

**2. Restore the backup** – an unencrypted one:

```bash
docker compose run --rm --no-deps app python -m app.cli restore /data/backups/cobe-news-20261030-023000.tar
```

An encrypted one: read in the passphrase first (it appears neither on screen nor in the history), then restore:

```bash
read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE
docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-20261030-023000.tar.enc
unset BACKUP_PASSPHRASE
```

**3. Confirm** – the command shows what it restores (date, version, schema, rows) and whether the file is genuine
(`Genuine: encrypted with the passphrase.` or `Genuine: signed with this installation's key.`). Type `RESTORE` to
confirm. Before that it backs up the current state (`Current state saved first: …-pre-restore…`) – that is the way
back, encrypted with the same passphrase as the restore. At the end it says `Restored: … rows, schema now …`.

**4. Start the app:**

```bash
docker compose start app
```

**5. Check** – sign in, look at *Version & changelog*, *Settings → Backup & export* shows the pre-restore backup as the
last backup, test a channel.

Anyone who signed in only after the backup was made signs in again; sign-ins that existed at the time of the backup are
valid again. A backup of an older version is brought up to this version; one of a **newer** version is refused.

The commands for the newest backup are also in the app: "Copy the restore commands".

### What is checked {#wiederherstellung-pruefungen}

Before anything is changed:

- **Authenticity:** passphrase (encrypted) or the signature with this installation's key (unencrypted). A signature
  that does not match always stops it.
- **Content:** only the expected files, checksums, schema revision, fingerprint of the key. The dump may only contain
  what Cobe News creates itself – otherwise it stops.
- **No running app:** if anything else is still connected to the database, the command stops ("stop the app first").

The restore runs in **one** transaction with the app's own database role (no superuser). Afterwards the rows per table
and the schema are compared with the backup. If anything differs or fails, everything is rolled back – the database
stays as it was.

### Another key, old backup {#wiederherstellung-optionen}

| Option | Effect |
|---|---|
| `--yes` | no "RESTORE" question – needed when there is no terminal (script) |
| `--use-backup-key` | takes the master key from an **encrypted** backup into `data/secret.key`; the old one is kept next to it |
| `--ignore-key` | restores despite another key – stored secrets are unreadable afterwards and must be entered again |
| `--allow-unsigned` | restores an unencrypted backup **without** a signature (before version 0.1.22) or with another installation's key |
| `--passphrase-file FILE` | the passphrase from a file (path in the container) instead of `BACKUP_PASSPHRASE` |

If the backup was made with another master key, the command stops with an explanation. Then choose either
`--use-backup-key` (only for `.tar.enc`) or `--ignore-key`, not both. If `SECRET_KEY` is set in the `.env`,
`--use-backup-key` refuses: remove `SECRET_KEY` from the `.env` (or put the backup's key there) and run the command
again.

> [!WARNING]
> Use `--allow-unsigned` only for a file you know for sure is your own. A crafted backup can bring any data and admin
> accounts. The command then warns explicitly (`WARNING: … not checked`).

## Restore test {#ruecksicherungs-test}

A backup is only worth something if it can be restored. The restore test checks exactly that – regularly and by
itself: it really restores the **newest** backup, but into a **throwaway database** of its own
(`cobe_news_restore_test`), **never** into the real one. Afterwards it empties it again.

The page for it: *Settings → Backup & export*, tab **"Restore test"**. It shows:

- a switch (on out of the box),
- **"Who starts the test"**: the app on a schedule, or "The host (cron script)" (see [By host cron](#ruecksicherungs-test-host)),
- how often (every 1, 7, 14 or 30 days, default 7) and from which hour (UTC, default 03:00),
- the last test (time, file, duration, tables and rows – or the error with its code), the next planned test, and a
  hint when the last test is more than a day overdue,
- **"Test now"** starts a test at once.

The app starts its test within 3 hours from the set hour – so it still runs after a restart at 03:10. It runs at low
CPU priority, only one at a time, never during a backup, and stops after **1 hour**. The outcome is shown on the page
and in the [metrics](/docs/api#metriken). There is no message through the channels – set up an
[alert in Prometheus](/docs/api#alarme) for that.

**Why a role of its own:** the app's role (`cobe_news_app`) gets **no** additional right for the test. The test works
as its own role `cobe_news_restore`: no superuser, may not create databases or roles, owns only the throwaway database
and may not even connect to the app's database. Before every test the app asks the database server whether this is so
– otherwise it stops (code `unsafe`). So even a bug in the program can never restore into the real data: the database
server would not allow it.

What it costs:

- **Space:** during the test, a second copy of the data lies in the database (disk and WAL), plus briefly the unpacked
  dump in `data/.backup-work/`. Plan enough free space – at least as much as the database is big.
- **Data:** the copy contains the same as the backup, including personal data (stored secrets stay encrypted). It
  only stays until the end of the test – the throwaway database is emptied after a failure too. If a test was killed
  (e.g. by a restart), the next one empties it first.

### Setting up {#ruecksicherungs-test-einrichten}

A **new** installation has everything already: `scripts/setup-env.sh` generates the password, `db-init` creates role
and database. Set up an **existing** installation once like this:

**1. Update the code** – as with every [update](/docs/betrieb#update-schritte) (`git pull`).

**2. Add the password** – this adds `POSTGRES_RESTORE_PASSWORD` to the `.env`; everything else in it stays as it is:

```bash
cd /opt/cobe-news
scripts/setup-env.sh
```

**3. Restart** – `db-init` creates or checks the role and the throwaway database at every start. The log then says
`cobe_news_restore ready`:

```bash
docker compose up -d --build
docker compose logs db-init
```

**4. Try it** – *Settings → Backup & export → Restore test*, "Test now". If there is no backup yet, choose "Back up
now" first.

> [!WARNING]
> If the newest backup is encrypted with a passphrase the app does **not** know (recommended: `BACKUP_PASSPHRASE` only
> in the cron job, see [cron](#cron)), the app's test fails with the code `passphrase`. Then let the host start the
> test: [By host cron](#ruecksicherungs-test-host).

`POSTGRES_RESTORE_PASSWORD` must be at least 16 characters long. If it is shorter, `db-init` stops and the app does not
start – `setup-env.sh` generates 40 characters.

**Not wanted?** Leave `POSTGRES_RESTORE_PASSWORD=` empty in the `.env` (keep the line, otherwise `setup-env.sh` adds it
again) and run `docker compose up -d`. Then `db-init` creates nothing, and the tab says "not set up". A role and
database created earlier stay. To remove them:

```bash
cd /opt/cobe-news
docker compose exec db psql -U cobe_news cobe_news -c "DROP DATABASE cobe_news_restore_test" -c "DROP ROLE cobe_news_restore"
```

### By host cron {#ruecksicherungs-test-host}

For backups whose passphrase only the cron job knows:

**1. Switch over** – under *Restore test*, set "Who starts the test" to **"The host (cron script)"** and save. The app
then starts no test by itself any more.

**2. Passphrase file** – it is already in a file only root may read (see [cron](#cron), step 2).

**3. Create the cron file** – e.g. `/etc/cron.d/cobe-news-restore-test`, here every Sunday at 04:30, i.e. after the
daily backup:

```
30 4 * * 0 root /opt/cobe-news/scripts/restore-test.sh --passphrase-file /root/.cobe-news-backup-pass >>/var/log/cobe-news-restore-test.log 2>&1
```

**4. Test** – run the command once by hand as root and check `/var/log/cobe-news-restore-test.log`.

The script reads the file on the host and hands the passphrase to the container on standard input. It never appears
on a command line, in the container or in a log. If the file is readable by others, the script warns (`chmod 600`).
Exit code 0 means passed, 1 failed, 2 wrong use. The outcome appears on the page and in the metrics, as with the app.

Without a passphrase (unencrypted backup, or `BACKUP_PASSPHRASE` in the `.env`): `scripts/restore-test.sh` without an
option. Underneath is this command:

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli restore-test
docker compose exec -T app python -m app.cli restore-test --passphrase-file - < /root/.cobe-news-backup-pass
```

> [!NOTE]
> The test from the command line does not check whether a backup is running. So do not put the cron line into the
> minutes of the daily backup.

### What is checked {#ruecksicherungs-test-pruefungen}

The same checks as a real [restore](#wiederherstellung-pruefungen):

1. **The file:** decrypted with the passphrase (encrypted) or the signature with this installation's key
   (unencrypted); only the expected files; checksums; the dump's table of contents; a schema revision this version
   knows.
2. **The restore:** `pg_restore` → `psql` into the throwaway database, in **one** transaction, without errors.
3. **The content:** the rows per table **exactly** as in the backup's manifest, and the schema **exactly** that of a
   freshly migrated database of the same revision.
4. **The revision:** afterwards the schema revision (`alembic_version`) of the restored database is the backup's.

Finally the throwaway database is emptied (schema dropped and created anew).

If a test fails, the page names a code:

| Code | Meaning | What to do |
|---|---|---|
| `not_configured` | no throwaway database set up | [Setting up](#ruecksicherungs-test-einrichten) |
| `unsafe` | the target is the app's database or role, or the test's role has too many rights (superuser, may create databases or roles, may connect to the app's database, is a member of the app's role, does not own the throwaway database) | `docker compose up -d` (db-init sets the rights again), read `docker compose logs db-init`; never grant rights by hand |
| `busy` | another test is running (not recorded as an outcome) | wait |
| `no_backup` | there is no backup | "Back up now" |
| `passphrase` | the newest backup is encrypted, the app does not know the passphrase | [By host cron](#ruecksicherungs-test-host) |
| `verify` | the file failed a check: wrong passphrase, signature of another key or none, missing or foreign files, checksum, table of contents, schema of a newer version | read the message – a restore of this backup would fail too |
| `connect` | the throwaway database cannot be reached (wrong password, role or database missing) | `docker compose up -d`, `docker compose logs db-init` |
| `restore` | `pg_restore` or `psql` reported an error | read the message and `docker compose logs app` |
| `rows` | the rows per table differ from the manifest | back up again and test again |
| `schema` | the schema differs from that of a freshly migrated database | read the message; the backup contains something Cobe News does not create itself |
| `revision` | after the restore, another schema revision than in the backup | read the message, test again |
| `timeout` | not done within 1 hour | check space and load of the server; move the test to quieter hours |
| `failed` | an unexpected error | read `docker compose logs app` |

## New server {#neuer-server}

For a disaster you only need:

- the backup file, and
- for `.tar.enc` the passphrase, for `.tar` the old `SECRET_KEY` or the old file `data/secret.key`.

**1. Install** – get Cobe News onto the new server into `/opt/cobe-news` and run `scripts/setup-env.sh` (see
[Start and stop](/docs/betrieb#start-stopp)). Take over settings such as `BASE_URL` from the old `.env`.

- For `.tar`: put the old `SECRET_KEY` into the `.env` – or place the old `secret.key` in `data/`.
- For `.tar.enc`: **no** `SECRET_KEY` in the `.env` – the key comes from the backup.

**2. Place the backup** – copy it to `data/backups/` and give it to the container's user (UID 10001):

```bash
cd /opt/cobe-news
sudo mkdir -p data/backups
sudo cp /path/to/cobe-news-20261030-023000.tar.enc data/backups/
sudo chown -R 10001 data
```

**3. Start the database** – build the image and create only the (empty) database with the app's role:

```bash
docker compose build && docker compose up -d db-init
```

**4. Restore** – with `--use-backup-key`, so that the key is taken from the backup:

```bash
read -rs BACKUP_PASSPHRASE && export BACKUP_PASSPHRASE
docker compose run --rm --no-deps -e BACKUP_PASSPHRASE app python -m app.cli restore /data/backups/cobe-news-20261030-023000.tar.enc --use-backup-key
unset BACKUP_PASSPHRASE
```

For a `.tar` without `-e BACKUP_PASSPHRASE` and without `--use-backup-key`. Into an empty database it restores without
a pre-restore backup; `RESTORE` is asked all the same.

**5. Start and check** – as for the [restore](#wiederherstellung):

```bash
docker compose up -d
```

If the address (`BASE_URL`) changes with the move, the redirect URI for Entra ID changes too – see
[Address](/docs/betrieb#adresse).

## Export {#export}

The export holds the settings to read or carry over – **no backup** and **without secrets**.

In *Settings → Backup & export*, section "Export":

- **"Download JSON"** – one JSON file,
- **"Download CSV (ZIP)"** – one CSV file per area in a ZIP (UTF-8, opens correctly in Excel).

The export contains the names and e-mail addresses of all users and therefore requires you to
[confirm your identity again](/docs/anmeldung#erneut-bestaetigen).

| Area | Content |
|---|---|
| Rules | name, on/off, kinds, severities, sources, language, channels |
| Channels | name, type, settings without secrets, **which** secrets are set, last error |
| Sources | name, address, built-in or own, on/off, last fetch, error |
| Followed products | product, note, tags, CPE, versions with label and count |
| Users | user name, display name, e-mail, role, origin, active, whether TOTP is set up, last sign-in |

Not included: webhook URLs, tokens, passwords, password hashes, TOTP secrets.

By command on the server (without confirming again – whoever gets onto the server may do this anyway):

```bash
cd /opt/cobe-news
docker compose exec -T app python -m app.cli export --format csv --out /data/export.zip
docker compose exec -T app python -m app.cli export > export.json
```

Without `--out`, JSON goes to standard output. The file contains personal data – delete it after use.
