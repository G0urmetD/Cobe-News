---
title: Sign-in & users
summary: Set up local accounts, the emergency admin, Active Directory and Microsoft Entra ID, map groups to roles, understand sessions and lockouts.
audience: admin
---

## Overview {#ueberblick}

Cobe News knows three ways to sign in. They can be combined – the sign-in page only shows what is switched on and
completely set up.

### Sign-in methods {#anmeldearten}

| Method | Who creates the account | Second factor | Role comes from |
|---|---|---|---|
| **Local** | an admin under *Settings → Users & roles* | [TOTP](term:totp) or a [passkey](#passkeys) in Cobe News – required for admins (TOTP), optional for readers or [required for everyone](#zweiter-faktor-alle) | the setting on the account |
| **Active Directory / LDAP** | created automatically at the first sign-in | TOTP in Cobe News – required for admins, optional for readers or [required for everyone](#zweiter-faktor-alle) | the [role mapping](#gruppen-rollen) |
| **Microsoft Entra ID** | created automatically at the first sign-in | Microsoft asks for it ([Conditional Access](term:conditionalaccess)); where a second factor is required and the token does not prove it, TOTP in Cobe News as well ([MFA proof](#entra-mfa-nachweis)) | the [role mapping](#gruppen-rollen) |

The sign-in page then shows "Sign in with Microsoft" (Entra ID) and below it the tabs "Active Directory" and
"Local account".

### Roles {#rollen}

- **Admin** – settings, sources, notification rules, users and sign-in. TOTP is required – for Entra accounts only
  while Microsoft's token does not prove a second factor ([MFA proof](#entra-mfa-nachweis)).
- **Reader** – reads news, marks them read and sets up their own desktop notifications.

More on what each role may do: [Roles](/docs/erste-schritte#rollen).

### The emergency admin {#ueberblick-notfall}

The first account from the initial setup is the **emergency admin**: local, always an active admin, never switched off
by the directory and never locked by failed attempts. It is the way in when AD or Entra ID fail or are set up wrongly.
Details: [Emergency admin](#notfall-admin).

### Order of setup {#einrichtung-reihenfolge}

1. Initial setup with the setup token – the emergency admin is created.
2. Create further local accounts if needed.
3. Set up AD and/or Entra ID under *Settings → Sign-in*, test, save.
4. Map groups to roles under *Settings → Users & roles → Role mapping*. **Without a mapping nobody from AD or Entra ID
   can sign in.**
5. Sign in with a test account from each group and check the role.

## Local users {#lokale-benutzer}

You manage local accounts under [Settings → Users & roles](/settings/users), tab *Users*. AD and Entra users appear in
the same list once they have signed in (with their origin *Local*, *Active Directory* or *Entra ID*).

### Create {#benutzer-anlegen}

1. Open *Settings → Users & roles* and choose "Create local user".
2. Enter user name, display name, optionally an email, and the role.
3. Click "Create". Creating an admin account asks you to [confirm](#erneut-bestaetigen) who you are.
4. Cobe News shows a temporary password **once** (four groups of five characters with hyphens). Copy it, hand it over
   safely and close with "Noted". It cannot be shown again.
5. At the first sign-in the person chooses their own password. Until then the account is marked *Temporary password
   expires on …*.

A temporary password is valid for **7 days** from issue (adjustable from 1 to 30 days, [Timeouts](#sitzungen-zeitlimits))
– also one from "Reset password" and from `reset-emergency`. After that Cobe News refuses the sign-in with it ("Temporary
password expired – ask an admin for a new one"), and the list shows *Temporary password expired*. An admin then issues a
new one with "Reset password". A longer setting applies to passwords already issued too (counted from their issue). A
person's own password never expires.

Password rules: at least 12 characters, no common password, not containing the user name, and none of the account's
**last five passwords** (the current one and the four before it) – "one of the last five passwords". For this
Cobe News keeps only the Argon2 hashes of earlier passwords, never the password itself; they appear nowhere (no audit log,
no answer, no export). It applies to changing one's own password and to replacing a temporary one. Temporary passwords
(set by an admin) never enter the list – the password before them does: after a reset the old one cannot be chosen
again. Local accounts only; AD and Entra passwords are the directory's business.

### Second factor (TOTP) {#benutzer-totp}

- **Admins** (local and AD) must set up an authenticator app at their first sign-in ("Set up a second factor": scan
  the QR code, enter the 6-digit code). They cannot continue without it.
- **Readers** may set up TOTP voluntarily – in the user menu at the bottom left under *Profile & security*. With
  [Second factor for everyone](#zweiter-faktor-alle) on it is required for them too.
- **Entra accounts** get TOTP in Cobe News only where a second factor is required and Microsoft's token does not prove
  it – set up at the sign-in ([MFA proof](#entra-mfa-nachweis)). Otherwise Microsoft asks for the second factor.
- Five wrong codes during one sign-in end that attempt ("Too many wrong codes – please sign in again.").

Everyone changes their own password and TOTP under *Profile & security*, see
[Own account](/docs/erste-schritte#eigenes-konto).

### Second factor for everyone {#zweiter-faktor-alle}

[Settings → Sign-in](/settings/auth), card *Second factor*, switch "Second factor required for everyone" – **off by
default**: after an update nobody signs in differently than before. Saving requires [confirmation](#erneut-bestaetigen)
and is recorded in the [audit log](/docs/betrieb#protokoll).

With it on, every sign-in needs a second factor – not only the admins':

| Account | What happens at the next sign-in |
|---|---|
| Local, without TOTP and without a passkey | After the password the step "Set up a second factor": authenticator app **or** "Set up a passkey instead" (when [passkeys](#passkeys) are on and the page runs at their address). Signed in afterwards. |
| Local, with a passkey, without TOTP | The sign-in **with the passkey** needs nothing more. Signed in with the password, the set-up step comes – with the hint to rather sign in with the passkey. |
| Local or AD, with TOTP | as before: password, then code. |
| AD, without TOTP | set-up step (authenticator app only – there are no passkeys for AD accounts). |
| Entra ID | As for admins: if the token proves a second factor, signed in; otherwise Cobe News' own TOTP ([MFA proof](#entra-mfa-nachweis)). |

- **Running sessions** stay as they are until they expire or the person signs out – the requirement applies from the
  next sign-in. To be sure at once, end the accounts' sessions (*Users & roles* → "Sessions & passkeys").
- While the switch is on, nobody without a passkey can remove their TOTP under *Profile & security* ("A second factor
  is required …").
- Switching it off takes nothing away: apps and passkeys set up stay.

### Manage {#benutzer-verwalten}

In each row of the user list:

| What | Where | Notes |
|---|---|---|
| Change role | *Role* selection | Local accounts only – for AD/Entra the role follows the group. Requires confirmation. All sessions of the account end. |
| Disable / enable | *Active* switch | Sessions end at once. For an admin account with confirmation. A directory account you disabled is never switched on again by the directory sync. |
| Block permanently | "More actions" → "Block permanently" | Also for an account the sync or Teams has switched off already (its switch is off already). Afterwards it shows *Blocked by an admin*: neither the sync nor Teams nor a sign-in switches the account on again. Requires confirmation, all sessions end. |
| Lift the permanent block | "More actions" → "Lift the permanent block" | Directory account: the sync decides again (*Waiting for the sync*) – active as soon as a sign-in or the next sync finds a mapped group or a team. Local account: active again at once. Requires confirmation. |
| Unlock | "More actions" menu → "Unlock" | Only available when the account is locked after failed attempts (marked *Locked (… min)*). |
| Reset password | "More actions" → "Reset password" | Local accounts only. New temporary password, shown once. The account's passkeys are removed. All sessions end. |
| Reset TOTP | "More actions" → "Reset TOTP" | Local and AD accounts with TOTP. Admins set up a new app at their next sign-in. All sessions end. |
| Sessions & passkeys | "More actions" → "Sessions & passkeys" | End the account's running sessions, remove passkeys – each with confirmation, see [My sessions](#meine-sitzungen) and [Passkeys of an account](#passkeys-admin). |
| Delete | "More actions" → "Delete" | Deletes the account and its read marks. A directory account comes back at the next sign-in while the group fits – to lock someone out, disable instead. |

Why an account is off shows in its mark (explained on hover): *Blocked by an admin* is the permanent block. *No team any
more*, *Teams switched off*, *No role group any more*, *Disabled in the directory* and *No longer in the directory* were
set by the sync – it switches such accounts on again by itself as soon as they fit again. Whoever should not come back
gets "Block permanently".

Resetting and deleting always require [confirmation](#erneut-bestaetigen). Protected are:

- **your own account** – cannot be demoted, disabled, reset or deleted (use *Profile & security*),
- **the emergency admin** – always stays an active admin; reset only on the server ([Emergency admin](#notfall-admin)),
- **the last active admin** – cannot be demoted, disabled or deleted.

> [!NOTE]
> If two admins change the same account at the same time, the last one does not silently win: whoever saves an
> outdated state sees "Changed by someone else meanwhile" and reloads.

## Passkeys {#passkeys}

Local accounts can sign in with a [passkey](term:passkey) ([WebAuthn](term:webauthn)) instead of password and TOTP. How
people set one up: [Passkeys](/docs/erste-schritte#passkeys). AD and Entra accounts keep signing in through their
directory – there are no passkeys for them.

### Requirements {#passkeys-voraussetzungen}

- **HTTPS and a host name** in `BASE_URL` (e.g. `https://news.corp.example`). The host name is the *RP ID* every passkey
  is bound to; the address in `BASE_URL` (with port) is the only one where passkeys work. Plain HTTP only for
  `localhost`.
- **No IP address**: browsers allow no passkeys for an IP address. If `BASE_URL` holds an IP,
  [Settings → Sign-in](/settings/auth) shows *Not possible* with the reason, and the sign-in page offers no passkey.
- If someone opens Cobe News at another address (IP, another name), no passkey button appears there.

### Switching on and off {#passkeys-schalter}

[Settings → Sign-in](/settings/auth), card *Passkeys*, switch *Allow passkeys* – **on** by default: nobody has a passkey
before setting one up themselves, and a passkey is safer than password + TOTP (it cannot be phished). Saving requires
[confirmation](#erneut-bestaetigen). Off means: no new passkeys, no passkey sign-in. Passkeys already set up stay stored
(visible, removable) and work again once the switch is on.

### Changing the host name {#passkeys-hostname}

> [!WARNING]
> If the host name in `BASE_URL` changes (e.g. from `news.corp.example` to `secnews.corp.example`), **all** existing
> passkeys stop working – they belong to the old name. Everyone then signs in with their password, removes the old
> passkey and sets up a new one. Another port alone does not change the RP ID, but it does change the address where
> passkeys work.

### What is checked {#passkeys-pruefung}

- **Two factors**: Cobe News requires *user verification* – the device checked fingerprint, face or PIN. A passkey
  without that check is refused (when set up and at every sign-in). After that the usual rules apply: a temporary
  password is replaced first, an admin without TOTP sets it up.
- **Origin and one-time challenge**: exactly the address from `BASE_URL`, the RP ID, a challenge valid once and for three
  minutes only, bound to this browser or session. Challenges live in memory only, never in the database or a backup.
- **Stored** are only the id, the public key, the counter, the transports, the name and the times – the secret key never
  leaves the device. A backup therefore holds public keys only.
- **Counter**: if a passkey's counter goes backwards, it may have been copied. The sign-in is not refused (otherwise a
  copy could lock the owner out); the passkey then shows *Check*, the log a warning. Synced passkeys (iCloud, Google,
  password managers) do not count – their counter is always 0.
- **Failed attempts** count on the address like wrong passwords ([Failed attempts and lockouts](#sperren)); a blocked
  address gets no passkey sign-in. At most 30 passkey sign-ins per address (IPv6: per /64) and 300 per IPv6 /48 in 10
  minutes. The account lock after wrong
  passwords does not stop a passkey (it cannot be guessed); a disabled or blocked account never signs in.
- Allowed algorithms: ES256, EdDSA, RS256; attestation "none" or self-attestation.

### Passkeys of an account {#passkeys-admin}

In the user list via "More actions" → "Sessions & passkeys". An admin sees the account's passkeys there (name, created,
last used, warning) and removes one – e.g. for a lost device. That requires [confirmation](#erneut-bestaetigen) and
signs out every session signed in with that passkey. The column next to TOTP shows how many passkeys an account has.
*Reset password* removes all of the account's passkeys as well.

## Emergency admin {#notfall-admin}

The emergency admin is the local admin account from the initial setup. It

- cannot be disabled, demoted or deleted by any other admin,
- is never touched by the directory sync,
- is never locked by failed attempts – its **correct** password with TOTP is accepted even from a blocked address. As a
  brake, after 20 failed attempts in one hour every check waits 3 seconds, and only one runs at a time.
- reports when someone guesses its password: once the failed attempts pass the 20 in an hour, Cobe News writes a warning
  to the app's log ("emergency admin: … failed sign-in checks"), an entry to the [audit log](/docs/betrieb#protokoll)
  ("Emergency admin: failure budget exceeded") and shows a notice under
  [Settings → HTTPS & certificate](/settings/https) for 24 hours – at most once an hour, so an attacker can flood neither
  the log nor the audit log with it.

Keep the emergency admin's password and TOTP access offline (password vault).

### Setup token {#setup-token}

At the first start the app writes a one-time **setup token** to its log. It is valid for 60 minutes and only once; every
restart before the setup is finished brings a new one.

```bash
cd /opt/cobe-news
docker compose logs app | grep -A1 "Setup token"
```

In the browser a wizard leads through three steps: enter the token, choose user name, display name and password, then
set up the authenticator app. The token is only used up when the account has really been created – if something fails
on the way, it stays valid.

A new token without a restart (only while there is no emergency admin yet):

```bash
docker compose exec app python -m app.cli new-setup-token
```

If the setup is already finished, the command answers "Setup is already done."

### Regaining access {#notfall-zuruecksetzen}

Lost the emergency admin's password or authenticator? On the server:

```bash
cd /opt/cobe-news
docker compose exec app python -m app.cli reset-emergency
```

The command

- prints a **temporary password**,
- removes the TOTP (it is set up again at the next sign-in) and all passkeys of the account – none that someone else
  set up still lets them in,
- ends all sessions of the account and lifts a lock.

Then sign in with the temporary password, choose a new password and set up TOTP again. Like every temporary password it
is valid for 7 days ([adjustable](#sitzungen-zeitlimits)); after that simply run the command again. More commands:
[Command line](/docs/betrieb#cli).

## Active Directory / LDAP {#ad-ldap}

With AD, users sign in with their `sAMAccountName` or [UPN](term:upn) and their AD password. Cobe News checks the password at the
domain controller, reads the groups and derives the role from them. Admins from AD also set up TOTP.

### Prerequisites {#ad-voraussetzungen}

- A **service account** with read rights in AD ([bind DN](term:binddn)), e.g.
  `CN=svc-cobe-news,OU=Service,DC=corp,DC=example` – or as UPN `svc-cobe-news@corp.example`.
- One or more domain controllers, reachable through [LDAPS](term:ldaps) (port 636) or [StartTLS](term:starttls)
  (port 389).
- With an internal certificate authority: its root CA certificate in PEM format.

### Set up {#ad-einrichten}

[Settings → Sign-in](/settings/auth), card *Active Directory / LDAP*:

1. Turn on the switch "Sign-in with Active Directory" – only then can the fields be edited. It takes effect when you
   save.
2. **Domain controllers**: one per line, at most 4, optionally with a port (e.g. `dc01.corp.example`). The first
   reachable one is used.
3. **Encryption**: "LDAPS (636)" – encrypted from the start – or "StartTLS (389)" – switches to TLS after connecting.
   "None (insecure)" only works together with the switch "Explicitly allow unencrypted LDAP": then every password
   crosses the network in clear text. For tests only.
4. Leave **Verify certificate** on. With an internal CA paste its certificate into the field *Own CA certificate (PEM,
   optional)* (starts with `-----BEGIN CERTIFICATE-----`).
5. **Timeout**: 2–60 seconds (default 10).
6. **Base DN** ([base DN](term:basedn)): where users and groups are searched, e.g. `DC=corp,DC=example`. Left empty,
   Cobe News derives it from the name of the first server.
7. **Service account (bind DN)** and **Service account password**. The password is stored encrypted and never shown
   again; leaving it empty keeps the stored one.
8. **User filter**: the default is `sAMAccountName` or `userPrincipalName`; `{username}` stands for what is typed at
   sign-in and must be in the filter. **Nested groups**: when on, groups inside groups count too.
9. "Test connection" – success: "Service account signed in, base DN found." The form as it is gets tested; nothing is
   saved.
10. "Save" – requires [confirmation](#erneut-bestaetigen).
11. Map AD groups under *Users & roles → Role mapping* ([Groups → roles](#gruppen-rollen)).

> [!NOTE]
> If you change servers, encryption, certificate verification, CA certificate or bind DN, you must enter the service
> account password again ("Please enter the password again …"). That way the stored password never goes out to another
> server or for another account.

### Allowed targets {#ad-ziele}

Domain controllers may be in the company network (private addresses are allowed). Never allowed are loopback,
link-local, Cobe News' own Docker networks and the Docker host itself (e.g. `host.docker.internal`, with Docker Desktop
the network `192.168.65.0/24`). "Test connection" then reports "Target not allowed …". On errors Cobe News only shows
their kind, never answers from the server.

### Errors when testing {#ad-fehler}

| Message | Cause and fix |
|---|---|
| No connection (check network, firewall or proxy). | Check DC name, port, and the firewall between Cobe News and the DC. |
| TLS error – check certificate or CA. | The DC's certificate does not match the name, or the internal CA is missing in the PEM field. Enter the DC under the name in its certificate. |
| The service account is refused (bind DN or password wrong). | Check bind DN (full DN or UPN) and password; account locked or expired? |
| The search failed (check the base DN). | The base DN does not exist or the service account may not read it. |
| Target not allowed … | see [Allowed targets](#ad-ziele). |
| Unencrypted LDAP is not explicitly allowed. | Choose LDAPS or StartTLS – or, for a test, set the switch. |

### Signing in with AD {#ad-anmelden}

On the sign-in page choose the tab "Active Directory" and enter the user name (`a.weber`) or UPN
(`a.weber@corp.example`). If the directory cannot be reached, "The directory cannot be reached right now." appears. A
correct password without a fitting group is answered like a wrong one – the sign-in page does not reveal whether an AD
password is right.

## Entra ID: app registration {#entra-app-registrierung}

For sign-in with Microsoft, Cobe News needs an **app registration** in your [tenant](term:tenant). Cobe News uses
[OIDC](term:oidc) with the authorization code flow and [PKCE](term:pkce) and verifies the ID token completely. The steps in the
[Microsoft Entra admin center](https://entra.microsoft.com) need a role such as *Application Administrator*; the admin
consent in step 5 needs a *Global Administrator* or *Privileged Role Administrator*.

> [!TIP]
> Microsoft rearranges the admin center's menu from time to time. If you cannot find a path, type the page's name
> (e.g. "App registrations") into the search at the top.

### Step 1: Register {#entra-registrieren}

1. Open *Identity → Applications → App registrations* and choose "New registration".
2. **Name**: e.g. "Cobe News" – shown at sign-in and in Enterprise applications.
3. **Supported account types**: "Accounts in this organizational directory only" (single tenant). Cobe News checks that
   the token comes from exactly this tenant.
4. **Redirect URI**: enter it right here – see [Step 2](#entra-redirect-uri).
5. Click "Register".
6. In the app's **Overview** note the *Application (client) ID* ([client ID](term:clientid)) and the *Directory
   (tenant) ID*. Both are GUIDs like `00000000-0000-0000-0000-000000000000`.

### Step 2: Redirect URI {#entra-redirect-uri}

The [redirect URI](term:redirecturi) is the address Microsoft sends the browser back to after the sign-in. For this
installation it is:

```text
{{redirect_uri}}
```

It is also shown in *Settings → Sign-in*, card *Microsoft Entra ID*, field *Redirect URI* – with a button to copy it.

1. In the app registration open *Authentication* (during registration: the field *Redirect URI*).
2. "Add a platform" → choose **Web** – not "Single-page application" and not "Mobile and desktop applications".
3. Paste the value above **exactly** and save.
4. Leave the boxes under *Implicit grant and hybrid flows* empty – Cobe News does not need them.

The rule behind it: **`BASE_URL` + `/api/auth/oidc/callback`** – character for character.

- **Scheme**: `https://` (Microsoft only allows `http://` for `localhost`).
- **Port**: part of it when it is in `BASE_URL`, e.g. `https://news.corp.example:8095/api/auth/oidc/callback`.
- **Host name**: exactly the one from `BASE_URL` – not the IP address, not another DNS name.
- **No trailing slash.**

> [!WARNING]
> If `BASE_URL` changes (another name, another port), the redirect URI changes too. Then enter the new value in the app
> registration, otherwise every sign-in fails with AADSTS50011. How `BASE_URL` is set: [Address](/docs/betrieb#adresse).

Also always open Cobe News at the address from `BASE_URL`. Whoever starts the sign-in at another address (e.g. by IP)
lands, after Microsoft, on the `BASE_URL` address, where the browser cookie is missing – the result: "The Microsoft
sign-in does not belong to this browser".

### Step 3: Client secret {#entra-geheimnis}

With the [client secret](term:clientsecret) Cobe News identifies itself to Microsoft.

1. *Certificates & secrets* → tab *Client secrets* → "New client secret".
2. Enter a description (e.g. "Cobe News 2026") and choose the expiry (Microsoft recommends 180 days; at most 24 months).
3. "Add".
4. Copy the **Value** at once – **not the Secret ID**. The value is only visible now; later the portal shows it
   truncated.

> [!WARNING]
> **The secret expires.** Put the expiry date into your calendar right away (with a few weeks' lead time). After it
> expires every sign-in with Microsoft fails ("The sign-in with Microsoft failed.", AADSTS7000222 in the log), group
> search and the hourly sync stop working. Change it in time: create a new secret, enter it in Cobe News, save,
> delete the old one in Entra.

### Replacing an expired secret {#entra-geheimnis-abgelaufen}

An admin signed in with Microsoft then **cannot** save the new secret: the change needs a
[re-confirmation](#erneut-bestaetigen), which goes through Microsoft – and Microsoft refuses Cobe News with the
expired secret. Cobe News then reports "Microsoft refuses the client secret of Cobe News – it has expired or is wrong …".

1. Create a new secret in Entra and copy its **value** (as above).
2. Sign in to Cobe News with a **local administrator** or the [emergency admin](#notfall-admin) ("Emergency account"
   in the user list) – tab "Local account" of the sign-in page.
3. *Settings → Sign-in* ([open](/settings/auth)), card **Microsoft Entra ID**: enter the new secret, "Test
   connection", save.

> [!TIP]
> So always keep a local admin account or the emergency admin ready (credentials in the password vault) and note the
> secret's expiry date – for example in the calendar and in the secret's description in Entra.

### Step 4: Groups claim {#entra-gruppenanspruch}

For Cobe News to know the groups, the ID token must contain them ([groups claim](term:groupclaim)).

1. *Token configuration* → "Add groups claim".
2. Tick **Security groups**.
3. Under *ID* choose the type **Group ID** (default) – Cobe News maps groups by their object ID, not by name.
4. "Add".

If a user has more than 200 groups, Microsoft puts only a reference into the token instead of the list ([groups
overage](term:groupsoverage)). Cobe News then fetches the groups through Microsoft Graph – which needs the permissions
from step 5.

### Step 5: API permissions {#entra-api-berechtigungen}

1. *API permissions* → "Add a permission" → **Microsoft Graph** → **Application permissions** (not "Delegated
   permissions").
2. Search for `GroupMember.Read.All` and `User.Read.All`, tick them, "Add permissions".
3. Click "Grant admin consent for …" and confirm with "Yes" ([admin consent](term:adminconsent)). The *Status* column
   then shows a green tick "Granted for …".

| Permission | Type | Why Cobe News needs it | What does not work without it |
|---|---|---|---|
| `GroupMember.Read.All` | Application | Group search under *Role mapping* and for teams; groups of users with more than 200 groups (or without a groups claim in the token); groups in the hourly sync; [Teams](#teams): the members of a bound group (`transitiveMembers`) | The group search reports "The app registration lacks a permission" – Entra groups **cannot be mapped** in the interface. Users with more than 200 groups cannot sign in ("The sign-in with Microsoft failed."). Teams: the group shows "Microsoft Graph refuses access (403) …", nobody is loaded. |
| `User.Read.All` | Application | Hourly sync: does the account still exist, is it enabled, which groups is it in; [Teams](#teams): name, UPN, e-mail and state of the loaded members | The sync for Entra is skipped (log: `directory sync (entra) skipped: forbidden`). Whoever is disabled, deleted or removed from the group in Entra keeps a running session until it expires (default: 60 minutes without activity, 12 hours at the latest); only the next sign-in checks again. Teams: Graph returns ids only, the group shows "Graph returns ids without names …", nobody is loaded. |

For [Teams](#teams) with Entra groups **both are required** – Teams needs no new permission.

Both are **application permissions**: Cobe News asks Graph with its own secret, without a signed-in person – which is
why admin consent is needed. It only reads; Cobe News writes nothing to your directory.

> [!NOTE]
> "Test connection" checks whether Graph may read groups (otherwise the warning "Graph may not read groups …").
> It does not check `User.Read.All` – whether the sync runs shows in the log
> (`docker compose logs app | grep "directory sync"`).

### Step 6: Enter it in Cobe News {#entra-in-cobe-news}

[Settings → Sign-in](/settings/auth), card *Microsoft Entra ID*:

1. Turn on the switch "Sign-in with Microsoft Entra ID" – only then can the fields be edited.
2. **Directory (tenant) ID**: the GUID from the app registration's overview (not a domain name).
3. **Application (client) ID**: the GUID from the overview.
4. **Client secret**: the **value** from step 3. It is stored encrypted and never shown again; leaving it empty keeps
   the stored one.
5. "Test connection" – success: "Tenant, client ID and secret are correct." The form as it is gets tested.
6. Choose the **MFA proof** ([below](#entra-mfa-nachweis)) – best with an authentication context.
7. "Save" – requires [confirmation](#erneut-bestaetigen).
8. Map Entra groups under *Users & roles → Role mapping* ([Groups → roles](#gruppen-rollen)). The group search only
   works once the settings are saved.
9. Try "Sign in with Microsoft" in a private browser window.

Possible results of "Test connection":

| Message | Fix |
|---|---|
| The application's sign-in was refused (tenant, client ID or secret wrong or expired). | Copy the IDs again from the overview; secret: value instead of secret ID, check the expiry date. |
| No connection (check network, firewall or proxy). | Cobe News must reach `login.microsoftonline.com` and `graph.microsoft.com` over HTTPS (through `HTTPS_PROXY` if needed). |
| Graph may not read groups … | Grant `GroupMember.Read.All` as an application permission with admin consent (step 5). |
| Not set up completely. | Tenant, client ID or secret is missing. |

### MFA proof {#entra-mfa-nachweis}

Microsoft asks for the second factor of an Entra sign-in through [Conditional Access](term:conditionalaccess). Without
the policy, or one that does not apply to an account or excludes a location, the **Entra password alone** gets in –
for admins too. So Cobe News checks what Microsoft's ID token proves and otherwise asks for its own TOTP. Setting "MFA
proof" in the card *Microsoft Entra ID*:

| Setting | Readers | Admins |
|---|---|---|
| **Trust Entra (Conditional Access)** – default | as before: signed in | only with a proof in the token, otherwise Cobe News' own TOTP as well |
| **Require an authentication context** | the token must contain the context – otherwise only with their own TOTP | as readers |
| **Require proof** | a proof in the token, otherwise their own TOTP | as readers |

What counts as a proof:

- **Authentication context** (`acrs`): Cobe News asks for the configured context (C1 to C99) as an "essential claim" at
  the sign-in; Entra issues it only once the policy tied to it (MFA) is met. The only reliable proof – recommended.
- **`amr` with "mfa"**: if the token says so, it counts; "pwd" without "mfa" counts as proof of the opposite. The usual
  ID tokens (v2.0) mostly carry no `amr` though – then Cobe News knows nothing and, where needed, asks for its own TOTP.

Without a proof where one is needed:

- **With their own TOTP**: after Microsoft, Cobe News asks for the code (sign-in method "Microsoft + TOTP").
- **Without TOTP, the token says nothing**: the TOTP is set up at this sign-in. That first set-up is then protected
  only by the Entra sign-in itself – one more reason for the authentication context.
- **Without TOTP, the token says otherwise** (context missing, or `amr` without "mfa"): **refused** – "Microsoft did not
  prove a second factor for this sign-in …". Otherwise the Entra password alone would set up the "second" factor.
  Nothing of this sign-in stays (no new account, no changed role).

While no context is configured, the card shows a hint. To create a context:

1. Entra admin center → *Protection → Conditional Access → Authentication context* → "New authentication context",
   e.g. "Cobe News MFA", ID **C1**, "Publish to apps" on.
2. *Conditional Access → Policies* → new policy: users = the Cobe News groups, *Target resources* → "Authentication
   context" → C1, *Grant* → "Require multifactor authentication", enable it.
3. In Cobe News choose "Require an authentication context", enter **C1**, save.
4. Sign in with a test account: Microsoft asks for the second factor, Cobe News no longer does.

> [!NOTE]
> **After the update to 0.1.42**: with the default setting, Entra admins whose token carries no proof need Cobe News'
> own TOTP at their next sign-in (it is set up then). Readers sign in as before. An Entra admin's
> [confirmation](#erneut-bestaetigen) requires the proof as well.

### Optional: restrict access to certain people {#entra-zuweisung}

Who may use Cobe News at all is decided by the [role mapping](#gruppen-rollen). If Microsoft should already refuse
others, set it up in the matching enterprise application:

1. *Identity → Applications → Enterprise applications* → open the app "Cobe News".
2. *Properties* → set "Assignment required?" to **Yes** → "Save".
3. *Users and groups* → "Add user/group" → choose the groups that should have access.

People not assigned then see AADSTS50105 at Microsoft. The role mapping in Cobe News is still needed.

## Entra ID: errors {#entra-fehler}

Errors in the sign-in with Microsoft show up in one of two places: **at Microsoft** (an error page with an `AADSTS…`
code, the browser does not come back) or **in Cobe News** (a message on the sign-in page, details in the log).

### AADSTS messages {#entra-aadsts}

| Code | Meaning | Where it shows | Fix |
|---|---|---|---|
| AADSTS500113 | No reply address is registered for the app. | Microsoft page | Enter the redirect URI under *Authentication* as platform **Web** ([Step 2](#entra-redirect-uri)). |
| AADSTS50011 | The request's redirect URI matches none registered. | Microsoft page | Enter exactly `{{redirect_uri}}`. Typical differences: `http` instead of `https`, missing or other port, other host name, trailing slash, `BASE_URL` changed. |
| AADSTS700016 | Application not found in the directory. | Microsoft page; "Test connection": "The application's sign-in was refused …" | Wrong client ID, or the app is registered in a different tenant than the tenant ID entered. Copy both GUIDs again from the overview. |
| AADSTS90002 | Tenant not found. | Microsoft page; test as above | Check the directory (tenant) ID. |
| AADSTS7000215 | Invalid client secret. | Cobe News: "Microsoft refuses the client secret of Cobe News …"; log | Usually the **secret ID instead of the value** was entered. Create a new secret and enter its value ([Step 3](#entra-geheimnis)). |
| AADSTS7000222 | The client secret has expired. | Cobe News: "Microsoft refuses the client secret of Cobe News …"; log | Create a new secret and enter it with a local admin or the emergency admin ([Expired secret](#entra-geheimnis-abgelaufen)). Put the expiry date in the calendar. |
| AADSTS65001 (also AADSTS90094) | Consent missing – users may not consent to the app themselves. | Microsoft page ("Approval required") or Cobe News: "Microsoft cancelled or refused the sign-in." | *API permissions* → "Grant admin consent for …". If user consent is switched off entirely in the tenant, first add `openid`, `profile` and `email` under Microsoft Graph → *Delegated permissions*, then consent. |
| AADSTS50105 | The account is not assigned to the app ("Assignment required" is on). | Microsoft page | Assign the person or group under *Enterprise applications → Cobe News → Users and groups* – or set "Assignment required?" to No ([Assignment](#entra-zuweisung)). |
| AADSTS9002327 | Platform "Single-page application" instead of "Web". | Cobe News: "… failed."; log | Enter the redirect URI under the platform **Web**, remove the SPA entry. |

### Messages from Cobe News {#entra-meldungen}

| Message on the sign-in page | Cause | Fix |
|---|---|---|
| Microsoft refuses the client secret of Cobe News – it has expired or is wrong. … | Microsoft does not accept the client secret (AADSTS7000215/7000222). Nobody gets in through Microsoft – not even a re-confirmation. | Enter a new secret with a local admin or the emergency admin ([Expired secret](#entra-geheimnis-abgelaufen)). |
| The sign-in with Microsoft failed. | The exchange with Microsoft afterwards failed: wrong platform, token invalid, Graph unreachable or without permission (with more than 200 groups). | Look at the log ([Diagnosis](#entra-diagnose)). |
| Microsoft cancelled or refused the sign-in. | Microsoft sent back an error, e.g. a cancelled sign-in, missing consent, Conditional Access. | Check the sign-in log in Entra; grant consent. |
| Your account is in no group that gives access to Cobe News. | The sign-in at Microsoft worked, but no mapped group fits. | Add the person to a mapped group or map a group; check the groups claim ([Step 4](#entra-gruppenanspruch)). |
| Your account is disabled. | An admin disabled the account in Cobe News. | Enable it again under *Users & roles*. |
| Another account already has this user name – contact an admin. | A local account already has the person's UPN as its name. A directory account never takes over a local one. | Rename or delete the local account. |
| The Microsoft sign-in does not belong to this browser – please try again. | The sign-in cookie is missing or does not match – often because Cobe News was opened at another address than `BASE_URL`. | Open Cobe News at the `BASE_URL` address. |
| The Microsoft sign-in took too long – please try again. | More than 10 minutes passed between start and return. | Start again. |
| Too many sign-ins right now – please try again shortly. | More than 30 sign-in starts from one address in 10 minutes (300 for a [shared address](#geteilte-adressen)). | Wait a moment. |
| Sign-in with Microsoft is switched off. | The switch is off, or tenant, client ID or secret are missing. | Check the settings and save. |
| Your address is temporarily blocked after too many failed attempts (with IPv6 the whole /64 network). | The address is blocked, with IPv6 its /64 network ([Lockouts](#sperren)). | Wait, or check `SHARED_ADDRESSES`. |
| Microsoft did not prove a second factor for this sign-in, and your account has none set up in Cobe News. … | A second factor is required, the token says otherwise (context missing, `amr` without "mfa"), and the account has no TOTP ([MFA proof](#entra-mfa-nachweis)). | Check Conditional Access: does the MFA policy apply to this account and – with a context – to the authentication context? Look at the sign-in log in Entra. |

### Where to find the cause {#entra-diagnose}

**Cobe News log** – errors in the exchange with Microsoft are logged with the AADSTS code:

```bash
cd /opt/cobe-news
docker compose logs app | grep -i entra
```

A line like `entra token endpoint 401: … AADSTS7000215 …` names the code. If Microsoft sends the browser back with an
error, the log only holds its short name (e.g. `access_denied`).

**Sign-in logs in Entra** – *Identity → Monitoring & health → Sign-in logs*, filtered by the application "Cobe News".
They show the code and reason of every refused sign-in, including Conditional Access.

## Groups → roles {#gruppen-rollen}

AD and Entra accounts get their role **only** through groups. The mapping is under
[Settings → Users & roles](/settings/users?tab=mapping), tab *Role mapping*.

1. Under *Map a group* choose the **Directory**: "Active Directory" or "Entra ID". It must be set up and saved first.
2. Type the name under **Search group** – the search runs live in the directory (AD: full DN, Entra: object ID).
3. Click the group in the list and choose the **Role** ("Reader" or "Admin").
4. Click "Map …" – requires [confirmation](#erneut-bestaetigen).

Rules:

- **No fitting group, no access.** There is no default role. With AD the sign-in fails like with a wrong password, with
  Entra "Your account is in no group that gives access to Cobe News." appears.
- **Admin wins**: if an admin group and a reader group both fit, the account becomes an admin.
- The role is determined again **at every sign-in and hourly** ([Sync](#abgleich)). If it changes, all older sessions of
  the account end – a reader session never silently becomes an admin session.
- AD: with *Nested groups* groups inside groups count too. Entra: the token or Graph returns all groups, nested ones
  included.
- Removing a mapping (trash icon): see [Removing a mapping](#gruppen-entfernen).
- The role of a directory account cannot be changed by hand in the user list – it follows the group.

> [!TIP]
> Create groups of their own for Cobe News (e.g. "Cobe News Admins" and "Cobe News Readers"). Then the directory shows
> who has access, and nobody gets it by chance through a big department group.

### Removing a mapping {#gruppen-entfernen}

The trash icon asks first, says how many accounts it concerns and has the toggle **"Sign out those concerned at once"**
(default: on). Requires [confirmation](#erneut-bestaetigen).

- **On**: the accounts of the group are re-checked at once – from the groups Cobe News stored at their last sign-in or
  sync. The directory is not asked, so an outage of the DC or of Microsoft does not hold the change up.
  - Whoever has **no role left** is switched off (*No role group any more*) and signed out at once.
  - Whoever falls **from admin to reader** is signed out at once and signs in again as a reader.
  - Whoever keeps **the same role through another mapping or a team** stays signed in.
  - Whoever is signed in but has **no stored groups yet** (last signed in before this update and not synced since) might
    have access through this group only: they are signed out to be safe, their role is set by the next sign-in or sync.
- **Off**: as before – the roles change at the next hourly sync. If the directory cannot be reached then, running
  sessions last until they end (default: at most 12 hours).

Local accounts and the emergency admin are never concerned. **If your own admin access depends on the group**, the
mapping cannot be removed – you would lock yourself out. Remove it with another admin account, e.g. the emergency
account.

## Hourly sync {#abgleich}

Once an hour Cobe News asks the directory about every AD and Entra account:

- **Deleted, disabled or no longer in a mapped group** → the account is disabled, all sessions end at once. The user
  list shows why: *No longer in the directory*, *Disabled in the directory* or *No role group any more*.
- **Active again and in a group** → an account disabled by the sync is switched on again. An account an admin disabled
  or [blocked permanently](#benutzer-verwalten) stays off.
- **Other group, other role** → the role follows; all sessions end, the new role applies from the next sign-in.
- **Renamed** → accounts are recognised by their ID, not their name. The new name (AD: `sAMAccountName`, Entra: UPN)
  follows at the next sign-in, for AD in the sync as well. The name of an account deleted in the directory is released,
  so a newly created account of the same name can sign in.
- **Directory unreachable** → the sync changes **nothing**. An outage of the DC or of Microsoft locks nobody out.

Local accounts – above all the emergency admin – are never touched by the sync. For Entra it needs both
[API permissions](#entra-api-berechtigungen); without them it is skipped and changes only take effect at the next
sign-in.

### Switching AD or Entra ID off {#verzeichnis-ausschalten}

If you switch *Active Directory / LDAP* or *Entra ID* off under [Settings → Sign-in](/settings/auth), "Save" asks first:
it says how many accounts of this sign-in method are signed in right now and has the toggle **"Sign out those concerned
at once"** (default: on). On: all sessions of these accounts end at once. Off: they run until they end. The accounts are
kept; once switched on again they sign in as before.

If you are signed in with an account of this sign-in method **yourself**, it cannot be switched off – you could not sign
in again afterwards. Sign in with a local admin account (e.g. the emergency account) and switch it off from there.

With [Teams](#teams) the sync first loads the members of all bound groups, then checks the accounts as above. Accounts a
team loaded that have never signed in are not looked up one by one – they hold no session, and the first sign-in checks
everything anyway.

## Teams {#teams .admin}

Teams group people who take care of the same products. A team is bound to one or more groups from AD or Entra ID; under
[Vendor News](/docs/vendor-news#mein-team) its members see only the team's products with "My team", and a notification
rule can be limited to the products of teams ([Rules](/docs/benachrichtigungen#regel-teams)). Teams is **off by default**
– while it is off, nothing changes for anyone.

### Switching it on {#teams-einschalten}

1. [Settings → Teams](/settings/teams?tab=settings), tab *Settings*.
2. **Switch Teams on** – asks you to [confirm it is you](#erneut-bestaetigen), because from now on the members of every
   team group may read. Switching it off asks as well.
3. Optionally switch on the **welcome e-mail** ([below](#teams-willkommen)).

Prerequisite: AD/LDAP or Entra ID is set up. For Entra the app registration needs `GroupMember.Read.All` **and**
`User.Read.All` as application permissions ([step 5](#entra-api-berechtigungen)).

### Creating a team and binding groups {#teams-gruppen}

1. Tab *Teams* → **Create team**, a name and optionally a description.
2. In the drawer, *Groups*: choose the directory, search the group live, click it, **bind** (confirm it is you).
   Groups of the [role mapping](#gruppen-rollen) are already listed on top under *From the role mapping* – with their
   role next to them and without those bound to the team already. The search text filters them too. Binding does not
   change the role.
3. The members are loaded **at once** in the background – the group shows "Loading …", then "N people loaded". After
   that the [hourly sync](#abgleich) keeps them current; *Load now* under *Members* loads again right away.

Nested groups count too: AD searches with `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`) page by page,
Entra reads `transitiveMembers` (users only) page by page. A group has at most 50,000 members.

- Whoever is **taken out of the group**, or whose **group is unbound**, leaves the team at the next load (right away when
  unbinding).
- Whoever is then in **no team group any more** and has **never signed in** is disabled automatically – *Users*
  shows "No team any more". If the person is back in a team group, the account is active again with the next load.
  Whoever has signed in before loses access with the [hourly sync](#abgleich) once no group gives them a role.
- If a group **cannot be read** (directory unreachable, permission missing), the team stays as it is – an outage empties
  no team. The reason is shown at the group.
- While Teams is off you can prepare teams and groups; the group shows "Waiting – Teams is switched off".

### Members and roles {#teams-mitglieder}

- Loaded people appear at once under [Users](/settings/users) as AD or Entra accounts marked *Never signed in* until
  their first sign-in. A local account of the same name is never taken over.
- A team group gives the **reader** role. If someone is also in an admin group of the [role mapping](#gruppen-rollen),
  they become admin – admin wins. Teams is an additional way to read, only while Teams is on; there is still no default
  role.
- **Local accounts** are added by hand under *Members*. Their role does not change.
- Switching Teams off: whoever had access only through a team loses it at the next sync. Loaded accounts that never
  signed in are disabled right away ("Teams switched off") and are active again once Teams is switched on.

### Blocking {#teams-sperren}

Under [Users](/settings/users) the *Active* switch turns an account off – also one that has never signed in. That counts
as blocked by an admin: neither loading the groups nor the hourly sync switches it on again; the person stays a member
but cannot sign in. If Teams has switched the account off itself already (*No team any more*, *Teams switched off*),
the switch is off already – then "More actions → Block permanently" blocks it so that it stays off even when the person
comes back into a team group. Do not **delete** a loaded account while the person is in the group – the next load
creates it again. Block instead of deleting.

### Products {#teams-produkte}

Under *Products* you choose the team's [followed products](/docs/vendor-news#produkten-folgen); a product can belong to
several teams. A product no longer followed (deleted) disappears from all teams. A team a rule is limited to can be
deleted only after the rule is changed. Who in the team gets which product you decide below it
([Who gets what?](#teams-zuteilung)).

### Who gets what? {#teams-zuteilung}

Under *Products* every assigned product has the switch **Everyone in the team** (on by default): every member then gets
its news. Switch it off and you choose the people yourself – for example "Anna and Ben get Palo Alto, Anna and Cem get
Cisco":

1. [Settings → Teams](/settings/teams), open the team, part *Products*.
2. Switch **Everyone in the team** off for the product.
3. **Add person**, search the name, click it. Chosen people show as chips; the × takes them out again.
4. **Save**.

- Only members of the team can be chosen.
- With nobody chosen it says "Nobody gets the news of this product."
- Whoever leaves the team (group, sync or by hand) loses their choice, too.
- Under *Members* each person shows which products they get.
- The choice counts for "My team" in [Vendor News](/docs/vendor-news#mein-team) and for the
  [personal notifications](#teams-persoenlich). Whoever newly gets a product receives its news from now on – nothing
  older.

### Forward channel {#teams-weiterleiten}

Members can “forward to team” a story or a finding with a comment
([Forward to my team](/docs/benachrichtigungen#weiterleiten)). Only you decide where it goes:

1. [Settings → Teams](/settings/teams), open the team, part *General*.
2. Under **Forward channel** choose one of the existing [channels](/docs/benachrichtigungen#kanaele), *Save*.

Out of the box no channel is chosen – forwarding is off for the team. Readers only see *that* there is a channel, not
which one. If the channel is deleted, the team has none any more. The channel sends as for the rules (the same checks of
the targets); forwarding does not change its pause or its last error.

### Personal notifications {#teams-persoenlich}

Each person can have the Vendor News of **their** products sent to them
([Vendor news of my products](/docs/benachrichtigungen#meine-produkte)). Which ways there are you decide under
[Settings → Teams](/settings/teams?tab=settings), tab *Settings*, section **Personal notifications**. Each way is **off
by default**:

| Way | What happens | Needs |
|---|---|---|
| E-mail | a mail to the address of the account | a [mail server](/docs/benachrichtigungen#e-mail) set up |
| Desktop | a push to the person's browsers, also with the tab closed | Web Push on the server (`WEB_PUSH`) |
| Microsoft Teams | a card to the person's own Workflows webhook | outgoing https to Microsoft |

- While a way is off, nobody gets anything through it; the person sees "Switched off by the admin". What came meanwhile
  is not sent when it is switched on.
- With Teams switched off there are no personal notifications.
- A person's Teams webhook may only be a Microsoft address (`*.logic.azure.com`, `*.powerplatform.com`,
  `*.webhook.office.com`, https, port 443) and only a public target. `WEBHOOK_HOSTS` and `WEBHOOK_PRIVATE_NETS` do not
  apply here.
- The switches need no re-confirmation – they do not change who may read.

### Entering an absence {#teams-abwesenheit}

In the team, tab **Members**, the calendar icon of a person enters their
[absence](/docs/benachrichtigungen#abwesenheit): from–to, a **deputy from this team** and optionally "Also to me". The
same rules apply as for the person themselves. The list shows "Away until … – deputy …" and a hint when the deputy is
away then too.

### Weekly review {#teams-wochenrueckblick}

In the team, tab **Weekly review**, you switch on a short e-mail a week about the team's products (**off by
default**): weekday, time and time zone (Monday 08:00, *Europe/Berlin* by default).

- It goes only to members who switch it on themselves under
  [Vendor news of my products](/docs/benachrichtigungen#wochenrueckblick), whose account is active and who have an
  e-mail address. The tab shows how many they are.
- Switched on or moved, it applies from the next date on – the running week is not sent afterwards.
- Exactly once per team, person and week, also after a restart. After an outage at most the last missed week.
- Without a [mail server](/docs/benachrichtigungen#e-mail) set up the tab shows a hint and nothing is attempted.
- At most 200 mails per round; a large team gets the review over a few minutes.

### Welcome e-mail {#teams-willkommen}

A switch of its own, **off by default**. When it is on, every **newly loaded** person gets exactly **one** e-mail through
the configured [mail server](/docs/benachrichtigungen#e-mail): that they can use Cobe News, the address `{{base_url}}`
and how to sign in – never a password.

- Never twice – not after a restart, a new load, or when the account is deleted and loaded again.
- People without an e-mail address in the directory are skipped; the user list shows *No e-mail*.
- Whoever was loaded while the switch was off gets no e-mail.
- Without a mail server the e-mails wait. If the server refuses the connection, Cobe News tries again later; after an
  error where the e-mail may have arrived (a timeout, for example), it does not – the user list then shows *Welcome
  e-mail failed*.
- At most 50 e-mails a minute; a big team gets its e-mails over a few minutes.

## Sessions & lockouts {#sitzungen}

Sessions live on the server; the browser only holds a random token in a cookie (HttpOnly, Secure, SameSite=Lax).
Signing out ends the session at once.

### Timeouts {#sitzungen-zeitlimits}

[Settings → Sign-in](/settings/auth), card *Sessions*:

| Setting | Range | Default |
|---|---|---|
| Sign out after inactivity | 5–480 minutes without action | 60 minutes |
| Sign in again at the latest after | 1–72 hours, even when active | 12 hours |
| Temporary password valid for | 1–30 days from issuing a temporary password ([Create](#benutzer-anlegen)) | 7 days |

A shorter limit applies at once to running sessions too. Saving requires [confirmation](#erneut-bestaetigen).

Only what the person does counts as activity (opening a page, clicking, saving). Automatic updates in the background –
counters, new stories, desktop notifications, the state of a running backup – do not keep the session open: a tab left
open is signed out after the set time.

### All tabs together {#sitzungen-tabs}

The tabs of one browser share one session (one cookie) and keep each other informed: signing out in one tab, a session
that expired (inactivity or the maximum lifetime) or one an admin ended – every tab goes to the sign-in, drops the data
it loaded and closes open dialogs. After a sign-out the other tabs show "Signed out – in another tab.", after an expiry
"Your session has expired". Sign in in one tab (with a passkey or through Microsoft too) and tabs on the sign-in page
reload and are back in.

- **Expiry without a click:** the server tells the tabs how long the session has left. A request you cause in any tab
  counts for all of them (the way the server writes "last active" at most every 5 minutes). Shortly after the computed
  end one tab asks (`GET /api/auth/session`) – asking does not extend the session. A tab that becomes visible again asks at once, so
  a session ended meanwhile is noticed too.
- **Warning:** two minutes before the inactivity timeout "Your session ends soon" appears with the time. *Stay signed
  in* is a normal request and extends the session; closing it in one tab closes it in all. There is no warning before
  the maximum lifetime – it cannot be extended.
- **What the tabs exchange:** only the event and times (BroadcastChannel, in older browsers an entry in localStorage) –
  no token, nothing about the person.
- Other browsers and devices have sessions of their own and are not affected. Another address (such as the emergency
  access `http://localhost:8096`, [`APP_PORT`](/docs/betrieb#env-adresse)) is a separate area for the browser with a
  session of its own: its tabs only keep each other informed.

### My sessions {#meine-sitzungen}

Everyone sees their running sessions under *Profile & security → My sessions* and signs out one or all others
([Signing out and sessions](/docs/erste-schritte#abmelden)). Shown are browser and system (roughly from the User-Agent),
the sign-in method, start, last active and the **full IP address** – it is the person's own data. Cobe News writes
"last active" at most every 5 minutes, not on every request. Sign-ins under way (password right, code still missing)
appear too, marked.

An admin sees and ends the sessions of any account via "More actions" → "Sessions & passkeys": a single one, or all with
"End all sessions" (the admin's own current session stays). Both require [confirmation](#erneut-bestaetigen). An ended
session is gone at once – that browser's next request is refused.

Sessions also end by themselves on: a password change (all others), a password or TOTP reset by an admin, a role
change, disabling or blocking (all), and removing a passkey (those signed in with it).

### Confirm it is you {#erneut-bestaetigen}

Sensitive changes require that you proved who you are within the last **10 minutes** – the sign-in itself counts. This
applies to:

- **Sign-in and accounts:** sign-in settings (AD, Entra, sessions), role mappings, creating an admin, changing a role,
  enabling or disabling an admin account or changing its e-mail address, resetting someone else's password or TOTP,
  [blocking an account permanently](#benutzer-verwalten) or lifting the block, deleting an account, adding or removing a
  passkey, ending someone else's sessions.
- **[Teams](#teams):** switching Teams on or off, binding a group to a team or unbinding it, deleting a team with bound
  groups.
- **Operations:** creating or revoking [API tokens](/docs/api#token-anlegen), downloading the
  [export](/docs/sicherung#export), keeping fewer backups under [retention](/docs/sicherung#aufbewahrung) (older ones are
  deleted at once).

- **Local and AD accounts**: a dialog "Confirm it is you" asks for the password and – if set up – the current code from
  the app. The change is then carried out.
- **Entra accounts**: "Confirm at Microsoft" – Microsoft asks for the sign-in again. You come back afterwards and make the
  change again. If the confirmation fails, Cobe News shows "Confirmation at Microsoft failed" with the reason. With an
  expired client secret this no longer works – see [Expired secret](#entra-geheimnis-abgelaufen). The second factor is
  checked as at the sign-in ([MFA proof](#entra-mfa-nachweis)): if the account has Cobe News' own TOTP, the dialog asks
  for the code first, then it goes to Microsoft. Without a proof and without a code: "The confirmation at Microsoft
  proved no second factor."
- Five wrong confirmations end the session (the account itself is not locked by them).

### Failed attempts and lockouts {#sperren}

- **Account**: 5 failed attempts in 15 minutes lock the account for 15 minutes; longer on repeated locks (up to
  2 hours). An admin lifts the lock under *Users & roles* with "Unlock". A locked AD account is not even checked at the
  DC – the lock in Cobe News does not count against your AD lockout policy.
- **Address**: only 30 failed attempts across at least 5 different names in 15 minutes (password spraying) block an
  address for 30 minutes. One person's typos only lock that person's account.
- **IPv6 counts per /64 network**: a connection usually gets a whole /64 with countless addresses. So all addresses of
  a /64 count and are blocked together (e.g. `2001:db8:1:2::/64`). IPv4 counts per single address, an IPv4-mapped IPv6
  address (`::ffff:192.0.2.1`) like the IPv4 address. A [shared address](#geteilte-adressen) always counts on its own.
- **Restart**: the counters (failed attempts so far) live in memory only – a restart clears them. Running **locks** of
  accounts and **blocks** of addresses survive it though: Cobe News writes each one to the database (table
  `auth_locks`) and reads back the ones still running at the start. Expired ones go at the start and hourly, at most
  10,000 are kept. "Unlock" removes the stored entry too.
- Failed attempts count separately per origin: a refused AD sign-in never locks the local account of the same name.
- Every failed attempt delays the next check a little.
- The emergency admin is never locked ([Emergency admin](#notfall-admin)).
- **Failed CSRF check**: a write without or with a wrong CSRF token (another site, a script – the browser with Cobe News
  always sends it) is refused and written to the app's log as a warning ("csrf check failed", with method, path and
  address or /64 network, never with the token or cookie). At most one line per address and minute; what came in
  between is counted in the next line.

### Shared addresses {#geteilte-adressen}

The client address comes from the bundled nginx. A **shared address** – the Docker gateway (under Docker Desktop all
clients arrive from there), a [reverse proxy](term:reverseproxy) in front, or an address from `SHARED_ADDRESSES` – is
never blocked; spraying through it is slowed down instead (3 seconds per failed attempt), single accounts lock as
always.

If many colleagues sit behind an office NAT, enter its address in the `.env` (comma-separated, networks in
[CIDR](term:cidr) notation too) and restart the app:

```bash
SHARED_ADDRESSES=192.0.2.10,198.51.100.0/24
```

If you run your own proxy in front of Cobe News, it must pass on the real client address – otherwise everybody shares
the proxy's address. See [Reverse proxy](/docs/betrieb#reverse-proxy).
