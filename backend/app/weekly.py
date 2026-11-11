"""Weekly review of a team by e-mail (0.1.35): an admin switches it on per team (off by default) with weekday, time and
time zone (Monday 08:00 Europe/Berlin); members who switched it on for themselves (Hersteller-News meiner Produkte –
off by default), with an active account and an e-mail address, get one mail a week about the team's products.

- **Content** of the seven days before: new vulnerabilities by severity (the most severe listed), own versions affected
  now, advisory changes with an effect on them, EOL within 90 days, new versions – each with a link into Cobe News.
  A confirmed finding (app/finding_confirm.py) is handled: neither among the new ones nor counted as affecting.
  HTML and a text alternative as the other mails; every value from the feeds is escaped (Jinja autoescape) or plain text.
- **Exactly once** per team, person and ISO week (team_weekly_sends, keyed): queued once per week (team_weekly.last_week),
  claimed (pending → sending) and committed before the mail goes out – a restart or a crash in between never sends it
  twice (a row left at "sending" is marked failed after an hour). Retried only after a failure that certainly delivered
  nothing (teams.WELCOME_RETRY), at most TRIES times.
- **No catching up**: only the newest weekly time at or before now is ever looked at – after an outage of three weeks
  the last one comes (late), the others never; a week still open when a newer one is queued is skipped.
- **No SMTP, no attempt**: without a mail server (host and sender) nothing is queued or tried; the team drawer says so.
- **Bounded**: at most PER_ROUND mails and ROUND_S seconds per round, the rest the next round (the oldest first).
"""

import logging
import time
import uuid
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import case, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app import delivery_log, notify, quiet, teams
from app import settings as settings_store
from app.config import get_config
from app.models import PersonNotify, Team, TeamMember, TeamProduct, TeamWeekly, TeamWeeklySend, User, VendorEvent, VendorFollow

log = logging.getLogger("cobe_news.weekly")

PER_ROUND = 200
ROUND_S = 20.0
CLAIM = 25  # rows claimed and committed together
TRIES = 5
STALE = timedelta(hours=1)
WINDOW = timedelta(days=7)
EOL_DAYS = 90
LIST = 8
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")

TEXTS = {
    "de": {
        "label": "Wochenrückblick",
        "subject": "[Cobe News] Wochenrückblick {team} · KW {week}",
        "heading": "Wochenrückblick {team}",
        "range": "{start} – {end} · {n} Produkte",
        "vulns": "Neue Schwachstellen",
        "vulns_none": "Keine neuen Schwachstellen.",
        "affected": "Eigene Versionen, die gerade betroffen sind",
        "affected_line": "{product} {version}: {n} Schwachstellen ({critical} kritisch)",
        "changes": "Advisory-Änderungen mit Wirkung",
        "eol": "Support-Ende in den nächsten 90 Tagen",
        "eol_line": "{product} {version}: Support endet am {date}",
        "versions": "Neue Versionen",
        "version_line": "{product} {version} → {latest}",
        "review": "Versionen zu prüfen",
        "review_lead": "Seit über {days} Tagen nicht bestätigt – läuft das noch so? In Vendor News bestätigen oder ändern.",
        "review_line": "{product} {version}: seit {n} Tagen nicht bestätigt",
        "none": "Nichts.",
        "more": "… und {n} weitere",
        "open": "Öffnen",
        "button": "Vendor News öffnen",
        "footer": [
            "Diese Nachricht hat Cobe News automatisch an dich versendet, weil du den Wochenrückblick deines Teams eingeschaltet hast.",
            "Ausschalten: Einstellungen › Benachrichtigungen › Hersteller-News meiner Produkte › Wochenrückblick.",
        ],
        "sev": {"critical": "Kritisch", "high": "Hoch", "medium": "Mittel", "low": "Niedrig", "info": "Info"},
    },
    "en": {
        "label": "Weekly review",
        "subject": "[Cobe News] Weekly review {team} · week {week}",
        "heading": "Weekly review {team}",
        "range": "{start} – {end} · {n} products",
        "vulns": "New vulnerabilities",
        "vulns_none": "No new vulnerabilities.",
        "affected": "Own versions affected now",
        "affected_line": "{product} {version}: {n} vulnerabilities ({critical} critical)",
        "changes": "Advisory changes with an effect",
        "eol": "End of support in the next 90 days",
        "eol_line": "{product} {version}: support ends on {date}",
        "versions": "New versions",
        "version_line": "{product} {version} → {latest}",
        "review": "Versions to review",
        "review_lead": "Not confirmed for more than {days} days – still running like this? Confirm or change them in Vendor News.",
        "review_line": "{product} {version}: not confirmed for {n} days",
        "none": "Nothing.",
        "more": "… and {n} more",
        "open": "Open",
        "button": "Open Vendor News",
        "footer": [
            "Sent to you automatically by Cobe News because you switched on the weekly review of your team.",
            "Switch off: Settings › Notifications › Vendor news of my products › Weekly review.",
        ],
        "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
    },
}


# ---------------------------------------------------------------- settings (admin, per team)


def settings_out(w: TeamWeekly | None) -> dict:
    return {
        "enabled": bool(w and w.enabled),
        "weekday": int(w.weekday) if w else 0,
        "at": w.at if w else "08:00",
        "tz": w.tz if w else quiet.DEFAULT_TZ,
        "last_week": w.last_week if w else None,
    }


async def settings_of(db: AsyncSession, team_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict]:
    rows = {w.team_id: w for w in await db.scalars(select(TeamWeekly).where(TeamWeekly.team_id.in_(team_ids)))} if team_ids else {}
    counts = await recipients_count(db, team_ids)
    return {t: {**settings_out(rows.get(t)), "recipients": counts.get(t, 0)} for t in team_ids}


async def put(db: AsyncSession, team_id: uuid.UUID, enabled: bool, weekday: int, at: str, tz: str) -> TeamWeekly:
    """Not committed. Switched on, or its time changed: only weeks whose time comes after now are sent."""
    w = await db.get(TeamWeekly, team_id)
    now = datetime.now(UTC)
    if w is None:
        w = TeamWeekly(team_id=team_id, enabled=False, weekday=0, at="08:00", tz=quiet.DEFAULT_TZ, since=now)
        db.add(w)
    if enabled and (not w.enabled or (w.weekday, w.at, w.tz) != (weekday, at, tz)):
        w.since = now
    w.enabled, w.weekday, w.at, w.tz = enabled, weekday, at, tz
    await db.flush()
    return w


def _eligible_people(team_ids: list[uuid.UUID]):  # noqa: ANN202
    """SQL: (team, person, e-mail, weekly_since) – members with the review switched on and an active account."""
    return (
        select(TeamMember.team_id, User.id, User.email, PersonNotify.weekly_since)
        .join(User, User.id == TeamMember.user_id)
        .join(PersonNotify, PersonNotify.user_id == User.id)
        .where(TeamMember.team_id.in_(team_ids), User.is_active.is_(True), PersonNotify.weekly_on.is_(True), User.email.is_not(None))
    )


async def recipients_count(db: AsyncSession, team_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    out: dict[uuid.UUID, int] = {}
    if not team_ids:
        return out
    for tid, _uid, email, _since in await db.execute(_eligible_people(team_ids)):
        if email and teams.MAIL.fullmatch(email):
            out[tid] = out.get(tid, 0) + 1
    return out


async def mine(db: AsyncSession, user_id: uuid.UUID) -> list[dict]:
    """The person's teams that send a weekly review (name, weekday, time, zone) – for the person's own switch."""
    q = (
        select(Team.name, TeamWeekly.weekday, TeamWeekly.at, TeamWeekly.tz)
        .join(TeamWeekly, TeamWeekly.team_id == Team.id)
        .join(TeamMember, TeamMember.team_id == Team.id)
        .where(TeamMember.user_id == user_id, TeamWeekly.enabled.is_(True))
        .order_by(func.lower(Team.name))
    )
    return [{"team": n, "weekday": int(d), "at": a, "tz": z} for n, d, a, z in await db.execute(q)]


# ---------------------------------------------------------------- the round


def smtp_ready(smtp: dict) -> bool:
    return bool(smtp.get("host") and smtp.get("from_addr"))


async def run(db: AsyncSession) -> int:
    """Queue the due weeks, then send what is open (bounded). Nothing at all without Teams or without a mail server."""
    try:
        if not await teams.is_on(db):
            return 0
        smtp = await settings_store.get(db, "smtp")
        if not smtp_ready(smtp):
            return 0  # no mail server: nothing queued, nothing tried (the team drawer says so)
        now = datetime.now(UTC)
        await queue(db, now)
        return await send(db, smtp)
    finally:
        await dbm.release(db)


async def queue(db: AsyncSession, now: datetime) -> int:
    """Per team switched on: its newest weekly time at or before now – queued once (rows per recipient), never an older
    one. Each team in a transaction of its own."""
    await db.execute(
        update(TeamWeeklySend)
        .where(TeamWeeklySend.status == "sending", TeamWeeklySend.claimed_at < now - STALE)
        .values(status="failed", error="interrupted")
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    added = 0
    for w in list(await db.scalars(select(TeamWeekly).where(TeamWeekly.enabled.is_(True)))):
        slot = quiet.last_weekly(w.weekday, w.at, w.tz, now)
        if slot <= w.since:
            continue  # switched on (or moved) after this week's time: from the next one on
        week = quiet.week_of(slot, w.tz)
        if w.last_week == week:
            continue
        # an older week still open: never sent now (no catching up on old weeks)
        await db.execute(
            update(TeamWeeklySend)
            .where(TeamWeeklySend.team_id == w.team_id, TeamWeeklySend.status == "pending", TeamWeeklySend.week != week)
            .values(status="skipped", error="superseded")
            .execution_options(synchronize_session=False)
        )
        rows = [
            {"team_id": tid, "user_id": uid, "week": week, "status": "pending", "tries": 0, "created_at": now}
            for tid, uid, email, since in await db.execute(_eligible_people([w.team_id]))
            if email and teams.MAIL.fullmatch(email) and (since is None or since < slot)
        ]
        for i in range(0, len(rows), 1000):
            await db.execute(pg_insert(TeamWeeklySend).values(rows[i : i + 1000]).on_conflict_do_nothing())
        await db.execute(update(TeamWeekly).where(TeamWeekly.team_id == w.team_id).values(last_week=week).execution_options(synchronize_session=False))
        await db.commit()
        added += len(rows)
    return added


async def _claim(db: AsyncSession, n: int) -> list[tuple]:
    res = await db.execute(
        text(
            "UPDATE team_weekly_sends s SET status = 'sending', tries = s.tries + 1, claimed_at = :now "
            "FROM (SELECT team_id, user_id, week FROM team_weekly_sends WHERE status = 'pending' ORDER BY created_at, team_id, user_id LIMIT :n FOR UPDATE SKIP LOCKED) o "
            "WHERE s.team_id = o.team_id AND s.user_id = o.user_id AND s.week = o.week RETURNING s.team_id, s.user_id, s.week, s.tries, s.created_at"
        ),
        {"now": datetime.now(UTC), "n": n},
    )
    rows = list(res)
    await db.commit()  # claimed before anything is sent
    return rows


async def _done(db: AsyncSession, team_id: uuid.UUID, user_id: uuid.UUID, week: str, **values) -> None:  # noqa: ANN003
    await db.execute(
        update(TeamWeeklySend)
        .where(TeamWeeklySend.team_id == team_id, TeamWeeklySend.user_id == user_id, TeamWeeklySend.week == week, TeamWeeklySend.status == "sending")
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    await db.commit()


async def send(db: AsyncSession, smtp: dict) -> int:
    sent = 0
    deadline = time.monotonic() + ROUND_S
    cache: dict[tuple, tuple[str, str, str]] = {}
    while sent < PER_ROUND and time.monotonic() < deadline:
        batch = await _claim(db, min(CLAIM, PER_ROUND - sent))
        if not batch:
            break
        stop = False
        for k, (team_id, user_id, week, tries, queued) in enumerate(batch):
            if stop or time.monotonic() >= deadline:
                # claimed, certainly not sent: back in line without counting the try
                for tid, uid, wk, *_ in batch[k:]:
                    await _done(db, tid, uid, wk, status="pending", tries=func.greatest(TeamWeeklySend.tries - 1, 0), claimed_at=None)
                stop = True
                break
            row = (
                await db.execute(
                    select(User.email, User.is_active, PersonNotify.weekly_on, PersonNotify.lang, Team.name, TeamMember.user_id)
                    .join(PersonNotify, PersonNotify.user_id == User.id)
                    .join(Team, Team.id == team_id)
                    .outerjoin(TeamMember, (TeamMember.team_id == team_id) & (TeamMember.user_id == User.id))
                    .where(User.id == user_id)
                )
            ).first()
            if row is None or not row[1] or not row[2] or row[5] is None or not row[0] or not teams.MAIL.fullmatch(row[0]):
                await _done(db, team_id, user_id, week, status="skipped", error="not_wanted")  # left, switched off, no address
                continue
            email, _active, _on, lang, team_name, _m = row
            lang = lang if lang in TEXTS else "de"
            key = (team_id, week, lang)
            if key not in cache:
                c = await content(db, team_id, min(queued, datetime.now(UTC)))
                cache[key] = render(team_name, week, c, lang)
            subject, text_, html = cache[key]
            await dbm.release(db)  # nothing open while the mail server answers
            # the delivery log: the team, the person and the week – never the mail; its tries are attempts of one delivery
            logged = {
                "kind": "weekly",
                "channel_type": "email",
                "ref": delivery_log.ref_of(f"weekly:{team_id}:{user_id}:{week}"),
                "items": [{"kind": "weekly", "id": week, "title": subject, "severity": ""}],
                "total": 1,
                "lang": lang,
                "team_id": team_id,
                "team_name": team_name,
                "user_id": user_id,
            }
            started = time.monotonic()
            try:
                await notify.send_mail(smtp, [email], subject, text_, html)
            except notify.NotifyError as exc:
                await delivery_log.record(db, error=exc, started=started, **logged)
                again = exc.category in teams.WELCOME_RETRY and tries < TRIES
                await _done(db, team_id, user_id, week, status="pending" if again else "failed", error=exc.category)
                log.info("weekly: not sent (%s)", exc.category)
                if exc.category != "rejected":
                    stop = True  # the mail server is the problem – the rest waits for the next round
                continue
            await delivery_log.record(db, started=started, **logged)
            await _done(db, team_id, user_id, week, status="sent", error=None, sent_at=datetime.now(UTC))
            sent += 1
        if stop:
            break
    return sent


async def prune(db: AsyncSession, days: int = 90) -> int:
    """Decided weekly reviews older than `days` (hourly, in batches)."""
    return await dbm.delete_batched(db, TeamWeeklySend, TeamWeeklySend.status.in_(("sent", "failed", "skipped")), TeamWeeklySend.created_at < datetime.now(UTC) - timedelta(days=days))


# ---------------------------------------------------------------- the content


async def _affected(db: AsyncSession, follows: list[VendorFollow]) -> list[dict]:
    """Per own version how many vulnerabilities affect it now (the product page's card)."""
    from app import finding_confirm
    from app import vendor as vendor_svc

    out = []
    vers = await vendor_svc.versions_of(db, [f.id for f in follows])
    st = await finding_confirm.standing(db, [f.product for f in follows])  # confirmed findings are handled: not counted
    for f in follows:
        vs = vers.get(f.id, [])
        if not vs or vendor_svc.product_of(f) is None:
            continue
        try:
            view = await vendor_svc.product_view(db, f, vs)
            per = vendor_svc.summary(view, vs, st.skip(f.product, view["findings"]) if st else frozenset())["per_version"]
        except Exception:  # noqa: BLE001 - one product's view must not stop the review
            log.exception("weekly: view of %s failed", f.product)
            continue
        for v in vs:
            s = per.get(str(v.id)) or {}
            if s.get("affected"):
                out.append({"product": f.product, "version": v.version + (f" ({v.label})" if v.label else ""), "n": int(s["affected"]), "critical": int(s.get("critical") or 0)})
    return sorted(out, key=lambda x: (-x["critical"], -x["n"]))


async def _eol(db: AsyncSession, follows: list[VendorFollow], today: date) -> list[dict]:
    """Own versions whose support ends in the next EOL_DAYS days."""
    from app import vendor as vendor_svc

    out = []
    vers = await vendor_svc.versions_of(db, [f.id for f in follows])
    for f in follows:
        p = vendor_svc.product_of(f)
        if p is None:
            continue
        for v in vers.get(f.id, []):
            info = vendor_svc.release_info(p, v.version, today) or {}
            at = ((info.get("line") or {}).get("eol_from")) or ""
            try:
                d = date.fromisoformat(at[:10])
            except ValueError:
                continue
            if today <= d <= today + timedelta(days=EOL_DAYS):
                out.append({"product": f.product, "version": v.version, "date": d.isoformat()})
    return sorted(out, key=lambda x: x["date"])


async def content(db: AsyncSession, team_id: uuid.UUID, until: datetime) -> dict:
    """What the review of a team says for the seven days before `until`."""
    from app import finding_confirm, personal
    from app import vendor as vendor_svc

    since = until - WINDOW
    follows = list(await db.scalars(select(VendorFollow).join(TeamProduct, TeamProduct.follow_id == VendorFollow.id).where(TeamProduct.team_id == team_id, VendorFollow.enabled.is_(True))))
    labels = {f.product: ((vendor_svc.product_of(f) or {}).get("label") or f.product) for f in follows}
    base = get_config().base_url
    rank = case(*((VendorEvent.severity == s, n) for s, n in notify.RANK.items()), else_=0)
    events = list(
        await db.scalars(
            select(VendorEvent)
            .where(
                VendorEvent.product.in_(list(labels)),
                VendorEvent.baseline.is_(False),
                VendorEvent.kind.in_(("vuln", "version", "change")),
                VendorEvent.created_at >= since,
                VendorEvent.created_at < until,
                ~finding_confirm.held(standing_only=True),  # confirmed now (app/finding_confirm.py): handled, not in the review
            )
            .order_by(rank.desc(), VendorEvent.created_at.desc())
            .limit(2000)
        )
    ) if labels else []
    vulns: dict[tuple, VendorEvent] = {}
    changes, versions = [], []
    for ev in events:
        d = ev.data or {}
        if ev.kind == "vuln":
            vulns.setdefault((ev.product, str(d.get("ident") or ev.key)), ev)  # once per finding (it may hit several versions)
        elif ev.kind == "change" and d.get("impact"):
            green = notify.TLP_PREFIX if d.get("tlp") == "GREEN" else ""  # a TLP:GREEN document: labelled
            changes.append({"product": labels.get(ev.product, ev.product), "ident": str(d.get("ident") or d.get("advisory") or ""), "title": green + str(d.get("title") or ""), "severity": ev.severity, "link": base + personal.event_path(ev)})
        elif ev.kind == "version":
            versions.append({"product": labels.get(ev.product, ev.product), "version": str(d.get("version") or ""), "latest": str(d.get("latest") or ""), "link": base + personal.event_path(ev)})
    by_sev = {s: 0 for s in notify.RANK}
    for ev in vulns.values():
        by_sev[ev.severity if ev.severity in by_sev else "info"] += 1
    top = [
        {
            "severity": ev.severity if ev.severity in by_sev else "info",
            "product": labels.get(ev.product, ev.product),
            "ident": str((ev.data or {}).get("ident") or ""),
            "title": (notify.TLP_PREFIX if (ev.data or {}).get("tlp") == "GREEN" else "") + str((ev.data or {}).get("headline") or (ev.data or {}).get("title") or ""),
            "link": base + personal.event_path(ev),
        }
        for ev in list(vulns.values())[:LIST]
    ]
    affected = [{**x, "product": labels.get(x["product"], x["product"]), "link": f"{base}/vendor?product={x['product']}"} for x in await _affected(db, follows)]
    eol = [{**x, "product": labels.get(x["product"], x["product"]), "link": f"{base}/vendor?product={x['product']}&view=versions"} for x in await _eol(db, follows, until.date())]
    return {
        "review": await _review(db, follows, labels, until, base),
        "since": since,
        "until": until,
        "products": len(follows),
        "vulns": {"total": len(vulns), "by_severity": by_sev, "top": top},
        "affected": affected,
        "changes": changes,
        "eol": eol,
        "versions": versions,
    }


async def _review(db: AsyncSession, follows: list[VendorFollow], labels: dict[str, str], until: datetime, base: str) -> dict | None:
    """"Versionen zu prüfen" (app/catalog_care.py): the team's versions not confirmed within the interval – the
    reminder of the people responsible, once a week with the review. None: the review of versions is off."""
    from app import catalog_care as care

    days = await care.review_days(db)
    if not days:
        return None
    items = []
    for x in await care.due_list(db, {f.product for f in follows}, days, until):
        key = x["product"]["key"]
        for v in x["versions"]:
            version = v["version"] + (f" ({v['label']})" if v["label"] else "")
            items.append({"product": labels.get(key, key), "version": version, "n": v["age_days"], "link": f"{base}/vendor?product={key}&view=versions"})
    return {"days": days, "items": sorted(items, key=lambda x: -x["n"])}


def _date(d: datetime | date, lang: str) -> str:
    return d.strftime("%d.%m.%Y" if lang == "de" else "%Y-%m-%d")


def render(team: str, week: str, c: dict, lang: str) -> tuple[str, str, str]:
    """(subject, text, html) – short; everything from the feeds is plain text here and escaped by the template."""
    lang = lang if lang in TEXTS else "de"
    tx = TEXTS[lang]
    team = notify.one_line(team)[:80] or "–"
    week_no = week.split("-W")[-1].lstrip("0") or week
    subject = notify.one_line(tx["subject"].format(team=team, week=f"{week_no}/{week[:4]}"))
    heading = tx["heading"].format(team=team)
    last = (c["until"] - timedelta(seconds=1)).date()
    span = tx["range"].format(start=_date(c["since"].date(), lang), end=_date(last, lang), n=c["products"])
    sev_line = " · ".join(f"{tx['sev'][s]} {n}" for s, n in c["vulns"]["by_severity"].items() if n)

    def capped(items: list[dict], line) -> tuple[list[dict], int]:  # noqa: ANN001
        shown = items[:LIST]
        return [{"text": notify.one_line(line(x))[:300], "link": x.get("link") or "", "severity": x.get("severity")} for x in shown], max(0, len(items) - LIST)

    sections = []
    vul_items = [{"text": notify.one_line(f"[{tx['sev'][x['severity']]}] {x['product']}: {x['ident']} – {x['title']}".strip(" –"))[:300], "link": x["link"], "severity": x["severity"]} for x in c["vulns"]["top"]]
    sections.append({"title": tx["vulns"], "lead": sev_line or tx["vulns_none"], "items": vul_items, "more": max(0, c["vulns"]["total"] - len(vul_items))})
    for key, line in (
        ("affected", lambda x: tx["affected_line"].format(product=x["product"], version=x["version"], n=x["n"], critical=x["critical"])),
        ("changes", lambda x: f"{x['product']}: {x['ident']} – {x['title']}".strip(" –")),
        ("eol", lambda x: tx["eol_line"].format(product=x["product"], version=x["version"], date=_date(date.fromisoformat(x["date"]), lang))),
        ("versions", lambda x: tx["version_line"].format(product=x["product"], version=x["version"], latest=x["latest"])),
    ):
        items, more = capped(c[key], line)
        sections.append({"title": tx[key], "lead": "" if items else tx["none"], "items": items, "more": more})
    if c.get("review") is not None:  # the review of versions is on: what the team should confirm
        items, more = capped(c["review"]["items"], lambda x: tx["review_line"].format(product=x["product"], version=x["version"], n=x["n"]))
        sections.append({"title": tx["review"], "lead": tx["review_lead"].format(days=c["review"]["days"]) if items else tx["none"], "items": items, "more": more})
    url = get_config().base_url + "/vendor"
    for s in sections:
        s["more_text"] = tx["more"].format(n=s["more"]) if s["more"] else ""
        for it in s["items"]:
            col = notify.SEV_COLORS.get(it.get("severity") or "", None)
            it["color"] = col[0] if col else "#3d55d4"
    html = notify._env.get_template("weekly.html.j2").render(lang=lang, subject=subject, heading=heading, span=span, label=tx["label"], sections=sections, url=url, button=tx["button"], open=tx["open"], footer=tx["footer"])
    lines = [heading, "=" * min(len(heading), 60), span, ""]
    for s in sections:
        lines += [s["title"], "-" * min(len(s["title"]), 60)]
        if s["lead"]:
            lines.append(s["lead"])
        for it in s["items"]:
            lines.append(f"- {it['text']}")
            if it["link"]:
                lines.append(f"  {it['link']}")
        if s["more_text"]:
            lines.append(s["more_text"])
        lines.append("")
    lines += [f"{tx['button']}: {url}", "", "-- ", *tx["footer"]]
    return subject, "\n".join(lines) + "\n", html
