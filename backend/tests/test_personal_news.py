"""A person's own security stories by e-mail or their Teams webhook (app/personal_news.py, app/personal_news_api.py):
off until an admin allows it (and the way), the person's choice as a channel rule's (severities, sources, topics,
systems or words, exclusions; loud only, no backlog) with "Treffer", nothing from before switching on, each story at
most once per way (a certain failure comes again, an uncertain one or a stopped process never), no flood (up to three
on their own, more as one summary, at most one round per GAP), quiet hours and absence, the own settings only."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_client, sign_in
from sqlalchemy import select, text, update
from test_notify import _source
from test_personal import TEAMS_URL, _person, _switch
from test_personal import mails, web  # noqa: F401 - fixtures
from test_rule_filters import _news

from app import db, personal_news, quiet
from app import settings as settings_store
from app.models import NewsItem, PersonAbsence, PersonNews, PersonNewsSent

PAN = {"vendor": "Palo Alto Networks"}


async def _allow(news: bool = True, **ways) -> None:
    await _switch(**ways)
    async with db.session() as s:
        cur = await settings_store.get(s, "teams")
        await settings_store.put(s, "teams", {**cur, "personal_news": news})
        await s.commit()


async def _dispatch() -> dict:
    async with db.session() as s:
        return await personal_news.dispatch(s)


async def _signed(name: str = "anja"):  # noqa: ANN202
    u = await _person(name)
    c = make_client()
    await sign_in(c, u)
    return u, c


def _body(**kw) -> dict:
    return {"email_on": True, "severities": [], "sources": [], "topics": [], "systems": [], "keywords": [], "exclude": [], "lang": "de", **kw}


async def _row(uid) -> PersonNews:  # noqa: ANN001
    async with db.session() as s:
        return await s.get(PersonNews, uid)


async def _no_gap(uid) -> None:  # noqa: ANN001
    """As if the last message went out longer than GAP ago."""
    async with db.session() as s:
        p = await s.get(PersonNews, uid)
        p.email_sent_at = datetime.now(UTC) - personal_news.GAP - timedelta(minutes=1)
        await s.commit()


# ---------------------------------------------------------------- allowed, own settings, checked


async def test_off_until_an_admin_allows_it_and_own_settings_only():
    u, c = await _signed()
    async with c:
        assert (await c.get("/api/me/news-notify")).json()["reason"] == "teams_off"
        await _allow(news=False)
        me = (await c.get("/api/me/news-notify")).json()
        assert me["available"] is False and me["reason"] == "news_off"
        assert (await c.put("/api/me/news-notify", json=_body())).status_code == 409  # switching a way on: refused
        assert (await c.put("/api/me/news-notify", json=_body(email_on=False))).status_code == 200  # the choice alone: fine
        await _allow(email=True, teams=False)
        me = (await c.get("/api/me/news-notify")).json()
        assert me["available"] and me["allowed"] == {"email": True, "teams": False} and me["email"]["on"] is False
        # a way the admin has not allowed
        r = await c.put("/api/me/news-notify", json=_body(email_on=False, teams_on=True, teams_url=TEAMS_URL))
        assert r.status_code == 409 and r.json()["detail"]["code"] == "way_off"
        # the own row only – nothing in the body names another person
        other = await _person("otto")
        assert (await c.put("/api/me/news-notify", json=_body(user_id=str(other.id)))).status_code == 422
        # checked as a rule's choice
        for bad in ({"systems": [{"product": "no-such-product"}]}, {"keywords": ["x"]}, {"exclude": ["(.*)+$"]}, {"topics": ["bogus"]}, {"severities": ["fatal"]}, {"sources": ["not-a-uuid"]}, {"keywords": [f"w{n}xx" for n in range(31)]}):
            r = await c.put("/api/me/news-notify", json=_body(**bad))
            assert r.status_code == 422, (bad, r.text)
        r = await c.put("/api/me/news-notify", json=_body(severities=["critical"], systems=[PAN], keywords=["Ransomware"], exclude=["Webinar"]))
        assert r.status_code == 200, r.text
        got = r.json()
        assert got["email"]["on"] and got["systems"] == [PAN] and got["keywords"] == ["Ransomware"] and got["exclude"] == ["Webinar"] and got["severities"] == ["critical"]
    assert await _row(other.id) is None
    assert (await make_client().get("/api/me/news-notify")).status_code == 401


# ---------------------------------------------------------------- what comes


async def test_by_own_choice_with_match_nothing_old_no_backlog_once(mails):  # noqa: F811
    await _allow()
    src = await _source()
    await _news(src, "Palo Alto Networks: Lücke in PAN-OS vor dem Einschalten")  # before switching on: never
    u, c = await _signed()
    async with c:
        r = await c.put("/api/me/news-notify", json=_body(severities=["critical"], systems=[PAN], keywords=["Bleed"], exclude=["Webinar"]))
        assert r.status_code == 200, r.text
    await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS")
    await _news(src, "Citrix Bleed 3 wird ausgenutzt")
    await _news(src, "Webinar: PAN-OS richtig härten")  # an exclusion word
    await _news(src, "Fortinet schließt Lücke in FortiOS")  # neither system nor word
    await _news(src, "PAN-OS: Update für Version 11", severity="high")  # not chosen
    late = await _news(src, "Palo Alto Networks: Lücke in Prisma Access")
    async with db.session() as s:  # the backlog of a source switched on later: never
        await s.execute(update(NewsItem).where(NewsItem.id == late).values(backlog=True))
        await s.commit()
    assert await _dispatch() == {"sent": 1}
    assert len(mails.sent) == 2  # two stories: each on its own (up to notify.BATCH)
    text_ = "\n".join(m["text"] for m in mails.sent)
    assert "Kritische Lücke in PAN-OS" in text_ and "Citrix Bleed 3" in text_ and "Treffer: PAN-OS" in text_ and "Treffer: Bleed" in text_
    assert "vor dem Einschalten" not in text_ and "Webinar" not in text_ and "FortiOS" not in text_ and "Prisma" not in text_
    assert mails.sent[0]["to"] == ["anja@corp.example"] and "Security-Meldungen" in mails.sent[0]["text"]
    assert (await _row(u.id)).email_claim_at is None
    # each story once: the next rounds bring nothing again – also after widening the filter
    await _no_gap(u.id)
    assert await _dispatch() == {}
    async with make_client() as c2:
        await sign_in(c2, u)
        assert (await c2.put("/api/me/news-notify", json=_body(severities=[]))).status_code == 200
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 2


async def test_many_stories_one_summary_and_one_round_per_gap(mails):  # noqa: F811
    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200  # "alle"
    for n in range(40):
        await _news(src, f"Meldung Nummer {n}", severity="critical" if n == 7 else "medium")
    await _dispatch()
    assert len(mails.sent) == 1  # one summary, not 40 mails
    m = mails.sent[0]
    assert "40" in m["subject"] and "Meldung Nummer 7" in m["text"]  # the critical one is listed
    # within GAP: what arrives waits for the next message
    await _news(src, "Danach")
    await _dispatch()
    assert len(mails.sent) == 1
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 2 and "Danach" in mails.sent[1]["text"] and "Nummer 3" not in mails.sent[1]["text"]


async def test_a_certain_failure_comes_again_an_uncertain_one_never(mails):  # noqa: F811
    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        await c.put("/api/me/news-notify", json=_body())
    await _news(src, "Erste Meldung")
    mails.fail.append("refused")  # the mail server refused the connection: certainly nothing delivered
    assert await _dispatch() == {"failed": 1}
    p = await _row(u.id)
    assert p.email_claim_at is None and p.state_email["last_error"] == "refused" and p.email_next_at is not None
    mails.fail.clear()
    async with db.session() as s:  # the pause is over
        p = await s.get(PersonNews, u.id)
        p.email_next_at = None
        await s.commit()
    await _dispatch()
    assert len(mails.sent) == 1 and "Erste Meldung" in mails.sent[0]["text"]
    # may have arrived (a timeout): never again
    await _no_gap(u.id)
    await _news(src, "Zweite Meldung")
    mails.fail.append("timeout")
    await _dispatch()
    mails.fail.clear()
    async with db.session() as s:
        p = await s.get(PersonNews, u.id)
        p.email_next_at, p.email_sent_at = None, None
        await s.commit()
    await _dispatch()
    assert len(mails.sent) == 1
    # a claim a stopped process left behind (its stories written as sent): given up after STALE, never sent
    third = await _news(src, "Dritte Meldung")
    old = datetime.now(UTC) - personal_news.STALE - timedelta(minutes=1)
    async with db.session() as s:
        s.add(PersonNewsSent(user_id=u.id, way="email", item_id=third, sent_at=old))
        p = await s.get(PersonNews, u.id)
        p.email_claim_at = old
        await s.commit()
    await _dispatch()
    p = await _row(u.id)
    assert p.email_claim_at is None and p.state_email["last_error"] == "interrupted"
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 1


async def test_teams_way_with_the_own_workflow_url(web):  # noqa: F811
    await _allow(email=False)
    src = await _source()
    u, c = await _signed()
    async with c:
        assert (await c.put("/api/me/news-notify", json=_body(email_on=False, teams_on=True))).status_code == 422  # a URL first
        r = await c.put("/api/me/news-notify", json=_body(email_on=False, teams_on=True, systems=[PAN], teams_url=TEAMS_URL))
        assert r.status_code == 200, r.text
        assert r.json()["teams"]["url_set"] and "TopSecret" not in r.text
    await _news(src, "Palo Alto Networks: Kritische Lücke in PAN-OS")
    await _dispatch()
    sent = web.to("logic.azure.com")
    assert len(sent) == 1
    card = json.dumps(json.loads(sent[0].content), ensure_ascii=False)
    assert "Kritische Lücke in PAN-OS" in card and "PAN-OS" in card and "Treffer" in card


async def test_not_allowed_or_away_nothing_piles_up_quiet_hours_wait(mails, monkeypatch):  # noqa: F811
    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        await c.put("/api/me/news-notify", json=_body())
    # the admin switches it off: what arrives meanwhile never comes, also after switching on again
    await _allow(news=False)
    await _news(src, "Während es aus war")
    await _dispatch()
    await _allow()
    await _dispatch()
    assert mails.sent == []
    # away (without "auch an mich"): nothing is sent, nothing waits for the return
    deputy = await _person("dora")
    now = datetime.now(UTC)
    async with db.session() as s:
        s.add(PersonAbsence(user_id=u.id, deputy_id=deputy.id, starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1)))
        await s.commit()
    await _news(src, "Während der Abwesenheit")
    await _dispatch()
    async with db.session() as s:
        await s.execute(update(PersonAbsence).values(ends_at=now - timedelta(minutes=1)))
        await s.commit()
    await _dispatch()
    assert mails.sent == []
    # quiet hours: it waits, then comes as one message
    real = quiet.hold
    monkeypatch.setattr(quiet, "hold", lambda schedule, way, at: (True, None))
    await _news(src, "In der Ruhezeit")
    await _dispatch()
    assert mails.sent == []
    monkeypatch.setattr(quiet, "hold", real)
    await _dispatch()
    assert len(mails.sent) == 1 and "In der Ruhezeit" in mails.sent[0]["text"]


async def test_switched_off_account_moves_on():
    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        await c.put("/api/me/news-notify", json=_body())
    async with db.session() as s:
        await s.execute(text("UPDATE users SET is_active = false WHERE id = :u"), {"u": u.id})
        await s.commit()
    await _news(src, "Während das Konto aus war")
    await _dispatch()
    async with db.session() as s:
        top = int(await s.scalar(text("SELECT value FROM counters WHERE name = 'news_seq'")))
    assert (await _row(u.id)).email_on_seq == top  # switched on again later: nothing of this time comes


@pytest.mark.parametrize("lang", ["de", "en"])
def test_texts_in_both_languages(lang):
    assert personal_news.LABELS[lang]["label"] and len(personal_news.LABELS[lang]["footer"]) == 2


async def test_migration_0042_down_and_up():
    from alembic import command
    from sqlalchemy import inspect

    def tables(conn):  # noqa: ANN001, ANN202
        return set(inspect(conn).get_table_names())

    def down(conn):  # noqa: ANN001, ANN202
        command.downgrade(db.alembic_config(conn), "-1")  # one step: whatever comes before it after a merge
        return tables(conn)

    def up(conn):  # noqa: ANN001, ANN202
        command.upgrade(db.alembic_config(conn), "head")
        return tables(conn)

    async with db.engine().begin() as conn:
        assert "person_news" not in await conn.run_sync(down)
    async with db.engine().begin() as conn:
        assert "person_news" in await conn.run_sync(up)
    async with db.session() as s:
        assert list(await s.scalars(select(PersonNews))) == []


async def test_the_admin_switch_is_off_by_default_kept_and_audited(admin_client):
    await _switch()  # Teams on, the ways allowed – the security stories not
    r = await admin_client.get("/api/admin/teams/settings")
    assert r.json()["personal_news"] is False
    r = await admin_client.put("/api/admin/teams/settings", json={"enabled": True, "personal_email": True, "personal_teams": True, "personal_news": True})
    assert r.status_code == 200 and r.json()["personal_news"] is True, r.text
    # an older client that does not know the switch keeps it
    assert (await admin_client.put("/api/admin/teams/settings", json={"enabled": True})).json()["personal_news"] is True
    from app.models import AuditEntry

    async with db.session() as s:
        details = [a.details for a in await s.scalars(select(AuditEntry).where(AuditEntry.action == "settings.changed"))]
    assert any("personal_news" in json.dumps(d) for d in details)


async def test_a_round_is_bounded_the_rest_comes_next(mails, monkeypatch):  # noqa: F811
    monkeypatch.setattr(personal_news, "ROUND_JOBS", 2)
    await _allow()
    src = await _source()
    for name in ("anja", "bert", "cleo"):
        _u, c = await _signed(name)
        async with c:
            assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
    await _news(src, "Für alle")
    await _dispatch()
    assert len(mails.sent) == 2 and personal_news.backlog()
    await _dispatch()
    assert sorted(m["to"][0] for m in mails.sent) == ["anja@corp.example", "bert@corp.example", "cleo@corp.example"] and not personal_news.backlog()


# ---------------------------------------------------------------- fair rounds, no busy loop (review 0.1.54)


async def test_waiting_people_never_block_the_others_nor_keep_the_loop_busy(mails, monkeypatch):  # noqa: F811
    """More due person-ways than a round takes, some inside GAP, some in their quiet hours: everybody else is served in
    turn, and backlog() ends once each was looked at – no round after round for people who only wait."""
    monkeypatch.setattr(personal_news, "ROUND_JOBS", 2)
    real = quiet.hold
    monkeypatch.setattr(quiet, "hold", lambda schedule, way, at: (True, None) if (schedule or {}).get("quiet") else real(schedule, way, at))
    await _allow()
    src = await _source()
    people = {}
    for name in ("anja", "bert", "cleo", "dora", "emil"):
        u, c = await _signed(name)
        async with c:
            assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
        people[name] = u
    from app.models import PersonNotify

    async with db.session() as s:
        for name in ("anja", "bert"):  # in their quiet hours
            s.add(PersonNotify(user_id=people[name].id, kinds=["vendor_vuln"], min_severity="info", state_email={}, state_desktop={}, state_teams={}, schedule={"quiet": True}, weekly_on=False))
        p = await s.get(PersonNews, people["cleo"].id)  # inside GAP: not even due
        p.email_sent_at = datetime.now(UTC)
        await s.commit()
    await _news(src, "Für alle")
    busy = 0
    for _ in range(6):
        await _dispatch()
        busy += personal_news.backlog()
    assert sorted(m["to"][0] for m in mails.sent) == ["dora@corp.example", "emil@corp.example"]
    assert busy <= 2 and not personal_news.backlog()


async def test_backlog_never_sticks_after_switching_off(mails, monkeypatch):  # noqa: F811
    monkeypatch.setattr(personal_news, "ROUND_JOBS", 1)
    await _allow()
    src = await _source()
    for name in ("anja", "bert"):
        _u, c = await _signed(name)
        async with c:
            assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
    await _news(src, "Eins")
    await _dispatch()
    assert personal_news.backlog()
    await _allow(news=False)  # the admin switches it off
    await _dispatch()
    assert personal_news.backlog() is False
    await _allow()
    await _dispatch()
    async with db.session() as s:  # and everybody switches off
        await s.execute(update(PersonNews).values(email_on=False))
        await s.commit()
    personal_news._state.more = True
    await _dispatch()
    assert personal_news.backlog() is False


# ---------------------------------------------------------------- later changes, as a rule (review 0.1.54)


async def test_a_story_matching_later_through_a_loud_change_comes_once(mails):  # noqa: F811
    from test_rule_filters import _pan_details

    from app import news, systems
    from app.models import StoryDetail

    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        assert (await c.put("/api/me/news-notify", json=_body(severities=["critical"], systems=[PAN]))).status_code == 200
    iid = await _news(src, "CVE-2026-1234: Lücke in einer Firewall")  # nothing about Palo Alto yet
    rated = await _news(src, "Palo Alto Networks: Lücke in PAN-OS", severity="high")  # not critical yet
    await _dispatch()
    assert mails.sent == []
    # its details arrive (PAN-OS, loud) – and the other one is rated critical later
    async with db.session() as s:
        s.add(StoryDetail(item_id=iid, kind="nvd", status="ok", data=_pan_details(), fetched_at=datetime.now(UTC)))
        assert await systems.set_exact(s, iid, systems.exact(_pan_details()), quiet=False) is True
        i = await s.get(NewsItem, rated)
        i.severity = "critical"
        i.changes = news.noted(i.changes, datetime.now(UTC), rated_from="high")
        x = await s.get(NewsItem, iid)
        x.severity = "critical"
        await s.commit()
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 2  # each on its own
    text_ = "\n".join(m["text"] for m in mails.sent)
    assert "CVE-2026-1234" in text_ and "Palo Alto Networks: Lücke in PAN-OS" in text_ and "Treffer: PAN-OS" in text_
    # once: further changes bring them no more
    async with db.session() as s:
        i = await s.get(NewsItem, rated)
        i.changes = news.noted(i.changes, datetime.now(UTC), text_was="x")
        await s.commit()
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 2


async def test_a_quiet_change_or_a_wider_choice_brings_nothing_older_a_loud_change_after_it_does(mails):  # noqa: F811
    from test_rule_filters import _pan_details

    from app import news, systems

    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        assert (await c.put("/api/me/news-notify", json=_body(severities=["critical"], systems=[PAN]))).status_code == 200
        quietly = await _news(src, "Speicherfehler in einer Firewall", severity="critical")
        high = await _news(src, "Palo Alto Networks: Lücke in PAN-OS", severity="high")
        await _dispatch()
        assert mails.sent == []
        async with db.session() as s:  # a recompute (quiet) finds PAN-OS in the first one's details: no news
            await systems.set_exact(s, quietly, systems.exact(_pan_details()), quiet=True)
            await s.commit()
        await _no_gap(u.id)
        await _dispatch()
        assert mails.sent == []
        # widened to "high": the high story from before does not come by that alone …
        assert (await c.put("/api/me/news-notify", json=_body(severities=["critical", "high"], systems=[PAN]))).status_code == 200
    await _no_gap(u.id)
    await _dispatch()
    assert mails.sent == []
    # … but a loud change of its own after the widening judges it anew: it comes, once
    async with db.session() as s:
        i = await s.get(NewsItem, high)
        i.topics = ["exploited"]
        i.changes = news.noted(i.changes, datetime.now(UTC), topics=["exploited"])
        await s.commit()
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 1 and "Lücke in PAN-OS" in mails.sent[0]["text"]
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 1


# ---------------------------------------------------------------- consistency of the settings (review 0.1.54)


async def test_removing_the_shared_teams_url_switches_teams_off_for_both(web):  # noqa: F811
    from app.models import PersonNotify

    await _allow()
    u, c = await _signed()
    async with c:
        r = await c.put("/api/me/news-notify", json=_body(email_on=False, teams_on=True, teams_url=TEAMS_URL))
        assert r.status_code == 200 and r.json()["teams"]["on"]
        async with db.session() as s:
            n = await s.get(PersonNotify, u.id)
            n.teams_on = True
            await s.commit()
        # removed under "Hersteller-News meiner Produkte"
        from test_personal import _team

        await _team([u])
        r = await c.put("/api/me/vendor-notify", json={"kinds": ["vendor_vuln"], "teams_url": ""})
        assert r.status_code == 200 and r.json()["teams"]["on"] is False and r.json()["teams"]["url_set"] is False
        me = (await c.get("/api/me/news-notify")).json()
        assert me["teams"]["on"] is False and me["teams"]["url_set"] is False
        # and the other way round: removed here, the vendor news' Teams way is off too
        await c.put("/api/me/news-notify", json=_body(email_on=False, teams_on=True, teams_url=TEAMS_URL))
        await c.put("/api/me/vendor-notify", json={"kinds": ["vendor_vuln"], "teams_on": True})
        r = await c.put("/api/me/news-notify", json=_body(email_on=False, teams_on=False, teams_url=""))
        assert r.status_code == 200
        assert (await c.get("/api/me/vendor-notify")).json()["teams"]["on"] is False


async def test_ways_can_be_switched_off_while_the_admin_has_it_off(mails):  # noqa: F811
    await _allow()
    u, c = await _signed()
    async with c:
        assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
        await _allow(news=False)
        r = await c.put("/api/me/news-notify", json=_body(email_on=False, severities=["critical"]))
        assert r.status_code == 200 and r.json()["email"]["on"] is False and r.json()["severities"] == ["critical"]
        r = await c.put("/api/me/news-notify", json=_body(email_on=True))
        assert r.status_code == 409 and r.json()["detail"]["code"] == "news_off"


async def test_switched_off_and_on_while_sending_brings_nothing_from_before(mails, monkeypatch):  # noqa: F811
    """A message being sent while the person switches the way off and on again: its failure (certainly not delivered)
    must not hand back stories from before the new switch-on, nor overwrite the new start."""
    from app import notify

    await _allow()
    src = await _source()
    u, c = await _signed()
    await c.__aenter__()
    try:
        assert (await c.put("/api/me/news-notify", json=_body())).status_code == 200
        await _news(src, "Vor dem neuen Einschalten")

        async def send_mail(cfg, to, subject, text_, html):  # noqa: ANN001, ANN202
            assert (await c.put("/api/me/news-notify", json=_body(email_on=False))).status_code == 200
            assert (await c.put("/api/me/news-notify", json=_body(email_on=True))).status_code == 200
            raise notify.NotifyError("refused")

        monkeypatch.setattr(notify, "send_mail", send_mail)
        await _dispatch()
        p = await _row(u.id)
        assert p.email_on and p.email_claim_at is None
        monkeypatch.setattr(notify, "send_mail", lambda *a: mails.sent.append({"to": a[1], "subject": a[2], "text": a[3]}) or _done())
        async with db.session() as s:
            q = await s.get(PersonNews, u.id)
            q.email_next_at = None
            await s.commit()
        await _no_gap(u.id)
        await _news(src, "Nach dem neuen Einschalten")
        await _dispatch()
        text_ = "\n".join(m["text"] for m in mails.sent)
        assert "Nach dem neuen Einschalten" in text_ and "Vor dem neuen Einschalten" not in text_
    finally:
        await c.__aexit__(None, None, None)


async def _done() -> None:
    return None


async def test_changed_after_reads_every_loud_change():
    from app import news
    from app.models import NewsItemSource, NewsSource

    src = await _source()
    before = datetime.now(UTC)
    ids = {k: await _news(src, f"Meldung {k}") for k in ("sev", "text", "topic", "system", "carried", "none")}
    later = datetime.now(UTC) + timedelta(seconds=1)
    async with db.session() as s:
        other = NewsSource(key="o", name="Other", url="https://o.example.org/f.xml", site="", builtin=False, enabled=True, failures=0)
        s.add(other)
        await s.flush()
        for k, what in (("sev", {"rated_from": "low"}), ("text", {"text_was": "x"}), ("topic", {"topics": ["poc"]}), ("system", {"systems": ["panos"]})):
            i = await s.get(NewsItem, ids[k])
            i.changes = news.noted(i.changes, later, **what)
        s.add(NewsItemSource(item_id=ids["carried"], source_id=other.id, fresh=True, carried_at=later))
        await s.commit()
        got = set(await s.scalars(select(NewsItem.id).where(personal_news.changed_after(before), NewsItem.id.in_(list(ids.values())))))
        assert got == {ids[k] for k in ("sev", "text", "topic", "system", "carried")}
        assert set(await s.scalars(select(NewsItem.id).where(personal_news.changed_after(later + timedelta(seconds=1)), NewsItem.id.in_(list(ids.values()))))) == set()


async def test_sent_rows_go_after_a_week_and_a_day():
    src = await _source()
    u = await _person("anja")
    iid = await _news(src, "Alt")
    new = await _news(src, "Neu")
    async with db.session() as s:
        s.add(PersonNewsSent(user_id=u.id, way="email", item_id=iid, sent_at=datetime.now(UTC) - personal_news.MAX_AGE - timedelta(days=2)))
        s.add(PersonNewsSent(user_id=u.id, way="email", item_id=new, sent_at=datetime.now(UTC)))
        await s.commit()
    async with db.session() as s:
        assert await personal_news.prune(s) == 1
        assert list(await s.scalars(select(PersonNewsSent.item_id))) == [new]


async def test_more_than_one_message_takes_come_the_next_time(mails, monkeypatch):  # noqa: F811
    monkeypatch.setattr(personal_news, "CLAIM_MAX", 2)
    await _allow()
    src = await _source()
    u, c = await _signed()
    async with c:
        await c.put("/api/me/news-notify", json=_body())
    for n in range(5):
        await _news(src, f"Meldung {n}")
    await _dispatch()
    assert len(mails.sent) == 2
    await _no_gap(u.id)
    await _dispatch()
    await _no_gap(u.id)
    await _dispatch()
    text_ = "\n".join(m["text"] for m in mails.sent)
    assert all(f"Meldung {n}" in text_ for n in range(5)) and len(mails.sent) == 5
    await _no_gap(u.id)
    await _dispatch()
    assert len(mails.sent) == 5
