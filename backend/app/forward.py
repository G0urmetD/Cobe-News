"""An mein Team weiterleiten: a reader sends a story or a Vendor News finding with a short comment to one of their teams.

Security boundary: the reader names only the team (one of their own) and the thing (a story, a finding of a followed
product) – never a target. Where it goes is the team's forward channel, chosen by an admin among the existing notification
channels (Team.forward_channel_id). The channel's own sending is used unchanged (app/notify.py: the egress checks of
the webhook URLs, the pinned connection, no redirects, SMTP through its checked socket).

What the reader writes is text, nothing more, in every format: escaped for the channel (Slack plain text, Teams markdown
escaped, Discord escaped with no mention allowed, Telegram HTML escaped, the mail's HTML through Jinja's autoescape),
links in it defanged ("example[.]com", "https[:]//…" – nothing becomes a link), "@" never a mention, and it never reaches
a mail header (the subject carries the title, made one line).

The chat channels (Slack, Teams, Discord, Telegram, Mattermost, ntfy, Gotify) get the notifications' card
(notify.card_fields, 0.1.46): the title, Produkt (only when reliably known), Quelle, Kategorie (topics and severity), for a
finding Dringlichkeit and the own versions, the reader's comment as a field of its own ("Kommentar"), the short
description (notify.brief). The mail keeps its form; the webhook's JSON gains topics and product (additive).

Limits (per process – the app runs one worker): per person PER_HOUR forwards an hour; the same story or finding to the
same team once within SAME_WINDOW (whoever sends it). Nothing is stored about who forwarded what: the delivery log
(app/delivery_log.py) records the attempt with the team and the story / finding only – never the sender or the comment."""

import asyncio
import html
import math
import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlencode

from fastapi import APIRouter
from jinja2 import Environment, FileSystemLoader
from pydantic import ConfigDict, Field, model_validator
from sqlalchemy import select

from app import db as dbm
from app import delivery_log, news, notify, story_details, teams
from app import settings as settings_store
from app import vendor as vendor_svc
from app import vendor_score
from app.config import get_config
from app.deps import Db, NoNul, Reader, api_error
from app.models import NewsItem, NewsSource, NotifyChannel, StoryDetail, Team, TeamMember, VendorFollow
from app.plaintext import neutral

router = APIRouter(prefix="/api", tags=["forward"])

COMMENT_MAX = 1000
PER_HOUR = 10
HOUR = 3600.0
SAME_WINDOW = 600.0  # the same thing to the same team: once within ten minutes
DEADLINE = 30.0  # the whole send – the reader waits for the answer
VERSIONS_SHOWN = 6

clock = time.monotonic  # tests move it on
_attempts: dict[uuid.UUID, deque[float]] = {}  # person → the times of their forwards within the last hour
_recent: dict[tuple[uuid.UUID, str], float] = {}  # (team, thing) → when it went out (or is going out now)


def reset() -> None:
    _attempts.clear()
    _recent.clear()


# ---------------------------------------------------------------- the comment: plain text in every channel

_SCHEME = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}):(?=//)")
_DOT = re.compile(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z][A-Za-z0-9-])")
ZWSP = "​"


def defang(text: str) -> str:
    """Nothing in the text becomes a link or a mention: "https://x.example" → "https[:]//x[.]example", "@team" →
    "@​team" (a zero-width space after the @). The security way of writing an address that must not be clicked."""
    text = _SCHEME.sub(r"\1[:]", text)
    text = _DOT.sub("[.]", text)
    return text.replace("@", "@" + ZWSP)


def clean_comment(text: str) -> str:
    """Line breaks kept (at most one empty line in a row), every other control or direction character out, defanged,
    at most COMMENT_MAX characters."""
    text = neutral(text or "", control="").replace("\t", " ")
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return defang(text[:COMMENT_MAX])


def _lines(text: str) -> list[str]:
    return [" ".join(x.split()) for x in text.split("\n")]


# ---------------------------------------------------------------- the message

TEXT = {
    "de": {
        "head": "{who} hat eine Meldung an {team} weitergeleitet",
        "subject": "[Cobe News] Weitergeleitet von {who}: {title}",
        "comment": "Kommentar",
        "score": "Dringlichkeit {value} ({level})",
        "score_label": "Dringlichkeit",
        "score_value": "{value} ({level})",
        "levels": {"now": "Sofort", "soon": "Bald", "watch": "Beobachten"},
        "versions": "Eure Versionen",
        "status": {"affected": "betroffen", "possible": "möglicherweise betroffen", "unversioned": "ohne Version", "service": "Cloud-Dienst", "stale": "unklare Altdaten", "not_affected": "nicht betroffen"},
        "fix": "Fix",
        "article": "Quelle öffnen",
        "open": "In Cobe News öffnen",
        "footer": "Weitergeleitet mit Cobe News an das Team {team}. Den Kanal legt ein Admin unter Einstellungen › Teams fest.",
        "vendor": "Vendor News",
    },
    "en": {
        "head": "{who} forwarded a story to {team}",
        "subject": "[Cobe News] Forwarded by {who}: {title}",
        "comment": "Comment",
        "score": "Urgency {value} ({level})",
        "score_label": "Urgency",
        "score_value": "{value} ({level})",
        "levels": {"now": "Now", "soon": "Soon", "watch": "Watch"},
        "versions": "Your versions",
        "status": {"affected": "affected", "possible": "possibly affected", "unversioned": "no version given", "service": "cloud service", "stale": "unclear old data", "not_affected": "not affected"},
        "fix": "fix",
        "article": "Open source",
        "open": "Open in Cobe News",
        "footer": "Forwarded with Cobe News to the team {team}. An admin chooses the channel under Settings › Teams.",
        "vendor": "Vendor News",
    },
}


@dataclass
class Forward:
    """What goes out – the sender's and the feed's text still raw; each renderer escapes it for its format."""

    sender: str
    team: str
    comment: str  # already cleaned and defanged (clean_comment)
    title: str
    summary: str
    url: str  # the article / advisory (feed data: only http(s) becomes a link)
    link: str  # Cobe News
    severity: str
    source: str
    published_at: datetime | None
    cves: list[str] = field(default_factory=list)
    score: dict | None = None  # {"value", "level"} – a finding's Dringlichkeit
    versions: list[dict] = field(default_factory=list)  # {"product", "version", "label", "status", "fixed"}
    kind: str = "story"  # story | finding
    # the card's fields as the notifications have them (notify.card_fields): the product when reliably known, the
    # topics (news.TOPICS), the kind of source (notify.CARD_LABELS kinds)
    product: str = ""
    topics: list[str] = field(default_factory=list)
    source_kind: str = ""
    tlp: str = ""  # "GREEN": a finding from a CSAF provider's TLP:GREEN document – labelled in every format

    def __post_init__(self) -> None:
        # the feed's text: no direction or control characters in any channel (app/plaintext.py, as the notifications)
        self.title, self.summary, self.source, self.product = (neutral(x) for x in (self.title, self.summary, self.source, self.product))


def _sev(lang: str, s: str) -> str:
    return notify.LABELS[lang]["sev"].get(s, s)


def _score(f: Forward, lang: str) -> str:
    lb = TEXT[lang]
    return lb["score_value"].format(value=f.score["value"], level=lb["levels"].get(f.score["level"], f.score["level"])) if f.score else ""


def _versions(f: Forward, lang: str) -> str:
    lb = TEXT[lang]
    rows = []
    for v in f.versions[:VERSIONS_SHOWN]:
        what = " ".join(x for x in (v.get("product") or "", v.get("version") or "") if x).strip() or "–"
        if v.get("label"):
            what += f" ({v['label']})"
        st = lb["status"].get(v.get("status") or "", v.get("status") or "")
        rows.append(f"{what}: {st}" + (f", {lb['fix']} {v['fixed']}" if v.get("fixed") else ""))
    more = f" (+{len(f.versions) - VERSIONS_SHOWN})" if len(f.versions) > VERSIONS_SHOWN else ""
    return "; ".join(rows) + more if rows else ""


def _facts(f: Forward, lang: str) -> list[str]:
    """The mail's plain lines: the Dringlichkeit, the own versions – escaped like the feed's text."""
    lb = TEXT[lang]
    out = [notify.tlp_line(lang)] if f.tlp == "GREEN" else []
    if f.score:
        out.append(lb["score"].format(value=f.score["value"], level=lb["levels"].get(f.score["level"], f.score["level"])))
    if v := _versions(f, lang):
        out.append(f"{lb['versions']}: {v}")
    return out


def _meta(f: Forward, lang: str) -> str:
    return " · ".join(x for x in (_sev(lang, f.severity), f.source, _when(f, lang)) if x)


def _when(f: Forward, lang: str) -> str:
    return notify._date(f.published_at, lang) if f.published_at else ""


def _card(f: Forward, lang: str) -> list[tuple[str, str]]:
    """The chat channels' card, as the notifications have it (notify.card_fields): Produkt (when known), Quelle,
    Kategorie (topics and severity) – then a finding's Dringlichkeit and the own versions. (label, value), plain text:
    each renderer escapes it. The comment is a field of its own ("Kommentar", line by line, plain text), the short
    description (notify.brief) follows the fields."""
    lb = TEXT[lang]
    s = notify.Story("", f.title, f.summary, f.url, f.severity, f.source, f.published_at or datetime.now(UTC), product=f.product, topics=list(f.topics), source_kind=f.source_kind, tlp=f.tlp)
    out = notify.card_fields(s, lang)
    if f.score:
        out.append((lb["score_label"], _score(f, lang)))
    if v := _versions(f, lang):
        out.append((lb["versions"], v))
    return out


def render_slack(f: Forward, lang: str) -> dict:
    lb = TEXT[lang]
    head = lb["head"].format(who=f.sender, team=f.team)
    # the header as plain_text: Slack parses no markup, no <!channel>, no <url|label> in it
    blocks: list[dict] = [{"type": "header", "text": {"type": "plain_text", "text": defang(" ".join(head.split()))[:150]}}]
    url = notify._safe_url(f.url)
    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*<{url}|{notify._slack_esc(f.title)}>*" if url else f"*{notify._slack_esc(f.title)}*"}})
    blocks.append({"type": "section", "fields": [{"type": "mrkdwn", "text": f"*{label}*\n{notify._slack_esc(value)}"} for label, value in _card(f, lang)]})
    if f.comment:
        # plain_text: Slack parses no markup, no <!channel>, no <url|label> in it
        blocks.append({"type": "section", "text": {"type": "plain_text", "text": f"{lb['comment']}:\n{f.comment}"[:2900], "emoji": False}})
    if b := notify.brief(f.summary):
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": notify._slack_esc(b)}})
    if when := _when(f, lang):
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": notify._slack_esc(when)}]})
    blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": lb["open"]}, "url": f.link}]})
    return {"text": f"[Cobe News] {notify._slack_esc(head)}: {notify._slack_esc(f.title)}"[:300], "blocks": blocks}


def render_teams(f: Forward, lang: str) -> dict:
    lb = TEXT[lang]
    esc = notify._teams_esc
    body: list[dict] = [{"type": "TextBlock", "text": esc(defang(lb["head"].format(who=f.sender, team=f.team))), "weight": "Bolder", "size": "Medium", "wrap": True}]
    url = notify._safe_url(f.url)
    items: list[dict] = [
        {"type": "TextBlock", "text": f"[{esc(f.title)}]({url})" if url else esc(f.title), "weight": "Bolder", "wrap": True},
        {"type": "FactSet", "facts": [{"title": label, "value": esc(value)} for label, value in _card(f, lang)]},
    ]
    if f.comment:
        quoted = "\n\n".join(esc(x) for x in _lines(f.comment) if x)
        label = {"type": "TextBlock", "text": esc(lb["comment"]), "isSubtle": True, "spacing": "None", "wrap": True}
        items.append({"type": "Container", "style": "emphasis", "items": [label, {"type": "TextBlock", "text": quoted[:3000], "wrap": True}]})
    if b := notify.brief(f.summary):
        items.append({"type": "TextBlock", "text": esc(b), "wrap": True})
    if when := _when(f, lang):
        items.append({"type": "TextBlock", "text": esc(when), "isSubtle": True, "spacing": "Small", "wrap": True})
    body.append({"type": "Container", "separator": True, "items": items})
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "actions": [{"type": "Action.OpenUrl", "title": lb["open"], "url": f.link}],
    }
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def render_discord(f: Forward, lang: str) -> dict:
    lb = TEXT[lang]
    esc = notify._discord_esc
    content = f"**{esc(defang(lb['head'].format(who=f.sender, team=f.team)))}**"
    fields = [{"name": label[:256], "value": (esc(value) or "–")[: notify.DISCORD_FIELD], "inline": True} for label, value in _card(f, lang)]
    if f.comment:
        quoted = "\n".join(esc(x) for x in _lines(f.comment))
        cut = quoted if len(quoted) <= notify.DISCORD_FIELD else quoted[: notify.DISCORD_FIELD - 2] + " …"
        fields.append({"name": lb["comment"], "value": cut or "–", "inline": False})
    b = notify.brief(f.summary)
    e: dict = {
        "title": esc(f.title)[:250],
        "description": (f"{esc(b)}\n" if b else "") + f"[{esc(lb['open'])}]({notify._safe_url(f.link)})",
        "color": notify.DISCORD_COLORS.get(f.severity, notify.DISCORD_COLORS["info"]),
        "fields": fields,
    }
    if when := _when(f, lang):
        e["footer"] = {"text": when}
    if url := notify._safe_url(f.url):
        e["url"] = url
    # nobody is pinged, whatever the text says (the @ is defused as well)
    return {"username": "Cobe News", "content": content[:1900], "embeds": [e], "allowed_mentions": {"parse": []}}


def render_telegram(f: Forward, lang: str) -> str:
    lb = TEXT[lang]
    tg = notify._tg
    out = [f"<b>{tg(defang(lb['head'].format(who=f.sender, team=f.team)))}</b>", ""]
    head = notify._tg_link(f.url, f.title[:300])
    out.append(head if head.startswith("<b>") else f"<b>{head}</b>")
    out += [f"<b>{tg(label)}:</b> {tg(value)}" for label, value in _card(f, lang)]
    if f.comment:
        out += [f"<b>{tg(lb['comment'])}:</b>", "\n".join(html.escape(x, quote=False) for x in _lines(f.comment))]
    if b := notify.brief(f.summary):
        out.append(tg(b))
    out.append(" · ".join(x for x in (tg(_when(f, lang)), notify._tg_link(f.link, lb["open"])) if x))
    text = "\n".join(out)
    if len(text) > notify.TELEGRAM_MAX and f.summary:  # the summary goes first (never a cut through a tag)
        return render_telegram(Forward(**{**f.__dict__, "summary": ""}), lang)
    return text


def render_text(f: Forward, lang: str) -> tuple[str, str]:
    """(title, message) for ntfy and Gotify – plain text (neither renders it; nothing of it goes into a header)."""
    lb = TEXT[lang]
    head = defang(lb["head"].format(who=f.sender, team=f.team))
    out = [notify.one_line(f.title), *(f"{label}: {notify.one_line(value)}" for label, value in _card(f, lang))]
    if f.comment:
        out += [f"{lb['comment']}:", f.comment]
    if b := notify.brief(f.summary):
        out += ["", b]
    if when := _when(f, lang):
        out.append(when)
    if u := notify._safe_url(f.url):
        out.append(f"{lb['article']}: {u}")
    out.append(f"{lb['open']}: {notify._safe_url(f.link)}")
    return head, notify.plain_block("\n".join(out))


def render_mattermost(f: Forward, lang: str) -> dict:
    """Mattermost: everything escaped (mm_esc – no markup, no mention), the comment line by line."""
    lb = TEXT[lang]
    esc = notify.mm_esc
    text = f"**{esc(defang(lb['head'].format(who=f.sender, team=f.team)))}**"
    url = notify._safe_url(f.url)
    body = f"**[{esc(f.title)[:400]}]({url})**" if url else f"**{esc(f.title)[:400]}**"
    if b := notify.brief(f.summary):
        body += "\n" + esc(b)
    body += "\n" + " · ".join(x for x in (esc(_when(f, lang)), f"[{esc(lb['open'])}]({notify._safe_url(f.link)})") if x)
    fields = [{"title": notify.mm_plain(label), "value": esc(value), "short": True} for label, value in _card(f, lang)]
    if f.comment:
        fields.append({"title": notify.mm_plain(lb["comment"]), "value": "\n".join(esc(x) for x in _lines(f.comment)), "short": False})
    att = {"fallback": notify.mm_plain(f.title)[:300], "color": notify.MM_COLORS.get(f.severity, notify.MM_COLORS["info"]), "text": body, "fields": fields}
    return {"username": "Cobe News", "text": text[:4000], "attachments": [att]}


_env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"), autoescape=True)


def render_mail(f: Forward, lang: str) -> tuple[str, str, str]:
    """(subject, text, html). The subject: sender and title only, one line (send_mail makes it one line again); the
    comment never goes into a header."""
    lb = TEXT[lang]
    nl = notify.LABELS[lang]
    head = defang(lb["head"].format(who=f.sender, team=f.team))
    subject = notify.one_line(lb["subject"].format(who=f.sender, title=f.title))[:250]
    facts = _facts(f, lang)
    footer = lb["footer"].format(team=f.team)
    body = _env.get_template("forward.html.j2").render(
        lang=lang,
        subject=subject,
        head=head,
        comment_label=lb["comment"],
        comment=f.comment,
        title=f.title,
        summary=f.summary,
        url=notify._safe_url(f.url),
        link=f.link,
        meta=_meta(f, lang),
        sev_color=notify.SEV_COLORS.get(f.severity, notify.SEV_COLORS["info"])[0],
        sev_bg=notify.SEV_COLORS.get(f.severity, notify.SEV_COLORS["info"])[1],
        accent=notify.ACCENTS.get(f.severity, notify.ACCENTS["info"]),
        facts=[x for x in facts if x != notify.tlp_line(lang)],
        tlp=notify.tlp_line(lang) if f.tlp == "GREEN" else "",
        labels={"article": lb["article"], "open": lb["open"], "button": nl["button"]},
        app_url=get_config().base_url + "/",
        footer=footer,
    )
    lines = [head, "=" * min(len(head), 60), ""]
    if f.comment:
        lines += [f"{lb['comment']}:", *(f"> {x}" for x in f.comment.split("\n")), ""]
    lines += [f"[{_meta(f, lang)}]", f.title]
    if f.summary:
        lines.append(f.summary)
    lines += facts
    if u := notify._safe_url(f.url):
        lines.append(f"{lb['article']}: {u}")
    lines += [f"{lb['open']}: {f.link}", "", "-- ", footer]
    return subject, "\n".join(lines) + "\n", body


def render_webhook(f: Forward, channel: str, lang: str, delivery: str) -> dict:
    """The generic webhook's JSON, type "news.forward" – sender, comment and the feed's text are untrusted input for
    the receiver (the comment comes defanged)."""
    return {
        "version": notify.WEBHOOK_VERSION,
        "type": "news.forward",
        "id": delivery,
        "sent_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "app": "cobe-news",
        "app_url": get_config().base_url + "/",
        "channel": channel,
        "lang": lang,
        "forward": {
            "by": f.sender,
            "team": f.team,
            "comment": f.comment,
            "kind": f.kind,
            "title": f.title,
            "summary": f.summary,
            "url": f.url if f.url.lower().startswith(("https://", "http://")) else "",
            "link": f.link,
            "severity": f.severity,
            "source": f.source,
            "published_at": f.published_at.astimezone(UTC).isoformat().replace("+00:00", "Z") if f.published_at else None,
            "cves": list(f.cves),
            "score": f.score,
            "versions": f.versions[:VERSIONS_SHOWN],
            # 0.1.46, additive (as news.stories): the topics (news.TOPICS) and the product when reliably known ("" otherwise)
            "topics": list(f.topics),
            "product": f.product,
            "tlp": f.tlp or "",  # additive: "GREEN" – share internally only
        },
    }


async def deliver(t: notify.Target, f: Forward, lang: str, smtp: dict | None) -> None:
    """One message to the team's channel through the channel's own sending (notify.post / notify.send_mail) – or
    notify.NotifyError."""
    lang = lang if lang in TEXT else "de"
    if t.type == "email":
        subject, text, body = render_mail(f, lang)
        await notify.send_mail(smtp or {}, t.recipients, subject, text, body)
        return
    if t.type == "telegram":
        if not notify.TELEGRAM_TOKEN.match(t.token) or not notify.TELEGRAM_CHAT.match(t.chat_id):
            raise notify.NotifyError("not_configured")
        chat: int | str = int(t.chat_id) if t.chat_id.lstrip("-").isdigit() else t.chat_id
        payload = {"chat_id": chat, "text": render_telegram(f, lang), "parse_mode": "HTML", "link_preview_options": {"is_disabled": True}}
        reply = await notify.post(f"{notify.TELEGRAM_API}/bot{t.token}/sendMessage", notify._json(payload), notify.JSON_HEADERS, describe=notify._telegram_detail)
        if reply.json().get("ok") is False:
            raise notify.NotifyError("rejected", notify._telegram_detail(reply))
        return
    if t.type in ("ntfy", "gotify", "mattermost"):
        title, message = render_text(f, lang)
        await notify.send_text(t, title=title, message=message, severity=f.severity, click=f.link, mattermost=render_mattermost(f, lang))
        return
    if not t.url:
        raise notify.NotifyError("not_configured")
    notify.check_url(t.type, t.url, allow_http=t.allow_http)
    if t.type == "slack":
        await notify.post(t.url, notify._json(render_slack(f, lang)), notify.JSON_HEADERS)
    elif t.type == "teams":
        await notify.post(t.url, notify._json(render_teams(f, lang)), notify.JSON_HEADERS)
    elif t.type == "discord":
        await notify.post(t.url, notify._json(render_discord(f, lang)), notify.JSON_HEADERS)
    elif t.type == "webhook":
        delivery = str(uuid.uuid4())
        body = notify._json(render_webhook(f, t.name, lang, delivery))
        headers = {"Content-Type": "application/json", "User-Agent": "Cobe-News-Webhook/1", "X-Cobe-Event": "news.forward", "X-Cobe-Delivery": delivery}
        if t.hmac:
            ts = str(int(time.time()))
            headers |= {"X-Cobe-Timestamp": ts, "X-Cobe-Signature": notify.sign(t.hmac, ts, body)}
        if t.header_name and t.header_value:
            headers[t.header_name] = t.header_value
        await notify.post(t.url, body, headers, use_proxy=t.use_proxy)
    else:
        raise notify.NotifyError("not_configured")


# ---------------------------------------------------------------- the limits


def _check_rate(user_id: uuid.UUID, now: float) -> None:
    q = _attempts.setdefault(user_id, deque())
    while q and now - q[0] >= HOUR:
        q.popleft()
    if len(q) >= PER_HOUR:
        raise api_error(429, "forward_rate_limited", retry_after=max(1, math.ceil(HOUR - (now - q[0]))))


def _reserve(key: tuple[uuid.UUID, str], now: float) -> None:
    for k in [k for k, at in _recent.items() if now - at >= SAME_WINDOW]:
        _recent.pop(k, None)
    at = _recent.get(key)
    if at is not None:
        raise api_error(409, "forward_duplicate", retry_after=max(1, math.ceil(SAME_WINDOW - (now - at))))
    _recent[key] = now


# ---------------------------------------------------------------- what is forwarded


def _cobe_link(path: str, **query: str) -> str:
    return f"{get_config().base_url}{path}?{urlencode(query)}"


async def _story(db, story_id: uuid.UUID) -> tuple[str, Forward]:  # noqa: ANN001
    row = (await db.execute(select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(NewsItem.id == story_id))).first()
    if row is None:
        raise api_error(404, "not_found")
    i, s = row
    det = await db.get(StoryDetail, i.id)
    data = det.data if det is not None and det.status == "ok" else None
    versions = []
    matched = story_details.matches(data, await story_details.followed(db)) if data else []
    for m in matched:
        label = m.get("label") or m["product"]  # the catalogue's label of today (story_details.followed)
        versions += [{"product": label, "version": v.get("version"), "label": v.get("label") or "", "status": v["status"], "fixed": v.get("fixed")} for v in m["versions"] if v["status"] != "not_affected"]
    b = news.BUILTIN_BY_KEY.get(s.key) if s.builtin else None
    f = Forward(
        sender="", team="", comment="", title=i.title, summary=i.summary or "", url=i.url or "", link=_cobe_link("/", story=str(i.id)), severity=i.severity,
        source=s.name, published_at=i.published_at, cves=list(i.cves or [])[:30], versions=versions, kind="story",
        product=notify.card_product(data, matched) if data else "", topics=[t for t in news.TOPICS if t in (i.topics or [])], source_kind=b.category if b else "custom",
    )
    return f"story:{i.id}", f


async def _finding(db, product: str, finding: str, lang: str) -> tuple[str, Forward]:  # noqa: ANN001
    fol = await db.scalar(select(VendorFollow).where(VendorFollow.product == product))
    if fol is None:
        raise api_error(404, "not_found")
    vs = (await vendor_svc.versions_of(db, [fol.id])).get(fol.id, [])
    view = await vendor_svc.product_view(db, fol, vs)
    vendor_score.apply(view)
    x = next((y for y in view["findings"] if y["id"] == finding), None)
    if x is None:
        raise api_error(404, "not_found")
    p = view["product"]
    label = p.get("label") or product
    rows = [{"product": label, "version": r.get("version"), "label": next((v.label for v in vs if str(v.id) == r.get("id")), ""), "status": r["status"], "fixed": r.get("fixed")} for r in x["versions"]]
    published = None
    if x.get("published_at"):
        try:
            published = datetime.fromisoformat(x["published_at"])
        except ValueError:
            published = None
    sc = x.get("score")
    f = Forward(
        sender="", team="", comment="", title=f"{label}: {x['ident']} – {x.get('headline') or x.get('title') or ''}".strip(" –"), summary=(x.get("summary") or "")[:600],
        url=x.get("url") or "", link=_cobe_link("/vendor", product=product, finding=x["id"]), severity=x.get("severity") or "info", source=TEXT[lang]["vendor"],
        published_at=published, cves=list(x.get("cves") or [])[:30], score={"value": sc["value"], "level": sc["level"]} if sc else None, versions=rows, kind="finding",
        product=label, topics=["exploited"] if x.get("exploited") else [], source_kind="vendor_news", tlp="GREEN" if x.get("tlp") == "GREEN" else "",
    )
    if f.tlp:
        f.title = notify.TLP_PREFIX + f.title
    return f"finding:{product}:{x['id']}", f


# ---------------------------------------------------------------- the API


class ForwardIn(NoNul):
    """The team and the thing – no target, no address: extra fields are refused."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    team_id: uuid.UUID
    comment: str = Field(default="", max_length=COMMENT_MAX)
    story_id: uuid.UUID | None = None
    product: str | None = Field(default=None, min_length=1, max_length=200)
    finding: str | None = Field(default=None, min_length=1, max_length=300)
    lang: Literal["de", "en"] = "de"

    @model_validator(mode="after")
    def _one_thing(self):  # noqa: ANN202
        if (self.story_id is None) == (self.product is None or self.finding is None):
            raise ValueError("a story or a finding (product and finding)")
        if self.story_id is not None and (self.product or self.finding):
            raise ValueError("a story or a finding, not both")
        return self


@router.post("/forward")
async def forward(body: ForwardIn, user: Reader, db: Db) -> dict:
    """Forward a story or a finding to one of the own teams – to the channel an admin chose for it."""
    if not await teams.is_on(db):
        raise api_error(409, "teams_off")
    # one of the own teams – a foreign or unknown team looks the same (404)
    team = await db.scalar(select(Team).join(TeamMember, TeamMember.team_id == Team.id).where(Team.id == body.team_id, TeamMember.user_id == user.id))
    if team is None:
        raise api_error(404, "not_found")
    if team.forward_channel_id is None:
        raise api_error(409, "forward_no_channel")
    ch = await db.get(NotifyChannel, team.forward_channel_id)
    if ch is None:
        raise api_error(409, "forward_no_channel")
    _check_rate(user.id, clock())  # before any work: over the limit, nothing is looked up
    if body.story_id is not None:
        key, msg = await _story(db, body.story_id)
    else:
        key, msg = await _finding(db, body.product or "", body.finding or "", body.lang)
    msg.sender = (user.display_name or user.username or "?").strip()[:120]
    msg.team = team.name
    msg.comment = clean_comment(body.comment)
    now = clock()
    _check_rate(user.id, now)
    rkey = (team.id, key)
    _reserve(rkey, now)
    _attempts[user.id].append(now)  # counts also when the channel fails: it was asked
    # the delivery log: the team and the thing – never the sender or the comment (no log of who forwarded what)
    logged = {
        "kind": "forward",
        "channel_id": ch.id,
        "channel_name": ch.name,
        "channel_type": ch.type,
        "ref": uuid.uuid4().hex,
        "items": [{"kind": msg.kind, "id": key.split(":", 1)[1], "title": msg.title, "severity": msg.severity}],
        "total": 1,
        "lang": body.lang,
        "team_id": team.id,
        "team_name": team.name,
    }
    started = time.monotonic()
    t: notify.Target | None = None
    try:
        t = notify.resolve(ch)
        smtp = await settings_store.get(db, "smtp") if ch.type == "email" else None
        await dbm.release(db)  # nothing open while the channel is asked
        async with asyncio.timeout(DEADLINE):
            await deliver(t, msg, body.lang, smtp)
    except (notify.NotifyError, TimeoutError) as exc:
        _recent.pop(rkey, None)  # not sent: may be tried again at once
        category = exc.category if isinstance(exc, notify.NotifyError) else "timeout"
        err = exc if isinstance(exc, notify.NotifyError) else notify.NotifyError("timeout")
        await delivery_log.record(db, error=err, secrets=t.secrets() if t else (), started=started, **logged)
        raise api_error(502, "forward_failed", detail=category) from exc
    except BaseException:
        _recent.pop(rkey, None)
        raise
    await delivery_log.record(db, started=started, **logged)
    return {"ok": True, "team": team.name}
