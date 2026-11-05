"""Push notifications: **channels** (where to: e-mail through the SMTP server, Microsoft Teams, Slack, Discord, Telegram,
Mattermost, ntfy, Gotify, a generic HTTP webhook) and **rules** (what: severities, sources – empty = all, language, on/off) that point to one or
several channels.

- after every fetch round (the background loop): every channel that is not pausing gets the stories its switched-on
  rules bring – only stories that arrived after the rule was created/switched on and the channel was added to it,
  each story at most once per channel (also when two rules bring it),
- up to BATCH stories one message each; more in one summary (at most LIST stories listed, the rest counted),
- the channels are sent to side by side, each with its own deadline: a slow or failing channel never holds back the
  others. A failure keeps the stories for the next try, with a growing pause (2 min … 6 h, longer when the service
  asks for it with 429 / retry_after) and the error on the channel,
- a rule whose filter is widened (more severities, sources or kinds) sends what newly matches only from then on – not
  everything older (NotifyRule.earlier),
- incremental: a round looks at the rules only when a story or Vendor News event arrived, a channel or rule changed, a
  channel's retry is due, or FULL_EVERY passed (a story rated higher since) – otherwise it costs two small queries,
- at least once: each message is marked as sent right after it went out, in a short transaction of its own (a story or
  channel deleted meanwhile is simply not marked). Should the process stop or the database fail in that moment, the
  message comes again – a webhook's delivery id stays the same for the same message, so a receiver can drop it,
- secrets (webhook URLs, the Telegram bot token, HMAC secret, auth header value) are encrypted at rest and never sent
  back to the browser; they are never logged (httpx' request log is silenced – the Telegram token is in the URL path),
- feed text (titles, summaries, links) is escaped for each format: no @everyone / <!channel> / @channel, no own links or
  markup; ntfy and Gotify get plain text in a JSON body – nothing of the feed in a header, no CR/LF where none belongs,
- every attempt is recorded in the delivery log (app/delivery_log.py) – by reference and title, never a body or secret;
  a rule's matching is one set of pure filters (news_filter / vendor_filter / health_filter) shared by the round and
  the dry run (dry_run), and a failed delivery can be sent again by hand (resend).
"""

import asyncio
import hashlib
import hmac
import html
import json
import logging
import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, make_msgid
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import aiosmtplib
import httpx
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import ColumnElement, Uuid, and_, exists, false, func, literal, or_, select, text, true, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import advisory_changes, audit, bounded, delivery_log
from app import db as dbm
from app import netaddr
from app import news as news_svc
from app import quiet
from app import settings as settings_store
from app import vendor_titles as titles
from app.config import get_config, tls_verify
from app.plaintext import neutral
from app.crypto import decrypt_str
from app.models import (
    NewsItem,
    NewsSource,
    NotifyChannel,
    NotifyDelivery,
    NotifyRule,
    NotifyRuleChannel,
    NotifyRuleTeam,
    SourceHealthDelivery,
    SourceHealthEvent,
    StoryDetail,
    TeamProduct,
    VendorDelivery,
    VendorEvent,
    VendorFollow,
)

log = logging.getLogger("cobe_news.notify")
TYPES = ("email", "teams", "slack", "discord", "telegram", "webhook", "ntfy", "gotify", "mattermost")
BATCH = 3  # more than this in one round: one summary instead of one message per story
LIST = 10  # stories listed in a summary
PENDING_MAX = 1000
BACKOFF_MAX = timedelta(hours=6)
RETRY_AFTER_MAX = 6 * 3600
RETRY_INLINE_MAX = 5.0  # a 429 asking for at most this many seconds: wait (without blocking) and try once more
TIMEOUT = httpx.Timeout(15.0, connect=10.0)
REQUEST_DEADLINE = 25.0  # one request as a whole (a receiver that trickles bytes)
CHANNEL_DEADLINE = 90.0  # everything one channel sends in one round
BODY_MAX = 64 * 1024  # what is read of a response (Telegram / Discord errors, retry_after)
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
DISCORD_HOSTS = ("discord.com", "discordapp.com")
TELEGRAM_API = "https://api.telegram.org"
TELEGRAM_TOKEN = re.compile(r"^\d{5,12}:[A-Za-z0-9_-]{30,50}$")
TELEGRAM_CHAT = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")
HEADER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
NTFY_TOPIC = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # ntfy's own rule for a topic name
# an ntfy access token ("tk_…") or a Gotify application token: never a line break, a blank or a header of its own
PUSH_TOKEN = re.compile(r"^[A-Za-z0-9_.~+/=-]{8,200}$")
NTFY_TAG = re.compile(r"^[A-Za-z0-9_+-]{1,40}$")  # ntfy shows a tag as text or, when it names an emoji, as that
NTFY_TAGS_MAX = 5
MATTERMOST_PATH = re.compile(r"/hooks/[A-Za-z0-9]{8,64}/?$")
# one bare address – what a recipient must be however it came (channel, the directory's `mail`, an admin's input)
MAIL_ADDRESS = re.compile(r"[^@\s,;<>\"()]{1,64}@[^@\s,;<>\"()]+\.[^@\s,;<>\"()]+")
# headers the client sets itself or that change how the request is read – never a "custom auth header"
RESERVED_HEADERS = {"host", "content-length", "content-type", "transfer-encoding", "connection", "user-agent", "te", "trailer", "upgrade", "expect", "cookie"}
transport: httpx.AsyncBaseTransport | None = None  # tests: a MockTransport – never Microsoft, Slack, Discord or Telegram

_env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"), autoescape=True)


class _NoSecrets(logging.Filter):
    """Defence in depth: should a request line of httpx still be logged (level changed), the Telegram token in the URL
    path and webhook paths (their secret) are cut out."""

    _token = re.compile(r"/bot\d+:[A-Za-z0-9_-]+")
    _url = re.compile(r"(https?://[^/\s\"']+)/[^\s\"']*")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        clean = self._url.sub(r"\1/…", self._token.sub("/bot<redacted>", msg))
        if clean != msg:
            record.msg, record.args = clean, ()
        return True


for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)  # "HTTP Request: POST https://api.telegram.org/bot<token>/…"
    logging.getLogger(_name).addFilter(_NoSecrets())


LABELS = {
    "de": {
        "sev": {"critical": "Kritisch", "high": "Hoch", "medium": "Mittel", "low": "Niedrig", "info": "Info"},
        "one": "Neue Security-Meldung",
        "many": "{n} neue Security-Meldungen",
        "more": "… und {n} weitere in Cobe News.",
        "article": "Artikel öffnen",
        "open": "In Cobe News öffnen",
        "button": "Cobe News öffnen",
        "test": "Testnachricht",
        "test_title": "Testnachricht von Cobe News – der Kanal „{rule}“ ist richtig eingerichtet.",
        "footer": "Diese Nachricht hat Cobe News automatisch versendet.",
        "footer2": "Welche Meldungen kommen, stellt ein Admin unter Einstellungen › Kanäle & Regeln ein.",
        "source": "Quelle",
        "severity": "Schwere",
        "published": "Veröffentlicht",
        # the mail (render_mail): subject, summary line, the story's marks, why it comes
        "subject_many": "{n} neue Meldungen",
        "top_sev": "Höchste Schwere: {sev}",
        "n_ours": ("1 betrifft eure Produkte", "{n} betreffen eure Produkte"),
        "n_exploited": "{n} aktiv ausgenutzt",
        "ours": "Betrifft eure Produkte",
        "exploited": "Aktiv ausgenutzt",
        "why_rule": ("Regel „{names}“", "Regeln {names}"),
        "edit_rule": ("Regel bearbeiten", "Regeln bearbeiten"),
        "why_test": "Testnachricht für „{rule}“",
        "edit_test": "Kanäle & Regeln",
        "quote": "„{}“",
    },
    "en": {
        "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "one": "New security story",
        "many": "{n} new security stories",
        "more": "… and {n} more in Cobe News.",
        "article": "Open article",
        "open": "Open in Cobe News",
        "button": "Open Cobe News",
        "test": "Test message",
        "test_title": "Test message from Cobe News – the channel “{rule}” is set up correctly.",
        "footer": "Sent automatically by Cobe News.",
        "footer2": "An admin chooses which stories come under Settings › Channels & rules.",
        "source": "Source",
        "severity": "Severity",
        "published": "Published",
        "subject_many": "{n} new stories",
        "top_sev": "Highest severity: {sev}",
        "n_ours": ("1 concerns your products", "{n} concern your products"),
        "n_exploited": "{n} actively exploited",
        "ours": "Concerns your products",
        "exploited": "Actively exploited",
        "why_rule": ("Rule “{names}”", "Rules {names}"),
        "edit_rule": ("Edit rule", "Edit rules"),
        "why_test": "Test message for “{rule}”",
        "edit_test": "Channels & rules",
        "quote": "“{}”",
    },
}
# (text, background) for mails – mail clients know no oklch
SEV_COLORS = {
    "critical": ("#b3261e", "#fde8e6"),
    "high": ("#a8490c", "#fdeee2"),
    "medium": ("#8a6100", "#fdf3d7"),
    "low": ("#2a5d9f", "#e6eefa"),
    "info": ("#4a5066", "#eef0f6"),
}
ACCENTS = {"critical": "#c62828", "high": "#e0661c", "medium": "#c98a12", "low": "#3d55d4", "info": "#3d55d4"}


class NotifyError(Exception):
    """not_configured | invalid_url | host_not_allowed | forbidden_target | http | timeout | connection | auth |
    rejected | tls | dns | refused | secret_unreadable | rate_limited. `detail` never holds a URL or a secret. `code`:
    the HTTP status of the answer, or the SMTP reply code of the mail server (the delivery log shows it)."""

    def __init__(self, category: str, detail: str = "", retry_after: float | None = None, code: int | None = None):
        super().__init__(category)
        self.category = category
        self.detail = detail
        self.retry_after = retry_after
        self.code = code


# ---------------------------------------------------------------- target URLs


def host_allowed(host: str) -> bool:
    """Teams / Slack webhooks: the hosts of WEBHOOK_HOSTS (Teams, Slack and own ones)."""
    host = host.lower().rstrip(".")
    for pat in get_config().webhook_hosts:
        if pat.startswith("*.") and host.endswith(pat[1:]) and len(host) > len(pat) - 1:
            return True
        if host == pat:
            return True
    return False


def check_url(kind: str, url: str, *, allow_http: bool = False) -> str:
    """The URL of a Teams / Slack / Discord / generic webhook channel – or NotifyError(invalid_url | host_not_allowed |
    forbidden_target). Only what is written in the URL is checked here; the address it resolves to is checked when
    connecting (pinned transport)."""
    url = url.strip()
    generic = kind == "webhook"
    if not netaddr.valid_url(url, https_only=not (generic and allow_http)):
        raise NotifyError("invalid_url")
    if netaddr.forbidden_literal(url, **netaddr.channel_policy()):
        raise NotifyError("forbidden_target")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if kind == "discord":
        if host not in DISCORD_HOSTS or parts.port not in (None, 443) or not re.match(r"^/api/webhooks/\d+/[A-Za-z0-9_-]+/?$", parts.path):
            raise NotifyError("host_not_allowed")
    elif kind in ("teams", "slack"):
        if not host_allowed(host):
            raise NotifyError("host_not_allowed")
    elif kind == "mattermost":
        # self-hosted: any (public, or WEBHOOK_PRIVATE_NETS) host – but the path of an incoming webhook
        if not MATTERMOST_PATH.search(parts.path) or parts.query or parts.fragment:
            raise NotifyError("invalid_url")
    elif kind in ("ntfy", "gotify"):
        # the server's address (also below a path, a reverse proxy's /ntfy) – the topic and the token are not in it
        if parts.query or parts.fragment:
            raise NotifyError("invalid_url")
    elif not generic:
        raise NotifyError("invalid_url")
    return url


def server_base(url: str) -> str:
    """An ntfy / Gotify server address without a trailing slash: "https://ntfy.corp.example" or "…/ntfy"."""
    return url.strip().rstrip("/")


def secret_hint(enc: str | None) -> str | None:
    """What the UI shows of a stored URL: the host only (the path holds the secret)."""
    if not enc:
        return None
    try:
        return urlsplit(decrypt_str(enc)).hostname
    except Exception:  # noqa: BLE001 - key changed: the URL has to be entered again
        return "?"


# ---------------------------------------------------------------- the stories as text


@dataclass
class Story:
    id: str
    title: str
    summary: str
    url: str
    severity: str
    source: str
    published_at: datetime
    cves: list[str] = field(default_factory=list)
    # "news" (a story of the feed) or a Vendor News event (vendor.vuln | vendor.version | vendor.eol) – then `link`
    # opens the product on the Vendor News page instead of a story
    kind: str = "news"
    link: str = ""
    # the card's fields (card_fields): the product when reliably known (with_products, vendor_story), the story's topics
    # (news.TOPICS), the kind of its source (authority | vendor | research | press | catalog | custom | vendor_news |
    # health | watch)
    product: str = ""
    topics: list[str] = field(default_factory=list)
    source_kind: str = ""
    # "GREEN": from a CSAF provider's TLP:GREEN document (allowed per provider) – every format labels it
    tlp: str = ""
    # "Betrifft eure Produkte": the followed products (their labels) the story concerns – a news story's
    # news_items.products (`product_keys`, the catalogue keys; resolved by with_products), a Vendor News vulnerability's
    # product. The mail marks such a story and lists it first (priority)
    ours: list[str] = field(default_factory=list)
    product_keys: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # feed text: no direction or control characters in any channel (app/plaintext.py)
        self.title, self.summary, self.source, self.product = (neutral(x) for x in (self.title, self.summary, self.source, self.product))
        self.ours = [neutral(x) for x in self.ours or []]

    @property
    def headline(self) -> str:
        """The title as the messages show it: without the publisher's status and severity tags in front (headline)."""
        return headline(self.title)


TLP_PREFIX = "[TLP:GREEN] "
# The tags the BSI's WID / CERT-Bund feed puts in front of a title: "[NEU] [hoch] Emerson Ovation: …", "[UPDATE]
# [kritisch] …", "[UNGEPATCHT] [hoch] …" – the state of the advisory and its rating, which every message shows anyway
# (the severity, the topic "Ohne Patch"). Only these words, only in front, only whole bracketed tags.
_STATUS_TAGS = re.compile(r"^(?:\s*\[(?:neu|update|ungepatcht|kritisch|hoch|mittel|niedrig)\])+\s*", re.I)


def headline(title: str) -> str:
    """A title without the publisher's status and severity tags in front ("[NEU] [hoch] Emerson Ovation: Mehrere
    Schwachstellen" → "Emerson Ovation: Mehrere Schwachstellen") – a TLP:GREEN prefix stays in front; a title that is
    nothing but tags stays as it is. Used by the mail, the chat cards and the push messages (not the webhook's JSON:
    the receiver gets the title as the source wrote it)."""
    t = title or ""
    pre = TLP_PREFIX if t.startswith(TLP_PREFIX) else ""
    rest = _STATUS_TAGS.sub("", t[len(pre) :], count=1)
    return pre + rest if rest.strip() else t


def priority(s: Story) -> tuple:
    """The order of the stories of one message (and which make the cut when there are more): the urgent ones first –
    actively exploited or critical –, then those concerning our products, then by severity, then the newest first. So a
    low or medium finding of a followed product never pushes an exploited or critical story out of a summary. Sort with
    reverse=True."""
    urgent = "exploited" in (s.topics or []) or s.severity == "critical"
    return (urgent, bool(s.ours), RANK.get(s.severity, 0), s.published_at)


def tlp_line(lang: str) -> str:
    """The label of a TLP:GREEN item, as each channel shows it."""
    return CARD_LABELS.get(lang, CARD_LABELS["de"])["tlp_green"]


def _link(story_id: str) -> str:
    return f"{get_config().base_url}/?story={story_id}"


def _open(s: Story) -> str:
    return s.link or _link(s.id)


def _date(d: datetime, lang: str) -> str:
    return d.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC" if lang == "de" else "%Y-%m-%d %H:%M UTC")


def _head(lb: dict, total: int, test: bool) -> str:
    return lb["test"] if test else (lb["one"] if total == 1 else lb["many"].format(n=total))


_CONTROL = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]+")


def one_line(text: str) -> str:
    """A mail header value: line breaks and other control characters (from a rule or channel name, a product or version
    label, a story title) become spaces – the email package refuses a header with a line break, which made every mail
    of the channel fail and retry for ever."""
    return " ".join(_CONTROL.sub(" ", neutral(text)).split())


SUBJECT_MAX = 150  # characters of a summary's subject (the names of its stories, then "+N")
SUBJECT_NAME_MAX = 40  # characters of one story's name in it
COMPACT_FROM = 6  # stories in one mail from which it is a compact list (a line per story, no summaries) instead of cards
CVES_SHOWN = 3  # CVEs named on a mail's story (then "+N")
HOT_TOPICS = ("zeroday", "exploited", "ransomware")  # topic chips in the warning colour
# a product's version range ("Example Gateway < 2.4.1", "PAN-OS 11.1.2 → 11.1.6-h3", "GitLab 17.0 - 19.5") – not the
# numbers that are part of its name ("Exchange Server 2019 CU14", "Windows 11")
_RANGE = re.compile(r"(?:\s+v?\d[\w.-]*)?\s+(?:→|->).*$|\s+(?:<=?|>=?|≤|≥|=)\s*v?\d.*$|\s+v?\d[\w.]*\s*[-–]\s*v?\d.*$")


def product_name(product: str) -> str:
    """A product without its version range (the subject's and the compact line's name)."""
    return _RANGE.sub("", one_line(product)).strip()


def _local(d: datetime, lang: str, tz: str | None = None) -> str:
    """A mail's time: in the recipient's zone (a person's own, else the installation's Europe/Berlin – quiet.DEFAULT_TZ)
    with the zone's abbreviation, so it is never ambiguous: "04.11.2026 11:19 MEZ", "2026-11-04 11:19 CET"."""
    x = d.astimezone(quiet.zone(tz))
    abbr = x.tzname() or ""
    if lang == "de":
        abbr = {"CET": "MEZ", "CEST": "MESZ"}.get(abbr, abbr)
    return x.strftime("%d.%m.%Y %H:%M" if lang == "de" else "%Y-%m-%d %H:%M") + (f" {abbr}" if abbr else "")


def _cut(text: str, limit: int) -> str:
    """At most `limit` characters, cut at a blank (never inside a word) with "…"."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    head = text[: limit - 1]
    return (head.rsplit(" ", 1)[0] if " " in head else head).rstrip(",;:–—-") + "…"


def mail_name(s: Story) -> str:
    """What a summary's subject calls a story: the followed product it concerns, else what its title names before the
    colon ("Emerson Ovation: Mehrere Schwachstellen" → "Emerson Ovation"), else its product without the versions, else
    the title shortened."""
    if s.ours:
        return _cut(one_line(s.ours[0]), SUBJECT_NAME_MAX)
    title = one_line(s.headline.removeprefix(TLP_PREFIX))
    head, colon, _ = title.partition(": ")
    if colon and 2 <= len(head) <= SUBJECT_NAME_MAX:
        return head
    if s.product and (p := product_name(s.product)):
        return _cut(p, SUBJECT_NAME_MAX)
    return _cut(title, SUBJECT_NAME_MAX)


def _subject(rule: str, stories: list[Story], total: int, lang: str, test: bool) -> str:
    """One story: its severity and title. More: how many and what they are about – the names in the mail's order, as
    many as fit SUBJECT_MAX, then "+N" ("[Cobe News] 5 neue Meldungen: Emerson Ovation, SolarWinds Dameware +3")."""
    lb = LABELS[lang]
    if test:
        return f"[Cobe News] {lb['test']} · {rule}"
    if total == 1:
        s = stories[0]
        return f"[Cobe News] {lb['sev'][s.severity]}: {s.headline}"[:250]
    green = "[TLP:GREEN] " if any(s.tlp == "GREEN" for s in stories) else ""
    head = f"[Cobe News] {green}{lb['subject_many'].format(n=total)}"
    names: list[str] = []
    covered = 0
    for s in stories:
        name = mail_name(s)
        if name in names:
            covered += 1
            continue
        rest = total - covered - 1
        if len(f"{head}: {', '.join([*names, name])}") + (len(f" +{rest}") if rest else 0) > SUBJECT_MAX:
            break
        names.append(name)
        covered += 1
    if not names:
        return head
    rest = total - covered
    return f"{head}: {', '.join(names)}" + (f" +{rest}" if rest else "")


def _summary_line(lb: dict, stories: list[Story], total: int) -> str:
    """The line above the heading: the highest severity, how many concern our products, how many are actively exploited
    (each only when there are any). One story: its severity and marks."""
    top = max(stories, key=lambda s: RANK.get(s.severity, 0))
    ours = sum(1 for s in stories if s.ours)
    hot = sum(1 for s in stories if "exploited" in (s.topics or []))
    if total == 1:
        return " · ".join([f"{lb['severity']}: {lb['sev'][top.severity]}", *([lb["ours"]] if ours else []), *([lb["exploited"]] if hot else [])])
    parts = [lb["top_sev"].format(sev=lb["sev"][top.severity])]
    if ours:
        parts.append(lb["n_ours"][0] if ours == 1 else lb["n_ours"][1].format(n=ours))
    if hot:
        parts.append(lb["n_exploited"].format(n=hot))
    return " · ".join(parts)


def rule_link(rule_ids: list[str] | None = None) -> str:
    """Where a rule is edited: Einstellungen › Kanäle & Regeln › Regeln – one rule opens in the editor."""
    base = f"{get_config().base_url}/settings/rules?tab=rules"
    ids = [str(x) for x in rule_ids or [] if x]
    return f"{base}&{urlencode({'rule': ids[0]})}" if len(ids) == 1 else base


def _why(lb: dict, rule: str, rules: list[str] | None, rule_ids: list[str] | None, test: bool) -> dict:
    """The footer's first line: why the mail comes (the rule or rules) and where that is changed."""
    if test:
        return {"text": lb["why_test"].format(rule=rule), "label": lb["edit_test"], "url": f"{get_config().base_url}/settings/rules"}
    names = [n for n in rules or [] if n] or [rule]
    one = len(names) == 1
    shown = names[0] if one else ", ".join(lb["quote"].format(n) for n in names[:5]) + (" …" if len(names) > 5 else "")
    return {"text": lb["why_rule"][0 if one else 1].format(names=shown), "label": lb["edit_rule"][0 if one else 1], "url": rule_link(rule_ids)}


def _body_title(s: Story) -> str:
    """A title in the mail's body: a TLP:GREEN story has its pill (and its line in the text part) – the "[TLP:GREEN]"
    in front of the title would say it twice. The subject and the chat cards keep it."""
    return s.headline.removeprefix(TLP_PREFIX) if s.tlp == "GREEN" else s.headline


def _compact_name(s: Story) -> str:
    """The product in front of a compact line – only when neither the title (what it names before the colon) nor the
    "Betrifft eure Produkte" mark says it anyway."""
    name = product_name(s.product) if s.product and not s.ours else ""
    title = s.headline.removeprefix(TLP_PREFIX).lower()
    head = title.partition(": ")[0] if ": " in title else title
    low = name.lower()
    return "" if not name or title.startswith(low) or low.startswith(head) else name


def _facts(s: Story, lang: str) -> dict:
    """A story's facts line: the product (when known), its CVEs (CVES_SHOWN, then "+N"), its topics (news.TOPICS order)."""
    topics = CARD_LABELS[lang]["topics"]
    cves = list(dict.fromkeys(s.cves or []))
    return {
        "product": s.product,
        "cves": cves[:CVES_SHOWN],
        "cves_more": f"+{len(cves) - CVES_SHOWN}" if len(cves) > CVES_SHOWN else "",
        "topics": [{"label": topics[t], "hot": t in HOT_TOPICS} for t in news_svc.TOPICS if t in (s.topics or [])],
    }


def _facts_text(f: dict) -> str:
    cves = " ".join(x for x in (", ".join(f["cves"]), f["cves_more"]) if x)
    return " · ".join(x for x in (f["product"], cves, ", ".join(t["label"] for t in f["topics"])) if x)


def _dark_css() -> str:
    """The dark colours (Apple Mail, iOS Mail, Outlook for Mac, Thunderbird: prefers-color-scheme; Outlook.com: its
    [data-ogsc] / [data-ogsb] marks). The light colours stay inline – what Gmail and Outlook for Windows read."""
    rules = []
    for cls, (color, bg, border) in DARK.items():
        decl = [f"color:{color} !important"] if color else []
        decl += [f"background-color:{bg} !important"] if bg else []
        decl += [f"border-color:{border} !important"] if border else []
        rules.append((cls, decl, color, bg))
    dark = "".join(f".{c}{{{';'.join(d)}}}" for c, d, _, _ in rules if d)
    ogsc = "".join(f"[data-ogsc] .{c}{{color:{col} !important}}" for c, _, col, _ in rules if col)
    ogsb = "".join(f"[data-ogsb] .{c}{{background-color:{bg} !important}}" for c, _, _, bg in rules if bg)
    return f"@media (prefers-color-scheme: dark){{{dark}}}{ogsc}{ogsb}"


# (text, background, border) of the mail in dark mode, by class – text on its background at least 4.5:1
DARK = {
    "cn-page": ("#e8eaf0", "#0f1115", ""),
    "cn-card": ("", "#1a1d24", "#2f3340"),
    "cn-story": ("", "#1a1d24", "#2f3340"),
    "cn-ours": ("", "#1d2238", "#7d8fff"),
    "cn-text": ("#e8eaf0", "", ""),
    "cn-muted": ("#a6acbd", "", ""),
    "cn-body": ("#c3c8d6", "", ""),
    "cn-foot": ("#9097a8", "", ""),
    "cn-link": ("#a9b8ff", "", ""),
    "cn-line": ("", "", "#2f3340"),
    "cn-chip": ("#d0d4e0", "#2a2e3a", ""),
    "cn-hot": ("#ffb4ab", "#4a1d1a", ""),
    "cn-tlp": ("#9be3b4", "#173a24", ""),
    "cn-ourspill": ("#ffffff", "#4257d6", ""),
    **{f"cn-sev-{k}": v for k, v in {
        "critical": ("#ffb4ab", "#4f1b17", ""),
        "high": ("#ffc29b", "#4d2810", ""),
        "medium": ("#f3d27a", "#3f3200", ""),
        "low": ("#aac8ff", "#1b2f52", ""),
        "info": ("#c9cdd9", "#2b2f3b", ""),
    }.items()},
}  # fmt: skip
_DARK_CSS = _dark_css()


def render_mail(
    rule: str,
    stories: list[Story],
    total: int,
    lang: str,
    *,
    test: bool = False,
    footer: list[str] | None = None,
    rules: list[str] | None = None,
    rule_ids: list[str] | None = None,
    tz: str | None = None,
) -> tuple[str, str, str]:
    """(subject, text, html) in the mail style (HTML escaped by Jinja's autoescape). The stories in their order
    (priority: our products, actively exploited, severity, newest); up to COMPACT_FROM - 1 as cards (facts line,
    summary, links), more as a compact list (a line each). Times in `tz` (the person's zone; else Europe/Berlin).
    `footer`: other closing lines than a rule's (the personal notifications say why the person gets it and where to
    change it) – without it the footer names the rule(s) (`rules`) with a link to edit them (`rule_ids`)."""
    lb = LABELS[lang]
    stories = sorted(stories, key=priority, reverse=True)
    top = max(stories, key=lambda s: RANK.get(s.severity, 0))
    heading = lb["test_title"].format(rule=rule) if test else (_body_title(stories[0]) if total == 1 else lb["many"].format(n=total))
    eyebrow = lb["test"] if test else _summary_line(lb, stories, total)
    more = lb["more"].format(n=total - len(stories)) if total > len(stories) else ""
    compact = len(stories) >= COMPACT_FROM
    cards = []
    for s in stories:
        facts = _facts(s, lang)
        cards.append(
            {
                "title": _body_title(s),
                "summary": s.summary,
                "url": _safe_url(s.url),
                "link": _open(s),
                "source": s.source,
                "date": _local(s.published_at, lang, tz),
                "sev": s.severity if s.severity in SEV_COLORS else "info",
                "sev_label": lb["sev"][s.severity],
                "sev_color": SEV_COLORS[s.severity][0],
                "sev_bg": SEV_COLORS[s.severity][1],
                "tlp": tlp_line(lang) if s.tlp == "GREEN" else "",
                "ours": f"{lb['ours']}: {', '.join(s.ours[:3])}" + (f" +{len(s.ours) - 3}" if len(s.ours) > 3 else "") if s.ours else "",
                "facts": facts,
                "facts_text": _facts_text(facts),
                "name": _compact_name(s),
            }
        )
    why = None if footer else _why(lb, rule, rules, rule_ids, test)
    footer = footer or [f"{lb['footer']} {lb['footer2']}"]
    subject = _subject(rule, stories, total, lang, test)
    body = _env.get_template("mail.html.j2").render(
        lang=lang,
        subject=subject,
        preheader=heading if total == 1 or test else f"{eyebrow} – {', '.join(mail_name(s) for s in stories[:3])}",
        rule=rule,
        accent=ACCENTS[top.severity],
        eyebrow=eyebrow,
        heading=heading,
        stories=cards,
        compact=compact,
        more=more,
        app_url=get_config().base_url + "/",
        labels=lb,
        why=why,
        footer=footer,
        dark_css=_DARK_CSS,
    )
    # the text part: every field of one line stays one line (a title, product or rule name with a line break would
    # make a line of its own – "Bcc: …" looking like a header); only the summary keeps its lines (plain_block)
    ol = one_line
    lines = [ol(heading), ol(eyebrow), "=" * min(max(len(ol(heading)), len(ol(eyebrow))), 60), ""]
    for c in cards:
        mark = f" · {ol(c['ours'])}" if c["ours"] else ""
        if compact:
            green = TLP_PREFIX if c["tlp"] else ""  # the compact line's one TLP marker (no line of its own)
            lines += [f"• [{c['sev_label']}] {green}{ol(c['name']) + ' · ' if c['name'] else ''}{ol(c['title'])}{mark}", f"  {c['link']}"]
            continue
        lines += [f"[{c['sev_label']}]{mark}", ol(c["title"])]
        if c["facts_text"]:
            lines.append(ol(c["facts_text"]))
        lines.append(ol(f"{c['source']} · {c['date']}"))
        if c["tlp"]:
            lines.append(c["tlp"])
        if c["summary"]:
            lines.append(plain_block(c["summary"]))
        if c["url"]:
            lines.append(f"{lb['article']}: {c['url']}")
        lines += [f"{lb['open']}: {c['link']}", ""]
    if compact:
        lines.append("")
    if more:
        lines += [more, ""]
    lines += [f"{lb['button']}: {get_config().base_url}/", "", "-- "]
    if why:
        lines.append(ol(f"{why['text']} · {why['label']}: {why['url']}"))
    lines += [ol(f) for f in footer]
    return subject, "\n".join(lines) + "\n", body


# ---------------------------------------------------------------- the card of one story (every chat channel)
#
# One story is a card with labelled fields – Produkt (only when reliably known: a followed product the details concern,
# the details' first affected product, a Vendor News event's product and version), Quelle, Kategorie (the topics and the
# severity; without a topic the kind of source) – and a short description (BRIEF_MAX characters, cut at the end of a
# sentence, never inside a word), then "In Cobe News öffnen". A summary of many stories is a compact list instead: one
# line per story (title · Produkt · Kategorie) and "… und N weitere".

CARD_LABELS = {
    "de": {
        "product": "Produkt",
        "source": "Quelle",
        "category": "Kategorie",
        "tlp": "TLP",
        "tlp_green": "TLP:GREEN – nur intern weitergeben",
        "topics": {
            "zeroday": "Zero-Day",
            "exploited": "Aktiv ausgenutzt",
            "poc": "Exploit veröffentlicht",
            "ransomware": "Ransomware",
            "nopatch": "Ohne Patch",
            "breach": "Vorfall/Datenleck",
            "supply": "Lieferkette",
            "phishing": "Phishing/Social Engineering",
            "ot": "OT/ICS",
        },
        "kinds": {
            "authority": "Behörde",
            "vendor": "Hersteller",
            "research": "Forschung",
            "press": "Presse",
            "catalog": "Katalog",
            "custom": "Eigene Quelle",
            "vendor_news": "Vendor News",
            "health": "Quellen-Gesundheit",
            "watch": "Beobachtete CVE",
        },
    },
    "en": {
        "product": "Product",
        "source": "Source",
        "category": "Category",
        "tlp": "TLP",
        "tlp_green": "TLP:GREEN – share internally only",
        "topics": {
            "zeroday": "Zero-day",
            "exploited": "Actively exploited",
            "poc": "Exploit published",
            "ransomware": "Ransomware",
            "nopatch": "No patch",
            "breach": "Incident/data leak",
            "supply": "Supply chain",
            "phishing": "Phishing/social engineering",
            "ot": "OT/ICS",
        },
        "kinds": {
            "authority": "Authority",
            "vendor": "Vendor",
            "research": "Research",
            "press": "Press",
            "catalog": "Catalogue",
            "custom": "Own feed",
            "vendor_news": "Vendor News",
            "health": "Source health",
            "watch": "Watched CVE",
        },
    },
}
BRIEF_MAX = 200  # characters of a card's short description
TOPICS_SHOWN = 3  # topics named in a card's category (in the order of news.TOPICS)
_SENTENCE_END = re.compile(r"[.!?…](?=\s|$)")


def brief(text: str, limit: int = BRIEF_MAX) -> str:
    """The first one or two sentences of a text, at most `limit` characters: cut at the end of a sentence – a first
    sentence longer than that at the last blank before the limit, with "…" – never inside a word. Each line of the text
    (a Vendor News event's status line) counts as a sentence of its own."""
    lines = [" ".join(x.split()) for x in str(text or "").replace("\r", "\n").split("\n")]
    sentences: list[str] = []
    for line in lines:
        start = 0
        for m in _SENTENCE_END.finditer(line):
            sentences.append(line[start : m.end()].strip())
            start = m.end()
        if line[start:].strip():
            sentences.append(line[start:].strip())
    sentences = [x for x in sentences if x]
    if not sentences:
        return ""
    out = ""
    for x in sentences[:2]:
        nxt = f"{out} {x}".strip()
        if len(nxt) > limit:
            break
        out = nxt
    if out:
        return out
    first = sentences[0]
    cut = first[: limit - 1].rsplit(" ", 1)[0].rstrip(",;:–—-") if " " in first[: limit - 1] else first[: limit - 1]
    return cut + " …"


def category(s: "Story", lang: str) -> str:
    """The card's "Kategorie": its topics and the severity – without a topic the kind of its source."""
    cl, lb = CARD_LABELS[lang], LABELS[lang]
    names = [cl["topics"][t] for t in news_svc.TOPICS if t in (s.topics or [])][:TOPICS_SHOWN]
    sev = lb["sev"].get(s.severity, s.severity)
    if names:
        return " · ".join([*names, sev])
    kind = cl["kinds"].get(s.source_kind or "")
    return f"{sev} · {kind}" if kind else sev


def card_fields(s: "Story", lang: str) -> list[tuple[str, str]]:
    """(label, value) of a card: Produkt (when known), Quelle, Kategorie – plain text, each channel escapes it."""
    cl = CARD_LABELS[lang]
    out = [(cl["tlp"], cl["tlp_green"])] if s.tlp == "GREEN" else []
    out += [(cl["product"], s.product)] if s.product else []
    return [*out, (cl["source"], s.source), (cl["category"], category(s, lang))]


def compact_extra(s: "Story", lang: str) -> str:
    """What a summary's line says after the title: Produkt (when known) · Kategorie."""
    return " · ".join(x for x in (s.product, category(s, lang)) if x)


def _compact(total: int) -> bool:
    """A summary of many stories (more than plan() sends one by one): a compact list instead of cards."""
    return total > BATCH


def _safe_url(url: str) -> str:
    """A story link inside Slack's <url|label>, Teams' / Discord's [label](url), Telegram's or a mail's href:
    characters that would end the link or start markup are percent-encoded; anything but http(s) is no link at all."""
    u = (url or "").strip()
    if not u.lower().startswith(("https://", "http://")):
        return ""
    return "".join(f"%{ord(c):02X}" if c in "|<>()[] \"'`\\" or ord(c) < 32 or ord(c) == 127 else c for c in u)[:2000]


def _one_line(v: str) -> str:
    return " ".join(neutral(str(v)).split())


def _slack_esc(v: str) -> str:
    """Free text for Slack mrkdwn: no <!channel>, no <url|label> links of its own."""
    return _one_line(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "¦")[:500]


SLACK_SECTION_MAX = 2900  # a section's text: at most 3000 characters


def render_slack(rule: str, stories: list[Story], total: int, lang: str, *, test: bool = False) -> dict:
    lb = LABELS[lang]
    head = _head(lb, total, test)
    # a header is plain text (no mentions) – angle brackets still swapped, so it never even looks like <!channel>
    plain = _one_line(rule).replace("<", "‹").replace(">", "›")
    blocks: list[dict] = [{"type": "header", "text": {"type": "plain_text", "text": f"{head} · {plain}"[:150]}}]
    if test:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _slack_esc(lb["test_title"].format(rule=rule))}})
    shown = len(stories)
    if _compact(total):
        lines = []
        for s in stories:
            url = _safe_url(_open(s))  # a summary's line opens the story in Cobe News
            title = _slack_esc(s.headline)[:200]
            lines.append(f"• *<{url}|{title}>* · {_slack_esc(compact_extra(s, lang))}" if url else f"• *{title}* · {_slack_esc(compact_extra(s, lang))}")
        chunk = ""
        for line in lines:  # sections of at most SLACK_SECTION_MAX characters
            if chunk and len(chunk) + len(line) + 1 > SLACK_SECTION_MAX:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})
                chunk = ""
            chunk = f"{chunk}\n{line}" if chunk else line
        if chunk:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})
    else:
        for s in stories:
            url = _safe_url(s.url)
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*<{url}|{_slack_esc(s.headline)}>*" if url else f"*{_slack_esc(s.headline)}*"}})
            # labelled fields (at most 10 per section, 2000 characters each)
            blocks.append({"type": "section", "fields": [{"type": "mrkdwn", "text": f"*{label}*\n{_slack_esc(value)[:300]}"} for label, value in card_fields(s, lang)]})
            if b := brief(s.summary):
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _slack_esc(b)}})
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"{_date(s.published_at, lang)} · <{_safe_url(_open(s))}|{lb['open']}>"}]})
    if total > shown:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _slack_esc(lb["more"].format(n=total - shown))}]})
    blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": lb["button"]}, "url": get_config().base_url + "/"}]})
    # at most 50 blocks: the button stays the last one
    blocks = [*blocks[:49], blocks[-1]] if len(blocks) > 50 else blocks
    return {"text": f"[Cobe News] {head}: " + "; ".join(_slack_esc(s.headline) for s in stories)[:300], "blocks": blocks}


def _teams_esc(v: str) -> str:
    """Free text for an Adaptive Card TextBlock (a markdown subset): no links, emphasis or headings of its own."""
    return re.sub(r"([\\`*_\[\]()<>#~|])", r"\\\1", _one_line(v))[:500]


TEAMS_COLOR = {"critical": "Attention", "high": "Warning", "medium": "Warning", "low": "Accent", "info": "Default"}


def render_teams(rule: str, stories: list[Story], total: int, lang: str, *, test: bool = False) -> dict:
    lb = LABELS[lang]
    head = _head(lb, total, test)
    body: list[dict] = [{"type": "TextBlock", "text": f"{head} · {_teams_esc(rule)}", "weight": "Bolder", "size": "Medium", "wrap": True}]
    if test:
        body.append({"type": "TextBlock", "text": _teams_esc(lb["test_title"].format(rule=rule)), "wrap": True})
    for s in stories:
        url = _safe_url(s.url)
        title = f"[{_teams_esc(s.headline)}]({url})" if url else _teams_esc(s.headline)
        if _compact(total):
            # one line per story: title · Produkt · Kategorie, coloured by its severity
            line = f"{title} · {_teams_esc(compact_extra(s, lang))}"
            body.append({"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small", "color": TEAMS_COLOR[s.severity]})
            continue
        items: list[dict] = [
            {"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
            {"type": "FactSet", "facts": [{"title": label, "value": _teams_esc(value)[:300]} for label, value in card_fields(s, lang)]},
        ]
        if b := brief(s.summary):
            items.append({"type": "TextBlock", "text": _teams_esc(b), "wrap": True})
        items.append(
            {"type": "TextBlock", "text": f"{_date(s.published_at, lang)} · [{_teams_esc(lb['open'])}]({_safe_url(_open(s))})", "isSubtle": True, "spacing": "Small", "wrap": True, "color": TEAMS_COLOR[s.severity]}
        )
        body.append({"type": "Container", "separator": True, "items": items, "selectAction": {"type": "Action.OpenUrl", "url": _open(s)}})
    if total > len(stories):
        body.append({"type": "TextBlock", "text": _teams_esc(lb["more"].format(n=total - len(stories))), "isSubtle": True, "wrap": True})
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "actions": [{"type": "Action.OpenUrl", "title": lb["button"], "url": get_config().base_url + "/"}],
    }
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def _discord_plain(v: str) -> str:
    """Text Discord shows as it is (embed footer): only mentions are defused (a zero-width space after the @)."""
    return _one_line(v).replace("@", "@​")


def _discord_esc(v: str) -> str:
    """Free text for Discord markdown: no @everyone/@here/<@id>/<#channel>/<t:…>, no [masked](links), no emphasis,
    headings, quotes, spoilers or code of its own. Mentions would not ping anyway (allowed_mentions: parse = [])."""
    return re.sub(r"([\\`*_~|>\[\]()<#:-])", r"\\\1", _discord_plain(v))


DISCORD_COLORS = {"critical": 0xC62828, "high": 0xE0661C, "medium": 0xC98A12, "low": 0x3D55D4, "info": 0x6B7280}
DISCORD_EMBEDS = 10  # per message
DISCORD_FIELD = 1024  # characters of a field's value
DISCORD_TOTAL = 5800  # all embeds' text together (Discord: 6000)
DISCORD_LIST = 3900  # a summary's list (an embed's description: 4096)


def _embed_size(e: dict) -> int:
    return len(e.get("title", "")) + len(e.get("description", "")) + len((e.get("footer") or {}).get("text", "")) + sum(len(f["name"]) + len(f["value"]) for f in e.get("fields", []))


def render_discord(rule: str, stories: list[Story], total: int, lang: str, *, test: bool = False) -> dict:
    lb = LABELS[lang]
    content = f"**{_discord_esc(_head(lb, total, test))}** · {_discord_esc(rule)}"
    if test:
        content += "\n" + _discord_esc(lb["test_title"].format(rule=rule))
    embeds: list[dict] = []
    shown = 0
    if _compact(total):
        # one embed: a line per story (title · Produkt · Kategorie), coloured by the most severe of them
        lines: list[str] = []
        for s in stories:
            url = _safe_url(_open(s))  # a summary's line opens the story in Cobe News
            line = f"• [{_discord_esc(s.headline)[:200]}]({url}) · {_discord_esc(compact_extra(s, lang))}"
            if len("\n".join([*lines, line])) > DISCORD_LIST:
                break
            lines.append(line)
            shown += 1
        embeds.append({"description": "\n".join(lines), "color": DISCORD_COLORS.get(_top(stories), DISCORD_COLORS["info"])})
    else:
        for s in stories[:DISCORD_EMBEDS]:
            b = brief(s.summary)
            e: dict = {
                "title": _discord_esc(s.headline)[:250],
                "description": (f"{_discord_esc(b)}\n" if b else "") + f"[{_discord_esc(lb['open'])}]({_safe_url(_open(s))})",
                "color": DISCORD_COLORS.get(s.severity, DISCORD_COLORS["info"]),
                "fields": [{"name": label[:256], "value": (_discord_esc(value) or "–")[:DISCORD_FIELD], "inline": True} for label, value in card_fields(s, lang)],
                "footer": {"text": _date(s.published_at, lang)},
            }
            if url := _safe_url(s.url):
                e["url"] = url
            if sum(map(_embed_size, embeds)) + _embed_size(e) > DISCORD_TOTAL:
                break
            embeds.append(e)
            shown += 1
    if total > shown:
        content += "\n" + _discord_esc(lb["more"].format(n=total - shown))
    # allowed_mentions: whatever the text says, nobody is pinged – not @everyone, no role, no user
    return {"username": "Cobe News", "content": content[:1900], "embeds": embeds, "allowed_mentions": {"parse": []}}


def _tg(v: str) -> str:
    """Free text for Telegram's HTML parse mode: only &, < and > are special."""
    return html.escape(_one_line(v), quote=False)


def _tg_link(url: str, label: str) -> str:
    u = _safe_url(url)
    return f'<a href="{html.escape(u, quote=True)}">{_tg(label)}</a>' if u else f"<b>{_tg(label)}</b>"


TELEGRAM_MAX = 3900  # sendMessage: 4096 characters after entity parsing – room to spare


def render_telegram(rule: str, stories: list[Story], total: int, lang: str, *, test: bool = False) -> str:
    """The text of one sendMessage with parse_mode HTML: a card per story (labelled fields), a compact list for many."""
    lb = LABELS[lang]
    out = [f"<b>{_tg(_head(lb, total, test))}</b> · {_tg(rule)}"]
    if test:
        out.append(_tg(lb["test_title"].format(rule=rule)))
    if _compact(total):
        out.append("")
    shown = 0
    for s in stories:
        if _compact(total):
            block = [f"• {_tg_link(_open(s), s.headline[:200])} · {_tg(compact_extra(s, lang))}"]
        else:
            head = _tg_link(s.url, s.headline[:300])
            block = ["", head if head.startswith("<b>") else f"<b>{head}</b>", *(f"<b>{_tg(label)}:</b> {_tg(value[:300])}" for label, value in card_fields(s, lang))]
            if b := brief(s.summary):
                block.append(_tg(b))
            block.append(f"{_tg(_date(s.published_at, lang))} · {_tg_link(_open(s), lb['open'])}")
        if len("\n".join(out + block)) > TELEGRAM_MAX - 120:
            break
        out += block
        shown += 1
    if total > shown:
        out += ["", _tg(lb["more"].format(n=total - shown))]
    return "\n".join(out)


WEBHOOK_VERSION = 1


def render_webhook(channel: str, rules: list[str], stories: list[Story], total: int, lang: str, *, test: bool = False, delivery: str = "") -> dict:
    """The generic webhook's JSON (docs/BETRIEB.md: "Generischer Webhook"). The story fields are feed text – the receiver has to
    treat them as untrusted input."""
    return {
        "version": WEBHOOK_VERSION,
        "type": "news.test" if test else "news.stories",
        "id": delivery or str(uuid.uuid4()),
        "sent_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "app": "cobe-news",
        "app_url": get_config().base_url + "/",
        "channel": channel,
        "rules": rules,
        "lang": lang,
        "total": total,
        "more": max(0, total - len(stories)),
        "stories": [
            {
                "id": s.id,
                "title": s.title,
                "summary": s.summary,
                "url": s.url if s.url.lower().startswith(("https://", "http://")) else "",
                "link": _open(s),
                "severity": s.severity,
                "source": s.source,
                "published_at": s.published_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "cves": list(s.cves or []),
                "kind": s.kind,
                # 0.1.46, additive: the story's topics (news.TOPICS) and the product when reliably known ("" otherwise)
                "topics": list(s.topics or []),
                "product": s.product,
                # additive: "GREEN" for a CSAF provider's TLP:GREEN document (share internally only), else ""
                "tlp": s.tlp or "",
            }
            for s in stories
        ],
    }


# ---------------------------------------------------------------- ntfy, Gotify, Mattermost

NTFY_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}  # ntfy: 1 min … 5 max/urgent
GOTIFY_PRIORITY = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}  # Gotify: 0 … 10 (8 and up: high)
# ntfy shows a tag that names an emoji as the emoji in front of the title
NTFY_SEV_TAGS = {"critical": "rotating_light", "high": "warning", "medium": "large_orange_diamond", "low": "small_blue_diamond", "info": "information_source"}
PUSH_TEXT_MAX = 3500  # characters of an ntfy / Gotify message (ntfy: up to 4096 bytes, more would become an attachment)
_BLOCK_CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f\x85\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def plain_block(text: str) -> str:
    """Plain text of several lines: line breaks kept (one empty line at most), every other control or direction
    character out."""
    text = _BLOCK_CONTROL.sub(" ", neutral(text or ""))
    return re.sub(r"\n{3,}", "\n\n", "\n".join(" ".join(x.split()) for x in text.split("\n"))).strip()


def _top(stories: list[Story]) -> str:
    return max(stories, key=lambda s: RANK.get(s.severity, 0)).severity


def render_push(rule: str, stories: list[Story], total: int, lang: str, *, test: bool = False) -> tuple[str, str, str, str]:
    """(title, message, top severity, click URL) of an ntfy or Gotify message – plain text: neither renders anything of
    it (ntfy's markdown stays off, Gotify's content type is text/plain), and nothing of it goes into a header. The same
    card as the chats (Produkt, Quelle, Kategorie, short description), a compact list for many stories."""
    lb = LABELS[lang]
    if total == 1 and not test:
        title = f"{lb['sev'][stories[0].severity]}: {stories[0].headline}"
    else:
        title = f"{_head(lb, total, test)} · {rule}"
    out: list[str] = []
    if test:
        out.append(lb["test_title"].format(rule=rule))
    shown = 0
    for s in stories:
        if _compact(total):
            block = [f"• {one_line(s.headline)[:200]} · {one_line(compact_extra(s, lang))}"]
        else:
            block = [one_line(s.headline), *(f"{label}: {one_line(value)[:300]}" for label, value in card_fields(s, lang))]
            if b := brief(s.summary):
                block += ["", b]
            if url := _safe_url(s.url):
                block.append(f"{lb['article']}: {url}")
            block.append(f"{lb['open']}: {_safe_url(_open(s))}")
        sep = "\n" if _compact(total) and shown else "\n\n"
        if len(sep.join(["\n".join(out), "\n".join(block)])) > PUSH_TEXT_MAX - 120:
            break
        if out:
            out += [*([""] if sep == "\n\n" else []), *block]
        else:
            out += block
        shown += 1
    if total > shown:
        out += ["", lb["more"].format(n=total - shown)]
    click = _open(stories[0]) if total == 1 and not test else get_config().base_url + "/"
    return one_line(title)[:250], plain_block("\n".join(out))[:PUSH_TEXT_MAX], _top(stories), click


def ntfy_payload(topic: str, title: str, message: str, severity: str, click: str, tags: list[str] | None = None) -> dict:
    """ntfy's JSON publishing (POST to the server's root): everything in the body – no header carries feed text."""
    extra = [x for x in tags or [] if NTFY_TAG.match(x)][:NTFY_TAGS_MAX]
    return {
        "topic": topic,
        "title": one_line(title)[:250],
        "message": plain_block(message)[:PUSH_TEXT_MAX],
        "priority": NTFY_PRIORITY.get(severity, 3),
        "tags": [NTFY_SEV_TAGS.get(severity, "information_source"), *extra],
        "click": _safe_url(click),
        "markdown": False,
    }


def gotify_payload(title: str, message: str, severity: str, click: str) -> dict:
    """Gotify's POST /message: plain text (content type text/plain – no markdown), a click opens Cobe News."""
    return {
        "title": one_line(title)[:250],
        "message": plain_block(message)[:PUSH_TEXT_MAX],
        "priority": GOTIFY_PRIORITY.get(severity, 5),
        "extras": {"client::display": {"contentType": "text/plain"}, "client::notification": {"click": {"url": _safe_url(click)}}},
    }


def mm_plain(v: str) -> str:
    """Text Mattermost shows as it is (an attachment's fallback, the notification): one line, mentions defused."""
    return _one_line(v).replace("@", "@\u200b")


def mm_esc(v: str) -> str:
    """Free text for Mattermost's Markdown: no link, image, emphasis, heading, code, table, emoji or ~channel of its
    own – the special characters backslash-escaped; @all / @channel / @here / @name defused by a zero-width space after
    the @ (Mattermost would highlight and notify them)."""
    return re.sub(r"([\\`*_~\[\]()<>#|:!$&{}])", r"\\\1", mm_plain(v))


MM_COLORS = ACCENTS  # an attachment's colour bar by severity


def render_mattermost(rule: str, stories: list[Story], total: int, lang: str, *, test: bool = False) -> dict:
    """An incoming webhook's JSON: the heading as text, one attachment per story with its colour and labelled fields
    (Produkt, Quelle, Kategorie) – for many stories one attachment with a line each."""
    lb = LABELS[lang]
    text = f"**{mm_esc(_head(lb, total, test))}** · {mm_esc(rule)}"
    if test:
        text += "\n" + mm_esc(lb["test_title"].format(rule=rule))
    attachments = []
    if _compact(total):
        lines = []
        for s in stories:
            url = _safe_url(_open(s))  # a summary's line opens the story in Cobe News
            lines.append(f"• [{mm_esc(s.headline)[:200]}]({url}) · {mm_esc(compact_extra(s, lang))}")
        attachments.append({"fallback": mm_plain(_head(lb, total, test))[:300], "color": MM_COLORS.get(_top(stories), MM_COLORS["info"]), "text": "\n".join(lines)[:3800]})
        shown = len(stories)
    else:
        for s in stories[:10]:
            url = _safe_url(s.url)
            body = f"**[{mm_esc(s.headline)[:400]}]({url})**" if url else f"**{mm_esc(s.headline)[:400]}**"
            if b := brief(s.summary):
                body += "\n" + mm_esc(b)
            body += f"\n{mm_esc(_date(s.published_at, lang))} · [{mm_esc(lb['open'])}]({_safe_url(_open(s))})"
            fields = [{"title": mm_plain(label), "value": mm_esc(value)[:300], "short": True} for label, value in card_fields(s, lang)]
            attachments.append({"fallback": mm_plain(f"{lb['sev'][s.severity]}: {s.headline}")[:300], "color": MM_COLORS.get(s.severity, MM_COLORS["info"]), "text": body, "fields": fields})
        shown = len(stories[:10])
    if total > shown:
        text += "\n" + mm_esc(lb["more"].format(n=total - shown))
    return {"username": "Cobe News", "text": text[:4000], "attachments": attachments}


async def send_text(t: "Target", *, title: str, message: str, severity: str, click: str, mattermost: dict) -> None:
    """One message to an ntfy, Gotify or Mattermost channel through the channels' own POST (egress checks, pinned
    connection, no redirects) – or NotifyError. ntfy / Gotify get `title` and `message` (plain text), Mattermost its
    JSON. The token goes only into its own header (checked: no line break, no blank)."""
    if not t.url:
        raise NotifyError("not_configured")
    if t.type == "mattermost":
        check_url("mattermost", t.url)
        await post(t.url, _json(mattermost), JSON_HEADERS)
        return
    base = server_base(check_url(t.type, t.url))
    if t.type == "ntfy":
        if not NTFY_TOPIC.match(t.topic) or (t.token and not PUSH_TOKEN.match(t.token)):
            raise NotifyError("not_configured")
        headers = {**JSON_HEADERS, **({"Authorization": f"Bearer {t.token}"} if t.token else {})}
        await post(base + "/", _json(ntfy_payload(t.topic, title, message, severity, click, t.tags)), headers)
    elif t.type == "gotify":
        if not PUSH_TOKEN.match(t.token):
            raise NotifyError("not_configured")
        await post(base + "/message", _json(gotify_payload(title, message, severity, click)), {**JSON_HEADERS, "X-Gotify-Key": t.token})
    else:
        raise NotifyError("not_configured")


def sign(secret: str, ts: str, body: bytes) -> str:
    """The signature: "sha256=" + HMAC-SHA256(secret, "<timestamp>.<body>")."""
    return "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- sending: mail


def _classify_mail(exc: BaseException) -> str:
    if isinstance(exc, aiosmtplib.SMTPAuthenticationError):
        return "auth"
    if isinstance(exc, aiosmtplib.SMTPRecipientsRefused | aiosmtplib.SMTPSenderRefused):
        return "rejected"
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLError):
            return "tls"
        if isinstance(seen, socket.gaierror):
            return "dns"
        if isinstance(seen, ConnectionRefusedError):
            return "refused"
        if isinstance(seen, TimeoutError | aiosmtplib.SMTPConnectTimeoutError | aiosmtplib.SMTPTimeoutError):
            return "timeout"
        seen = seen.__cause__ or seen.__context__
    text = str(exc).lower()
    return "tls" if "tls" in text or "ssl" in text else "refused" if "refused" in text else "connection"


async def send_mail(cfg: dict, to: list[str], subject: str, text: str, body: str) -> None:
    if not cfg.get("host") or not cfg.get("from_addr"):
        raise NotifyError("not_configured", "smtp")
    if not to:
        raise NotifyError("not_configured", "recipients")
    # the To header is where the recipients are read from: "me@corp.example,spy@evil.example" (an LDAP / Entra `mail`,
    # an e-mail field) would be two – also one outside the company
    if not all(len(a) <= 254 and MAIL_ADDRESS.fullmatch(a) for a in to):
        raise NotifyError("not_configured", "recipients")
    msg = EmailMessage()
    try:
        msg["From"] = formataddr((one_line(cfg.get("from_name") or "") or "Cobe News", cfg["from_addr"]))
        msg["To"] = ", ".join(to)
        msg["Subject"] = one_line(subject)
    except ValueError as exc:
        raise NotifyError("not_configured") from exc
    msg["Message-ID"] = make_msgid(domain=cfg["from_addr"].split("@")[-1])
    msg["Date"] = format_datetime(datetime.now(UTC))
    msg["Auto-Submitted"] = "auto-generated"  # no out-of-office replies back (RFC 3834)
    msg["X-Auto-Response-Suppress"] = "All"
    msg.set_content(text)
    msg.add_alternative(body, subtype="html")
    ctx = ssl.create_default_context()
    if not cfg.get("verify_cert", True):
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    enc = cfg.get("encryption", "starttls")
    password = None
    if cfg.get("username") and cfg.get("password_enc"):
        try:
            password = decrypt_str(cfg["password_enc"])
        except Exception as exc:  # noqa: BLE001
            raise NotifyError("secret_unreadable") from exc
    sock = None
    try:
        # the SMTP host is admin input like a webhook URL: checked and pinned the same way (netaddr.mail_socket)
        sock = await netaddr.mail_socket(cfg["host"], int(cfg.get("port") or 25), 20)
        await aiosmtplib.send(
            msg,
            hostname=cfg["host"],
            sock=sock,
            use_tls=enc == "tls",
            start_tls=enc == "starttls",
            tls_context=ctx,
            username=cfg.get("username") or None,
            password=password,
            timeout=20,
        )
    except netaddr.ForbiddenTarget as exc:
        raise NotifyError("forbidden_target") from exc
    except (aiosmtplib.SMTPException, OSError, UnicodeError) as exc:
        # the category and the reply code only: the server's own text (its banner, an internal host name) is not shown
        # or stored
        code = getattr(exc, "code", None)
        raise NotifyError(_classify_mail(exc), code=code if isinstance(code, int) and 200 <= code < 600 else None) from exc
    finally:
        if sock is not None:
            sock.close()


# ---------------------------------------------------------------- sending: HTTP


@dataclass
class Reply:
    status: int
    headers: httpx.Headers
    body: bytes

    def json(self) -> dict:
        try:
            v = json.loads(self.body or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}
        return v if isinstance(v, dict) else {}


def _retry_after(reply: Reply) -> float | None:
    """Seconds a 429 asks to wait: Telegram's parameters.retry_after, Discord's retry_after (body), else the header."""
    data = reply.json()
    params = data.get("parameters") if isinstance(data.get("parameters"), dict) else {}
    for v in (params.get("retry_after"), data.get("retry_after"), reply.headers.get("retry-after")):
        try:
            if v is not None and float(v) >= 0:
                return min(float(v), RETRY_AFTER_MAX)
        except (TypeError, ValueError):
            continue
    return None


async def _post_once(url: str, body: bytes, headers: dict[str, str], *, use_proxy: bool, policy: dict | None = None) -> Reply:
    """One POST: no redirects, timeouts, without a proxy the name is resolved once, checked (netaddr.channel_policy:
    public addresses, private ones only in WEBHOOK_PRIVATE_NETS, never loopback / link-local / own Docker networks / the
    Docker host – or `policy`, e.g. PUBLIC_ONLY) and exactly that address connected to. Errors carry no URL."""
    proxy = get_config().proxy if use_proxy else None
    policy = policy if policy is not None else netaddr.channel_policy()
    if netaddr.forbidden_literal(url, **policy):
        raise NotifyError("forbidden_target")
    try:
        async with (
            asyncio.timeout(REQUEST_DEADLINE),
            httpx.AsyncClient(
                timeout=TIMEOUT,
                proxy=None if transport else proxy,
                transport=transport or (None if proxy else netaddr.pinned_transport(tls_verify(), **policy)),
                follow_redirects=False,
                trust_env=False,
                verify=tls_verify(),
            ) as c,
            c.stream("POST", url, content=body, headers={"Accept-Encoding": bounded.ACCEPT_ENCODING, **headers}) as resp,
        ):
            try:  # only peeked at (errors, retry_after): up to BODY_MAX, also after decompression
                data = await bounded.read_limited(resp, BODY_MAX, truncate=True)
            except bounded.BadEncoding:
                data = b""
            return Reply(resp.status_code, resp.headers, data)
    except (TimeoutError, httpx.TimeoutException) as exc:
        raise NotifyError("timeout") from exc
    except httpx.ConnectError as exc:
        text = str(exc).lower()
        if "forbidden target" in text:
            raise NotifyError("forbidden_target") from exc
        if "cannot resolve" in text:
            raise NotifyError("dns") from exc
        if "ssl" in text or "certificate" in text:
            raise NotifyError("tls") from exc
        raise NotifyError("connection", "ConnectError") from exc
    except httpx.HTTPError as exc:
        raise NotifyError("connection", type(exc).__name__) from exc


# public addresses only – whatever WEBHOOK_PRIVATE_NETS lists (a person's own Teams webhook, app/personal.py)
PUBLIC_ONLY: dict = {"private_ok": False, "allow": ()}


async def post(url: str, body: bytes, headers: dict[str, str], *, use_proxy: bool = True, describe=None, policy: dict | None = None) -> Reply:  # noqa: ANN001
    """POST a body; a 429 that asks for a short wait is waited for (asyncio.sleep – the event loop goes on) and tried
    once more; otherwise NotifyError with the wait the service asked for. `describe(reply)` gives a safe error detail.
    `policy`: the egress policy (netaddr) instead of the channels' one."""
    for attempt in (1, 2):
        reply = await _post_once(url, body, headers, use_proxy=use_proxy, policy=policy)
        if 200 <= reply.status < 300:
            return reply
        detail = (describe(reply) if describe else "") or f"HTTP {reply.status}"
        if reply.status == 429:
            wait = _retry_after(reply)
            if attempt == 1 and wait is not None and wait <= RETRY_INLINE_MAX:
                await asyncio.sleep(wait)
                continue
            raise NotifyError("rate_limited", detail, retry_after=wait, code=429)
        if reply.status in (401, 403):
            raise NotifyError("auth", detail, code=reply.status)
        if reply.status in (404, 410):
            raise NotifyError("rejected", detail, code=reply.status)
        raise NotifyError("http", detail, code=reply.status)
    raise NotifyError("rate_limited")  # pragma: no cover - the loop returns or raises


def _json(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()


JSON_HEADERS = {"Content-Type": "application/json", "User-Agent": "Cobe-News"}


def _telegram_detail(reply: Reply) -> str:
    """Telegram's own description ("Bad Request: chat not found") – never the URL (it holds the token)."""
    d = reply.json().get("description")
    if not isinstance(d, str):
        return ""
    d = re.sub(r"\d{5,12}:[A-Za-z0-9_-]{20,}", "<token>", d)
    return f"HTTP {reply.status}: {_one_line(d)[:120]}"


# ---------------------------------------------------------------- channels


@dataclass
class Target:
    """A channel ready to send to: its secrets decrypted (only in memory, only for this round)."""

    id: uuid.UUID
    name: str
    type: str
    recipients: list[str] = field(default_factory=list)
    url: str = ""
    token: str = ""
    chat_id: str = ""
    allow_http: bool = False
    use_proxy: bool = True
    hmac: str = ""
    header_name: str = ""
    header_value: str = ""
    topic: str = ""  # ntfy
    tags: list[str] = field(default_factory=list)  # ntfy

    def secrets(self) -> tuple[str, ...]:
        """What must never show up in a stored error text (app/delivery_log.sanitize)."""
        return tuple(x for x in (self.url, self.token, self.hmac, self.header_value, self.topic) if x)


def _secret(ch: NotifyChannel, key: str) -> str:
    enc = (ch.secrets or {}).get(key)
    if not enc:
        return ""
    try:
        return decrypt_str(enc)
    except Exception as exc:  # noqa: BLE001
        raise NotifyError("secret_unreadable") from exc


def resolve(ch: NotifyChannel) -> Target:
    cfg = ch.config or {}
    t = Target(id=ch.id, name=ch.name, type=ch.type)
    if ch.type == "email":
        t.recipients = list(cfg.get("recipients") or [])
    elif ch.type == "telegram":
        t.token, t.chat_id = _secret(ch, "token"), str(cfg.get("chat_id") or "")
    elif ch.type in ("ntfy", "gotify"):
        # the server's address is no secret (config); the topic (on a public server the only protection) and the
        # tokens are
        t.url, t.token = str(cfg.get("server") or ""), _secret(ch, "token")
        if ch.type == "ntfy":
            t.topic, t.tags = _secret(ch, "topic"), [str(x) for x in cfg.get("tags") or []]
    else:
        t.url = _secret(ch, "url")
        if ch.type == "webhook":
            t.allow_http, t.use_proxy = bool(cfg.get("allow_http")), bool(cfg.get("use_proxy", True))
            t.hmac = _secret(ch, "hmac")
            t.header_name = str(cfg.get("header_name") or "")
            t.header_value = _secret(ch, "header_value") if t.header_name else ""
    return t


# webhook delivery ids: the same message (channel + its stories) keeps its id when it is sent again (retry, a send whose
# acknowledgment was lost) – the receiver can drop the second one
DELIVERY_NS = uuid.uuid5(uuid.NAMESPACE_URL, "urn:cobe-news:webhook-delivery")


def delivery_id(channel_id: uuid.UUID, key: str) -> str:
    return str(uuid.uuid5(DELIVERY_NS, f"{channel_id}|{key}")) if key else str(uuid.uuid4())


async def deliver(
    t: Target,
    stories: list[Story],
    total: int,
    lang: str,
    label: str,
    *,
    rules: list[str] | None = None,
    smtp: dict | None = None,
    test: bool = False,
    key: str = "",
    rule_ids: list[str] | None = None,
) -> None:
    """One message to one channel – or NotifyError. `key`: what the message carries (its stories / events) – the
    webhook's delivery id is derived from it (none, e.g. a test: a new id each time). `rule_ids`: the rules that brought
    it (the mail's footer links to them)."""
    lang = lang if lang in LABELS else "de"
    if t.type == "email":
        subject, text, body = render_mail(label, stories, total, lang, test=test, rules=rules, rule_ids=rule_ids)
        await send_mail(smtp or {}, t.recipients, subject, text, body)
        return
    if t.type == "telegram":
        if not TELEGRAM_TOKEN.match(t.token) or not TELEGRAM_CHAT.match(t.chat_id):
            raise NotifyError("not_configured")
        chat: int | str = int(t.chat_id) if t.chat_id.lstrip("-").isdigit() else t.chat_id
        payload = {"chat_id": chat, "text": render_telegram(label, stories, total, lang, test=test), "parse_mode": "HTML", "link_preview_options": {"is_disabled": True}}
        reply = await post(f"{TELEGRAM_API}/bot{t.token}/sendMessage", _json(payload), JSON_HEADERS, describe=_telegram_detail)
        if reply.json().get("ok") is False:
            raise NotifyError("rejected", _telegram_detail(reply))
        return
    if t.type in ("ntfy", "gotify", "mattermost"):
        title, message, severity, click = render_push(label, stories, total, lang, test=test)
        await send_text(t, title=title, message=message, severity=severity, click=click, mattermost=render_mattermost(label, stories, total, lang, test=test))
        return
    if not t.url:
        raise NotifyError("not_configured")
    check_url(t.type, t.url, allow_http=t.allow_http)
    if t.type == "slack":
        await post(t.url, _json(render_slack(label, stories, total, lang, test=test)), JSON_HEADERS)
    elif t.type == "teams":
        await post(t.url, _json(render_teams(label, stories, total, lang, test=test)), JSON_HEADERS)
    elif t.type == "discord":
        await post(t.url, _json(render_discord(label, stories, total, lang, test=test)), JSON_HEADERS)
    elif t.type == "webhook":
        delivery = delivery_id(t.id, key)
        body = _json(render_webhook(t.name, rules or [], stories, total, lang, test=test, delivery=delivery))
        headers = {"Content-Type": "application/json", "User-Agent": "Cobe-News-Webhook/1", "X-Cobe-Event": "news.test" if test else "news.stories", "X-Cobe-Delivery": delivery}
        if t.hmac:  # signed exactly as sent: the body bytes, not a second serialisation
            ts = str(int(time.time()))
            headers |= {"X-Cobe-Timestamp": ts, "X-Cobe-Signature": sign(t.hmac, ts, body)}
        if t.header_name and t.header_value:
            headers[t.header_name] = t.header_value
        await post(t.url, body, headers, use_proxy=t.use_proxy)
    else:
        raise NotifyError("not_configured")


# ---------------------------------------------------------------- the rules → the channels


def _story(i: NewsItem, s: NewsSource) -> Story:
    b = news_svc.BUILTIN_BY_KEY.get(s.key) if s.builtin else None
    topics = [t for t in news_svc.TOPICS if t in (i.topics or [])]
    return Story(
        str(i.id), i.title, i.summary, i.url, i.severity, s.name, i.published_at, list(i.cves or []), topics=topics, source_kind=b.category if b else "custom",
        product_keys=[str(k) for k in i.products or []],
    )


async def rule_scopes(db: AsyncSession, rule_ids: list[uuid.UUID]) -> dict[uuid.UUID, set[str]]:
    """The products (catalogue keys) of the teams a rule is limited to (notify_rule_teams → team_products) – per rule
    that is limited to teams; a rule not in the result covers every followed product. One query for all the rules."""
    if not rule_ids:
        return {}
    q = (
        select(NotifyRuleTeam.rule_id, VendorFollow.product)
        .select_from(NotifyRuleTeam)
        .outerjoin(TeamProduct, TeamProduct.team_id == NotifyRuleTeam.team_id)
        .outerjoin(VendorFollow, VendorFollow.id == TeamProduct.follow_id)
        .where(NotifyRuleTeam.rule_id.in_(rule_ids))
    )
    out: dict[uuid.UUID, set[str]] = {}
    for rid, product in await db.execute(q):
        out.setdefault(rid, set())
        if product:
            out[rid].add(str(product))
    return out


def scope_of(rule_ids, scopes: dict[uuid.UUID, set[str]]) -> set[str] | None:  # noqa: ANN001
    """What "eure Produkte" means for a story the rules `rule_ids` brought: the union of what they cover – None (every
    followed product) as soon as one of them is not limited to teams."""
    keys: set[str] = set()
    for rid in rule_ids:
        if rid not in scopes:
            return None
        keys |= scopes[rid]
    return keys


async def with_products(db: AsyncSession, stories: list[Story], scope: dict[str, set[str] | None] | None = None) -> None:
    """The cards' "Produkt" of news stories – only what is reliably known: a followed product the story's details
    concern (with the version entered and its fix: "PAN-OS 11.1.2 → 11.1.6-h3"), else the details' first affected
    product with its range ("GitLab < 19.5.1", as the News page's card hint). Without details: no product (no guess).
    And "Betrifft eure Produkte": the labels of the followed products a story concerns (news_items.products, those
    still followed) – one query for all the stories. `scope`: per story id the products that count (the teams of the
    rules that brought it – scope_of); a story not in it, or None: every followed product."""
    from app import story_details

    scope = scope or {}
    keyed = [st for st in stories if st.kind == "news" and st.product_keys and not st.ours]
    if keyed:
        labels = await story_details.followed_labels(db)
        for st in keyed:
            allowed = scope.get(st.id)
            st.ours = [neutral(labels[k])[:120] for k in st.product_keys if k in labels and (allowed is None or k in allowed)]
    news_ids = {}
    for st in stories:
        if st.kind == "news" and not st.product:
            try:
                news_ids[uuid.UUID(st.id)] = st
            except ValueError:
                continue
    if not news_ids:
        return
    rows = dict((await db.execute(select(StoryDetail.item_id, StoryDetail.data).where(StoryDetail.item_id.in_(list(news_ids)), StoryDetail.data.is_not(None)))).all())
    if not rows:
        return
    fol = await story_details.followed(db)
    for iid, data in rows.items():
        news_ids[iid].product = card_product(data, story_details.matches(data, fol) if fol else [])


def card_product(data: dict | None, matched: list[dict]) -> str:
    """A news story's "Produkt" from its details: the first followed product (story_details.matches – the catalogue's
    label of today, also for a product split or merged since) with a version it concerns, that version and its fix –
    else the details' first affected product with its range. "" when neither (no guess). Also the team forward's card."""
    from app import story_details

    product = ""
    for m in matched:
        hit = next((v for v in m["versions"] if v["status"] in ("affected", "possible")), None)
        if hit is None:
            continue
        product = " ".join(x for x in (str(m.get("label") or m["product"]), str(hit.get("version") or "")) if x)
        if hit.get("fixed"):
            product += f" → {hit['fixed']}"
        break
    if not product and (h := story_details.hint(data)) and h.get("product"):
        product = str(h["product"])
    # the advisory's text: no direction or control characters (set after Story.__post_init__ – neutral here)
    return neutral(product)[:200]


# ---------------------------------------------------------------- what a rule lets through (the live round and the dry run)
#
# The filters below are the one matcher of the rules: built from the rule's fields only (severities, sources, topics,
# kinds, teams) – no channel, no "sent" marks, no time. The live round (pending / vendor_pending / health_pending) adds the
# time since the rule (and the link) and what the channel got already; the dry run (dry_run) adds only the time window.


def news_filter(rule: NotifyRule) -> list:
    """The stories a rule lets through (NewsSource joined as the story's own source – news.visible)."""
    where = [
        # no backlog: a source switched on later (or the news switched on for the first time) brings up to 200 older
        # stories at once – only what was fresh when it arrived is sent (news._backlog: decided once, when stored – the
        # same for the rules, the tab and Web Push)
        NewsItem.backlog.is_(False),
    ]
    if rule.severities:
        where.append(NewsItem.severity.in_(list(rule.severities)))
    # topics: one of them (OR within the topics, AND with the rest) – a story that gets one only later by an event of
    # its own (a new KEV entry, a list's new exploit entry, its details) matches from then on and is sent then, once
    # (pending: not sent to the channel yet); one gained quietly (a full recompute: an exploit list switched on or its
    # first import, a new rule version – news.loud_topic) never: an older story is no news because of that
    if topics := rule_topics(rule):
        where.append(news_svc.loud_topic(topics))
    # carried by a switched-on source (of the rule's, when it names some) – also as a further source ("also in")
    ids = news_svc._ids(rule.sources)
    where.append(news_svc.visible(ids) if ids or not rule.sources else false())  # only unreadable ids: nothing, not "all"
    return where


def rule_topics(rule: NotifyRule) -> list[str]:
    """The rule's topics as news.TOPICS knows them (in their order) – empty: every story, whatever its topics."""
    return [t for t in news_svc.TOPICS if t in (getattr(rule, "topics", None) or [])]


def _teams_clause(teams) -> ColumnElement:  # noqa: ANN001
    """Limited to teams: a stored rule's teams (a select of notify_rule_teams – none: every product) or a list (the dry
    run's form – empty: every product)."""
    if isinstance(teams, (list, tuple)):
        return _of_teams(list(teams)) if teams else true()
    return or_(~exists(teams), _of_teams(teams))


def vendor_filter(rule: NotifyRule, teams) -> list | None:  # noqa: ANN001
    """The Vendor News events a rule lets through – None: none of its kinds is a Vendor News one."""
    want = _vendor_kinds(rule_kinds(rule))
    if not want:
        return None
    where = [VendorEvent.kind.in_(want), VendorEvent.baseline.is_(False)]
    if rule.severities:
        where.append(or_(VendorEvent.kind.not_in(SEVERITY_KINDS), VendorEvent.severity.in_(list(rule.severities))))
    where.append(_teams_clause(teams))
    return where


def health_filter(rule: NotifyRule) -> list | None:
    """The source health changes a rule lets through (its severities and sources do not apply) – None: not chosen."""
    if "source_health" not in rule_kinds(rule):
        return None
    return [SourceHealthEvent.notify.is_(True)]


async def pending(db: AsyncSession, rule: NotifyRule, channel_id: uuid.UUID, since: datetime) -> list[tuple[NewsItem, NewsSource]]:
    """The stories `rule` brings to a channel: arrived after `since`, matching, not sent to that channel yet."""
    where = [NewsItem.fetched_at > since, *news_filter(rule), *_earlier_news(rule)]
    sent = exists().where(and_(NotifyDelivery.channel_id == channel_id, NotifyDelivery.item_id == NewsItem.id))
    stmt = select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where, ~sent).order_by(NewsItem.published_at.desc()).limit(PENDING_MAX)
    return [(i, s) for i, s in (await db.execute(stmt)).all()]


# ---------------------------------------------------------------- widening a rule: from then on


EARLIER_MAX = 10  # filters kept per rule; more: the two oldest become one (stricter, never wider)


def rule_filter(rule: NotifyRule, teams: list | None = None) -> dict:
    """What a rule lets through, normalised: severities / sources / topics / teams None = all (a rule's empty list).
    `teams`: the rule's team filter (notify_rule_teams – not on the rule row)."""
    return {
        "severities": sorted(rule.severities or []) or None,
        "sources": sorted(str(x) for x in rule.sources or []) or None,
        "topics": sorted(rule_topics(rule)) or None,
        "kinds": sorted(rule_kinds(rule)),
        "teams": sorted(str(x) for x in teams or []) or None,
    }


def widens(old: dict, new: dict) -> bool:
    """`new` lets through something `old` did not: another severity, source, topic, kind or team (or "all" instead of a
    choice). A filter of before topics existed has none (`topics` missing: all)."""

    def more(a: list | None, b: list | None) -> bool:
        return a is not None and (b is None or bool(set(b) - set(a)))

    return (
        more(old["severities"], new["severities"])
        or more(old["sources"], new["sources"])
        or more(old.get("topics"), new.get("topics"))
        or bool(set(new["kinds"]) - set(old["kinds"]))
        or more(old.get("teams"), new.get("teams"))
    )


def _both(a: list | None, b: list | None) -> list | None:
    return b if a is None else a if b is None else sorted(set(a) & set(b))


def _at(x: dict) -> datetime:
    return datetime.fromisoformat(x["at"])


def widened(rule: NotifyRule, before: dict, seq: int, at: datetime) -> None:
    """The rule's filter was widened when the last story was number `seq` (at `at`): whatever arrived up to then is sent
    only when it matched `before` as well – no flood of older stories that match only now. Filters from before the rule
    was (last) switched on are dropped: nothing older than that is sent anyway."""
    keep = [x for x in rule.earlier or [] if _at(x) > rule.active_since]
    keep.append({**before, "seq": int(seq), "at": at.isoformat()})
    while len(keep) > EARLIER_MAX:
        a, b = keep[0], keep[1]
        merged = {
            "severities": _both(a["severities"], b["severities"]),
            "sources": _both(a["sources"], b["sources"]),
            "topics": _both(a.get("topics"), b.get("topics")),
            "kinds": sorted(set(a["kinds"]) & set(b["kinds"])),
            "teams": _both(a.get("teams"), b.get("teams")),
        }
        keep[:2] = [{**merged, "seq": max(a["seq"], b["seq"]), "at": max(_at(a), _at(b)).isoformat()}]
    rule.earlier = keep


def _earlier_news(rule: NotifyRule) -> list:
    """Per widening: a story up to its number counts only when it matched the filter before as well."""
    out = []
    for x in rule.earlier or []:
        match = [] if "news" in x["kinds"] else [false()]
        if x["severities"] is not None:
            match.append(NewsItem.severity.in_(list(x["severities"])))
        if x["sources"] is not None:
            ids = news_svc._ids(x["sources"])
            match.append(news_svc.carried(ids) if ids else false())
        if x.get("topics") is not None:
            want = [t for t in x["topics"] if t in news_svc.TOPICS]
            match.append(news_svc.loud_topic(want) if want else false())
        if match:
            out.append(or_(NewsItem.seq > int(x["seq"]), and_(*match)))
    return out


def _vendor_kinds(kinds: list[str]) -> list[str]:
    return (["vuln"] if "vendor_vuln" in kinds else []) + (["version", "eol"] if "vendor_version" in kinds else []) + (["change"] if "vendor_change" in kinds else [])


SEVERITY_KINDS = ("vuln", "change")  # the event kinds a rule's severities filter (versions and EOL have their own)


def _of_teams(team_ids) -> ColumnElement:  # noqa: ANN001
    """SQL: the event's product belongs to one of these teams (a select of team ids, or a list) – and did so when the
    event was created (a product added to a team brings its events from then on, not its older ones)."""
    return exists().where(
        TeamProduct.team_id.in_(team_ids),
        VendorFollow.id == TeamProduct.follow_id,
        VendorFollow.product == VendorEvent.product,
        TeamProduct.added_at <= VendorEvent.created_at,
    )


def _earlier_vendor(rule: NotifyRule) -> list:
    """Per widening: a Vendor News event created up to then counts only when it matched the filter before as well."""
    out = []
    for x in rule.earlier or []:
        match = [VendorEvent.kind.in_(_vendor_kinds(x["kinds"]))]
        if x["severities"] is not None:
            match.append(or_(VendorEvent.kind.not_in(SEVERITY_KINDS), VendorEvent.severity.in_(list(x["severities"]))))
        if x.get("teams") is not None:
            match.append(_of_teams([uuid.UUID(t) for t in x["teams"]]))
        out.append(or_(VendorEvent.created_at > _at(x), and_(*match)))
    return out


NEWS_KINDS = ("news",)
# vendor_change (0.1.32): an advisory of a followed product was revised (app/advisory_changes.py) – only rules that
# choose it; existing rules do not get it
VENDOR_KINDS = ("vendor_vuln", "vendor_version", "vendor_change")
HEALTH_KINDS = ("source_health",)  # a source became disturbed or dead, or is back (app/source_health.py)


def rule_kinds(rule: NotifyRule) -> list[str]:
    return [k for k in (rule.kinds or ["news"]) if k in (*NEWS_KINDS, *VENDOR_KINDS, *HEALTH_KINDS)]


async def vendor_pending(db: AsyncSession, rule: NotifyRule, channel_id: uuid.UUID, since: datetime) -> list[VendorEvent]:
    """Vendor News events a rule brings to a channel: of its kinds (a vulnerability of a followed product – of the rule's
    severities –, a newer version or EOL, a revised advisory – of the rule's severities too), created after `since`, not the baseline of a new product, not sent there yet."""
    # limited to teams: only the products of those teams (notify_rule_teams; none: every product)
    match = vendor_filter(rule, select(NotifyRuleTeam.team_id).where(NotifyRuleTeam.rule_id == rule.id))
    if match is None:
        return []
    where = [*match, VendorEvent.created_at > since, *_earlier_vendor(rule)]
    sent = exists().where(and_(VendorDelivery.channel_id == channel_id, VendorDelivery.event_id == VendorEvent.id))
    stmt = select(VendorEvent).where(*where, ~sent).order_by(VendorEvent.created_at.desc()).limit(PENDING_MAX)
    return list(await db.scalars(stmt))


def _earlier_health(rule: NotifyRule) -> list:
    """Per widening: a state change from before it counts only when the rule sent state changes then as well."""
    return [SourceHealthEvent.created_at > _at(x) for x in rule.earlier or [] if "source_health" not in x["kinds"]]


async def health_pending(db: AsyncSession, rule: NotifyRule, channel_id: uuid.UUID, since: datetime) -> list[SourceHealthEvent]:
    """State changes of the sources worth a message (into disturbed / dead, or back), after `since`, not sent there yet.
    The rule's severities and sources do not apply – a source's health is no story."""
    match = health_filter(rule)
    if match is None:
        return []
    sent = exists().where(and_(SourceHealthDelivery.channel_id == channel_id, SourceHealthDelivery.event_id == SourceHealthEvent.id))
    where = [*match, SourceHealthEvent.created_at > since, *_earlier_health(rule), ~sent]
    return list(await db.scalars(select(SourceHealthEvent).where(*where).order_by(SourceHealthEvent.created_at.desc()).limit(PENDING_MAX)))


HEALTH_LABELS = {
    "de": {
        "source": "Quellen-Gesundheit",
        "dead": "Quelle tot: {name}",
        "disturbed": "Quelle gestört: {name}",
        "back": "Quelle wieder in Ordnung: {name}",
        "vendor": "Vendor News",
        "news": "News",
        "reasons": {
            "blocked": "lehnt automatische Abrufe ab (HTTP 401/403/410)",
            "not_found": "Adresse nicht mehr vorhanden (HTTP 404)",
            "no_success": "seit 14 Tagen kein erfolgreicher Abruf",
            "stale": "seit 60 Tagen keine neuen Meldungen",
            "failing": "mehrere Fehlschläge in Folge",
            "error": "der letzte Abruf ist fehlgeschlagen",
            "parse": "Antwort in den letzten 24 Stunden nicht lesbar",
        },
        "was": "vorher: {state}",
        "states": {"healthy": "gesund", "slow": "langsam", "disturbed": "gestört", "dead": "tot", "off": "aus", "never": "noch nicht abgerufen"},
        "hint": "Details unter Einstellungen › Integrationen › Gesundheit.",
    },
    "en": {
        "source": "Source health",
        "dead": "Source dead: {name}",
        "disturbed": "Source disturbed: {name}",
        "back": "Source back to normal: {name}",
        "vendor": "Vendor News",
        "news": "News",
        "reasons": {
            "blocked": "refuses automatic fetches (HTTP 401/403/410)",
            "not_found": "address no longer exists (HTTP 404)",
            "no_success": "no successful fetch for 14 days",
            "stale": "no new stories for 60 days",
            "failing": "several failures in a row",
            "error": "the last fetch failed",
            "parse": "answer not readable within the last 24 hours",
        },
        "was": "before: {state}",
        "states": {"healthy": "healthy", "slow": "slow", "disturbed": "disturbed", "dead": "dead", "off": "off", "never": "not fetched yet"},
        "hint": "Details under Settings › Integrations › Health.",
    },
}
HEALTH_SEVERITY = {"dead": "high", "disturbed": "medium"}


def health_story(ev: SourceHealthEvent, lang: str) -> Story:
    """A source's state change as a story for the channels' formats; the link opens it on the health page."""
    lb = HEALTH_LABELS.get(lang, HEALTH_LABELS["de"])
    name = f"{ev.name or ev.key} ({lb['vendor' if ev.kind == 'vendor' else 'news']})"
    title = lb[ev.state if ev.state in ("dead", "disturbed") else "back"].format(name=name)
    why = [lb["reasons"].get(r, r) for r in ev.reasons or [] if r in lb["reasons"]]
    summary = " · ".join([*why, lb["was"].format(state=lb["states"].get(ev.prev or "", ev.prev or "?"))]) + "\n" + lb["hint"]
    link = f"{get_config().base_url}/settings/integrations?{urlencode({'view': 'health', 'source': f'{ev.kind}:{ev.key}'})}"
    return Story(str(ev.id), title[:300], summary[:600], link, HEALTH_SEVERITY.get(ev.state, "info"), lb["source"], ev.created_at, [], "source.health", link, source_kind="health")


VENDOR_LABELS = {
    "de": {
        "source": "Vendor News",
        "affected": "betroffen",
        "possible": "möglicherweise betroffen – Version nicht eindeutig",
        "unversioned": "betrifft das Produkt (ohne Versionsangabe)",
        "service": "betrifft den Cloud-Dienst – behebt der Hersteller",
        "status": "Status",
        "fix": "Fix",
        "exploited": "aktiv ausgenutzt",
        "now_exploited": "Jetzt aktiv ausgenutzt",
        "version": "{product} {version}: neue Version {latest} verfügbar",
        "version_text": "Release-Linie {line} – aktuellste Version {latest}.",
        "eol_soon": "{product} {version}: Ende des Supports am {date}",
        "eol_past": "{product} {version}: Support beendet seit {date}",
        "eol_days": "{product} {version}: Support endet in {days} Tagen ({date})",
        "eol_text": "Release-Linie {line}. Auf eine unterstützte Version aktualisieren.",
        "watch_source": "Beobachtete CVE",
        "watch_kev": "{cve}: jetzt in CISA KEV (aktiv ausgenutzt)",
        "watch_kev_text": "In den KEV-Katalog aufgenommen am {added}{due}.",
        "watch_kev_due": ", Frist für US-Bundesbehörden {due}",
        "watch_fix": "{cve}: Fix-Version verfügbar",
        "watch_fix_text": "Neu genannte Fix-Versionen: {fixed}",
        "watch_more": " und {n} weitere",
        "watch_epss": "{cve}: EPSS gestiegen auf {score}",
        "watch_epss_high": "Perzentil {pct} – unter den 10 % der CVEs, die am wahrscheinlichsten ausgenutzt werden.",
        "watch_epss_jump": "Vorher {before}.",
        "watch_withdrawn": "{cve}: Advisory zurückgezogen",
        "watch_withdrawn_text": "{ident} ({source}) wurde von der Quelle zurückgezogen.",
        "watch_exploit": "{cve}: Exploit veröffentlicht",
        "watch_exploit_text": "Öffentlich verfügbar: {where}.",
        "watch_hint": "Du beobachtest diese CVE in Cobe News.",
    },
    "en": {
        "source": "Vendor News",
        "affected": "affected",
        "possible": "possibly affected – version not decidable",
        "unversioned": "concerns the product (no version given)",
        "service": "concerns the cloud service – fixed by the vendor",
        "status": "Status",
        "fix": "Fix",
        "exploited": "actively exploited",
        "now_exploited": "Now actively exploited",
        "version": "{product} {version}: new version {latest} available",
        "version_text": "Release line {line} – latest version {latest}.",
        "eol_soon": "{product} {version}: end of support on {date}",
        "eol_past": "{product} {version}: support ended on {date}",
        "eol_days": "{product} {version}: support ends in {days} days ({date})",
        "eol_text": "Release line {line}. Update to a supported version.",
        "watch_source": "Watched CVE",
        "watch_kev": "{cve}: now in CISA KEV (actively exploited)",
        "watch_kev_text": "Added to the KEV catalogue on {added}{due}.",
        "watch_kev_due": ", due date for US federal agencies {due}",
        "watch_fix": "{cve}: fixed version available",
        "watch_fix_text": "Newly named fixed versions: {fixed}",
        "watch_more": " and {n} more",
        "watch_epss": "{cve}: EPSS rose to {score}",
        "watch_epss_high": "Percentile {pct} – among the 10 % of CVEs most likely to be exploited.",
        "watch_epss_jump": "Before: {before}.",
        "watch_withdrawn": "{cve}: advisory withdrawn",
        "watch_withdrawn_text": "{ident} ({source}) was withdrawn by its source.",
        "watch_exploit": "{cve}: exploit published",
        "watch_exploit_text": "Publicly available: {where}.",
        "watch_hint": "You watch this CVE in Cobe News.",
    },
}


def label_now(key: str, stored: str = "") -> str:
    """The product's name as the catalogue has it today: an event keeps the label of its day (data.product), but a
    product may have been renamed, split (nginx / NGINX Plus) or merged into another key since (catalogue `replaces`,
    migration 0025 moved the events' key, not their data) – a custom product, unknown to the catalogue, keeps its own."""
    from app import vendor_catalog as catalog

    p = catalog.product(catalog.REPLACED.get(key, key))
    return str((p or {}).get("label") or stored or key)


def vendor_story(ev: VendorEvent, lang: str) -> Story:
    """A Vendor News event as a story for the channels' formats (title, summary, link to the product page)."""
    lb = VENDOR_LABELS.get(lang, VENDOR_LABELS["de"])
    d = ev.data or {}
    product = label_now(ev.product, str(d.get("product") or ""))
    version = str(d.get("version") or "")
    where = f"{product} {version}".strip() + (f" ({d['label']})" if d.get("label") else "")
    link = f"{get_config().base_url}/vendor?product={ev.product}"
    if ev.kind == "vuln":
        parts = [f"{lb['status']}: {lb.get(str(d.get('status')), str(d.get('status')))}"]
        if d.get("fixed"):
            parts.append(f"{lb['fix']}: {d['fixed']}")
        if d.get("cvss") is not None:
            parts.append(f"CVSS {float(d['cvss']):.1f}")
        if d.get("exploited"):
            parts.append(lb["exploited"])
        if d.get("now_exploited") and (d.get("kev") or {}).get("ransomware"):
            parts.append("Ransomware")
        summary = " · ".join(parts) + (f"\n{d['summary']}" if d.get("summary") else "")
        # the readable title (the vendor's, a short description – not NVD's marketing sentence); events from before
        # 0.1.14 have none stored: made the same way from what they have
        head = str(d.get("headline") or "") or titles.headline("nvd" if "nvd.nist.gov" in str(d.get("url") or "") else "vendor", str(d.get("title") or ""), str(d.get("summary") or ""), None, product)
        title = f"{where}: {d.get('ident') or ''} – {head}".strip(" –")
        if d.get("now_exploited"):
            title = f"{lb['now_exploited']}: {title}"
        tlp = "GREEN" if d.get("tlp") == "GREEN" else ""
        if tlp:
            title = TLP_PREFIX + title  # also in a subject, a compact list and a desktop notification
        product_line = f"{product} {version}".strip() + (f" → {d['fixed']}" if d.get("fixed") and version else "")
        return Story(
            str(ev.id), title[:300], summary[:600], str(d.get("url") or link), ev.severity, lb["source"], ev.created_at, list(d.get("cves") or []), "vendor.vuln", link,
            product=product_line, topics=["exploited"] if d.get("exploited") else [], source_kind="vendor_news", tlp=tlp,
            ours=[product],  # a Vendor News finding is one of a followed product
        )
    if ev.kind == "change":
        return change_story(ev, lang, where=product, link=link)
    if ev.kind == "watch":
        return watch_story(ev, lang)
    if ev.kind == "version":
        title = lb["version"].format(product=product, version=version, latest=d.get("latest", ""))
        text_ = lb["version_text"].format(line=d.get("line", ""), latest=d.get("latest", ""))
        product_line = f"{product} {version} → {d['latest']}".strip() if d.get("latest") else f"{product} {version}".strip()
        return Story(str(ev.id), title, text_, link, ev.severity, lb["source"], ev.created_at, [], "vendor.version", link, product=product_line, source_kind="vendor_news")
    if d.get("stage") in ("90", "30"):
        title = lb["eol_days"].format(product=product, version=version, days=d.get("days", d["stage"]), date=d.get("eol_from") or "?")
    else:
        title = lb["eol_past" if d.get("eol_state") == "past" else "eol_soon"].format(product=product, version=version, date=d.get("eol_from") or "?")
    eol_text = lb["eol_text"].format(line=d.get("line", ""))
    return Story(str(ev.id), title, eol_text, link, ev.severity, lb["source"], ev.created_at, [], "vendor.eol", link, product=f"{product} {version}".strip(), source_kind="vendor_news")


def _pct(x, lang: str) -> str:  # noqa: ANN001
    try:
        v = float(x) * 100
    except (TypeError, ValueError):
        return "–"
    s = f"{v:.1f} %"
    return s.replace(".", ",") if lang == "de" else s


def watch_story(ev: VendorEvent, lang: str) -> Story:
    """A watched CVE's event (app/cve_watch.py): a fix, KEV, EPSS, an advisory withdrawn. Plain text – every channel
    escapes it as it does a story's. The link opens the person's list of watched CVEs at it."""
    lb = VENDOR_LABELS.get(lang, VENDOR_LABELS["de"])
    d = ev.data or {}
    cve = str(d.get("cve") or "")
    link = f"{get_config().base_url}/watch?{urlencode({'cve': cve})}"
    what = d.get("what")
    if what == "kev":
        k = d.get("kev") or {}
        title = lb["watch_kev"].format(cve=cve)
        text = lb["watch_kev_text"].format(added=k.get("added") or "?", due=lb["watch_kev_due"].format(due=k["due"]) if k.get("due") else "")
        if k.get("ransomware"):
            text += " Ransomware."
    elif what == "fix":
        title = lb["watch_fix"].format(cve=cve)
        text = lb["watch_fix_text"].format(fixed="; ".join(str(x) for x in d.get("fixed") or [])) + (lb["watch_more"].format(n=d["more"]) if d.get("more") else "")
    elif what == "epss":
        title = lb["watch_epss"].format(cve=cve, score=_pct(d.get("score"), lang))
        parts = []
        if "high" in (d.get("reasons") or []):
            parts.append(lb["watch_epss_high"].format(pct=_pct(d.get("percentile"), lang)))
        if d.get("from") is not None:
            parts.append(lb["watch_epss_jump"].format(before=_pct(d.get("from"), lang)))
        text = " ".join(parts)
    elif what == "exploit":
        from app.exploits import SOURCES

        title = lb["watch_exploit"].format(cve=cve)
        names = [f"{SOURCES[x['source']].name} ({x.get('url') or ''})" if x.get("url") else SOURCES[x["source"]].name for x in d.get("exploits") or [] if isinstance(x, dict) and x.get("source") in SOURCES]
        text = lb["watch_exploit_text"].format(where="; ".join(names) or "?")
    else:
        title = lb["watch_withdrawn"].format(cve=cve)
        text = lb["watch_withdrawn_text"].format(ident=d.get("ident") or d.get("advisory") or "?", source=d.get("source") or "?")
    if d.get("title"):
        text += f"\n{d['title']}"
    text += f"\n{lb['watch_hint']}"
    return Story(
        str(ev.id), title[:300], text.strip()[:600], link, ev.severity, lb["watch_source"], ev.created_at, [cve] if cve else [], "vendor.watch", link,
        topics=["exploited"] if what == "kev" else [], source_kind="watch",
    )


def change_story(ev: VendorEvent, lang: str, *, where: str, link: str) -> Story:
    """A revised advisory (kind "change"): "Advisory geändert: PAN-OS – CVE-… (Revision 3)", the summary says what changed
    – the impact on the versions entered first ("PAN-OS 11.1.2: jetzt betroffen …"). Plain text: every channel escapes it
    as it does a story's."""
    lb = advisory_changes.TEXT.get(lang, advisory_changes.TEXT["de"])
    d = ev.data or {}
    lines = advisory_changes.describe(list(d.get("diff") or []), list(d.get("impact") or []), lang)
    rev = lb["revision"].format(n=d.get("revision") or "?")
    title = f"{lb['title']}: {where} – {d.get('ident') or ''} ({rev})".replace(" –  (", " (")
    summary = f"{rev}: " + "; ".join(lines) if lines else rev
    if d.get("title"):
        summary += f"\n{d['title']}"
    src_name = VENDOR_LABELS.get(lang, VENDOR_LABELS["de"])["source"]
    tlp = "GREEN" if d.get("tlp") == "GREEN" else ""
    if tlp:
        title = TLP_PREFIX + title
    return Story(str(ev.id), title[:300], summary[:600], str(d.get("url") or link), ev.severity, src_name, ev.created_at, list(d.get("cves") or []), "vendor.change", link, product=where, source_kind="vendor_news", tlp=tlp)


@dataclass
class Row:
    """One thing to send: a story of the feed or a Vendor News event, the rule that brought it, and its mark."""

    story: Story
    rule: NotifyRule
    mark: tuple[str, uuid.UUID]  # ("news", story id) | ("vendor", event id) | ("health", source health event id)


async def channel_pending(db: AsyncSession, ch: NotifyChannel, lang_of=None) -> list[Row]:  # noqa: ANN001
    """Everything the switched-on rules of a channel bring, once – with the first rule (by name) that brought it."""
    links = (
        await db.execute(
            select(NotifyRule, NotifyRuleChannel.added_at)
            .join(NotifyRuleChannel, NotifyRuleChannel.rule_id == NotifyRule.id)
            .where(NotifyRuleChannel.channel_id == ch.id, NotifyRule.enabled.is_(True))
            .order_by(NotifyRule.name, NotifyRule.id)
        )
    ).all()
    out: dict[tuple[str, uuid.UUID], Row] = {}
    brought: dict[uuid.UUID, list[uuid.UUID]] = {}  # per news story: every rule that brought it ("eure Produkte")
    for rule, added in links:
        since = max(rule.active_since, added)
        if "news" in rule_kinds(rule):
            for i, s in await pending(db, rule, ch.id, since):
                out.setdefault(("news", i.id), Row(_story(i, s), rule, ("news", i.id)))
                brought.setdefault(i.id, []).append(rule.id)
        for ev in await vendor_pending(db, rule, ch.id, since):
            out.setdefault(("vendor", ev.id), Row(vendor_story(ev, rule.lang), rule, ("vendor", ev.id)))
        for hv in await health_pending(db, rule, ch.id, since):
            out.setdefault(("health", hv.id), Row(health_story(hv, rule.lang), rule, ("health", hv.id)))
    # a Vendor News finding is ours anyway (a rule limited to teams brings only its teams' products); a news story's
    # products count as far as the rules that brought it cover them – a team's rule calls only its products "eure"
    scopes = await rule_scopes(db, sorted({r for rs in brought.values() for r in rs}))
    scope = {str(i): scope_of(rs, scopes) for i, rs in brought.items()} if scopes else None
    await with_products(db, [r.story for r in out.values()], scope)
    return list(out.values())


@dataclass
class Message:
    stories: list[Story]
    total: int
    lang: str
    label: str
    rules: list[str]
    items: list[tuple[str, uuid.UUID, uuid.UUID]]  # (kind, story or event, rule) – marked as sent once the message went out
    by: list[dict] = field(default_factory=list)  # the rules that brought it: [{"id", "name"}] (the delivery log)

    @property
    def key(self) -> str:
        """What the message carries – the same message sent again has the same key (webhook delivery id)."""
        return ",".join(sorted(f"{kind}:{item}" for kind, item, _ in self.items))

    def log(self) -> dict:
        """What the delivery log keeps of it: the listed stories by reference and title, the rules, what a resend sends."""
        return {
            "ref": delivery_log.ref_of(self.key),
            "items": [{"kind": x.kind, "id": x.id, "title": x.title, "severity": x.severity, "topics": list(x.topics or []) if x.kind == "news" else []} for x in self.stories],
            "total": self.total,
            "rules": self.by,
            "refs": [f"{kind}:{item}:{rule}" for kind, item, rule in self.items],
            "lang": self.lang,
        }


def plan(rows: list[Row]) -> list[Message]:
    """Per language: up to BATCH stories one message each (oldest first), more in one summary (the LIST first by
    priority: our products, actively exploited, severity, newest)."""
    out: list[Message] = []
    for lang in sorted({r.rule.lang for r in rows}):
        group = [x for x in rows if x.rule.lang == lang]
        names = sorted({x.rule.name for x in group})
        label = ", ".join(names[:3]) + (" …" if len(names) > 3 else "")
        if len(group) <= BATCH:
            for x in sorted(group, key=lambda x: x.story.published_at):
                out.append(Message([x.story], 1, lang, x.rule.name, [x.rule.name], [(x.mark[0], x.mark[1], x.rule.id)], [{"id": str(x.rule.id), "name": x.rule.name}]))
        else:
            top = sorted(group, key=lambda x: priority(x.story), reverse=True)[:LIST]
            by = sorted({str(x.rule.id): x.rule.name for x in group}.items(), key=lambda kv: (kv[1], kv[0]))
            out.append(Message([x.story for x in top], len(group), lang, label, names, [(x.mark[0], x.mark[1], x.rule.id) for x in group], [{"id": i, "name": n} for i, n in by]))
    return out


def summary(stories: list[tuple[Story, str, uuid.UUID]], lang: str, rules: list[dict]) -> Message:
    """One message of these stories (story, mark kind, rule id) – as plan() makes it: one story as itself, more as a
    summary (the LIST first by priority listed). A resend sends a delivery again this way."""
    names = sorted({r["name"] for r in rules if r.get("name")})
    label = ", ".join(names[:3]) + (" …" if len(names) > 3 else "") if names else "Cobe News"
    items = [(kind, uuid.UUID(st.id), rid) for st, kind, rid in stories]
    if len(stories) == 1:
        return Message([stories[0][0]], 1, lang, label, names, items, rules)
    top = sorted((x[0] for x in stories), key=priority, reverse=True)[:LIST]
    return Message(top, len(stories), lang, label, names, items, rules)


def _failure(failures: int, exc: NotifyError, now: datetime) -> dict:
    """A channel's state after a failed round: a growing pause (at least what the service asked for) and the error."""
    failures += 1
    wait = min(timedelta(minutes=2 * 2 ** min(failures - 1, 12)), BACKOFF_MAX)
    if exc.retry_after:
        wait = max(wait, timedelta(seconds=exc.retry_after))
    error = f"{exc.category}: {exc.detail}"[:200] if exc.detail else exc.category
    return {"failures": failures, "next_try_at": now + wait, "last_error": error, "last_error_at": now}


# ---------------------------------------------------------------- the round

FULL_EVERY = 600.0  # seconds: all rules looked at even without anything new (a story rated higher or carried by another source since)


@dataclass
class _Seen:
    marks: tuple | None = None  # what _marks() said at the last full look
    full_at: float = -1e9
    generation: int = 0  # counted up by changed()


_seen = _Seen()


def changed() -> None:
    """A channel, a rule or the mail server changed: the next round looks at everything again."""
    _seen.generation += 1


def reset() -> None:
    """Forget the last round (tests: a database of their own each)."""
    global _seen
    _seen = _Seen()


async def _marks(db: AsyncSession) -> tuple:
    """Whether anything new can be there: the last story's arrival number, the newest Vendor News event (its number and
    time – one deleted and another added still moves it), the newest source health change and the changes of channels
    and rules. Four lookups by index."""
    vendor = (await db.execute(select(func.max(VendorEvent.n), func.max(VendorEvent.created_at)))).one()
    health = await db.scalar(select(func.max(SourceHealthEvent.n)))
    return (await news_svc.last_seq(db), tuple(vendor), health, _seen.generation)


@dataclass
class _Job:
    """One channel in this round – plain values: nothing of the session is touched while (or after) sending."""

    id: uuid.UUID
    name: str
    type: str
    failures: int
    messages: list[Message]
    version: int = 0  # the channel as it was read: an admin's edit meanwhile (a new URL) wins over this round's outcome
    target: Target | None = None
    error: NotifyError | None = None  # could not even be set up (a secret unreadable)


async def _write(db: AsyncSession, gate: asyncio.Lock, what: str, *statements) -> bool:  # noqa: ANN002
    """Statements in a short transaction of their own; a failure is logged and rolled back – it never touches what the
    other channels write."""
    async with gate:  # one session: the channels' writes one after the other
        try:
            for st in statements:
                await db.execute(st)
            await db.commit()
            return True
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            log.warning("notify: %s not written (%s)", what, type(exc).__name__)
            return False


def _marked(channel_id: uuid.UUID, items: list[tuple[str, uuid.UUID, uuid.UUID]], at: datetime) -> list:
    """INSERTs marking a message's stories / events as sent – only those still there, and only while the channel is
    (INSERT … SELECT: a story pruned or a channel deleted meanwhile adds nothing instead of failing on its foreign key)."""
    by: dict[tuple[str, uuid.UUID], list[uuid.UUID]] = {}
    for kind, item, rule_id in items:
        by.setdefault((kind, rule_id), []).append(item)
    out = []
    for (kind, rule_id), ids in by.items():
        table, ref, col = {"vendor": (VendorDelivery, VendorEvent, "event_id"), "health": (SourceHealthDelivery, SourceHealthEvent, "event_id")}.get(kind, (NotifyDelivery, NewsItem, "item_id"))
        alive = exists().where(NotifyChannel.id == channel_id)
        rows = select(literal(channel_id, Uuid()), ref.id, literal(rule_id, Uuid()), literal(at, dbm.UTCDateTime())).where(ref.id.in_(ids), alive)
        out.append(pg_insert(table).from_select(["channel_id", col, "rule_id", "sent_at"], rows).on_conflict_do_nothing())
    out.append(update(NotifyChannel).where(NotifyChannel.id == channel_id).values(last_sent_at=at).execution_options(synchronize_session=False))
    return out


async def _run(db: AsyncSession, gate: asyncio.Lock, job: _Job, smtp: dict) -> int:
    """All messages of one channel, within its deadline; each marked as sent right after it went out. Returns how many
    stories / events went out."""
    sent = 0
    err = job.error
    deadline = asyncio.get_running_loop().time() + CHANNEL_DEADLINE
    # a channel that could not even be set up: its first message is the attempt that failed (the delivery log)
    for m in job.messages if job.target else job.messages[:1]:
        started = time.monotonic()
        if job.target is not None:
            try:
                async with asyncio.timeout_at(deadline):
                    await deliver(job.target, m.stories, m.total, m.lang, m.label, rules=m.rules, smtp=smtp, key=m.key, rule_ids=[r["id"] for r in m.by])
            except NotifyError as exc:
                err = exc
            except TimeoutError:
                err = NotifyError("timeout")
            except Exception as exc:  # noqa: BLE001 - one broken channel must not stop the round
                log.warning("notify channel %s: %s", job.id, type(exc).__name__)
                err = NotifyError("connection", type(exc).__name__)
        entry = delivery_log.entry(
            kind="rule", channel_id=job.id, channel_name=job.name, channel_type=job.type, error=err, secrets=job.target.secrets() if job.target else (), started=started, **m.log()
        )
        if err is not None:
            await _write(db, gate, f"delivery log of channel {job.id}", entry)
            break
        sent += len(m.items)
        # the marks on their own: a delivery log entry that cannot be written never undoes them (no message twice)
        await _write(db, gate, f"sent marks of channel {job.id}", *_marked(job.id, m.items, datetime.now(UTC)))
        await _write(db, gate, f"delivery log of channel {job.id}", entry)
    values = {"failures": 0, "next_try_at": None, "last_error": None} if err is None else _failure(job.failures, err, datetime.now(UTC))
    if err is not None:
        log.info("notify channel %s (%s): %s", job.name, job.type, values["last_error"])
        values["failures"] = NotifyChannel.failures + 1  # counted in the database, not from what was read before sending
    # only the channel as it was sent to: edited meanwhile (an admin fixed its URL, which resets its error and pause) –
    # the old target's outcome is not written over the fix
    stmt = update(NotifyChannel).where(NotifyChannel.id == job.id, NotifyChannel.version == job.version).values(**values)
    await _write(db, gate, f"state of channel {job.id}", stmt.execution_options(synchronize_session=False))
    return sent


async def dispatch(db: AsyncSession) -> dict[str, int]:
    """After a fetch round: every channel whose pause (after a failure) is over gets what its rules bring. The channels
    are sent to side by side (no database work open while sending); each message is marked as sent right after it went
    out and each channel's state is written on its own – a story, rule or channel deleted meanwhile, or one channel's
    failing write, never undoes or holds back the others.
    Nothing arrived and nothing changed since the last round: only the channels whose retry is due are looked at."""
    now = datetime.now(UTC)
    marks = await _marks(db)
    full = marks != _seen.marks or time.monotonic() - _seen.full_at > FULL_EVERY
    stmt = select(NotifyChannel).order_by(NotifyChannel.name)
    if not full:
        stmt = stmt.where(NotifyChannel.next_try_at.is_not(None), NotifyChannel.next_try_at <= now)
    smtp: dict = {}
    jobs: list[_Job] = []
    idle: list[uuid.UUID] = []
    for ch in list(await db.scalars(stmt)):
        if ch.next_try_at is not None and ch.next_try_at > now:
            continue
        try:
            rows = await channel_pending(db, ch)
        except Exception:  # noqa: BLE001 - one channel's rules unreadable: the others still go out
            log.exception("notify channel %s: rules not readable", ch.id)
            continue
        if not rows:
            if ch.next_try_at is not None:
                idle.append(ch.id)  # its retry is due but nothing waits any more: no retry (and no "next try" shown)
            continue
        job = _Job(ch.id, ch.name, ch.type, ch.failures or 0, plan(rows), version=ch.version)
        try:
            job.target = resolve(ch)
        except NotifyError as exc:
            job.error = exc
        jobs.append(job)
        if ch.type == "email" and not smtp:
            smtp = await settings_store.get(db, "smtp")
    await dbm.release(db)  # nothing pending or open while the channels are sent to
    gate = asyncio.Lock()
    if idle:
        await _write(db, gate, "idle retries", update(NotifyChannel).where(NotifyChannel.id.in_(idle)).values(next_try_at=None).execution_options(synchronize_session=False))
    counts = await asyncio.gather(*(_run(db, gate, j, smtp) for j in jobs))
    if full:
        _seen.marks, _seen.full_at = marks, time.monotonic()
    return {j.name: n for j, n in zip(jobs, counts, strict=True) if n}


EXAMPLE = Story(
    "00000000-0000-4000-8000-000000000001",
    "Example: critical vulnerability in Example Gateway (CVE-2026-0001)",
    "This is an example story. It shows how a story arrives in this channel.",
    "https://news.example.com/",
    "critical",
    "Example",
    datetime(2026, 1, 1, tzinfo=UTC),
    ["CVE-2026-0001"],
    product="Example Gateway < 2.4.1",
    topics=["exploited"],
    source_kind="press",
)


async def send_test(db: AsyncSession, ch: NotifyChannel, lang: str = "de") -> None:
    """A test message with the newest story (or an example) – marks nothing as sent. When it went out, the channel works:
    an old error is cleared and a pause ends (what waits for the retry goes out in the next round)."""
    row = (await db.execute(select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).order_by(NewsItem.published_at.desc()).limit(1))).first()
    story = _story(row[0], row[1]) if row else EXAMPLE
    if row:
        await with_products(db, [story])
    smtp = await settings_store.get(db, "smtp") if ch.type == "email" else None
    who = {"channel_id": ch.id, "channel_name": ch.name, "channel_type": ch.type}
    started = time.monotonic()
    t: Target | None = None
    err: NotifyError | None = None
    try:
        t = resolve(ch)
        await dbm.release(db)  # nothing open while the channel is asked
        async with asyncio.timeout(CHANNEL_DEADLINE):
            await deliver(t, [story], 1, lang, ch.name, rules=[], smtp=smtp, test=True)
    except TimeoutError as exc:
        err = NotifyError("timeout")
        raise err from exc
    except NotifyError as exc:
        err = exc
        raise
    except Exception as exc:
        err = NotifyError("connection", type(exc).__name__)
        raise
    finally:
        item = {"kind": "example" if story is EXAMPLE else story.kind, "id": story.id, "title": story.title, "severity": story.severity}
        await delivery_log.record(db, kind="test", ref=uuid.uuid4().hex, items=[item], total=1, lang=lang, error=err, secrets=t.secrets() if t else (), started=started, **who)
    if ch.last_error or ch.next_try_at or ch.failures:
        await db.execute(
            update(NotifyChannel).where(NotifyChannel.id == ch.id).values(failures=0, next_try_at=None, last_error=None, last_error_at=None).execution_options(synchronize_session=False)
        )
        await db.commit()
        changed()


# ---------------------------------------------------------------- resend (the delivery log's "Erneut senden")


class Gone(Exception):
    """Nothing of the delivery can be sent again: `reason` already_delivered (everything reached the channel since) or
    gone (its stories / events no longer exist)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _refs(refs: list) -> list[tuple[str, uuid.UUID, uuid.UUID | None]]:
    out = []
    for x in refs or []:
        try:
            kind, item, rule = str(x).split(":", 2)
            out.append((kind, uuid.UUID(item), uuid.UUID(rule) if rule and rule != "None" else None))
        except ValueError:
            continue
    return out


async def resend(db: AsyncSession, ch: NotifyChannel, row, actor=None) -> NotifyError | None:  # noqa: ANN001 - a DeliveryLog row, the admin
    """A rule's delivery sent again by hand: the same stories / events (those of it the channel has not got meanwhile and
    that still exist) as one message to the same channel, through the same sending (egress checks, the pinned
    connection; a webhook gets the same delivery id when it is the same message). The channel's pause does not apply
    (it is asked now, by an admin); quiet hours never apply to channels. Recorded as the delivery's next attempt
    (manual). Sent: marked as sent – the round never sends it again – and the channel's error and pause end, as after a
    test. Failed: the channel's pause and error stay as the round left them. Gone(reason) when nothing is left.
    `actor`: the admin who asked – delivery.resent in the audit log, committed with the attempt's entry."""
    refs = _refs(row.refs)
    by_kind: dict[str, list[uuid.UUID]] = {}
    for kind, item, _ in refs:
        by_kind.setdefault(kind, []).append(item)
    sent_tables = {"news": (NotifyDelivery, NotifyDelivery.item_id), "vendor": (VendorDelivery, VendorDelivery.event_id), "health": (SourceHealthDelivery, SourceHealthDelivery.event_id)}
    done: set[tuple[str, uuid.UUID]] = set()
    for kind, ids in by_kind.items():
        if kind in sent_tables:
            table, col = sent_tables[kind]
            done |= {(kind, x) for x in await db.scalars(select(col).where(table.channel_id == ch.id, col.in_(ids)))}
    left = [(k, i, r) for k, i, r in refs if (k, i) not in done]
    if not left:
        raise Gone("already_delivered")
    lang = row.lang if row.lang in LABELS else "de"
    found: dict[tuple[str, uuid.UUID], Story] = {}
    ids = [i for k, i, _ in left if k == "news"]
    if ids:
        for i, src in (await db.execute(select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(NewsItem.id.in_(ids)))).all():
            found[("news", i.id)] = _story(i, src)
    ids = [i for k, i, _ in left if k == "vendor"]
    if ids:
        for ev in await db.scalars(select(VendorEvent).where(VendorEvent.id.in_(ids))):
            found[("vendor", ev.id)] = vendor_story(ev, lang)
    ids = [i for k, i, _ in left if k == "health"]
    if ids:
        for hv in await db.scalars(select(SourceHealthEvent).where(SourceHealthEvent.id.in_(ids))):
            found[("health", hv.id)] = health_story(hv, lang)
    stories = [(found[(k, i)], k, r) for k, i, r in left if (k, i) in found]
    if not stories:
        raise Gone("gone")
    # the rules of the delivery: their union decides what counts as "eure Produkte" (as in the round)
    rids = []
    for r in row.rules or []:
        try:
            rids.append(uuid.UUID(str(r.get("id"))))
        except (ValueError, AttributeError):
            continue
    scopes = await rule_scopes(db, rids)
    whole = scope_of(rids, scopes) if rids else None
    await with_products(db, [x[0] for x in stories], {x[0].id: whole for x in stories} if whole is not None else None)
    m = summary(stories, lang, list(row.rules or []))
    smtp = await settings_store.get(db, "smtp") if ch.type == "email" else None
    who = {"channel_id": ch.id, "channel_name": ch.name, "channel_type": ch.type}
    started = time.monotonic()
    t: Target | None = None
    err: NotifyError | None = None
    try:
        t = resolve(ch)
        await dbm.release(db)  # nothing open while the channel is asked
        async with asyncio.timeout(CHANNEL_DEADLINE):
            await deliver(t, m.stories, m.total, m.lang, m.label, rules=m.rules, smtp=smtp, key=m.key, rule_ids=[str(r.get("id") or "") for r in m.by])
    except NotifyError as exc:
        err = exc
    except TimeoutError:
        err = NotifyError("timeout")
    except Exception as exc:  # noqa: BLE001 - recorded like any failed attempt
        log.warning("notify resend %s: %s", ch.id, type(exc).__name__)
        err = NotifyError("connection", type(exc).__name__)
    info = {**m.log(), "ref": row.ref}  # an attempt of the same delivery (also when fewer of its stories are left)
    if err is None:
        gate = asyncio.Lock()
        await _write(db, gate, f"sent marks of channel {ch.id}", *_marked(ch.id, m.items, datetime.now(UTC)))
        await _write(
            db,
            gate,
            f"state of channel {ch.id}",
            update(NotifyChannel).where(NotifyChannel.id == ch.id).values(failures=0, next_try_at=None, last_error=None, last_error_at=None).execution_options(synchronize_session=False),
        )
        changed()
    if actor is not None:
        audit.record(db, actor, "delivery.resent", audit.target("channel", ch.id, ch.name), {"ref": row.ref, "ok": err is None, **({"error": err.category} if err else {})})
    await delivery_log.record(db, kind="rule", error=err, secrets=t.secrets() if t else (), started=started, manual=True, **who, **info)
    return err


# ---------------------------------------------------------------- the dry run of a rule ("Probelauf")

DRY_DAYS = (1, 7, 30)
DRY_LIMIT = 200  # matches listed (all are counted)
DRY_TIMEOUT_MS = 5000  # each query of a dry run – it never holds the database for long
FLOOD_PER_DAY = 20  # messages a day from which the dry run warns: the channel would be flooded


def _bucket(d: datetime) -> datetime:
    return d.astimezone(UTC).replace(second=0, microsecond=0)


async def dry_run(db: AsyncSession, rule: NotifyRule, teams: list[uuid.UUID], days: int, now: datetime | None = None) -> dict:
    """What `rule` (a rule as it is being edited – not stored) would have brought in the last `days` days: the stored
    stories, Vendor News events and source health changes it matches – by the same filters as the live round
    (news_filter, vendor_filter, health_filter), as if a channel had been linked to it all along. Nothing is sent and
    nothing written: one read-only transaction (statement timeout DRY_TIMEOUT_MS), rolled back.

    The messages a day are estimated as the round sends them: what arrives within the same minute comes in one round –
    up to BATCH as single messages, more as one summary."""
    now = now or datetime.now(UTC)
    since = now - timedelta(days=days)
    lang = rule.lang if rule.lang in LABELS else "de"
    restricted = {"severity": bool(rule.severities), "source": bool(rule.sources), "topic": bool(rule_topics(rule)), "teams": bool(teams)}
    wanted = set(rule_topics(rule))
    items: list[dict] = []
    buckets: dict[datetime, int] = {}
    total = 0
    await db.commit()  # whatever the request's session holds (the sign-in's own writes) – then a read-only transaction
    try:
        await db.execute(text("SET TRANSACTION READ ONLY"))
        await db.execute(text(f"SET LOCAL statement_timeout = {int(DRY_TIMEOUT_MS)}"))
        minute = func.date_trunc("minute", NewsItem.fetched_at)
        if "news" in rule_kinds(rule):
            where = [NewsItem.fetched_at > since, NewsItem.fetched_at <= now, *news_filter(rule)]
            counted = select(minute, func.count()).select_from(NewsItem).join(NewsSource, NewsSource.id == NewsItem.source_id)  # visible() expects the own source joined
            for b, n in (await db.execute(counted.where(*where).group_by(minute))).all():
                buckets[_bucket(b)] = buckets.get(_bucket(b), 0) + int(n)
                total += int(n)
            stmt = select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where).order_by(NewsItem.fetched_at.desc()).limit(DRY_LIMIT)
            for i, src in (await db.execute(stmt)).all():
                # the topics it matched by (the rule's that the story has) – shown as "Thema: …"
                hit = [t for t in news_svc.TOPICS if t in wanted and t in (i.topics or [])]
                items.append(
                    {"kind": "news", "id": str(i.id), "title": i.title, "severity": i.severity, "at": i.fetched_at.isoformat(), "source": src.name, "topics": hit, "match": {"kind": "news", **restricted, "teams": False}}
                )
        match = vendor_filter(rule, list(teams))
        if match is not None:
            where = [VendorEvent.created_at > since, VendorEvent.created_at <= now, *match]
            vminute = func.date_trunc("minute", VendorEvent.created_at)
            for b, n in (await db.execute(select(vminute, func.count()).where(*where).group_by(vminute))).all():
                buckets[_bucket(b)] = buckets.get(_bucket(b), 0) + int(n)
                total += int(n)
            for ev in await db.scalars(select(VendorEvent).where(*where).order_by(VendorEvent.created_at.desc()).limit(DRY_LIMIT)):
                st = vendor_story(ev, lang)
                kind = {"vuln": "vendor_vuln", "change": "vendor_change"}.get(ev.kind, "vendor_version")
                severity_counts = ev.kind in SEVERITY_KINDS and restricted["severity"]
                items.append(
                    {
                        "kind": kind,
                        "id": str(ev.id),
                        "title": st.title,
                        "severity": ev.severity,
                        "at": ev.created_at.isoformat(),
                        "source": st.source,
                        "match": {"kind": kind, "severity": severity_counts, "source": False, "topic": False, "teams": restricted["teams"]},
                    }
                )
        match = health_filter(rule)
        if match is not None:
            where = [SourceHealthEvent.created_at > since, SourceHealthEvent.created_at <= now, *match]
            hminute = func.date_trunc("minute", SourceHealthEvent.created_at)
            for b, n in (await db.execute(select(hminute, func.count()).where(*where).group_by(hminute))).all():
                buckets[_bucket(b)] = buckets.get(_bucket(b), 0) + int(n)
                total += int(n)
            for hv in await db.scalars(select(SourceHealthEvent).where(*where).order_by(SourceHealthEvent.created_at.desc()).limit(DRY_LIMIT)):
                st = health_story(hv, lang)
                items.append({"kind": "source_health", "id": str(hv.id), "title": st.title, "severity": st.severity, "at": hv.created_at.isoformat(), "source": st.source, "match": {"kind": "source_health", "severity": False, "source": False, "topic": False, "teams": False}})
    finally:
        await db.rollback()
    per_day: dict[str, dict] = {}
    for b, n in buckets.items():
        d = per_day.setdefault(b.date().isoformat(), {"day": b.date().isoformat(), "matches": 0, "messages": 0})
        d["matches"] += n
        d["messages"] += n if n <= BATCH else 1
    days_out = sorted(per_day.values(), key=lambda x: x["day"])
    peak = max((d["messages"] for d in days_out), default=0)
    items.sort(key=lambda x: x["at"], reverse=True)
    return {
        "days": days,
        "since": since.isoformat(),
        "count": total,
        "items": items[:DRY_LIMIT],
        "truncated": total > min(len(items), DRY_LIMIT),
        "per_day": days_out,
        "messages": sum(d["messages"] for d in days_out),
        "peak_per_day": peak,
        "flood": peak > FLOOD_PER_DAY,
        "flood_limit": FLOOD_PER_DAY,
    }
