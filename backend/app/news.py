"""Security news: RSS/Atom feeds of news sites, authorities, vendors' PSIRTs and
researchers (heise, BSI, CERT.at, Cisco …), two JSON catalogs of exploited vulnerabilities (CISA KEV, ENISA EUVD – one
story per entry) and Microsoft's Patchday index (MSRC CVRF – one story per release).

The background loop fetches one feed after the other – each host at most every HOST_GAP_S seconds, with conditional requests
(ETag / If-Modified-Since → 304) and growing pauses after refusals (429/503 with Retry-After). Downloads are https
only, never to internal addresses (app/netaddr.py), capped in size and time. XML with a DTD or
entities is refused (no entity expansion).

Every story is stored once: a normalised URL (host without www, no tracking parameters, no fragment) is unique, and
the same normalised title from another source within TITLE_WINDOW counts as the same story – the second source is only
added to `also_in` (and news_item_sources: the story counts for it too); between the vulnerability sources the same CVE does as
well. Within one source a different URL is a different story (CISA posts "… Adds Two Known Exploited Vulnerabilities
…" every few days). A known URL whose title or text changed ("[UPDATE] …") is updated: re-rated (the severity only
rises) and its CVEs merged. The severity comes from rules (CVSS in the text, the publisher's rating, "actively
exploited", ransomware …) with the reasons kept; catalog entries rate themselves (exploited: at least high).

What arrives as backlog (older than BACKLOG_DAYS when fetched – a date without a time counts to the end of that day –,
or without a date in a source's first fetch) is listed but never notified: `backlog` is decided once, when the story is
stored, and the rules, the tab's desktop notifications and Web Push all go by it.
"""

import asyncio
import hashlib
import html
import json
import logging
import re
import ssl
import time
import unicodedata
import uuid
import xml.etree.ElementTree as ET
from xml.parsers import expat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import NamedTuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import httpx
import nh3
from sqlalchemy import Text, and_, case, delete, func, literal_column, or_, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import array as pg_array
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app import bounded
from app import __version__, db as dbm
from app.db import fold
from app.config import get_config, tls_verify
from app import settings as settings_store
from app import source_health
from app.models import Counter, NewsItem, NewsItemSource, NewsSource, StoryDetail, VendorAdvisory, VendorKev
from app.netaddr import forbidden_literal, forbidden_target, pinned_transport

log = logging.getLogger("cobe_news.news")

DEFAULTS = settings_store.DEFAULTS["news"]  # off until switched on

class Builtin(NamedTuple):
    key: str
    name: str
    url: str  # the feed (RSS/Atom) or JSON catalog
    site: str  # home page – where the logo comes from
    on: bool  # switched on in a new installation (and when the key is new to an existing one)
    lang: str  # de | en | fr
    category: str  # authority | vendor | research | press | catalog – the groups in the settings


BUILTIN: list[Builtin] = [
    Builtin("heise", "heise online", "https://www.heise.de/rss/heise-atom.xml", "https://www.heise.de", True, "de", "press"),
    Builtin("heise-security", "heise Security", "https://www.heise.de/security/rss/news-atom.xml", "https://www.heise.de", True, "de", "press"),
    Builtin("thehackernews", "The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "https://thehackernews.com", True, "en", "press"),
    Builtin("golem-security", "golem.de Security", "https://rss.golem.de/rss.php?tp=sec&feed=ATOM1.0", "https://www.golem.de", True, "de", "press"),
    Builtin("bleepingcomputer", "BleepingComputer", "https://www.bleepingcomputer.com/feed/", "https://www.bleepingcomputer.com", True, "en", "press"),
    # off since 0.1.7: www.cisa.gov refuses automatic fetches from many networks (403, bot protection) – see DEFAULT_CHANGED
    Builtin("cisa", "CISA Alerts", "https://www.cisa.gov/cybersecurity-advisories/alerts.xml", "https://www.cisa.gov", False, "en", "authority"),
    Builtin(
        "bsi-csw",
        "BSI Cyber-Sicherheitswarnungen",
        "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_CSW.xml",
        "https://www.bsi.bund.de",
        True,
        "de",
        "authority",
    ),
    Builtin(
        "cert-eu",
        "CERT-EU Security Advisories",
        "https://cert.europa.eu/publications/security-advisories-rss",
        "https://cert.europa.eu",
        True,
        "en",
        "authority",
    ),
    Builtin(
        "microsoft-ti",
        "Microsoft Threat Intelligence",
        "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
        "https://www.microsoft.com",
        True,
        "en",
        "research",
    ),
    Builtin("talos", "Cisco Talos", "https://blog.talosintelligence.com/rss/", "https://blog.talosintelligence.com", True, "en", "research"),
    # JSON, not a feed: every entry of the catalog is a story (parse_catalog)
    Builtin(
        "cisa-kev",
        "CISA KEV",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",  # = KEV_URL
        "https://www.cisa.gov",
        True,
        "en",
        "catalog",
    ),
    # many advisories a day – off until somebody wants them
    Builtin(
        "cert-bund", "BSI CERT-Bund (WID)", "https://wid.cert-bund.de/content/public/securityAdvisory/rss", "https://wid.cert-bund.de", False, "de", "authority"
    ),
    Builtin(
        "bsi-presse",
        "BSI Presse",
        "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_Presse_Veranstaltungen.xml",
        "https://www.bsi.bund.de",
        False,
        "de",
        "authority",
    ),
    Builtin("ncsc-uk", "NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "https://www.ncsc.gov.uk", False, "en", "authority"),
    # vendors' own advisories (PSIRT): exact, but only about their products
    Builtin("fortinet-psirt", "Fortinet PSIRT", "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "https://www.fortiguard.com", False, "en", "vendor"),
    Builtin(
        "paloalto-psirt",
        "Palo Alto Networks PSIRT",
        "https://security.paloaltonetworks.com/rss.xml",
        "https://security.paloaltonetworks.com",
        False,
        "en",
        "vendor",
    ),
    Builtin(
        "cisco-psirt",
        "Cisco PSIRT",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "https://www.cisco.com",
        False,
        "en",
        "vendor",
    ),
    Builtin(
        "ivanti", "Ivanti Security Advisories", "https://www.ivanti.com/blog/topics/security-advisory/rss", "https://www.ivanti.com", False, "en", "vendor"
    ),
    # the whole history (2.1 MB, oldest entries from 2018) – the newest are taken (parse_feed sorts by date)
    Builtin(
        "siemens-productcert",
        "Siemens ProductCERT",
        "https://cert-portal.siemens.com/productcert/rss/advisories.atom",
        "https://cert-portal.siemens.com",
        False,
        "en",
        "vendor",
    ),
    Builtin("unit42", "Unit 42", "https://unit42.paloaltonetworks.com/feed/", "https://unit42.paloaltonetworks.com", False, "en", "research"),
    Builtin(
        "google-ti",
        "Google Threat Intelligence (Mandiant)",
        "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
        "https://cloud.google.com",
        False,
        "en",
        "research",
    ),
    Builtin("securelist", "Kaspersky Securelist", "https://securelist.com/feed/", "https://securelist.com", False, "en", "research"),
    Builtin("eset", "ESET WeLiveSecurity", "https://feeds.feedburner.com/eset/blog", "https://www.welivesecurity.com", False, "en", "research"),
    Builtin("checkpoint-research", "Check Point Research", "https://research.checkpoint.com/feed/", "https://research.checkpoint.com", False, "en", "research"),
    Builtin(
        "zdi", "Zero Day Initiative (ZDI)", "https://www.zerodayinitiative.com/rss/published/", "https://www.zerodayinitiative.com", False, "en", "research"
    ),
    Builtin("sans-isc", "SANS Internet Storm Center", "https://isc.sans.edu/rssfeed.xml", "https://isc.sans.edu", False, "en", "research"),
    Builtin("securityweek", "SecurityWeek", "https://www.securityweek.com/feed/", "https://www.securityweek.com", False, "en", "press"),
    Builtin("krebs", "Krebs on Security", "https://krebsonsecurity.com/feed/", "https://krebsonsecurity.com", False, "en", "press"),
    Builtin("darkreading", "Dark Reading", "https://www.darkreading.com/rss.xml", "https://www.darkreading.com", False, "en", "press"),
    Builtin("therecord", "The Record", "https://therecord.media/feed/", "https://therecord.media", False, "en", "press"),
    Builtin("borncity", "Borns IT- und Windows-Blog", "https://www.borncity.com/blog/feed/", "https://www.borncity.com", False, "de", "press"),
    Builtin("security-insider", "Security-Insider", "https://www.security-insider.de/rss/news.xml", "https://www.security-insider.de", False, "de", "press"),
    Builtin("t3n-security", "t3n Security", "https://t3n.de/tag/security/rss.xml", "https://t3n.de", False, "de", "press"),
    # exploited vulnerabilities as ENISA sees them – mostly the same CVEs as the KEV (then only "also in")
    Builtin(
        "enisa-euvd",
        "ENISA EUVD",
        "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities",
        "https://euvd.enisa.europa.eu",
        False,
        "en",
        "catalog",
    ),
    # added 0.1.7: authorities, OT vendors and research for industrial (OT) environments
    Builtin("cert-at", "CERT.at Warnungen", "https://www.cert.at/cert-at.de.warnings.rss_2.0.xml", "https://www.cert.at", True, "de", "authority"),
    Builtin("certvde", "CERT@VDE (OT-Hersteller)", "https://certvde.com/en/advisories/feeds/rss/", "https://certvde.com", True, "en", "vendor"),
    Builtin(
        "securityweek-ics", "SecurityWeek ICS/OT", "https://www.securityweek.com/category/ics-ot/feed/", "https://www.securityweek.com", True, "en", "press"
    ),
    Builtin("veeam", "Veeam Security", "https://www.veeam.com/services/open/kb/security-feed", "https://www.veeam.com", True, "en", "vendor"),
    Builtin(
        "cccs",
        "Canadian Centre for Cyber Security",
        "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en",
        "https://www.cyber.gc.ca",
        False,
        "en",
        "authority",
    ),
    Builtin("cert-fr", "CERT-FR Alertes", "https://cert.cyber.gouv.fr/alerte/feed/", "https://cert.cyber.gouv.fr", False, "fr", "authority"),
    Builtin("watchtowr", "watchTowr Labs", "https://labs.watchtowr.com/rss/", "https://labs.watchtowr.com", False, "en", "research"),
    Builtin("huntress", "Huntress", "https://www.huntress.com/blog/rss.xml", "https://www.huntress.com", False, "en", "research"),
    Builtin(
        "rockwell",
        "Rockwell Automation",
        "https://www.rockwellautomation.com/bin/rss/security-advisories.xml",
        "https://www.rockwellautomation.com",
        False,
        "en",
        "vendor",
    ),
    Builtin(
        "oracle",
        "Oracle Security Alerts",
        "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml",
        "https://www.oracle.com",
        False,
        "en",
        "vendor",
    ),
    Builtin("risky-bulletin", "Risky Bulletin", "https://news.risky.biz/rss/", "https://risky.biz", False, "en", "press"),
    # JSON: Microsoft's CVRF release index – one story per Patchday (parse_catalog)
    Builtin("msrc", "Microsoft Patchday (MSRC)", "https://api.msrc.microsoft.com/cvrf/v3.0/updates", "https://msrc.microsoft.com", False, "en", "catalog"),
]
BUILTIN_BY_KEY = {b.key: b for b in BUILTIN}
# built-in sources whose default changed in an update: where no admin ever switched them (switched_at None – nothing was
# recorded before 0.1.7, so that is every installation that never touched them since), they follow the new default.
# CISA Alerts (0.1.7: on → off): www.cisa.gov answers 403 to automatic fetches from many networks.
DEFAULT_CHANGED = ("cisa",)
# sources about single vulnerabilities: a story with the same CVE from another of them is the same story ("also in")
CVE_SOURCES = frozenset({"cisa-kev", "enisa-euvd", "bsi-csw"})
CVE_WINDOW = timedelta(days=30)

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_LOGO_BYTES = 100 * 1024
DOWNLOAD_S = 30.0
HOST_GAP_S = 60.0  # one request per host and minute at most (heise online and heise Security share a host)
MAX_ENTRIES = 200  # per fetch
MAX_BACKOFF = timedelta(hours=24)
# failures of the way there (DNS, TLS, refused, a timeout), not of the site: back soon, not after up to a day
TRANSIENT = frozenset({"connection", "timeout"})
TRANSIENT_BACKOFF = timedelta(hours=1)
TITLE_WINDOW = timedelta(days=3)
BACKLOG_DAYS = 1  # older than this when it arrived: no push or desktop notification (backlog of a new source)
LOGO_RETRY = timedelta(days=7)
SUMMARY_MAX = 600
CONTENT_MAX = 100_000
SEVERITIES = ("info", "low", "medium", "high", "critical")
USER_AGENT = f"Cobe/{__version__} (security news reader; self-hosted; Cobe News)"  # some feeds (CISA) refused "Cobe-News/…"
# query parameters that only track where a click came from – the same article with and without them is one
TRACKING = re.compile(r"^(utm_|wt_|mc_|pk_|fbclid$|gclid$|ref$|source$|from$|cmp$|xing_share$|seite$|view$|rss$)", re.I)


class NewsError(Exception):
    def __init__(self, category: str, detail: str = "", wait: timedelta | None = None):
        super().__init__(category)
        self.category = category
        self.detail = detail
        self.wait = wait  # Retry-After of a refusal


# ---------------------------------------------------------------- download


def _guard(proxy: str | None, resolve: bool = True, only=None):  # noqa: ANN001
    """Every request, redirects included: https only, never this server itself, the internal network or a metadata
    service; with `only` (a check of the URL) also never off the hosts it allows – a CSAF provider's redirect stays on
    its domain. (`resolve` False: a test transport – no DNS lookups in tests.)"""

    async def guard(request: httpx.Request) -> None:
        if request.url.scheme != "https":
            raise NewsError("http", "redirect to non-https")
        if only is not None and not only(str(request.url)):
            raise NewsError("http", "redirect off the allowed hosts")
        if forbidden_literal(str(request.url)) or (resolve and not proxy and await asyncio.to_thread(forbidden_target, str(request.url))):
            raise NewsError("http", "forbidden target")

    return guard


@dataclass
class Fetched:
    status: int
    headers: httpx.Headers
    body: bytes


async def download(
    url: str,
    *,
    proxy: str | None,
    verify: ssl.SSLContext | bool = True,
    headers: dict | None = None,
    limit: int = MAX_FEED_BYTES,
    transport: httpx.AsyncBaseTransport | None = None,
    follow_redirects: bool = True,
    only=None,  # noqa: ANN001 - a check every request (redirects included) must pass, see _guard
    timeout: float | None = None,
) -> Fetched:
    """One GET (redirects included unless `follow_redirects` is off), measured for the source health (source_health.measure:
    time, size, status). `timeout`: seconds for the whole download (default DOWNLOAD_S – a big file asks for more)."""
    t0 = time.monotonic()
    got: Fetched | None = None
    try:
        got = await _download(url, proxy=proxy, verify=verify, headers=headers, limit=limit, transport=transport, follow_redirects=follow_redirects, only=only, timeout=timeout)
        return got
    finally:
        source_health.measure(time.monotonic() - t0, got.status if got else None, len(got.body) if got else 0)


async def _download(
    url: str,
    *,
    proxy: str | None,
    verify: ssl.SSLContext | bool,
    headers: dict | None,
    limit: int,
    transport: httpx.AsyncBaseTransport | None,
    follow_redirects: bool = True,
    only=None,  # noqa: ANN001
    timeout: float | None = None,
) -> Fetched:
    if transport is None and not proxy and await asyncio.to_thread(forbidden_target, url):
        raise NewsError("http", "forbidden target")
    try:
        async with (
            asyncio.timeout(timeout or DOWNLOAD_S),
            httpx.AsyncClient(
                timeout=httpx.Timeout(20.0, connect=10.0),
                proxy=proxy,
                transport=transport or (None if proxy else pinned_transport(verify)),
                follow_redirects=follow_redirects,
                max_redirects=3,
                event_hooks={"request": [_guard(proxy, resolve=transport is None, only=only)]},
                trust_env=False,
                verify=verify,
            ) as c,
            c.stream("GET", url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": bounded.ACCEPT_ENCODING, **(headers or {})}) as resp,
        ):
            body = b""
            if resp.status_code < 300:
                # raw bytes, inflated by our own decompressor with a cap – the limit holds after decompression too
                try:
                    body = await bounded.read_limited(resp, limit)
                except bounded.TooLarge as exc:
                    raise NewsError("too_large", f"> {limit // 1024} KB") from exc
                except bounded.BadEncoding as exc:
                    raise NewsError("parse", f"content-encoding {exc}") from exc
            return Fetched(resp.status_code, resp.headers, body)
    except NewsError:
        raise
    except (TimeoutError, httpx.TimeoutException) as exc:  # httpx's read/connect/pool timeouts are no TimeoutError
        raise NewsError("timeout", type(exc).__name__ if isinstance(exc, httpx.TimeoutException) else "") from exc
    except Exception as exc:  # noqa: BLE001 - DNS, TLS, refused …: one source, not the run
        raise NewsError("connection", type(exc).__name__) from exc


# CISA's KEV: one download feeds both – the news source "cisa-kev" (one story per entry, the newest MAX_ENTRIES) and
# Vendor News' whole catalogue (vendor_kev, vendor.kev_received). www.cisa.gov refuses automatic fetches from many
# networks (403, bot protection): then the same JSON from CISA's official mirror on GitHub (cisagov/kev-data, updated by
# CISA with the catalogue), through the same guard (https only, no internal addresses, size cap).
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
KEV_LIMIT = 2 * MAX_FEED_BYTES  # the whole catalogue (1.5 MB in 2026, growing)


async def kev_mirror(headers: dict | None, *, proxy: str | None, verify: ssl.SSLContext | bool, transport=None) -> Fetched:  # noqa: ANN001
    """The KEV from CISA's mirror (after a 403 of www.cisa.gov) – the same conditional request."""
    host = urlsplit(KEV_MIRROR).hostname or ""
    _host_last[host] = time.monotonic()
    log.info("news cisa-kev: www.cisa.gov refused (403) – the catalogue from CISA's mirror on GitHub")
    return await download(KEV_MIRROR, proxy=proxy, verify=verify, headers=headers, transport=transport, limit=KEV_LIMIT)


async def _kev_filled(db: AsyncSession) -> bool:
    return await db.scalar(select(VendorKev.cve).limit(1)) is not None


async def _kev_checked(db: AsyncSession) -> None:
    """The KEV fetch of the news answered "unchanged": Vendor News' catalogue is current – its own fetch waits."""
    from app import vendor

    await vendor.kev_checked(db)


def http_error(status: int) -> NewsError:
    """An error answer of the site. 403: the site refuses automatic fetches (bot protection – www.cisa.gov from many
    networks) – its own category, shown as such in the settings; Cobe News does not work around it (no other user agent,
    no browser headers)."""
    return NewsError("blocked" if status == 403 else "http", f"HTTP {status}")


# ---------------------------------------------------------------- parsing

ATOM = "{http://www.w3.org/2005/Atom}"
CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"
DC_DATE = "{http://purl.org/dc/elements/1.1/}date"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _child(el: ET.Element, *names: str) -> ET.Element | None:
    for c in el:
        if _local(c.tag) in names or c.tag in names:
            return c
    return None


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


# RFC 822 dates in German ("Di, 27 Okt 2026 10:00:00 MEZ") and zone names the email parser does not know (it would
# take them as UTC): mapped to what it reads. "CST" stays what RFC 822 says (US Central, -0600) – China Standard Time
# writes the same letters, but no built-in feed is from there and an own feed with it is off by hours, not days.
_DE_NAMES = {
    **dict.fromkeys(("mo", "montag"), "Mon"),
    **dict.fromkeys(("di", "dienstag"), "Tue"),
    **dict.fromkeys(("mi", "mittwoch"), "Wed"),
    **dict.fromkeys(("do", "donnerstag"), "Thu"),
    **dict.fromkeys(("fr", "freitag"), "Fri"),
    **dict.fromkeys(("sa", "samstag", "sonnabend"), "Sat"),
    **dict.fromkeys(("so", "sonntag"), "Sun"),
    **dict.fromkeys(("januar", "jän", "jänner"), "Jan"),
    "februar": "Feb",
    **dict.fromkeys(("mär", "märz", "mrz", "maerz"), "Mar"),
    "april": "Apr",
    "mai": "May",
    "juni": "Jun",
    "juli": "Jul",
    "august": "Aug",
    **dict.fromkeys(("sept", "september"), "Sep"),
    **dict.fromkeys(("okt", "oktober"), "Oct"),
    "november": "Nov",
    **dict.fromkeys(("dez", "dezember"), "Dec"),
}
_ZONES = {"CET": "+0100", "MEZ": "+0100", "CEST": "+0200", "MESZ": "+0200", "WET": "+0000", "WEST": "+0100", "BST": "+0100", "EET": "+0200", "EEST": "+0300"}


def _rfc822_names(v: str) -> str:
    def one(m: re.Match) -> str:
        word = m.group(0)
        return _ZONES.get(word) or _DE_NAMES.get(word.rstrip(".").casefold(), word)

    return re.sub(r"[^\W\d_]+\.?", one, v)


def _date(value: str) -> datetime | None:
    v = (value or "").strip()[:200]  # a date is short – a giant one is no date (and no work for the parsers)
    if not v:
        return None
    if not re.match(r"\d{4}-\d\d", v):  # not ISO: maybe German names or a zone abbreviation
        v = _rfc822_names(v)
    try:
        d = parsedate_to_datetime(v)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    try:
        d = (d if d.tzinfo else d.replace(tzinfo=UTC)).astimezone(UTC)
    except (OverflowError, ValueError):
        return None
    # year 0001 (.NET's DateTime.MinValue) or 9999: no date – arithmetic around it would overflow
    return d if 1990 <= d.year <= 2100 else None


def _refuse_dtd(data: bytes) -> None:
    """A DTD can declare entities that expand a small feed to gigabytes – refused by the XML parser itself, in any
    encoding and wherever it stands (a byte search misses UTF-16 or a DTD after a long comment)."""

    def no(*_a) -> None:
        raise NewsError("format", "DTD/entities not accepted")

    p = expat.ParserCreate()
    p.StartDoctypeDeclHandler = no
    p.EntityDeclHandler = no
    try:
        p.Parse(data, True)
    except expat.ExpatError as exc:
        raise NewsError("format", f"no XML: {str(exc)[:80]}") from exc
    except (LookupError, ValueError) as exc:  # an encoding the parser does not know
        raise NewsError("format", f"no XML: {str(exc)[:80]}") from exc


def _newest(dated: list[tuple[datetime | None, ET.Element]]) -> list[tuple[datetime | None, ET.Element]]:
    """The newest MAX_ENTRIES – a feed may carry its whole history, oldest first (Siemens: 2474 advisories since 2018).
    Entries without a date keep their place behind the dated ones (stable sort)."""
    floor = datetime.min.replace(tzinfo=UTC)
    return sorted(dated, key=lambda x: x[0] or floor, reverse=True)[:MAX_ENTRIES]


def parse_feed(data: bytes) -> tuple[list[dict], dict]:
    """(entries, feed facts) of an RSS 2.0, RSS 1.0/RDF or Atom feed: link, title, summary (HTML), content (HTML), date –
    newest first. A JSON body is a vulnerability catalog (CISA KEV, ENISA EUVD): see parse_catalog."""
    if data[:64].lstrip(b"\xef\xbb\xbf \t\r\n")[:1] in (b"{", b"["):
        return parse_catalog(data), {"icon": ""}
    _refuse_dtd(data)
    try:
        root = ET.fromstring(data)  # noqa: S314 - DTDs and entities are refused above (no expansion, no external entities)
    except (ET.ParseError, LookupError, ValueError) as exc:
        raise NewsError("format", f"no XML: {str(exc)[:80]}") from exc
    kind = _local(root.tag).lower()
    meta: dict = {"icon": ""}
    entries: list[dict] = []
    if kind == "feed":  # Atom
        meta["icon"] = _text(_child(root, "icon")) or _text(_child(root, "logo"))
        dated = [(_date(_text(e.find(f"{ATOM}published")) or _text(e.find(f"{ATOM}updated"))), e) for e in root.findall(f"{ATOM}entry")]
        for date, e in _newest(dated):
            link = ""
            for ln in e.findall(f"{ATOM}link"):
                if ln.get("rel") in (None, "alternate") and ln.get("href"):
                    link = ln.get("href", "")
                    break
            content = e.find(f"{ATOM}content")
            entries.append(
                {
                    "link": link or _text(e.find(f"{ATOM}id")),
                    "title": _text(e.find(f"{ATOM}title")),
                    "summary": _text(e.find(f"{ATOM}summary")),
                    "content": _text(content) if content is not None else "",
                    "date": date,
                }
            )
    elif kind in ("rss", "rdf"):
        channel = _child(root, "channel")
        img = _child(channel, "image") if channel is not None else None
        meta["icon"] = _text(_child(img, "url")) if img is not None else ""
        items = channel.findall("item") if kind == "rss" and channel is not None else [c for c in root if _local(c.tag) == "item"]
        dated = [(_date(_text(_child(it, "pubDate")) or _text(it.find(DC_DATE)) or _text(_child(it, "date"))), it) for it in items]
        for date, it in _newest(dated):
            entries.append(
                {
                    "link": _text(_child(it, "link")) or _text(_child(it, "guid")),
                    "title": _text(_child(it, "title")),
                    "summary": _text(_child(it, "description")),
                    "content": _text(it.find(CONTENT)),
                    "date": date,
                }
            )
    else:
        raise NewsError("format", f"not a feed (<{kind}>)")
    return entries, meta


# ---------------------------------------------------------------- JSON catalogs of exploited vulnerabilities

NVD = "https://nvd.nist.gov/vuln/detail/"
EUVD_PAGE = "https://euvd.enisa.europa.eu/vulnerability/"
EUVD_ID = re.compile(r"EUVD-\d{4}-\d{1,9}")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")


def _s(value, limit: int = 2000) -> str:
    """A text field of the JSON – anything else (number, list, object, null) counts as empty."""
    return value.strip()[:limit] if isinstance(value, str) else ""


def _euvd_date(value) -> datetime | None:
    """EUVD writes "Oct 27, 2026, 12:00:00 AM" (Java's default format, sometimes with a narrow no-break space before
    AM/PM); ISO dates are taken as well."""
    v = re.sub(r"[  \s]+", " ", _s(value, 64))
    if not v:
        return None
    for fmt in ("%b %d, %Y, %I:%M:%S %p", "%b %d, %Y %I:%M:%S %p"):
        try:
            d = datetime.strptime(v, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
        return d if 1990 <= d.year <= 2100 else None
    return _date(v)


def _p(text: str) -> str:
    return f"<p>{html.escape(text)}</p>" if text else ""


def _li(label: str, text: str) -> str:
    return f"<li><strong>{html.escape(label)}:</strong> {html.escape(text)}</li>" if text else ""


def _kev(doc: dict) -> list[dict]:
    """CISA's catalog of known exploited vulnerabilities: one story per CVE, dated by when CISA added it."""
    out = []
    for v in doc["vulnerabilities"]:
        if not isinstance(v, dict) or not CVE_ID.fullmatch(cve := _s(v.get("cveID"), 32).upper()):
            continue
        vendor, product, name = _s(v.get("vendorProject"), 100), _s(v.get("product"), 150), _s(v.get("vulnerabilityName"), 300)
        what = f"{vendor} {product}".strip()
        # "Adobe Commerce Unrestricted Upload …" under "Adobe Commerce": the name without the repetition
        if what and name.casefold().startswith(what.casefold() + " "):
            name = name[len(what) :].strip()
        desc, action = _s(v.get("shortDescription")), _s(v.get("requiredAction"))
        due, ransomware = _s(v.get("dueDate"), 32), _s(v.get("knownRansomwareCampaignUse"), 32).casefold() == "known"
        reasons = [{"kind": "kev", "value": due}] + ([{"kind": "ransomware", "value": "CISA"}] if ransomware else [])
        out.append(
            {
                "link": NVD + cve,
                "title": html.escape(f"{cve} · {what}: {name}" if what else f"{cve}: {name}"),
                "summary": html.escape(f"{desc} Required action: {action}" if action else desc),
                "content": _p(desc)
                + "<ul>"
                + _li("Required action", action)
                + _li("Due date (US federal agencies)", due)
                + _li("Added to the catalog", _s(v.get("dateAdded"), 32))
                + _li("Known ransomware campaign use", _s(v.get("knownRansomwareCampaignUse"), 32))
                + "</ul>",
                "date": _date(_s(v.get("dateAdded"), 32)),
                "severity": "critical" if ransomware else "high",
                "reasons": reasons,
                "cves": [cve],
            }
        )
    return out


MSRC_NOTE = "https://msrc.microsoft.com/update-guide/releaseNote/"
MSRC_ID = re.compile(r"\d{4}-[A-Za-z]{3}(?:-[A-Za-z0-9]{1,4})?")  # 2026-Oct, 2018-FEB, 2017-May-B


def _msrc(items: list) -> list[dict]:
    """Microsoft's monthly security update releases (the CVRF index): one story per Patch Tuesday or out-of-band
    release – the low-noise way to follow Microsoft (the update guide feed has one entry per CVE, hundreds a month)."""
    out = []
    for v in items:
        if not isinstance(v, dict) or not MSRC_ID.fullmatch(rid := _s(v.get("ID"), 16)):
            continue
        title = " ".join(re.sub(r"<[^>]+>", " ", _s(v.get("DocumentTitle"), 200)).split()) or f"{rid} Security Updates"
        out.append(
            {
                "link": MSRC_NOTE + rid,
                "title": html.escape(f"Microsoft: {title}"),
                "summary": html.escape(f"Microsoft security update release {rid}."),
                "content": _p(f"Microsoft security update release {rid}.")
                + "<ul>"
                + _li("Released", _s(v.get("InitialReleaseDate"), 32))
                + _li("Last updated", _s(v.get("CurrentReleaseDate"), 32))
                + "</ul>",
                "date": _date(_s(v.get("InitialReleaseDate"), 32)),
                "severity": "high",
                "reasons": [{"kind": "vendor", "value": "Microsoft Patchday"}],
                "cves": [],
            }
        )
    return out


def _euvd_names(v: dict, field: str, inner: str) -> list[str]:
    """Vendor or product names: [{"vendor": {"name": "Adobe"}}, …] – at most three, each once."""
    got = v.get(field)
    if not isinstance(got, list):
        return []
    names = [_s(x[inner].get("name"), 100) for x in got[:20] if isinstance(x, dict) and isinstance(x.get(inner), dict)]
    return list(dict.fromkeys(n for n in names if n))[:3]


def _euvd(items: list) -> list[dict]:
    """ENISA's EU vulnerability database, the exploited ones: one story per EUVD id (its CVE, if any, for the dedupe).
    Exploited means at least high; a CVSS score of 9 or more critical."""
    out = []
    for v in items:
        if not isinstance(v, dict) or not EUVD_ID.fullmatch(eid := _s(v.get("id"), 32)):
            continue
        aliases = [a.strip() for a in _s(v.get("aliases"), 2000).splitlines() if a.strip()][:30]
        ids = sorted({a.upper() for a in aliases if CVE_ID.fullmatch(a.upper())})[:30]
        vendors, products = _euvd_names(v, "enisaIdVendor", "vendor"), _euvd_names(v, "enisaIdProduct", "product")
        what = " ".join([", ".join(vendors), ", ".join(products)]).strip()
        desc = _s(v.get("description"), 4000)
        score = v.get("baseScore")
        score = float(score) if isinstance(score, int | float) and not isinstance(score, bool) and 0 < score <= 10 else None
        exploited = _euvd_date(v.get("exploitedSince"))
        head = ids[0] if ids else eid
        refs = [r for r in _s(v.get("references"), 4000).split() if r.startswith("https://")][:10]
        reasons = [{"kind": "euvd", "value": exploited.date().isoformat() if exploited else ""}]
        if score is not None:
            reasons.append({"kind": "cvss", "value": f"{score:.1f}"})
        out.append(
            {
                "link": EUVD_PAGE + eid,
                "title": html.escape(f"{head} · {what}: {_short(desc, 140)}" if what else f"{head}: {_short(desc, 160)}"),
                "summary": html.escape(desc),
                "content": _p(desc)
                + "<ul>"
                + _li("EUVD", eid)
                + _li("Aliases", ", ".join(aliases))
                + _li("CVSS", f"{score:.1f} ({_s(v.get('baseScoreVector'), 200)})" if score is not None else "")
                + _li("EPSS", f"{v['epss']} %" if isinstance(v.get("epss"), int | float) else "")
                + _li("Exploited since", exploited.date().isoformat() if exploited else "")
                + "</ul>"
                + "".join(f'<p><a href="{html.escape(r)}">{html.escape(r)}</a></p>' for r in refs),
                "date": exploited or _euvd_date(v.get("datePublished")) or _euvd_date(v.get("dateUpdated")),
                "severity": "critical" if score is not None and score >= 9 else "high",
                "reasons": reasons,
                "cves": ids,
            }
        )
    return out


def parse_catalog(data: bytes) -> list[dict]:
    """A JSON catalog as entries (newest first, at most MAX_ENTRIES): the CISA KEV ({"vulnerabilities": [...]}), the
    Microsoft CVRF release index ({"value": [{"ID", "DocumentTitle", …}]}) or the ENISA EUVD ([...] or {"items": [...]}).
    Each entry brings its own severity, reasons and CVEs – the text rules do not apply."""
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError; nesting a thousand deep the other
        raise NewsError("format", f"no JSON: {str(exc)[:80]}") from exc
    if isinstance(doc, dict) and isinstance(doc.get("vulnerabilities"), list):
        entries = _kev(doc)
    elif isinstance(doc, dict) and isinstance(doc.get("value"), list):
        entries = _msrc(doc["value"])
        if doc["value"] and not entries:
            raise NewsError("format", "JSON, but no known vulnerability catalog")
    elif isinstance(doc, list) or (isinstance(doc, dict) and isinstance(doc.get("items"), list)):
        items = doc if isinstance(doc, list) else doc["items"]
        entries = _euvd(items)
        if items and not entries:
            raise NewsError("format", "JSON, but no known vulnerability catalog")
    else:
        raise NewsError("format", "JSON, but no known vulnerability catalog")
    floor = datetime.min.replace(tzinfo=UTC)
    return sorted(entries, key=lambda e: e["date"] or floor, reverse=True)[:MAX_ENTRIES]


# ---------------------------------------------------------------- one story: keys, text, severity


def normalize_url(url: str) -> str | None:
    """The URL that identifies a story: https/http alike, host without www, no tracking parameters, no fragment."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        return None
    host = p.hostname.lower().removeprefix("www.")
    path = re.sub(r"/{2,}", "/", p.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    query = urlencode(sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k)))
    return f"{host}{path}" + (f"?{query}" if query else "")


def _key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def title_key(title: str) -> str:
    """The title without case, accents and punctuation. Latin titles keep the key they always had (a-z, 0-9); a title
    with other letters (Cyrillic, Chinese, Greek …) keeps them – folded to a-z it would be empty (or only its CVE), and
    every such title would be "the same story"."""
    t = unicodedata.normalize("NFKD", title.casefold())  # casefold: ß → ss
    t = "".join(c for c in t if not unicodedata.combining(c))
    latin = re.sub(r"[^a-z0-9]+", " ", t).strip()
    every = re.sub(r"[\W_]+", " ", t).strip()
    if latin and latin.replace(" ", "") == every.replace(" ", ""):
        return _key(latin)
    return _key("u:" + (every or t.strip()))


TEXT_SRC_MAX = 200_000  # what one entry's HTML is read up to – the rest of a giant entry is not text anyone reads
# nh3 (html5ever) is quadratic in the nesting depth: 20 000 nested <ul><li> took 1.7 s per pass, a 5 MB feed of such
# entries minutes of CPU. Deeper (or more tags) than this: the text without any tags instead – linear, and no article
# that anyone reads nests like that.
NEST_MAX = 200
TAGS_MAX = 20_000
_TAG = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9:-]*)[^<>]*(>?)")  # [^<>]* stops at the next < or >: linear
_ANY_TAG = re.compile(r"<[^<>]*>?")
_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})
# closed by the next one of their kind (an unclosed <p> or <li> after another is no deeper): not counted
_SIBLING = frozenset({"p", "li", "dt", "dd", "option", "optgroup", "tr", "td", "th", "thead", "tbody", "tfoot", "rt", "rp"})
_BREAKS = re.compile(r"<br\s*/?>|</p>|</li>|</h\d>", re.I)
_SAFE_TAGS = {"p", "br", "ul", "ol", "li", "strong", "em", "b", "i", "a", "blockquote", "h2", "h3", "h4", "code", "pre"}
_EMPTY = re.compile(r"(<p>\s*</p>|<a[^<>]*>\s*</a>)")


def _tame(value: str) -> bool:
    """True when nh3 may read `value`: at most TAGS_MAX tags, nested at most NEST_MAX deep (one linear pass, a rough
    count – an unclosed <div> counts as open, which only errs towards the plain-text way)."""
    depth = tags = 0
    for m in _TAG.finditer(value):
        tags += 1
        if tags > TAGS_MAX:
            return False
        name = m.group(2).lower()
        if name in _VOID or name in _SIBLING:
            continue
        if m.group(1):
            depth = max(0, depth - 1)
        elif not m.group(0).rstrip(">").endswith("/"):
            depth += 1
            if depth > NEST_MAX:
                return False
    return True


def _plain(value: str) -> str:
    """Text without tags, linear (the fallback for HTML nh3 would take too long on)."""
    return html.unescape(_ANY_TAG.sub(" ", _BREAKS.sub("\n", value)))


def html_to_text(value: str) -> str:
    # linear: nh3 drops every tag and the content of script/style (a regex for that was quadratic on an unclosed tag)
    src = (value or "")[:TEXT_SRC_MAX]
    if _tame(src):
        text = html.unescape(nh3.clean(_BREAKS.sub("\n", src), tags=set()))
    else:
        text = _plain(src)
    return re.sub(r"[ \t\r\f\v]+", " ", re.sub(r"\n\s*\n+", "\n", text)).strip()


def _short(text: str, limit: int = SUMMARY_MAX) -> str:
    t = re.sub(r"\s+", " ", text).strip()
    if len(t) <= limit:
        return t
    cut = t[:limit]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    return (cut[: end + 1] if end > limit // 2 else cut.rsplit(" ", 1)[0]) + " …"


def _nh3(value: str) -> str:
    return nh3.clean(
        value,
        tags=_SAFE_TAGS,
        attributes={"a": {"href"}},
        url_schemes={"http", "https"},
        # only absolute links: a relative one ("/x", "//host/x") would lead inside Cobe News or to another site unseen
        attribute_filter=lambda tag, attr, value: value if attr != "href" or value.lower().startswith(("https://", "http://")) else None,
        set_tag_attribute_values={"a": {"target": "_blank"}},
        link_rel="noopener noreferrer nofollow",
        strip_comments=True,
    )


def _drop_empty(out: str) -> str:
    for _ in range(20):  # removing an empty link can leave an empty paragraph behind: until nothing changes
        nxt = _EMPTY.sub("", out)
        if nxt == out:
            break
        out = nxt
    return out


def _paragraphs(text: str) -> str:
    """Plain text as escaped paragraphs (up to CONTENT_MAX)."""
    out, size = [], 0
    for x in text.split("\n"):
        if x := re.sub(r"\s+", " ", x).strip():
            part = f"<p>{html.escape(x, quote=False)}</p>"
            if size + len(part) > CONTENT_MAX:
                break
            out.append(part)
            size += len(part)
    return "".join(out)


def clean_html(value: str) -> str:
    """The article text for the drawer: structure and links only – no images (nothing is loaded from other sites).
    Never ends inside a tag (a long text is cut, then cleaned again – which also closes what the cut left open), and
    cleaning its own output changes nothing: cleaned until it stays the same (mis-nested HTML can take a few rounds).
    HTML nh3 would take too long on – or that does not settle – comes back as escaped paragraphs of its text."""
    src = (value or "")[:TEXT_SRC_MAX]
    if _tame(src):
        out = _drop_empty(_nh3(src))[:CONTENT_MAX]
        for _ in range(6):
            nxt = _drop_empty(_nh3(out))
            if nxt == out:
                return out
            out = nxt
    return _paragraphs(_plain(src))


# hyphen, non-breaking hyphen (U+2011, Word and some CMS put it in), figure dash, en dash
CVE = re.compile(r"\bCVE[-\u2010\u2011\u2012\u2013](\d{4})[-\u2010\u2011\u2012\u2013](\d{4,7})\b", re.I)
# "CVSS 9.8", "CVSS-Score von 9.8", "CVSS-Basiswert 9,8", "CVSSv3.1 Base Score: 9.8", "CVSS 3.1 Basisscore 9,8" – the
# version (v3, 3.1, 4.0, "CVSS:3.1/AV:N/…") is skipped, never read as the score; atomic groups: once taken as a
# version, "CVSS 3.1 as medium" does not fall back to reading 3.1 as the score
CVSS = re.compile(
    r"""\bCVSS
    (?>(?:[\s:\-]*(?:v\s?[234](?:\.\d)?|(?:2\.0|3\.[01]|4\.0|[234])(?=[\s/:)\-]|$)))?)   # version
    (?>(?:/[A-Z]{1,3}:[A-Z](?:/[A-Z]{1,3}:[A-Z]{1,2})*)?)                               # vector after CVSS:3.1
    [\s:\-(]*
    (?:(?:base|basis)?[\s\-]?(?:score|wert|rating|bewertung)\s*(?:[:=]|of|von|is|beträgt|liegt\s+bei)?\s*)?
    (\d{1,2}(?:[.,]\d)?)(?![\d]|[.,]\d)""",
    re.I | re.X,
)
BSI_TAG = re.compile(r"\[(kritisch|hoch|mittel|niedrig)\]", re.I)
# the publisher's own rating: Palo Alto "(Severity: HIGH)" in the title, Cisco "Security Impact Rating: Critical"
VENDOR_TAG = re.compile(
    r"\((?:severity|schweregrad):\s*(critical|high|medium|moderate|low|informational|none)\s*\)|"
    r"security impact rating\s*:?\s*(critical|high|medium|low|informational)\b",
    re.I,
)
VENDOR_LEVEL = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low", "informational": "info", "none": "info"}
# "not known to be actively exploited", "no evidence of … exploited in the wild", "keine Hinweise auf eine aktive Ausnutzung"
NEGATED = re.compile(
    r"\bnot (?:\w+ ){0,2}(?:aware|known|seen|observed|exploited|being)\b|\bno (?:\w+ )?(?:evidence|indications?|signs?|reports?|knowledge)\b|"
    r"\bunaware\b|\bkeine (?:\w+ )?(?:hinweise|anzeichen|kenntnis|berichte|belege)\b|\bnicht (?:bekannt|beobachtet)\b",
    re.I,
)
# a negation right before the match, at most a few filler words between: "not actively exploited", "has not been
# exploited in the wild", "no known exploit in the wild", "bislang nicht aktiv ausgenutzt", "keine aktive Ausnutzung",
# "Kein Zero-Day" – "no fix for the zero-day" is no denial (fix, for, the are no fillers)
NEGATED_NEAR = re.compile(
    r"(?<![\w-])(?:not|never|no|nicht|nie|niemals|kein(?:e[nmrs]?)?|\w+n['’]t)"
    r"(?:\s+(?:known|currently|yet|been|being|be|to|ever|actively|active|publicly|confirmed|reported|seen|observed|"
    r"bislang|bisher|derzeit|aktuell|noch|aktiv|aktive|aktiven|bekannt|bekannte|bekannten|öffentlich|öffentliche)){0,3}\s*$",
    re.I,
)
# a denial right after the match: "Ein öffentlicher Exploit ist (bislang) nicht bekannt", "a public exploit is not known"
DENIED_AFTER = re.compile(
    r"\s*(?:\S+\s+){0,3}?(?:ist|sind|war|is|are|was|were|existiert|exist[s]?|gibt es)\s+(?:\w+\s+){0,2}?(?:nicht|not|keine?n?|no|nie|never)\b|"
    r"\s*(?:\S+\s+){0,2}?(?:liegt|liegen)\s+(?:\w+\s+){0,2}?nicht\b|\s*(?:\S+\s+){0,2}?(?:has|have)\s+not\b",
    re.I,
)
RULES: list[tuple[str, str, re.Pattern]] = [
    (
        "critical",
        "exploited",
        re.compile(
            # "in the wild" / "in freier Wildbahn" only about exploitation ("infostealer spotted in the wild" is none),
            # "out-of-band" only of a patch ("out-of-band management interface" is hardware), the Zero Day Initiative
            # (also "Zero-Day-Initiative") is a program. \bexploit\w*+ – from the start of a word, possessive: tried at
            # every "exploit" inside one word and backtracking, "exploitexploit…" (200 KB of one feed entry) was
            # quadratic – a minute with the GIL held
            r"zero[- ]?day(?![- ]initiative)|\b0-day|actively exploited|under active exploitation|known exploited|"
            r"(?:\bexploit\w*+|abused|weaponi[sz]ed)\s+(?:\S+\s+){0,3}?in the wild|"
            r"aktiv (?:ausgenutzt|angegriffen|missbraucht)|(?:wird|werden) (?:bereits |aktiv )?ausgenutzt|aktive ausnutzung|"
            r"in freier wildbahn(?=(?:\s+\S+){0,4}?\s+(?:angriff|attack|ausgenutzt|ausnutz|exploit|missbrauch|angegriffen))|"
            r"(?:ausgenutzt|angegriffen|missbraucht|ausnutzung|\bexploit\w*+)\s+(?:\S+\s+){0,2}?in freier wildbahn|"
            r"notfall-?(?:patch|update)|emergency (?:patch|update)|out-of-band (?:security )?(?:patch|update|fix|release)",
            re.I,
        ),
    ),
    (
        "high",
        "impact",
        re.compile(
            r"ransomware|erpressungs|data breach|datenleck|datenpanne|daten(?:diebstahl|abfluss)|leaked|remote code execution|\brce\b|"
            r"codeschmuggel|schadcode|code ausf(?:ü|ue)hren|supply[- ]chain|lieferkett|backdoor|hintert(?:ü|ue)r|wiper|"
            r"critical (?:vulnerabilit|flaw|bug)|kritische (?:sicherheits)?(?:l(?:ü|ue)cke|schwachstelle)|account takeover|authentication bypass",
            re.I,
        ),
    ),
    (
        "medium",
        "vulnerability",
        re.compile(
            r"vulnerabilit|sicherheitsl(?:ü|ue)cke|schwachstelle|\bl(?:ü|ue)cke|\bflaw|exploit|privilege escalation|rechteausweitung|"
            r"security update|sicherheitsupdate|\bpatch|phishing|malware|trojan|botnet|\bcve-",
            re.I,
        ),
    ),
    ("low", "topic", re.compile(r"security|sicherheit|cyber|hacker|angriff|attack|datenschutz|privacy", re.I)),
]


# a duty, not an event: "Hersteller müssen aktiv ausgenutzte Schwachstellen binnen 24 Stunden melden" (the Cyber
# Resilience Act's reporting obligation), "manufacturers must report actively exploited vulnerabilities" – the words name
# a class of bugs in a rule, nobody exploits anything. A story about a real exploitation does not phrase an obligation to
# report in the same sentence (bounded, lazy gaps within one sentence: linear)
DUTY = re.compile(
    r"meldepflicht\w*|meldefrist\w*|meldungspflicht\w*|\b(?:müssen|muss|sollen|soll|haben)\b[^.!?;\n]{0,120}?\bmelden\b|"
    r"\bverpflichtet\b[^.!?;\n]{0,120}?\bmelden\b|reporting (?:obligations?|requirements?|duty|duties|deadlines?|rules?)|"
    r"\b(?:must|shall|required to|obliged to|obligated to|have to|has to|need to)\s+(?:\S+\s+){0,3}?(?:report|notify)\b|cyber resilience act",
    re.I,
)
# a title about the obligation itself ("Cyber Resilience Act: Meldepflicht startet", "CRA: …"): nothing in its teaser
# counts as an exploitation either
DUTY_TITLE = re.compile(r"meldepflicht|reporting obligation|cyber resilience act|\bcra\b", re.I)


def _found(rx: re.Pattern, text: str, kind: str, *, title: str | None = None) -> re.Match | None:
    """The first match – for "exploited" the first one not denied in the same sentence ("not known to be actively
    exploited": Cisco and Ivanti write that under advisories of bugs nobody exploits) and not part of a duty to report
    ("müssen aktiv ausgenutzte Schwachstellen melden", see DUTY; `title`: none at all under a title about that duty).
    "poc" (a public exploit) likewise – and not denied right after it either ("Ein öffentlicher Exploit ist nicht
    bekannt")."""
    if kind == "exploited" and title is not None and DUTY_TITLE.search(title):
        return None
    for m in rx.finditer(text):
        if kind not in ("exploited", "poc"):
            return m
        before = re.split(r"[.!?;\n]", text[max(0, m.start() - 120) : m.start()])[-1]
        if NEGATED.search(before) or NEGATED_NEAR.search(re.split(r"[,:–—()]", before)[-1]):
            continue
        after = re.split(r"[.!?;\n]", text[m.end() : m.end() + 160])[0]
        if DUTY.search(f"{before}{m.group(0)}{after}"):
            continue
        if kind == "poc" and DENIED_AFTER.match(after):
            continue
        return m
    return None


def rate(title: str, text: str, body: str = "") -> tuple[str, list[dict]]:
    """Severity by rules, with what it rests on (shown in the drawer). `text` (the teaser) counts fully; `body` (the
    whole article) one level less – a long report on an arrest mentions "zero-day" somewhere without being one.
    A publisher's own rating (BSI, vendor PSIRT) stands: only a CVSS score or "exploited" raise it further."""
    hay = f"{title}\n{text}"
    level, reasons, rated = "info", [], False

    def raise_to(sev: str) -> None:
        nonlocal level
        if SEVERITIES.index(sev) > SEVERITIES.index(level):
            level = sev

    scores = []
    for m in CVSS.finditer(hay):
        try:
            v = float(m.group(1).replace(",", "."))
        except ValueError:
            continue
        if 0 < v <= 10:
            scores.append(v)
    if scores:
        top = max(scores)
        raise_to("critical" if top >= 9 else "high" if top >= 7 else "medium" if top >= 4 else "low")
        reasons.append({"kind": "cvss", "value": f"{top:.1f}"})
    if m := BSI_TAG.search(title):
        raise_to({"kritisch": "critical", "hoch": "high", "mittel": "medium", "niedrig": "low"}[m.group(1).lower()])
        reasons.append({"kind": "bsi", "value": m.group(1).lower()})
        rated = True
    elif m := VENDOR_TAG.search(hay):
        sev = VENDOR_LEVEL[(m.group(1) or m.group(2)).lower()]
        raise_to(sev)
        reasons.append({"kind": "vendor", "value": sev})
        rated = True
    for sev, kind, rx in RULES:
        if rated and kind != "exploited":
            continue
        m, weaker = _found(rx, hay, kind, title=title), False
        if not m and body:
            m, weaker = _found(rx, body, kind, title=title), True
        if not m or (sev == "low" and level != "info"):  # "security" adds nothing to a story already rated
            continue
        raise_to(SEVERITIES[max(1, SEVERITIES.index(sev) - 1)] if weaker else sev)
        reasons.append({"kind": kind, "value": m.group(0).strip()[:60], **({"in_text": True} if weaker else {})})
    return level, reasons[:5]


def cves(text: str) -> list[str]:
    return sorted({f"CVE-{a}-{b}" for a, b in CVE.findall(text)})[:30]


def search_text(title: str, summary: str, cve_ids: list[str]) -> str:
    """What the search looks in, folded once on storing (case and accents ignored, see db.fold)."""
    return " ".join((fold(title), fold(summary), fold(" ".join(cve_ids))))


# ---------------------------------------------------------------- topics


# The topics of a story (the filter "Thema" on the News page, the badges on the cards). Wording counts only in the title
# and the stored teaser – never in the full article (a long report mentions "zero-day" or "phishing" in passing) and
# never in a catalogue's own text (CISA's "Known ransomware campaign use: Unknown" is boilerplate). The order is the
# order of the badges: the first two are shown on a card. "poc": a public exploit or proof of concept exists.
TOPICS = ("zeroday", "exploited", "poc", "ransomware", "nopatch", "breach", "supply", "phishing", "ot")
# raised when a rule changes: the background job (backfill_topics) computes every stored story again
# (2: "Exploit veröffentlicht" – CISA's SSVC "exploitation: poc" and the wording)
TOPICS_V = 2
TOPICS_COUNTER = "news_topics_v"
# every story's topics again for another reason than a rule version (topics_again: the KEV's first fetch, an exploit
# list's first import or switched on or off): ASK counts the requests up, DONE is the request the last full run answered
TOPICS_ASK = "news_topics_ask"
TOPICS_DONE = "news_topics_done"
KEV_KEY = "cisa-kev"
CATALOG_KEYS = frozenset({"cisa-kev", "enisa-euvd"})
# OT vendors and the ICS desk of a newsroom: everything they publish is about OT/ICS
OT_SOURCES = frozenset({"siemens-productcert", "certvde", "securityweek-ics", "rockwell"})
# a story naming more CVEs than this is a digest ("Patchday: 80 Lücken") – a KEV CVE among them makes it "exploited"
# only when its title or teaser names that CVE
KEV_DIGEST = 3
# advertisements and paid content of the newsrooms: no wording topics (an ad for a phishing training is no phishing)
ADS = re.compile(r"^\s*(?:heise-angebot|anzeige|sponsored|webinar)\b|\(g\+\)|\bwebinar\s*:", re.I)
_W = re.I
TOPIC_WORDS: list[tuple[str, re.Pattern]] = [
    # "Zero Day Initiative" (Trend Micro's program) and Microsoft's "Zero Day Quest" (a bug bounty) are no zero-days
    ("zeroday", re.compile(r"zero[- ]?day(?![- ](?:initiative|quest))|\b0-day", _W)),
    (
        "exploited",
        re.compile(
            r"actively exploited|under active exploitation|known exploited|active exploitation|mass[- ]exploitation|exploitation (?:attempts|activity|campaign)|"
            r"(?:\bexploit\w*+|abused|weaponi[sz]ed)\s+(?:\S+\s+){0,3}?in the wild|"
            r"exploited (?:by|in) (?:attackers|hackers|threat actors|attacks|ransomware)|"
            r"(?:attackers|hackers|threat actors|cybercriminals) (?:are |have been |were )?(?:actively )?(?:exploit(?:ing|ed)?|abusing)\b|"
            r"aktiv (?:ausgenutzt|angegriffen|missbraucht)|(?:wird|werden|wurde|wurden) (?:bereits |aktiv |schon |derzeit |massiv )?(?:ausgenutzt|missbraucht)\b|"
            r"aktive ausnutzung|angriffe (?:auf|gegen) [^.!?\n]{0,40}?(?:lücke|schwachstelle)|"
            r"in freier wildbahn(?=(?:\s+\S+){0,4}?\s+(?:angriff|attack|ausgenutzt|ausnutz|exploit|missbrauch|angegriffen))|"
            r"(?:ausgenutzt|angegriffen|missbraucht|ausnutzung|\bexploit\w*+)\s+(?:\S+\s+){0,2}?in freier wildbahn",
            _W,
        ),
    ),
    # a public exploit or proof of concept – named as such, not "exploit" alone (every advisory says "could exploit")
    (
        "poc",
        re.compile(
            r"(?:proof[- ]of[- ]concepts?|\bpocs?)(?:[- ]|\s+)(?:exploit\w*|code\b|released|published|veröffentlicht|for cve-)|"
            r"\bexploit(?:[- ]code)?s? (?:for (?:(?!patch|update|fix)\S+ ){1,3})?(?:released|published|now public|made public|goes public|leaked)\b|"
            r"public(?:ly available)? (?:exploits?|exploit[- ]code|pocs?)\b|"
            r"\b(?:exploit|poc)(?:[- ]code)? (?:(?!patch|update|fix|sicherheitsupdate)\S+ ){0,6}?veröffentlicht\b|"
            r"veröffentlich\w* (?:(?:einen|den|ein|nun|jetzt) )?(?:poc|exploit|proof)\w*|"
            r"öffentliche[rn]? exploit\w*|\bexploit(?:[- ]code)? (?:ist |sind )?(?:öffentlich|frei verfügbar)\b",
            _W,
        ),
    ),
    (
        "ransomware",
        re.compile(r"ransomware|erpresser(?:software|trojaner|bande|gruppe)|erpressungs(?:trojaner|software)|\blockbit|\bakira\b|\bqilin\b|black ?basta|\bcl[o0]p\b", _W),
    ),
    (
        "nopatch",
        re.compile(
            r"\[ungepatcht\]|no (?:patch|fix)(?:es)? (?:yet|available|is available)|(?:still|yet) no (?:patch|fix)\b|without (?:a )?(?:patch|fix)\b|"
            r"unpatched (?:flaw|bug|vulnerabilit\w*|zero[- ]?day|security hole)|patch (?:is )?not (?:yet )?available|"
            r"ungepatcht\w* (?:lücke|sicherheitslücke|schwachstelle|zero)|noch kein(?:en)? (?:patch|update|fix|sicherheitsupdate)\b|"
            r"kein(?:en)? (?:patch|fix)\b(?! (?:nötig|erforderlich|notwendig))|ohne (?:patch|sicherheitsupdate)\b",
            _W,
        ),
    ),
    (
        "breach",
        re.compile(
            r"data breach|data leak|datenleck|datenpanne|daten(?:diebstahl|abfluss|klau)|"
            r"(?:customer|personal|user|patient|employee)s?'? (?:data|records|information|details) (?:was |were |have been |has been )?(?:stolen|leaked|exposed|compromised)|"
            r"(?:records|daten|datensätze) (?:\S+ ){0,3}?(?:stolen|leaked|exposed|gestohlen|erbeutet|abgeflossen|geleakt)|"
            r"kundendaten|nutzerdaten|patientendaten|(?:cyber|hacker|ransomware)-?angriff auf|cyber[- ]?attack on|\b(?:was|were|been|got) breached\b|hackers breached",
            _W,
        ),
    ),
    (
        "supply",
        re.compile(
            r"supply[- ]chain|lieferkett\w*|malicious (?:npm|pypi|rubygems|nuget|packages?|extensions?|libraries|crates?|gems?)|"
            r"(?:npm|pypi|nuget|rubygems)[- ](?:packages?|pakete?|bibliothek\w*)\s+(?:\S+\s+){0,4}?(?:malicious|compromised|backdoor\w*|hijack\w*|kompromittiert\w*|schadcode|bösartig\w*|infiziert\w*)|"
            r"(?:bösartige|schädliche|manipulierte|kompromittierte) (?:npm|pypi|pakete|bibliotheken|erweiterungen)|typo-?squat\w*|dependency confusion|backdoored|trojani[sz]ed",
            _W,
        ),
    ),
    # "campaign" or "threat actor" alone are no phishing
    (
        "phishing",
        re.compile(r"phishing|smishing|vishing|quishing|social[- ]engineering|clickfix|\baitm\b|adversary[- ]in[- ]the[- ]middle|fake (?:login|it support|captcha)|gefälschte (?:login|anmelde)\w*", _W),
    ),
    (
        "ot",
        re.compile(
            r"\bics\b|\bscada\b|\bplcs?\b|\bsps\b|\bhmi\b|\bot[- /](?:security|networks?|environments?|systems?|devices?|sicherheit|netze?|netzwerk\w*|umgebung\w*|systeme?n?|geräte?n?)|"
            r"operational technology|industrial control|industrieanlage\w*|industriesteuerung\w*|simatic|codesys|modbus|profinet|wincc",
            _W,
        ),
    ),
]
# wording whose denial counts ("Kein Zero-Day", "not actively exploited", "no public exploit") – and whose duty to report
# does not count
NEGATABLE = frozenset({"zeroday", "exploited", "poc"})
SSVC_LABEL = "CISA SSVC"
NO_FIX = ("none_available", "no_fix_planned")


def topics_of(
    title: str,
    teaser: str,
    source: str,
    ids: list[str] | None = None,
    *,
    details: dict | None = None,
    kev: set[str] | frozenset = frozenset(),
    reasons: list | None = None,
    exploits: dict[str, str] | None = None,
) -> dict[str, dict]:
    """The topics of one story with what each rests on ({"kind", "value"} – the drawer says why): `source` is the key of
    the story's own source, `ids` its CVEs, `details` its Details aus der Quelle (data), `kev` the CVEs among them CISA's
    KEV lists, `reasons` its severity reasons, `exploits` the CVEs among them a public exploit is known for (CVE → what
    says so – exploit_cves). Pure – ordered as TOPICS.

    - exploited: a catalogue's story (CISA KEV, ENISA EUVD – or a story they carry, by its reasons), a CVE the KEV lists
      (when the title or teaser names it, or the story names at most KEV_DIGEST CVEs – a digest is not exploited because
      one of its 80 CVEs is), the details' "exploited" (not for a digest with a KEV CVE), the wording (denials and duties
      to report do not count); a zero-day is exploited too.
    - ransomware: the wording – and CISA's ransomware flag on the KEV's own stories only (never passed on by a CVE).
    - nopatch: the BSI's "[UNGEPATCHT]", a CSAF advisory with no fix available or planned (and no vendor fix), a few
      narrow phrases.
    - poc ("Exploit veröffentlicht"): a CVE with a known public exploit (`exploits`: CISA's SSVC "exploitation: poc" –
      by the KEV's digest rule), the details' SSVC "poc" (not for a digest), the wording ("proof of concept", "PoC
      exploit", "exploit released", "Exploit veröffentlicht" – denied ones do not count). SSVC "active" is no PoC: it
      makes the story "exploited" (the details' "exploited").
    - ot: the OT sources (Siemens, CERT@VDE, Rockwell, SecurityWeek ICS) and the OT terms."""
    got: dict[str, dict] = {}

    def put(topic: str, kind: str, value: str = "") -> None:
        got.setdefault(topic, {"kind": kind, "value": str(value or "")[:80]})

    rs = [r for r in reasons or [] if isinstance(r, dict)]
    catalog = source in CATALOG_KEYS
    if source == KEV_KEY or any(r.get("kind") == "kev" for r in rs):
        put("exploited", "catalog", "CISA KEV")
    elif source in CATALOG_KEYS or any(r.get("kind") == "euvd" for r in rs):
        put("exploited", "catalog", "ENISA EUVD")
    if any(r.get("kind") == "ransomware" and r.get("value") == "CISA" for r in rs):  # only the KEV's catalog entries carry it
        put("ransomware", "kev_flag", "CISA KEV")
    d = details if isinstance(details, dict) else {}
    named = set(cves(f"{title}\n{teaser}"))
    mine = [str(c).upper() for c in ids or []]
    ex = exploits or {}
    known = [c for c in mine if c in ex]
    if known:
        hit = next((c for c in known if c in named), None)
        if hit or len(mine) <= KEV_DIGEST:
            put("poc", "exploit", f"{hit or known[0]} · {ex[hit or known[0]]}")
    ssvc = d.get("ssvc") if isinstance(d.get("ssvc"), dict) else {}
    if str(ssvc.get("exploitation") or "").lower() == "poc" and len(mine) <= KEV_DIGEST:
        put("poc", "ssvc", SSVC_LABEL)
    if not catalog:
        listed = [c for c in mine if c in kev]
        if listed:
            hit = next((c for c in listed if c in named), None)
            if hit or len(mine) <= KEV_DIGEST:
                put("exploited", "kev", hit or listed[0])
        elif d.get("exploited"):
            put("exploited", "details", d.get("publisher") or "")
    rem = [r for r in d.get("remediations") or [] if isinstance(r, dict)]
    none = next((str(r.get("category")) for r in rem if r.get("category") in NO_FIX), None)
    if none and not any(r.get("category") == "vendor_fix" for r in rem):
        put("nopatch", "csaf", none)
    if source in OT_SOURCES:
        put("ot", "source", source)
    if not catalog and not ADS.search(title or ""):
        for topic, rx in TOPIC_WORDS:
            for where, text_ in (("title", title or ""), ("teaser", teaser or "")):
                m = _found(rx, text_, "poc" if topic == "poc" else "exploited", title=title) if topic in NEGATABLE else rx.search(text_)
                if m:
                    put(topic, where, m.group(0).strip())
                    break
    if "zeroday" in got:
        put("exploited", "zeroday")
    return {t: got[t] for t in TOPICS if t in got}


def topic_list(title: str, teaser: str, source: str, ids: list[str] | None = None, **kw) -> list[str]:  # noqa: ANN003
    return list(topics_of(title, teaser, source, ids, **kw))


def has_topic(topics: list[str]):  # noqa: ANN201
    """SQL: the story has one of these topics (OR within the topics; the GIN index on news_items.topics) – the News
    filter, desktop and Web Push."""
    return NewsItem.topics.op("?|")(pg_array(sorted(set(topics))))


# news_items.quiet_topics as a text[] – for "topics minus quiet_topics" (jsonb - text[] drops those array elements)
_QUIET = literal_column("ARRAY(SELECT jsonb_array_elements_text(news_items.quiet_topics))", type_=ARRAY(Text))


def loud_topic(topics: list[str]):  # noqa: ANN201
    """SQL: the story has one of these topics, and not only quietly (quiet_topics: gained by a full recompute – the
    topics' backfill, an exploit list's first import, a list switched on – not by an event of its own) – the
    notification rules: a story that gains a topic quietly is no news for a rule asking for that topic. The GIN index
    first (has_topic), then the quiet ones taken out."""
    want = sorted({t for t in topics if t in TOPICS})
    if not want:
        return has_topic([])
    return and_(has_topic(want), NewsItem.topics.op("-", return_type=JSONB)(_QUIET).op("?|")(pg_array(want)))


async def kev_cves(db: AsyncSession, ids) -> set[str]:  # noqa: ANN001
    """Which of these CVEs CISA's KEV lists: the whole catalogue (vendor_kev, fetched daily) – and the KEV stories of
    the news, should the catalogue not be there (yet)."""
    want = sorted({str(c).upper() for c in ids or [] if c})
    if not want:
        return set()
    got: set[str] = set()
    for i in range(0, len(want), 1000):
        part = want[i : i + 1000]
        got |= set(await db.scalars(select(VendorKev.cve).where(VendorKev.cve.in_(part))))
        kev_src = select(NewsSource.id).where(NewsSource.key == KEV_KEY).scalar_subquery()
        for cs in await db.scalars(select(NewsItem.cves).where(NewsItem.source_id == kev_src, NewsItem.cves.op("?|")(pg_array(part)))):
            got |= {str(c).upper() for c in cs or []} & set(part)
    return got


async def kev_all(db: AsyncSession) -> set[str]:
    """Every CVE the KEV lists (the catalogue and the KEV stories) – for the backfill."""
    got = set(await db.scalars(select(VendorKev.cve)))
    kev_src = select(NewsSource.id).where(NewsSource.key == KEV_KEY).scalar_subquery()
    for cs in await db.scalars(select(NewsItem.cves).where(NewsItem.source_id == kev_src)):
        got |= {str(c).upper() for c in cs or []}
    return got


async def exploit_cves(db: AsyncSession, ids) -> dict[str, str]:  # noqa: ANN001
    """Which of these CVEs a public exploit or proof of concept is known for – CVE → what says so (the topic "poc", its
    reason in the drawer). Today: CISA's SSVC "exploitation: poc" in the stored cvelistV5 records (Vendor News keeps
    those of the followed products and the ones looked up for stories and findings – app/cvelist.py).

    And the exploit lists (app/exploits.py – Metasploit modules, Exploit-DB entries, nuclei templates; switched-on
    lists only, from memory): CVE → the list's name, where SSVC says nothing. A list that learns or drops CVEs calls
    retopic_cves for them (exploits.retopic_later → retopic_pending) – topics_of takes whatever this returns."""
    from app import exploits as exploit_lists  # exploits imports this module

    want = sorted({str(c).upper() for c in ids or [] if c})
    got: dict[str, str] = {}
    for i in range(0, len(want), 1000):
        keys = [f"cvelist:{c}" for c in want[i : i + 1000]]
        rows = await db.scalars(select(VendorAdvisory.ident).where(VendorAdvisory.id.in_(keys), _ssvc_poc()))
        got |= {str(c).upper(): SSVC_LABEL for c in rows}
    if want:
        for c, label in (await exploit_lists.labels(db, want)).items():
            got.setdefault(c, label)
    return got


def _ssvc_poc():  # noqa: ANN202
    return func.lower(func.jsonb_extract_path_text(VendorAdvisory.data, "ssvc", "exploitation")) == "poc"


async def exploit_all(db: AsyncSession) -> dict[str, str]:
    """exploit_cves for every stored record – for the backfill."""
    from app import exploits as exploit_lists

    rows = await db.scalars(select(VendorAdvisory.ident).where(VendorAdvisory.source == "cvelist", _ssvc_poc()))
    got = {str(c).upper(): SSVC_LABEL for c in rows}
    for c, label in (await exploit_lists.labels(db)).items():
        got.setdefault(c, label)
    return got


RETOPIC_BATCH = 500


def _ordered(topics) -> list[str]:  # noqa: ANN001
    return [t for t in TOPICS if t in topics]


def quiet_after(old: list[str], new: list[str], quiet_before: list[str], *, bulk: bool, baseline_poc: bool = False) -> list[str]:
    """The story's quiet topics after a recompute (old → new topics): a topic gained by a full recompute (`bulk`) is
    quiet – so is "poc" gained only through an exploit list's baseline (`baseline_poc`); a topic the story loses is no
    longer quiet (gained again later by an event of its own, it is news); the rest stays as it was."""
    gained = set(new) - set(old)
    keep = set(quiet_before) & set(new)
    if bulk:
        keep |= gained
    elif baseline_poc and "poc" in gained:
        keep.add("poc")
    return _ordered(keep)


async def retopic(db: AsyncSession, where, *, kev: set[str] | None = None, exploits: dict[str, str] | None = None, bulk: bool = False) -> int:  # noqa: ANN001
    """The topics of the stories matching `where` computed again (their text, CVEs or details changed, the KEV, a known
    exploit) – in chunks of RETOPIC_BATCH by id, a few columns each (not the article text); only changed rows are
    written. In the caller's transaction (it commits). Returns how many changed – a change makes the next notification
    round look at every rule (a rule asking for a topic the story has only now sends it then, once).

    `bulk` (the full recompute – backfill_topics): what a story gains is quiet (quiet_topics) – shown and filtered, never
    a rule's delivery (loud_topic): an exploit list switched on, its first import or a new rule version would otherwise
    send every older story that gains a topic. Not bulk (an event: a new KEV entry, a list's new entry, the details of a
    story arriving): a gained topic is loud – except "poc" that rests only on a list's baseline entries."""
    from app import exploits as exploit_lists  # exploits imports this module

    keys = dict((await db.execute(select(NewsSource.id, NewsSource.key))).all())
    cols = (NewsItem.id, NewsItem.source_id, NewsItem.title, NewsItem.summary, NewsItem.cves, NewsItem.reasons, NewsItem.topics, NewsItem.quiet_topics)
    changed, last = 0, None
    while True:
        stmt = select(*cols).where(where).order_by(NewsItem.id).limit(RETOPIC_BATCH)
        if last is not None:
            stmt = stmt.where(NewsItem.id > last)
        rows = (await db.execute(stmt)).all()
        if not rows:
            break
        last = rows[-1][0]
        ids = [r[0] for r in rows]
        dets = dict((await db.execute(select(StoryDetail.item_id, StoryDetail.data).where(StoryDetail.item_id.in_(ids), StoryDetail.data.is_not(None)))).all())
        named = [c for r in rows for c in r[4] or []]
        known = kev if kev is not None else await kev_cves(db, named)
        ex = exploits if exploits is not None else await exploit_cves(db, named)
        # an event: "poc" through a list counts only by an entry that is no baseline (SSVC always)
        loud = None
        if not bulk:
            listed = [c for c, label in ex.items() if label != SSVC_LABEL]
            fresh = await exploit_lists.loud(db, listed) if listed else set()
            loud = {c: label for c, label in ex.items() if label == SSVC_LABEL or c in fresh}

        def compute(rows=rows, dets=dets, known=known, ex=ex, loud=loud) -> list[dict]:  # noqa: ANN001
            out = []
            for iid, sid, title, summary, ids_, reasons, topics, quiet in rows:
                old, was_quiet = list(topics or []), list(quiet or [])
                kw = {"details": dets.get(iid), "kev": known, "reasons": reasons}
                new = topic_list(title, summary or "", keys.get(sid, ""), list(ids_ or []), exploits=ex, **kw)
                baseline_poc = False
                if loud is not None and "poc" in new and "poc" not in old and len(loud) < len(ex):
                    baseline_poc = "poc" not in topic_list(title, summary or "", keys.get(sid, ""), list(ids_ or []), exploits=loud, **kw)
                q = quiet_after(old, new, was_quiet, bulk=bulk, baseline_poc=baseline_poc)
                if new != old or q != was_quiet:
                    out.append({"id": iid, "topics": new, "quiet_topics": q, "_moved": new != old})
            return out

        upd = await asyncio.to_thread(compute) if len(rows) > 50 else compute()
        if upd:
            changed += sum(1 for u in upd if u.pop("_moved"))
            await db.execute(update(NewsItem), upd)
        if len(rows) < RETOPIC_BATCH:
            break
    if changed and not bulk:
        from app import notify  # notify imports this module

        notify.changed()
    return changed


async def retopic_cves(db: AsyncSession, ids) -> int:  # noqa: ANN001
    """The stories naming one of these CVEs (newly listed in the KEV, or a new KEV story) – their topics again."""
    want = sorted({str(c).upper() for c in ids or [] if c})
    n = 0
    for i in range(0, len(want), 1000):
        n += await retopic(db, NewsItem.cves.op("?|")(pg_array(want[i : i + 1000])))
    return n


async def _counters(db: AsyncSession) -> dict[str, int]:
    rows = await db.execute(select(Counter.name, Counter.value).where(Counter.name.in_([TOPICS_COUNTER, TOPICS_ASK, TOPICS_DONE])))
    return {n: int(v or 0) for n, v in rows.all()}


async def topics_due(db: AsyncSession) -> bool:
    c = await _counters(db)
    return c.get(TOPICS_COUNTER, 0) < TOPICS_V or c.get(TOPICS_DONE, 0) < c.get(TOPICS_ASK, 0)


async def backfill_topics(db: AsyncSession) -> int | None:
    """Background job: every stored story's topics, once per rule version (counters `news_topics_v` < TOPICS_V – a new
    installation, the upgrade to 0.1.46, a later rule change) and once more per request (topics_again: the KEV's first
    fetch, an exploit list's first import or switched on or off – `news_topics_ask` above `news_topics_done`). In
    chunks of RETOPIC_BATCH, each committed on its own (a restart midway starts again – it changes nothing twice).
    What a story gains here is quiet (retopic bulk: shown, never a rule's delivery). A request arriving while it runs
    (after the upgrade: the version, then each list's first import) starts it again from the beginning with what is
    known now – one run answers them all, and none ends with the data of before. None: nothing to do."""
    from app import exploits as exploit_lists  # exploits imports this module

    if not await topics_due(db):
        return None

    async def known() -> tuple[int, set[str], dict[str, str]]:
        ask = (await _counters(db)).get(TOPICS_ASK, 0)
        exploit_lists.invalidate()  # the lists as stored now (a list's import may have committed a moment ago)
        return ask, await kev_all(db), await exploit_all(db)

    ask, kev, exploits = await known()
    await dbm.release(db)
    changed, last = 0, None
    while True:
        if last is not None and (await _counters(db)).get(TOPICS_ASK, 0) != ask:
            ask, kev, exploits = await known()  # asked again meanwhile: from the start
            await dbm.release(db)
            last = None
        cond = NewsItem.id > last if last is not None else text("true")
        stmt = select(NewsItem.id).where(cond).order_by(NewsItem.id).offset(RETOPIC_BATCH - 1).limit(1)
        upto = await db.scalar(stmt)
        part = and_(cond, NewsItem.id <= upto) if upto is not None else cond
        changed += await retopic(db, part, kev=kev, exploits=exploits, bulk=True)
        await db.commit()
        if upto is None:
            break
        last = upto
    stmt = "INSERT INTO counters (name, value) VALUES (:n, :v) ON CONFLICT (name) DO UPDATE SET value = :v"
    await db.execute(text(stmt), {"n": TOPICS_COUNTER, "v": TOPICS_V})
    await db.execute(text(stmt), {"n": TOPICS_DONE, "v": ask})
    await db.commit()
    if changed:
        log.info("news: topics of %d stories computed", changed)
    return changed


async def topics_again(db: AsyncSession) -> None:
    """All topics computed again with the next round (the KEV's first fetch: every story may name one of its CVEs; an
    exploit list's first import, switched on or off) – a request counted up, in the caller's transaction: committed
    with what caused it, it cannot be lost (a restart between the two). What a story gains then is quiet."""
    stmt = "INSERT INTO counters (name, value) VALUES (:n, 1) ON CONFLICT (name) DO UPDATE SET value = counters.value + 1"
    await db.execute(text(stmt), {"n": TOPICS_ASK})


async def story_topics(db: AsyncSession, i: NewsItem, source_key: str, details: dict | None) -> list[dict]:
    """The drawer's "Themen": each topic of the story with what it rests on – computed on request, as stored."""
    kev = await kev_cves(db, i.cves or [])
    ex = await exploit_cves(db, i.cves or [])
    got = topics_of(i.title, i.summary or "", source_key, list(i.cves or []), details=details, kev=kev, reasons=i.reasons, exploits=ex)
    return [{"topic": t, **r} for t, r in got.items()]


def story(entry: dict, now: datetime) -> dict | None:
    """One feed entry as a story (None: no usable link or title). Control characters (a NUL above all – PostgreSQL
    refuses it) are dropped from every text of the entry first."""
    entry = {k: (v if isinstance(v, datetime) else dbm.clean(v)) for k, v in entry.items()}
    url = (entry.get("link") or "").strip()
    norm = normalize_url(url)
    # cut before the regex: "<" thousands of times without ">" made it quadratic (a minute for 400 KB)
    title = html.unescape(re.sub(r"<[^>]+>", " ", (entry.get("title") or "")[:2000]))
    title = re.sub(r"\s+", " ", title).strip()[:500]
    if not norm or not title:
        return None
    raw = entry.get("content") or entry.get("summary") or ""
    summary_src = entry.get("summary") or entry.get("content") or ""
    text = html_to_text(raw)
    published = entry.get("date") or now  # undated: first seen (store() keeps such a story while its feed lists it)
    published = min(published, now)  # a feed's future date would keep its story on top for ever
    summary_text = text if summary_src == raw else html_to_text(summary_src)  # most feeds: one text, read once
    if entry.get("severity") in SEVERITIES:  # a catalog entry rates itself (CISA/ENISA: exploited)
        severity, reasons = entry["severity"], list(entry.get("reasons") or [])[:5]
    else:
        teaser = summary_text if entry.get("summary") else _short(summary_text, 400)
        severity, reasons = rate(title, teaser, text if text != summary_text else "")
    summary = _short(summary_text)
    found = entry["cves"][:30] if entry.get("cves") else cves(f"{title}\n{summary_text}\n{text}")
    return {
        "url": url[:2000],
        "url_key": _key(norm),
        "title": title,
        "title_key": title_key(title),
        "summary": summary,
        "content_html": clean_html(raw),
        "published_at": published,
        "severity": severity,
        "reasons": reasons,
        "cves": found,
        "search": search_text(title, summary, found),
        "undated": entry.get("date") is None,
    }


# ---------------------------------------------------------------- sources, fetch, store


def _ids(values) -> list[uuid.UUID]:  # noqa: ANN001
    """Source ids of a filter (rules and desktop choices keep them as text) – anything else dropped."""
    out = []
    for x in values or []:
        try:
            out.append(x if isinstance(x, uuid.UUID) else uuid.UUID(str(x)))
        except ValueError:
            continue
    return out


def _also(sources: list[uuid.UUID] | None, *, enabled: bool):  # noqa: ANN202
    """The story is carried by a further source (news_item_sources) – of `sources`, when given; switched on, when asked.
    An uncorrelated IN: SQLite builds the list once (through the source index), not a lookup per story."""
    q = select(NewsItemSource.item_id)
    if enabled:
        other = aliased(NewsSource)
        q = q.join(other, other.id == NewsItemSource.source_id).where(other.enabled.is_(True))
    if sources:
        q = q.where(NewsItemSource.source_id.in_(sources))
    return NewsItem.id.in_(q)


def visible(sources: list[uuid.UUID] | None = None):  # noqa: ANN201
    """Where-clause: the story is carried by a switched-on source (the one it was first stored for or a further one,
    news_item_sources) – of `sources`, when given. Expects NewsSource joined as the story's own source."""
    if not sources:
        # correlated: asked only for a story whose own source is off (rare) – one lookup by the primary key
        other = aliased(NewsSource)
        also = select(1).select_from(NewsItemSource).join(other, other.id == NewsItemSource.source_id)
        return or_(NewsSource.enabled.is_(True), also.where(NewsItemSource.item_id == NewsItem.id, other.enabled.is_(True)).exists())
    return or_(and_(NewsSource.enabled.is_(True), NewsItem.source_id.in_(sources)), _also(sources, enabled=True))


def carried(sources: list[uuid.UUID]):  # noqa: ANN201
    """Where-clause: one of `sources` carries the story (switched on or not) – no join needed."""
    return or_(NewsItem.source_id.in_(sources), _also(sources, enabled=False))


def _backlog(published: datetime, now: datetime, *, undated: bool, primed: bool) -> bool:
    """Arrived as backlog – listed, never notified: older than BACKLOG_DAYS when fetched, or without a date of its own
    in a source's first fetch (it is dated by its arrival, nothing tells its age). A date without a time (CISA KEV,
    ENISA, many advisories: midnight UTC) counts to the end of that day – read as midnight, a catalog entry fetched a
    few hours late was never notified."""
    if undated:
        return not primed
    if (published.hour, published.minute, published.second, published.microsecond) == (0, 0, 0, 0):
        published += timedelta(days=1) - timedelta(seconds=1)
    return published < now - timedelta(days=BACKLOG_DAYS)


async def config(db: AsyncSession) -> dict:
    return await settings_store.get(db, "news")


async def save_config(db: AsyncSession, value: dict) -> dict:
    out = await settings_store.put(db, "news", value)
    await db.commit()
    return out


async def ensure_sources(db: AsyncSession) -> None:
    """The built-in sources exist (switched on or off as left in the settings); name and address follow the code.
    A key new to an existing installation comes with its default (on or off) – an existing source keeps its switch.
    Only a source whose default changed (DEFAULT_CHANGED) and that no admin ever switched follows the new default."""
    for b in BUILTIN:
        stmt = pg_insert(NewsSource).values(id=uuid.uuid4(), key=b.key, name=b.name, url=b.url, site=b.site, builtin=True, enabled=b.on, failures=0)
        # a new address (a release moved the feed): the old one's ETag / Last-Modified, pause and error are not the
        # new one's – asked in the next round, as a new feed (its first fetch is the baseline again)
        moved = NewsSource.url != b.url
        fresh = {c: case((moved, None), else_=getattr(NewsSource, c)) for c in ("etag", "last_modified", "next_fetch_at", "error", "primed_at")}
        set_ = {"name": b.name, "url": b.url, "site": b.site, "builtin": True, **fresh, "failures": case((moved, 0), else_=NewsSource.failures)}
        await db.execute(stmt.on_conflict_do_update(index_elements=["key"], set_=set_))
    for key in DEFAULT_CHANGED:
        on = BUILTIN_BY_KEY[key].on
        await db.execute(
            update(NewsSource)
            .where(NewsSource.key == key, NewsSource.builtin.is_(True), NewsSource.switched_at.is_(None), NewsSource.enabled.is_not(on))
            .values(enabled=on)
        )
    await db.commit()


def _retry_after(headers: httpx.Headers) -> timedelta | None:
    v = (headers.get("retry-after") or "").strip()
    if not v:
        return None
    if v.isdigit():
        return timedelta(seconds=min(int(v), int(MAX_BACKOFF.total_seconds())))  # a huge number would overflow
    d = _date(v)
    if d is None or d <= datetime.now(UTC):
        return None  # a date in the past asks for no pause (not "-86400 s")
    return min(d - datetime.now(UTC), MAX_BACKOFF)


async def _cve_peers(db: AsyncSession, src: NewsSource, stories: list[dict]) -> dict[str, list[NewsItem]]:
    """The stories of the other vulnerability sources around these dates, by CVE – one query per fetch, matched here."""
    dated = [s["published_at"] for s in stories if s["cves"]]
    if src.key not in CVE_SOURCES or not dated:
        return {}
    peers = select(NewsSource.id).where(NewsSource.key.in_(CVE_SOURCES), NewsSource.id != src.id)
    lo, hi = min(dated) - CVE_WINDOW, max(dated) + CVE_WINDOW
    out: dict[str, list[NewsItem]] = {}
    for it in await db.scalars(select(NewsItem).where(NewsItem.source_id.in_(peers), NewsItem.published_at.between(lo, hi), func.jsonb_array_length(NewsItem.cves) > 0)):
        for c in it.cves or []:
            out.setdefault(str(c).upper(), []).append(it)
    return out


def _same_cve(by_cve: dict[str, list[NewsItem]], s: dict) -> NewsItem | None:
    """The newest peer story within CVE_WINDOW sharing a CVE – when one side is about that single CVE."""
    lo, hi = s["published_at"] - CVE_WINDOW, s["published_at"] + CVE_WINDOW
    found = {id(it): it for c in s["cves"] for it in by_cve.get(c.upper(), [])}.values()
    ok = [it for it in found if lo <= it.published_at <= hi and (len(s["cves"]) == 1 or len(it.cves or []) == 1)]
    return max(ok, key=lambda it: it.published_at) if ok else None


SEQ = "news_seq"


async def next_seq(db: AsyncSession) -> int:
    """The next arrival number – in the caller's transaction: it becomes visible together with the story, and the
    counter's row stays locked until then (the next one waits: numbers become visible in order)."""
    stmt = "INSERT INTO counters (name, value) VALUES (:n, 1) ON CONFLICT (name) DO UPDATE SET value = counters.value + 1 RETURNING value"
    return int(await db.scalar(text(stmt), {"n": SEQ}))


async def last_seq(db: AsyncSession) -> int:
    """The newest arrival number readers can see (the cursor for /news/recent and Web Push)."""
    return int(await db.scalar(text("SELECT value FROM counters WHERE name = :n"), {"n": SEQ}) or 0)


async def _carried_by(db: AsyncSession, known: NewsItem, src: NewsSource) -> None:
    """`src` carries this story too: named under "also in" and counted for that source (filters, visibility)."""
    if known.source_id == src.id:
        return
    if src.name not in (known.also_in or []):
        known.also_in = [*(known.also_in or []), src.name][:10]
    await db.execute(pg_insert(NewsItemSource).values(item_id=known.id, source_id=src.id).on_conflict_do_nothing())


def _updated(known: NewsItem, s: dict) -> bool:
    """The source changed a story it published before ("[UPDATE] … wird aktiv ausgenutzt"): new title and text, the
    rating only rises (a later "[mittel]" does not undo an exploitation), CVEs merged. True: title or CVEs changed –
    the details are asked again."""
    if known.title == s["title"] and known.summary == s["summary"] and known.content_html == s["content_html"] and set(s["cves"]) <= set(known.cves or []):
        return False
    again = known.title != s["title"]
    known.title, known.title_key, known.summary, known.content_html = s["title"], s["title_key"], s["summary"], s["content_html"]
    if SEVERITIES.index(s["severity"]) > SEVERITIES.index(known.severity):
        known.severity = s["severity"]
        known.reasons = [*s["reasons"], *(r for r in (known.reasons or []) if r not in s["reasons"])][:5]
    merged = sorted({*(known.cves or []), *s["cves"]})[:30]
    if merged != sorted(known.cves or []):
        known.cves, again = merged, True
    known.search = search_text(known.title, known.summary, known.cves)
    return again


PRUNED = "news_pruned_before"  # counters: up to when (epoch seconds) stories were deleted by the retention


async def pruned_before(db: AsyncSession) -> datetime | None:
    v = await db.scalar(text("SELECT value FROM counters WHERE name = :n"), {"n": PRUNED})
    return datetime.fromtimestamp(int(v), UTC) if v else None


async def store(db: AsyncSession, src: NewsSource, entries: list[dict], keep: timedelta | None = None, facts: dict | None = None) -> int:
    """New stories of one feed; a story known by URL, or (within days) by title from another source, only names this
    source as well. Within one source a different URL is a different story; the same URL with a changed title or text
    is an update of the story (see _updated).
    Between the vulnerability sources (CVE_SOURCES: KEV, EUVD, BSI warnings) the same CVE within CVE_WINDOW is the same
    story too – when one side is about that single CVE (a warning on five CVEs is not the KEV entry of one of them alone).
    Older than the retention – or than what the retention deleted already (keep_days raised later) –: not taken; it
    would be deleted at the next prune and come back as new (and unread) afterwards.
    One transaction, a savepoint per story: a story the database refuses is left out (logged, counted as unusable),
    the others are stored; any other failure rolls all of it back (sequence numbers included).
    `facts` (optional) gets "unusable": entries without a usable link or title, or refused (the source health's parse errors)."""
    now = datetime.now(UTC)
    added = 0
    floor = max(x for x in (now - keep if keep is not None else None, await pruned_before(db), datetime.min.replace(tzinfo=UTC)) if x is not None)
    primed = src.primed_at is not None
    # text, cleaning and rating of up to 200 entries: off the event loop (a big feed would hold every request)
    stories = await asyncio.to_thread(lambda: [story(e, now) for e in entries])
    if facts is not None:
        facts["unusable"] = sum(1 for x in stories if x is None)
    by_cve = await _cve_peers(db, src, [x for x in stories if x is not None])
    # the CVEs of this fetch the KEV lists – once per fetch, for the topics of the stories (topics_of)
    kev = await kev_cves(db, [c for x in stories if x is not None for c in x["cves"]])
    exploits = await exploit_cves(db, [c for x in stories if x is not None for c in x["cves"]])
    fresh_kev: list[str] = []  # CVEs of new KEV stories: the other stories naming them become "exploited"
    skipped = 0
    for s in stories:
        if s is None:
            continue
        undated = s.pop("undated", False)
        if s["published_at"] < floor:
            continue
        # one savepoint per story: a story the database refuses is left out (and logged), not the whole feed with it
        try:
            async with db.begin_nested():
                got = await _store_one(db, src, s, now, undated=undated, primed=primed, by_cve=by_cve, kev=kev, exploits=exploits)
                added += got
                if got and src.key == KEV_KEY:
                    fresh_kev += s["cves"]
        except DBAPIError as exc:
            skipped += 1
            log.warning("news %s: story not stored (%s): %s", src.key, type(getattr(exc, "orig", exc)).__name__, s["url"][:200])
    if skipped and facts is not None:
        facts["unusable"] = facts.get("unusable", 0) + skipped
    if fresh_kev:
        await retopic_cves(db, fresh_kev)
    await db.commit()
    return added


async def _store_one(
    db: AsyncSession, src: NewsSource, s: dict, now: datetime, *, undated: bool, primed: bool, by_cve: dict, kev: set[str] | None = None, exploits: dict[str, str] | None = None
) -> int:
    """One story of store(): known (by URL, title or CVE) – only noted for this source – or inserted. 1: inserted.
    The topics follow what changed: a new story gets them, an updated one (title, teaser, CVEs) or one that took a
    catalogue's rating (the same CVE) has them computed again."""
    known = await db.scalar(select(NewsItem).where(NewsItem.url_key == s["url_key"]))
    if known is not None and known.source_id == src.id:
        before = (known.title, known.summary, list(known.cves or []))
        if _updated(known, s):
            await db.execute(update(StoryDetail).where(StoryDetail.item_id == known.id).values(next_try_at=now))
        if (known.title, known.summary, list(known.cves or [])) != before:
            await db.flush()
            await retopic(db, NewsItem.id == known.id)
    if known is not None and undated and known.seen_at is not None:
        known.seen_at = now  # still listed: it stays past the retention (see prune)
    if known is None:
        # the same title from another source (one this source does not carry yet): the same story
        lo, hi = s["published_at"] - TITLE_WINDOW, s["published_at"] + TITLE_WINDOW
        same_title = and_(NewsItem.title_key == s["title_key"], NewsItem.source_id != src.id, ~_also([src.id], enabled=False), NewsItem.published_at.between(lo, hi))
        known = await db.scalar(select(NewsItem).where(same_title).limit(1))
    if known is None and by_cve and s["cves"]:
        known = _same_cve(by_cve, s)
        # "CISA: exploited" on a BSI warning rated by its words: the story takes the higher rating and its reason
        if known is not None and SEVERITIES.index(s["severity"]) > SEVERITIES.index(known.severity):
            known.severity, known.reasons = s["severity"], [*s["reasons"], *(known.reasons or [])][:5]
            await db.flush()
            await retopic(db, NewsItem.id == known.id)  # "CISA: exploited" – the catalogue's reasons count for its topics
    if known is not None:
        await _carried_by(db, known, src)
        return 0
    seq = await next_seq(db)  # a number lost to a clash below leaves a gap – harmless
    row = {"id": uuid.uuid4(), "source_id": src.id, "fetched_at": now, "seq": seq, **s}
    known_kev = kev if kev is not None else await kev_cves(db, s["cves"])
    ex = exploits if exploits is not None else await exploit_cves(db, s["cves"])
    row["topics"] = topic_list(s["title"], s["summary"], src.key, s["cves"], kev=known_kev, reasons=s["reasons"], exploits=ex)
    row |= {"seen_at": now if undated else None, "backlog": _backlog(s["published_at"], now, undated=undated, primed=primed)}
    res = await db.execute(pg_insert(NewsItem).values(**row).on_conflict_do_nothing(index_elements=["url_key"]))
    return res.rowcount or 0


async def fetch_source(
    db: AsyncSession, src: NewsSource, *, every: timedelta, proxy: str | None, verify: ssl.SSLContext | bool, transport=None, keep: timedelta | None = None
) -> int:
    """One feed: conditional request, parse, store; on refusal a growing pause. Returns new stories (-1: failed)."""
    now = datetime.now(UTC)
    src.last_fetch_at = now
    # stored before the download: should this feed bring the process down (memory), it pauses after a restart
    # instead of being fetched again right away – success or a handled failure overwrite it below
    src.next_fetch_at = now + min(every * (2 ** min((src.failures or 0) + 1, 6)), MAX_BACKOFF)
    await db.commit()
    # any content type is read (Siemens sends its Atom feed as binary/octet-stream) – the body decides: XML or JSON
    headers = {"Accept": "application/atom+xml, application/rss+xml, application/xml;q=0.9, text/xml;q=0.8, application/json;q=0.8, */*;q=0.1"}
    kev = src.key == KEV_KEY and src.builtin
    # the KEV feeds Vendor News' whole catalogue too (one download for both, kev_received): while that is empty – a
    # first start, the upgrade – the catalogue is asked for in full, not "unchanged since"
    conditional = not kev or await _kev_filled(db)
    if src.etag and conditional:
        headers["If-None-Match"] = src.etag
    if src.last_modified and conditional:
        headers["If-Modified-Since"] = src.last_modified
    meter = source_health.start()  # the requests of this fetch are measured (one stats row with the commit below)
    try:
        limit = KEV_LIMIT if kev else MAX_FEED_BYTES
        got = await download(src.url, proxy=proxy, verify=verify, headers=headers, transport=transport, limit=limit)
        if got.status == 403 and kev:
            got = await kev_mirror(headers, proxy=proxy, verify=verify, transport=transport)
        if got.status == 304:
            src.failures, src.error, src.last_ok_at, src.next_fetch_at = 0, None, now, now + every
            src.primed_at = src.primed_at or now
            source_health.record(db, source_health.NEWS, src.key, ok=True, meter=meter)
            await db.commit()
            if kev:
                await _kev_checked(db)
            return 0
        if got.status in (429, 503):
            wait = _retry_after(got.headers)
            raise NewsError("rate_limited", f"HTTP {got.status}" + (f", Retry-After {int(wait.total_seconds())} s" if wait else ""), wait)
        if got.status >= 400:
            raise http_error(got.status)
        entries, meta = await asyncio.to_thread(parse_feed, got.body)
    except Exception as exc:  # noqa: BLE001 - whatever a feed sends: this source pauses, the round goes on
        if not isinstance(exc, NewsError):
            log.warning("news %s: unexpected %s", src.key, type(exc).__name__)
            exc = NewsError("format", type(exc).__name__)
        return await _failed(db, src, exc, now=now, every=every, meter=meter)
    src.etag = (got.headers.get("etag") or "")[:300] or None
    src.last_modified = (got.headers.get("last-modified") or "")[:100] or None
    facts: dict = {}
    sid, key = src.id, src.key
    try:
        added = await store(db, src, entries, keep, facts)
    except DBAPIError as exc:
        # the database refused the batch (not one story – store() skips those): the source shows it and pauses like
        # after any other failure, instead of looking healthy while it brings nothing
        await db.rollback()
        why = type(getattr(exc, "orig", None) or exc).__name__
        log.warning("news %s: not stored: %s", key, why)
        src = await db.get(NewsSource, sid, populate_existing=True)
        if src is None:
            raise  # removed meanwhile (refresh_due logs it)
        return await _failed(db, src, NewsError("format", f"not stored ({why})"), now=now, every=every, meter=meter)
    src = await db.get(NewsSource, src.id) or src
    src.failures, src.error, src.last_ok_at, src.next_fetch_at = 0, None, datetime.now(UTC), datetime.now(UTC) + every
    src.primed_at = src.primed_at or datetime.now(UTC)  # its first fetch is stored: from now on undated stories are news
    source_health.record(db, source_health.NEWS, src.key, ok=True, meter=meter, items=added, parse_errors=facts.get("unusable", 0))
    await db.commit()
    if kev:
        from app import vendor

        try:
            await vendor.kev_received(db, got.body)
        except Exception:  # noqa: BLE001 - the stories are stored; the catalogue waits for its own daily fetch
            await db.rollback()
            log.exception("news %s: KEV catalogue not taken over", key)
    if src.logo is None and (src.logo_checked_at is None or datetime.now(UTC) - src.logo_checked_at > LOGO_RETRY):
        await fetch_logo(db, src, meta.get("icon") or "", proxy=proxy, verify=verify, transport=transport)
    return added


async def _failed(db: AsyncSession, src: NewsSource, exc: NewsError, *, now: datetime, every: timedelta, meter) -> int:  # noqa: ANN001
    """A failed fetch (or store): the error on the source, a growing pause, the source health's note. Returns -1."""
    src.failures = (src.failures or 0) + 1
    pause = every * (2 ** min(src.failures, 6))
    if exc.category in TRANSIENT:
        # a timeout or a lost connection (DNS, proxy, the uplink) says nothing about the site: back soon, not after
        # 16 hours – at most an hour (or the interval, when that is longer)
        pause = min(pause, max(every, TRANSIENT_BACKOFF))
    if exc.category == "rate_limited":
        pause = max(pause, exc.wait or timedelta(hours=1))  # as long as the site asked, at least an hour
    src.next_fetch_at = now + min(pause, MAX_BACKOFF)
    src.error = f"{exc.category}: {exc.detail}"[:200] if exc.detail else exc.category
    source_health.record(db, source_health.NEWS, src.key, ok=False, meter=meter, exc=exc)
    await db.commit()
    log.info("news %s: %s", src.key, src.error)
    return -1


LOGO_MAGIC = [(b"\x89PNG\r\n\x1a\n", "image/png"), (b"\x00\x00\x01\x00", "image/x-icon"), (b"GIF8", "image/gif"), (b"\xff\xd8\xff", "image/jpeg")]


def logo_type(data: bytes) -> str | None:
    """Only bitmap formats by their first bytes – an SVG can carry script, it is not taken."""
    for magic, mime in LOGO_MAGIC:
        if data.startswith(magic):
            return mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


async def fetch_logo(db: AsyncSession, src: NewsSource, icon: str, *, proxy: str | None, verify: ssl.SSLContext | bool, transport=None) -> None:
    """The site's icon, fetched once by the server and kept – the browser never loads anything from the news sites."""
    candidates = []
    if icon.startswith("https://"):
        candidates.append(icon)
    base = src.site or f"https://{urlsplit(src.url).hostname}"
    candidates += [urljoin(base + "/", "/favicon.ico"), urljoin(base + "/", "/apple-touch-icon.png")]
    await dbm.release(db)  # nothing pending while the site is asked
    checked = datetime.now(UTC)
    logo = None
    for url in dict.fromkeys(candidates):
        try:
            got = await download(url, proxy=proxy, verify=verify, limit=MAX_LOGO_BYTES, transport=transport)
        except NewsError:
            continue
        mime = logo_type(got.body) if got.status == 200 else None
        if mime:
            logo = (got.body, mime)
            break
    src.logo_checked_at = checked
    if logo:
        src.logo, src.logo_type = logo
    await db.commit()


_host_last: dict[str, float] = {}


async def refresh_due(*, force: bool | datetime = False, transport=None) -> dict[str, int]:
    """Background loop: the switched-on sources whose time has come, one after the other, each host at most once a
    minute. `force` ("fetch now", the time it was asked): every switched-on source not pausing after a refusal and not
    fetched since then, each once."""
    out: dict[str, int] = {}
    async with dbm.session() as db:
        cfg = await config(db)
        if not cfg.get("enabled"):
            return out
        proxy, verify = get_config().proxy, tls_verify()
        every = timedelta(minutes=max(15, int(cfg.get("every_min") or 30)))
        keep = timedelta(days=max(7, int(cfg.get("keep_days") or 90)))
        now = datetime.now(UTC)
        since = (now if force is True else force) or None
        stmt = select(NewsSource.id).where(NewsSource.enabled.is_(True)).order_by(NewsSource.next_fetch_at.asc().nullsfirst())
        for sid in list(await db.scalars(stmt)):
            # switched off meanwhile (news as a whole or this source), or removed: not asked any more
            if not (await config(db)).get("enabled"):
                break
            src = await db.get(NewsSource, sid, populate_existing=True)
            if src is None or not src.enabled:
                continue
            # the interval was shortened meanwhile: a healthy source is due by the new one, not after the old wait
            # (decided here, not written – fetch_source sets the next time anyway, and the session stays clean)
            next_at = src.next_fetch_at
            if not src.failures and src.last_fetch_at and next_at and src.last_fetch_at + every < next_at:
                next_at = src.last_fetch_at + every
            forced = since is not None and (src.last_fetch_at is None or src.last_fetch_at < since)
            due = next_at is None or next_at <= now or (forced and not (src.error or "").startswith("rate_limited"))
            if not due:
                continue
            host = urlsplit(src.url).hostname or ""
            if time.monotonic() - _host_last.get(host, -1e9) < HOST_GAP_S:
                continue  # next round
            _host_last[host] = time.monotonic()
            key = src.key
            try:
                out[key] = await fetch_source(db, src, every=every, proxy=proxy, verify=verify, transport=transport, keep=keep)
            except (StaleDataError, IntegrityError):
                await db.rollback()  # removed in the settings while it was being fetched – the others go on
                log.info("news %s: removed while fetching", key)
            except Exception:  # noqa: BLE001 - one source must never end the round for all others
                await db.rollback()
                log.exception("news %s: failed", key)
    return out


PRUNE_BATCH = 500


async def prune(db: AsyncSession) -> int:
    """Stories older than the retention (and who read them, their details) go – in short transactions of PRUNE_BATCH
    stories each, so a big backlog never holds the database for long. One without a date of its own (dated by when it
    was first seen) stays while its feed still lists it – deleted, it would come back as new with the next fetch.
    The cut is remembered (store() takes nothing older again – a raised keep_days does not bring deleted stories back
    as unread). The freed space is reused by Postgres (autovacuum)."""
    days = max(7, int((await config(db)).get("keep_days") or 90))
    cut = datetime.now(UTC) - timedelta(days=days)
    old = and_(NewsItem.published_at < cut, or_(NewsItem.seen_at.is_(None), NewsItem.seen_at < cut))
    gone = 0
    while ids := list(await db.scalars(select(NewsItem.id).where(old).limit(PRUNE_BATCH))):
        res = await db.execute(delete(NewsItem).where(NewsItem.id.in_(ids)))
        await db.commit()
        gone += res.rowcount or 0
    stamp = int(cut.timestamp())
    await db.execute(text("INSERT INTO counters (name, value) VALUES (:n, :v) ON CONFLICT (name) DO UPDATE SET value = GREATEST(counters.value, :v)"), {"n": PRUNED, "v": stamp})
    await db.commit()
    return gone
