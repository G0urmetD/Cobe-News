"""Systeme, Schlagwörter and "Nicht senden, wenn enthalten" – one implementation for every place a story or a Vendor
News event is chosen by them:

- the admins' channel rules (notify.news_filter / vendor_filter, notify_api.RuleIn),
- the News list's "Systeme" filter (api.list_news, api.read_all – `system=v:<vendor>` / `system=p:<key>` /
  `system=ours`), and so its saved views,
- a person's own desktop notifications in the tab and by Web Push (api.desktop_filter, auth_api.DesktopIn),
- a person's "Hersteller-News meiner Produkte" (personal.wants, personal_api.MineIn – systems only: words are for
  news, as in the rules).

The semantics are the rules' (app/systems.py, app/keywords.py): systems OR words ("Betrifft" – one of them is enough),
AND with everything else; an exclusion word keeps a story away whatever else it matches. A notification asks only for
the systems a story gained loudly (`quiet_too=False`: a recompute never makes an older story news); a list – what the
News page shows, the dry run – counts the quiet ones too. Input is checked here once: a system is a catalogue vendor
(a name, no control characters, at most 120 characters), a product key (the catalogue's key format) or "Unsere
Produkte (aus Vendor News)" ({"ours": true} – the products followed when a story is judged: systems.Followed), at most
systems.ENTRIES_MAX; words as keywords.clean (plain text, never a pattern of the user's). Whoever judges "Unsere
Produkte" reads the followed products first (systems.load_followed – once per round or request)."""

import re

from pydantic import ConfigDict, Field, StrictBool, field_validator, model_validator
from sqlalchemy import ColumnElement, false, or_

from app import keywords as words_svc
from app import systems as systems_svc
from app.deps import NoNul, api_error
from app.models import NewsItem, VendorEvent

NAME = r"^[^\x00-\x1f\x7f  ]*$"  # as the rules' names: no control characters, no line or paragraph separator
PRODUCT = r"^[a-z0-9][a-z0-9._+-]{0,63}$"  # a catalogue key
VENDOR_MAX = 120
QUERY_MAX = VENDOR_MAX + 2  # one `system` of an address: "v:" + the vendor's name
_NAME, _PRODUCT = re.compile(NAME), re.compile(PRODUCT)


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SystemIn(_M):
    """One system: a catalogue vendor (every product of it, also one added later), one product, or "Unsere Produkte"
    (`ours: true` – the products followed in Vendor News, also one followed later)."""

    vendor: str | None = Field(default=None, min_length=1, max_length=VENDOR_MAX, pattern=NAME)
    product: str | None = Field(default=None, min_length=1, max_length=64, pattern=PRODUCT)
    ours: StrictBool | None = None  # only true (a JSON true – no 1, no "yes")

    @model_validator(mode="after")
    def _one(self) -> "SystemIn":
        if sum(x is not None for x in (self.vendor, self.product, self.ours)) != 1 or self.ours is False:
            raise ValueError("a vendor, a product or ours: true")
        return self

    def entry(self) -> dict:
        if self.ours:
            return {systems_svc.OURS: True}
        return {"vendor": self.vendor} if self.vendor is not None else {"product": self.product}


def _words(v: list[str] | None) -> list[str] | None:
    return None if v is None else words_svc.clean(v)


class Concerns(_M):
    """"Betrifft" (systems, words) and "Nicht senden, wenn enthalten" of a request. None (not sent – a client from
    before the field): what is stored stays (a new row has none)."""

    systems: list[SystemIn] | None = Field(default=None, max_length=systems_svc.ENTRIES_MAX)
    keywords: list[str] | None = Field(default=None, max_length=words_svc.WORDS_MAX)
    exclude: list[str] | None = Field(default=None, max_length=words_svc.WORDS_MAX)

    _kw = field_validator("keywords", "exclude")(_words)

    def system_entries(self) -> list[dict] | None:
        """The systems as stored ([{"vendor"} | {"product"}]), each choice once (another spelling of the same vendor
        is the same choice) – None: not sent."""
        if self.systems is None:
            return None
        return dedupe([x.entry() for x in self.systems])


def dedupe(entries: list[dict]) -> list[dict]:
    return list({systems_svc.text_of(e): e for e in entries}.values())


def check_known(chosen: list[dict] | None, had: list[dict]) -> None:
    """A system the catalogue does not know is refused (422 system_not_found) – unless it was stored already (the
    catalogue dropped it since: kept, it stands for nothing; the form shows it as gone)."""
    known_before = {systems_svc.text_of(e) for e in had}
    if unknown := [e for e in chosen or [] if not systems_svc.known(e) and systems_svc.text_of(e) not in known_before]:
        raise api_error(422, "system_not_found", name=str(unknown[0].get("product") or unknown[0].get("vendor"))[:120])


def from_query(values: list[str]) -> list[dict]:
    """The `system` parameters of an address ("v:Palo Alto Networks", "p:panos", "ours") as entries – checked as
    SystemIn (a product key, a vendor's name without control characters), at most systems.ENTRIES_MAX; ValueError
    otherwise. A system the catalogue does not know is no error here: it stands for nothing (a link from before a
    catalogue change)."""
    if len(values) > systems_svc.ENTRIES_MAX:
        raise ValueError(f"system: at most {systems_svc.ENTRIES_MAX}")
    out = []
    for raw in values:
        v = str(raw).strip()
        if v == systems_svc.OURS:
            out.append({systems_svc.OURS: True})
            continue
        kind, _, ref = v.partition(":")
        ref = ref.strip()
        if len(v) > QUERY_MAX or not ref:
            raise ValueError("system: v:<vendor>, p:<product> or ours")
        if kind == "p" and _PRODUCT.fullmatch(ref):
            out.append({"product": ref})
        elif kind == "v" and len(ref) <= VENDOR_MAX and _NAME.fullmatch(ref):
            out.append({"vendor": ref})
        else:
            raise ValueError("system: v:<vendor>, p:<product> or ours")
    return dedupe(out)


# ---------------------------------------------------------------- the SQL


def systems_clause(systems: list[dict], *, quiet_too: bool) -> ColumnElement:
    """SQL: the story concerns one of the systems (systems.wanted – entries the catalogue no longer knows stand for no
    story); `quiet_too`: also one it has only quietly (a list, the dry run), else only loudly (a notification). The GIN
    index on news_items.systems serves both. "Unsere Produkte": the followed products (systems.ours_loud – from when
    each was followed – / ours_has), next to the other entries."""
    if not systems_svc.has_ours(systems):
        want = systems_svc.wanted(systems)
        return systems_svc.has(want) if quiet_too else systems_svc.loud(want)
    rest = [e for e in systems if systems_svc.OURS not in e]
    if quiet_too:
        return or_(systems_svc.has(systems_svc.wanted(rest)), systems_svc.ours_has())
    return or_(systems_svc.loud(systems_svc.wanted(rest)), systems_svc.ours_loud())


def news_clause(systems: list[dict] | None, words: list[str] | None, *, quiet_too: bool = False) -> ColumnElement | None:
    """SQL "Betrifft" of news: one of the systems or one of the words – None: neither chosen (both None: no
    restriction; an empty list is a choice of nothing, as an earlier rule filter merged keeps it)."""
    if systems is None and words is None:
        return None
    parts = [systems_clause(systems or [], quiet_too=quiet_too)]
    if (w := words_svc.clause(words or [])) is not None:
        parts.append(w)
    return or_(*parts)


def news_where(systems: list[dict] | None, words: list[str] | None, exclude: list[str] | None, *, quiet_too: bool = False) -> list:
    """The conditions on news: "Betrifft" (news_clause – an empty choice is none) and "Nicht senden, wenn enthalten"
    (none of these words)."""
    out = []
    if (b := news_clause(systems or None, words or None, quiet_too=quiet_too)) is not None:
        out.append(b)
    if (x := words_svc.none_of(exclude or [])) is not None:
        out.append(x)
    return out


def vendor_clause(systems: list[dict] | None) -> ColumnElement | None:
    """SQL: the Vendor News event's product is one of the systems' (a vendor: each of its catalogue products, with the
    keys merged into them; "Unsere Produkte": every product followed now, also by CPE) – None: no systems (every
    product); none known: no event."""
    if not systems:
        return None
    keys = systems_svc.product_keys(systems)
    return VendorEvent.product.in_(keys) if keys else false()


def vendor_wants(systems: list[dict] | None, product: str | None, keys: set[str] | None = None) -> bool:
    """In Python, as vendor_clause: the event's product is one of the systems' (`keys`: product_keys of them, when
    known already) – True without systems."""
    if not systems:
        return True
    return (product or "") in (keys if keys is not None else set(systems_svc.product_keys(systems)))


def story_names(i: NewsItem) -> list[str]:
    """The products a story is about, as names – for a notification that names no "Treffer" (the person chose no
    systems or words): the followed products its details concern first (news_items.products), then the catalogue
    systems it concerns or names (systems.hits over all of them – exact, named, vendors). Custom products (no catalogue
    entry) are left out: their key says nothing."""
    out: list[str] = []
    for key in i.products or []:
        p = systems_svc.catalog.product(systems_svc.catalog.REPLACED.get(key, key))
        if p and (name := systems_svc.short_label(p)) and name not in out:
            out.append(name)
    every = list(i.systems or [])
    for name in systems_svc.hits(every, list(i.quiet_systems or []), every, f"{i.title} {i.summary or ''}") if every else []:
        if name not in out:
            out.append(name)
    return out


def story_hits(i: NewsItem, systems: list[dict] | None, words: list[str] | None, want: list[str] | None = None) -> list[str]:
    """What a story matched by: the names of its systems (systems.hits – `want`: systems.wanted of them, when known
    already) and the words in its title or teaser – [] when neither was chosen. The messages' "Treffer"."""
    out = systems_svc.hits(list(i.systems or []), list(i.quiet_systems or []), want if want is not None else systems_svc.wanted(systems), f"{i.title} {i.summary or ''}") if systems else []
    # "Unsere Produkte": a product followed by CPE by its label (its details concern it – news_items.products)
    custom = systems_svc.followed().custom if systems and systems_svc.has_ours(systems) else {}
    out += [n for k in i.products or [] if (n := custom.get(k)) and n not in out]
    return out + [w for w in words_svc.hits(i.search or "", words or []) if w not in out]
