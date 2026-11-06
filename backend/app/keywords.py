"""Schlagwörter and "Nicht senden, wenn enthalten" of the notification rules: own words, matched in a story's title and
teaser (news_items.search – title, teaser and CVEs, folded once when stored: db.fold) as whole words, case and accents
ignored. A blank or a hyphen in a word stands for either ("Palo Alto" finds "Palo-Alto-Firewalls"); everything else is
plain text – never a pattern of the admin's: each character is escaped into the regular expression the database runs
(a bound parameter, no SQL of its own), which has no nested repetition (no catastrophic backtracking). A word is
"whole" when no letter or digit touches it on either side ("Fortinet" is not in "Fortinets", "PAN-OS" is in
"PAN-OS-Lücke")."""

import re

from sqlalchemy import ColumnElement

from app.db import fold
from app.models import NewsItem

WORDS_MAX = 30  # words per list
WORD_MIN, WORD_MAX = 2, 60  # characters of a word
# letters (any script), digits and the signs product names and terms use – no line break, no quote other than '
ALLOWED = re.compile(r"^[\w .+#&/:'@!-]+$")
_SEP = re.compile(r"[\s-]+")
_ALNUM = re.compile(r"[^\W_]")


def clean(values) -> list[str]:  # noqa: ANN001
    """The words as entered, checked: trimmed, inner blanks single, each once (case and accents ignored), at most
    WORDS_MAX of WORD_MIN to WORD_MAX characters with a letter or digit – ValueError (a 422) otherwise."""
    out: list[str] = []
    seen: set[str] = set()
    for v in values or []:
        w = " ".join(str(v).split())
        if not w:
            continue
        if not WORD_MIN <= len(w) <= WORD_MAX:
            raise ValueError(f"a word has {WORD_MIN} to {WORD_MAX} characters: {w[:60]}")
        if not ALLOWED.match(w) or not _ALNUM.search(w):
            raise ValueError(f"letters, digits, blanks and . + # & / : ' @ ! - only: {w[:60]}")
        if (f := fold(w)) not in seen:
            seen.add(f)
            out.append(w)
    if len(out) > WORDS_MAX:
        raise ValueError(f"at most {WORDS_MAX} words")
    return out


def folded(values) -> list[str]:  # noqa: ANN001
    """The words as the matching compares them (sorted, each once) – the rules' filter (notify.rule_filter)."""
    return sorted({" ".join(fold(str(v)).split()) for v in values or [] if str(v).strip()})


def _pg(word: str) -> str:
    """One folded word for PostgreSQL's regular expressions: letters and digits as they are, a run of blanks and
    hyphens as either, every other character escaped (a backslash before a sign is that sign)."""
    out = []
    for part in _SEP.split(word):
        out.append("".join(c if c.isalnum() else "\\" + c for c in part))
    return "[-[:space:]]+".join(x for x in out if x)


def pattern(values) -> str | None:  # noqa: ANN001
    """The regular expression (PostgreSQL) for "one of these words, whole" – None: no word."""
    words = [w for w in (_pg(x) for x in folded(values)) if w]
    if not words:
        return None
    return f"(^|[^[:alnum:]])({'|'.join(words)})($|[^[:alnum:]])"


def clause(values) -> ColumnElement | None:  # noqa: ANN001
    """SQL: the story's title or teaser has one of these words – None: no words (no restriction)."""
    p = pattern(values)
    return NewsItem.search.op("~")(p) if p else None


def none_of(values) -> ColumnElement | None:  # noqa: ANN001
    """SQL: the story's title or teaser has none of these words – None: no words."""
    p = pattern(values)
    return NewsItem.search.op("!~")(p) if p else None  # search is never NULL (default "")


def _py(word: str) -> re.Pattern:
    parts = [re.escape(x) for x in _SEP.split(word) if x]
    return re.compile(r"(?<![^\W_])" + r"[-\s]+".join(parts) + r"(?![^\W_])")


def hits(search: str, values) -> list[str]:  # noqa: ANN001
    """Which of the words (as entered) the folded text has – the messages' "Treffer" (the same rule as clause)."""
    out = []
    for v in values or []:
        f = " ".join(fold(str(v)).split())
        if f and _py(f).search(search or ""):
            out.append(str(v))
    return out

