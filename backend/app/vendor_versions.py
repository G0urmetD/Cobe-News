"""Version strings of vendor products – parsed into comparable keys, per version scheme.

A key is a tuple of ints; shorter keys are padded with zeros when compared ("8.5" == "8.5.0"). Pre-releases get negative
markers so they sort before the release ("1.2.0-rc1" < "1.2.0"). Schemes:

- ``panos``    PAN-OS / Panorama: ``11.2.4-h23`` → (11, 2, 4, 23). A hotfix is the fourth part: 11.2.4-h23 > 11.2.4-h4 > 11.2.4.
- ``fortios``  FortiOS and the other Forti products: ``7.4.3``, also ``v7.4.3 build2573`` / ``7.4.3,build2573``.
- ``cisco``    ASA ``9.18(4)22`` (= 9.18.4.22), FTD ``7.2.5.1``, IOS XE ``17.9.4a`` (letter = one more part), NX-OS ``10.2(5)``.
- ``windows``  build numbers ``10.0.20348.2762`` (or ``20348.2762``); a KB number cannot be compared (no table of all KBs).
- ``vmware``   ``8.0 U3c`` / ``8.0.3`` / ``8.0 Update 3c`` – ESXi and vCenter. A patch of the GA release is a letter on the
               line (``8.0c``, vCenter ``7.0.0d``): 8.0 < 8.0a < 8.0c < 8.0 U1. From 9.0 on the four-part version is the
               release (``9.0.2.0100``). vCenter's four-part ``8.0.3.00400`` and build numbers (``24322831``,
               ``8.0.3-24022510``) are not parsed here – app/vmware_builds.py looks them up when they are entered.
- ``ivanti``   ``22.7R2.3`` → (22, 7, 2, 3).
- ``veeam``    Veeam builds ``12.3.2.4934`` (four parts; old cumulative patches ``11.0.1.1261 P20240304`` a fifth),
               also ``13.1.2 (build 13.1.2.57)`` (the build counts). A short ``12.3.2`` is taken – it stands for every
               build of 12.3.2, and the matching only decides what holds for all of them (vendor_match.evaluate).
               ``12.3.2 P4`` does not parse: which build a patch number is, the KB says, not the number.
- ``sfos``     Sophos Firewall: ``21.0.1.272``, ``SFOS 21.0.1 MR-1-Build272``, ``21.0 MR1`` (MR n = the third part),
               ``21.0.0 GA-Build169`` → (21, 0, 1, 272) / (21, 0, 1) / (21, 0, 0, 169). Not the generic rule: there
               ``21.0 MR1`` and ``21.0.1 MR-1`` would be different versions.
- ``java``     Oracle Java SE: ``1.8.0_411``, ``8u411``, ``Java 8 Update 411``, ``1.8.0 update411`` (NVD's jre:1.8.0:
               update411) are all (8, 0, 411) – the same form as 11.0.23 → (11, 0, 23); ``21.0.5+11`` drops the build.
- ``sap``      SAP component releases as SAP's records write them: ``S4CORE 108``, ``SAP_BASIS 758``, ``758``, and the
               NetWeaver release ``7.58`` (= SAP_BASIS 758) → (758,); a support package ``SP02`` is one more part. The
               product release (S/4HANA ``2023``) is no component release – refused.
- ``distro``   a Linux distribution release (``12``, ``9.4``, ``22.04``): its packages decide, not this number.
- ``cloud``    a service the vendor runs: no version on the customer side.
- ``generic``  anything else with digits: numbers and letters (``1.0.2u``, ``9.8p1``, ``2.4.62``, ``14.1-29.72``).

Never guessed: a string that does not parse gives None and the caller says "möglicherweise betroffen".

`parse` reads advisory data and stored versions leniently (a word between numbers is a separator). What an admin types
is checked strictly as well (`validate` → `strict_problem`): a word standing on its own before a number must be a
separator word (``Update 3``, ``build 2573``) – "iLO 6 v1.62" or "MX 18.211.5" would otherwise turn the product's model
number into the first part of the version. The product layer (app/version_input.py) strips the product's own name first.
"""

import re
from dataclasses import dataclass
from functools import lru_cache, total_ordering

SCHEMES = ("panos", "fortios", "cisco", "windows", "vmware", "ivanti", "veeam", "sfos", "java", "sap", "distro", "cloud", "generic")
PRE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "pre": -1, "preview": -1, "rc": -1, "cr": -1, "ea": -1}
# words that only separate parts ("8.0 Update 3", "21.0 MR1", "11.2.4-h23", "22.7R2", "SP3", "CU14", "build 2573")
MILESTONE = {"m", "milestone"}  # only after "-" or "." and before a number: Maven's 7.0.0-M1
SEPARATORS = {"h", "hotfix", "u", "update", "r", "mr", "sp", "cu", "su", "p", "patch", "build", "b", "ga", "release", "fp", "pl", "v", "version"}
# words after the version that say nothing about it: GitLab 17.4.1-ee, Junos 23.2R2-S1-EVO, SonicWall 10.2.1.15-81sv,
# Checkmk 2.3.0p34.cee (its editions cre/cee/cce/cme/cse), NetScaler 14.1-29.72.nc, Citrix 2402 LTSR CU1
TRAILING_IGNORED = {
    "ga", "lts", "ltsr", "final", "release", "stable", "esr", "lts-sts", "ee", "ce", "evo", "sv", "nc",
    "cre", "cee", "cce", "cme", "cse", "fips", "ndcpp",
}  # fmt: skip
# a platform after the version (131.0.2903.86 x64, 24.7.12_4-amd64, "(X64)") – the tokenizer would split x64 into a word
# and the number 64 (a part more), so it is cut before
_PLATFORM = re.compile(r"(?:[\s_.\-]+\(?|\s*\()(?:x86[_-]64|x64|x86|amd64|arm64|aarch64|win64|win32|64-?bit|32-?bit)\)?$", re.I)
# a word standing on its own before a number that only separates parts – what `strict_problem` lets through
SEPARATOR_WORDS = SEPARATORS | {"upd", "rel", "hf", "ru", "ep", "up", "cp", "core", "s", "take", "fixpack", "service", "pack", "sr", "tp", "lts", "ltsr", "esr"} | set(PRE)
MAX_LEN = 64


@total_ordering
@dataclass(frozen=True)
class V:
    """A parsed version: `key` compares, `depth` says how many parts were given (11.2 vs 11.2.4-h23)."""

    key: tuple[int, ...]
    text: str

    @property
    def depth(self) -> int:
        return len(self.key)

    def _pad(self, other: "V") -> tuple[tuple[int, ...], tuple[int, ...]]:
        n = max(len(self.key), len(other.key))
        return self.key + (0,) * (n - len(self.key)), other.key + (0,) * (n - len(other.key))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, V):
            return NotImplemented
        a, b = self._pad(other)
        return a == b

    def __lt__(self, other: "V") -> bool:
        a, b = self._pad(other)
        return a < b

    def __hash__(self) -> int:
        k = list(self.key)
        while k and k[-1] == 0:
            k.pop()
        return hash(tuple(k))

    def startswith(self, prefix: "V") -> bool:
        """11.2.4-h23 is in the line 11.2 (and in 11.2.4); 11.20 is not in 11.2."""
        n = len(prefix.key)
        return (self.key + (0,) * max(0, n - len(self.key)))[:n] == prefix.key if n else True  # 7.4 is in 7.4.0

    def __str__(self) -> str:
        return self.text


def strip_platform(text: str) -> str:
    """131.0.2903.86 x64 → 131.0.2903.86 (the platform is no part of the version)."""
    return _PLATFORM.sub("", text).strip()


def strict_problem(text: str) -> bool:
    """Whether a typed version has a word of its own before a number that is no separator word ("iLO 6 v1.62",
    "MX 18.211.5", "Exchange 2019 CU15") – parse() would skip the word and read the model number as a version part.
    Glued words (22.4R3-S5, 1.37-eks-4, R81.20, pc.7.6.0.8) and separator words (8.0 Update 3, 6.4 build 6402) pass."""
    s = strip_platform(re.sub(r"\s+", " ", (text or "").strip().lower()))
    s = re.sub(r"^(?:v(?=\d)|version\s*:?\s*)", "", s)
    for m in re.finditer(r"(?:^|(?<=[\s(,;]))([a-z]+)(?=\s+v?\d)", s):
        if m.group(1) not in SEPARATOR_WORDS:
            return True
    return False


def _generic_key(text: str) -> tuple[int, ...] | None:
    s = strip_platform(text.strip().lower())
    if not s or len(s) > MAX_LEN or not re.search(r"\d", s) or ":" in s:
        return None  # "1:2.3" is a Debian epoch, not the version 1.2.3
    s = re.sub(r"^(?:v(?=\d)|version\s+)", "", s)
    spans = [(m.group(0), m.start(), m.end()) for m in re.finditer(r"\d+|[a-z]+", s)]
    out: list[int] = []
    for i, (tok, at, end) in enumerate(spans):
        nxt = spans[i + 1] if i + 1 < len(spans) else None
        prev = spans[i - 1] if i else None
        if tok.isdigit():
            if len(tok) > 12:
                return None
            out.append(int(tok))
            continue
        follows_number = prev is not None and prev[0].isdigit()
        before_number = nxt is not None and nxt[0].isdigit()
        # "3.13.0b2": a or b glued between two numbers is a pre-release; "11.2.4-h23", "9.8p1", "22.7R2" separate parts
        glued = follows_number and before_number and prev[2] == at and nxt[1] == end
        if tok in PRE and before_number and (tok not in ("a", "b") or glued):
            out.append(PRE[tok])  # 1.2.0-rc1, 3.13.0b2 – before the release
        elif tok in MILESTONE and before_number and follows_number and s[at - 1 : at] in ("-", "."):
            out.append(PRE["beta"])  # Maven: 7.0.0-M1, 11.0.0-M26 – a milestone before the release (not IOS' 15.2(4)M1)
        elif tok in PRE and nxt is None and tok not in ("a", "b"):
            out.append(PRE[tok])  # 1.2.0-beta
        elif before_number:
            continue  # a separator word: 11.2.4-h23, 8.0 U3, 22.7R2.3, 9.8p1, SP3, CU14, build 2573
        elif len(tok) == 1 and follows_number and prev[2] == at:
            out.append(ord(tok) - 96)  # 17.9.4a, 1.0.2u, 8.0 U3c: one more part (glued to its number)
        elif tok in TRAILING_IGNORED or tok in SEPARATORS:
            continue
        else:
            return None  # a word we do not know – not compared rather than compared wrongly
    return tuple(out) if out else None


_PANOS = re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{1,3})(?:[-.]?h(\d{1,3}))?$", re.I)
_ASA = re.compile(r"^(\d+)\.(\d+)\((\d+)\)(\d+)?(?:\.(\d+))?$")  # 9.18(4)22, 9.16(4)48.1? (interim)
_NXOS = re.compile(r"^(\d+)\.(\d+)\((\d+)([a-z]?)\)$", re.I)  # 10.2(5), 9.3(12), 7.0(3)I7(9) is not taken
_WIN = re.compile(r"^(?:10\.0\.)?(\d{5})\.(\d{1,6})$")
# winver: "Version 24H2 (OS Build 26100.2605)", "OS Build 26100.2605", "Build 26100.2605"
_WIN_OS_BUILD = re.compile(r"^(?:version\s+\w+\s*\()?\s*(?:os\s*)?build\s*:?\s*((?:10\.0\.)?\d{5}\.\d{1,6})\s*\)?$", re.I)
# classic IOS: 15.9(3)M9, 12.2(55)SE12, 15.2(7)E10, 15.1(2)SY16 – release (rebuild) and train letters
_IOS = re.compile(r"^(\d{1,2})\.(\d{1,2})\((\d{1,3})([a-z]?)\)([a-z]{1,3})(\d{0,3})([a-z]?)$", re.I)
IOS_TRAIN_FROM = 100  # the train letters as a number above every release part: (15, 9, 3, <train>, 9)
_FTD_BUILD = re.compile(r"\s*\(\s*build\s*\d{1,6}\s*\)$", re.I)  # FTD/FMC "show version": 7.2.5 (build 208)
_KB = re.compile(r"^kb\s?\d{6,8}$", re.I)
_IVANTI = re.compile(r"^(\d+)\.(\d+)\s*r(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\s*(?:build\s*)?(\d+))?$", re.I)
_VEEAM = re.compile(r"^(\d{1,3}(?:\.\d{1,6}){1,4})(?:\s*(?:p|patch)\s*(\d{8}))?$", re.I)  # 12.3.2.4934, 11.0.1.1261 P20240304
_VEEAM_BUILD = re.compile(r"\bbuild\s*(\d{1,3}(?:\.\d{1,6}){3,4})\s*\)?$", re.I)  # "13.1.2 (build 13.1.2.57)"
VEEAM_BUILD_DEPTH = 4
_VMW = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?([a-z])?(?:\s*(?:u|update)\s*(\d+)\s*([a-z])?)?(?:\s*(?:p|patch)\s*(\d+))?$", re.I)
_VMW9 = re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{1,5})$")  # vSphere 9: 9.0.2.0100 is the release
VMW_FOUR_FROM = 9  # before 9.0 a four-part version is vCenter's appliance version – a build, looked up (app/vmware_builds.py)
# Sophos Firewall: 21.0.1.272 · SFOS 21.0.1 MR-1-Build272 · 21.0 MR1 · 21.0 MR1 (21.0.1) · 21.0.0 GA-Build169
_SFOS = re.compile(
    r"^(?:sfos\s*)?v?(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?(?:\.(\d{1,5}))?"
    r"(?:\s*[-_]?\s*(?:(ga)|mr\s*-?\s*(\d{1,2})))?(?:\s*[-_]?\s*(?:build|b)\s*-?\s*(\d{1,5}))?"
    r"(?:\s*\((\d{1,2})\.(\d{1,2})\.(\d{1,2})\))?$",
    re.I,
)
# Oracle Java SE: 1.8.0_411(-b09), 8u411(-b09, b33, -perf), "8 Update 411", NVD's "1.8.0 update411" – all (8, 0, 411)
_JAVA_PREFIX = re.compile(r"^(?:oracle\s+)?(?:java(?:\s*\(tm\))?(?:\s*se)?(?:\s*(?:jdk|jre|runtime environment|development kit))?\s*:?\s*)", re.I)
# (line, sub, update): 1.8.0_411 → (8, 0, 411), 1.4.2_42 → (4, 2, 42), 5.0u85 → (5, 0, 85)
_JAVA_OLD = (
    re.compile(r"^1\.(\d{1,2})\.(\d)(?:[_.](\d{1,4}))?(?:[-.]?b\d{1,3})?(?:-perf)?$", re.I),
    re.compile(r"^(\d{1,2})(?:\.(0))?u(\d{1,4})(?:[-.]?b\d{1,3})?(?:-perf)?$", re.I),
    re.compile(r"^(\d{1,2})()\s+update\s*(\d{1,4})$", re.I),
    re.compile(r"^1\.(\d{1,2})\.(\d)\s+update\s*_?\s*(\d{1,4})$", re.I),
)
_SAP = re.compile(
    r"^(?:sap[_ ]?)?(?:[a-z][a-z0-9_]{1,15}\s*[_ ]\s*)?(?:(\d)\.(\d{1,2})|(\d{3}))(?:\s*[,;]?\s*(?:sp|support\s+package)\s*(\d{1,4}))?$", re.I
)
_JAVA_NEW = re.compile(r"^(\d{1,2}(?:\.\d{1,4}){0,4})(?:[+]\d{1,4})?(?:-perf)?$", re.I)  # 21.0.5, 21.0.5+11, 24


@lru_cache(maxsize=65536)
def parse(scheme: str, text: str) -> V | None:
    """The version in this scheme, or None (not comparable – the caller must not decide on it). Cached: the matching
    parses the same bounds of the same records for every version and candidate (V is immutable)."""
    if not isinstance(text, str):
        return None
    t = re.sub(r"\s+", " ", (text or "").strip())
    if not t or len(t) > MAX_LEN:
        return None
    if scheme == "cloud":
        return None
    if scheme == "panos":
        m = _PANOS.match(t)
        if not m:
            return None
        a, b, c, h = (int(x) if x else 0 for x in m.groups())
        return V((a, b, c, h), f"{a}.{b}.{c}" + (f"-h{h}" if m.group(4) else ""))
    if scheme == "windows":
        if m := _WIN_OS_BUILD.match(t):
            t = m.group(1)
        m = _WIN.match(t)
        if not m:
            return None
        return V((10, 0, int(m.group(1)), int(m.group(2))), f"10.0.{int(m.group(1))}.{int(m.group(2))}")
    if scheme == "sfos":
        return _sfos(t)
    if scheme == "java":
        return _java(t)
    if scheme == "sap":
        if m := _SAP.match(t):
            rel = int(m.group(1) + m.group(2).ljust(2, "0")) if m.group(1) else int(m.group(3))  # 7.5 = 7.50 = 750
            return V((rel,) + ((int(m.group(4)),) if m.group(4) else ()), t)
        return None
    if scheme == "cisco":
        t = _FTD_BUILD.sub("", t)
        if m := _ASA.match(t):
            parts = [int(x) for x in m.groups() if x]
            return V(tuple(parts), t)
        if m := _NXOS.match(t):
            a, b, c, letter = m.groups()
            key = (int(a), int(b), int(c)) + ((ord(letter.lower()) - 96,) if letter else ())
            return V(key, t)
        if m := _IOS.match(t):
            # classic IOS: comparable within its train only (vendor_match.evaluate never says "not affected" from it)
            a, b, c, c_letter, train, rebuild, letter = m.groups()
            code = IOS_TRAIN_FROM + sum((ord(ch) - 96) * 27**i for i, ch in enumerate(reversed(train.lower())))
            key = (int(a), int(b), int(c) * 27 + (ord(c_letter.lower()) - 96 if c_letter else 0), code, int(rebuild or 0))
            return V(key + ((ord(letter.lower()) - 96,) if letter else ()), t)
        if "(" in t:
            return None  # "7.0(3)I7(9)": a train letter we cannot compare – not read as 7.0.3.7.9 by the generic rule
    if scheme == "ivanti":
        if m := _IVANTI.match(t):
            parts = [int(x) if x else 0 for x in m.groups()[:5]]
            return V(tuple(parts), t)
        return None
    if scheme == "veeam":
        if m := _VEEAM_BUILD.search(t):
            t = m.group(1)
        m = _VEEAM.match(t)
        if not m:
            return None
        key = tuple(int(x) for x in m.group(1).split("."))
        if m.group(2):
            if len(key) != VEEAM_BUILD_DEPTH:
                return None  # a patch date belongs to a full build (11.0.1.1261 P20240304)
            key += (int(m.group(2)),)
        return V(key, m.group(1) + (f" P{m.group(2)}" if m.group(2) else ""))
    if scheme == "vmware":
        if (m := _VMW9.match(t)) and int(m.group(1)) >= VMW_FOUR_FROM:
            return V(tuple(int(x) for x in m.groups()), t)
        if m := _VMW.match(t):
            a, b, c, ga_letter, upd, letter, patch = m.groups()
            if c is not None and upd is not None:
                return None  # "8.0.3 U3" – two ways of saying the update at once
            if ga_letter and (upd is not None or (c or "0") != "0"):
                return None  # "8.0a U1", "8.0.3a": a letter on the GA line only (8.0c, 7.0.0d) – 8.0 U3c says the update
            u = int(upd) if upd is not None else int(c or 0)
            letter = letter or ga_letter
            key = (int(a), int(b), u) + ((ord(letter.lower()) - 96,) if letter else ((0,) if patch else ()))
            if patch:
                key += (int(patch),)
            return V(key, t)
        return None
    if scheme == "fortios":
        # GUI "v7.4.3 build2573 (GA.F)", CLI "FortiGate-60F v7.4.3,build2573,240201 (GA.F)": the model, the build date
        # and the maturity say nothing about the version; the build number follows the version 1:1
        t2 = re.sub(r"\s*\((?:ga|feature|mature|interim|beta)[.\w]*\)$", "", t, flags=re.I)
        t2 = re.sub(r"^forti[a-z]*(?:-[\w-]+)?\s+", "", t2, flags=re.I)
        t2 = re.sub(r"[ ,]*\bbuild\s*\d+(?:\s*,\s*\d{6})?$", "", t2, flags=re.I)
        if m := re.match(r"^v?(\d+)\.(\d+)\.(\d+)\.\d{3,5}$", t2):
            t2 = ".".join(m.groups())  # FortiClient 7.4.2.1737: the fourth part is the build
        m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", t2, re.I)
        if m:
            return V(tuple(int(x) for x in m.groups()), t2.lstrip("vV"))
        m = re.match(r"^v?(\d+)\.(\d+)$", t2, re.I)
        return V(tuple(int(x) for x in m.groups()), t2.lstrip("vV")) if m else None
    key = _generic_key(t)
    return V(key, t) if key else None


def ios_classic(text: str) -> bool:
    """15.9(3)M9, 12.2(55)SE12: a classic IOS release with its train (comparable within the train only)."""
    return bool(_IOS.match(re.sub(r"\s+", " ", (text or "").strip())))


def _sfos(t: str) -> V | None:
    m = _SFOS.match(t)
    if not m:
        return None
    a, b, c, build4, ga, mr, build, pa, pb, pc = m.groups()
    if ga and mr:
        return None
    if mr is not None:
        if c is not None and int(c) != int(mr):
            return None  # "21.0.2 MR-1": two different maintenance releases
        c = mr
    if build4 is not None and build is not None:
        return None  # the build said twice
    key = (int(a), int(b), int(c or 0))
    if pa is not None and (int(pa), int(pb), int(pc)) != key:
        return None  # "21.0 MR1 (21.0.2)"
    if (b4 := build4 or build) is not None:
        key += (int(b4),)
    return V(key, ".".join(str(x) for x in key))


def _java(t: str) -> V | None:
    t = _JAVA_PREFIX.sub("", t).strip()
    for rx in _JAVA_OLD:
        if m := rx.match(t):
            line, sub, upd = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
            if sub:
                return V((line, sub, upd), f"1.{line}.{sub}_{upd}")  # 1.4.2_42: Java before 5 had a minor of its own
            return V((line, 0, upd), f"{line}u{upd}" if upd else f"{line}")
    if m := _JAVA_NEW.match(t):
        key = tuple(int(x) for x in m.group(1).split("."))
        return V(key, m.group(1))
    return None


def from_cpe(scheme: str, version: str, update: str = "*") -> tuple[V | None, bool]:
    """A version of a CPE (version + update field) in this scheme – and whether the update field was "any" (*): then
    the CPE stands for every hotfix/update of that version (less precise than an installed 11.2.4-h23)."""
    version = (version or "").replace("\\", "")
    update = (update or "*").replace("\\", "").lower()
    if version in ("*", "-", ""):
        return None, True
    any_update = update in ("*", "")
    if update in ("*", "-", "", "na"):
        text = version
    elif scheme == "panos" and re.fullmatch(r"h\d+", update):
        text = f"{version}-{update}"
    elif scheme == "vmware":
        m = re.fullmatch(r"update_?(\d+)([a-z]?)|u(\d+)([a-z]?)", update)
        if not m:
            return (None if update not in ("ga",) else parse(scheme, version)), False
        n, letter = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        text = f"{version} U{n}{letter}"
    elif scheme == "ivanti":
        text = f"{version}{update.upper()}"
    else:
        text = f"{version} {update.replace('_', ' ')}"
    return parse(scheme, text), any_update


def validate(scheme: str, text: str) -> tuple[bool, str, str]:
    """(ok, normalised text, reason) for the version field of a followed product. Reasons: empty | too_long | kb |
    format | cloud. The UI shows the scheme's example next to it."""
    t = re.sub(r"\s+", " ", (text or "").strip())
    if not t:
        return False, "", "empty"
    if len(t) > MAX_LEN:
        return False, t, "too_long"
    if scheme == "cloud":
        return False, t, "cloud"
    if scheme == "windows" and _KB.match(t):
        return False, t, "kb"
    v = parse(scheme, t)
    if v is None:
        return False, t, "format"
    if scheme == "generic" and strict_problem(t):
        return False, t, "format"  # "iLO 6 v1.62": a word of its own before a number (strict_problem)
    if scheme == "generic" and (p := strip_platform(t)) != t:
        t = p  # 131.0.2903.86 x64 → 131.0.2903.86
    return True, v.text if scheme in ("panos", "windows", "veeam", "sfos", "java", "fortios") else t, ""


EXAMPLES = {
    "panos": "11.2.4-h23",
    "fortios": "7.4.8",
    "cisco": "9.18(4)22 · 17.9.4a",
    "windows": "10.0.20348.2762",
    "vmware": "8.0 U3c",
    "ivanti": "22.7R2.3",
    "veeam": "12.3.2.4934",
    "sfos": "21.0.1.272",
    "java": "21.0.5 · 8u411",
    "sap": "S4CORE 108 · SAP_BASIS 758",
    "distro": "12 · 9.4 · 24.04",
    "cloud": "",
    "generic": "8.3.14",
}


# ---------------------------------------------------------------- ranges


def in_range(v: V, *, start: V | None = None, start_incl: bool = True, end: V | None = None, end_incl: bool = False) -> bool:
    if start is not None and (v < start or (not start_incl and v == start)):
        return False
    if end is not None and (v > end or (not end_incl and v == end)):
        return False
    return True


# Windows: which build belongs to which product name in the CPE dictionary (NVD lists Windows CVEs per release)
WINDOWS_SERVER = {14393: "windows_server_2016", 17763: "windows_server_2019", 20348: "windows_server_2022", 25398: "windows_server_2022_23h2", 26100: "windows_server_2025"}
WINDOWS_CLIENT = {
    14393: "windows_10_1607",
    17763: "windows_10_1809",
    19044: "windows_10_21h2",
    19045: "windows_10_22h2",
    22621: "windows_11_22h2",
    22631: "windows_11_23h2",
    26100: "windows_11_24h2",
    26200: "windows_11_25h2",
}


def windows_cpe(product_key: str, v: V) -> str | None:
    """The CPE product of a Windows build (10.0.20348.x → windows_server_2022); None: a build we do not know."""
    if len(v.key) < 3:
        return None
    table = WINDOWS_CLIENT if product_key == "windows" else WINDOWS_SERVER  # Windows Server, Hyper-V
    name = table.get(v.key[2])
    return f"cpe:2.3:o:microsoft:{name}" if name else None
