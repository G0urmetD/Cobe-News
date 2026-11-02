"""Readable titles for Vendor News findings – what a card and the drawer show next to the CVE.

The vendor's own title comes first (Palo Alto, Fortinet, Veeam, a CSAF document, CISA's KEV name, the CNA's title of a
CVE 5 record): someone wrote it as a title. An NVD record alone has only its description, which often starts with a
sentence about the product ("Wazuh is a free and open source platform used for …") – that sentence is dropped, the
version preamble too ("Prior to version 4.14.5, …"), and what remains is cut before "allows …": "Heap buffer overflow in
the wazuh-analysisd daemon". Where that gives nothing readable, the weakness (CWE) or the impact the text names stands
there, with the component if the text names one ("Command Injection in the GlobalProtect feature").

Pure functions, no I/O; English like the sources (CWE names are English terms of art)."""

import re

TITLE_MAX = 110

# the weaknesses NVD and the CNAs name most – a short, common name each (CWE-20 "Improper Input Validation" and the
# NVD placeholders say nothing about the impact and are left out)
CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-23": "Path Traversal",
    "CWE-59": "Link Following",
    "CWE-74": "Injection",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Code Injection",
    "CWE-98": "File Inclusion",
    "CWE-113": "HTTP Response Splitting",
    "CWE-119": "Memory Corruption",
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Format String",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Disclosure",
    "CWE-209": "Information Disclosure",
    "CWE-250": "Excessive Privileges",
    "CWE-269": "Privilege Escalation",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Authentication Bypass",
    "CWE-288": "Authentication Bypass",
    "CWE-290": "Authentication Bypass",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-307": "Brute Force",
    "CWE-312": "Cleartext Storage of Sensitive Data",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Weak Encryption",
    "CWE-327": "Broken Cryptography",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Signature Verification",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-400": "Denial of Service",
    "CWE-401": "Memory Leak",
    "CWE-416": "Use After Free",
    "CWE-427": "Uncontrolled Search Path",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Sensitive Data in Log Files",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-639": "Insecure Direct Object Reference",
    "CWE-668": "Exposure of Resource",
    "CWE-670": "Incorrect Control Flow",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-770": "Denial of Service",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-922": "Insecure Storage of Sensitive Data",
    "CWE-1021": "Clickjacking",
    "CWE-1236": "CSV Injection",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Regular Expression Denial of Service",
    "CWE-1336": "Template Injection",
}

# the impact a description names, for records without a usable CWE (checked in this order)
IMPACTS = (
    (re.compile(r"(?i)remote code execution|execute arbitrary (?:code|commands)|arbitrary code execution"), "Remote Code Execution"),
    (re.compile(r"(?i)\bsql injection|execute arbitrary sql"), "SQL Injection"),
    (re.compile(r"(?i)cross[- ]site scripting|\bxss\b|inject arbitrary web script"), "Cross-Site Scripting"),
    (re.compile(r"(?i)cross[- ]site request forgery|\bcsrf\b"), "Cross-Site Request Forgery"),
    (re.compile(r"(?i)server[- ]side request forgery|\bssrf\b"), "Server-Side Request Forgery"),
    (re.compile(r"(?i)command injection"), "Command Injection"),
    (re.compile(r"(?i)path traversal|directory traversal"), "Path Traversal"),
    (re.compile(r"(?i)authentication bypass|bypass (?:the )?authentication"), "Authentication Bypass"),
    (re.compile(r"(?i)privilege escalation|escalate (?:their )?privileges|elevation of privilege|gain (?:root|elevated|administrator) privileges"), "Privilege Escalation"),
    (re.compile(r"(?i)denial of service|\bdos\b|crash"), "Denial of Service"),
    (re.compile(r"(?i)information disclosure|sensitive information|obtain (?:sensitive )?information"), "Information Disclosure"),
    (re.compile(r"(?i)open redirect"), "Open Redirect"),
)

_IDENT = re.compile(r"^\s*(?:(?:CVE-\d{4}-\d{4,7}|PAN-SA-\d{4}-\d{4}|FG-IR-\d{2}-\d{1,5}|KB\d{3,6})\s*(?:[,;]\s*)?)+\s*[:\-–—]?\s*", re.I)
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\"'])")
# "Wazuh is a free and open source platform used for …", "TYPO3 is an open source PHP based web content management system …"
_ABOUT = re.compile(r"^[^.]{1,100}?\b(?:is|are)\s+(?:a|an|the)\s", re.I)
_ABOUT_NOUN = re.compile(
    r"(?i)\b(?:free|open[- ]?source|platform|tool(?:kit)?|software|solution|application|app|framework|system|library|suite|server|cms|"
    r"content management|service|product|plugin|extension|manager|client|agent|engine|implementation|package|module|utility|"
    r"distribution|database|interface|environment|toolchain|runtime)\b"
)
_VULN_WORDS = re.compile(
    r"(?i)vulnerab|overflow|injection|scripting|\bxss\b|traversal|bypass|disclos|deserializ|forgery|csrf|ssrf|execution|escalat|denial|"
    r"use[- ]after[- ]free|race condition|leak|exposure|redirect|upload|improper|missing|incorrect|insecure|weak|hard[- ]?coded|"
    r"out[- ]of[- ]bounds|null pointer|corruption|access control|sanitiz|neutraliz|spoof|hijack|smuggling|xxe|pollution|clickjacking|tampering|crash"
)
# version preambles: "Prior to version 4.14.5, ", "In versions 4.4.0 through 4.14.4, ", "Starting in 2.1 and prior to 2.4.2, "
_PREAMBLE = re.compile(
    r"^(?:(?:starting|beginning) (?:in|with|from) (?:version )?[^,]{1,40}?(?:,| and) )?(?:in |for |on )?(?:versions?|releases?|builds?)?\s*"
    r"(?:prior to|before|until|up to(?: and including)?|through|from)\s[^,]{1,60},\s+",
    re.I,
)
_PREAMBLE2 = re.compile(r"^(?:in|for) (?:versions?|releases?) [^,]{1,60},\s+", re.I)
# where the subject of the sentence ends: "… allows a remote attacker …", "… which lets …"
_CUT = re.compile(
    r",\s|\s(?:allows?|allowing|could allow|can allow|may allow|might allow|could enable|may enable|can enable|could let|lets|enables?|"
    r"which|that|leads? to|leading to|resulting in|results? in|because|due to|when|where|if|exists|existed|was|were|is|are|has been|"
    r"have been|could|can|may|might|would)\b",
    re.I,
)
# words that end a subject after its product name: "… in TYPO3 4.0.13 and earlier" – dropped one by one from the end
_TAIL_WORDS = {"before", "prior", "to", "through", "up", "until", "and", "or", "earlier", "below", "versions", "version", "<", "<=", "=", "x"}
_TAIL_VERSION = re.compile(r"v?\d[\w.\-]{0,30}", re.I)
_GENERIC_LEAD = re.compile(r"(?i)^(?:an? |the )?(?:(?:security |potential )?(?:issue|vulnerability|flaw|problem|bug|weakness)s?)\b(?: (?:was|has been|have been) (?:discovered|found|identified|reported))?(?:\s+(?:in|within|exists in|affecting))?\b")
_COMPONENT = re.compile(
    r"(?:\b(?:in|of|within|via)\s+|^)(the\s+)?((?:[\w./:@-]+\s){0,3}?[\w./:@-]+)\s+"
    r"(component|module|feature|function|functionality|endpoint|plugin|extension|service|daemon|interface|API|page|form|handler|parser|"
    r"subcomponent|subsystem|controller|console|portal|dashboard|library|driver|agent|script|template)\b",
    re.I,
)


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")[:2000]).strip()  # a description is at most 1500 characters (vendor_sources)


def short(text: str, n: int = TITLE_MAX) -> str:
    """Cut at a word boundary, with an ellipsis."""
    t = _clean(text).rstrip(" .;:,")
    if len(t) <= n:
        return t
    cut = t[:n].rsplit(" ", 1)[0].rstrip(" ,;:–-(")
    return f"{cut} …"


def strip_ident(title: str) -> str:
    """"CVE-2024-3400 PAN-OS: Arbitrary File Creation …" → "PAN-OS: Arbitrary File Creation …" (the ID stands beside it)."""
    t = _clean(title)
    out = _IDENT.sub("", t, count=1)
    return out or t


def drop_about(desc: str) -> str:
    """The description without its leading sentences about what the product is."""
    parts = _SENTENCE.split(_clean(desc))
    while len(parts) > 1 and _ABOUT.match(parts[0]) and _ABOUT_NOUN.search(parts[0]) and not _VULN_WORDS.search(parts[0]):
        parts = parts[1:]
    return " ".join(parts)


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:] if s else s


def body(sentence: str) -> str:
    """A sentence without its version preamble ("Prior to version 4.14.5, …")."""
    s = _clean(sentence)
    for _ in range(2):
        s = _PREAMBLE.sub("", s, count=1)
        s = _PREAMBLE2.sub("", s, count=1)
    return s


def lead(sentence: str) -> str:
    """The subject of a description's first sentence: what is wrong, before "allows …" – without the version preamble,
    a leading article and trailing version numbers."""
    s = body(sentence)
    m = _CUT.search(s, 8)
    if m:
        s = s[: m.start()]
    words = s.split(" ")
    while len(words) > 1 and (words[-1].lower() in _TAIL_WORDS or _TAIL_VERSION.fullmatch(words[-1])):
        words.pop()
    s = " ".join(words).rstrip(" .;:,–-(")
    s = re.sub(r"(?i)^(?:a|an|the)\s+", "", s)
    return _cap(s)


def _usable(s: str) -> bool:
    return 12 <= len(s) <= TITLE_MAX and bool(_VULN_WORDS.search(s)) and not _GENERIC_LEAD.fullmatch(s.strip())


def _generic(s: str) -> bool:
    """"An issue was discovered in …", "A vulnerability in …": says nothing about what is wrong."""
    return bool(_GENERIC_LEAD.match(s)) and not re.search(r"(?i)overflow|injection|scripting|traversal|bypass|disclos|deserializ|forgery|execution|escalat|denial|use[- ]after", s)


def cwe_label(cwes: list[str] | None) -> str | None:
    for c in cwes or []:
        name = CWE_NAMES.get(str(c).upper())
        if name:
            return name
    return None


def impact_label(desc: str) -> str | None:
    for rx, name in IMPACTS:
        if rx.search(desc or ""):
            return name
    return None


def component(desc: str, product: str = "") -> str | None:
    """"in the GlobalProtect feature of …" → "the GlobalProtect feature"; not the product itself."""
    for m in _COMPONENT.finditer(_clean(desc)):
        name = m.group(2).strip()
        if not name or _VULN_WORDS.search(name) or name.lower() in ("this", "that", "a", "an", "affected", "vulnerable", "same"):
            continue
        found = f"{name} {m.group(3)}"
        if product and found.lower() == product.lower():
            continue
        return f"{m.group(1) or ''}{found}".strip()
    return None


def _same_start(title: str, desc: str) -> bool:
    """An NVD "title" that is only the start of its description (no title of its own)."""
    t = re.sub(r"[\s…]+$", "", _clean(title)).lower()
    return bool(t) and _clean(desc).lower().startswith(t[: max(20, len(t) - 2)])


def headline(source: str, title: str, desc: str = "", cwes: list[str] | None = None, product: str = "", cna_title: str = "") -> str:
    """The title a person reads first. `source`: paloalto | fortinet | veeam | csaf | nvd; `title` as stored (an NVD
    record: CISA's KEV name or the start of the description); `cna_title`: the CNA's title of a CVE 5 record, if known."""
    if cna_title.strip():
        return short(strip_ident(cna_title))
    t = strip_ident(title)
    if source != "nvd" and t:
        return short(t)
    if t and desc and not _same_start(t, desc):
        return short(t)  # CISA's name of an exploited vulnerability ("Palo Alto Networks PAN-OS Command Injection …")
    text = drop_about(desc or title)
    sentences = _SENTENCE.split(text, maxsplit=2) if text else [""]
    first = sentences[0]
    if len(sentences) > 1 and _generic(first):
        first = sentences[1]  # "An issue was discovered in TYPO3 before 13.4.5. Missing authorization checks in …"
    subject = lead(first)
    if _usable(subject) and not _generic(subject):
        return short(subject)
    label = cwe_label(cwes) or impact_label(text)
    if label:
        comp = component(body(first), product)
        return short(f"{label} in {comp}" if comp else label)
    return short(first or t)
