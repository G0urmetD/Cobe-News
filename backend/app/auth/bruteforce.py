"""Brute-force protection (in-process, no Redis – one app process):
- per account: 5 failures in 15 minutes lock it for 15 minutes (doubling up to 2 hours on repeated locks),
- per client address: 30 failures in 15 minutes across at least 5 different names (password spraying) block it for
  30 minutes – typos of one person only ever lock that one account,
- a growing delay after each failure (per account and per address + name), one check at a time per account and address.
The emergency admin is never locked (anyone could lock it from outside), and its correct sign-in is never refused for its
address either: behind NAT or a Docker gateway every client can share one address, and a blocked address must not
lock the last way in. Instead its checks have an hourly budget of failures (from anywhere); beyond it every check waits
a few seconds first and only one runs at a time, across all addresses (`emergency_brake`).
A shared address (the Docker gateway – under Docker Desktop every client arrives from it –, a trusted proxy,
SHARED_ADDRESSES; netaddr.shared_address) is never blocked: spraying through it is slowed down instead.
The client address is the one the bundled nginx reports (X-Forwarded-For only from it, see deps.client_ip). Addresses
count per `source_key`: an IPv4 address on its own, an IPv6 address by its /64 – one connection or host is usually handed a
whole /64, so counting single IPv6 addresses would give an attacker as many fresh addresses as he likes. An IPv4-mapped
IPv6 address counts as the IPv4 address. A shared address keeps a key of its own (it is never blocked, its neighbours in
the /64 are).
Accounts are counted by `lock_key`: local:<name> or ldap:<objectGUID> / entra:<object id> – a directory sign-in that is
refused never locks the local account of the same name. Names are compared NFKC-normalised and case-folded.
Every counter keeps only its newest KEEP failures – more than any limit here needs: an attempt on a locked account is
answered at once (no password check, no delay), so its count must cost the same small time however long the flood.
The counters live in this process only (one app process, by design) – a restart forgets them. The locks and blocks they
set do not: each new one (and each admin unlock) is noted here (`take_dirty`) and written by app/auth/lock_store.py to
the table auth_locks, which the next start reads back (`restore`)."""

import asyncio
import ipaddress
import time
import unicodedata
from contextlib import asynccontextmanager
from dataclasses import dataclass

ACCOUNT_MAX = 5
ACCOUNT_WINDOW = 15 * 60
ACCOUNT_LOCK = 15 * 60
LOCK_FACTOR_MAX = 8
V6_PREFIX = 64  # IPv6 addresses count per /64 (source_key)
IP_MAX = 30
IP_MIN_NAMES = 5  # distinct names among them – one person mistyping is not an attack on everyone
IP_WINDOW = 15 * 60
IP_BLOCK = 30 * 60
DELAY_STEP = 0.3  # s per failure, at most DELAY_MAX (tests set 0)
DELAY_MAX = 3.0
SPRAY_DELAY = 3.0  # each failure through a shared address beyond the address limit (it is never blocked)
EMERGENCY_BUDGET = 20  # failed checks of the emergency admin per hour, from anywhere
EMERGENCY_WINDOW = 3600
EMERGENCY_SLOW = 3.0  # beyond the budget: each check waits this long first, one at a time across all addresses
KEEP = 256  # failures kept per counter (account, address, address + name) – the newest; every limit above is far below

_acct_fail: dict[str, list[float]] = {}
_acct_lock: dict[str, tuple[float, int]] = {}  # until, how many locks in a row
_ip_fail: dict[str, list[tuple[float, str]]] = {}
_pair_fail: dict[str, list[float]] = {}
_ip_block: dict[str, float] = {}
_gates: dict[str, asyncio.Lock] = {}
_emergency_fail: list[float] = []
_emergency_alerted: list[float] = []  # when the budget was last reported exceeded (at most once per EMERGENCY_WINDOW)
# locks and blocks set or lifted since the last lock_store.flush: "acct:<key>" / "ip:<source key>" → (until on the
# monotonic clock, strikes) or None (lifted)
_dirty: dict[str, tuple[float, int] | None] = {}
_emergency_gate = asyncio.Lock()


@dataclass
class Failure:
    attempts_left: int
    locked_for: int  # s
    ip_blocked: bool
    delay: float
    # the emergency admin's hourly failure budget was just exceeded: the failures of the last hour (0: nothing to report)
    # – at most once per EMERGENCY_WINDOW, a flood cannot turn it into a flood of log lines (auth_api._fail reports it)
    emergency_alert: int = 0


def lock_key(user) -> str:  # noqa: ANN001 - a User (not imported: no cycle)
    """What a known account's failures and lock count on: a directory account by its directory id (typed as "jdoe",
    "JDoe" or "jdoe@corp.example", it is one account and one counter), a local account by its name – in key spaces of
    their own, so a refused AD sign-in never locks the local account "jdoe" and the other way round."""
    source = getattr(user, "auth_source", "local")
    if source == "local":
        return local_key(user.username)
    return f"{source}:{user.external_id}" if getattr(user, "external_id", None) else f"{source}-name:{user.username}"


def local_key(username: str) -> str:
    return f"local:{username}"


def ldap_name_key(username: str) -> str:
    """A directory sign-in under a name the directory does not know (or before it answered)."""
    return f"ldap-name:{username}"


def _key(username: str) -> str:
    return unicodedata.normalize("NFKC", username.strip()).casefold()[:255]


def _recent(store: dict, k: str, window: float) -> list:
    t = time.monotonic()
    v = [x for x in store.get(k, []) if t - (x[0] if isinstance(x, tuple) else x) < window]
    if v:
        store[k] = v
    else:
        store.pop(k, None)
    return v


def _add(store: dict, k: str, window: float, item) -> list:  # noqa: ANN001 - a time or (time, name)
    """One more failure under `k`: the recent ones within `window`, at most the newest KEEP."""
    v = _recent(store, k, window)
    v.append(item)
    if len(v) > KEEP:
        del v[: len(v) - KEEP]
    store[k] = v
    return v


def source_key(ip: str) -> str:
    """What the address counters and blocks are keyed on: an IPv4 address as it is, an IPv6 address as its /64 network
    ("2001:db8:1:2::/64"), an IPv4-mapped IPv6 address (::ffff:192.0.2.1) as the IPv4 address. A shared address
    (netaddr.shared_address – the Docker gateway, a trusted proxy, SHARED_ADDRESSES) keeps its exact address: it is never
    blocked and must not lend that to its /64, nor take a block of the /64. Anything unparsable stays as it is."""
    try:
        a = ipaddress.ip_address(ip.strip().split("%", 1)[0])
    except (ValueError, AttributeError):
        return ip
    if isinstance(a, ipaddress.IPv6Address):
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        if not _shared(str(a)):
            return str(ipaddress.IPv6Network((a, V6_PREFIX), strict=False))
    return str(a)


def locked_for(username: str) -> int:
    until = _acct_lock.get(_key(username), (0.0, 0))[0]
    return max(0, int(until - time.monotonic()))


def ip_blocked(ip: str) -> bool:
    return _ip_block.get(source_key(ip), 0.0) > time.monotonic()


def _shared(ip: str) -> bool:
    from app.netaddr import shared_address

    return shared_address(ip)


def emergency_failures() -> int:
    return len(_recent_list(_emergency_fail, EMERGENCY_WINDOW))


def _recent_list(v: list[float], window: float) -> list[float]:
    t = time.monotonic()
    v[:] = [x for x in v if t - x < window]
    return v


def register_failure(username: str, ip: str, *, lock_account: bool = True, emergency: bool = False) -> Failure:
    t = time.monotonic()
    alert = 0
    if emergency:
        recent = _recent_list(_emergency_fail, EMERGENCY_WINDOW)
        recent.append(t)
        if len(recent) >= EMERGENCY_BUDGET and not (_emergency_alerted and t - _emergency_alerted[-1] < EMERGENCY_WINDOW):
            _emergency_alerted[:] = [t]
            alert = len(recent)
    k = _key(username)
    src = source_key(ip)
    # without a name (an attempt on a locked account, bruteforce._guard): only the address counts – a per-name list of
    # "" would collect every such attempt from everywhere
    fails = _add(_acct_fail, k, ACCOUNT_WINDOW, t) if k else []
    locked = 0
    if lock_account and username and len(fails) >= ACCOUNT_MAX:
        n = _acct_lock.get(k, (0.0, 0))[1] + 1
        locked = ACCOUNT_LOCK * min(2 ** (n - 1), LOCK_FACTOR_MAX)
        _acct_lock[k] = (t + locked, n)
        _acct_fail.pop(k, None)
        _dirty[f"acct:{k}"] = (t + locked, n)
    ipf = _add(_ip_fail, src, IP_WINDOW, (t, k))
    pair = _add(_pair_fail, f"{src}|{k}", ACCOUNT_WINDOW, t) if k else []
    blocked = False
    delay = min(DELAY_STEP * max(len(fails), len(pair)), DELAY_MAX)
    if len(ipf) >= IP_MAX and len({n for _, n in ipf}) >= IP_MIN_NAMES:
        if _shared(src):
            # everyone arrives with this address (Docker gateway, proxy): blocking it would lock everybody out – the
            # failures through it are slowed down instead (the accounts still lock on their own)
            delay = max(delay, SPRAY_DELAY)
        else:
            _ip_block[src] = t + IP_BLOCK
            _ip_fail.pop(src, None)
            _dirty[f"ip:{src}"] = (t + IP_BLOCK, 1)
            blocked = True
    left = 0 if locked else max(ACCOUNT_MAX - len(fails), 1 if not lock_account else 0)
    return Failure(attempts_left=left, locked_for=locked, ip_blocked=blocked, delay=delay, emergency_alert=alert)


def failures(username: str) -> int:
    """The account's failed attempts of the last ACCOUNT_WINDOW – read right before a sign-in succeeds (the audit log
    marks a sign-in after several of them)."""
    k = _key(username)
    return len(_recent(_acct_fail, k, ACCOUNT_WINDOW)) if k else 0


def register_success(username: str) -> None:
    _acct_fail.pop(_key(username), None)


def purge() -> None:
    """Old entries go (hourly): a long-running process must not keep every name and address it ever saw."""
    t = time.monotonic()
    for store, window in ((_acct_fail, ACCOUNT_WINDOW), (_ip_fail, IP_WINDOW), (_pair_fail, ACCOUNT_WINDOW)):
        for k in list(store):
            _recent(store, k, window)
    for k, (until, _n) in list(_acct_lock.items()):
        if until + ACCOUNT_LOCK * LOCK_FACTOR_MAX < t:  # the doubling forgets after the longest lock
            _acct_lock.pop(k, None)
    for k, until in list(_ip_block.items()):
        if until < t:
            _ip_block.pop(k, None)
    _recent_list(_emergency_fail, EMERGENCY_WINDOW)
    for k, lock in list(_gates.items()):
        if not lock.locked():
            _gates.pop(k, None)


def unlock(username: str) -> None:
    k = _key(username)
    _acct_fail.pop(k, None)
    if _acct_lock.pop(k, None) is not None:
        _dirty[f"acct:{k}"] = None


def take_dirty() -> dict[str, tuple[float, int] | None]:
    """The locks and blocks set or lifted since the last call (lock_store.flush writes them)."""
    out = dict(_dirty)
    _dirty.clear()
    return out


def restore(key: str, remaining: float, strikes: int) -> None:
    """A lock or block read back at the start (lock_store.load): `key` as in take_dirty, `remaining` seconds left."""
    if remaining <= 0:
        return
    kind, _, k = key.partition(":")
    until = time.monotonic() + remaining
    if kind == "acct" and k:
        if _acct_lock.get(k, (0.0, 0))[0] < until:
            _acct_lock[k] = (until, max(1, min(int(strikes), 64)))
    elif kind == "ip" and k:
        _ip_block[k] = max(_ip_block.get(k, 0.0), until)


def reset() -> None:
    global _emergency_gate
    _emergency_gate = asyncio.Lock()
    for d in (_acct_fail, _acct_lock, _ip_fail, _pair_fail, _ip_block, _gates, _dirty):
        d.clear()
    _emergency_fail.clear()
    _emergency_alerted.clear()


@asynccontextmanager
async def emergency_brake():
    """The emergency admin is never locked – so beyond EMERGENCY_BUDGET failures in an hour (from any address) each of
    its checks, right or wrong, waits EMERGENCY_SLOW first and only one runs at a time across all addresses: guessing
    from many addresses at once is held to one guess per few seconds, the owner still gets in (a little slower). The
    wait comes before the check, so the answer time tells nothing. Yields False when another check holds the slot (the
    caller answers 429 at once – no request queues up holding a database connection)."""
    if emergency_failures() < EMERGENCY_BUDGET:
        yield True
        return
    if _emergency_gate.locked():
        yield False
        return
    async with _emergency_gate:
        await asyncio.sleep(EMERGENCY_SLOW)
        yield True


@asynccontextmanager
async def gate(username: str, ip: str):
    """One credential check per account and address at a time: parallel guesses queue up behind the delay."""
    k = f"{_key(username)}|{source_key(ip)}"
    lock = _gates.setdefault(k, asyncio.Lock())
    try:
        async with asyncio.timeout(8):
            await lock.acquire()
    except TimeoutError:
        yield False
        return
    try:
        yield True
    finally:
        lock.release()
        if not lock.locked() and len(_gates) > 5000:
            _gates.pop(k, None)
