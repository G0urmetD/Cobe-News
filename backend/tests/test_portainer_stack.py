"""The deployment: three images – the app (Dockerfile), the database (deploy/postgres: PostgreSQL 18 that sets up the app's
role at every start) and the proxy (deploy/nginx: nginx with its configuration) – no one-shot container, nothing of
deploy/ mounted. docker-compose.yml builds them, docker-compose.image.yml and docker-compose.portainer.yml (Portainer's
web editor, no checkout) run the released ones of this version; the release pipeline builds and signs all three.
The Portainer file stays in step with docker-compose.yml: the same settings, hardening and networks; nothing that needs
a checkout (no build, no relative path, no env_file)."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "docker-compose.yml"
PORTAINER = ROOT / "docker-compose.portainer.yml"
IMAGE_OVERRIDE = ROOT / "docker-compose.image.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"

pytestmark = pytest.mark.skipif(not (LOCAL.is_file() and PORTAINER.is_file()), reason="no compose files next to the backend")

SERVICES = {"app", "db", "proxy"}
HARDENING = ("read_only", "cap_drop", "cap_add", "security_opt", "mem_limit", "pids_limit", "tmpfs", "shm_size", "logging", "restart", "user", "healthcheck", "scale")
REGISTRY = "ghcr.io/g0urmetd/cobe-news"
# service → (its image in the registry, the override variable, the local build context, the local image)
IMAGES = {
    "app": (REGISTRY, "COBE_NEWS_IMAGE", ".", "cobe-news:latest"),
    "db": (f"{REGISTRY}-db", "COBE_NEWS_DB_IMAGE", "deploy/postgres", "cobe-news-db:latest"),
    "proxy": (f"{REGISTRY}-proxy", "COBE_NEWS_PROXY_IMAGE", "deploy/nginx", "cobe-news-proxy:latest"),
}
PINNED = re.compile(r"^FROM (\S+:\S+@sha256:[0-9a-f]{64})$", re.M)


class _Loader(yaml.SafeLoader):
    """Compose's own tag `!reset` (docker-compose.image.yml: `build: !reset null`) – read as None."""


_Loader.add_constructor("!reset", lambda loader, node: None)  # noqa: ARG005


def _load(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)  # noqa: S506 - a SafeLoader with one more tag


@pytest.fixture(scope="module")
def local() -> dict:
    return _load(LOCAL)


@pytest.fixture(scope="module")
def portainer() -> dict:
    return _load(PORTAINER)


def _version() -> str:
    from app import __version__

    return __version__


def _required(value: str) -> str:
    """${VAR:?message} → ${VAR:?} – the messages differ (.env there, Portainer's environment variables here)."""
    return re.sub(r"\$\{(\w+):\?[^}]*\}", r"${\1:?}", value)


def _env(svc: dict) -> dict:
    return {k: _required(str(v)) for k, v in svc.get("environment", {}).items()}


def test_three_services_and_nothing_from_a_checkout(local, portainer):
    assert set(local["services"]) == set(portainer["services"]) == SERVICES  # no db-init, no assets (up to 0.1.48)
    assert "name" not in portainer  # Portainer names the stack
    text = PORTAINER.read_text(encoding="utf-8")
    for svc in portainer["services"].values():
        assert "build" not in svc and "env_file" not in svc and "entrypoint" not in svc
        # no fixed names: the stack's containers never clash with a local install (cobe-news-app …) or a second stack
        assert "container_name" not in svc
        for vol in svc.get("volumes", []):
            source = vol.split(":", 1)[0]
            assert not source.startswith((".", "/", "~")), vol  # named volumes (TLS_SOURCE: the user's choice)
    assert not re.search(r"(^|[\s\"'=:])\.\.?/", re.sub(r"#[^\n]*", "", text)), "a relative path in the stack file"
    assert set(portainer["volumes"]) == {"data", "tls", "db18"} and set(local["volumes"]) == {"tls", "db18"}
    # the local install: no bind mount of deploy/ any more – the files are in the images
    for svc in local["services"].values():
        assert not any("deploy/" in v for v in svc.get("volumes", [])), svc.get("volumes")


def test_the_local_install_keeps_its_names(local):
    """scripts/ and the docs use these names; the project name keeps the volumes (cobe-news_db18 …)."""
    assert local["name"] == "cobe-news"
    assert {n: s["container_name"] for n, s in local["services"].items()} == {n: f"cobe-news-{n}" for n in SERVICES}
    for name, (_, _, context, image) in IMAGES.items():
        assert local["services"][name]["build"] == context and local["services"][name]["image"] == image, name


def test_released_images_of_this_version(portainer):
    version = _version()
    for name, (image, var, _, _) in IMAGES.items():
        assert portainer["services"][name]["image"] == f"${{{var}:-{image}:${{COBE_NEWS_VERSION:-{version}}}}}", name
    override = _load(IMAGE_OVERRIDE)["services"]
    assert set(override) == SERVICES
    for name, (image, var, _, _) in IMAGES.items():
        svc = override[name]
        assert re.fullmatch(rf"\$\{{{var}:-{re.escape(image)}:\$\{{COBE_NEWS_VERSION:\?[^}}]+\}}\}}", svc["image"]), svc["image"]
        assert svc["build"] is None and svc["pull_policy"] == "missing"
    assert "!reset null" in IMAGE_OVERRIDE.read_text(encoding="utf-8")


def test_the_same_settings_hardening_and_networks(local, portainer):
    for name in SERVICES:
        want, got = local["services"][name], portainer["services"][name]
        assert _env(got) == _env(want), name
        for key in HARDENING:
            assert got.get(key) == want.get(key), f"{name}: {key}"
        assert got["networks"] == want["networks"] and got.get("ports") == want.get("ports"), name
        assert got.get("depends_on") == want.get("depends_on"), name
        assert got.get("read_only") is True and got.get("security_opt") == ["no-new-privileges:true"] and got.get("cap_drop") == ["ALL"], name
    app, papp = local["services"]["app"], portainer["services"]["app"]
    assert papp["volumes"] == ["data:/data", *app["volumes"][1:]] and app["volumes"][0] == "./data:/data"
    assert app["depends_on"] == {"db": {"condition": "service_healthy"}}
    assert "cap_add" not in app
    assert portainer["services"]["db"]["volumes"] == local["services"]["db"]["volumes"] == ["db18:/var/lib/postgresql"]
    assert portainer["services"]["proxy"]["volumes"] == local["services"]["proxy"]["volumes"] == ["${TLS_SOURCE:-tls}:/etc/nginx/tls:ro"]
    assert portainer["networks"] == local["networks"]
    assert local["networks"]["db"] == {"internal": True}


def test_the_database_is_healthy_only_after_the_role_setup(local):
    db = local["services"]["db"]
    test = " ".join(db["healthcheck"]["test"])
    assert "test -f /var/run/postgresql/.cobe-news-ready" in test and "pg_isready" in test
    assert "/var/run/postgresql" in db["tmpfs"]  # the marker is gone at every start
    script = (ROOT / "deploy" / "postgres" / "cobe-news-db.sh").read_text(encoding="utf-8")
    assert "ready=/var/run/postgresql/.cobe-news-ready" in script and 'rm -f "$ready"' in script
    # the marker only after a successful db-init; a failed one stops PostgreSQL and exits 1
    assert re.search(r'db-init\.sh"; then\n\s+: >"\$ready"', script) and "finish 1" in script
    assert "trap stop INT TERM" in script and 'kill -INT "$pg"' in script
    # the app's role and the restore role: the db container has their passwords, the app never the superuser's
    env = db["environment"]
    assert env["POSTGRES_APP_PASSWORD"].startswith("${POSTGRES_APP_PASSWORD:?") and env["POSTGRES_RESTORE_PASSWORD"] == "${POSTGRES_RESTORE_PASSWORD:-}"
    app = local["services"]["app"]["environment"]
    assert app["POSTGRES_USER"] == "cobe_news_app" and app["POSTGRES_PASSWORD"].startswith("${POSTGRES_APP_PASSWORD:?")
    assert not any("${POSTGRES_PASSWORD" in str(v) for v in app.values())


def test_passwords_are_required(portainer):
    services = portainer["services"]
    for value in (services["app"]["environment"]["POSTGRES_PASSWORD"], services["db"]["environment"]["POSTGRES_PASSWORD"], services["db"]["environment"]["POSTGRES_APP_PASSWORD"]):
        assert re.fullmatch(r"\$\{POSTGRES_(APP_)?PASSWORD:\?.+\}", value), value


def test_one_switch_for_an_own_reverse_proxy(local, portainer):
    """PROXY_ENABLED=0 alone: TLS_MODE has no fixed default any more (the app derives external), TRUSTED_PROXIES empty
    (the app trusts its gateway), the app's port on 127.0.0.1 only – what makes trusting the gateway safe."""
    for f in (local, portainer):
        env = f["services"]["app"]["environment"]
        assert env["TLS_MODE"] == "${TLS_MODE:-}" and env["TRUSTED_PROXIES"] == "${TRUSTED_PROXIES:-}"
        assert f["services"]["app"]["ports"] == ["127.0.0.1:${APP_PORT:-8096}:8000"]
        assert f["services"]["proxy"]["scale"] == "${PROXY_ENABLED:-1}"
        # an explicit gateway only when asked for: empty keeps an existing network as it is (a changed IPAM config makes
        # compose re-create the network – it fails while a container of your own is attached to it)
        assert f["networks"]["edge"]["ipam"]["config"][0]["gateway"] == "${EDGE_GATEWAY:-}"
    header = PORTAINER.read_text(encoding="utf-8").split("\nx-logging:", 1)[0]
    blocks = re.findall(r"^# [AB]\) ", header, re.M)
    assert blocks == ["# A) ", "# B) "]
    own, bundled = header.split("# B) ", 1)
    assert "PROXY_ENABLED=0" in own and "proxy_pass http://127.0.0.1:8096" in own and "X-Forwarded-For $remote_addr" in own
    assert "PROXY_ENABLED" not in bundled.split("Recommended", 1)[0]
    for block in (own, bundled):
        assert "POSTGRES_PASSWORD=" in block and "POSTGRES_APP_PASSWORD=" in block and "BASE_URL=https://" in block
    assert "TRUSTED_PROXIES" not in own and "TLS_MODE" not in own  # not needed any more


def test_dockerfiles_pin_their_base_images_and_carry_the_files(local):
    app = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    db = (ROOT / "deploy" / "postgres" / "Dockerfile").read_text(encoding="utf-8")
    proxy = (ROOT / "deploy" / "nginx" / "Dockerfile").read_text(encoding="utf-8")
    for text in (app, db, proxy):
        froms = re.findall(r"^FROM .+$", text, re.M)
        assert froms and all(PINNED.match(re.sub(r"--platform=\S+ ", "", f).split(" AS ")[0]) for f in froms), froms
    assert PINNED.search(db).group(1).startswith("postgres:18-alpine@") and PINNED.search(proxy).group(1).startswith("nginx:1.30-alpine@")
    # the app image no longer carries deploy/ (0.1.48 did, for the assets service)
    assert "deploy" not in re.sub(r"#[^\n]*", "", app) and "/assets" not in app
    assert re.search(r"^deploy$", (ROOT / ".dockerignore").read_text(encoding="utf-8"), re.M)  # never deploy/certs (an own key)
    # the database image: the role set-up as its entrypoint, the fast shutdown on docker stop
    assert 'ENTRYPOINT ["/usr/local/share/cobe-news/cobe-news-db.sh"]' in db and "STOPSIGNAL SIGINT" in db and 'CMD ["postgres"]' in db
    for name in ("cobe-news-db.sh", "db-init.sh", "app-role.sql", "restore-role.sql"):
        assert name in db and (ROOT / "deploy" / "postgres" / name).is_file(), name
    assert 'here/app-role.sql"' in (ROOT / "deploy" / "postgres" / "db-init.sh").read_text(encoding="utf-8")
    # the proxy image: exactly what the local install mounted up to 0.1.48, where nginx's entrypoint takes it
    assert "COPY cobe-news.conf.template /etc/nginx/templates/default.conf.template" in proxy
    assert "COPY --chmod=0755 16-server-names.envsh 40-cert-watch.sh /docker-entrypoint.d/" in proxy
    # each build context lets in only its own files
    for folder, files in (("postgres", {"Dockerfile", "cobe-news-db.sh", "db-init.sh", "app-role.sql", "restore-role.sql"}), ("nginx", {"Dockerfile", "cobe-news.conf.template", "16-server-names.envsh", "40-cert-watch.sh"})):
        lines = [x for x in (ROOT / "deploy" / folder / ".dockerignore").read_text(encoding="utf-8").splitlines() if x and not x.startswith("#")]
        assert lines[0] == "*" and {x.removeprefix("!") for x in lines[1:]} == files, folder
        for f in files:
            assert (ROOT / "deploy" / folder / f).is_file(), f


def test_the_release_builds_and_signs_all_three():
    wf = _load(RELEASE)
    text = RELEASE.read_text(encoding="utf-8")
    env = wf["env"]
    assert (env["IMAGE"], env["DB_IMAGE"], env["PROXY_IMAGE"]) == tuple(i[0] for i in IMAGES.values())
    assert all(v == v.lower() for v in env.values())  # cosign: lower-case names only
    steps = {s.get("id"): s for s in wf["jobs"]["image"]["steps"] if s.get("id")}
    for build, meta, context, var in (("build", "meta", ".", "IMAGE"), ("build-db", "meta-db", "deploy/postgres", "DB_IMAGE"), ("build-proxy", "meta-proxy", "deploy/nginx", "PROXY_IMAGE")):
        w = steps[build]["with"]
        assert w["context"] == context and w["platforms"] == "linux/amd64,linux/arm64" and w["push"] is True
        assert w["provenance"] == "mode=max" and w["sbom"] is True and w["tags"] == f"${{{{ steps.{meta}.outputs.tags }}}}"
        assert steps[meta]["with"]["images"] == f"${{{{ env.{var} }}}}"
        assert "type=semver,pattern={{version}}" in steps[meta]["with"]["tags"]
    sign = next(s for s in wf["jobs"]["image"]["steps"] if s.get("name", "").startswith("Sign"))
    for line in ('cosign sign --yes "${IMAGE}@${DIGEST}"', 'cosign sign --yes "${DB_IMAGE}@${DB_DIGEST}"', 'cosign sign --yes "${PROXY_IMAGE}@${PROXY_DIGEST}"'):
        assert line in sign["run"]
    assert set(wf["jobs"]["image"]["outputs"]) == {"digest", "db-digest", "proxy-digest"}
    # every action pinned by its commit, still one tag-triggered pipeline
    uses = re.findall(r"uses: (\S+)", text)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
    assert wf[True] == {"push": {"tags": ["v[0-9]+.[0-9]+.[0-9]+"]}}  # PyYAML reads the key "on" as True
    assert sorted(p.name for p in RELEASE.parent.iterdir()) == ["release.yml"]


def _tags(text: str) -> list[str]:
    return re.findall(r"ghcr\.io/g0urmetd/cobe-news(?:-db|-proxy)?:([0-9][0-9A-Za-z._-]*)", text) + re.findall(r"COBE_NEWS_VERSION(?::-|=)([0-9][0-9.]*[0-9])", text)


def test_default_version_is_this_version():
    """The stack file of a release starts that release – and the docs name no other one."""
    version = _version()
    tags = _tags(PORTAINER.read_text(encoding="utf-8"))
    assert tags and set(tags) == {version}, tags
    assert set(_tags(IMAGE_OVERRIDE.read_text(encoding="utf-8"))) <= {version}
    betrieb = (ROOT / "docs" / "BETRIEB.md").read_text(encoding="utf-8")
    section = betrieb.split("### Portainer (Stack-Editor)", 1)[1].split("\n## ", 1)[0]
    texts = [section] + [(ROOT / "docs" / "handbuch" / lang / "08-betrieb.md").read_text(encoding="utf-8").split("{#portainer}", 1)[1].split("\n## ", 1)[0] for lang in ("de", "en")]
    for text in texts:
        assert set(_tags(text)) <= {version}, _tags(text)


def test_no_one_shot_containers_left_in_scripts_and_wrong_gateway_advice_gone():
    """The old container cobe-news-db-init is named only where an upgrade removes it; the gateway of the network edge is
    not 172.31.250.1 (with ip_range Docker takes the first address of EDGE_RANGE, 172.31.250.128)."""
    for path in (ROOT / "scripts").iterdir():
        assert "db-init" not in path.read_text(encoding="utf-8"), path
    texts = {p: p.read_text(encoding="utf-8") for p in [ROOT / "docs" / "BETRIEB.md", ROOT / "README.md", ROOT / ".env.example", *sorted((ROOT / "docs" / "handbuch").glob("*/*.md"))]}
    for path, text in texts.items():
        # only as the wrong one ("nicht `172.31.250.1`", "not `172.31.250.1`")
        wrong = re.findall(r"(?<!nicht `)(?<!not `)172\.31\.250\.1(?![0-9])", text)
        assert not wrong and "172.31.250.1/32" not in text, path
        assert "docker compose logs db-init" not in text and "up -d db-init" not in text, path
