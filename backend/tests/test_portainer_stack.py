"""docker-compose.portainer.yml – the stack for Portainer's web editor – stays in step with docker-compose.yml: the same
settings for the app, the same pinned images, the same hardening and networks; nothing that needs a checkout (no
build, no relative path, no env_file); the deploy files come from the app image (Dockerfile: /srv/deploy) through the
one-shot service "assets"."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "docker-compose.yml"
PORTAINER = ROOT / "docker-compose.portainer.yml"

pytestmark = pytest.mark.skipif(not (LOCAL.is_file() and PORTAINER.is_file()), reason="no compose files next to the backend")

HARDENING = ("read_only", "cap_drop", "cap_add", "security_opt", "mem_limit", "pids_limit", "tmpfs", "shm_size", "logging", "restart", "user", "healthcheck")


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def local() -> dict:
    return _load(LOCAL)


@pytest.fixture(scope="module")
def portainer() -> dict:
    return _load(PORTAINER)


def _required(value: str) -> str:
    """${VAR:?message} → ${VAR:?} – the messages differ (.env there, Portainer's environment variables here)."""
    return re.sub(r"\$\{(\w+):\?[^}]*\}", r"${\1:?}", value)


def test_same_services_plus_assets_and_nothing_from_a_checkout(local, portainer):
    assert set(portainer["services"]) == set(local["services"]) | {"assets"}
    assert "name" not in portainer  # Portainer names the stack
    text = PORTAINER.read_text(encoding="utf-8")
    for svc in portainer["services"].values():
        assert "build" not in svc and "env_file" not in svc
        # no fixed names: the stack's containers never clash with a local install (cobe-news-app …) or a second stack
        assert "container_name" not in svc
        for vol in svc.get("volumes", []):
            source = vol.split(":", 1)[0]
            assert not source.startswith((".", "/", "~")), vol  # named volumes (TLS_SOURCE: the user's choice)
    assert not re.search(r"(^|[\s\"'=:])\.\.?/", re.sub(r"#[^\n]*", "", text)), "a relative path in the stack file"


def test_the_app_gets_exactly_the_settings_of_the_local_install(local, portainer):
    want, got = local["services"]["app"], portainer["services"]["app"]
    assert {k: _required(str(v)) for k, v in got["environment"].items()} == {k: _required(str(v)) for k, v in want["environment"].items()}
    assert got["image"].startswith("${COBE_NEWS_IMAGE:-ghcr.io/g0urmetd/cobe-news:") and "latest" not in got["image"]
    assert got["ports"] == want["ports"] and got["networks"] == want["networks"] and got["depends_on"] == want["depends_on"]
    assert got["volumes"] == ["data:/data", *want["volumes"][1:]] and want["volumes"][0] == "./data:/data"
    for key in HARDENING:
        assert got.get(key) == want.get(key), key


def test_same_images_hardening_and_networks(local, portainer):
    for name in ("db", "db-init", "proxy"):
        want, got = local["services"][name], portainer["services"][name]
        assert got["image"] == want["image"] and "@sha256:" in got["image"], name
        for key in HARDENING:
            assert got.get(key) == want.get(key), f"{name}: {key}"
        assert got["networks"] == want["networks"] and got.get("ports") == want.get("ports"), name
    db, pdb = local["services"]["db"], portainer["services"]["db"]
    assert {k: _required(str(v)) for k, v in pdb["environment"].items()} == {k: _required(str(v)) for k, v in db["environment"].items()}
    assert pdb["volumes"] == db["volumes"]
    init, pinit = local["services"]["db-init"], portainer["services"]["db-init"]
    assert pinit["entrypoint"] == init["entrypoint"]
    assert {k: _required(str(v)) for k, v in pinit["environment"].items()} == {k: _required(str(v)) for k, v in init["environment"].items()}
    assert pinit["volumes"] == ["deploy-postgres:/init:ro"] and init["volumes"] == ["./deploy/postgres:/init:ro"]
    assert portainer["networks"] == local["networks"]
    assert set(local["volumes"]) | {"data", "deploy-postgres", "deploy-nginx"} == set(portainer["volumes"])


def test_passwords_are_required(portainer):
    services = portainer["services"]
    for value in (services["app"]["environment"]["POSTGRES_PASSWORD"], services["db"]["environment"]["POSTGRES_PASSWORD"], services["db-init"]["environment"]["PGPASSWORD"]):
        assert re.fullmatch(r"\$\{POSTGRES_(APP_)?PASSWORD:\?.+\}", value), value
    assert re.fullmatch(r"\$\{POSTGRES_APP_PASSWORD:\?.+\}", services["db-init"]["environment"]["POSTGRES_APP_PASSWORD"])


def test_proxy_keeps_nginx_entrypoint_scripts_and_reads_the_deploy_files_from_the_volume(local, portainer):
    want, got = local["services"]["proxy"], portainer["services"]["proxy"]
    # nothing mounted over /docker-entrypoint.d (nginx's own scripts, e.g. 20-envsubst-on-templates.sh, keep running)
    assert not any("/docker-entrypoint.d" in v for v in got["volumes"])
    assert got["volumes"] == ["deploy-nginx:/etc/nginx/cobe-news:ro", "${TLS_SOURCE:-tls}:/etc/nginx/tls:ro"]
    env = got["environment"]
    assert env["NGINX_ENVSUBST_TEMPLATE_DIR"] == "/etc/nginx/cobe-news"
    assert env["COBE_NEWS_ASSETS_FROM"] == portainer["services"]["app"]["image"]  # a new image recreates the proxy
    assert {k: v for k, v in env.items() if k not in ("NGINX_ENVSUBST_TEMPLATE_DIR", "COBE_NEWS_ASSETS_FROM")} == want["environment"]
    steps = [s.strip() for s in got["entrypoint"][2].split(";")]
    assert steps[:2] == [". /etc/nginx/cobe-news/16-server-names.envsh", "/bin/sh /etc/nginx/cobe-news/40-cert-watch.sh"]
    assert steps[-1] == 'exec /docker-entrypoint.sh "$$@"'
    assert got["entrypoint"][:2] == ["/bin/sh", "-ec"] and got["command"] == ["nginx", "-g", "daemon off;"]
    assert got["depends_on"]["app"] == want["depends_on"]["app"]
    assert got["depends_on"]["assets"] == {"condition": "service_completed_successfully"}
    assert portainer["services"]["db-init"]["depends_on"]["assets"] == {"condition": "service_completed_successfully"}
    # every file of deploy/nginx the local install mounts reaches nginx here, too: an entrypoint script (sourced when
    # .envsh, run when .sh – as nginx's entrypoint does) through the wrapper, the template through the template dir
    for vol in want["volumes"]:
        if not vol.startswith("./deploy/nginx/"):
            continue
        source, target = vol.split(":")[:2]
        name = Path(source).name
        assert (ROOT / source).is_file(), source
        if target.startswith("/docker-entrypoint.d/"):
            assert target == f"/docker-entrypoint.d/{name}", vol
            step = f". /etc/nginx/cobe-news/{name}" if name.endswith(".envsh") else f"/bin/sh /etc/nginx/cobe-news/{name}"
            assert step in steps[:-1], f"{name} is mounted for the local install but not run by the stack's proxy"
        elif target.startswith("/etc/nginx/templates/"):
            assert name.endswith(".template"), vol  # 20-envsubst-on-templates.sh only takes *.template from the dir
        else:
            raise AssertionError(f"a deploy/nginx mount the stack does not know: {vol}")
    # and the wrapper runs nothing the local install does not mount
    mounted = {Path(v.split(":")[0]).name for v in want["volumes"] if v.startswith("./deploy/nginx/")}
    assert {s.rsplit("/", 1)[1] for s in steps[:-1]} <= mounted


def test_assets_copies_from_the_image_locked_down(portainer):
    svc = portainer["services"]["assets"]
    assert svc["image"] == portainer["services"]["app"]["image"]
    assert svc["network_mode"] == "none" and svc["read_only"] is True and svc["restart"] == "no"
    assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["volumes"] == ["deploy-postgres:/assets/postgres", "deploy-nginx:/assets/nginx"]
    assert "user" not in svc  # the image's user cobenews – the owner of the fresh volumes (Dockerfile: /assets)
    assert svc["tmpfs"] == ["/data", "/tls"]  # the image's VOLUMEs: no anonymous volumes left behind
    script = svc["command"][0]
    assert "for d in postgres nginx" in script and "chmod -R u=rwX,go=rX" in script and "-mindepth 1 -delete" in script
    assert '[ ! -w "/assets/$$d" ]' in script  # a volume it cannot write: a clear message, not a half copy
    assert "$d" not in script.replace("$$d", "")  # compose would fill in a single $ itself


def test_the_image_carries_the_deploy_files():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY deploy/postgres /srv/deploy/postgres" in dockerfile and "COPY deploy/nginx /srv/deploy/nginx" in dockerfile
    assert "COPY deploy/ " not in dockerfile and "COPY deploy " not in dockerfile  # never deploy/certs (an own key)
    assert "deploy/certs" in (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "mkdir -p /assets/postgres /assets/nginx" in dockerfile and "chown cobenews /assets/postgres /assets/nginx" in dockerfile
    assert re.search(r'VOLUME \["/data", "/tls"\]', dockerfile)  # the reason for the tmpfs of "assets"


def _tags(text: str) -> list[str]:
    return re.findall(r"ghcr\.io/g0urmetd/cobe-news:([0-9A-Za-z._-]+)", text)


def test_default_image_is_this_version():
    """The stack file of a release starts that release – and the docs name no other one."""
    from app import __version__

    tags = _tags(PORTAINER.read_text(encoding="utf-8"))
    assert tags and set(tags) == {__version__}, tags
    betrieb = (ROOT / "docs" / "BETRIEB.md").read_text(encoding="utf-8")
    section = betrieb.split("### Portainer (Stack-Editor)", 1)[1].split("\n## ", 1)[0]
    texts = [section] + [(ROOT / "docs" / "handbuch" / lang / "08-betrieb.md").read_text(encoding="utf-8").split("{#portainer}", 1)[1].split("\n## ", 1)[0] for lang in ("de", "en")]
    for text in texts:
        assert set(_tags(text)) <= {__version__}, _tags(text)
    for name in ("db-init.sh", "app-role.sql", "restore-role.sql"):
        assert (ROOT / "deploy" / "postgres" / name).is_file()
