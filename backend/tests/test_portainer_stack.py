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
    script = got["entrypoint"][2]
    names, watch, run = (s.strip() for s in script.split(";"))
    assert names == ". /etc/nginx/cobe-news/16-server-names.envsh"  # sourced: it exports NEWS_SERVER_NAMES
    assert watch == "/bin/sh /etc/nginx/cobe-news/40-cert-watch.sh"
    assert run == 'exec /docker-entrypoint.sh "$$@"'
    assert got["entrypoint"][:2] == ["/bin/sh", "-ec"] and got["command"] == ["nginx", "-g", "daemon off;"]
    assert got["depends_on"]["app"] == want["depends_on"]["app"]
    assert got["depends_on"]["assets"] == {"condition": "service_completed_successfully"}
    assert portainer["services"]["db-init"]["depends_on"]["assets"] == {"condition": "service_completed_successfully"}
    # every file of deploy/nginx the local install mounts is in the volume under the same name
    for vol in want["volumes"]:
        if vol.startswith("./deploy/nginx/"):
            assert (ROOT / vol.split(":", 1)[0]).is_file()


def test_assets_copies_from_the_image_locked_down(portainer):
    svc = portainer["services"]["assets"]
    assert svc["image"] == portainer["services"]["app"]["image"]
    assert svc["network_mode"] == "none" and svc["read_only"] is True and svc["restart"] == "no"
    assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["volumes"] == ["deploy-postgres:/assets/postgres", "deploy-nginx:/assets/nginx"]
    script = svc["command"][0]
    assert "for d in postgres nginx" in script and "chmod -R u=rwX,go=rX" in script and "-mindepth 1 -delete" in script
    assert "$d" not in script.replace("$$d", "")  # compose would fill in a single $ itself


def test_the_image_carries_the_deploy_files():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY deploy/postgres /srv/deploy/postgres" in dockerfile and "COPY deploy/nginx /srv/deploy/nginx" in dockerfile
    assert "COPY deploy/ " not in dockerfile and "COPY deploy " not in dockerfile  # never deploy/certs (an own key)
    assert "deploy/certs" in (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for name in ("db-init.sh", "app-role.sql", "restore-role.sql"):
        assert (ROOT / "deploy" / "postgres" / name).is_file()
