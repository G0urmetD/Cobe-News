"""The deployment: three images – the app (Dockerfile), the database (deploy/postgres: PostgreSQL 18 that sets up the app's
role at every start) and the proxy (deploy/nginx: nginx with its configuration) – no one-shot container, nothing of
deploy/ mounted. docker-compose.yml builds them, docker-compose.image.yml and docker-compose.portainer.yml (Portainer's
web editor, no checkout) run the released ones of this version; the release pipeline builds and signs all three.
The Portainer file stays in step with docker-compose.yml: the same settings, hardening and networks; nothing that needs
a checkout (no build, no relative path, no env_file)."""

import os
import re
import shutil
import subprocess
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
    # backup-secret: the empty default of BACKUP_SECRET_DIR – the folder with the passphrase file stays optional (0.1.50)
    assert set(portainer["volumes"]) == {"data", "tls", "backup-secret", "db18"} and set(local["volumes"]) == {"tls", "backup-secret", "db18"}
    # the local install: no bind mount of deploy/ any more – the files are in the images
    for svc in local["services"].values():
        assert not any("deploy/" in v for v in svc.get("volumes", [])), svc.get("volumes")


def test_the_backup_passphrase_file_is_optional_in_both(local, portainer):
    """BACKUP_PASSPHRASE_FILE and its folder: a bind mount with an empty source breaks a stack – the default is an empty
    volume of its own, read-only; the variable empty: no passphrase file."""
    for f in (local, portainer):
        app = f["services"]["app"]
        assert "${BACKUP_SECRET_DIR:-backup-secret}:/run/backup-secret:ro" in app["volumes"]
        assert app["environment"]["BACKUP_PASSPHRASE_FILE"] == "${BACKUP_PASSPHRASE_FILE:-}"


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
    assert "trap stop INT TERM" in script and 'kill -INT "$pg"' in script and "trap 'kill -HUP \"$pg\"" in script
    # root only to prepare the data folder, then PID 1 is postgres without capabilities (no su-exec for anything after;
    # su-exec from Alpine instead of the base image's gosu, built with an old Go – deploy/postgres/Dockerfile)
    code = [x.strip() for x in script.splitlines() if x.strip() and not x.strip().startswith("#")]
    assert [x for x in code if "su-exec" in x or "gosu" in x] == ['exec su-exec postgres "$0" "$@"']
    dockerfile = (ROOT / "deploy" / "postgres" / "Dockerfile").read_text(encoding="utf-8")
    assert "apk add --no-cache su-exec" in dockerfile and "rm /usr/local/bin/gosu" in dockerfile
    assert 'test "$(su-exec postgres id -u)" = "$(id -u postgres)"' in dockerfile and 'test "$(gosu nobody id -un)" = nobody' in dockerfile
    assert "docker_create_db_directories" in script and "source docker-entrypoint.sh" in script
    # the app's role and the restore role: the db container has their passwords, the app never the superuser's
    env = db["environment"]
    assert env["POSTGRES_APP_PASSWORD"].startswith("${POSTGRES_APP_PASSWORD:?") and env["POSTGRES_RESTORE_PASSWORD"] == "${POSTGRES_RESTORE_PASSWORD:-}"
    app = local["services"]["app"]["environment"]
    assert app["POSTGRES_USER"] == "cobe_news_app" and app["POSTGRES_PASSWORD"].startswith("${POSTGRES_APP_PASSWORD:?")
    assert not any("${POSTGRES_PASSWORD" in str(v) for v in app.values())


def test_a_new_database_locks_its_audit_log_once_the_app_made_it():
    """M3 (0.1.52): a new install – db-init finds no audit_log yet – starts one background loop (as postgres, no root):
    every LATE_EVERY s for LATE_FOR s it looks for the table and runs audit-lock.sql once (lock_timeout: never holding
    up the app), then ends. PID 1 keeps the signals; stop() and finish() end the loop with the server. Checked against
    the real image by hand (docs/BETRIEB.md, Datenbank-Sperre: the lock within seconds of the app's first start)."""
    script = (ROOT / "deploy" / "postgres" / "cobe-news-db.sh").read_text(encoding="utf-8")
    assert "LATE_EVERY=10" in script and "LATE_FOR=1800" in script
    assert re.search(r'if \[ "\$pending" = t \] && \[ -z "\$stopping" \]; then\n\s+late_lock &\n\s+late=\$!', script)
    loop = script.split("late_lock() {", 1)[1].split("\n}\n", 1)[0]
    assert "to_regclass('public.audit_log') IS NOT NULL" in loop and '-f "$here/audit-lock.sql"' in loop and "lock_timeout=5s" in loop
    assert "alive || exit 0" in loop and "exit 0" in loop.split("audit-lock.sql", 1)[1]
    for fn in ("stop() {", "finish() {"):
        body = script.split(fn, 1)[1].split("\n}\n", 1)[0]
        assert 'kill "$late"' in body, fn
    # every superuser connection of the image pins the search_path (app-role.sql: the app owns the database)
    assert script.count("superuser ") >= 3 and 'PGOPTIONS="-c search_path=pg_catalog,pg_temp' in script


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
        # the gateway is trusted only inside the network edge: the app gets its subnet, the same expression as the network
        assert env["EDGE_SUBNET"] == f["networks"]["edge"]["ipam"]["config"][0]["subnet"] == "${EDGE_SUBNET:-172.31.250.0/24}"
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
    variables = [x for x in own.splitlines() if re.match(r"# {6}[A-Z_]+=", x)]
    assert len(variables) == 4 and not any("TRUSTED_PROXIES" in x or "TLS_MODE" in x for x in variables)  # not needed any more
    # the port of the app beyond 127.0.0.1 only with TRUSTED_PROXIES=none; the old advice (.1) to be removed
    flat = " ".join(x.lstrip("# ") for x in own.splitlines())
    assert "TRUSTED_PROXIES=none" in flat and "TRUSTED_PROXIES=172.31.250.1/32: remove" in flat


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
    for name in ("cobe-news-db.sh", "db-init.sh", "app-role.sql", "audit-lock.sql", "restore-role.sql"):
        assert name in db and (ROOT / "deploy" / "postgres" / name).is_file(), name
    init = (ROOT / "deploy" / "postgres" / "db-init.sh").read_text(encoding="utf-8")
    assert 'here/app-role.sql"' in init and 'here/audit-lock.sql"' in init and init.index("app-role.sql\"") < init.index("audit-lock.sql\"")
    # the proxy image: exactly what the local install mounted up to 0.1.48, where nginx's entrypoint takes it
    assert "COPY cobe-news.conf.template /etc/nginx/templates/default.conf.template" in proxy
    assert "COPY --chmod=0755 16-server-names.envsh 40-cert-watch.sh /docker-entrypoint.d/" in proxy
    # each build context lets in only its own files
    for folder, files in (("postgres", {"Dockerfile", "cobe-news-db.sh", "db-init.sh", "app-role.sql", "audit-lock.sql", "restore-role.sql"}), ("nginx", {"Dockerfile", "cobe-news.conf.template", "16-server-names.envsh", "40-cert-watch.sh"})):
        lines = [x for x in (ROOT / "deploy" / folder / ".dockerignore").read_text(encoding="utf-8").splitlines() if x and not x.startswith("#")]
        assert lines[0] == "*" and {x.removeprefix("!") for x in lines[1:]} == files, folder
        for f in files:
            assert (ROOT / "deploy" / folder / f).is_file(), f


def test_the_release_builds_signs_and_only_then_tags():
    """Build and push by digest only (no tag), sign the three digests, and only then – job "publish", after all of it –
    check signatures and attestations, put the version tag on the signed digests (no rebuild) and `latest` only for the
    highest release."""
    wf = _load(RELEASE)
    text = RELEASE.read_text(encoding="utf-8")
    env = wf["env"]
    assert (env["IMAGE"], env["DB_IMAGE"], env["PROXY_IMAGE"]) == tuple(i[0] for i in IMAGES.values())
    assert all(v == v.lower() for v in env.values())  # cosign: lower-case names only
    jobs = wf["jobs"]
    assert list(jobs) == ["checks", "image", "publish", "release"]
    assert jobs["image"]["needs"] == "checks" and jobs["publish"]["needs"] == "image" and jobs["release"]["needs"] == ["image", "publish"]
    steps = {s.get("id"): s for s in jobs["image"]["steps"] if s.get("id")}
    for build, meta, context, var in (("build", "meta", ".", "IMAGE"), ("build-db", "meta-db", "deploy/postgres", "DB_IMAGE"), ("build-proxy", "meta-proxy", "deploy/nginx", "PROXY_IMAGE")):
        w = steps[build]["with"]
        assert w["context"] == context and w["platforms"] == "linux/amd64,linux/arm64"
        assert w["provenance"] == "mode=max" and w["sbom"] is True and w["labels"] == f"${{{{ steps.{meta}.outputs.labels }}}}"
        # by digest only: no tags, no push shorthand – nothing in this job moves a tag
        assert "tags" not in w and "push" not in w
        assert w["outputs"] == f"type=image,name=${{{{ env.{var} }}}},push-by-digest=true,name-canonical=true,push=true"
        assert steps[meta]["with"]["images"] == f"${{{{ env.{var} }}}}" and "tags" not in steps[meta]["with"]
    image_steps = jobs["image"]["steps"]
    sign = next(s for s in image_steps if s.get("name", "").startswith("Sign"))
    assert image_steps.index(sign) > max(image_steps.index(steps[b]) for b in ("build", "build-db", "build-proxy"))
    for line in ('cosign sign --yes "${IMAGE}@${DIGEST}"', 'cosign sign --yes "${DB_IMAGE}@${DB_DIGEST}"', 'cosign sign --yes "${PROXY_IMAGE}@${PROXY_DIGEST}"'):
        assert line in sign["run"]
    assert set(jobs["image"]["outputs"]) == {"digest", "db-digest", "proxy-digest"}
    assert jobs["image"]["permissions"] == {"contents": "read", "packages": "write", "id-token": "write"}
    # publish: no signing rights; one at a time across tags (latest)
    pub = jobs["publish"]
    assert pub["permissions"] == {"contents": "read", "packages": "write"}
    assert pub["concurrency"] == {"group": "release-tags", "cancel-in-progress": False}
    checkout = next(s for s in pub["steps"] if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0 and checkout["with"]["persist-credentials"] is False
    names = [s.get("name") or s.get("id") or s.get("uses") for s in pub["steps"]]
    verify, latest, tag = (next(s for s in pub["steps"] if s.get("name", "").startswith(p)) for p in ("Check signatures", "Is this the highest", "Version tag"))
    assert names.index(verify["name"]) < names.index(latest["name"]) < names.index(tag["name"])
    assert 'cosign verify "$ref"' in verify["run"] and "release.yml@${GITHUB_REF}" in verify["run"] and "attestation-manifest" in verify["run"]
    run = tag["run"]
    assert 'docker buildx imagetools create --tag "$1:$3" "$1@$2"' in run and '[ "$got" != "$2" ]' in run  # same digest, else stop
    for img, dig in (("IMAGE", "DIGEST"), ("DB_IMAGE", "DB_DIGEST"), ("PROXY_IMAGE", "PROXY_DIGEST")):
        assert f'put "${img}" "${dig}" "$v"' in run and f'put "${img}" "${dig}" latest' in run
    assert run.index("latest\n") > run.index('if [ "$MOVE_LATEST" = true ]; then')
    assert tag["env"]["MOVE_LATEST"] == "${{ steps.latest.outputs.move }}" and pub["outputs"]["latest"] == "${{ steps.latest.outputs.move }}"
    # every action pinned by its commit, still one tag-triggered pipeline
    uses = re.findall(r"uses: (\S+)", text)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
    assert wf[True] == {"push": {"tags": ["v[0-9]+.[0-9]+.[0-9]+"]}}  # PyYAML reads the key "on" as True
    assert sorted(p.name for p in RELEASE.parent.iterdir()) == ["release.yml"]


def test_the_release_scans_the_pushed_digests_before_signing():
    """Trivy (a pinned version, its archive checked by checksum, no third-party action) scans the three digests as
    pushed, both platforms, with scripts/scan-images.sh – before anything is signed; a fixable high or critical finding
    fails the step, so nothing is signed or tagged. The full reports are kept as a workflow artifact also when the scan
    fails – never in the GitHub release, whose notes stay German and scan-free; the script's Trivy image is the same
    version, pinned by digest."""
    wf = _load(RELEASE)
    steps = wf["jobs"]["image"]["steps"]
    by_name = {s.get("name") or s.get("id") or s.get("uses"): s for s in steps}
    install = by_name["Trivy (pinned version, checksum checked)"]
    version = install["env"]["TRIVY_VERSION"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", version) and re.fullmatch(r"[0-9a-f]{64}", install["env"]["TRIVY_SHA256"])
    assert 'sha256sum -c -' in install["run"] and "releases/download/v${TRIVY_VERSION}/" in install["run"]
    scan = next(s for s in steps if s.get("id") == "scan")
    assert scan["run"] == 'scripts/scan-images.sh "${IMAGE}@${DIGEST}" "${DB_IMAGE}@${DB_DIGEST}" "${PROXY_IMAGE}@${PROXY_DIGEST}"'
    assert scan["env"]["PLATFORMS"] == "linux/amd64 linux/arm64" and scan["env"]["OUT"] == "trivy-reports"
    for var, step in (("DIGEST", "build"), ("DB_DIGEST", "build-db"), ("PROXY_DIGEST", "build-proxy")):
        assert scan["env"][var] == f"${{{{ steps.{step}.outputs.digest }}}}"
    sign = next(s for s in steps if s.get("name", "").startswith("Sign"))
    builds = [i for i, s in enumerate(steps) if s.get("id") in ("build", "build-db", "build-proxy")]
    assert max(builds) < steps.index(install) < steps.index(scan) < steps.index(sign)
    assert "if" not in scan and "continue-on-error" not in scan and "if" not in sign  # a failed scan stops the signing
    keep = next(s for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert steps.index(scan) < steps.index(keep) < steps.index(sign) and "!cancelled()" in keep["if"]
    assert keep["with"]["name"] == "trivy-reports" and keep["with"]["path"] == "trivy-reports/" and keep["with"]["overwrite"] is True
    release = wf["jobs"]["release"]["steps"]
    assert not any(str(s.get("uses", "")).startswith("actions/download-artifact@") for s in release)
    notes = next(s for s in release if s.get("name") == "Release notes from CHANGELOG.md")
    create = next(s for s in release if s.get("name") == "Create the release")
    assert "trivy" not in notes["run"].lower() and "trivy" not in create["run"].lower()
    assert "Alle drei mit cosign signiert" in notes["run"] and "signed with cosign" not in notes["run"]
    assert create["run"].endswith("--notes-file notes.md --verify-tag")
    # the gate of the script: Trivy's own flags, high and critical with a fixed version – and nothing that weakens it:
    # no trivy.yaml / .trivyignore (loading switched off for every Trivy run), no TRIVY_* from outside
    script = (ROOT / "scripts" / "scan-images.sh").read_text(encoding="utf-8")
    assert "--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1" in script
    assert 'NOCONFIG=(--config "" --ignorefile "")' in script
    runs = [x for x in script.splitlines() if re.search(r"trivy_run (image|convert) ", x)]
    assert len(runs) == 4 and all('"${NOCONFIG[@]}"' in x for x in runs), runs
    assert "TRIVY_IMAGE_SRC | TRIVY_DB_REPOSITORY | TRIVY_CACHE_DIR | TRIVY_CACHE_VOLUME) ;;" in script and '*) unset "$v" ;;' in script
    found = []
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in {".git", "node_modules", ".venv", "dist", "trivy-reports"}]
        found += [Path(d, f) for f in files if f in {"trivy.yaml", "trivy.yml", ".trivyignore", ".trivyignore.yaml"}]
    assert not found, found  # the release runs the script from the checkout's root
    assert re.search(rf'^TRIVY_IMAGE="aquasec/trivy:{re.escape(version)}@sha256:[0-9a-f]{{64}}"$', script, re.M)
    assert os.access(ROOT / "scripts" / "scan-images.sh", os.X_OK)
    # it only reads images: no tag, no pull into Docker, no compose
    code = "\n".join(x for x in script.splitlines() if not x.lstrip().startswith("#"))
    assert not re.search(r"docker (tag|pull|push|compose|rmi|image rm)|docker-compose", code)


@pytest.mark.skipif(not (shutil.which("git") and shutil.which("bash")), reason="needs git and bash")
@pytest.mark.parametrize(
    ("tag", "move"),
    [("v0.1.51", True), ("v0.1.50", False), ("v0.1.9", False), ("v0.1.100", True)],
)
def test_latest_moves_only_for_the_highest_release(tmp_path, tag, move):
    """The step of the release workflow as it is: a backport (a lower tag) never moves latest; versions compare as
    numbers (0.1.100 above 0.1.51); other tags (rc, test names) do not count."""
    step = next(s for s in _load(RELEASE)["jobs"]["publish"]["steps"] if s.get("id") == "latest")
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.email=t@example.org", "-c", "user.name=t", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "x"], check=True)
    tags = ["v0.1.9", "v0.1.10", "v0.1.49", "v0.1.50", "v0.1.51", "v0.2.0-rc1", "v0.1.52x", "test-dates"] + (["v0.1.100"] if tag == "v0.1.100" else [])
    for t in tags:
        subprocess.run([*git, "tag", t], check=True)
    out = tmp_path / "out"
    out.write_text("")
    r = subprocess.run(["bash", "-c", step["run"]], cwd=repo, env={**os.environ, "TAG": tag, "GITHUB_OUTPUT": str(out)}, capture_output=True, text=True, timeout=30)  # noqa: S603, S607
    assert r.returncode == 0, r.stderr
    assert out.read_text().strip() == f"move={'true' if move else 'false'}"


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
        # only where it is called wrong or to be removed (the advice of 0.1.48: TRUSTED_PROXIES=172.31.250.1/32)
        for para in re.split(r"\n\s*\n", text):
            if re.search(r"172\.31\.250\.1(?![0-9])", para):
                assert any(w in para for w in ("entfernen", "remove", "nicht `172.31.250.1`", "not `172.31.250.1`")), (path, para[:300])
        assert "docker compose logs db-init" not in text and "up -d db-init" not in text, path
