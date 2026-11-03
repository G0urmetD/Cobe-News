"""The bundled nginx (deploy/nginx): only the names of the installation get a page (BASE_URL's host, NEWS_HOSTNAME,
TLS_NAMES, localhost) – any other Host header gets a short plain-text 421 on https (how to add the name) and nothing
on plain http (444); plain http sent to the https port is redirected; the names script lets nothing but a name into
the configuration (no line break) and warns when the proxy is published to the network while BASE_URL names
localhost. With the pinned nginx image on this machine (never pulled here) the rendered configuration also passes
`nginx -t` and answers an unknown name with the 421."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NGINX = ROOT / "deploy" / "nginx"
TEMPLATE = NGINX / "cobe-news.conf.template"
NAMES = NGINX / "16-server-names.envsh"

pytestmark = pytest.mark.skipif(not TEMPLATE.is_file(), reason="no deploy/ next to the backend")


def _source(**env: str) -> tuple[str, str]:
    """The names script sourced by sh, as the image's entrypoint does (with set -e): (its log, NEWS_SERVER_NAMES)."""
    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("no sh")
    full = {"PATH": "/usr/bin:/bin", **{f"NEWS_{k.upper()}": v for k, v in env.items()}}
    out = subprocess.run([sh, "-ec", f'. "{NAMES}" >&2; printf %s "$NEWS_SERVER_NAMES"'], env=full, capture_output=True, text=True, timeout=20, check=True)
    return out.stderr, out.stdout


def _names(**env: str) -> list[str]:
    """NEWS_SERVER_NAMES as the names script sets it."""
    return _source(**env)[1].split()


def render(names: str, port: str = "8095") -> str:
    """What 20-envsubst-on-templates.sh makes of the template: only ${NEWS_…} filled in, nginx's $variables untouched."""
    text = TEMPLATE.read_text()
    values = {"NEWS_SERVER_NAMES": names, "NEWS_HTTPS_PORT": port}
    assert set(re.findall(r"\$\{(\w+)\}", text)) == set(values), "the template uses a variable the proxy does not get"
    return re.sub(r"\$\{(NEWS_\w+)\}", lambda m: values[m.group(1)], text)


def _servers(conf: str) -> list[str]:
    """The server blocks (top level of the file)."""
    conf = re.sub(r"#[^\n]*", "", conf)
    out, depth, start = [], 0, None
    for m in re.finditer(r"[{}]", conf):
        if m.group() == "{":
            if depth == 0:
                start = conf.rfind("server", 0, m.start())
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                out.append(conf[start : m.end()])
    return out


def test_unknown_names_get_nothing_and_plain_http_on_the_https_port_is_redirected():
    conf = render("localhost 127.0.0.1 [::1] news.corp.example")
    servers = _servers(conf)
    defaults = [s for s in servers if "default_server" in s]
    assert len(defaults) == 2 and {re.search(r"listen (\d+)", s).group(1) for s in defaults} == {"80", "443"}
    for s in defaults:
        assert "server_name _;" in s and "return 444;" in s and "proxy_pass" not in s
    # https: a short 421 that says what to do (plain http on that port, and port 80, stay closed: 444)
    tls_default = next(s for s in defaults if "listen 443" in s)
    m = re.search(r'return 421 "([^"]*)";', tls_default)
    assert m and "Unbekannter Hostname" in m.group(1) and "BASE_URL" in m.group(1) and "TLS_NAMES" in m.group(1)
    assert "localhost" not in m.group(1) and "news.corp.example" not in m.group(1)  # nothing of the installation
    assert "default_type text/plain;" in tls_default and "error_page 497 @close;" in tls_default
    assert "return 421" not in next(s for s in defaults if "listen 80" in s)
    named = [s for s in servers if "default_server" not in s]
    assert len(named) == 2
    for s in named:
        assert "server_name localhost 127.0.0.1 [::1] news.corp.example;" in s
    https = next(s for s in named if "listen 443 ssl;" in s)
    assert "error_page 497 =301 https://$host:8095$request_uri;" in https and "proxy_pass http://app:8000;" in https
    assert "client_max_body_size 1m;" in https
    # the TLS settings once, for both https servers
    assert conf.count("ssl_certificate ") == 1 and "ssl_protocols TLSv1.2 TLSv1.3;" in conf


def test_names_from_base_url_hostname_and_tls_names():
    assert _names() == ["localhost", "127.0.0.1", "[::1]"]
    assert _names(base_url="https://News.Corp.Example:8443/pfad", tls_hostname="news.corp.example.", tls_names="10.0.0.5, fe80::1,*.corp.example,localhost") == [
        "localhost",
        "127.0.0.1",
        "[::1]",
        "news.corp.example",
        "10.0.0.5",
        "[fe80::1]",
        "*.corp.example",
    ]
    assert _names(base_url="https://[2001:db8::5]:8095") == ["localhost", "127.0.0.1", "[::1]", "[2001:db8::5]"]
    assert _names(base_url="https://user@host.example") == ["localhost", "127.0.0.1", "[::1]", "host.example"]


def test_nothing_but_a_name_gets_into_the_configuration():
    got = _names(tls_names="evil;return,a{b},x}y,bücher.example,*.*.x,a*b,$(id),`id`,~^.*$,ok.example")
    assert got == ["localhost", "127.0.0.1", "[::1]", "ok.example"]
    assert all(re.fullmatch(r"(\*\.)?[a-z0-9.:\[\]-]+", n) for n in got)
    # a line break (or a carriage return) in a value: the whole value is left out, never split into names
    for env in ({"tls_hostname": "a.example\nlisten"}, {"base_url": "https://b.example\nreturn/"}, {"tls_hostname": "c.example\r"}):
        log, names = _source(**env)
        assert names.split() == ["localhost", "127.0.0.1", "[::1]"] and "\n" not in names
        assert "line break" in log


def test_a_warning_when_published_to_the_network_with_base_url_on_localhost():
    log, _ = _source(bind="0.0.0.0")  # BASE_URL's default: https://localhost:8095
    assert "WARNING" in log and "BIND=0.0.0.0" in log and "BASE_URL" in log
    log, _ = _source(bind="0.0.0.0", base_url="https://localhost:8095")
    assert "WARNING" in log
    assert "WARNING" not in _source(bind="0.0.0.0", base_url="https://news.corp.example")[0]
    assert "WARNING" not in _source(base_url="https://localhost:8095")[0]  # only on this machine: fine
    assert "WARNING" not in _source(bind="127.0.0.1")[0]
    # a fixed address of the machine: said when it is not among the names
    log, _ = _source(bind="10.0.0.5", base_url="https://news.corp.example")
    assert "BIND=10.0.0.5 is not among the names" in log
    assert "WARNING" not in _source(bind="10.0.0.5", base_url="https://news.corp.example", tls_names="10.0.0.5")[0]


def _image() -> str:
    compose = (ROOT / "docker-compose.yml").read_text()
    return re.search(r"image: (nginx:[^\s]+)", compose).group(1)


def test_rendered_configuration_passes_nginx_t(tmp_path):
    """The pinned image from docker-compose.yml, only when it is on this machine already (no pull, no network)."""
    from app import tls

    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("no docker")
    image = _image()
    if subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=30).returncode != 0:
        pytest.skip(f"{image} not on this machine")
    (tmp_path / "tls").mkdir()
    cert, key = tls.make(["localhost", "news.corp.example"])
    (tmp_path / "tls" / "cobe.crt").write_bytes(cert)
    (tmp_path / "tls" / "cobe.key").write_bytes(key)
    (tmp_path / "tls").chmod(0o755)
    (tmp_path / "tls" / "cobe.key").chmod(0o644)  # the container's root reads it (a throwaway test key)
    run = [
        docker, "run", "--rm", "--network", "none", "--add-host", "app:127.0.0.1",
        "-e", "NEWS_HTTPS_PORT=8095", "-e", "NEWS_BASE_URL=https://news.corp.example:8095", "-e", "NEWS_TLS_NAMES=10.0.0.5,fe80::1", "-e", "NGINX_ENVSUBST_FILTER=^NEWS_",
        "-v", f"{TEMPLATE}:/etc/nginx/templates/default.conf.template:ro",
        "-v", f"{NAMES}:/docker-entrypoint.d/16-server-names.envsh:ro",
        "-v", f"{tmp_path / 'tls'}:/etc/nginx/tls:ro",
        image, "sh", "-c",
        "/docker-entrypoint.sh nginx -t && grep -h server_name /etc/nginx/conf.d/default.conf && nginx && sleep 1"
        " && curl -sk -o /tmp/body -w 'status=%{http_code}\\n' -H 'Host: other.example' https://127.0.0.1/ && cat /tmp/body"
        " && (curl -s -o /dev/null -H 'Host: other.example' http://127.0.0.1/ || echo \"http closed: $?\")",
    ]  # fmt: skip
    out = subprocess.run(run, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    assert "test is successful" in out.stderr
    assert "server_name localhost 127.0.0.1 [::1] news.corp.example 10.0.0.5 [fe80::1];" in out.stdout
    # an unknown name on https: the 421 with its text; on plain http the connection closed without an answer (curl 52)
    assert "status=421" in out.stdout and "Unbekannter Hostname – in .env BASE_URL oder TLS_NAMES eintragen." in out.stdout
    assert "http closed: 52" in out.stdout
