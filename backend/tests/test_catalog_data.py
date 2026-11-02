"""The catalogue as data (app/catalog): the files load and are checked; a broken file is refused with file and product
named; the schema files for editors are current; the UI knows every icon; the catalogue version is delivered."""

import json
import re
import shutil
from pathlib import Path

import pytest

from app import catalog_data
from app.catalog_data import CatalogError

FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "src"


@pytest.fixture
def cat_dir(tmp_path) -> Path:
    d = tmp_path / "catalog"
    shutil.copytree(catalog_data.DIR, d)
    return d


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text, old
    path.write_text(text.replace(old, new, 1))


def test_bundled_catalogue_loads():
    cat = catalog_data.load()
    assert re.fullmatch(r"\d{4}\.\d{2}\.\d{2}-\d+", cat.version)
    assert len(cat.overlay) >= 480 and len(cat.categories) == 30
    by = {o["key"]: o for o in cat.overlay}
    assert by["panos"] == {
        "key": "panos", "label": "PAN-OS (Firewalls)", "vendor": "Palo Alto Networks", "category": "firewall", "cpes": ["o:paloaltonetworks:pan-os"],
        "scheme": "panos", "adv": "paloalto", "names": ["PAN-OS"], "cna": [["Palo Alto Networks", "PAN-OS"]], "kw": ["PAN-OS", "GlobalProtect"],
        "aliases": ["Palo Alto Firewall", "NGFW", "PA-Series"], "example": "11.2.4-h23", "where": "panos",
    }  # fmt: skip
    # an entry without label only patches an endoflife.date product
    assert by["rhel"] == {"key": "rhel", "label": None, "vendor": None, "category": "os", "cpes": [], "scheme": "distro", "hint": "distro"}
    # NVD's escaped characters survive YAML
    assert "a:veeam:veeam_backup_\\&_replication" in by["veeam-backup-and-replication"]["cpes"]
    for c in cat.categories:
        assert c["de"] and c["en"] and c["icon"] in catalog_data.ICONS
    assert cat.texts["hints"]["cloud"]["de"] and cat.texts["where"]["veeam_br"]["en"]


def test_check_command(capsys):
    assert catalog_data.main([]) == 0
    assert "ok" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("file", "old", "new", "message"),
    [
        ("products/firewall.yaml", "cpes: [o:fortinet:fortios]", "cpes: [fortinet:fortios]", "products/firewall.yaml: product 'fortios' (entry"),
        ("products/firewall.yaml", "cpes: [o:fortinet:fortios]", "cpes: [o:fortinet:fortios, o:fortinet:fortios]", "a CPE is listed twice"),
        ("products/firewall.yaml", "scheme: panos", "scheme: pan-os", "product 'panos'"),
        ("products/firewall.yaml", "adv: paloalto", "adv: palo", "adv"),
        ("products/firewall.yaml", "example: 11.2.4-h23", "example: 8.0", "Input should be a valid string"),
        ("products/firewall.yaml", "example: 11.2.4-h23", "exampel: 11.2.4-h23", "Extra inputs are not permitted"),
        ("products/firewall.yaml", "hint: panorama", "hint: no_such_hint", "hint 'no_such_hint' has no text in texts.yaml"),
        ("products/backup.yaml", "where: veeam_br", "where: nowhere", "where 'nowhere' has no text"),
        ("products/firewall.yaml", "- key: panorama", "- key: panos", "product 'panos' (entry 2): key already used in products/firewall.yaml"),
        ("products/firewall.yaml", "- key: panorama\n  label: Panorama\n  vendor: Palo Alto Networks", "- key: panorama\n  label: Panorama", "vendor is missing"),
        ("products/os.yaml", "- key: rhel\n  scheme: distro", "- key: rhel\n  kw: [RHEL]\n  scheme: distro", "without a label only aliases, belongs, cpe_editions, cpes, hint"),
        ("products/cloud.yaml", "cloud: true", 'cloud: "true"', "cloud: Input should be a valid boolean"),
        ("categories.yaml", "    en: Firewalls & VPN\n", "", "categories.yaml: categories.0.en: Field required"),
        ("categories.yaml", "icon: brick-wall", "icon: no-such-icon", "categories.yaml"),
        ("texts.yaml", "hints:\n  cloud:\n", "hints:\n  cloud_old:\n", "hint 'cloud'"),
        ("catalog.yaml", "catalog_version: 2026", "catalog_version: v2026", "catalog.yaml: catalog_version"),
        ("catalog.yaml", "format: 1", "format: 2", "catalog.yaml: format"),
    ],
)
def test_broken_file_is_refused_with_file_and_product(cat_dir, file, old, new, message):
    _edit(cat_dir / file, old, new)
    with pytest.raises(CatalogError) as e:
        catalog_data.load(cat_dir)
    assert message in str(e.value)
    assert catalog_data.main(["--dir", str(cat_dir)]) == 1


def test_unknown_category_file_and_bad_yaml(cat_dir):
    (cat_dir / "products" / "toasters.yaml").write_text("- key: toaster\n  label: Toaster\n  vendor: Example\n")
    with pytest.raises(CatalogError, match=r"products/toasters.yaml: unknown category 'toasters'"):
        catalog_data.load(cat_dir)
    (cat_dir / "products" / "toasters.yaml").unlink()
    (cat_dir / "products" / "dev.yaml").write_text("- key: [unclosed\n")
    with pytest.raises(CatalogError, match=r"products/dev.yaml: not valid YAML"):
        catalog_data.load(cat_dir)
    (cat_dir / "products" / "dev.yaml").write_text("key: not-a-list\n")
    with pytest.raises(CatalogError, match=r"must be a list"):
        catalog_data.load(cat_dir)


def test_new_product_in_a_new_file(cat_dir):
    (cat_dir / "products" / "dev.yaml").unlink()  # every category has its file by now: one made anew
    (cat_dir / "products" / "dev.yaml").write_text("# a comment\n- key: example-ide\n  label: Example IDE\n  vendor: Example Corp\n  cpes: [a:example:ide]\n  kw: [Example IDE]\n")
    cat = catalog_data.load(cat_dir)
    got = next(o for o in cat.overlay if o["key"] == "example-ide")
    assert got == {"key": "example-ide", "label": "Example IDE", "vendor": "Example Corp", "category": "dev", "cpes": ["a:example:ide"], "kw": ["Example IDE"]}


def test_schema_files_are_current():
    for name, schema in catalog_data.schemas().items():
        path = catalog_data.DIR / "schema" / f"{name}.schema.json"
        assert path.read_text() == catalog_data.schema_text(schema), f"{path.name} is outdated – python -m app.catalog_data --write-schema"
    products = json.loads((catalog_data.DIR / "schema" / "products.schema.json").read_text())
    assert products["type"] == "array" and "cpes" in products["$defs"]["Product"]["properties"]


def test_every_file_points_to_its_schema():
    for f in [*catalog_data.DIR.glob("*.yaml"), *catalog_data.DIR.glob("products/*.yaml")]:
        first = f.read_text().splitlines()[0]
        m = re.fullmatch(r"# yaml-language-server: \$schema=(\S+)", first)
        assert m and (f.parent / m.group(1)).resolve().is_file(), f


def test_ui_knows_every_icon():
    text = (FRONTEND / "lib" / "catalog-icons.tsx").read_text()
    mapped = set(re.findall(r'^\s*"?([a-z-]+)"?: [A-Z]', text, re.MULTILINE))
    assert mapped == set(catalog_data.ICONS)


def test_ui_has_no_catalogue_texts_of_its_own():
    """Category labels, hints and "where" texts come with the catalogue data (texts can be updated with it)."""
    for name in ("vendor.de.ts", "vendor.en.ts"):
        text = (FRONTEND / "i18n" / name).read_text()
        left = re.findall(r'"vendor\.(?:cat|hint|where)\.([a-z_]+)"', text)
        assert set(left) <= {"all", "followed"}, (name, left)


async def test_api_delivers_version_categories_and_texts(admin_client, reader_client):
    client = admin_client
    assert (await reader_client.get("/api/vendor/catalog/meta")).status_code == 200
    r = await client.get("/api/vendor/catalog/meta")
    assert r.status_code == 200
    body = r.json()
    assert body["catalog_version"] == catalog_data.load().version
    assert [c["key"] for c in body["categories"]][:3] == ["firewall", "network", "lb"]
    assert body["categories"][0]["label"] == {"de": "Firewalls & VPN", "en": "Firewalls & VPN"} and body["categories"][0]["icon"] == "brick-wall"
    assert set(body["texts"]) == {"hints", "where"} and body["texts"]["hints"]["nocpe"]["en"]
    assert (await client.get("/api/vendor/catalog")).json()["catalog_version"] == body["catalog_version"]
    assert (await client.get("/api/changelog")).json()["catalog_version"] == body["catalog_version"]
    assert (await client.get("/api/admin/vendor")).json()["catalog"]["catalog_version"] == body["catalog_version"]
