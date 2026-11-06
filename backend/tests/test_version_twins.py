"""Version entry (0.1.51): invisible format and direction characters never become part of a version or its label
(bug hunt 0.1.50: "3.9.0" + U+202E was stored as a version of its own that looked like 3.9.0), and the same version with
the same label is refused instead of entered twice."""

import pytest

from app import plaintext, version_input
from app import vendor_catalog as catalog


@pytest.mark.parametrize(
    "typed",
    ["3.9.0‮", "​3.9.0", "3.9​.0", "⁦ 3.9.0 ⁩", "３.９.０", "3.9.0﻿", "3.9.0‎"],
)
def test_invisible_and_compatibility_characters_are_not_part_of_the_version(typed):
    c = version_input.check(catalog.product("gitlab"), typed)
    assert c.ok and c.value == "3.9.0", (typed, c)


def test_label_keeps_the_text_and_drops_direction_and_invisible_characters():
    assert plaintext.label("‏שרת ראשי‏") == "שרת ראשי"
    assert plaintext.label("RZ‮ Nord") == "RZ Nord"
    assert plaintext.label("  RZ \t Nord\n") == "RZ Nord"
    assert plaintext.label("Team \U0001f468‍\U0001f4bb") == "Team \U0001f468‍\U0001f4bb"  # the joiner of an emoji stays
    assert plaintext.label("مركز البيانات") == "مركز البيانات"


async def _follow(client) -> None:  # noqa: ANN001
    assert (await client.put("/api/vendor/follows/gitlab", json={"enabled": True})).status_code == 200


async def test_stored_version_and_label_are_clean(admin_client):
    await _follow(admin_client)
    r = await admin_client.post("/api/vendor/follows/gitlab/versions", json={"version": "19.5.0‮", "label": "‏שרת‏"})
    assert r.status_code == 200, r.text
    assert r.json()["version"] == "19.5.0" and r.json()["label"] == "שרת"


async def test_the_same_version_with_the_same_label_is_refused(admin_client):
    await _follow(admin_client)
    add = lambda **b: admin_client.post("/api/vendor/follows/gitlab/versions", json=b)  # noqa: E731
    assert (await add(version="19.5.0")).status_code == 200
    r = await add(version="19.5.0")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "version_exists"
    assert (await add(version="19.5.0‮")).status_code == 409  # invisible difference: the same
    assert (await add(version="19.5.0", label="RZ Nord")).status_code == 200  # a second site: fine
    r = await add(version="19.5.0", label="rz nord")
    assert r.status_code == 409  # case does not make another site
    other = await add(version="19.4.2", label="RZ Süd")
    assert other.status_code == 200
    vid = other.json()["id"]
    # editing one into another's twin is refused too – saving it unchanged is not
    r = await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "19.5.0", "label": "RZ Nord"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "version_exists"
    assert (await admin_client.put(f"/api/vendor/versions/{vid}", json={"version": "19.4.2", "label": "RZ Süd"})).status_code == 200
    versions = (await admin_client.get("/api/vendor/products/gitlab")).json()["versions"]
    assert sorted((v["version"], v["label"]) for v in versions) == [("19.4.2", "RZ Süd"), ("19.5.0", ""), ("19.5.0", "RZ Nord")]
