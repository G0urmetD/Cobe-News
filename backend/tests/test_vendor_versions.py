"""Version comparators per scheme – the core of "is this version affected"."""

import pytest

from app.vendor_versions import V, from_cpe, in_range, parse, validate, windows_cpe


def P(scheme: str, text: str) -> V:  # noqa: N802
    v = parse(scheme, text)
    assert v is not None, (scheme, text)
    return v


# ---------------------------------------------------------------- PAN-OS hotfixes


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("11.2.4", "11.2.4-h4"),
        ("11.2.4-h4", "11.2.4-h23"),  # numeric, not text: h23 > h4
        ("11.2.4-h9", "11.2.4-h10"),
        ("11.2.4-h23", "11.2.5"),
        ("10.2.13-h5", "11.1.6-h3"),
        ("11.1.6-h3", "11.2.4-h23"),
        ("9.1.19", "10.0.0"),
        ("11.2.10-h2", "11.2.13"),
    ],
)
def test_panos_order(lower, higher):
    assert P("panos", lower) < P("panos", higher)
    assert P("panos", higher) > P("panos", lower)


def test_panos_equal_and_normalised():
    assert P("panos", "11.2.4") == P("panos", "11.2.4-h0")
    assert P("panos", "11.2.4-H23").text == "11.2.4-h23"
    assert P("panos", "11.2.4h23") == P("panos", "11.2.4-h23")
    assert P("panos", "11.2.4-h23").startswith(P("generic", "11.2"))
    assert not P("panos", "11.20.1").startswith(P("generic", "11.2"))


@pytest.mark.parametrize("bad", ["11.2", "11.2.4-hx", "11.2.4-h", "PAN-OS 11.2.4", "11.2.4 h23 beta", "", "a.b.c"])
def test_panos_rejects(bad):
    assert parse("panos", bad) is None


# ---------------------------------------------------------------- FortiOS


def test_fortios():
    assert P("fortios", "7.4.3") < P("fortios", "7.4.10")
    assert P("fortios", "v7.6.3 build3510") == P("fortios", "7.6.3")
    assert P("fortios", "7.6.3,build3510") == P("fortios", "7.6.3")
    assert P("fortios", "7.2") < P("fortios", "7.2.1")
    assert parse("fortios", "7.x") is None


# ---------------------------------------------------------------- Cisco


def test_cisco_asa_parentheses():
    assert P("cisco", "9.18(4)22") == P("generic", "9.18.4.22")
    assert P("cisco", "9.18(4)22") < P("cisco", "9.18(4)47")
    assert P("cisco", "9.18(4)") < P("cisco", "9.18(4)8")
    assert P("cisco", "9.16(4)48") < P("cisco", "9.18(1)")


def test_cisco_ios_xe_letters_and_nxos():
    assert P("cisco", "17.9.4") < P("cisco", "17.9.4a") < P("cisco", "17.9.5")
    assert P("cisco", "17.12.1") > P("cisco", "17.9.4a")  # 12 > 9, not text order
    assert P("cisco", "10.2(5)") < P("cisco", "10.2(6)")
    assert P("cisco", "9.3(12)") > P("cisco", "9.3(9)")
    assert P("cisco", "7.2.5.1") > P("cisco", "7.2.5")


# ---------------------------------------------------------------- Windows builds


def test_windows_builds():
    assert P("windows", "10.0.20348.2762").text == "10.0.20348.2762"
    assert P("windows", "20348.2762") == P("windows", "10.0.20348.2762")
    assert P("windows", "10.0.20348.2762") < P("windows", "10.0.20348.2849")
    assert P("windows", "10.0.20348.999") < P("windows", "10.0.20348.2762")  # numeric revision
    assert parse("windows", "KB5044281") is None
    assert validate("windows", "KB5044281") == (False, "KB5044281", "kb")
    assert windows_cpe("windows-server", P("windows", "10.0.20348.2762")) == "cpe:2.3:o:microsoft:windows_server_2022"
    assert windows_cpe("windows-server", P("windows", "10.0.17763.6414")) == "cpe:2.3:o:microsoft:windows_server_2019"
    assert windows_cpe("windows", P("windows", "10.0.26100.2605")) == "cpe:2.3:o:microsoft:windows_11_24h2"
    assert windows_cpe("windows-server", P("windows", "10.0.99999.1")) is None


# ---------------------------------------------------------------- VMware, Ivanti


def test_vmware_updates():
    assert P("vmware", "8.0 U3") == P("vmware", "8.0.3")
    assert P("vmware", "8.0 U3") < P("vmware", "8.0 U3c") < P("vmware", "8.0 U3d")
    assert P("vmware", "8.0 Update 3c") == P("vmware", "8.0 U3c")
    assert P("vmware", "7.0 U3w") < P("vmware", "8.0")
    assert parse("vmware", "8.0.3 U3") is None  # said twice – refused rather than guessed


def test_ivanti_releases():
    assert P("ivanti", "22.7R2.3") > P("ivanti", "22.7R2.2")
    assert P("ivanti", "22.7R2") < P("ivanti", "22.7R2.1")
    assert P("ivanti", "9.1R18.2") < P("ivanti", "22.7R1")
    assert parse("ivanti", "22.7") is None


# ---------------------------------------------------------------- generic


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("8.3.9", "8.3.14"),
        ("1.2.0-rc1", "1.2.0"),
        ("1.2.0-beta", "1.2.0-rc1"),
        ("3.13.0b2", "3.13.0"),
        ("9.8", "9.8p1"),
        ("9.8p1", "9.9"),
        ("1.0.2t", "1.0.2u"),
        ("14.1-29.72", "14.1-34.42"),
        ("2.4.62", "2.4.63"),
        ("12.3.0.310", "12.3.1.1139"),
        ("v22.12.0", "22.12.1"),
    ],
)
def test_generic_order(lower, higher):
    assert P("generic", lower) < P("generic", higher)


def test_generic_unknown_words_are_not_compared():
    assert parse("generic", "2.4.62 (Debian)") is None
    assert parse("generic", "latest") is None
    assert parse("generic", "") is None
    assert parse("generic", "1" * 80) is None
    assert parse("cloud", "11.2") is None


def test_ranges():
    v = P("generic", "7.4.3")
    assert in_range(v, start=P("generic", "7.4.0"), end=P("generic", "7.4.4"))
    assert not in_range(v, start=P("generic", "7.4.0"), end=P("generic", "7.4.3"))
    assert in_range(v, start=P("generic", "7.4.0"), end=P("generic", "7.4.3"), end_incl=True)
    assert not in_range(v, start=P("generic", "7.4.3"), start_incl=False)


# ---------------------------------------------------------------- CPE fields


def test_from_cpe():
    assert from_cpe("panos", "11.2.4", "h1") == (P("panos", "11.2.4-h1"), False)
    assert from_cpe("panos", "11.2.4", "-") == (P("panos", "11.2.4"), False)
    v, any_update = from_cpe("panos", "11.2.4", "*")
    assert v == P("panos", "11.2.4") and any_update
    assert from_cpe("vmware", "8.0", "update_3b")[0] == P("vmware", "8.0 U3b")
    assert from_cpe("ivanti", "22.7", "r2.3")[0] == P("ivanti", "22.7R2.3")
    assert from_cpe("generic", "*", "*") == (None, True)


def test_validate():
    assert validate("panos", " 11.2.4-H23 ") == (True, "11.2.4-h23", "")
    assert validate("panos", "11.2") == (False, "11.2", "format")
    assert validate("cloud", "1.0")[2] == "cloud"
    assert validate("generic", "")[2] == "empty"
    assert validate("generic", "x" * 70)[2] == "too_long"


def test_maven_milestones_come_before_the_release():
    """7.0.0-M1 (Maven, Tomcat, Struts) is a pre-release: before 7.0.0 – not after it (an OSV range "introduced
    7.0.0-M1" left 7.0.0 itself out). IOS' 15.2(4)M1 keeps its M as a separator."""
    assert parse("generic", "7.0.0-M1") < parse("generic", "7.0.0") < parse("generic", "7.0.1")
    assert parse("generic", "11.0.0-M2") < parse("generic", "11.0.0-M26") < parse("generic", "11.0.0")
    assert parse("generic", "2.0.M2") < parse("generic", "2.0")
    assert parse("generic", "15.2(4)M1").key == (15, 2, 4, 1)
