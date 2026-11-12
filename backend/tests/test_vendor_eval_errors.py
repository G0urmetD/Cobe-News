"""One followed product that fails – its view or its evaluation – never stops the others (deep review 0.1.56): the
error is logged (with its traceback once, then rate-limited), the products followed after it get their events, and the
Vendor News round still runs the CVE watch, wakes the news loop and notes its time."""

import logging

import pytest
from sqlalchemy import func, select
from test_vendor_service import _follow, _fresh_pan, _round, sites, vendor_reset  # noqa: F401

from app import db, vendor
from app.models import VendorEvent


async def _panos_events(cve: str) -> int:
    async with db.session() as s:
        return await s.scalar(select(func.count()).select_from(VendorEvent).where(VendorEvent.product == "panos", VendorEvent.key.like(f"%{cve}%")))


def _break(monkeypatch, where: str) -> None:
    if where == "view":
        real = vendor._compute_view

        async def broken(f, *a, **k):  # noqa: ANN001, ANN002, ANN003, ANN202
            if f.product == "fortios":
                raise ValueError("a record this parser cannot read")
            return await real(f, *a, **k)

        monkeypatch.setattr(vendor, "_compute_view", broken)
        vendor._views.pop("fortios", None)
    else:
        real_e = vendor._evaluate_product

        async def broken_e(db_, f, *a, **k):  # noqa: ANN001, ANN002, ANN003, ANN202
            if f.product == "fortios":
                raise ValueError("boom in the evaluation")
            return await real_e(db_, f, *a, **k)

        monkeypatch.setattr(vendor, "_evaluate_product", broken_e)
    vendor.bump(["fortios"])


@pytest.mark.parametrize("where", ["view", "evaluate"])
async def test_a_failing_product_does_not_starve_the_products_after_it(admin_client, sites, monkeypatch, caplog, where):
    await _follow(admin_client, "fortios", "7.4.3")  # followed first: evaluated first (follows by created_at)
    await _follow(admin_client, "panos", "11.2.4-h23")
    await _round()
    _break(monkeypatch, where)
    a = _fresh_pan("CVE-2026-9911", "< 11.2.4-h30", ">= 11.2.4-h30")
    caplog.set_level(logging.INFO, logger=vendor.log.name)
    async with db.session() as s:
        await vendor.store(s, [a], vendor.build_index())
        assert await vendor.evaluate_events(s) >= 1  # no exception, PAN-OS evaluated
    assert await _panos_events("CVE-2026-9911")
    # the real error is logged with its traceback – not a MissingGreenlet of a lazy load after the rollback
    errors = [r for r in caplog.records if r.levelno == logging.ERROR and "evaluating fortios failed" in r.getMessage()]
    assert len(errors) == 1 and errors[0].exc_info and isinstance(errors[0].exc_info[1], ValueError)
    assert "MissingGreenlet" not in caplog.text
    # fails again next round: a short warning, not the traceback every minute
    caplog.clear()
    vendor.bump(["fortios"])
    async with db.session() as s:
        await vendor.evaluate_events(s)
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(r.levelno == logging.WARNING and "evaluating fortios failed" in r.getMessage() for r in caplog.records)
    # works again: said once, and a later failure logs its traceback again
    monkeypatch.undo()
    vendor.bump(["fortios"])
    caplog.clear()
    async with db.session() as s:
        await vendor.evaluate_events(s)
    assert "fortios works again" in caplog.text and "eval:fortios" not in vendor._eval_failures


async def test_a_new_error_or_an_hour_later_logs_the_traceback_again(caplog):
    caplog.set_level(logging.INFO, logger=vendor.log.name)
    vendor._eval_failed_log("x", ValueError("one"))
    vendor._eval_failed_log("x", ValueError("one"))
    vendor._eval_failed_log("x", ValueError("two"))
    what, at = vendor._eval_failures["eval:x"]
    vendor._eval_failures["eval:x"] = (what, at - vendor.EVAL_FAIL_LOG)
    vendor._eval_failed_log("x", ValueError("two"))
    assert [r.levelno for r in caplog.records] == [logging.ERROR, logging.WARNING, logging.ERROR, logging.ERROR]


async def test_the_round_still_watches_cves_and_wakes_the_news_when_the_evaluation_fails(monkeypatch):
    async def nothing(**kw):  # noqa: ANN003, ANN202
        return {}

    async def broken(db_, **kw):  # noqa: ANN001, ANN003, ANN202
        raise RuntimeError("the evaluation broke before the products")

    watched: list[int] = []

    async def watch(db_, gen):  # noqa: ANN001, ANN202
        watched.append(1)
        return 0

    woke: list[int] = []
    monkeypatch.setattr(vendor, "run_round", nothing)
    monkeypatch.setattr(vendor, "evaluate_events", broken)
    monkeypatch.setattr(vendor.cve_watch, "evaluate_due", watch)
    loop = vendor.VendorLoop(notify_wake=lambda: woke.append(1))
    await loop.round()
    assert watched == [1] and woke == [1] and loop.last_round_at is not None
