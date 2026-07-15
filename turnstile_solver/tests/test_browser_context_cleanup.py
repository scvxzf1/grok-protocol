from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.browser_runtime import BrowserAffinity, BrowserSlot, PersistentBrowserPool
from src.config import SolverConfig
from src.models import SolveRequest, SolveResult


class FakePage:
    def __init__(self, browser, target_id: str, context_id: str):
        self.browser = browser
        self.tab_id = target_id
        self.browser_context_id = context_id

    def close(self):
        self.browser.events.append(("page.close", self.tab_id))


class FakeBrowser:
    def __init__(self, context_ids, *, fail_dispose: bool = False):
        self.context_ids = list(context_ids)
        self.fail_dispose = fail_dispose
        self.events = []
        self.pages = {}
        self.quit_called = False

    def new_tab(self, *, new_context=False):
        self.events.append(("new_tab", new_context))
        context_id = self.context_ids.pop(0)
        target_id = f"target-{len(self.pages) + 1}"
        page = FakePage(self, target_id, context_id)
        self.pages[target_id] = page
        return page

    def _run_cdp(self, method, **params):
        self.events.append(("cdp", method, dict(params)))
        if method == "Target.getTargetInfo":
            page = self.pages[params["targetId"]]
            return {
                "targetInfo": {
                    "targetId": page.tab_id,
                    "browserContextId": page.browser_context_id,
                }
            }
        if method == "Target.disposeBrowserContext" and self.fail_dispose:
            raise RuntimeError("synthetic disposal failure")
        return {}

    def get_tabs(self):
        return []

    def quit(self):
        self.quit_called = True
        self.events.append(("browser.quit",))


class FakeWorker:
    def __init__(self, failure=None):
        self.failure = failure
        self.pages = []

    def solve_on_page(self, page, _request, **_kwargs):
        self.pages.append(page.tab_id)
        page.browser.events.append(("worker", page.tab_id))
        if self.failure is not None:
            raise self.failure
        return SolveResult(ok=True, token="token")


def make_slot(browser, *, worker=None):
    # Unit tests only exercise context cleanup; skip strict browser binary checks.
    config = SolverConfig(strict_fingerprint=False, browser_path="/usr/bin/chromium")
    request = SolveRequest(expected_browser_major=136)
    accept_language = str(request.accept_language or config.accept_language or "").strip()
    locale = config.locale or accept_language.split(",", 1)[0].split(";", 1)[0].strip()
    affinity = BrowserAffinity.build(
        proxy=request.proxy or config.proxy,
        user_agent=request.user_agent or config.user_agent,
        headless=bool(request.headless or config.headless),
        locale=locale,
        accept_language=accept_language,
        browser_path=str(config.browser_path or ""),
        expected_platform=request.expected_platform,
        expected_client_hint_platform=request.expected_client_hint_platform,
        expected_browser_major=request.expected_browser_major,
        no_sandbox=config.resolved_no_sandbox(),
    )
    worker = worker or FakeWorker()
    slot = BrowserSlot(
        config,
        worker,
        affinity=affinity,
        upstream_proxy="",
        user_agent=request.user_agent or config.user_agent,
    )
    slot.browser = browser
    return slot, request, worker


class BrowserContextCleanupTests(unittest.TestCase):
    def test_closes_page_before_single_dispose_with_unique_context_ids(self):
        browser = FakeBrowser(["context-1", "context-2"])
        slot, request, _worker = make_slot(browser)

        first = slot.solve(request)
        second = slot.solve(request)

        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertEqual(first.extras["browser_context_cleanup"], "disposed")
        self.assertEqual(second.extras["browser_context_cleanup"], "disposed")
        disposals = [
            (index, event[2]["browserContextId"])
            for index, event in enumerate(browser.events)
            if event[0:2] == ("cdp", "Target.disposeBrowserContext")
        ]
        self.assertEqual([context_id for _, context_id in disposals], ["context-1", "context-2"])
        for target_id, (dispose_index, _context_id) in zip(("target-1", "target-2"), disposals):
            close_index = browser.events.index(("page.close", target_id))
            self.assertLess(close_index, dispose_index)

    def test_worker_exception_and_cancellation_still_dispose_context(self):
        for failure in (RuntimeError("worker failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                browser = FakeBrowser([f"context-{type(failure).__name__}"])
                slot, request, _worker = make_slot(browser, worker=FakeWorker(failure))
                if isinstance(failure, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        slot.solve(request)
                else:
                    result = slot.solve(request)
                    self.assertFalse(result.ok)
                self.assertEqual(
                    [event[0:2] for event in browser.events[-2:]],
                    [("page.close", f"target-1"), ("cdp", "Target.disposeBrowserContext")],
                )

    def test_dispose_failure_marks_slot_unhealthy_and_pool_recycles_it(self):
        browser = FakeBrowser(["context-fail"], fail_dispose=True)
        slot, request, worker = make_slot(browser)
        result = slot.solve(request)

        self.assertTrue(result.ok)
        self.assertEqual(result.extras["browser_context_cleanup"], "failed")
        self.assertEqual(slot.recycle_reason(), "context_close_failed")

        pool = PersistentBrowserPool(slot.config, worker=worker)
        with pool._condition:
            pool._slots[slot.slot_id] = slot
            pool._busy.add(slot.slot_id)
        with patch("src.browser_runtime.stop_browser_proxy"):
            pool._release(slot, result)
        self.assertTrue(browser.quit_called)
        self.assertNotIn(slot.slot_id, pool._slots)
        self.assertEqual(pool.stats.recycle_reasons.get("context_close_failed"), 1)

    def test_default_context_is_never_disposed_and_marks_slot_unhealthy(self):
        browser = FakeBrowser(["default"])
        slot, request, worker = make_slot(browser)

        result = slot.solve(request)

        self.assertFalse(result.ok)
        self.assertEqual(worker.pages, [])
        self.assertEqual(result.extras["browser_context_cleanup"], "failed")
        self.assertEqual(slot.recycle_reason(), "context_close_failed")
        self.assertFalse(
            any(event[0:2] == ("cdp", "Target.disposeBrowserContext") for event in browser.events)
        )


if __name__ == "__main__":
    unittest.main()
