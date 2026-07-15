# -*- coding: utf-8 -*-
"""Tests for GPT-style proxy pool rotator integration."""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from proxy_pool import (
    ProxyRotator,
    configure_global_rotator,
    extract_country,
    load_proxy_lines,
    normalize_proxy_line,
    normalize_proxy_pool,
    pick_proxy,
    report_outcome,
    redact_proxy_text,
    validate_proxy_line,
)


class ProxyNormalizeTests(unittest.TestCase):
    def test_host_port_user_pass(self):
        raw = "us.swiftproxy.net:7878:user_zone_JP:pass"
        self.assertEqual(
            normalize_proxy_line(raw),
            "http://user_zone_JP:pass@us.swiftproxy.net:7878",
        )

    def test_reject_null_host(self):
        raw = "null:10000:USER921375-zone-custom-region-US-session-1:secret"
        normalized, err = validate_proxy_line(raw)
        self.assertEqual(normalized, "")
        self.assertIn("无效代理主机", err)

    def test_reject_none_host(self):
        normalized, err = validate_proxy_line("none:10000:u:p")
        self.assertEqual(normalized, "")
        self.assertTrue(err)

    def test_normalize_pool_drops_invalid(self):
        pool = normalize_proxy_pool(
            [
                "null:10000:u:p",
                "us.swiftproxy.net:7878:user_zone_JP:pass",
                "us.swiftproxy.net:7878:user_zone_JP:pass",  # dup
            ]
        )
        self.assertEqual(len(pool), 1)
        self.assertIn("swiftproxy", pool[0])

    def test_load_proxy_lines_skips_null(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxies.txt"
            path.write_text(
                "\n".join(
                    [
                        "null:10000:u:p",
                        "# comment",
                        "gate.example.com:10000:user_zone_US:pwd",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            lines = load_proxy_lines(str(path))
        self.assertEqual(len(lines), 1)
        self.assertIn("gate.example.com", lines[0])

    def test_extract_country_zone_and_host(self):
        self.assertEqual(extract_country("http://u_zone_JP:p@h:1"), "JP")
        self.assertEqual(
            extract_country(
                "http://USER-zone-custom-region-US-session-1:p@host:10000"
            ),
            "US",
        )
        self.assertEqual(extract_country("http://u:p@us.swiftproxy.net:7878"), "US")


class ProxyRotatorTests(unittest.TestCase):
    def test_weighted_next_and_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = os.path.join(tmp, "stats.log")
            pool = [
                "http://u_zone_JP:p@a.example:1000",
                "http://u_zone_US:p@b.example:1000",
            ]
            rot = ProxyRotator(pool, stats_file=stats)
            self.assertEqual(len(rot), 2)
            first = rot.next()
            self.assertIn(first, pool)
            rot.record_result(first, False, "boom")
            rot.mark_bad(first, cooldown_seconds=60)
            second = rot.next()
            self.assertNotEqual(second, first)
            # status exposes cooldown
            statuses = {row["proxy"]: row for row in rot.get_status()}
            self.assertTrue(any(row["status"] == "bad" for row in statuses.values()))
            countries = {row["country"] for row in rot.get_country_stats()}
            self.assertTrue({"JP", "US"} & countries)

    def test_configure_global_and_pick(self):
        pool = [
            "http://u_zone_JP:p@a.example:1000",
            "http://u_zone_US:p@b.example:1000",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            stats = os.path.join(tmp, "stats.log")
            rot = configure_global_rotator(pool, stats_file=stats, force=True)
            self.assertEqual(len(rot), 2)
            chosen = pick_proxy()
            self.assertIn(chosen, pool)
            report_outcome(chosen, False, "proxy_error")
            report_outcome(chosen, True, "ok")

    def test_concurrent_leases_are_unique_and_release_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = os.path.join(tmp, "stats.log")
            pool = [f"http://user:secret@p{i}.example:8080" for i in range(5)]
            rot = ProxyRotator(pool, stats_file=stats)
            with ThreadPoolExecutor(max_workers=5) as executor:
                leases = list(
                    executor.map(
                        lambda index: rot.acquire_lease(owner=f"worker-{index}"),
                        range(5),
                    )
                )
            self.assertTrue(all(leases))
            self.assertEqual(len({lease.proxy for lease in leases}), 5)
            self.assertIsNone(rot.acquire_lease(owner="overflow"))
            self.assertEqual(rot.active_lease_count(), 5)

            lease = leases[0]
            self.assertTrue(rot.release_lease(lease, success=True, reason="ok"))
            self.assertFalse(rot.release_lease(lease, success=True, reason="duplicate"))
            self.assertEqual(rot.active_lease_count(), 4)
            replacement = rot.acquire_lease(owner="replacement")
            self.assertIsNotNone(replacement)
            self.assertEqual(replacement.proxy, lease.proxy)

    def test_generic_rotation_never_selects_an_actively_leased_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = [
                "http://u:p@one.example:8080",
                "http://u:p@two.example:8080",
            ]
            rot = ProxyRotator(pool, stats_file=os.path.join(tmp, "stats.log"))
            first = rot.acquire_lease(owner="worker-1")
            self.assertIsNotNone(first)
            self.assertEqual(rot.next(), next(item for item in pool if item != first.proxy))
            second = rot.acquire_lease(owner="worker-2")
            self.assertIsNotNone(second)
            self.assertIsNone(rot.next())
            self.assertEqual(rot.next_batch(3), [])

    def test_failed_lease_cools_down_then_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            proxy = "http://user:secret@p.example:8080"
            rot = ProxyRotator([proxy], stats_file=os.path.join(tmp, "stats.log"))
            lease = rot.acquire_lease(owner="worker")
            self.assertIsNotNone(lease)
            with mock.patch("proxy_pool.time.time", return_value=1000.0):
                self.assertTrue(
                    rot.release_lease(
                        lease,
                        success=False,
                        reason="curl: (35)",
                        cooldown_seconds=1,
                    )
                )
                self.assertEqual(rot.available_lease_count(), 0)
            with mock.patch("proxy_pool.time.time", return_value=1002.0):
                self.assertEqual(rot.available_lease_count(), 1)
                self.assertIsNotNone(rot.acquire_lease(owner="recovered"))

    def test_failed_release_applies_cooldown_before_route_becomes_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            rot = ProxyRotator(
                ["http://u:p@p.example:8080"],
                stats_file=os.path.join(tmp, "stats.log"),
            )
            lease = rot.acquire_lease(owner="worker")
            append_started = threading.Event()
            finish_append = threading.Event()

            def slow_append(*_args, **_kwargs):
                append_started.set()
                finish_append.wait(timeout=2)

            with mock.patch.object(rot, "_append_log", side_effect=slow_append):
                thread = threading.Thread(
                    target=lambda: rot.release_lease(
                        lease,
                        success=False,
                        reason="route failure",
                        cooldown_seconds=60,
                    )
                )
                thread.start()
                self.assertTrue(append_started.wait(timeout=1))
                self.assertIsNone(rot.acquire_lease(owner="racing-worker"))
                finish_append.set()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_expired_lease_is_recovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            rot = ProxyRotator(
                ["http://u:p@p.example:8080"],
                stats_file=os.path.join(tmp, "stats.log"),
            )
            with mock.patch(
                "proxy_pool.time.monotonic",
                side_effect=[10.0, 10.0, 12.0, 12.0],
            ):
                lease = rot.acquire_lease(owner="abandoned", ttl_seconds=1)
                self.assertIsNotNone(lease)
                self.assertEqual(rot.recover_expired_leases(), 1)
                self.assertEqual(rot.available_lease_count(), 1)

    def test_stats_and_diagnostics_redact_proxy_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = Path(tmp) / "stats.log"
            proxy = "http://alice:top-secret@p.example:8080"
            rot = ProxyRotator([proxy], stats_file=str(stats))
            lease = rot.acquire_lease(owner="worker")
            rot.release_lease(
                lease,
                success=False,
                reason=f"route failed via {proxy}",
                cooldown_seconds=1,
            )
            persisted = stats.read_text(encoding="utf-8")
            self.assertNotIn("alice", persisted)
            self.assertNotIn("top-secret", persisted)
            self.assertNotIn("top-secret", repr(lease))
            self.assertNotIn("top-secret", repr(rot.lease_status()))
            self.assertEqual(
                redact_proxy_text(f"failure {proxy}", [proxy]),
                "failure http://***@p.example:8080",
            )

            owner_lease = ProxyRotator(
                ["http://u:p@other.example:8080"],
                stats_file=str(Path(tmp) / "owner.log"),
            ).acquire_lease(owner="http://owner:owner-secret@internal.example:80")
            self.assertNotIn("owner-secret", repr(owner_lease))


if __name__ == "__main__":
    unittest.main()
