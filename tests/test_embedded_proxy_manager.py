# tests/test_embedded_proxy_manager.py
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from embedded_proxy_manager import EmbeddedProxyManager, NodeSlot


class LeaseTests(unittest.TestCase):
    def _mgr(self, n=3):
        m = EmbeddedProxyManager.__new__(EmbeddedProxyManager)
        m._lock = __import__("threading").RLock()
        m._nodes = {}
        for i in range(n):
            slot = NodeSlot(
                id=f"n{i}",
                name=f"node-{i}",
                server=f"{i}.example",
                port=443,
                protocol="vless",
                local_http=f"http://127.0.0.1:{28000+i}",
                healthy=True,
            )
            m._nodes[slot.id] = slot
        m._running = True
        return m

    def test_prefer_idle_then_reuse_lowest_ref(self):
        m = self._mgr(2)
        a = m.acquire()
        self.assertEqual(a.ref_count, 1)
        b = m.acquire()
        self.assertNotEqual(a.id, b.id)
        c = m.acquire()  # reuse
        self.assertIn(c.id, {a.id, b.id})
        self.assertEqual(m._nodes[c.id].ref_count, 2)

    def test_exclude_and_unhealthy_not_selected(self):
        m = self._mgr(2)
        m._nodes["n0"].healthy = False
        got = m.acquire(exclude_ids={"n1"})
        self.assertIsNone(got)

    def test_release_failed_marks_unhealthy_or_cooldown(self):
        m = self._mgr(1)
        n = m.acquire()
        m.release(n.id, failed=True)
        self.assertEqual(m._nodes[n.id].ref_count, 0)
        self.assertTrue(
            (not m._nodes[n.id].healthy)
            or m._nodes[n.id].cooldown_until > time.time()
        )


class ConfigGenTests(unittest.TestCase):
    def test_build_mihomo_config_maps_ports_and_proxies(self):
        from embedded_proxy_manager import NodeSlot, build_mihomo_config

        nodes = [
            NodeSlot(
                id="a", name="jp", server="jp.example", port=443, protocol="vless",
                local_http="", uuid="11111111-1111-1111-1111-111111111111",
                params={"security": "tls", "sni": "jp.example", "type": "tcp"},
            ),
            NodeSlot(
                id="b", name="hk", server="hk.example", port=443, protocol="vless",
                local_http="", uuid="22222222-2222-2222-2222-222222222222",
                params={"security": "reality", "sni": "www.example.com", "pbk": "PK", "sid": "abcd", "type": "tcp", "fp": "chrome"},
            ),
        ]
        cfg = build_mihomo_config(nodes, listen_host="127.0.0.1", base_port=28000)
        self.assertEqual(cfg["allow-lan"], False)
        self.assertEqual(len(cfg["proxies"]), 2)
        self.assertEqual(len(cfg["listeners"]), 2)
        self.assertEqual(cfg["listeners"][0]["port"], 28000)
        self.assertEqual(cfg["listeners"][1]["port"], 28001)
        # 每个 listener 绑定对应 proxy
        self.assertEqual(cfg["listeners"][0]["proxy"], cfg["proxies"][0]["name"])


class LifecycleTests(unittest.TestCase):
    def test_find_binary_prefers_explicit_then_path(self):
        from embedded_proxy_manager import find_mihomo_binary

        self.assertEqual(find_mihomo_binary("/usr/bin/verge-mihomo"), "/usr/bin/verge-mihomo")

    def test_probe_marks_healthy(self):
        from embedded_proxy_manager import EmbeddedProxyConfig, EmbeddedProxyManager, NodeSlot

        m = EmbeddedProxyManager(EmbeddedProxyConfig(probe_timeout_sec=1.0))
        slot = NodeSlot(
            id="n0",
            name="node-0",
            server="0.example",
            port=443,
            protocol="vless",
            local_http="http://127.0.0.1:28000",
            healthy=False,
        )
        m._nodes = {slot.id: slot}
        m._running = True

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, n=-1):
                return b"ok"

        with mock.patch("embedded_proxy_manager.urllib.request.build_opener") as build_opener:
            opener = mock.Mock()
            opener.open.return_value = _Resp()
            build_opener.return_value = opener
            result = m.probe_one("n0")

        self.assertTrue(result.get("healthy"))
        self.assertTrue(m._nodes["n0"].healthy)
        self.assertIsNotNone(m._nodes["n0"].last_latency_ms)

    def test_start_writes_config_and_spawns(self):
        from embedded_proxy_manager import (
            EmbeddedProxyConfig,
            EmbeddedProxyManager,
            NodeSlot,
        )

        nodes = [
            NodeSlot(
                id="a",
                name="jp",
                server="jp.example",
                port=443,
                protocol="vless",
                local_http="",
                uuid="11111111-1111-1111-1111-111111111111",
                params={"security": "tls", "sni": "jp.example", "type": "tcp"},
            )
        ]
        cfg = EmbeddedProxyConfig(
            binary_path="/usr/bin/verge-mihomo",
            base_port=28000,
            listen_host="127.0.0.1",
        )
        m = EmbeddedProxyManager(cfg)

        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        fake_proc.pid = 4242

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(m, "_project_root", return_value=root):
                with mock.patch("embedded_proxy_manager.subprocess.Popen", return_value=fake_proc) as popen:
                    with mock.patch.object(m, "_wait_port_open", return_value=True):
                        info = m.start(nodes, cfg)

            config_path = root / ".embedded_mihomo" / "config.yaml"
            self.assertTrue(config_path.is_file())
            self.assertTrue(m._running)
            self.assertTrue(info.get("running"))
            popen.assert_called_once()
            args = popen.call_args[0][0]
            self.assertEqual(args[0], "/usr/bin/verge-mihomo")
            self.assertIn("-f", args)
            self.assertIn("-d", args)
