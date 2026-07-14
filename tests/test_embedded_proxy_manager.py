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



    def test_tls_consecutive_fails_extend_cooldown(self):
        m = self._mgr(1)
        n = m.acquire()
        nid = n.id
        m.release(nid, failed=True, reason="curl: (35) TLS connect error")
        cd1 = m._nodes[nid].cooldown_until
        self.assertFalse(m._nodes[nid].healthy)
        self.assertEqual(m._nodes[nid].consecutive_tls_fails, 1)
        self.assertGreater(cd1, time.time())
        # force expire and release again with TLS
        m._nodes[nid].healthy = True
        m._nodes[nid].cooldown_until = 0
        m._nodes[nid].ref_count = 1
        m.release(nid, failed=True, reason="OPENSSL_internal:invalid library")
        self.assertEqual(m._nodes[nid].consecutive_tls_fails, 2)
        self.assertGreater(m._nodes[nid].cooldown_until - time.time(), 60.0)

    def test_non_tls_failure_resets_tls_streak(self):
        m = self._mgr(1)
        n = m.acquire()
        nid = n.id
        m.release(nid, failed=True, reason="curl: (35) TLS connect error")
        self.assertEqual(m._nodes[nid].consecutive_tls_fails, 1)
        m._nodes[nid].healthy = True
        m._nodes[nid].cooldown_until = 0
        m._nodes[nid].ref_count = 1
        m.release(nid, failed=True, reason="Connection refused")
        self.assertEqual(m._nodes[nid].consecutive_tls_fails, 0)

    def test_success_release_resets_tls_streak(self):
        m = self._mgr(1)
        n = m.acquire()
        nid = n.id
        m.release(nid, failed=True, reason="curl: (35) TLS connect error")
        self.assertEqual(m._nodes[nid].consecutive_tls_fails, 1)
        m._nodes[nid].healthy = True
        m._nodes[nid].cooldown_until = 0
        m._nodes[nid].ref_count = 1
        m.release(nid, failed=False)
        self.assertEqual(m._nodes[nid].consecutive_tls_fails, 0)


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

    def test_build_mihomo_config_hysteria2_and_anytls(self):
        from embedded_proxy_manager import (
            NodeSlot,
            build_mihomo_config,
            parse_anytls_node,
            parse_hysteria2_node,
        )

        hy = parse_hysteria2_node(
            "hy2://secret@hy.example:8443?sni=hy.example&insecure=1&obfs=salamander&obfs-password=op#hy-a"
        )
        anytls = parse_anytls_node(
            "anytls://pwd@any.example:443?sni=any.example&fp=chrome#any-a"
        )
        self.assertIsNotNone(hy)
        self.assertIsNotNone(anytls)
        nodes = [
            NodeSlot(
                id="hy1",
                name=hy["name"],
                server=hy["server"],
                port=hy["port"],
                protocol="hysteria2",
                local_http="",
                password=hy["password"],
                params=hy["params"],
                raw=hy["raw"],
            ),
            NodeSlot(
                id="any1",
                name=anytls["name"],
                server=anytls["server"],
                port=anytls["port"],
                protocol="anytls",
                local_http="",
                password=anytls["password"],
                params=anytls["params"],
                raw=anytls["raw"],
            ),
        ]
        cfg = build_mihomo_config(nodes, listen_host="127.0.0.1", base_port=29000)
        self.assertEqual(len(cfg["proxies"]), 2)
        types = {p["type"] for p in cfg["proxies"]}
        self.assertEqual(types, {"hysteria2", "anytls"})
        hy_proxy = next(p for p in cfg["proxies"] if p["type"] == "hysteria2")
        self.assertEqual(hy_proxy["password"], "secret")
        self.assertEqual(hy_proxy["sni"], "hy.example")
        self.assertTrue(hy_proxy.get("skip-cert-verify"))
        self.assertEqual(hy_proxy.get("obfs"), "salamander")
        any_proxy = next(p for p in cfg["proxies"] if p["type"] == "anytls")
        self.assertEqual(any_proxy["password"], "pwd")
        self.assertEqual(any_proxy["sni"], "any.example")
        self.assertEqual(any_proxy.get("client-fingerprint"), "chrome")
        self.assertEqual(cfg["listeners"][0]["port"], 29000)
        self.assertTrue(nodes[0].local_http.startswith("http://127.0.0.1:"))

    def test_build_mihomo_config_trojan(self):
        from embedded_proxy_manager import (
            NodeSlot,
            build_mihomo_config,
            is_embedded_share_link,
            parse_embedded_node,
            parse_trojan_node,
        )

        raw = (
            "trojan://synthetic%2Dsecret@trojan.example:443?"
            "sni=edge.example&skip-cert-verify=1&udp=1&ip-version=ipv4#trojan-a"
        )
        parsed = parse_trojan_node(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["password"], "synthetic-secret")
        self.assertEqual(parsed["server"], "trojan.example")
        self.assertEqual(parsed["params"]["ip-version"], "ipv4")
        self.assertEqual(parse_embedded_node(raw)["protocol"], "trojan")
        self.assertTrue(is_embedded_share_link(raw))
        self.assertIsNone(parse_trojan_node("trojan://trojan.example:443"))

        node = NodeSlot(
            id="trojan-1",
            name=parsed["name"],
            server=parsed["server"],
            port=parsed["port"],
            protocol="trojan",
            local_http="",
            password=parsed["password"],
            params=parsed["params"],
            raw=parsed["raw"],
        )
        cfg = build_mihomo_config([node], listen_host="127.0.0.1", base_port=29500)
        self.assertEqual(len(cfg["proxies"]), 1)
        proxy = cfg["proxies"][0]
        self.assertEqual(proxy["type"], "trojan")
        self.assertEqual(proxy["password"], "synthetic-secret")
        self.assertEqual(proxy["sni"], "edge.example")
        self.assertTrue(proxy["skip-cert-verify"])
        self.assertTrue(proxy["udp"])
        self.assertEqual(proxy["ip-version"], "ipv4")
        self.assertEqual(cfg["listeners"][0]["port"], 29500)
        self.assertEqual(node.local_http, "http://127.0.0.1:29500")


class LifecycleTests(unittest.TestCase):
    def test_find_binary_prefers_explicit_then_path(self):
        from embedded_proxy_manager import find_mihomo_binary

        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "verge-mihomo"
            binary.write_bytes(b"synthetic executable")
            binary.chmod(0o755)
            self.assertEqual(find_mihomo_binary(str(binary)), str(binary.resolve()))

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
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        fake_proc.pid = 4242

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "verge-mihomo"
            binary.write_bytes(b"synthetic executable")
            binary.chmod(0o755)
            cfg = EmbeddedProxyConfig(
                binary_path=str(binary),
                base_port=28000,
                listen_host="127.0.0.1",
            )
            m = EmbeddedProxyManager(cfg)
            with mock.patch.object(m, "_project_root", return_value=root):
                with mock.patch("embedded_proxy_manager.subprocess.Popen", return_value=fake_proc) as popen:
                    with mock.patch.object(m, "_wait_port_open", return_value=True):
                        info = m.start(nodes, cfg)

            config_path = root / ".local" / "state" / "embedded_mihomo" / "config.yaml"
            self.assertTrue(config_path.is_file())
            self.assertTrue(m._running)
            self.assertTrue(info.get("running"))
            popen.assert_called_once()
            args = popen.call_args[0][0]
            self.assertEqual(args[0], str(binary.resolve()))
            self.assertIn("-f", args)
            self.assertIn("-d", args)
            m.stop()


class CooldownReviveTests(unittest.TestCase):
    def test_revive_cooled_nodes_makes_them_acquirable(self):
        from embedded_proxy_manager import EmbeddedProxyManager, NodeSlot, EmbeddedProxyConfig
        import time
        mgr = EmbeddedProxyManager(EmbeddedProxyConfig())
        node = NodeSlot(
            id="n1",
            name="n1",
            server="x",
            port=443,
            protocol="vless",
            local_http="http://127.0.0.1:28001",
            healthy=False,
            fail_count=2,
            cooldown_until=time.time() - 1,
        )
        mgr._nodes = {"n1": node}
        mgr._running = True
        revived = mgr.revive_cooled_nodes()
        self.assertEqual(revived, 1)
        self.assertTrue(node.healthy)
        got = mgr.acquire()
        self.assertIsNotNone(got)
        self.assertEqual(got.id, "n1")

    def test_status_revives_before_counting_healthy(self):
        from embedded_proxy_manager import EmbeddedProxyManager, NodeSlot, EmbeddedProxyConfig
        import time
        mgr = EmbeddedProxyManager(EmbeddedProxyConfig())
        mgr._nodes = {
            "n1": NodeSlot(
                id="n1", name="n1", server="x", port=443, protocol="vless",
                local_http="http://127.0.0.1:28001", healthy=False,
                cooldown_until=time.time() - 5,
            )
        }
        mgr._running = True
        st = mgr.status()
        self.assertEqual(st["healthy"], 1)
