"""Protocol and exclusive-port tests for the local HTTP proxy forwarder."""

import socket
import socketserver
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import local_proxy_forwarder as forwarder


class _RecordingSocket:
    def __init__(self, replies=()):
        self.replies = list(replies)
        self.sent = []
        self.timeouts = []
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _size):
        return self.replies.pop(0) if self.replies else b""

    def close(self):
        self.closed = True


class _RecordingClient:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)


def _handler(upstream):
    """Build a handler without constructing a socketserver request handler."""
    handler = object.__new__(forwarder._ProxyHandler)
    handler.upstream = upstream
    handler._pipe = lambda *_args: None
    return handler


class LocalProxyForwarderProtocolTests(unittest.TestCase):
    def test_authenticated_upstream_connect_injects_proxy_authorization(self):
        upstream = forwarder.UpstreamProxy(
            "http", "residential.example", 10000, "up-user", "up-pass"
        )
        tunnel = _RecordingSocket(
            (
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
            )
        )
        client = _RecordingClient()

        with mock.patch.object(forwarder.socket, "create_connection", return_value=tunnel) as connect:
            _handler(upstream)._handle_connect(client, "api.example:443", "HTTP/1.1")

        connect.assert_called_once_with(
            ("residential.example", 10000),
            timeout=forwarder.CONNECT_TIMEOUT,
        )
        self.assertEqual(len(tunnel.sent), 1)
        request = tunnel.sent[0]
        self.assertIn(b"CONNECT api.example:443 HTTP/1.1", request)
        self.assertIn(b"Proxy-Authorization: Basic dXAtdXNlcjp1cC1wYXNz", request)
        self.assertEqual(client.sent, [b"HTTP/1.1 200 Connection Established\r\n\r\n"])

    def test_opening_upstream_is_direct(self):
        upstream = forwarder.UpstreamProxy("http", "upstream.example", 8080)
        sock = _RecordingSocket()

        with mock.patch.object(forwarder.socket, "create_connection", return_value=sock) as connect:
            actual = _handler(upstream)._open_upstream()

        self.assertIs(actual, sock)
        connect.assert_called_once_with(("upstream.example", 8080), timeout=forwarder.CONNECT_TIMEOUT)
        self.assertEqual(sock.sent, [])

    def test_plain_http_request_injects_upstream_auth_directly(self):
        upstream = forwarder.UpstreamProxy(
            "http", "residential.example", 10000, "up-user", "up-pass"
        )
        tunnel = _RecordingSocket()
        raw_head = (
            b"GET http://api.example/status HTTP/1.1\r\n"
            b"Host: api.example\r\n"
            b"Proxy-Authorization: Basic client-credentials\r\n\r\n"
        )

        with mock.patch.object(forwarder.socket, "create_connection", return_value=tunnel) as connect:
            _handler(upstream)._handle_http(
                _RecordingClient(),
                "GET",
                "http://api.example/status",
                "HTTP/1.1",
                {},
                raw_head,
            )

        connect.assert_called_once_with(
            ("residential.example", 10000),
            timeout=forwarder.CONNECT_TIMEOUT,
        )
        request = tunnel.sent[0]
        self.assertTrue(request.startswith(b"GET http://api.example/status HTTP/1.1\r\n"))
        self.assertIn(b"Proxy-Authorization: Basic dXAtdXNlcjp1cC1wYXNz", request)
        self.assertNotIn(b"client-credentials", request)


class LocalProxyForwarderOwnershipTests(unittest.TestCase):
    @staticmethod
    def _free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def _instance(port):
        return forwarder.LocalProxyForwarder(
            forwarder.UpstreamProxy("http", "upstream.example", 8080),
            local_port=port,
        )

    def tearDown(self):
        forwarder.stop_local_forwarder()

    def test_parallel_bind_never_shares_one_worker_port(self):
        port = self._free_port()
        first = self._instance(port)
        second = self._instance(port)
        try:
            self.assertEqual(first.start(), f"http://127.0.0.1:{port}")
            with self.assertRaises(OSError):
                second.start()
        finally:
            second.stop()
            first.stop()

    def test_parallel_start_race_has_exactly_one_port_owner(self):
        port = self._free_port()
        instances = [self._instance(port), self._instance(port)]

        def start(item):
            try:
                return (True, item.start())
            except OSError:
                return (False, "")

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(start, instances))
            self.assertEqual(sum(ok for ok, _url in results), 1)
        finally:
            for item in instances:
                item.stop()

    def test_fast_stop_start_reclaims_port_after_full_shutdown(self):
        port = self._free_port()
        first = self._instance(port)
        first.start()
        first.stop()
        second = self._instance(port)
        try:
            self.assertEqual(second.start(), f"http://127.0.0.1:{port}")
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        finally:
            second.stop()

    def test_registry_replacement_cleans_stale_worker_before_rebind(self):
        port = self._free_port()
        key = "stale-worker-test"
        first_url, used = forwarder.ensure_local_forwarder(
            "http://u1:p1@one.example:8080",
            preferred_local_port=port,
            instance_key=key,
        )
        self.assertTrue(used)
        second_url, used = forwarder.ensure_local_forwarder(
            "http://u2:p2@two.example:8080",
            preferred_local_port=port,
            instance_key=key,
        )
        self.assertTrue(used)
        self.assertEqual(first_url, second_url)
        self.assertEqual(len(forwarder._FORWARDERS), 1)
        self.assertEqual(forwarder.get_active_local_proxy_url(key), second_url)

    def test_registry_does_not_return_externally_stopped_instance(self):
        port = self._free_port()
        key = "externally-stopped-test"
        first_url, _ = forwarder.ensure_local_forwarder(
            "http://u:p@one.example:8080",
            preferred_local_port=port,
            instance_key=key,
        )
        stale = forwarder._FORWARDERS[key]
        stale.stop()
        self.assertFalse(stale.is_running)
        second_url, used = forwarder.ensure_local_forwarder(
            "http://u:p@one.example:8080",
            preferred_local_port=port,
            instance_key=key,
        )
        self.assertTrue(used)
        self.assertEqual(first_url, second_url)
        self.assertIsNot(forwarder._FORWARDERS[key], stale)
        self.assertTrue(forwarder._FORWARDERS[key].is_running)

    def test_non_bind_startup_error_is_not_hidden_by_ephemeral_fallback(self):
        with mock.patch.object(
            forwarder.LocalProxyForwarder,
            "start",
            side_effect=RuntimeError("readiness failed"),
        ) as start:
            with self.assertRaisesRegex(RuntimeError, "readiness failed"):
                forwarder.ensure_local_forwarder(
                    "http://u:p@one.example:8080",
                    preferred_local_port=self._free_port(),
                    instance_key="startup-error-test",
                )
        self.assertEqual(start.call_count, 1)

    def test_windows_server_bind_requests_exclusive_address_use(self):
        server = object.__new__(forwarder.ThreadingTCPServer)
        server.socket = mock.Mock()
        exclusive_address_use = getattr(socket, "SO_EXCLUSIVEADDRUSE", 0x4)
        with mock.patch.object(
            socket,
            "SO_EXCLUSIVEADDRUSE",
            exclusive_address_use,
            create=True,
        ), mock.patch.object(forwarder.os, "name", "nt"), mock.patch.object(
            socketserver.TCPServer,
            "server_bind",
        ) as base_bind:
            forwarder.ThreadingTCPServer.server_bind(server)
        server.socket.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET,
            exclusive_address_use,
            1,
        )
        base_bind.assert_called_once_with()

    def test_server_reuse_flags_are_disabled(self):
        self.assertFalse(forwarder.ThreadingTCPServer.allow_reuse_address)
        self.assertFalse(forwarder.ThreadingTCPServer.allow_reuse_port)


if __name__ == "__main__":
    unittest.main()
