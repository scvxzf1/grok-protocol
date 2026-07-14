"""Small protocol tests for the optional parent HTTP proxy tunnel."""

import unittest
from unittest import mock
from urllib.parse import urlparse

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


def _handler(upstream, parent=None):
    """Build a handler without constructing a socketserver request handler."""
    handler = object.__new__(forwarder._ProxyHandler)
    handler.upstream = upstream
    handler.parent_proxy = parent
    handler._pipe = lambda *_args: None
    return handler


class LocalProxyForwarderParentChainTests(unittest.TestCase):
    def tearDown(self):
        forwarder.stop_local_forwarder()

    def test_parent_connect_precedes_authenticated_upstream_connect(self):
        parent = forwarder.UpstreamProxy(
            "http", "127.0.0.1", 7890, "parent-user", "parent-pass"
        )
        upstream = forwarder.UpstreamProxy(
            "http", "residential.example", 10000, "up-user", "up-pass"
        )
        # The first response belongs to the outer parent CONNECT; the second
        # belongs to the CONNECT sent through that tunnel to the upstream.
        tunnel = _RecordingSocket(
            (
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
            )
        )
        client = _RecordingClient()

        with mock.patch.object(forwarder.socket, "create_connection", return_value=tunnel) as connect:
            _handler(upstream, parent)._handle_connect(client, "api.example:443", "HTTP/1.1")

        connect.assert_called_once_with(("127.0.0.1", 7890), timeout=forwarder.CONNECT_TIMEOUT)
        self.assertEqual(len(tunnel.sent), 2)
        outer, inner = tunnel.sent
        self.assertIn(b"CONNECT residential.example:10000 HTTP/1.1", outer)
        self.assertIn(b"Proxy-Authorization: Basic cGFyZW50LXVzZXI6cGFyZW50LXBhc3M=", outer)
        self.assertNotIn(b"dXAtdXNlcjp1cC1wYXNz", outer)
        self.assertIn(b"CONNECT api.example:443 HTTP/1.1", inner)
        self.assertIn(b"Proxy-Authorization: Basic dXAtdXNlcjp1cC1wYXNz", inner)
        self.assertNotIn(b"cGFyZW50LXVzZXI6cGFyZW50LXBhc3M=", inner)
        self.assertEqual(client.sent, [b"HTTP/1.1 200 Connection Established\r\n\r\n"])

    def test_without_parent_opening_upstream_remains_direct(self):
        upstream = forwarder.UpstreamProxy("http", "upstream.example", 8080)
        sock = _RecordingSocket()

        with mock.patch.object(forwarder.socket, "create_connection", return_value=sock) as connect:
            actual = _handler(upstream)._open_upstream()

        self.assertIs(actual, sock)
        connect.assert_called_once_with(("upstream.example", 8080), timeout=forwarder.CONNECT_TIMEOUT)
        self.assertEqual(sock.sent, [])

    def test_plain_http_request_is_sent_inside_parent_tunnel(self):
        parent = forwarder.UpstreamProxy("http", "127.0.0.1", 7890)
        upstream = forwarder.UpstreamProxy(
            "http", "residential.example", 10000, "up-user", "up-pass"
        )
        tunnel = _RecordingSocket(
            (
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
        )
        raw_head = (
            b"GET http://api.example/status HTTP/1.1\r\n"
            b"Host: api.example\r\n"
            b"Proxy-Authorization: Basic client-credentials\r\n\r\n"
        )

        with mock.patch.object(forwarder.socket, "create_connection", return_value=tunnel):
            _handler(upstream, parent)._handle_http(
                _RecordingClient(),
                "GET",
                "http://api.example/status",
                "HTTP/1.1",
                {},
                raw_head,
            )

        outer, inner = tunnel.sent
        self.assertIn(b"CONNECT residential.example:10000 HTTP/1.1", outer)
        self.assertTrue(inner.startswith(b"GET http://api.example/status HTTP/1.1\r\n"))
        self.assertIn(b"Proxy-Authorization: Basic dXAtdXNlcjp1cC1wYXNz", inner)
        self.assertNotIn(b"client-credentials", inner)

    def test_concurrent_forwarders_never_share_listener_port(self):
        first_url, first_used = forwarder.ensure_local_forwarder(
            "upstream-a.example:8080:user-a:pass-a",
            preferred_local_port=0,
            instance_key="route-a",
        )
        first_port = int(urlparse(first_url).port or 0)
        second_url, second_used = forwarder.ensure_local_forwarder(
            "upstream-b.example:8080:user-b:pass-b",
            preferred_local_port=first_port,
            instance_key="route-b",
        )
        second_port = int(urlparse(second_url).port or 0)

        self.assertTrue(first_used)
        self.assertTrue(second_used)
        self.assertGreater(first_port, 0)
        self.assertGreater(second_port, 0)
        self.assertNotEqual(first_port, second_port)


if __name__ == "__main__":
    unittest.main()
