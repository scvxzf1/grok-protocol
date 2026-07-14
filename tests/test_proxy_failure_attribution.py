# -*- coding: utf-8 -*-
from __future__ import annotations

import unittest

from http_batch_service import _looks_like_proxy_failure


class ProxyFailureAttributionTests(unittest.TestCase):
    def test_tls_still_proxy(self):
        self.assertTrue(
            _looks_like_proxy_failure(
                "Failed to perform, curl: (35) TLS connect error: OPENSSL_internal"
            )
        )

    def test_turnstile_timeout_not_proxy(self):
        self.assertFalse(
            _looks_like_proxy_failure(
                "Turnstile broker 求解失败: 在 30s 内未捕获到可用 Turnstile token"
            )
        )

    def test_fake_token_not_proxy(self):
        self.assertFalse(
            _looks_like_proxy_failure(
                "Turnstile 求解返回 | token_len=0 reported_len=794 lease=yes\n"
                "注册验证被拒绝: Failed to verify Cloudflare turnstile token"
            )
        )

    def test_connect_refused_is_proxy(self):
        self.assertTrue(_looks_like_proxy_failure("ProxyError Connection refused"))

    def test_later_transport_error_wins_over_earlier_challenge_timeout(self):
        self.assertTrue(
            _looks_like_proxy_failure(
                "Turnstile timeout while waiting\nProxyError Connection refused"
            )
        )


if __name__ == "__main__":
    unittest.main()
