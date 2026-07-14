from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from src.api import create_app
from src.models import SolveResult, TokenLease


class FakeService:
    def __init__(self):
        self.last_request = None
        self.result = SolveResult(ok=False, error="fake solver")
        self.last_permit_args = None
        self.health_payload = {"ok": True}

    def start(self):
        return None

    def close(self):
        return None

    def health(self):
        return self.health_payload

    def solve(self, request):
        self.last_request = request
        return self.result

    def consume_lease(self, lease_id):
        if self.result.lease is None or self.result.lease.lease_id != lease_id:
            raise AssertionError("unexpected lease")
        return self.result.lease

    def acquire_submit_permit(self, timeout_sec, lease_sec=0):
        self.last_permit_args = (timeout_sec, lease_sec)

        class Permit:
            def to_dict(self):
                return {"ok": True, "permit_id": "permit", "lease_sec": lease_sec}

        return Permit()


class ApiSchemaRegressionTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeService()
        self.app = create_app(self.service)

    def test_openapi_contains_json_solve_body(self):
        schema = self.app.openapi()
        operation = schema["paths"]["/v1/solve"]["post"]
        self.assertIn("requestBody", operation)
        self.assertIn("application/json", operation["requestBody"]["content"])
        properties = schema["components"]["schemas"]["SolveBody"]["properties"]
        self.assertNotIn("parent_proxy", properties)

    def test_minimal_solve_json_is_not_model_resolution_422(self):
        with TestClient(self.app) as client:
            response = client.post("/v1/solve", json={})
        self.assertNotEqual(response.status_code, 422)
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(self.service.last_request)
        self.assertEqual(self.service.last_request.provider, "local")

    def test_success_response_redacts_token_and_browser_cookies(self):
        raw_proxy = "socks5://private-user:private-password@[2001:db8::7]:1080"
        public_proxy = "socks5://[2001:db8::7]:1080"
        lease = TokenLease.issue("secret-token", proxy=raw_proxy)
        self.service.result = SolveResult(
            ok=True,
            token="secret-token",
            proxy=raw_proxy,
            extras={
                "token_length": 12,
                "cookies": [{"name": "session"}],
                "proxy_details": {
                    "url": raw_proxy,
                    "proxyLogin": "private-user",
                    "proxyPassword": "private-password",
                    "history": [raw_proxy],
                },
                "last_error": f"failed through {raw_proxy}",
            },
            lease=lease,
        )
        with TestClient(self.app) as client:
            response = client.post("/v1/solve", json={})
        payload = response.json()
        self.assertEqual(payload["token"], "")
        self.assertEqual(payload["proxy"], public_proxy)
        self.assertEqual(payload["lease"]["proxy"], public_proxy)
        self.assertEqual(payload["extras"]["proxy_details"]["url"], public_proxy)
        self.assertEqual(payload["extras"]["proxy_details"]["history"], [public_proxy])
        self.assertNotIn("proxyLogin", payload["extras"]["proxy_details"])
        self.assertNotIn("proxyPassword", payload["extras"]["proxy_details"])
        self.assertEqual(payload["extras"]["last_error"], f"failed through {public_proxy}")
        self.assertEqual(payload["lease"]["lease_id"], lease.lease_id)
        self.assertNotIn("secret-token", response.text)
        self.assertNotIn("private-user", response.text)
        self.assertNotIn("private-password", response.text)

        with TestClient(self.app) as client:
            consumed = client.post(f"/v1/leases/{lease.lease_id}/consume")
        consumed_payload = consumed.json()
        self.assertEqual(consumed_payload["token"], "secret-token")
        self.assertEqual(consumed_payload["proxy"], public_proxy)
        self.assertNotIn("private-user", consumed.text)
        self.assertNotIn("private-password", consumed.text)

    def test_health_redacts_authenticated_proxy_urls(self):
        raw_proxy = "http://health-user:health-password@198.51.100.7:8080"
        self.service.health_payload = {
            "ok": True,
            "config": {"proxy": raw_proxy},
            "pool": {"last_error": f"connection failed via {raw_proxy}"},
        }
        with TestClient(self.app) as client:
            response = client.get("/health")
        payload = response.json()
        self.assertEqual(payload["config"]["proxy"], "http://198.51.100.7:8080")
        self.assertEqual(
            payload["pool"]["last_error"],
            "connection failed via http://198.51.100.7:8080",
        )
        self.assertNotIn("health-user", response.text)
        self.assertNotIn("health-password", response.text)

    def test_submit_permit_acquire_accepts_lease_sec(self):
        with TestClient(self.app) as client:
            response = client.post(
                "/v1/permits/submit/acquire",
                json={"timeout_sec": 7, "lease_sec": 45},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.service.last_permit_args, (7, 45))


if __name__ == "__main__":
    unittest.main()
