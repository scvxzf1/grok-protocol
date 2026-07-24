import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote
from unittest import mock

import xai_http_flow as flow


class DummyResponse:
    def __init__(
        self,
        *,
        text="",
        content=b"",
        status_code=200,
        url="https://accounts.x.ai/sign-up",
        json_data=None,
    ):
        self.text = text
        self.content = content
        self.status_code = status_code
        self.url = url
        self.json_data = json_data

    def json(self):
        if self.json_data is None:
            raise ValueError("No JSON payload")
        return self.json_data


class DummySession:
    def __init__(self, responses):
        self.responses = responses
        self.headers = {}

    def get(self, url, **kwargs):
        return self.responses[url]


class XAIHttpFlowTests(unittest.TestCase):
    def test_normalize_authenticated_proxy_pool_line(self):
        self.assertEqual(
            flow.normalize_proxy("proxy.example.test:1000:user:name:with:colons"),
            "http://user:name%3Awith%3Acolons@proxy.example.test:1000",
        )

    def test_parse_grpc_web_empty_success_response(self):
        raw = b"\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0fgrpc-status:0\r\n"
        frames, trailers = flow.parse_grpc_web_response(raw)
        self.assertEqual(frames, [b""])
        self.assertEqual(trailers, {"grpc-status": "0"})

    def test_extract_trace_sso_does_not_depend_on_request_body(self):
        events = [
            {
                "sequence": 1,
                "request_headers": json.dumps({"Cookie": "sso=old; sso-rw=oldrw"}),
                "request_body": "contains-an-unrelated-password",
            },
            {
                "sequence": 2,
                "request_headers": json.dumps({"cookie": "sso=new; sso-rw=newrw"}),
                "request_body": "another-unrelated-secret",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            path.write_text(json.dumps(events), encoding="utf-8")
            cookies = flow.extract_trace_sso(str(path))
        self.assertEqual(cookies.sso, "new")
        self.assertEqual(cookies.sso_rw, "newrw")

    def test_server_action_id_is_discovered_from_turbopack_shape(self):
        page_url = "https://accounts.x.ai/sign-up?redirect=grok-com"
        script_url = "https://accounts.x.ai/_next/static/chunks/signup.js"
        action_id = "a" * 42
        session = DummySession(
            {
                script_url: DummyResponse(
                    text=(
                        f'let ref=(0,i.createServerReference)("{action_id}",i.callServer);'
                        "const request={createUserAndSessionRequest:{}};"
                    )
                )
            }
        )
        client = flow.BrowserlessXAIClient(session=session)
        found = client._find_action_id(
            page_url=page_url,
            page_html='<script src="/_next/static/chunks/signup.js"></script>',
            marker="createUserAndSessionRequest",
            fallback="fallback",
        )
        self.assertEqual(found, action_id)

    def test_router_state_targets_expected_auth_route(self):
        state = json.loads(unquote(flow._router_state("consent")))
        self.assertEqual(state[1]["children"][1]["children"][1]["children"][0], "consent")

    def test_xai_code_normalization(self):
        self.assertEqual(flow.extract_xai_email_code("", "MWM-AME xAI confirmation code"), "MWMAME")
        self.assertEqual(
            flow.extract_xai_email_code(
                "Thank you for creating an xAI account. Please use MWM-AME",
                "xAI confirmation code",
            ),
            "MWMAME",
        )
        # Must not steal OpenAI/ChatGPT numeric OTPs from a mixed inbox.
        self.assertEqual(flow.extract_xai_email_code("", "Your OpenAI code is 118738"), "")
        self.assertEqual(
            flow.extract_xai_email_code("Enter this temporary verification code: 335653", "ChatGPT login"),
            "",
        )

    def test_rsc_result_prefers_concrete_action_error_over_tree_placeholder(self):
        result = flow._extract_rsc_object(
            '0:{"error":"$undefined"}\n1:{"error":"Failed to verify Cloudflare turnstile token."}',
            "error",
        )
        self.assertEqual(result["error"], "Failed to verify Cloudflare turnstile token.")

    def test_account_record_uses_legacy_three_column_format(self):
        with tempfile.TemporaryDirectory() as directory:
            path = flow.save_account_record(
                str(Path(directory) / "accounts_http_test.txt"),
                email="test@example.test",
                password="password-value",
                sso="sso-value",
            )
            self.assertEqual(
                Path(path).read_text(encoding="utf-8"),
                "test@example.test----password-value----sso-value\n",
            )

    def test_save_registration_info_writes_json_detail(self):
        with tempfile.TemporaryDirectory() as directory:
            info_dir = Path(directory) / "registration_info"
            path = flow.save_registration_info(
                str(info_dir),
                email="test@example.test",
                password="password-value",
                sso="sso-value",
                given_name="Alex",
                family_name="Lee",
                credential_path="/tmp/xai-test@example.test.json",
                account_path="/tmp/accounts.txt",
                sso_path="/tmp/xai-test@example.test.sso",
                proxy="http://127.0.0.1:8080",
                turnstile_provider="capsolver",
            )
            self.assertTrue(path)
            target = Path(path)
            self.assertEqual(target.parent, info_dir.resolve())
            self.assertEqual(target.name, "xai-test@example.test.json")
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(payload["email"], "test@example.test")
            self.assertEqual(payload["password"], "password-value")
            self.assertEqual(payload["sso"], "sso-value")
            self.assertEqual(payload["given_name"], "Alex")
            self.assertEqual(payload["family_name"], "Lee")
            self.assertEqual(payload["credential_path"], "/tmp/xai-test@example.test.json")
            self.assertEqual(payload["turnstile_provider"], "capsolver")
            self.assertIn("registered_at", payload)
            self.assertGreater(int(payload["registered_at_unix"]), 0)

    def test_save_registration_info_skips_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                flow.save_registration_info(
                    str(Path(directory)),
                    email="test@example.test",
                    password="",
                    sso="sso",
                ),
                "",
            )

    def test_parse_ms_mail_line_four_fields(self):
        line = (
            "user@hotmail.com----Secret123----9e5f94bc-e8a4-4e73-b8be-63364c29d753----"
            "M.C553_BAY.0.U.MsaArtifacts.tokenvalue"
        )
        parsed = flow.parse_ms_mail_line(line)
        self.assertEqual(parsed["email"], "user@hotmail.com")
        self.assertEqual(parsed["password"], "Secret123")
        self.assertEqual(parsed["client_id"], "9e5f94bc-e8a4-4e73-b8be-63364c29d753")
        self.assertTrue(parsed["refresh_token"].startswith("M.C553_"))

    def test_build_mailbox_routes_yyds_provider(self):
        mailbox = flow.build_mailbox(
            config={
                "email_provider": "yyds",
                "yyds_api_key": "AC-test",
                "yyds_api_base": "https://example.test/v1",
            }
        )
        self.assertIsInstance(mailbox, flow.YydsTempMailbox)

    def test_build_mailbox_routes_mail_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mails.txt"
            path.write_text(
                "user@hotmail.com----pw----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.Ctoken\n",
                encoding="utf-8",
            )
            mailbox = flow.build_mailbox(mail_file=str(path))
            self.assertIsInstance(mailbox, flow.MicrosoftGraphMailbox)

    def test_ms_mail_claim_moves_line_to_used(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            path.write_text(
                "a@hotmail.com----pw----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.CtokenA\n"
                "b@hotmail.com----pw----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.CtokenB\n",
                encoding="utf-8",
            )
            mailbox = flow.MicrosoftGraphMailbox(str(path), mark_used=True)
            claimed = mailbox._claim_account()
            self.assertEqual(claimed["email"], "a@hotmail.com")
            remaining = path.read_text(encoding="utf-8")
            self.assertIn("b@hotmail.com", remaining)
            self.assertNotIn("a@hotmail.com", remaining)
            used = path.with_suffix(path.suffix + ".used").read_text(encoding="utf-8")
            self.assertIn("a@hotmail.com", used)

    def test_ms_mail_parallel_claims_are_unique(self):
        """Multiple workers claiming under flock must each get a distinct account."""
        import concurrent.futures

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            cid = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
            lines = [
                f"u{i}@hotmail.com----pw----{cid}----M.Ctoken{i}"
                for i in range(12)
            ]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            def claim_one(_idx: int) -> str:
                box = flow.MicrosoftGraphMailbox(str(path), mark_used=True)
                return box._claim_account()["email"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                emails = list(pool.map(claim_one, range(8)))
            self.assertEqual(len(emails), 8)
            self.assertEqual(len(set(emails)), 8, f"duplicate claims: {emails}")
            remaining = [
                ln.strip()
                for ln in path.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            self.assertEqual(len(remaining), 4)
            used = path.with_suffix(path.suffix + ".used").read_text(encoding="utf-8")
            for email in emails:
                self.assertIn(email, used)

    def test_ms_mail_release_to_pool_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            cid = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
            path.write_text(
                f"a@hotmail.com----pw----{cid}----M.CtokenA\n"
                f"b@hotmail.com----pw----{cid}----M.CtokenB\n",
                encoding="utf-8",
            )
            box = flow.MicrosoftGraphMailbox(str(path), mark_used=True)
            # simulate successful create claim without network token refresh
            claimed = box._claim_account()
            box.account = claimed
            box._claimed_for_return = True
            self.assertEqual(claimed["email"], "a@hotmail.com")
            self.assertNotIn("a@hotmail.com", path.read_text(encoding="utf-8"))
            self.assertIn("a@hotmail.com", path.with_suffix(path.suffix + ".used").read_text(encoding="utf-8"))
            ok = box.release_to_pool(reason="turnstile_timeout")
            self.assertTrue(ok)
            pool = path.read_text(encoding="utf-8")
            self.assertIn("a@hotmail.com", pool)
            # first line should be returned account
            first = [ln for ln in pool.splitlines() if ln.strip()][0]
            self.assertTrue(first.startswith("a@hotmail.com"))
            used = path.with_suffix(path.suffix + ".used").read_text(encoding="utf-8")
            self.assertNotIn("a@hotmail.com----", used)
            # second release is no-op
            self.assertFalse(box.release_to_pool(reason="again"))

    def test_ms_mail_commit_success_skips_return(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool.txt"
            cid = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
            path.write_text(f"a@hotmail.com----pw----{cid}----M.CtokenA\n", encoding="utf-8")
            box = flow.MicrosoftGraphMailbox(str(path), mark_used=True)
            claimed = box._claim_account()
            box.account = claimed
            box._claimed_for_return = True
            box.commit_success()
            self.assertFalse(box.release_to_pool(reason="should_skip"))
            self.assertNotIn("a@hotmail.com", path.read_text(encoding="utf-8"))


    def test_grpc_unary_reads_status_from_http_headers_when_body_empty(self):
        class HeaderOnlyResponse:
            status_code = 200
            content = b""
            text = ""
            headers = {
                "grpc-status": "3",
                "grpc-message": "Email%20validation%20code%20is%20invalid%20%5BWKE%3Demail%3Ainvalid-validation-code%5D",
            }

        class Session:
            headers = {}

            def post(self, url, **kwargs):
                return HeaderOnlyResponse()

        client = flow.BrowserlessXAIClient(session=Session())
        client.signup_page_url = "https://accounts.x.ai/sign-up"
        with self.assertRaises(flow.XAIHttpFlowError) as ctx:
            client.verify_email_validation_code("user@example.test", "ABC123")
        self.assertIn("invalid-validation-code", str(ctx.exception).lower())

    def test_parse_proxy_components_authenticated(self):
        parts = flow._parse_proxy_components("http://user:p%40ss@proxy.example.test:1000")
        self.assertEqual(parts["host"], "proxy.example.test")
        self.assertEqual(parts["port"], "1000")
        self.assertEqual(parts["username"], "user")
        self.assertEqual(parts["password"], "p@ss")

    def test_solve_turnstile_requires_api_key_or_token(self):
        with self.assertRaises(flow.VerificationRequiredError) as ctx:
            flow.solve_turnstile_token(sitekey="0x4AAAAAAAhr9JGVDZbrZOo0", api_key="")
        self.assertIn("API key", str(ctx.exception))

    def test_challenge_metadata_extracts_turnstile_action_and_cdata(self):
        html = (
            '<div class="cf-turnstile" data-sitekey="0xhtml" '
            'data-action="sign-up" data-cdata="opaque-cdata"></div>'
        )
        metadata = flow.BrowserlessXAIClient.challenge_metadata(html)
        self.assertEqual(metadata["turnstile_sitekey"], "0xhtml")
        self.assertEqual(metadata["turnstile_action"], "sign-up")
        self.assertEqual(metadata["turnstile_cdata"], "opaque-cdata")

        serialized = r'{"sitekey":"0xjson","action":"login","cData":"abc\/def"}'
        metadata = flow.BrowserlessXAIClient.challenge_metadata(serialized)
        self.assertEqual(metadata["turnstile_sitekey"], "0xjson")
        self.assertEqual(metadata["turnstile_action"], "login")
        self.assertEqual(metadata["turnstile_cdata"], "abc/def")

    def test_capsolver_turnstile_uses_proxyless_task_and_metadata(self):
        token = "t" * 120
        responses = [
            DummyResponse(json_data={"errorId": 0, "taskId": "capsolver-task"}),
            DummyResponse(json_data={"errorId": 0, "status": "processing"}),
            DummyResponse(json_data={"errorId": 0, "status": "ready", "solution": {"token": token}}),
        ]
        logs = []
        with mock.patch.object(flow.requests, "post", side_effect=responses) as post, mock.patch.object(
            flow.time, "sleep"
        ):
            actual = flow.solve_turnstile_token(
                sitekey="0x4AAAAAAAhr9JGVDZbrZOo0",
                page_url="https://accounts.x.ai/sign-up?redirect=grok-com",
                provider="cap-solver",
                api_key="capsolver-secret",
                proxy="http://user:password@proxy.example.test:1000",
                action="sign-up",
                cdata="opaque-cdata",
                timeout=30,
                log_callback=logs.append,
            )

        self.assertEqual(actual, token)
        self.assertEqual(post.call_count, 3)
        self.assertEqual(post.call_args_list[0].args[0], "https://api.capsolver.com/createTask")
        self.assertEqual(
            post.call_args_list[0].kwargs["json"],
            {
                "clientKey": "capsolver-secret",
                "task": {
                    "type": "AntiTurnstileTaskProxyLess",
                    "websiteURL": "https://accounts.x.ai/sign-up?redirect=grok-com",
                    "websiteKey": "0x4AAAAAAAhr9JGVDZbrZOo0",
                    "metadata": {"action": "sign-up", "cdata": "opaque-cdata"},
                },
            },
        )
        self.assertEqual(post.call_args_list[1].args[0], "https://api.capsolver.com/getTaskResult")
        self.assertEqual(
            post.call_args_list[1].kwargs["json"],
            {"clientKey": "capsolver-secret", "taskId": "capsolver-task"},
        )
        self.assertTrue(any("AntiTurnstileTaskProxyLess" in message for message in logs))

    def test_capsolver_uses_dedicated_environment_key_and_safe_errors(self):
        error = {
            "errorId": 1,
            "errorCode": "ERROR_KEY_DENIED",
            "errorDescription": "invalid key",
        }
        with mock.patch.dict("os.environ", {"CAPSOLVER_API_KEY": "environment-secret"}, clear=True), mock.patch.object(
            flow.requests, "post", return_value=DummyResponse(json_data=error)
        ) as post:
            with self.assertRaises(flow.VerificationRequiredError) as ctx:
                flow.solve_turnstile_token(sitekey="0x4AAAAAAAhr9JGVDZbrZOo0", timeout=30)

        self.assertEqual(post.call_args.kwargs["json"]["clientKey"], "environment-secret")
        self.assertIn("ERROR_KEY_DENIED", str(ctx.exception))
        self.assertNotIn("environment-secret", str(ctx.exception))

    def test_extract_cookie_setter_url_from_react_flight_typed_string(self):
        jwt = "aaa.bbb.ccc"
        url = f"https://auth.grokipedia.com/set-cookie?q={jwt}"
        # hex length of url
        hex_len = format(len(url), "x")
        payload = (
            f'0:{{"a":"$@1"}}\n'
            f"18:T{hex_len},{url}"
            f'1:"$18"\n'
            '2:"$Sreact.fragment"\n'
        )
        self.assertEqual(flow._extract_cookie_setter_url(payload), url)

    def test_classify_turnstile_block_detects_xai_hard_block(self):
        diag = {
            "url": "https://accounts.x.ai/sign-up?redirect=grok-com",
            "title": "Attention Required! | Cloudflare",
            "challengeLike": True,
            "bodySnippet": (
                "Sorry, you have been blocked You are unable to access x.ai "
                "Why have I been blocked?"
            ),
            "sitekeyCount": 0,
            "hasCfInput": False,
            "turnstileIframeCount": 0,
            "tokenLen": 0,
        }
        result = flow._classify_turnstile_page_state(diag)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["kind"], "cloudflare_hard_block")
        self.assertIn("x.ai", result["message"])

    def test_classify_turnstile_block_detects_challenge_interstitial(self):
        diag = {
            "title": "Just a moment...",
            "challengeLike": True,
            "bodySnippet": "Checking your browser before accessing accounts.x.ai",
            "sitekeyCount": 0,
            "hasCfInput": False,
            "turnstileIframeCount": 0,
            "tokenLen": 0,
        }
        result = flow._classify_turnstile_page_state(diag)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["kind"], "cloudflare_challenge")

    def test_build_turnstile_browser_options_sets_anti_automation_args(self):
        class FakeOptions:
            def __init__(self):
                self.args = []
                self.prefs = {}
                self.proxy = ""
                self.user_agent = ""
                self.headless_flag = False
                self.auto_port_called = False

            def auto_port(self):
                self.auto_port_called = True

            def set_argument(self, value):
                self.args.append(value)

            def set_pref(self, key, value):
                self.prefs[key] = value

            def set_proxy(self, value):
                self.proxy = value

            def set_user_agent(self, value):
                self.user_agent = value

            def set_local_port(self, port):
                self.port = port

            def set_user_data_path(self, path):
                self.user_data = path

            def headless(self, value=True):
                self.headless_flag = bool(value)

        fake = FakeOptions()
        logs = []
        built = flow._build_turnstile_browser_options(
            options=fake,
            proxy="http://127.0.0.1:17890",
            headless=True,
            user_agent="Mozilla/5.0 test-agent",
            log_callback=logs.append,
        )
        self.assertIs(built, fake)
        self.assertTrue(getattr(fake, "port", None))
        self.assertTrue(getattr(fake, "user_data", None))
        self.assertTrue(fake.headless_flag)
        self.assertEqual(fake.proxy, "http://127.0.0.1:17890")
        self.assertEqual(fake.user_agent, "Mozilla/5.0 test-agent")
        self.assertNotIn("--disable-blink-features=AutomationControlled", fake.args)
        self.assertIn("--no-first-run", fake.args)
        self.assertIn("--no-default-browser-check", fake.args)
        self.assertIn("--disable-dev-shm-usage", fake.args)
        self.assertIn("--no-sandbox", fake.args)
        self.assertIn("--headless=new", fake.args)
        self.assertNotIn("--disable-background-networking", fake.args)
        self.assertTrue(any("headless" in message.lower() for message in logs))

        bare = FakeOptions()
        bare_logs = []
        flow._build_turnstile_browser_options(
            options=bare,
            proxy="",
            headless=False,
            user_agent="",
            log_callback=bare_logs.append,
        )
        self.assertEqual(bare.user_agent, "")
        self.assertTrue(any("直连" in message for message in bare_logs))

    def test_capture_turnstile_token_fast_fails_on_hard_block(self):
        class FakePage:
            def get(self, url):
                self.url = url

            def wait(self):
                return self

            def doc_loaded(self):
                return True

        class FakeBrowser:
            def __init__(self, options):
                self.options = options
                self.quit_called = False

            def get_tabs(self):
                return [FakePage()]

            def quit(self):
                self.quit_called = True

        class FakeOptions:
            def auto_port(self):
                return None

            def set_argument(self, *_args, **_kwargs):
                return None

            def set_pref(self, *_args, **_kwargs):
                return None

            def set_proxy(self, *_args, **_kwargs):
                return None

            def set_user_agent(self, *_args, **_kwargs):
                return None

            def headless(self, *_args, **_kwargs):
                return None

        blocked_diag = {
            "url": "https://accounts.x.ai/sign-up?redirect=grok-com",
            "title": "Attention Required! | Cloudflare",
            "challengeLike": True,
            "bodySnippet": "Sorry, you have been blocked You are unable to access x.ai",
            "sitekeyCount": 0,
            "hasCfInput": False,
            "turnstileIframeCount": 0,
            "tokenLen": 0,
            "widgetLikeCount": 0,
            "inputs": {},
        }
        logs = []
        import types

        fake_module = types.SimpleNamespace(Chromium=FakeBrowser, ChromiumOptions=FakeOptions)
        with mock.patch.dict("sys.modules", {"DrissionPage": fake_module}), mock.patch(
            "xai_http_flow._diagnose_turnstile_page",
            return_value=blocked_diag,
        ), mock.patch("xai_http_flow.time.sleep"):
            with self.assertRaises(flow.VerificationRequiredError) as ctx:
                flow.capture_turnstile_token(
                    timeout=30,
                    headless=False,
                    click_email_signup=False,
                    output="",
                    log_callback=logs.append,
                )
        message = str(ctx.exception)
        self.assertIn("Cloudflare", message)
        self.assertIn("blocked", message.lower())
        self.assertTrue(any("拦截" in item or "blocked" in item.lower() for item in logs))

    def test_click_signup_continue_skips_x_oauth_button(self):
        class FakePage:
            def __init__(self):
                self.scripts = []

            def run_js(self, script):
                self.scripts.append(script)
                return False

        page = FakePage()
        clicked = flow._click_signup_continue(page, log_callback=None)
        self.assertEqual(clicked, "")
        script = page.scripts[0]
        self.assertIn("使用X", script)
        self.assertIn("oauth", script.lower())
        self.assertIn("sign in with x", script.lower())
        self.assertIn("确认邮箱", script)
        self.assertIn("验证您的邮箱", script)


    def test_inject_turnstile_widget_js_uses_sitekey(self):
        js = flow._inject_turnstile_widget_js(
            sitekey="0x4AAAAAAAhr9JGVDZbrZOo0",
            action="sign-up",
            cdata="opaque",
        )
        self.assertIn("0x4AAAAAAAhr9JGVDZbrZOo0", js)
        self.assertIn("turnstile.render", js)
        self.assertIn("sign-up", js)
        self.assertIn("opaque", js)
        self.assertIn("return true", js)
        self.assertNotIn("turnstile.execute", js)

    def test_solve_turnstile_local_forwards_sitekey_metadata(self):
        logs = []
        with mock.patch.object(
            flow,
            "capture_turnstile_token",
            return_value="t" * 100,
        ) as capture:
            token = flow._solve_turnstile_local(
                page_url="https://accounts.x.ai/sign-up?redirect=grok-com",
                proxy="",
                timeout=30,
                headless=False,
                log_callback=logs.append,
                sitekey="0xhtml",
                action="sign-up",
                cdata="cdata-1",
            )
        self.assertEqual(token, "t" * 100)
        kwargs = capture.call_args.kwargs
        self.assertEqual(kwargs["sitekey"], "0xhtml")
        self.assertEqual(kwargs["action"], "sign-up")
        self.assertEqual(kwargs["cdata"], "cdata-1")
        self.assertFalse(kwargs.get("click_email_signup", True))

    def test_classify_detects_email_verification_deadend(self):
        diag = {
            "title": "创建您的 Grok 账户 | Grok",
            "bodySnippet": "验证您的邮箱 我们已向 local.solver+demo@example.com 发送了一个一次性安全代码",
            "url": "https://accounts.x.ai/sign-up?redirect=grok-com",
            "sitekeyCount": 0,
            "hasCfInput": False,
            "turnstileIframeCount": 0,
            "tokenLen": 0,
            "challengeLike": False,
        }
        result = flow._classify_turnstile_page_state(diag)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["kind"], "email_verification_deadend")

    def test_build_turnstile_browser_options_avoids_unsupported_automation_flag(self):
        class FakeOptions:
            def __init__(self):
                self.args = []
                self.prefs = {}
                self.proxy = ""
                self.user_agent = ""
                self.headless_flag = False
                self.auto_port_called = False

            def auto_port(self):
                self.auto_port_called = True

            def set_argument(self, value):
                self.args.append(value)

            def set_pref(self, key, value):
                self.prefs[key] = value

            def set_proxy(self, value):
                self.proxy = value

            def set_user_agent(self, value):
                self.user_agent = value

            def set_local_port(self, port):
                self.port = port

            def headless(self, value=True):
                self.headless_flag = bool(value)

        fake = FakeOptions()
        flow._build_turnstile_browser_options(options=fake, proxy="", headless=False, user_agent="")
        self.assertNotIn("--disable-blink-features=AutomationControlled", fake.args)

    def test_local_turnstile_block_assets_and_shared_cache_defaults(self):
        with mock.patch.dict(flow.os.environ, {}, clear=False):
            flow.os.environ.pop("XAI_LOCAL_TURNSTILE_BLOCK_ASSETS", None)
            flow.os.environ.pop("XAI_LOCAL_TURNSTILE_SHARED_CACHE", None)
            self.assertTrue(flow.resolve_local_turnstile_block_assets({}))
            self.assertTrue(flow.resolve_local_turnstile_shared_cache({}))
            self.assertFalse(
                flow.resolve_local_turnstile_block_assets(
                    {"local_turnstile_block_assets": False}
                )
            )
            self.assertFalse(
                flow.resolve_local_turnstile_shared_cache(
                    {"local_turnstile_shared_cache": 0}
                )
            )
        with mock.patch.dict(
            flow.os.environ,
            {
                "XAI_LOCAL_TURNSTILE_BLOCK_ASSETS": "0",
                "XAI_LOCAL_TURNSTILE_SHARED_CACHE": "no",
            },
            clear=False,
        ):
            self.assertFalse(
                flow.resolve_local_turnstile_block_assets(
                    {"local_turnstile_block_assets": True}
                )
            )
            self.assertFalse(
                flow.resolve_local_turnstile_shared_cache(
                    {"local_turnstile_shared_cache": True}
                )
            )

    def test_build_turnstile_browser_options_adds_shared_disk_cache(self):
        class FakeOptions:
            def __init__(self):
                self.args = []

            def set_argument(self, value):
                self.args.append(value)

            def set_local_port(self, port):
                self.port = port

            def set_user_data_path(self, path):
                self.user_data = path

            def set_pref(self, key, value):
                return None

            def headless(self, value=True):
                return None

        with mock.patch.object(flow, "resolve_local_turnstile_shared_cache", return_value=True):
            fake = FakeOptions()
            flow._build_turnstile_browser_options(
                options=fake,
                proxy="",
                headless=True,
                user_agent="ua",
            )
        self.assertTrue(any(str(a).startswith("--disk-cache-dir=") for a in fake.args))
        self.assertTrue(any(str(a).startswith("--disk-cache-size=") for a in fake.args))

        with mock.patch.object(flow, "resolve_local_turnstile_shared_cache", return_value=False):
            bare = FakeOptions()
            flow._build_turnstile_browser_options(
                options=bare,
                proxy="",
                headless=True,
                user_agent="ua",
            )
        self.assertFalse(any("disk-cache" in str(a) for a in bare.args))

    def test_apply_turnstile_network_blocks_uses_cdp(self):
        class FakePage:
            def __init__(self):
                self.calls = []

            def run_cdp(self, method, *args, **kwargs):
                self.calls.append((method, args, kwargs))
                return {}

        page = FakePage()
        logs = []
        count = flow._apply_turnstile_network_blocks(
            page,
            enabled=True,
            patterns=["*.png", "*.woff2"],
            log_callback=logs.append,
        )
        self.assertEqual(count, 2)
        methods = [item[0] for item in page.calls]
        self.assertIn("Network.enable", methods)
        self.assertIn("Network.setBlockedURLs", methods)
        blocked_call = next(item for item in page.calls if item[0] == "Network.setBlockedURLs")
        # kwargs form preferred
        if blocked_call[2]:
            self.assertEqual(blocked_call[2].get("urls"), ["*.png", "*.woff2"])
        else:
            self.assertEqual(blocked_call[1][0].get("urls"), ["*.png", "*.woff2"])
        self.assertTrue(any("拦截" in msg for msg in logs))

        skipped = flow._apply_turnstile_network_blocks(page, enabled=False)
        self.assertEqual(skipped, 0)



    def test_ensure_injected_turnstile_widget_retries_until_api_ready(self):
        class FakePage:
            def __init__(self):
                self.calls = 0

            def run_js(self, script):
                self.calls += 1
                if self.calls == 1:
                    return {"ok": True, "reason": "script-loading"}
                return {"ok": True, "reason": "rendered", "tokenLen": 0}

        page = FakePage()
        logs = []
        with mock.patch.object(flow.time, "sleep"):
            result = flow._ensure_injected_turnstile_widget(
                page,
                sitekey="0xhtml",
                action="sign-up",
                cdata="",
                log_callback=logs.append,
                wait_api_sec=2,
            )
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("reason"), "rendered")
        self.assertGreaterEqual(page.calls, 2)


    def test_resolve_local_browser_mode_uses_native_headless_new(self):
        mode, use_headless = flow._resolve_local_browser_mode(want_headless=True)
        self.assertEqual(mode, "headless-new")
        self.assertTrue(use_headless)

    def test_resolve_local_browser_mode_does_not_depend_on_display(self):
        with mock.patch.dict(flow.os.environ, {"DISPLAY": ":99"}):
            mode, use_headless = flow._resolve_local_browser_mode(want_headless=True)
        self.assertEqual(mode, "headless-new")
        self.assertTrue(use_headless)

    def test_resolve_local_browser_mode_headed(self):
        mode, use_headless = flow._resolve_local_browser_mode(want_headless=False)
        self.assertEqual(mode, "headed")
        self.assertFalse(use_headless)



    def test_yyds_domain_round_robin_across_creates(self):
        class FakeResp:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self.text = json.dumps(payload)
                self._payload = payload

            def json(self):
                return self._payload

        domains = [
            {"domain": "a.example", "isVerified": True, "isPublic": False},
            {"domain": "b.example", "isVerified": True, "isPublic": False},
            {"domain": "c.example", "isVerified": True, "isPublic": False},
        ]
        seen = []

        class FakeSession:
            def get(self, url, **kwargs):
                return FakeResp(200, {"success": True, "data": domains})

            def post(self, url, **kwargs):
                if "accounts" in url:
                    domain = kwargs.get("json", {}).get("domain")
                    seen.append(domain)
                    return FakeResp(
                        200,
                        {
                            "success": True,
                            "data": {
                                "address": f"xai@{domain}",
                                "token": f"tok-{len(seen)}",
                            },
                        },
                    )
                return FakeResp(200, {"success": True, "data": {"token": "tok"}})

        with tempfile.TemporaryDirectory() as directory:
            rr_lock = Path(directory) / "rr.lock"
            rr_state = Path(directory) / "rr-state.json"
            box = flow.YydsTempMailbox({"yyds_api_key": "k"}, timeout=10)
            box.session = FakeSession()
            with mock.patch.object(flow, "_YYDS_DOMAIN_RR_LOCK_PATH", rr_lock), mock.patch.object(
                flow, "_YYDS_DOMAIN_RR_STATE_PATH", rr_state
            ), mock.patch.object(flow, "_yyds_create_spacing_sec", return_value=0.0), mock.patch.object(
                flow.time, "sleep"
            ):
                for _ in range(5):
                    box.create()
        self.assertEqual(seen, ["a.example", "b.example", "c.example", "a.example", "b.example"])

    def test_yyds_domain_candidates_merge_private_then_public(self):
        """One private domain must not trap RR; public domains stay in the pool."""

        class FakeResp:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self.text = json.dumps(payload)
                self._payload = payload

            def json(self):
                return self._payload

        domains = [
            {"domain": "public-b.example", "isVerified": True, "isPublic": True},
            {"domain": "private.example", "isVerified": True, "isPublic": False},
            {"domain": "public-a.example", "isVerified": True, "isPublic": True},
        ]

        class FakeSession:
            def get(self, url, **kwargs):
                return FakeResp(200, {"success": True, "data": domains})

        box = flow.YydsTempMailbox({"yyds_api_key": "k"}, timeout=10)
        box.session = FakeSession()
        pool = box._domain_candidates()
        self.assertEqual(
            pool,
            ["private.example", "public-b.example", "public-a.example"],
        )

        seen = []

        class CreateSession(FakeSession):
            def post(self, url, **kwargs):
                if "accounts" in url:
                    domain = kwargs.get("json", {}).get("domain")
                    seen.append(domain)
                    return FakeResp(
                        200,
                        {
                            "success": True,
                            "data": {
                                "address": f"xai@{domain}",
                                "token": f"tok-{len(seen)}",
                            },
                        },
                    )
                return FakeResp(200, {"success": True, "data": {"token": "tok"}})

        with tempfile.TemporaryDirectory() as directory:
            rr_lock = Path(directory) / "rr.lock"
            rr_state = Path(directory) / "rr-state.json"
            box.session = CreateSession()
            with mock.patch.object(flow, "_YYDS_DOMAIN_RR_LOCK_PATH", rr_lock), mock.patch.object(
                flow, "_YYDS_DOMAIN_RR_STATE_PATH", rr_state
            ), mock.patch.object(flow, "_yyds_create_spacing_sec", return_value=0.0), mock.patch.object(
                flow.time, "sleep"
            ):
                for _ in range(4):
                    box.create()
        self.assertEqual(
            seen,
            [
                "private.example",
                "public-b.example",
                "public-a.example",
                "private.example",
            ],
        )

    def test_yyds_domain_whitelist_round_robin(self):
        class FakeResp:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self.text = json.dumps(payload)
                self._payload = payload

            def json(self):
                return self._payload

        domains = [
            {"domain": "lios.edu.kg", "isVerified": True, "isPublic": False},
            {"domain": "lyf36mk1.cn", "isVerified": True, "isPublic": False},
            {"domain": "lyan97d11.cn", "isVerified": True, "isPublic": False},
        ]
        seen = []

        class FakeSession:
            def get(self, url, **kwargs):
                return FakeResp(200, {"success": True, "data": domains})

            def post(self, url, **kwargs):
                if "accounts" in url:
                    domain = kwargs.get("json", {}).get("domain")
                    seen.append(domain)
                    return FakeResp(
                        200,
                        {"success": True, "data": {"address": f"xai@{domain}", "token": "t"}},
                    )
                return FakeResp(200, {"success": True, "data": {"token": "t"}})

        with tempfile.TemporaryDirectory() as directory:
            rr_lock = Path(directory) / "rr.lock"
            rr_state = Path(directory) / "rr-state.json"
            box = flow.YydsTempMailbox(
                {
                    "yyds_api_key": "k",
                    "yyds_domains": "lyan97d11.cn,lyf36mk1.cn",
                },
                timeout=10,
            )
            box.session = FakeSession()
            with mock.patch.object(flow, "_YYDS_DOMAIN_RR_LOCK_PATH", rr_lock), mock.patch.object(
                flow, "_YYDS_DOMAIN_RR_STATE_PATH", rr_state
            ), mock.patch.object(flow, "_yyds_create_spacing_sec", return_value=0.0), mock.patch.object(
                flow.time, "sleep"
            ):
                for _ in range(4):
                    box.create()
        self.assertEqual(
            seen,
            ["lyan97d11.cn", "lyf36mk1.cn", "lyan97d11.cn", "lyf36mk1.cn"],
        )

    def test_yyds_create_retries_on_429(self):
        calls = {"n": 0}

        class FakeResp:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self.text = json.dumps(payload)
                self._payload = payload

            def json(self):
                return self._payload

        class FakeSession:
            def get(self, url, **kwargs):
                return FakeResp(200, {"success": True, "data": [{"domain": "lwvutyk.info", "isVerified": True, "isPublic": True}]})

            def post(self, url, **kwargs):
                calls["n"] += 1
                if "accounts" in url and calls["n"] < 3:
                    return FakeResp(429, {"success": False, "error": "Too many account creation requests. Please try again later."})
                if "accounts" in url:
                    return FakeResp(200, {"success": True, "data": {"address": "xaitest@lwvutyk.info", "token": "tok-1"}})
                return FakeResp(200, {"success": True, "data": {"token": "tok-1"}})

        box = flow.YydsTempMailbox({"yyds_api_key": "k"}, timeout=10)
        box.session = FakeSession()
        with mock.patch.object(flow.time, "sleep"), mock.patch.object(flow, "_yyds_create_spacing_sec", return_value=0):
            email, token = box.create()
        self.assertEqual(email, "xaitest@lwvutyk.info")
        self.assertEqual(token, "tok-1")
        self.assertGreaterEqual(calls["n"], 3)

    def test_yyds_create_guard_serializes_with_file_lock(self):
        calls = {"n": 0}
        observed = []

        class FakeResp:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self.text = json.dumps(payload)
                self._payload = payload

            def json(self):
                return self._payload

        class FakeSession:
            def get(self, url, **kwargs):
                return FakeResp(200, {"success": True, "data": [{"domain": "lwvutyk.info", "isVerified": True, "isPublic": True}]})

            def post(self, url, **kwargs):
                calls["n"] += 1
                observed.append(flow._yyds_read_last_create_at())
                if "accounts" in url:
                    return FakeResp(200, {"success": True, "data": {"address": f"xai{calls['n']}@lwvutyk.info", "token": f"tok-{calls['n']}"}})
                return FakeResp(200, {"success": True, "data": {"token": "tok"}})

        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "create.lock"
            state_path = Path(directory) / "create-state.json"
            box = flow.YydsTempMailbox({"yyds_api_key": "k"}, timeout=10)
            box.session = FakeSession()
            with mock.patch.object(flow, "_YYDS_CREATE_LOCK_PATH", lock_path), mock.patch.object(
                flow, "_YYDS_CREATE_STATE_PATH", state_path
            ), mock.patch.object(flow, "_yyds_create_spacing_sec", return_value=0.0), mock.patch.object(flow.time, "sleep"):
                email1, token1 = box.create()
                email2, token2 = box.create()
            self.assertTrue(email1.endswith("@lwvutyk.info"))
            self.assertTrue(email2.endswith("@lwvutyk.info"))
            self.assertEqual(token1, "tok-1")
            self.assertEqual(token2, "tok-2")
            self.assertEqual(calls["n"], 2)
            self.assertTrue(state_path.exists())
            self.assertGreater(float(json.loads(state_path.read_text(encoding="utf-8"))["last_create_at"]), 0)



    def test_proxy_has_embedded_auth(self):
        self.assertTrue(flow._proxy_has_embedded_auth("http://user:pass@host:1000"))
        self.assertFalse(flow._proxy_has_embedded_auth("http://127.0.0.1:17890"))
        self.assertFalse(flow._proxy_has_embedded_auth("http://host:1000"))

    def test_http_cli_has_no_parent_proxy_option(self):
        parser = flow.build_parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
            and "register" in action.choices
        )
        for command in ("credential", "register", "mail-probe", "turnstile-capture"):
            destinations = {action.dest for action in subparsers.choices[command]._actions}
            self.assertNotIn("proxy_parent", destinations)

    def test_prepare_browser_proxy_auth_uses_forwarder(self):
        logs = []
        with mock.patch(
            "local_proxy_forwarder.ensure_local_forwarder",
            return_value=("http://127.0.0.1:17999", True),
        ) as mocked:
            browser_proxy, key = flow._prepare_browser_proxy(
                "http://user:pass@gate.example:1000",
                log_callback=logs.append,
            )
        self.assertEqual(browser_proxy, "http://127.0.0.1:17999")
        self.assertTrue(key)
        mocked.assert_called_once()
        self.assertTrue(any("本机无鉴权转发" in item for item in logs))

    def test_prepare_browser_proxy_plain_proxy_passthrough(self):
        browser_proxy, key = flow._prepare_browser_proxy("http://1.2.3.4:8080")
        self.assertEqual(browser_proxy, "http://1.2.3.4:8080")
        self.assertEqual(key, "")

    def test_build_turnstile_browser_options_rejects_auth_proxy(self):
        class FakeOptions:
            def __init__(self):
                self.args = []
                self.prefs = {}
                self.proxy = ""

            def set_argument(self, value):
                self.args.append(value)

            def set_pref(self, key, value):
                self.prefs[key] = value

            def set_proxy(self, value):
                self.proxy = value

            def set_local_port(self, port):
                self.port = port

        fake = FakeOptions()
        with self.assertRaises(flow.XAIHttpFlowError) as ctx:
            flow._build_turnstile_browser_options(
                options=fake,
                proxy="http://user:pass@gate.example:1000",
                headless=False,
                user_agent="",
            )
        self.assertIn("账号密码", str(ctx.exception))
        self.assertEqual(fake.proxy, "")

    def test_capture_turnstile_token_forwards_auth_proxy(self):
        class FakeOptions:
            def __init__(self):
                self.args = []
                self.prefs = {}
                self.proxy = ""
                self._xai_profile_dir = None

            def set_argument(self, value):
                self.args.append(value)

            def set_pref(self, key, value):
                self.prefs[key] = value

            def set_proxy(self, value):
                self.proxy = value

            def set_local_port(self, port):
                self.port = port

            def set_user_data_path(self, path):
                self._xai_profile_dir = path

            def headless(self, value=True):
                return None

        class FakePage:
            def __init__(self):
                self.url = "https://accounts.x.ai/sign-up?redirect=grok-com"

            def get(self, url):
                self.url = url

            def run_js(self, script):
                if "tokenLen" in script or "cf-turnstile-response" in script:
                    return {
                        "url": self.url,
                        "title": "ok",
                        "tokenLen": 100,
                        "sitekeyCount": 1,
                        "hasCfInput": True,
                        "turnstileIframeCount": 1,
                        "token": "t" * 100,
                        "inputs": {},
                        "bodySnippet": "",
                    }
                return {"ok": True, "reason": "rendered", "tokenLen": 100, "token": "t" * 100}

            @property
            def wait(self):
                class W:
                    def doc_loaded(self_inner):
                        return None
                return W()

        class FakeBrowser:
            def __init__(self, options):
                self.options = options
                self.page = FakePage()

            def get_tabs(self):
                return [self.page]

            def new_tab(self):
                return self.page

            def quit(self):
                return None

        logs = []
        import types
        fake_module = types.SimpleNamespace(Chromium=FakeBrowser, ChromiumOptions=FakeOptions)
        with mock.patch.dict("sys.modules", {"DrissionPage": fake_module}), mock.patch.object(
            flow,
            "_prepare_browser_proxy",
            return_value=("http://127.0.0.1:17991", "fwd-1"),
        ) as prepare, mock.patch.object(
            flow,
            "_launch_turnstile_browser",
            side_effect=lambda options, log_callback=None: FakeBrowser(options),
        ), mock.patch.object(
            flow,
            "_resolve_local_browser_mode",
            return_value=("headed", False),
        ), mock.patch.object(
            flow,
            "_read_turnstile_token_js",
            return_value="t" * 100,
        ), mock.patch(
            "local_proxy_forwarder.stop_local_forwarder"
        ) as stop_fwd, mock.patch.object(flow.time, "sleep"):
            token = flow.capture_turnstile_token(
                proxy="http://user:pass@gate.example:1000",
                timeout=5,
                headless=False,
                click_email_signup=False,
                sitekey="0xhtml",
                output="",
                log_callback=logs.append,
            )
        self.assertEqual(token, "t" * 100)
        prepare.assert_called_once()
        stop_fwd.assert_called_once()
        self.assertEqual(stop_fwd.call_args.kwargs.get("instance_key"), "fwd-1")


if __name__ == "__main__":
    unittest.main()
