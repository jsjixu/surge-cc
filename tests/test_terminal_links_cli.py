"""The ordinary Orca shell bridge accepts URL arguments through stdin only."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import cli, link_router, shortcuts, terminal_links
from surge_cc.core import Blocked


class TerminalLinksCLITests(unittest.TestCase):
    config = Path("/private/tmp/synthetic-terminal-links/config.json")
    router = Path("/private/tmp/synthetic-terminal-links/Surge CC Links.app/Contents/Resources/router.json")

    def setUp(self):
        self.loader = patch.object(link_router, "load", return_value={"config": str(self.config)})
        self.load = self.loader.start()
        self.addCleanup(self.loader.stop)

    def invoke(self, action, raw=b"", *, as_json=True):
        output, errors = io.StringIO(), io.StringIO()
        stdin = SimpleNamespace(buffer=io.BytesIO(raw))
        args = ["--config", str(self.config), "links", action, "--router-config", str(self.router)]
        if as_json:
            args.append("--json")
        with patch.object(sys, "stdin", stdin), redirect_stdout(output), redirect_stderr(errors):
            status = cli.main(args)
        return status, output.getvalue(), errors.getvalue()

    def test_shell_management_uses_validated_router_without_changing_default_handlers(self):
        for action, method in (("shell-install", "install"), ("shell-status", "status"),
                               ("shell-remove", "remove")):
            reply = {"ok": True, "installed": action != "shell-remove", "message": "completed"}
            with self.subTest(action=action), patch.object(terminal_links, method, return_value=reply) as operation, \
                    patch.object(link_router, "set_default") as defaults:
                code, output, errors = self.invoke(action)
                self.assertEqual(code, 0, errors)
                self.assertEqual(json.loads(output)["links"], reply)
                operation.assert_called_once_with(self.router)
                defaults.assert_not_called()

    def test_shell_management_failure_is_not_reported_as_success(self):
        with patch.object(terminal_links, "install", return_value={"ok": False, "message": "blocked"}):
            code, output, _ = self.invoke("shell-install")
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output)["ok"])

    def test_shell_eligibility_returns_silent_status_for_source_scripts(self):
        for expected in (0, 3, 78):
            reply = {"ok": expected == 0, "exit_code": expected, "message": "scope check"}
            with self.subTest(expected=expected), patch.object(terminal_links, "eligible", return_value=reply) as eligible:
                code, output, errors = self.invoke("shell-eligible", as_json=False)
            self.assertEqual(code, expected)
            self.assertEqual(output, "")
            self.assertEqual(errors, "")
            eligible.assert_called_once_with(self.router)

    def test_shell_eligibility_errors_are_silent_and_fail_closed(self):
        with patch.object(terminal_links, "eligible", side_effect=RuntimeError("private backend data")):
            code, output, errors = self.invoke("shell-eligible")
        self.assertEqual(code, 78)
        self.assertEqual(output, "")
        self.assertEqual(errors, "")

    def test_shell_open_forwards_nul_payload_exactly_and_returns_no_url(self):
        payload = "https://example.com/private?token=synthetic-secret\x00https://example.net/中文\x00".encode()
        reply = {"ok": True, "action": "focus", "message": "opened", "exit_code": 0}
        with patch.object(terminal_links, "dispatch", return_value=reply) as dispatch:
            code, output, errors = self.invoke("shell-open", payload, as_json=False)
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output), reply)
        dispatch.assert_called_once_with(self.router, payload)
        self.assertNotIn("synthetic-secret", output + errors)
        self.assertNotIn("example.com", output + errors)

    def test_shell_open_propagates_native_passthrough_exit_code(self):
        reply = {"ok": False, "action": "system", "message": "system open finished", "exit_code": 17}
        with patch.object(terminal_links, "dispatch", return_value=reply):
            code, output, _ = self.invoke("shell-open", b"example.txt\0")
        self.assertEqual(code, 17)
        self.assertEqual(json.loads(output)["exit_code"], 17)

    def test_overlong_payload_is_blocked_before_dispatch(self):
        with patch.object(terminal_links, "dispatch") as dispatch:
            code, output, _ = self.invoke("shell-open", b"x" * 65537)
        self.assertEqual(code, 78)
        self.assertEqual(json.loads(output)["action"], "blocked")
        dispatch.assert_not_called()

    def test_maximum_payload_is_bounded_and_left_to_dispatch_validation(self):
        reply = {"ok": False, "action": "blocked", "message": "invalid payload", "exit_code": 78}
        with patch.object(terminal_links, "dispatch", return_value=reply) as dispatch:
            code, _, _ = self.invoke("shell-open", b"x" * 65536)
        self.assertEqual(code, 78)
        self.assertEqual(len(dispatch.call_args.args[1]), 65536)

    def test_config_mismatch_never_dispatches_or_installs(self):
        self.load.return_value = {"config": "/other/config.json"}
        for action, method in (("shell-open", "dispatch"), ("shell-eligible", "eligible"),
                               ("shell-install", "install")):
            with self.subTest(action=action), patch.object(terminal_links, method) as operation:
                code, output, errors = self.invoke(action, b"https://example.com/\0")
            self.assertEqual(code, 2 if action == "shell-install" else 78)
            operation.assert_not_called()
            self.assertNotIn("example.com", output + errors)

    def test_invalid_raw_input_and_unexpected_errors_do_not_echo_payload(self):
        for raw, error in ((b"\xff\0", UnicodeError("private URL query")),
                           (b"https://example.com/?token=private\0", RuntimeError("private URL query"))):
            with self.subTest(raw=raw), patch.object(terminal_links, "dispatch", side_effect=error):
                code, output, errors = self.invoke("shell-open", raw)
            self.assertEqual(code, 78)
            self.assertEqual(json.loads(output)["action"], "blocked")
            self.assertNotIn("private", output + errors)
            self.assertNotIn("example.com", output + errors)

    def test_safe_blocked_message_and_sigterm_handler_are_preserved(self):
        previous = signal.getsignal(signal.SIGTERM)
        for error in (Blocked("当前工作区为 B，未自动切换"), shortcuts.LauncherStopped("打开已取消，未自动切换")):
            with patch.object(terminal_links, "dispatch", side_effect=error):
                code, output, _ = self.invoke("shell-open", b"https://example.com/\0")
            self.assertEqual(code, 78)
            self.assertIn("未自动切换", json.loads(output)["message"])
            self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_invalid_module_result_is_never_a_success(self):
        for reply in (None, {"ok": True}, {"exit_code": True}, {"exit_code": -1},
                      {"exit_code": 256}, {"exit_code": "0"}):
            with self.subTest(reply=reply), patch.object(terminal_links, "dispatch", return_value=reply):
                code, _, _ = self.invoke("shell-open", b"https://example.com/\0")
            self.assertEqual(code, 78)


if __name__ == "__main__":
    unittest.main()
