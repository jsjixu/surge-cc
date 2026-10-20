import subprocess
import unittest
from unittest.mock import Mock, patch

from surge_cc import cli, oauth_gate
from surge_cc.core import Blocked
from test_core import config


class OAuthGateTests(unittest.TestCase):
    def settings(self):
        return dict(config(), proxy_url="http://127.0.0.1:62919")

    def test_actual_dedicated_proxy_is_used_without_environment_bypass_or_redirect(self):
        settings = self.settings()
        run = Mock(return_value=subprocess.CompletedProcess([], 0, '{"ip":"' + settings["expected_ip"] + '"}\n200', ""))
        oauth_gate.verify_proxy_exit(settings, run=run)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--proxy") + 1], settings["proxy_url"])
        self.assertEqual(args[args.index("--noproxy") + 1], "")
        self.assertEqual(args[args.index("--max-redirs") + 1], "0")
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        self.assertNotIn("--location", args)
        self.assertEqual(run.call_args.kwargs["env"]["NO_PROXY"], "")

    def test_failure_unknown_wrong_ip_and_redirect_all_block(self):
        for output, status in [
            ('{"ip":"192.0.2.99"}\n200', 0),
            ('{"ip":"' + self.settings()["expected_ip"] + '"}\n302', 0),
            ('[1]\n200', 0), ('{"ip":"not an IP"}\n200', 0),
            ('{"ip":"192.0.2.1","other":true}\n200', 0), ("bad", 0),
            ("x" * 3000, 0), ("", 35),
        ]:
            with self.subTest(output=output[:80], status=status), self.assertRaises(Blocked):
                oauth_gate.verify_proxy_exit(
                    self.settings(), run=Mock(return_value=subprocess.CompletedProcess([], status, output, "PRIVATE")))

    def test_timeout_redacts_command_and_payload(self):
        with self.assertRaises(Blocked) as caught:
            oauth_gate.verify_proxy_exit(self.settings(), run=Mock(side_effect=subprocess.TimeoutExpired("PRIVATE", 20)))
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_full_gate_runs_proxy_check_and_last_runtime_check(self):
        settings = self.settings()
        with patch.object(cli, "full_checks", return_value={"ok": True}) as full, \
                patch.object(oauth_gate, "verify_proxy_exit") as proxy, \
                patch("surge_cc.guard.RuntimeChecker") as runtime:
            self.assertTrue(cli.oauth_checks(settings)["ok"])
        full.assert_called_once_with(settings, external_dns=False)
        proxy.assert_called_once_with(settings)
        runtime.return_value.check.assert_called_once_with(include_exit=False)

    def test_failed_full_gate_never_tests_or_opens_another_route(self):
        with patch.object(cli, "full_checks", return_value={"ok": False}), \
                patch.object(oauth_gate, "verify_proxy_exit") as proxy:
            self.assertFalse(cli.oauth_checks(self.settings())["ok"])
        proxy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
