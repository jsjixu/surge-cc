"""Offline contract tests: browser lock repair never starts login or networking."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import cli, core


class BrowserLockCLITests(unittest.TestCase):
    def setUp(self):
        self.config = core.validate_config({"schema": 1, "group": "Claude", "policy": "Home",
            "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:6152"})

    def invoke(self, arguments):
        output = io.StringIO()
        with patch.object(cli, "load_config", return_value=self.config), redirect_stdout(output):
            code = cli.main(["--config", "/test/config.json", *arguments, "--json"])
        return code, json.loads(output.getvalue())

    def test_lock_failure_offers_explicit_recovery_without_rerunning_launch(self):
        with patch.object(cli, "launch", side_effect=core.BrowserProfileBusy("stale lock")) as launch:
            code, response = self.invoke(["launch", "web"])
        self.assertEqual(code, 2)
        self.assertFalse(response["ok"])
        self.assertEqual(response["recovery_action"], "repair-browser-locks")
        launch.assert_called_once()

    def test_other_errors_do_not_offer_lock_cleanup(self):
        with patch.object(cli, "launch", side_effect=core.Blocked("unsafe directory")):
            _, response = self.invoke(["launch", "web"])
        self.assertNotIn("recovery_action", response)

    def test_non_current_workspace_error_does_not_offer_wrong_target(self):
        with patch.object(cli.workspaces, "snapshot", side_effect=core.BrowserProfileBusy("locked")):
            _, response = self.invoke(["workspace", "snapshot", "--name", "B"])
        self.assertNotIn("recovery_action", response)

    def test_current_workspace_error_offers_recovery(self):
        with patch.object(cli.workspaces, "snapshot", side_effect=core.BrowserProfileBusy("locked")):
            _, response = self.invoke(["workspace", "snapshot", "--name", "A"])
        self.assertEqual(response["recovery_action"], "repair-browser-locks")

    def test_repair_is_offline_and_does_not_open_browser_or_start_claude(self):
        from surge_cc import browser_locks
        recovered = {"status": "repaired", "workspace": "A", "removed_count": 3,
                     "backup_path": "/test/backup", "message": "locks archived"}
        with patch.object(browser_locks, "repair", return_value=recovered) as repair, \
             patch.object(cli, "full_checks") as checks, patch.object(cli, "launch") as launch, \
             patch.object(cli, "Surge") as surge:
            code, response = self.invoke(["browser-locks", "repair", "--workspace", "A"])
        repair.assert_called_once_with(Path("/test/config.json"), "A")
        checks.assert_not_called()
        launch.assert_not_called()
        surge.assert_not_called()
        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["checks"], [])
        self.assertEqual(response["recovery"], recovered)
        self.assertNotIn("recovery_action", response)

    def test_workspace_change_blocks_stale_gui_repair(self):
        from surge_cc import browser_locks
        with patch.object(browser_locks, "repair") as repair:
            code, response = self.invoke(["browser-locks", "repair", "--workspace", "B"])
        repair.assert_not_called()
        self.assertEqual(code, 2)
        self.assertNotIn("recovery_action", response)

    def test_refused_repair_keeps_retry_action_and_reason(self):
        from surge_cc import browser_locks
        with patch.object(browser_locks, "repair", side_effect=core.Blocked("browser still running")):
            code, response = self.invoke(["browser-locks", "repair", "--workspace", "A"])
        self.assertEqual(code, 2)
        self.assertEqual(response["checks"][0]["detail"], "browser still running")
        self.assertEqual(response["recovery_action"], "repair-browser-locks")


if __name__ == "__main__":
    unittest.main()
