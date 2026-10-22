"""Orca integration contracts: exact local entry, bounded output, no account data."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import orca_integration as orca
from surge_cc.core import Blocked


def reply(result, *, ok=True):
    return subprocess.CompletedProcess([], 0, json.dumps({"ok": ok, "result": result}), "")


def runtime(running=True, version="1.4.237"):
    return {"target": {"kind": "local"}, "runtime": {"reachable": running, "appVersion": version}}


class OrcaIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "config.json"
        self.project = self.root / "project with spaces"
        self.project.mkdir()
        self.cli = self.root / "orca"
        self.cli.write_text("#!/bin/sh\nexit 0\n")
        self.cli.chmod(0o700)
        self.manifest = {"config_path": str(self.config), "command_path": str(self.root / "Claude Path" / "claude")}
        self.installation = patch.object(orca, "_installation", return_value=self.manifest)
        self.verify = self.installation.start()
        self.addCleanup(self.installation.stop)
        self.runner = Mock(return_value=reply(runtime()))

    def status(self):
        return orca.integration_status(self.config, cli_path=self.cli, runner=self.runner)

    def ready_to_launch(self):
        self.runner.side_effect = [reply(runtime()), reply({"worktree": {"hostId": "local", "path": str(self.project)}}),
                                   reply({"terminal": {"handle": "term_smoke-1", "executionHostId": "local"}})]

    def launch(self):
        return orca.open_protected_terminal(self.config, self.project, cli_path=self.cli, runner=self.runner)

    def test_status_is_read_only_and_does_not_claim_route_or_account_success(self):
        data = self.status()
        self.assertTrue(data["launch_ready"])
        self.assertEqual(data["version"], "1.4.237")
        self.assertNotIn("settings", data)
        self.assertNotIn("command_path", data)
        self.assertEqual(self.runner.call_args.args[0], [str(self.cli), "status", "--json"])
        self.assertEqual(self.runner.call_count, 1)
        modes = {mode["id"]: mode for mode in data["modes"]}
        self.assertEqual(modes["native-chat"]["status"], "info")
        self.assertEqual(modes["managed-account"]["status"], "warn")
        self.assertIn("A/B", modes["managed-account"]["detail"])
        self.assertIn("恢复", modes["native-chat"]["detail"])

    def test_status_missing_integration_is_actionable(self):
        self.verify.side_effect = Blocked("repair required")
        data = self.status()
        self.assertFalse(data["ok"])
        self.assertFalse(data["launch_ready"])
        self.assertEqual(data["action"], "repair-terminal")

    def test_status_stopped_orca_does_not_start_it(self):
        self.runner.return_value = reply(runtime(False))
        data = self.status()
        self.assertTrue(data["launch_ready"])
        self.assertFalse(data["running"])
        self.assertEqual(self.runner.call_count, 1)

    def test_status_unknown_output_is_not_ready_and_does_not_leak(self):
        self.runner.return_value = subprocess.CompletedProcess([], 2, "sensitive-content", "secret-token")
        data = self.status()
        self.assertFalse(data["launch_ready"])
        self.assertNotIn("sensitive-content", json.dumps(data))
        self.assertNotIn("secret-token", json.dumps(data))

    def test_status_remote_target_does_not_count_as_local(self):
        self.runner.return_value = reply({"target": {"kind": "remote"}, "runtime": {"reachable": True}})
        self.assertFalse(self.status()["launch_ready"])

    def test_status_discards_untrusted_version_text(self):
        self.runner.return_value = reply(runtime(version="private-email@example.test --anything"))
        data = self.status()
        self.assertIsNone(data["version"])
        self.assertNotIn("private-email", json.dumps(data))

    def test_status_timeout_does_not_launch_orca(self):
        self.runner.side_effect = subprocess.TimeoutExpired("orca", 10)
        self.assertFalse(self.status()["launch_ready"])
        self.assertEqual(self.runner.call_count, 1)

    def test_status_removes_remote_environment(self):
        with patch.dict(os.environ, {"ORCA_ENVIRONMENT": "remote", "ORCA_PAIRING_CODE": "secret-pairing"}):
            self.status()
        env = self.runner.call_args.kwargs["env"]
        self.assertNotIn("ORCA_ENVIRONMENT", env)
        self.assertNotIn("ORCA_PAIRING_CODE", env)

    def test_cli_rejects_world_writable_executable(self):
        self.cli.chmod(0o777)
        self.assertFalse(self.status()["available"])
        self.runner.assert_not_called()

    def test_explicit_bad_cli_does_not_fall_back(self):
        with patch.object(orca.shutil, "which") as lookup:
            with self.assertRaises(Blocked):
                orca._cli_path(self.root / "missing")
        lookup.assert_not_called()

    def test_cli_command_is_a_path_not_shell_script(self):
        with patch.dict(os.environ, {"ORCA_CLI_COMMAND": "orca; echo secret"}), patch.object(orca.shutil, "which", return_value=None):
            with self.assertRaises(Blocked):
                orca._cli_path()

    def test_launch_uses_exact_verified_absolute_entry_and_local_workspace(self):
        self.ready_to_launch()
        data = self.launch()
        self.assertTrue(data["terminal_created"])
        self.assertFalse(data["route_checked"])
        self.assertFalse(data["launched"])
        calls = [call.args[0] for call in self.runner.call_args_list]
        self.assertEqual(calls[-1], [str(self.cli), "terminal", "create", "--worktree", "path:" + str(self.project),
                                    "--title", "Surge CC", "--command", shlex.quote(self.manifest["command_path"]),
                                    "--focus", "--json"])
        self.assertEqual(self.verify.call_count, 2)
        self.assertFalse(any("send" in call for call in calls))
        self.assertFalse(any("account" in call for call in calls))

    def test_launch_auto_starts_orca_only_when_not_running(self):
        self.runner.side_effect = [reply(runtime(False)), reply(runtime()),
                                   reply({"worktree": {"hostId": "local", "path": str(self.project)}}),
                                   reply({"terminal": {"handle": "term_smoke-1", "executionHostId": "local"}})]
        self.assertTrue(self.launch()["terminal_created"])
        self.assertEqual(self.runner.call_args_list[1].args[0], [str(self.cli), "open", "--json"])

    def test_launch_wrong_project_does_not_create_terminal(self):
        self.runner.side_effect = [reply(runtime()), reply({"worktree": {"hostId": "local", "path": "/other"}})]
        with self.assertRaises(Blocked):
            self.launch()
        self.assertEqual(self.runner.call_count, 2)

    def test_launch_remote_project_does_not_create_terminal(self):
        self.runner.side_effect = [reply(runtime()), reply({"worktree": {"hostId": "ssh-other", "path": str(self.project)}})]
        with self.assertRaises(Blocked):
            self.launch()
        self.assertEqual(self.runner.call_count, 2)

    def test_launch_no_workspace_no_automatic_registration(self):
        self.runner.side_effect = [reply(runtime()), reply({}, ok=False)]
        with self.assertRaises(Blocked):
            self.launch()
        self.assertEqual(self.runner.call_count, 2)

    def test_launch_rechecks_entry_before_creating_terminal(self):
        self.ready_to_launch()
        self.verify.side_effect = [self.manifest, Blocked("entry changed")]
        with self.assertRaises(Blocked):
            self.launch()
        self.assertEqual(self.runner.call_count, 2)

    def test_launch_ambiguous_timeout_never_retries(self):
        self.runner.side_effect = [reply(runtime()), reply({"worktree": {"hostId": "local", "path": str(self.project)}}),
                                   subprocess.TimeoutExpired("orca", 30)]
        with self.assertRaises(Blocked):
            self.launch()
        self.assertEqual(self.runner.call_count, 3)

    def test_launch_invalid_receipt_never_retries(self):
        self.runner.side_effect = [reply(runtime()), reply({"worktree": {"hostId": "local", "path": str(self.project)}}),
                                   reply({"terminal": {"handle": "secret-token\n", "executionHostId": "local"}})]
        with self.assertRaises(Blocked) as error:
            self.launch()
        self.assertNotIn("secret-token", str(error.exception))
        self.assertEqual(self.runner.call_count, 3)

    def test_launch_rejects_relative_project_before_any_call(self):
        with self.assertRaises(Blocked):
            orca.open_protected_terminal(self.config, Path("relative"), cli_path=self.cli, runner=self.runner)
        self.runner.assert_not_called()

    def test_launch_rejects_control_character_project(self):
        with self.assertRaises(Blocked):
            orca.open_protected_terminal(self.config, Path("/tmp/bad\nproject"), cli_path=self.cli, runner=self.runner)
        self.runner.assert_not_called()

    def test_launch_missing_project_is_sanitized(self):
        with self.assertRaises(Blocked) as error:
            orca.open_protected_terminal(self.config, self.root / "secret-project", cli_path=self.cli, runner=self.runner)
        self.assertNotIn("secret-project", str(error.exception))
        self.runner.assert_not_called()

    def test_request_rejects_oversized_output(self):
        self.runner.return_value = subprocess.CompletedProcess([], 0, "x" * (orca._MAX_OUTPUT + 1), "")
        with self.assertRaises(Blocked):
            orca._request(self.cli, ["status"], self.runner)

    def test_installation_rejects_different_config(self):
        self.installation.stop()
        with patch.object(orca.terminal, "status", return_value={"ok": True, "installed": True}), \
                patch.object(orca.terminal, "_read", return_value={**self.manifest, "config_path": "/other/config.json"}), \
                patch.object(orca.terminal, "_verify_active"):
            with self.assertRaises(Blocked):
                orca._installation(self.config)


if __name__ == "__main__":
    unittest.main()
