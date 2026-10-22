"""Maintenance/update/Orca CLI envelopes with no network, login or process launch."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import cli, core, maintenance, orca_integration, remediation, updates


class MaintenanceCLIContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / "config.json"
        self.config = core.validate_config({"schema": 1, "group": "Claude", "policy": "Fixed",
                                           "expected_ip": "203.0.113.20", "proxy_url": "http://127.0.0.1:62919"})
        core.save_config(self.config_path, self.config)
        self.before_config = self.config_path.read_bytes()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.backends = {}
        for name, module, method in (
                ("maintenance_status", maintenance, "status"),
                ("maintenance_plan", maintenance, "plan"),
                ("maintenance_apply", maintenance, "apply"),
                ("updates_check", updates, "check"),
                ("updates_download", updates, "download"),
                ("updates_install", updates, "install"),
                ("orca_status", orca_integration, "integration_status"),
                ("orca_open", orca_integration, "open_protected_terminal")):
            self.backends[name] = self.stack.enter_context(patch.object(module, method))
        self.no_auto = []
        for module, method in ((cli, "launch"), (cli, "OAuthSession"), (cli, "migrate_accounts"),
                               (cli.keychain_auth, "migrate_legacy"), (cli.keychain_auth, "read_token"),
                               (cli.keychain_auth, "store_token"), (cli.workspaces, "use"),
                               (cli.subprocess, "Popen")):
            self.no_auto.append(self.stack.enter_context(patch.object(module, method)))
        self.stack.enter_context(patch.object(remediation.terminal, "status", return_value={"ok": True, "installed": True}))

    def invoke(self, arguments, *, config_path=None):
        out, err = io.StringIO(), io.StringIO()
        arguments = list(arguments)
        arguments.insert(arguments.index("--") if "--" in arguments else len(arguments), "--json")
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["--config", str(config_path or self.config_path), *arguments])
        text = out.getvalue()
        self.assertEqual(len(text.splitlines()), 1, text)
        data = json.loads(text)
        self.assertEqual(data["schema"], 1)
        self.assertIn("checked_at", data)
        self.assertIsInstance(data["checks"], list)
        self.assertIsInstance(data["summary"], str)
        for guard in self.no_auto:
            guard.assert_not_called()
        self.assertEqual(self.config_path.read_bytes(), self.before_config)
        self.assertEqual(err.getvalue(), "")
        return code, data

    def only_backend(self, expected):
        for name, backend in self.backends.items():
            if name == expected:
                self.assertEqual(backend.call_count, 1, name)
            else:
                backend.assert_not_called()

    def test_maintenance_status_preserves_diagnostic_result(self):
        inner = {"schema": 1, "ok": False, "summary": "repair needed", "entries": [
            {"id": "terminal", "title": "CLI", "status": "fail", "detail": "changed", "action": "repair-terminal"}]}
        self.backends["maintenance_status"].return_value = inner
        code, data = self.invoke(["maintenance", "status"])
        self.assertEqual(code, 0)  # inspection completed; the nested diagnostic failed
        self.assertEqual(data["maintenance"], inner)
        self.assertFalse(data["maintenance"]["ok"])
        self.assertEqual(data["summary"], "repair needed")
        self.backends["maintenance_status"].assert_called_once_with(self.config_path)
        self.only_backend("maintenance_status")

    def test_maintenance_plan_summary_is_not_passed_twice(self):
        plan = {"schema": 1, "ok": True, "summary": "review plan", "plan_id": "review-123",
                "operation": "repair-terminal", "actions": [{"title": "repair", "detail": "keep logins"}],
                "target_version": "2.1.296"}
        self.backends["maintenance_plan"].return_value = copy.deepcopy(plan)
        code, data = self.invoke(["maintenance", "plan", "--operation", "repair-terminal"])
        self.assertEqual(code, 0)
        self.assertTrue(data["ok"])
        self.assertEqual(data["summary"], plan["summary"])
        self.assertEqual(data["plan_id"], plan["plan_id"])
        self.assertEqual(data["actions"], plan["actions"])
        self.backends["maintenance_plan"].assert_called_once_with(self.config_path, "repair-terminal")
        self.only_backend("maintenance_plan")

    def test_maintenance_update_plan_dispatches_without_applying(self):
        self.backends["maintenance_plan"].return_value = {"summary": "update preview", "plan_id": "update-1", "actions": []}
        code, data = self.invoke(["maintenance", "plan", "--operation", "update-claude"])
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"], "update preview")
        self.backends["maintenance_plan"].assert_called_once_with(self.config_path, "update-claude")
        self.only_backend("maintenance_plan")

    def test_maintenance_apply_summary_and_nested_receipt(self):
        self.backends["maintenance_apply"].return_value = {"schema": 1, "ok": True, "summary": "entry repaired", "version": "2.1.296"}
        code, data = self.invoke(["maintenance", "apply", "--plan-id", "review-123"])
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"], "entry repaired")
        self.assertEqual(data["maintenance"]["version"], "2.1.296")
        self.backends["maintenance_apply"].assert_called_once_with(self.config_path, "review-123")
        self.only_backend("maintenance_apply")

    def test_maintenance_missing_operation_is_json_failure_before_backend(self):
        code, data = self.invoke(["maintenance", "plan"])
        self.assertEqual(code, 2)
        self.assertFalse(data["ok"])
        self.assertIn("维护操作", data["checks"][0]["detail"])
        for backend in self.backends.values():
            backend.assert_not_called()

    def test_maintenance_missing_plan_is_json_failure_before_backend(self):
        code, data = self.invoke(["maintenance", "apply"])
        self.assertEqual(code, 2)
        self.assertIn("预览维护计划", data["checks"][0]["detail"])
        for backend in self.backends.values():
            backend.assert_not_called()

    def test_updates_check_does_not_download_or_install(self):
        inner = {"version": "0.5.0", "state": "available", "summary": "new release", "update_available": True}
        self.backends["updates_check"].return_value = inner
        code, data = self.invoke(["updates", "check"])
        self.assertEqual(code, 0)
        self.assertEqual(data["update"], inner)
        self.backends["updates_check"].assert_called_once_with(self.config_path)
        self.only_backend("updates_check")

    def test_updates_check_can_run_before_initial_configuration(self):
        self.backends["updates_check"].return_value = {"state": "current", "version": "0.5.0"}
        code, data = self.invoke(["updates", "check"], config_path=self.root / "not-created.json")
        self.assertEqual(code, 0)
        self.assertEqual(data["settings"], {})
        self.only_backend("updates_check")

    def test_updates_download_only_dispatches_requested_version(self):
        inner = {"version": "0.5.0", "state": "downloaded", "summary": "verified", "verified": True}
        self.backends["updates_download"].return_value = inner
        code, data = self.invoke(["updates", "download", "--version", "0.5.0"])
        self.assertEqual(code, 0)
        self.assertEqual(data["update"], inner)
        self.backends["updates_download"].assert_called_once_with(self.config_path, "0.5.0")
        self.only_backend("updates_download")

    def test_updates_install_preserves_installing_not_completed_state(self):
        inner = {"state": "installing", "version": "0.5.0", "receipt_path": str(self.root / "receipt.json"), "summary": "restart pending"}
        self.backends["updates_install"].return_value = inner
        code, data = self.invoke(["updates", "install", "--version", "0.5.0"])
        self.assertEqual(code, 0)
        self.assertEqual(data["update"], inner)
        self.assertEqual(data["update"]["state"], "installing")
        self.backends["updates_install"].assert_called_once_with(self.config_path, "0.5.0")
        self.only_backend("updates_install")

    def test_update_mutations_require_explicit_version(self):
        for action in ("download", "install"):
            with self.subTest(action=action):
                code, data = self.invoke(["updates", action])
                self.assertEqual(code, 2)
                self.assertFalse(data["ok"])
        for backend in self.backends.values():
            backend.assert_not_called()

    def test_orca_status_envelope_preserves_modes_and_readiness(self):
        inner = {"schema": 1, "ok": True, "summary": "ready", "available": True, "running": True,
                 "version": "1.4.237", "launch_ready": True,
                 "modes": [{"id": "shell", "title": "Terminal", "status": "info", "detail": "exact entry"}]}
        self.backends["orca_status"].return_value = inner
        code, data = self.invoke(["orca", "status"])
        self.assertEqual(code, 0)
        self.assertEqual(data["orca"], inner)
        self.backends["orca_status"].assert_called_once_with(self.config_path)
        self.only_backend("orca_status")

    def test_orca_failed_status_is_not_reported_as_launch_ready(self):
        inner = {"ok": False, "launch_ready": False, "summary": "repair required", "modes": []}
        self.backends["orca_status"].return_value = inner
        code, data = self.invoke(["orca", "status"])
        self.assertEqual(code, 2)
        self.assertFalse(data["ok"])
        self.assertFalse(data["orca"]["launch_ready"])
        self.assertFalse(data["orca"]["ok"])
        self.only_backend("orca_status")

    def test_orca_open_requires_and_preserves_explicit_project(self):
        project = str(self.root / "Project with spaces; literal")
        inner = {"ok": True, "terminal_created": True, "launched": False, "route_checked": False,
                 "summary": "terminal created", "handle": "term_test"}
        self.backends["orca_open"].return_value = inner
        code, data = self.invoke(["orca", "open-terminal", "--project", project])
        self.assertEqual(code, 0)
        self.assertEqual(data["orca"], inner)
        self.backends["orca_open"].assert_called_once_with(self.config_path, project)
        self.assertFalse(data["orca"]["route_checked"])
        self.only_backend("orca_open")

    def test_orca_open_missing_project_never_falls_back_to_cwd(self):
        code, data = self.invoke(["orca", "open-terminal"])
        self.assertEqual(code, 2)
        self.assertIn("选择 Orca 工作区", data["checks"][0]["detail"])
        for backend in self.backends.values():
            backend.assert_not_called()

    def test_all_backend_refusals_produce_json_error_and_nonzero_exit(self):
        cases = [(["maintenance", "status"], "maintenance_status"),
                 (["maintenance", "plan", "--operation", "repair-terminal"], "maintenance_plan"),
                 (["maintenance", "apply", "--plan-id", "p1"], "maintenance_apply"),
                 (["updates", "check"], "updates_check"),
                 (["updates", "download", "--version", "0.5.0"], "updates_download"),
                 (["updates", "install", "--version", "0.5.0"], "updates_install"),
                 (["orca", "status"], "orca_status"),
                 (["orca", "open-terminal", "--project", str(self.root)], "orca_open")]
        for args, name in cases:
            with self.subTest(command=args):
                for backend in self.backends.values():
                    backend.reset_mock(side_effect=True)
                self.backends[name].side_effect = core.Blocked("operation refused safely")
                code, data = self.invoke(args)
                self.assertEqual(code, 2)
                self.assertFalse(data["ok"])
                self.assertEqual(data["checks"][0]["detail"], "operation refused safely")
                self.assertIn("remediation_action", data)
                self.only_backend(name)

    def test_all_backend_system_errors_are_sanitized_json_errors(self):
        cases = [(["maintenance", "status"], "maintenance_status"),
                 (["maintenance", "plan", "--operation", "update-claude"], "maintenance_plan"),
                 (["maintenance", "apply", "--plan-id", "p1"], "maintenance_apply"),
                 (["updates", "check"], "updates_check"),
                 (["updates", "download", "--version", "0.5.0"], "updates_download"),
                 (["updates", "install", "--version", "0.5.0"], "updates_install"),
                 (["orca", "status"], "orca_status"),
                 (["orca", "open-terminal", "--project", str(self.root)], "orca_open")]
        for args, name in cases:
            with self.subTest(command=args):
                for backend in self.backends.values():
                    backend.reset_mock(side_effect=True)
                self.backends[name].side_effect = OSError("credential-never-echo-this")
                code, data = self.invoke(args)
                self.assertEqual(code, 1)
                self.assertFalse(data["ok"])
                self.assertNotIn("credential-never-echo-this", json.dumps(data))
                self.only_backend(name)

    def test_nonlaunch_commands_reject_trailing_native_arguments(self):
        code, data = self.invoke(["orca", "status", "--", "auth", "login"])
        self.assertEqual(code, 2)
        self.assertFalse(data["ok"])
        for backend in self.backends.values():
            backend.assert_not_called()

    def test_parser_rejects_unrecognized_operation_without_backend(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit) as failure:
            cli.main(["--config", str(self.config_path), "maintenance", "plan", "--operation", "arbitrary-command", "--json"])
        self.assertEqual(failure.exception.code, 2)
        for backend in self.backends.values():
            backend.assert_not_called()


if __name__ == "__main__":
    unittest.main()
