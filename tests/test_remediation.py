"""Recovery action mapping stays narrow and never masks original diagnostics."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, remediation as r


class RemediationTests(unittest.TestCase):
    def report(self, identifier="exception", status="fail", *, required=True):
        return {"ok": False, "summary": "original failure", "settings": {"expected_ip": "203.0.113.10"},
                "checks": [{"id": identifier, "status": status, "required": required, "detail": "original evidence"}]}

    def attach(self, value, **kwargs):
        original = copy.deepcopy(value)
        result = r.attach(value, **kwargs)
        self.assertIs(result, value)
        self.assertIn(result.get("remediation_action"), r.ACTIONS)
        self.assertEqual({k: v for k, v in result.items() if k != "remediation_action"}, original)
        return result["remediation_action"]

    def test_explicit_route_errors_win_over_unrelated_terminal_failure(self):
        for identifier, action in (("surge", "open-surge"), ("mode", "open-surge"),
                                  ("proxy", "open-surge"), ("definition", "repair-route"),
                                  ("group", "repair-route"), ("route", "repair-route"),
                                  ("stable", "repair-route"), ("browser_containment", "repair-route")):
            with self.subTest(identifier=identifier), patch.object(r.terminal, "status", return_value={"ok": False}) as status:
                self.assertEqual(self.attach(self.report(identifier)), action)
                status.assert_not_called()

    def test_exit_mismatch_never_adopts_observed_address(self):
        for identifier in ("exit", "geoip_country", "geoip_asn"):
            value = self.report(identifier)
            value["actual_ip"] = "198.51.100.99"
            with patch.object(r.terminal, "status", return_value={"ok": False}):
                self.assertEqual(self.attach(value), "configure-route")
            self.assertEqual(value["settings"]["expected_ip"], "203.0.113.10")

    def test_browser_recovery_keeps_priority(self):
        for existing in ("recover-browser", "repair-browser-locks"):
            value = self.report("exception")
            value["recovery_action"] = existing
            self.assertEqual(self.attach(value, error=PermissionError("permission")), "recover-browser")

    def test_permission_exception_opens_settings(self):
        self.assertEqual(self.attach(self.report(), error=PermissionError("denied")), "open-app-management")

    def test_original_native_change_maps_to_maintenance(self):
        error = core.Blocked("原始 Claude 程序已变化；请通过维护流程重新安装终端集成。")
        self.assertEqual(self.attach(self.report(), error=error), "repair-terminal")
        value = self.report()
        value["checks"][0]["detail"] = str(error)
        self.assertEqual(self.attach(value), "repair-terminal")

    def test_auxiliary_status_exceptions_never_mask_original(self):
        for error in (RuntimeError("query failed"), core.Blocked("blocked"), PermissionError("permission"), ValueError("malformed")):
            with self.subTest(error=error), patch.object(r.terminal, "status", side_effect=error):
                value = self.report()
                value["checks"] = []
                self.assertEqual(self.attach(value), "recheck")

    def test_auxiliary_status_bad_types_ignored(self):
        for observed in (None, False, [], "not-json"):
            with patch.object(r.terminal, "status", return_value=observed):
                value = self.report()
                value["checks"] = []
                self.assertEqual(self.attach(value), "recheck")

    def test_primary_project_or_auth_error_not_hijacked_by_terminal(self):
        for identifier in ("exception", "project_isolation", "credentials", "dns_external"):
            with patch.object(r.terminal, "status", return_value={"ok": False}) as status:
                self.assertEqual(self.attach(self.report(identifier), error=core.Blocked("项目注册信息无效")), "recheck")
                status.assert_not_called()

    def test_global_terminal_issue_only_enriches_unexplained_failure(self):
        with patch.object(r.terminal, "status", return_value={"ok": False}):
            value = self.report()
            value["checks"] = []
            self.assertEqual(self.attach(value), "repair-terminal")

    def test_optional_failures_do_not_trigger_route_repair(self):
        with patch.object(r.terminal, "status", return_value={"ok": True}):
            self.assertEqual(self.attach(self.report("geoip_country", required=False)), "recheck")

    def test_malformed_checks_cannot_raise_or_produce_arbitrary_action(self):
        for checks in (None, "not-list", {}, [None, "bad", {"id": [], "status": []}],
                       [{"id": {"bad": 1}, "status": "fail"}], [{"status": "fail"}]):
            with patch.object(r.terminal, "status", side_effect=RuntimeError("offline")):
                value = self.report()
                value["checks"] = checks
                self.assertEqual(self.attach(value), "recheck")

    def test_success_and_explicit_global_pause_unchanged(self):
        for value in (None, [], {"ok": True}, {"ok": False, "paused": True}):
            original = copy.deepcopy(value)
            with patch.object(r.terminal, "status", side_effect=AssertionError("must not inspect")):
                self.assertIs(r.attach(value), value)
            self.assertEqual(value, original)

    def test_empty_settings_get_configuration_guidance(self):
        value = self.report()
        value["settings"] = {}
        self.assertEqual(self.attach(value), "configure-route")


if __name__ == "__main__":
    unittest.main()
