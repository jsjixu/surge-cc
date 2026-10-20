from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_core import config, group, route
from surge_cc import containment, repair
from surge_cc.core import Blocked, CHROME, profile_sections, split_fields


TEXT = """[General]
loglevel = notify
[Proxy]
Home = ss, example.invalid, 443, password=fixture
Other = socks5, example.invalid, 1080
[Proxy Group]
Claude = select, Home, DIRECT
Unrelated = select, Other, DIRECT
[Rule]
DOMAIN-SUFFIX,example.org,DIRECT
FINAL,Unrelated
"""


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name).resolve()
        self.path = self.folder / "surge.conf"
        self.path.write_text(TEXT)
        self.settings = config()
        self.settings["profile_path"] = str(self.path)
        self.surge = Mock()
        self.surge.status.return_value = {"mode": "rule", "profile-path": str(self.path)}
        self.surge.group.return_value = group()
        self.surge.profile.side_effect = lambda: self.path.read_text()
        self.surge.route.return_value = {"final": "DIRECT"}

    def test_patch_only_target_group_and_rule_prefix(self):
        fixed = repair.patch_profile(TEXT, self.settings, True, True)
        self.assertIn("Other = socks5, example.invalid, 1080", fixed)
        self.assertIn("Unrelated = select, Other, DIRECT", fixed)
        self.assertIn("DOMAIN-SUFFIX,example.org,DIRECT", fixed)
        self.assertIn("FINAL,Unrelated", fixed)
        self.assertIn('Claude = select, "Home", include-all-proxies=0', fixed)
        self.assertLess(fixed.index("DOMAIN-SUFFIX,claude.ai"), fixed.index("DOMAIN-SUFFIX,example.org"))

    def test_plan_public_output_never_contains_profile_credentials(self):
        value = repair.public_plan(repair.plan(self.settings, self.surge))
        self.assertNotIn("password", str(value))
        self.assertIn("plan_id", value)
        self.assertGreater(len(value["actions"]), 0)
        self.surge.call.assert_not_called()
        self.assertEqual(self.path.read_text(), TEXT)

    def test_changed_plan_is_rejected_before_mutation(self):
        plan = repair.plan(self.settings, self.surge)
        self.path.write_text(TEXT + "# edited\n")
        with self.assertRaises(Blocked):
            repair.apply(self.settings, self.folder / "config.json", plan["plan_id"], self.surge)
        self.assertTrue(self.path.read_text().endswith("# edited\n"))
        self.surge.call.assert_not_called()

    def test_validated_apply_keeps_private_backup(self):
        plan = repair.plan(self.settings, self.surge)
        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        result = repair.apply(self.settings, self.folder / "config.json", plan["plan_id"], self.surge, runner)
        self.assertTrue(result["backup_created"])
        backup = next((self.folder / "repair-backups").glob("*.conf"))
        self.assertEqual(backup.read_text(), TEXT)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.surge.call.assert_called_with("reload")
        self.surge.pin.assert_called_once()

    def test_failed_validation_does_not_write_original(self):
        plan = repair.plan(self.settings, self.surge)
        with self.assertRaises(Blocked):
            repair.apply(self.settings, self.folder / "config.json", plan["plan_id"], self.surge,
                         Mock(return_value=subprocess.CompletedProcess([], 1)))
        self.assertEqual(self.path.read_text(), TEXT)
        self.surge.call.assert_not_called()

    def test_reload_failure_restores_original(self):
        plan = repair.plan(self.settings, self.surge)
        self.surge.call.side_effect = Blocked("failed")
        with self.assertRaises(Blocked):
            repair.apply(self.settings, self.folder / "config.json", plan["plan_id"], self.surge,
                         Mock(return_value=subprocess.CompletedProcess([], 0)))
        self.assertEqual(self.path.read_text(), TEXT)

    def test_managed_profile_not_overwritten(self):
        self.path.write_text("#!MANAGED-CONFIG https://example.invalid/profile\n" + TEXT)
        with self.assertRaises(Blocked):
            repair.plan(self.settings, self.surge)

    def test_missing_or_different_active_profile_rejected(self):
        self.surge.status.return_value = {"mode": "rule", "profile-path": "other.conf"}
        with self.assertRaises(Blocked):
            repair.plan(self.settings, self.surge)


class DedicatedRepairTests(unittest.TestCase):
    """Only synthetic profiles and fake Surge state; never starts a browser."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name).resolve()
        self.path = self.folder / "surge.conf"
        self.original = TEXT.replace("Claude = select, Home, DIRECT", "Claude = select, Home")
        self.path.write_text(self.original)
        self.settings = config()
        self.settings.update(
            profile_path=str(self.path),
            browser_path=str(self.folder / "Surge CC Browser.app/Contents/MacOS/Google Chrome"),
            proxy_url="http://127.0.0.1:62919",
        )
        self.state = {"mode": "rule", "profile-path": str(self.path),
                      "features": {"enhanced-mode": True, "system-proxy": True}}
        self.surge = Mock()
        self.surge.status.side_effect = lambda: deepcopy(self.state)
        self.surge.group.return_value = group()
        self.surge.profile.side_effect = lambda: self.path.read_text()
        self.surge.route.return_value = route()
        self.runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        scope_patch = patch("surge_cc.repair.containment.validate_scope")
        self.validate = scope_patch.start()
        self.addCleanup(scope_patch.stop)
        sleep_patch = patch("surge_cc.repair.time.sleep")
        self.sleep = sleep_patch.start()
        self.addCleanup(sleep_patch.stop)

    def apply(self, reviewed=None):
        reviewed = reviewed or repair.plan(self.settings, self.surge)
        return repair.apply(self.settings, self.folder / "config.json", reviewed["plan_id"],
                            self.surge, self.runner)

    def assert_scope_first(self, text):
        rules = profile_sections(text)["rule"]
        self.assertEqual(split_fields(rules[0]), ["IN-PORT", "62919", self.settings["group"]])
        self.assertEqual(split_fields(rules[1]), [
            "PROCESS-NAME", str(Path(self.settings["browser_path"]).parents[2]) + "/", "REJECT",
        ])

    def test_domain_repair_keeps_scope_above_domain_rules(self):
        scoped = containment.patch_profile(self.original, self.settings)
        fixed = repair.patch_profile(scoped, self.settings, False, True)
        self.assert_scope_first(fixed)
        self.assertEqual(fixed.count(containment.BEGIN), 1)
        self.assertEqual(fixed.count(containment.END), 1)
        self.assertLess(fixed.index("PROCESS-NAME,"), fixed.index("DOMAIN-SUFFIX,claude.ai"))
        self.assertIn("DOMAIN-SUFFIX,example.org,DIRECT", fixed)
        self.assertIn("FINAL,Unrelated", fixed)

    def test_group_repair_preserves_existing_listeners_and_credentials(self):
        original = TEXT.replace(
            "loglevel = notify",
            "loglevel = notify\nhttp-listen = fixture-secret@127.0.0.1:6152\n"
            "socks5-listen = 127.0.0.1:6153\nexternal-controller-access = fixture-token@127.0.0.1:6171",
        )
        fixed = repair.patch_profile(original, self.settings, True, False)
        self.assert_scope_first(fixed)
        self.assertIn("http-listen = fixture-secret@127.0.0.1:6152, 127.0.0.1:62919", fixed)
        self.assertIn("socks5-listen = 127.0.0.1:6153", fixed)
        self.assertIn("external-controller-access = fixture-token@127.0.0.1:6171", fixed)
        self.assertIn("password=fixture", fixed)
        self.assertIn("Unrelated = select, Other, DIRECT", fixed)

    def test_missing_scope_is_reviewable_and_repaired_without_domain_or_group_changes(self):
        reviewed = repair.plan(self.settings, self.surge)
        ids = [action["id"] for action in reviewed["actions"]]
        self.assertEqual(ids, ["scope", "reload"])
        self.assertEqual(self.path.read_text(), self.original)
        self.surge.call.assert_not_called()
        self.assertNotIn("password", str(repair.public_plan(reviewed)))
        result = self.apply(reviewed)
        self.assertTrue(result["backup_created"])
        self.assert_scope_first(self.path.read_text())
        self.validate.assert_called_once_with(self.settings, self.surge)
        self.surge.call.assert_called_once_with("reload")
        self.surge.pin.assert_not_called()

    def test_plan_routes_use_dedicated_binary_instead_of_personal_chrome(self):
        repair.plan(self.settings, self.surge)
        processes = {call.args[2] for call in self.surge.route.call_args_list}
        self.assertIn(self.settings["browser_path"], processes)
        self.assertNotIn(str(CHROME), processes)

    def test_valid_scope_not_reported_as_new_repair_when_only_domains_need_fixing(self):
        self.path.write_text(containment.patch_profile(self.original, self.settings))
        self.surge.route.return_value = {"final": "DIRECT"}
        reviewed = repair.plan(self.settings, self.surge)
        self.assertEqual([item["id"] for item in reviewed["actions"]], ["rules", "reload"])
        self.assert_scope_first(reviewed["_proposed"])
        self.apply(reviewed)
        self.assert_scope_first(self.path.read_text())

    def test_disabled_enhanced_mode_is_a_manual_requirement_and_never_toggled(self):
        self.state["features"]["enhanced-mode"] = False
        reviewed = repair.plan(self.settings, self.surge)
        self.assertIn("enhanced-required", [item["id"] for item in reviewed["actions"]])
        with self.assertRaisesRegex(Blocked, "手动开启增强模式"):
            self.apply(reviewed)
        self.assertEqual(self.path.read_text(), self.original)
        self.assertFalse((self.folder / "repair-backups").exists())
        self.runner.assert_not_called()
        self.surge.call.assert_not_called()

    def test_enhanced_mode_changes_invalidate_review_before_mutation(self):
        reviewed = repair.plan(self.settings, self.surge)
        self.state["features"]["enhanced-mode"] = False
        with self.assertRaisesRegex(Blocked, "计划已变化"):
            self.apply(reviewed)
        self.assertEqual(self.path.read_text(), self.original)
        self.surge.call.assert_not_called()

    def test_post_apply_scope_failure_restores_source(self):
        self.validate.side_effect = Blocked("fixture: unrelated temporary override")
        reviewed = repair.plan(self.settings, self.surge)
        with self.assertRaisesRegex(Blocked, "已恢复"):
            self.apply(reviewed)
        self.assertEqual(self.path.read_text(), self.original)
        self.assertEqual([call.args for call in self.surge.call.call_args_list],
                         [("reload",), ("reload",)])
        backup = next((self.folder / "repair-backups").glob("*.conf"))
        self.assertEqual(backup.read_text(), self.original)

    def test_reload_waits_for_transient_enhanced_mode_and_effective_rule_convergence(self):
        proposed = containment.patch_profile(self.original, self.settings)
        statuses = [
            {**self.state, "features": {"enhanced-mode": False}},
            deepcopy(self.state), deepcopy(self.state), deepcopy(self.state), deepcopy(self.state),
        ]
        self.surge.status.side_effect = statuses
        self.surge.profile.side_effect = [self.original, proposed, proposed, proposed]
        repair._wait_scope_ready(self.settings, self.surge, proposed)
        self.assertEqual(self.sleep.call_count, 4)
        self.surge.call.assert_not_called()

    def test_reload_timeout_rolls_back_without_enabling_enhanced_mode(self):
        reviewed = repair.plan(self.settings, self.surge)

        def reload(*args):
            if args == ("reload",):
                self.state["features"]["enhanced-mode"] = False
            return {}

        self.surge.call.side_effect = reload
        with self.assertRaisesRegex(Blocked, "已恢复"):
            self.apply(reviewed)
        self.assertEqual(self.path.read_text(), self.original)
        self.validate.assert_not_called()
        self.assertEqual(self.sleep.call_count, 19)
        self.assertTrue(all(call.args == ("reload",) for call in self.surge.call.call_args_list))

    def test_effective_scope_failure_can_reload_unchanged_source_for_revalidation(self):
        scoped = containment.patch_profile(self.original, self.settings)
        self.path.write_text(scoped)
        self.validate.side_effect = Blocked("fixture: old effective profile")
        reviewed = repair.plan(self.settings, self.surge)
        self.assertEqual(reviewed["_proposed"], scoped)
        self.assertEqual([item["id"] for item in reviewed["actions"]], ["scope", "reload"])

        def reload(*args):
            if args == ("reload",):
                self.validate.side_effect = None
            return {}

        self.surge.call.side_effect = reload
        result = self.apply(reviewed)
        self.assertFalse(result["backup_created"])
        self.surge.call.assert_called_once_with("reload")
        self.assertEqual(self.path.read_text(), scoped)

    def test_profile_switch_during_wait_stops_without_touching_new_profile(self):
        proposed = containment.patch_profile(self.original, self.settings)
        other = self.folder / "unrelated.conf"
        other.write_text("unrelated configuration")
        self.state["profile-path"] = str(other)
        with self.assertRaisesRegex(Blocked, "配置已切换"):
            repair._wait_scope_ready(self.settings, self.surge, proposed)
        self.assertEqual(other.read_text(), "unrelated configuration")
        self.surge.call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
