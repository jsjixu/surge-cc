"""Offline route transactions preserve unrelated proxies and global mode."""
from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_core import config
from surge_cc import core, workspace_routes as routes
from surge_cc.core import Blocked, definition, profile_sections


PROFILE = """[General]
loglevel = notify
http-listen = 127.0.0.1:6152
[Proxy]
Home = ss, home.example.invalid, 443, password=fixture-a
Canada = ss, canada.example.invalid, 443, password=fixture-b
GenericProxy = socks5, generic.example.invalid, 1080, username=fixture, password=keep
[Proxy Group]
Claude = select, Home
General = select, GenericProxy, DIRECT
[Rule]
# Surge CC: fixed Claude routes
DOMAIN-SUFFIX,claude.ai,"Claude"
DOMAIN-SUFFIX,anthropic.com,"Claude"
DOMAIN-SUFFIX,example.org,General
PROCESS-NAME,PersonalBrowser,General
FINAL,General
"""


class FakeRouteSurge:
    def __init__(self, path):
        self.path = path
        self.state = {"mode": "rule", "profile-path": str(path), "features": {"enhanced-mode": True}}
        self.selections = {"Claude": "Home", "General": "GenericProxy"}
        self.calls = []
        self.pins = []

    def status(self):
        return deepcopy(self.state)

    def profile(self):
        return self.path.read_text()

    def group(self, name):
        fields = definition(profile_sections(self.profile()), "proxy group", name)
        members = [field for field in fields[1:] if "=" not in field]
        return {"name": name, "selected": self.selections.get(name, members[0]),
                "options": [{"name": item, "enabled": True, "isGroup": False} for item in members]}

    def pin(self, target):
        self.pins.append(deepcopy(target))
        self.selections[target["group"]] = target["policy"]

    def call(self, *args):
        self.calls.append(args)
        if args[:2] == ("policy-group", "set"):
            self.selections[args[2]] = args[3]


class WorkspaceRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "surge.conf"
        self.path.write_text(PROFILE)
        self.old = dict(config(), profile_path=str(self.path))
        self.target = dict(self.old, workspace="B", policy="Canada", expected_ip="203.0.113.20")
        self.surge = FakeRouteSurge(self.path)
        self.runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        self.check = Mock(return_value={"ok": True})
        self.sleep_patch = patch.object(routes.time, "sleep")
        self.sleep_patch.start()
        self.addCleanup(self.sleep_patch.stop)

    def activate(self, **kwargs):
        return routes.activate(self.root / "config.json", self.old, self.target,
                               surge=self.surge, runner=self.runner, check=self.check, **kwargs)

    def assert_unrelated_preserved(self, text):
        for line in (
            "GenericProxy = socks5, generic.example.invalid, 1080, username=fixture, password=keep",
            "General = select, GenericProxy, DIRECT", "DOMAIN-SUFFIX,example.org,General",
            "PROCESS-NAME,PersonalBrowser,General", "FINAL,General",
            "Home = ss, home.example.invalid, 443, password=fixture-a",
            "Canada = ss, canada.example.invalid, 443, password=fixture-b",
        ):
            self.assertIn(line, text)

    def test_proposal_replaces_only_owned_routes_and_is_idempotent(self):
        proposed = routes.proposal(PROFILE, self.old, self.target)
        self.assert_unrelated_preserved(proposed)
        self.assertEqual(proposed.count('DOMAIN-SUFFIX,claude.ai,"Claude"'), 1)
        self.assertIn('Claude = select, "Canada", include-all-proxies=0', proposed)
        self.assertEqual(routes.proposal(proposed, self.old, self.target), proposed)

    def test_new_account_group_keeps_old_group_and_other_domain_routes(self):
        target = dict(self.target, group="ClaudeB")
        proposed = routes.proposal(PROFILE, self.old, target)
        self.assert_unrelated_preserved(proposed)
        self.assertIn("Claude = select, Home", proposed)
        self.assertIn('ClaudeB = select, "Canada", include-all-proxies=0', proposed)
        self.assertIn('DOMAIN-SUFFIX,claude.ai,"ClaudeB"', proposed)
        self.assertNotIn('DOMAIN-SUFFIX,claude.ai,"Claude"', proposed)

    def test_activation_preserves_generic_proxy_and_mode_and_returns_working_undo(self):
        undo = self.activate()
        self.assert_unrelated_preserved(self.path.read_text())
        self.assertEqual(self.surge.selections["General"], "GenericProxy")
        self.assertEqual(self.surge.selections["Claude"], "Canada")
        self.assertEqual(self.surge.state["mode"], "rule")
        self.assertEqual(self.surge.calls, [("reload",)])
        backup = next((self.root / "repair-backups").glob("account-*.conf"))
        self.assertEqual(backup.read_text(), PROFILE)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.check.assert_called_once_with(self.target, surge=self.surge)
        undo()
        self.assertEqual(self.path.read_text(), PROFILE)
        self.assertEqual(self.surge.selections["Claude"], "Home")
        self.assertEqual(self.surge.selections["General"], "GenericProxy")

    def test_global_mode_remains_global_and_accepts_explicit_suspension(self):
        self.surge.state["mode"] = "proxy"
        self.check.return_value = core._global_mode_report(self.target)
        undo = self.activate()
        self.assertEqual(self.surge.state["mode"], "proxy")
        self.assertTrue(callable(undo))
        self.assertNotIn(("outbound-mode", "set", "rule"), self.surge.calls)
        self.assertNotIn(("outbound-mode", "set", "proxy"), self.surge.calls)

    def test_failed_target_check_rolls_back_file_and_selection(self):
        self.check.return_value = {"ok": False}
        with self.assertRaisesRegex(Blocked, "已恢复原线路"):
            self.activate()
        self.assertEqual(self.path.read_text(), PROFILE)
        self.assertEqual(self.surge.selections["Claude"], "Home")
        self.assertEqual(self.surge.selections["General"], "GenericProxy")

    def test_invalid_candidate_leaves_original_and_no_selection_change(self):
        self.runner.return_value.returncode = 1
        with self.assertRaisesRegex(Blocked, "语法检查失败"):
            self.activate()
        self.assertEqual(self.path.read_text(), PROFILE)
        self.assertEqual(self.surge.calls, [])
        self.assertEqual(self.surge.pins, [])
        self.assertFalse(list(self.root.glob(".surge-cc-account-check-*")))

    def test_validation_race_refuses_overwriting_external_edit(self):
        external = PROFILE + "# external edit\n"
        def edit(*args, **kwargs):
            self.path.write_text(external)
            return subprocess.CompletedProcess([], 0)
        self.runner.side_effect = edit
        with self.assertRaisesRegex(Blocked, "状态已变化"):
            self.activate()
        self.assertEqual(self.path.read_text(), external)
        self.assertEqual(self.surge.calls, [])

    def test_undo_refuses_overwriting_concurrent_profile_edit(self):
        undo = self.activate()
        external = self.path.read_text() + "# external edit\n"
        self.path.write_text(external)
        with self.assertRaisesRegex(Blocked, "其他程序更改"):
            undo()
        self.assertEqual(self.path.read_text(), external)

    def test_same_route_does_not_touch_surge_or_profile(self):
        self.target = dict(self.old, workspace="B")
        undo = self.activate()
        self.assertEqual(self.path.read_text(), PROFILE)
        self.assertEqual(self.surge.calls, [])
        self.assertEqual(self.surge.pins, [])
        self.check.assert_not_called()
        self.runner.assert_not_called()
        undo()

    def test_changed_active_profile_and_managed_file_are_refused(self):
        self.surge.state["profile-path"] = "/elsewhere.conf"
        with self.assertRaises(Blocked):
            self.activate()
        self.surge.state["profile-path"] = str(self.path)
        self.path.write_text("#!MANAGED-CONFIG\n" + PROFILE)
        with self.assertRaisesRegex(Blocked, "订阅配置"):
            self.activate()
        self.assertEqual(self.path.read_text(), "#!MANAGED-CONFIG\n" + PROFILE)
        self.runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
