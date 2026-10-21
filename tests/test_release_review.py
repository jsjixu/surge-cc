"""Release audit regressions; only temporary files and fake Surge state."""
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_core import config, group
from test_repair import TEXT
from surge_cc import repair, workspaces as ws
from surge_cc.core import Blocked, save_config


class RepairReleaseReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name).resolve()
        self.path = self.folder / "surge.conf"
        self.path.write_text(TEXT)
        self.settings = config()
        self.settings["profile_path"] = str(self.path)
        self.state = {"mode": "rule", "profile-path": str(self.path)}
        self.surge = Mock()
        self.surge.status.side_effect = lambda: deepcopy(self.state)
        self.surge.group.return_value = group()
        self.surge.profile.side_effect = lambda: self.path.read_text()
        self.surge.route.return_value = {"final": "DIRECT"}

    def test_active_profile_drift_during_syntax_validation_blocks_mutation(self):
        reviewed = repair.plan(self.settings, self.surge)

        def validation(*args, **kwargs):
            self.state["profile-path"] = str(self.folder / "unrelated.conf")
            return subprocess.CompletedProcess([], 0)

        with self.assertRaises(Blocked):
            repair.apply(self.settings, self.folder / "config.json",
                         reviewed["plan_id"], self.surge, validation)
        self.assertEqual(self.path.read_text(), TEXT)
        self.surge.call.assert_not_called()
        self.surge.pin.assert_not_called()

    def test_failed_pin_restores_previous_outbound_mode(self):
        self.state["mode"] = "proxy"
        reviewed = repair.plan(self.settings, self.surge)

        def call(*args):
            if args[:2] == ("mode", "set"):
                self.state["mode"] = args[2]
            return {}

        self.surge.call.side_effect = call
        self.surge.pin.side_effect = Blocked("Fixture pin failed")
        with self.assertRaises(Blocked):
            repair.apply(self.settings, self.folder / "config.json",
                         reviewed["plan_id"], self.surge,
                         Mock(return_value=subprocess.CompletedProcess([], 0)))
        self.assertEqual(self.path.read_text(), TEXT)
        self.assertEqual(self.state["mode"], "proxy")

    def test_backup_symlink_cannot_redirect_sensitive_profile_copy(self):
        outside = self.folder / "unrelated-export-directory"
        outside.mkdir()
        (self.folder / "repair-backups").symlink_to(outside, target_is_directory=True)
        reviewed = repair.plan(self.settings, self.surge)
        with self.assertRaises(Blocked):
            repair.apply(self.settings, self.folder / "config.json",
                         reviewed["plan_id"], self.surge,
                         Mock(return_value=subprocess.CompletedProcess([], 0)))
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.path.read_text(), TEXT)

    def test_unknown_or_malformed_mode_blocks_before_planning_mutation(self):
        for value in (None, "", "global", "RULE", 1, [], {}):
            with self.subTest(value=value):
                self.state["mode"] = value
                with self.assertRaises(Blocked):
                    repair.plan(self.settings, self.surge)
                self.assertEqual(self.path.read_text(), TEXT)
                self.surge.call.assert_not_called()

    def test_missing_or_malformed_selection_cannot_be_used_as_rollback_target(self):
        for value in (None, "", "   ", 1, [], {}):
            with self.subTest(value=value):
                candidate = group()
                candidate["selected"] = value
                self.surge.group.return_value = candidate
                with self.assertRaises(Blocked):
                    repair.plan(self.settings, self.surge)
                self.assertEqual(self.path.read_text(), TEXT)
                self.surge.call.assert_not_called()


class WorkspaceReleaseReviewTests(unittest.TestCase):
    def test_manifest_symlink_is_rejected_before_read_or_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            settings_path = root / "config.json"
            save_config(settings_path, config())
            loc = ws.paths(settings_path, "A")
            history = loc["claude"] / "history.jsonl"
            history.write_text("snapshot content")
            saved = ws.snapshot(settings_path, "A")
            history.write_text("current content")
            manifest = loc["root"] / "snapshots" / saved["id"] / "manifest.json"
            outside = root / "outside-manifest.json"
            os.replace(manifest, outside)
            before = outside.read_bytes()
            manifest.symlink_to(outside)
            with patch("surge_cc.workspaces.inventory") as inventory:
                with self.assertRaises(Blocked):
                    ws.restore(settings_path, "A", saved["id"])
                inventory.assert_not_called()
            self.assertEqual(history.read_text(), "current content")
            self.assertEqual(outside.read_bytes(), before)
            self.assertFalse(list(loc["root"].glob("previous-*")))

    def test_snapshot_parent_symlink_is_rejected_before_read_or_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            settings_path = root / "config.json"
            save_config(settings_path, config())
            loc = ws.paths(settings_path, "A")
            history = loc["claude"] / "history.jsonl"
            history.write_text("snapshot content")
            saved = ws.snapshot(settings_path, "A")
            history.write_text("current content")
            snapshots = loc["root"] / "snapshots"
            outside = root / "outside-snapshots"
            os.replace(snapshots, outside)
            snapshots.symlink_to(outside, target_is_directory=True)
            with patch("surge_cc.workspaces.inventory") as inventory:
                with self.assertRaises(Blocked):
                    ws.restore(settings_path, "A", saved["id"])
                inventory.assert_not_called()
            self.assertEqual(history.read_text(), "current content")
            self.assertEqual(len(list(outside.iterdir())), 1)
            self.assertFalse(list(loc["root"].glob("previous-*")))

    def test_interrupted_restore_is_not_silently_replaced_with_empty_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            settings_path = root / "config.json"
            save_config(settings_path, config())
            loc = ws.paths(settings_path, "A")
            (loc["claude"] / "history.jsonl").write_text("recoverable history")
            previous = loc["root"] / ("previous-" + "a" * 32)
            os.replace(loc["data"], previous)
            with self.assertRaises(Blocked):
                ws.paths(settings_path, "A")
            self.assertFalse(loc["data"].exists())
            self.assertEqual((previous / "Claude/history.jsonl").read_text(), "recoverable history")

    def test_case_alias_cannot_claim_to_create_a_separate_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            settings_path = root / "config.json"
            save_config(settings_path, config())
            first = ws.paths(settings_path, "Account")
            if not (first["root"].parent / "account").exists():
                self.skipTest("This regression applies to case-insensitive filesystems")
            (first["claude"] / "history.jsonl").write_text("first workspace only")
            with self.assertRaises(Blocked):
                ws.paths(settings_path, "account")
            self.assertEqual((first["claude"] / "history.jsonl").read_text(), "first workspace only")

    def test_workspace_lookup_during_restore_never_leaves_empty_active_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            settings_path = root / "config.json"
            save_config(settings_path, config())
            loc = ws.paths(settings_path, "A")
            working = loc["claude"] / "history.jsonl"
            working.write_text("snapshot version")
            saved = ws.snapshot(settings_path, "A")
            working.write_text("current version")
            replace = os.replace
            interfered = False

            def replace_with_concurrent_lookup(source, destination):
                nonlocal interfered
                answer = replace(source, destination)
                if (Path(source) == loc["data"] and
                        Path(destination).name.startswith("previous-") and not interfered):
                    interfered = True
                    # Another window may request paths while restore owns the
                    # exclusive lock. It must not recreate the missing data.
                    try:
                        ws.paths(settings_path, "A")
                    except Blocked:
                        pass
                return answer

            try:
                with patch("surge_cc.workspaces.os.replace", side_effect=replace_with_concurrent_lookup):
                    ws.restore(settings_path, "A", saved["id"])
            except (Blocked, OSError):
                pass
            self.assertTrue(interfered)
            self.assertTrue(working.is_file(), "restore left active workspace empty")
            self.assertIn(working.read_text(), ("snapshot version", "current version"))


class BrowserLanguageReleaseReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.settings_path = self.root / "config.json"
        self.settings = dict(config(), browser_language="zh-CN")
        save_config(self.settings_path, self.settings)

    def preferences(self):
        loc = ws.paths(self.settings_path, "A")
        default = loc["browser"] / "Default"
        default.mkdir(exist_ok=True)
        return loc, default / "Preferences"

    def test_empty_language_still_protects_webrtc_without_changing_language(self):
        ws.prepare_browser_language(self.settings_path, dict(self.settings, browser_language=""))
        prefs = self.root / "workspaces/A/data/Browser/Default/Preferences"
        self.assertEqual(json.loads(prefs.read_text()), {
            "webrtc": {"ip_handling_policy": "disable_non_proxied_udp", "ip_handling_url": []}})

    def test_language_preference_is_private_and_preserves_unrelated_settings(self):
        _, prefs = self.preferences()
        original = {
            "intl": {"accept_languages": "en-US,en", "selected_languages": "en-US"},
            "profile": {"name": "Fixture Profile", "content_settings": {"fixture": True}},
            "custom": [1, 2, 3],
        }
        prefs.write_text(json.dumps(original))
        ws.prepare_browser_language(self.settings_path, self.settings)
        expected = deepcopy(original)
        expected["intl"]["accept_languages"] = "zh-CN"
        expected["intl"]["selected_languages"] = "zh-CN"
        expected["webrtc"] = {"ip_handling_policy": "disable_non_proxied_udp", "ip_handling_url": []}
        self.assertEqual(json.loads(prefs.read_text()), expected)
        self.assertEqual(prefs.stat().st_mode & 0o777, 0o600)

    def test_new_profile_language_creates_only_app_owned_preferences(self):
        ws.prepare_browser_language(self.settings_path, self.settings)
        prefs = self.root / "workspaces/A/data/Browser/Default/Preferences"
        self.assertEqual(json.loads(prefs.read_text()), {"intl": {
            "accept_languages": "zh-CN", "selected_languages": "zh-CN"},
            "webrtc": {"ip_handling_policy": "disable_non_proxied_udp", "ip_handling_url": []}})
        self.assertEqual(prefs.stat().st_mode & 0o777, 0o600)
        self.assertEqual(prefs.parent.stat().st_mode & 0o777, 0o700)

    def test_invalid_preferences_are_left_byte_identical(self):
        _, prefs = self.preferences()
        for content in ("{broken", "[]", '{"intl":[]}', '{"intl":null}'):
            with self.subTest(content=content):
                prefs.write_text(content)
                with self.assertRaises(Blocked):
                    ws.prepare_browser_language(self.settings_path, self.settings)
                self.assertEqual(prefs.read_text(), content)

    def test_default_directory_symlink_cannot_write_outside_workspace(self):
        loc = ws.paths(self.settings_path, "A")
        outside = self.root / "outside-browser"
        outside.mkdir()
        prefs = outside / "Preferences"
        prefs.write_text('{"fixture":"unchanged"}')
        (loc["browser"] / "Default").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(Blocked):
            ws.prepare_browser_language(self.settings_path, self.settings)
        self.assertEqual(prefs.read_text(), '{"fixture":"unchanged"}')

    def test_preferences_symlink_cannot_overwrite_external_file(self):
        _, prefs = self.preferences()
        outside = self.root / "outside-preferences"
        outside.write_text('{"fixture":"unchanged"}')
        prefs.symlink_to(outside)
        with self.assertRaises(Blocked):
            ws.prepare_browser_language(self.settings_path, self.settings)
        self.assertTrue(prefs.is_symlink())
        self.assertEqual(outside.read_text(), '{"fixture":"unchanged"}')

    def test_running_workspace_prevents_preference_edit(self):
        loc, prefs = self.preferences()
        prefs.write_text('{"fixture":"unchanged"}')
        with loc["lock"].open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            with self.assertRaises(Blocked):
                ws.prepare_browser_language(self.settings_path, self.settings)
        self.assertEqual(prefs.read_text(), '{"fixture":"unchanged"}')


if __name__ == "__main__":
    unittest.main()
