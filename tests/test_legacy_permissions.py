"""Only the recognized obsolete Orca template may be narrowed."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import legacy_permissions
from surge_cc.core import Blocked


class LegacyPermissionsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="legacy-permissions-", dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.host_home = self.base / "host"
        self.root = self.host_home / "orca/workspaces/project/worker"
        self.home = self.base / "private-home"
        (self.root / ".claude").mkdir(parents=True)
        self.home.mkdir(mode=0o700)
        self.path = self.root / ".claude/settings.json"
        self.project = SimpleNamespace(root=self.root, home=self.home)
        self.rules = legacy_permissions.template(self.host_home)

    def write(self, *, rules=None, **extra):
        value = {"permissions": {"deny": self.rules if rules is None else rules}, **extra}
        self.path.write_text(json.dumps(value))
        self.path.chmod(0o600)
        return self.path.read_bytes()

    def repair(self):
        return legacy_permissions.repair(self.project, host_home=self.host_home)

    def test_complete_template_only_removes_orca_read_edit(self):
        self.write(theme="dark", enabledPlugins={"fixture@local": True})
        self.repair()
        value = json.loads(self.path.read_text())
        expected = [rule for rule in self.rules if str(self.host_home / "orca") not in rule]
        self.assertEqual(value["permissions"]["deny"], expected)
        self.assertEqual(len(expected), 10)
        self.assertEqual(value["theme"], "dark")
        self.assertEqual(value["enabledPlugins"], {"fixture@local": True})

    def test_custom_rules_and_other_permission_fields_preserved(self):
        custom = ["Read(./private/**)", "Bash(rm:*)", "Read(./CLAUDE.md)"]
        self.write(rules=self.rules + custom)
        value = json.loads(self.path.read_text())
        value["permissions"].update(allow=["Read(./src/**)"], defaultMode="auto")
        self.path.write_text(json.dumps(value))
        self.repair()
        migrated = json.loads(self.path.read_text())["permissions"]
        self.assertEqual(migrated["deny"][-3:], custom)
        self.assertEqual(migrated["allow"], ["Read(./src/**)"])
        self.assertEqual(migrated["defaultMode"], "auto")

    def test_partial_or_custom_template_is_never_removed(self):
        for rules in (self.rules[:-1], [self.rules[1]], [], ["Read(./CLAUDE.md)"]):
            with self.subTest(rules=rules):
                before = self.write(rules=rules)
                self.assertIsNone(self.repair())
                self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse((self.home / ".surge-cc-settings-backups").exists())

    def test_backup_private_exact_and_migration_idempotent(self):
        before = self.write()
        result = self.repair()
        backup = Path(result["backup"])
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(backup.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(result["before_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(result["after_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        after = self.path.read_bytes()
        self.assertIsNone(self.repair())
        self.assertEqual(self.path.read_bytes(), after)
        self.assertEqual(len(list(backup.parent.iterdir())), 1)

    def test_settings_local_is_not_migrated(self):
        self.write()
        local = self.path.with_name("settings.local.json")
        local.write_bytes(self.path.read_bytes())
        before = local.read_bytes()
        self.repair()
        self.assertEqual(local.read_bytes(), before)

    def test_symlink_settings_refused_without_touching_target(self):
        before = self.write()
        outside = self.base / "outside-settings.json"
        self.path.rename(outside)
        self.path.symlink_to(outside)
        with self.assertRaises(Blocked):
            self.repair()
        self.assertEqual(outside.read_bytes(), before)
        self.assertFalse((self.home / ".surge-cc-settings-backups").exists())

    def test_symlink_parent_refused_without_touching_target(self):
        before = self.write()
        folder = self.path.parent
        outside = self.base / "outside-settings"
        folder.rename(outside)
        folder.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(Blocked):
            self.repair()
        self.assertEqual((outside / "settings.json").read_bytes(), before)

    def test_hardlinked_settings_refused_without_touching_other_name(self):
        before = self.write()
        outside = self.base / "outside-settings.json"
        os.link(self.path, outside)
        with self.assertRaises(Blocked):
            self.repair()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(outside.read_bytes(), before)
        self.assertFalse((self.home / ".surge-cc-settings-backups").exists())

    def test_unsafe_backup_destination_refused(self):
        before = self.write()
        outside = self.base / "outside-backups"
        outside.mkdir()
        (self.home / ".surge-cc-settings-backups").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(Blocked):
            self.repair()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(outside.iterdir()), [])

    def test_missing_settings_has_no_effect(self):
        self.assertIsNone(self.repair())
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
