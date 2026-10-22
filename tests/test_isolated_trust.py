"""Scoped directory trust tests; no real projects, accounts or Claude calls."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, isolated_preferences as preferences, isolated_trust as trust, isolation


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve() / "isolated"
        self.root = self.base / "projects" / "vv"
        self.home = self.base / ".runtime" / "vv" / "home"
        self.root.mkdir(parents=True, mode=0o700)
        (self.home / ".claude").mkdir(parents=True, mode=0o700)
        self.project = isolation.Project("vv", self.root, self.home)
        self.runtime = self.base / ".runtime"
        self.marker = self.runtime / trust.MARKER
        self.config = self.home / ".claude" / preferences.CONFIG
        self.value = {"schema": 1, "enabled": True,
                      "projects": [{"id": "vv", "path": str(self.root)}]}

    def write(self, path, value, mode=0o600):
        path.write_text(json.dumps(value))
        path.chmod(mode)

    def read(self, path):
        return json.loads(path.read_text())

    def enable(self):
        self.write(self.marker, self.value)

    def test_absent_or_disabled_marker_does_not_create_config(self):
        self.assertFalse(trust.prepare(self.project))
        self.write(self.marker, {"schema": 1, "enabled": False})
        self.assertFalse(trust.prepare(self.project))
        self.assertFalse(self.config.exists())

    def test_unlisted_project_is_untouched(self):
        for entries in ([], [{"id": "other", "path": str(self.base / "projects/other")} ]):
            with self.subTest(entries=entries):
                self.write(self.marker, {**self.value, "projects": entries})
                self.config.write_text("invalid, intentionally never read")
                self.config.chmod(0o600)
                self.assertFalse(trust.prepare(self.project))
                self.assertEqual(self.config.read_text(), "invalid, intentionally never read")

    def test_initializes_only_exact_root_trust_boolean(self):
        self.enable()
        self.assertTrue(trust.prepare(self.project))
        self.assertEqual(self.read(self.config), {"projects": {
            str(self.root): {"hasTrustDialogAccepted": True}}})
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertFalse(trust.prepare(self.project))
        self.assertFalse((self.home / ".claude/settings.json").exists())

    def test_preserves_every_other_existing_field(self):
        self.enable()
        original = {"numStartups": 3, "oauthAccount": {"synthetic": "unchanged"},
                    "projects": {str(self.root): {"allowedTools": ["keep"], "history": [1]},
                                 "/other": {"hasTrustDialogAccepted": False}},
                    "hasCompletedOnboarding": True}
        self.write(self.config, original)
        self.assertTrue(trust.prepare(self.project))
        expected = json.loads(json.dumps(original))
        expected["projects"][str(self.root)]["hasTrustDialogAccepted"] = True
        self.assertEqual(self.read(self.config), expected)

    def test_explicit_true_and_false_are_never_overridden(self):
        self.enable()
        for value in (True, False):
            with self.subTest(value=value):
                self.write(self.config, {"projects": {str(self.root): {"hasTrustDialogAccepted": value}}})
                original = self.config.read_bytes()
                self.assertFalse(trust.prepare(self.project))
                self.assertEqual(self.config.read_bytes(), original)

    def test_worktree_uses_main_root_key_without_importing_main_auth_or_sessions(self):
        self.enable()
        self.write(self.config, {"oauthAccount": {"synthetic": "not-to-copy"}, "history": ["old"]})
        credentials = self.home / ".claude/.credentials.json"
        credentials.write_text("synthetic credentials not read")
        root = self.base.parent / "orca/workspaces/vv/fresh"
        root.mkdir(parents=True)
        admin = self.root / ".git/worktrees/fresh"
        admin.mkdir(parents=True)
        home = self.base / ".runtime/vv/worktrees" / ("a" * 64) / "home"
        (home / ".claude").mkdir(parents=True, mode=0o700)
        project = isolation.Project("vv", root, home, isolation.LinkedWorktree(self.root, admin))
        self.assertTrue(trust.prepare(project))
        self.assertEqual(self.read(home / ".claude/.claude.json"), {"projects": {
            str(self.root): {"hasTrustDialogAccepted": True}}})
        self.assertNotIn(str(root), self.read(home / ".claude/.claude.json")["projects"])
        self.assertFalse((home / ".claude/.credentials.json").exists())
        self.assertEqual(self.read(self.config)["history"], ["old"])

    def test_marker_rejects_bad_schema_extra_fields_ids_and_paths(self):
        bad = [{}, {**self.value, "schema": True}, {**self.value, "enabled": 1},
               {**self.value, "extra": "ignored?"}, {"schema": 1, "enabled": False, "projects": []},
               {**self.value, "projects": {}}, {**self.value, "projects": [None]}]
        for entry in ({"id": "vv", "path": str(self.root), "extra": True},
                      {"id": "vv", "path": str(self.root.parent)},
                      {"id": "vv", "path": str(self.root) + "/"},
                      {"id": "vv", "path": str(self.root.parent / "x/../vv")},
                      {"id": "vv", "path": "projects/vv"},
                      {"id": "*", "path": str(self.root)},
                      {"id": "../vv", "path": str(self.root)},
                      {"id": "VV", "path": str(self.root)},
                      {"id": 7, "path": str(self.root)},
                      {"id": "vv", "path": None}):
            bad.append({**self.value, "projects": [entry]})
        bad.append({**self.value, "projects": self.value["projects"] * 2})
        for value in bad:
            with self.subTest(value=value):
                self.write(self.marker, value)
                with self.assertRaises(core.Blocked) as result:
                    trust.prepare(self.project)
                self.assertEqual(str(result.exception), trust._ERROR)
                self.assertFalse(self.config.exists())

    def test_generic_safe_project_ids_are_supported(self):
        root = self.base / "projects/new-project-2"
        home = self.base / ".runtime/new-project-2/home"
        root.mkdir()
        (home / ".claude").mkdir(parents=True, mode=0o700)
        project = isolation.Project("new-project-2", root, home)
        self.write(self.marker, {**self.value, "projects": [{"id": project.name, "path": str(root)}]})
        self.assertTrue(trust.prepare(project))

    def test_symlinked_allowed_root_is_rejected(self):
        other = self.root.with_name("saved")
        self.root.rename(other)
        self.root.symlink_to(other, target_is_directory=True)
        self.enable()
        with self.assertRaises(core.Blocked):
            trust.prepare(self.project)

    def test_unsafe_marker_permissions_foreign_owner_and_directory_are_rejected(self):
        self.enable()
        self.marker.chmod(0o644)
        with self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.marker.chmod(0o600)
        with patch.object(preferences.os, "getuid", return_value=os.getuid() + 1), self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.runtime.chmod(0o777)
        with self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.assertFalse(self.config.exists())

    def test_marker_and_config_symlinks_hardlinks_rejected(self):
        for path, value in ((self.marker, self.value), (self.config, {"keep": 1})):
            target = path.parent / "target.json"
            self.write(target, value)
            if path == self.config:
                self.enable()
            for kind in ("symlink", "hardlink"):
                with self.subTest(path=path.name, kind=kind):
                    if kind == "symlink":
                        path.symlink_to(target)
                    else:
                        os.link(target, path)
                    original = target.read_bytes()
                    with self.assertRaises(core.Blocked):
                        trust.prepare(self.project)
                    self.assertEqual(target.read_bytes(), original)
                    path.unlink()
            target.unlink()

    def test_lock_symlink_and_hardlink_are_rejected(self):
        self.enable()
        target = self.runtime / "outside.lock"
        target.write_text("")
        target.chmod(0o600)
        lock = self.runtime / preferences.LOCK
        for kind in ("symlink", "hardlink"):
            if kind == "symlink":
                lock.symlink_to(target)
            else:
                os.link(target, lock)
            with self.assertRaises(core.Blocked):
                trust.prepare(self.project)
            lock.unlink()

    def test_malformed_and_duplicate_marker_never_change_config(self):
        self.write(self.config, {"keep": True})
        original = self.config.read_bytes()
        for raw in (b'{broken', b'{"schema":1,"schema":1,"enabled":false}', b'null',
                    b' ' * (trust.MAX_MARKER + 1),
                    ('{"deep":' + '[' * 1500 + '0' + ']' * 1500 + '}').encode()):
            with self.subTest(size=len(raw)):
                self.marker.write_bytes(raw)
                self.marker.chmod(0o600)
                with self.assertRaises(core.Blocked):
                    trust.prepare(self.project)
                self.assertEqual(self.config.read_bytes(), original)

    def test_malformed_native_config_is_preserved(self):
        self.enable()
        bad = [b'{broken', b'null', b'{"projects":{},"projects":{}}',
               b' ' * (preferences.MAX_CONFIG + 1)]
        for value in ({"projects": None}, {"projects": []}, {"projects": {str(self.root): []}},
                      {"projects": {str(self.root): {"hasTrustDialogAccepted": "true"}}},
                      {"projects": {str(self.root): {"hasTrustDialogAccepted": 1}}}):
            bad.append(json.dumps(value).encode())
        for raw in bad:
            self.config.write_bytes(raw)
            self.config.chmod(0o600)
            with self.assertRaises(core.Blocked):
                trust.prepare(self.project)
            self.assertEqual(self.config.read_bytes(), raw)

    def test_existing_config_must_be_private(self):
        self.enable()
        self.write(self.config, {"keep": 1}, 0o644)
        with self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.assertEqual(self.read(self.config), {"keep": 1})

    def test_atomic_replace_failure_does_not_truncate_original(self):
        self.enable()
        self.write(self.config, {"keep": True})
        original = self.config.read_bytes()
        with patch.object(preferences.os, "replace", side_effect=OSError("synthetic")), self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(list(self.config.parent.glob(".surge-cc-preferences-*.tmp")), [])

    def test_marker_revocation_race_stops_before_config_write(self):
        self.enable()
        unchanged = preferences._unchanged
        def revoke(directory, name, state):
            if name == trust.MARKER:
                self.write(self.marker, {"schema": 1, "enabled": False})
            return unchanged(directory, name, state)
        with patch.object(preferences, "_unchanged", side_effect=revoke), self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.assertFalse(self.config.exists())

    def test_native_write_race_preserves_native_update(self):
        self.enable()
        self.write(self.config, {"keep": "before"})
        unchanged = preferences._unchanged
        def update(directory, name, state):
            if name == preferences.CONFIG:
                self.write(self.config, {"keep": "native update"})
            return unchanged(directory, name, state)
        with patch.object(preferences, "_unchanged", side_effect=update), self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.assertEqual(self.read(self.config), {"keep": "native update"})
        self.assertEqual(list(self.config.parent.glob(".surge-cc-preferences-*.tmp")), [])

    def test_marker_replaced_while_reading_is_rejected(self):
        self.enable()
        original_read = preferences.os.read
        replaced = False
        def replacing_read(fd, length):
            nonlocal replaced
            result = original_read(fd, length)
            if result and not replaced:
                replaced = True
                replacement = self.marker.with_suffix(".next")
                self.write(replacement, self.value)
                replacement.replace(self.marker)
            return result
        with patch.object(preferences.os, "read", side_effect=replacing_read), self.assertRaises(core.Blocked):
            trust.prepare(self.project)
        self.assertFalse(self.config.exists())

    def test_concurrent_launchers_seed_once(self):
        self.enable()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: trust.prepare(self.project), range(4)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(self.read(self.config), {"projects": {
            str(self.root): {"hasTrustDialogAccepted": True}}})


if __name__ == "__main__":
    unittest.main()
