"""Offline UI-preference migration tests; no real credentials or Claude calls."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, isolated_preferences as preferences, isolation


class PreferenceTests(unittest.TestCase):
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
        self.template = self.runtime / preferences.TEMPLATE
        self.config = self.home / ".claude" / preferences.CONFIG
        self.settings = self.home / ".claude" / preferences.SETTINGS
        self.value = {"schema": 1, "hasCompletedOnboarding": True,
                      "lastOnboardingVersion": "2.1.296", "theme": "dark"}

    def write(self, path, value, mode=0o600):
        path.write_text(json.dumps(value))
        path.chmod(mode)

    def read(self, path):
        return json.loads(path.read_text())

    def completed(self):
        self.write(self.config, {"hasCompletedOnboarding": True,
                                 "lastOnboardingVersion": "2.1.296"})
        self.write(self.settings, {"theme": "dark"}, 0o644)

    def test_no_template_does_not_fabricate_completion(self):
        self.assertFalse(preferences.prepare(self.project))
        self.assertFalse(self.config.exists())
        self.assertFalse(self.settings.exists())
        self.assertIsNone(preferences.theme(self.project))

    def test_record_copies_only_preference_allowlist(self):
        self.write(self.config, {"hasCompletedOnboarding": True,
                                 "lastOnboardingVersion": "2.1.296",
                                 "oauthAccount": {"token": "synthetic-never-copy"},
                                 "userID": "synthetic-user", "machineID": "synthetic-machine",
                                 "projects": {"old": {"hasTrustDialogAccepted": True}},
                                 "cachedGrowthBookFeatures": {"not-a-preference": True}})
        self.write(self.settings, {"theme": "dark", "env": {"TOKEN": "synthetic"},
                                   "hooks": {"never": "copy"}}, 0o644)
        credentials = self.home / ".claude/.credentials.json"
        credentials.write_bytes(b"deliberately-not-json-never-read")
        old_config = self.config.read_bytes()
        self.assertTrue(preferences.record(self.project))
        self.assertEqual(self.read(self.template), self.value)
        self.assertEqual(self.config.read_bytes(), old_config)
        self.assertEqual(credentials.read_bytes(), b"deliberately-not-json-never-read")
        self.assertEqual(self.template.stat().st_mode & 0o777, 0o600)
        self.assertFalse(preferences.record(self.project))

    def test_incomplete_onboarding_does_not_create_template(self):
        for completion in (False, None, "true", 1):
            with self.subTest(completion=completion):
                self.write(self.config, {"hasCompletedOnboarding": completion})
                self.write(self.settings, {"theme": "dark"})
                self.assertFalse(preferences.record(self.project))
                self.assertFalse(self.template.exists())

    def test_invalid_source_cannot_create_or_replace_template(self):
        self.config.write_text('{broken')
        self.config.chmod(0o600)
        with self.assertRaises(core.Blocked):
            preferences.record(self.project)
        self.assertFalse(self.template.exists())
        self.write(self.template, self.value)
        original = self.template.read_bytes()
        with self.assertRaises(core.Blocked):
            preferences.record(self.project)
        self.assertEqual(self.template.read_bytes(), original)
        self.completed()
        self.config.chmod(0o666)
        with self.assertRaises(core.Blocked):
            preferences.record(self.project)
        self.assertEqual(self.template.read_bytes(), original)

    def test_deeply_nested_json_is_blocked_by_all_public_apis(self):
        nested = '{"unrelated":' + '[' * 1500 + '0' + ']' * 1500 + '}'
        self.write(self.template, self.value)
        for operation, path in ((preferences.prepare, self.config),
                                (preferences.record, self.config),
                                (preferences.theme, self.settings)):
            with self.subTest(operation=operation.__name__):
                path.write_text(nested)
                path.chmod(0o600)
                original_template = self.template.read_bytes()
                with self.assertRaises(core.Blocked):
                    operation(self.project)
                self.assertEqual(path.read_text(), nested)
                self.assertEqual(self.template.read_bytes(), original_template)
                path.unlink()

    def test_prepare_initializes_only_new_home_preferences(self):
        self.write(self.template, self.value)
        self.assertTrue(preferences.prepare(self.project))
        self.assertEqual(self.read(self.config), {"hasCompletedOnboarding": True,
                                                 "lastOnboardingVersion": "2.1.296"})
        self.assertEqual(self.read(self.settings), {"theme": "dark"})
        self.assertFalse(preferences.prepare(self.project))
        self.assertEqual(preferences.theme(self.project), "dark")
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_prepare_preserves_existing_config_account_and_trust_exactly(self):
        self.write(self.template, self.value)
        existing = {"numStartups": 8, "projects": {"current": {"hasTrustDialogAccepted": False}},
                    "oauthAccount": {"synthetic": "untouched"}}
        self.write(self.config, existing)
        settings = {"theme": "light", "unrelated": ["keep"]}
        self.write(self.settings, settings)
        self.assertTrue(preferences.prepare(self.project))
        result = self.read(self.config)
        self.assertEqual({k: result[k] for k in existing}, existing)
        self.assertEqual(set(result) - set(existing), {"hasCompletedOnboarding", "lastOnboardingVersion"})
        self.assertEqual(self.read(self.settings), settings)
        self.assertEqual(preferences.theme(self.project), "light")

    def test_explicit_incomplete_flag_and_existing_version_are_not_overwritten(self):
        self.write(self.template, self.value)
        current = {"hasCompletedOnboarding": False, "lastOnboardingVersion": "2.0.0"}
        self.write(self.config, current)
        preferences.prepare(self.project)
        self.assertEqual(self.read(self.config), current)

    def test_unsupported_source_values_are_not_copied(self):
        self.write(self.config, {"hasCompletedOnboarding": True,
                                 "lastOnboardingVersion": "../../anything"})
        self.write(self.settings, {"theme": "dark; execute this"})
        preferences.record(self.project)
        self.assertEqual(self.read(self.template), {"schema": 1, "hasCompletedOnboarding": True})
        self.assertIsNone(preferences.theme(self.project))

    def test_invalid_template_schema_extra_fields_and_values_fail_closed(self):
        bad = [{**self.value, "oauthAccount": {}}, {**self.value, "schema": True},
               {**self.value, "hasCompletedOnboarding": 1}, {**self.value, "theme": []},
               {**self.value, "theme": "Dark mode"},
               {**self.value, "lastOnboardingVersion": "2.1.296\n"},
               {**self.value, "lastOnboardingVersion": "v2.1.296"}]
        for value in bad:
            with self.subTest(value=value):
                self.write(self.template, value)
                with self.assertRaises(core.Blocked):
                    preferences.prepare(self.project)
                self.assertFalse(self.config.exists())

    def test_symlink_or_hardlink_template_is_rejected(self):
        target = self.runtime / "other.json"
        self.write(target, self.value)
        for link in (lambda: self.template.symlink_to(target), lambda: os.link(target, self.template)):
            link()
            with self.assertRaises(core.Blocked):
                preferences.prepare(self.project)
            self.assertFalse(self.config.exists())
            self.template.unlink()

    def test_current_config_and_settings_aliases_are_rejected_without_write(self):
        self.write(self.template, self.value)
        for path in (self.config, self.settings):
            target = self.home / "outside.json"
            self.write(target, {"valuable": True})
            original = target.read_bytes()
            for link in (lambda: path.symlink_to(target), lambda: os.link(target, path)):
                link()
                with self.assertRaises(core.Blocked):
                    preferences.prepare(self.project)
                self.assertEqual(target.read_bytes(), original)
                path.unlink()
            self.assertFalse(self.config.exists())

    def test_lock_alias_is_rejected(self):
        target = self.runtime / "outside.lock"
        target.write_text("")
        target.chmod(0o600)
        lock = self.runtime / preferences.LOCK
        for link in (lambda: lock.symlink_to(target), lambda: os.link(target, lock)):
            link()
            with self.assertRaises(core.Blocked):
                preferences.prepare(self.project)
            lock.unlink()

    def test_template_must_be_private_and_current_settings_not_writable_by_others(self):
        self.write(self.template, self.value, 0o644)
        with self.assertRaises(core.Blocked):
            preferences.prepare(self.project)
        self.template.chmod(0o600)
        self.write(self.settings, {"theme": "light"}, 0o666)
        with self.assertRaises(core.Blocked):
            preferences.prepare(self.project)
        self.assertFalse(self.config.exists())

    def test_foreign_owner_and_unsafe_directories_are_rejected(self):
        self.write(self.template, self.value)
        with patch.object(preferences.os, "getuid", return_value=os.getuid() + 10), self.assertRaises(core.Blocked):
            preferences.prepare(self.project)
        self.runtime.chmod(0o777)
        with self.assertRaises(core.Blocked):
            preferences.prepare(self.project)

    def test_home_directory_alias_is_rejected(self):
        old = self.home.with_name("saved-home")
        self.home.rename(old)
        self.home.symlink_to(old, target_is_directory=True)
        with self.assertRaises(core.Blocked):
            preferences.prepare(self.project)

    def test_malformed_or_oversized_sources_are_not_repaired_destructively(self):
        self.write(self.template, self.value)
        for raw in (b'{broken', b'{"theme":"dark","theme":"light"}', b'null', b' ' * (preferences.MAX_CONFIG + 1)):
            with self.subTest(size=len(raw)):
                self.config.write_bytes(raw)
                self.config.chmod(0o600)
                with self.assertRaises(core.Blocked):
                    preferences.prepare(self.project)
                self.assertEqual(self.config.read_bytes(), raw)

    def test_atomic_replace_failure_keeps_current_file_and_removes_temporary(self):
        self.write(self.template, self.value)
        self.write(self.config, {"keep": "original"})
        original = self.config.read_bytes()
        with patch.object(preferences.os, "replace", side_effect=OSError("synthetic write failure")), self.assertRaises(core.Blocked):
            preferences.prepare(self.project)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(list(self.config.parent.glob(".surge-cc-preferences-*.tmp")), [])

    def test_change_between_read_and_write_does_not_overwrite_native_update(self):
        self.write(self.template, self.value)
        self.write(self.config, {"keep": "initial"})
        original_unchanged = preferences._unchanged
        injected = False

        def concurrent_change(directory, name, state):
            nonlocal injected
            if name == preferences.CONFIG and not injected:
                injected = True
                self.write(self.config, {"keep": "native update"})
            return original_unchanged(directory, name, state)

        with patch.object(preferences, "_unchanged", side_effect=concurrent_change), self.assertRaises(core.Blocked):
            preferences.prepare(self.project)
        self.assertEqual(self.read(self.config), {"keep": "native update"})

    def test_concurrent_launchers_serialize_initialization(self):
        self.write(self.template, self.value)
        barrier = threading.Barrier(6)

        def launch(_):
            barrier.wait(timeout=10)
            return preferences.prepare(self.project)

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(launch, range(6)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(self.read(self.config)["hasCompletedOnboarding"], True)
        self.assertEqual(self.read(self.settings), {"theme": "dark"})

    def test_new_worktree_receives_preferences_but_not_existing_sessions_or_trust(self):
        self.completed()
        self.write(self.config, {**self.read(self.config), "projects": {"old": {"hasTrustDialogAccepted": True}}})
        preferences.record(self.project)
        new_home = self.runtime / "vv/worktrees" / ("a" * 64) / "home"
        (new_home / ".claude").mkdir(parents=True, mode=0o700)
        new_project = isolation.Project("vv", self.root, new_home)
        self.assertTrue(preferences.prepare(new_project))
        data = self.read(new_home / ".claude/.claude.json")
        self.assertNotIn("projects", data)
        self.assertEqual(set(data), {"hasCompletedOnboarding", "lastOnboardingVersion"})
        self.assertFalse((new_home / ".claude/.credentials.json").exists())
        self.assertFalse((new_home / ".claude/projects").exists())


if __name__ == "__main__":
    unittest.main()
