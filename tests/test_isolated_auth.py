"""Synthetic auth-only sharing tests. Never read production account files."""
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
from surge_cc import core, isolated_auth as auth, isolation


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve() / "isolated"
        self.root = self.base / "projects/vv"
        self.home = self.base / ".runtime/vv/worktrees" / ("a" * 64) / "home"
        self.root.mkdir(parents=True, mode=0o700)
        (self.home / ".claude").mkdir(parents=True, mode=0o700)
        self.home.chmod(0o700)
        self.project = isolation.Project("vv", self.root, self.home)
        self.auth_root = self.base / ".runtime/auth"
        self.store = self.auth_root / auth.STORE
        self.target = self.store / auth.CREDENTIALS
        self.marker = self.auth_root / auth.MARKER
        self.source = self.home / ".claude" / auth.CREDENTIALS
        self.oauth = {"accessToken": "synthetic-access", "refreshToken": "synthetic-refresh",
                      "expiresAt": 1, "refreshTokenExpiresAt": 2,
                      "scopes": ["user:inference", "user:profile"],
                      "subscriptionType": "pro", "rateLimitTier": "default_claude_pro"}
        self.write(self.source, {"claudeAiOauth": self.oauth})

    def write(self, path, data, mode=0o600):
        path.write_text(json.dumps(data))
        path.chmod(mode)

    def migrate(self):
        return auth.migrate(self.project, source_home=self.home, confirmed_new_isolated_home=True)

    def test_unenabled_state_preserves_original_behavior_without_creating_auth(self):
        self.assertIsNone(auth.prepare(self.project))
        self.assertEqual(auth.status(self.project), {"enabled": False, "credential_present": False})
        self.assertFalse(self.auth_root.exists())

    def test_uninitialized_runtime_does_not_block_first_launch(self):
        (self.base / ".runtime").rename(self.base / "unused-runtime")
        self.assertIsNone(auth.prepare(self.project))
        self.assertEqual(auth.status(self.project), {"enabled": False, "credential_present": False})
        self.assertFalse((self.base / ".runtime").exists())

    def test_migration_requires_explicit_confirmation(self):
        for value in (False, None, "true", 1):
            with self.subTest(value=value), self.assertRaises(core.Blocked):
                auth.migrate(self.project, source_home=self.home, confirmed_new_isolated_home=value)
        self.assertFalse(self.auth_root.exists())

    def test_migration_whitelists_oauth_and_never_modifies_source(self):
        self.write(self.source, {"claudeAiOauth": {**self.oauth, "accountUuid": "not-transferred"},
                                 "mcpOAuth": {"secret": "not-transferred"},
                                 "oauthAccount": {"email": "synthetic@example.invalid"},
                                 "userID": "not-transferred", "projects": {"old": "not-transferred"}})
        original = self.source.read_bytes()
        self.assertTrue(self.migrate())
        self.assertEqual(json.loads(self.target.read_text()), {"claudeAiOauth": self.oauth})
        self.assertEqual(json.loads(self.marker.read_text()), auth.ENABLED)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(auth.prepare(self.project), self.store)
        self.assertEqual(auth.status(self.project), {"enabled": True, "credential_present": True})
        for path in (self.marker, self.target, self.auth_root.parent / auth.LOCK):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for path in (self.auth_root, self.store):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_expired_access_token_is_not_rejected_or_refreshed_by_migration(self):
        self.assertTrue(self.migrate())
        self.assertEqual(json.loads(self.target.read_text())["claudeAiOauth"]["expiresAt"], 1)

    def test_repeated_migration_does_not_read_source_or_overwrite_refreshed_store(self):
        self.migrate()
        updated = {"claudeAiOauth": {**self.oauth, "accessToken": "synthetic-refreshed"}}
        self.write(self.target, updated)
        self.source.unlink()
        original = self.target.read_bytes()
        self.assertFalse(self.migrate())
        self.assertEqual(self.target.read_bytes(), original)

    def test_new_worktree_gets_only_shared_secure_storage_path(self):
        self.migrate()
        other_home = self.base / ".runtime/vv/worktrees" / ("b" * 64) / "home"
        (other_home / ".claude").mkdir(parents=True, mode=0o700)
        other = isolation.Project("vv", self.root, other_home)
        self.assertEqual(auth.prepare(other), self.store)
        self.assertEqual(list((other_home / ".claude").iterdir()), [])

    def test_deleted_marker_with_existing_store_never_falls_back(self):
        self.migrate()
        self.marker.unlink()
        for operation in (lambda: auth.prepare(self.project), lambda: auth.status(self.project), self.migrate):
            with self.assertRaises(core.Blocked):
                operation()

    def test_logout_keeps_shared_path_and_missing_store_fails_closed(self):
        self.migrate()
        self.target.unlink()
        self.assertEqual(auth.prepare(self.project), self.store)
        self.assertEqual(auth.status(self.project), {"enabled": True, "credential_present": False})
        self.assertFalse(self.migrate())
        self.store.rmdir()
        with self.assertRaises(core.Blocked):
            auth.prepare(self.project)
        with self.assertRaises(core.Blocked):
            self.migrate()

    def test_empty_native_logout_document_keeps_shared_storage_enabled(self):
        self.migrate()
        self.write(self.target, {})
        self.assertEqual(auth.prepare(self.project), self.store)
        self.assertEqual(auth.status(self.project), {"enabled": True, "credential_present": False})
        self.assertFalse(self.migrate())

    def test_nullable_refresh_token_from_native_storage_is_supported(self):
        self.migrate()
        self.write(self.target, {"claudeAiOauth": {**self.oauth, "refreshToken": None}})
        self.assertEqual(auth.prepare(self.project), self.store)
        self.assertEqual(auth.status(self.project), {"enabled": True, "credential_present": True})

    def test_native_store_lock_directory_is_allowed_but_aliases_are_rejected(self):
        self.migrate()
        lock = self.auth_root / (auth.STORE + ".lock")
        lock.mkdir(mode=0o755)
        self.assertEqual(auth.prepare(self.project), self.store)
        lock.chmod(0o777)
        with self.assertRaises(core.Blocked):
            auth.prepare(self.project)
        lock.rmdir()
        lock.symlink_to(self.store, target_is_directory=True)
        with self.assertRaises(core.Blocked):
            auth.prepare(self.project)

    def test_empty_unmarked_auth_directory_is_not_treated_as_disabled(self):
        self.auth_root.mkdir(mode=0o700)
        with self.assertRaises(core.Blocked):
            auth.prepare(self.project)
        with self.assertRaises(core.Blocked):
            self.migrate()

    def test_existing_unmarked_store_is_not_adopted_or_overwritten(self):
        self.store.mkdir(parents=True, mode=0o700)
        self.auth_root.chmod(0o700)
        self.write(self.target, {"claudeAiOauth": self.oauth})
        original = self.target.read_bytes()
        with self.assertRaises(core.Blocked):
            self.migrate()
        self.assertEqual(self.target.read_bytes(), original)
        self.assertFalse(self.marker.exists())

    def test_old_home_external_home_and_wrong_project_source_are_rejected(self):
        cases = [Path(self.temp.name) / ".claude", self.base.parent / "old-home",
                 self.base / ".runtime/other/home", self.base / ".runtime/auth/store"]
        for home in cases:
            with self.subTest(source=str(home)), self.assertRaises(core.Blocked):
                auth.migrate(self.project, source_home=home, confirmed_new_isolated_home=True)
        self.assertFalse(self.store.exists())

    def test_malformed_source_does_not_activate_or_expose_credentials_in_error(self):
        self.source.write_text('{"secret":"synthetic-secret-in-invalid-json"')
        with self.assertRaises(core.Blocked) as error:
            self.migrate()
        self.assertNotIn("synthetic-secret", str(error.exception))
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.store.exists())

    def test_invalid_oauth_fields_do_not_activate(self):
        cases = [{**self.oauth, "accessToken": "bad token"},
                 {**self.oauth, "refreshToken": {"nested": "secret"}},
                 {**self.oauth, "expiresAt": True},
                 {**self.oauth, "expiresAt": float("nan")},
                 {**self.oauth, "refreshTokenExpiresAt": -1},
                 {**self.oauth, "scopes": "not-a-list"},
                 {**self.oauth, "subscriptionType": ["pro"]}]
        for value in cases:
            self.write(self.source, {"claudeAiOauth": value})
            with self.assertRaises(core.Blocked):
                self.migrate()
            self.assertFalse(self.marker.exists())

    def test_shared_store_rejects_extra_mcp_or_account_fields(self):
        self.migrate()
        for value in ({"claudeAiOauth": self.oauth, "mcpOAuth": {}},
                      {"claudeAiOauth": {**self.oauth, "accountUuid": "unexpected"}}):
            self.write(self.target, value)
            with self.assertRaises(core.Blocked):
                auth.prepare(self.project)

    def test_corrupt_marker_never_acts_like_unenabled(self):
        self.migrate()
        for value in (None, {**auth.ENABLED, "schema": True}, {**auth.ENABLED, "enabled": 1},
                      {**auth.ENABLED, "storage": "../../old"}, {**auth.ENABLED, "extra": "field"}):
            self.write(self.marker, value)
            with self.assertRaises(core.Blocked):
                auth.prepare(self.project)

    def test_source_credential_symlinks_and_hardlinks_are_rejected(self):
        target = self.home / "outside-credentials"
        self.source.rename(target)
        for make in (lambda: self.source.symlink_to(target), lambda: os.link(target, self.source)):
            make()
            with self.assertRaises(core.Blocked):
                self.migrate()
            self.source.unlink()
        self.assertFalse(self.store.exists())

    def test_source_home_symlink_is_rejected(self):
        saved = self.home.with_name("saved")
        self.home.rename(saved)
        self.home.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(core.Blocked):
            self.migrate()

    def test_shared_credential_and_marker_links_are_rejected(self):
        self.migrate()
        for path in (self.target, self.marker):
            saved = path.with_name(path.name + ".saved")
            path.rename(saved)
            for make in (lambda: path.symlink_to(saved), lambda: os.link(saved, path)):
                make()
                with self.assertRaises(core.Blocked):
                    auth.prepare(self.project)
                path.unlink()
            saved.rename(path)

    def test_store_directory_symlink_is_rejected(self):
        self.migrate()
        saved = self.store.with_name("saved-store")
        self.store.rename(saved)
        self.store.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(core.Blocked):
            auth.prepare(self.project)

    def test_private_permissions_and_foreign_owners_are_enforced(self):
        self.source.chmod(0o644)
        with self.assertRaises(core.Blocked):
            self.migrate()
        self.source.chmod(0o600)
        self.migrate()
        for path, mode in ((self.marker, 0o644), (self.target, 0o644), (self.store, 0o755), (self.auth_root, 0o755)):
            original = path.stat().st_mode & 0o777
            path.chmod(mode)
            with self.assertRaises(core.Blocked):
                auth.prepare(self.project)
            path.chmod(original)
        with patch.object(auth.os, "getuid", return_value=os.getuid() + 1), self.assertRaises(core.Blocked):
            auth.prepare(self.project)

    def test_oversized_and_deep_json_is_blocked_without_activation(self):
        for value in (' ' * (auth.LIMIT + 1), '{"nested":' + '[' * 1500 + '0' + ']' * 1500 + '}'):
            self.source.write_text(value)
            with self.assertRaises(core.Blocked):
                self.migrate()
            self.assertFalse(self.marker.exists())

    def test_marker_write_failure_leaves_store_disabled_and_cannot_fallback(self):
        original_write = auth.safe._write

        def fail_marker(directory, name, data, expected):
            if name == auth.MARKER:
                raise OSError("synthetic marker failure")
            return original_write(directory, name, data, expected)

        with patch.object(auth.safe, "_write", side_effect=fail_marker), self.assertRaises(core.Blocked):
            self.migrate()
        self.assertTrue(self.target.exists())
        self.assertFalse(self.marker.exists())
        with self.assertRaises(core.Blocked):
            auth.prepare(self.project)

    def test_concurrent_migrations_cannot_overwrite_each_other(self):
        barrier = threading.Barrier(6)

        def migrate(_):
            barrier.wait(timeout=10)
            return self.migrate()

        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(migrate, range(6)))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 5)
        self.assertEqual(json.loads(self.target.read_text()), {"claudeAiOauth": self.oauth})


if __name__ == "__main__":
    unittest.main()
