"""Account-scope authentication tests using synthetic credentials only."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from surge_cc import core, keychain_auth as auth, isolation, isolated_auth, isolated_preferences


class WorkspaceAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = self.root / 'config.json'
        self.config.write_text(json.dumps({'workspace': 'A'}))
        self.config.chmod(0o600)
        self.token = 'sk-ant-oat01-' + 'synthetic-only_' * 5
        self.legacy = {'enabled': True, 'service': auth.SERVICE,
                       'account': auth._identity().pw_name}
        self.terminal = self.root / 'terminal'

    def legacy_marker(self):
        self.terminal.mkdir(mode=0o700)
        (self.terminal / auth.MARKER).write_text(json.dumps(self.legacy))
        (self.terminal / auth.MARKER).chmod(0o600)

    def test_missing_workspace_never_falls_back_to_legacy_marker(self):
        self.legacy_marker()
        with patch.object(auth, 'read_token') as read:
            self.assertIsNone(auth.load(self.config, 'A'))
            self.assertIsNone(auth.load(self.config, 'B'))
            read.assert_not_called()
        self.assertFalse((self.root / 'workspaces').exists())

    def test_migration_preserves_A_reference_and_B_is_empty(self):
        self.legacy_marker()
        before = (self.terminal / auth.MARKER).read_bytes()
        with patch.object(auth.subprocess, 'run') as read:
            self.assertTrue(auth.migrate_legacy(self.config, 'A'))
            self.assertFalse(auth.migrate_legacy(self.config, 'B'))
            reference = auth.load(self.config, 'A')
            self.assertEqual(reference['service'], auth.SERVICE)
            self.assertEqual(reference['account'], self.legacy['account'])
            self.assertTrue(reference['legacy'])
            self.assertIsNone(auth.load(self.config, 'B'))
            self.assertEqual(auth.legacy_workspace(self.config), 'A')
            self.assertEqual((self.terminal / auth.MARKER).read_bytes(), before)
            read.assert_not_called()

    def test_legacy_owner_is_selected_workspace_not_hardcoded_A(self):
        self.legacy_marker()
        auth.migrate_legacy(self.config, 'B')
        self.assertIsNotNone(auth.load(self.config, 'B'))
        self.assertIsNone(auth.load(self.config, 'A'))
        self.assertEqual(auth.legacy_workspace(self.config), 'B')

    def test_completed_migration_does_not_reopen_modified_legacy_marker(self):
        self.legacy_marker()
        auth.migrate_legacy(self.config, 'A')
        (self.terminal / auth.MARKER).write_text('broken')
        self.assertFalse(auth.migrate_legacy(self.config, 'B'))
        self.assertIsNotNone(auth.load(self.config, 'A'))

    def test_partial_migration_retries_only_recorded_owner(self):
        self.legacy_marker()
        self.terminal.joinpath(auth.MIGRATION).write_text(json.dumps({
            'schema': 1, 'workspace': 'A', 'legacy_marker_present': True}))
        self.terminal.joinpath(auth.MIGRATION).chmod(0o600)
        auth.migrate_legacy(self.config, 'B')
        self.assertIsNotNone(auth.load(self.config, 'A'))
        self.assertIsNone(auth.load(self.config, 'B'))

    def test_native_oauth_upgrade_preserves_existing_keychain_namespace_path(self):
        old_store = self.root / "workspaces/A/data/Claude"
        old_store.mkdir(parents=True, mode=0o700)
        # Ancestors created by pathlib use default mode, matching normal owned
        # folders; make account data roots private as the application does.
        for folder in (old_store.parent, old_store.parent.parent, old_store.parent.parent.parent):
            folder.chmod(0o700)
        before = old_store / ".credentials.json"
        before.write_text('{"synthetic":true}'); before.chmod(0o600)
        with patch.object(auth.subprocess, "run") as run:
            auth.migrate_legacy(self.config, "A")
            self.assertEqual(auth.auth_directory(self.config, "A"), old_store)
            self.assertEqual(auth.auth_directory(self.config, "B"), self.root / "workspaces/B/data/Auth")
            run.assert_not_called()
        self.assertEqual(before.read_text(), '{"synthetic":true}')

    def test_no_legacy_marker_creates_no_token_reference(self):
        auth.migrate_legacy(self.config, 'A')
        self.assertIsNone(auth.load(self.config, 'A'))
        self.assertEqual(auth.status(self.config, 'A')['mode'], 'oauth')
        self.assertTrue(auth.status(self.config, 'A')['configured'])
        self.assertFalse(auth.status(self.config, 'B')['configured'])

    def test_A_and_B_tokens_get_distinct_keychain_items_not_written_to_disk(self):
        with patch.object(auth, '_write_native_token') as write:
            self.assertEqual(auth.store_token(self.config, 'A', self.token)['mode'], 'token')
            self.assertEqual(auth.store_token(self.config, 'B', self.token)['mode'], 'token')
            self.assertEqual(write.call_count, 2)
            self.assertNotEqual(write.call_args_list[0].args[1], write.call_args_list[1].args[1])
        for path in self.root.rglob('*'):
            if path.is_file():
                self.assertNotIn(self.token, path.read_text())
        a, b = auth.load(self.config, 'A'), auth.load(self.config, 'B')
        self.assertNotEqual(a['account'], b['account'])
        with patch.object(auth.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, self.token.encode(), b'')
            self.assertEqual(auth.read_token(b), self.token)
            self.assertIn(b['account'], run.call_args.args[0])
            self.assertNotIn(a['account'], run.call_args.args[0])
            self.assertIn(auth.WORKSPACE_SERVICE, run.call_args.args[0])

    def test_switch_to_oauth_preserves_A_and_does_not_delete_keychain(self):
        with patch.object(auth, '_write_native_token'):
            auth.store_token(self.config, 'A', self.token)
            auth.store_token(self.config, 'B', self.token)
        before = auth.load(self.config, 'A')
        with patch.object(auth.subprocess, 'run') as run:
            status = auth.configure_oauth(self.config, 'B')
            run.assert_not_called()
        self.assertEqual(status['mode'], 'oauth')
        self.assertIsNone(auth.load(self.config, 'B'))
        self.assertEqual(auth.load(self.config, 'A'), before)

    def test_copied_workspace_reference_fails_closed(self):
        with patch.object(auth, '_write_native_token'):
            auth.store_token(self.config, 'A', self.token)
        auth.configure_oauth(self.config, 'B')
        a = self.root / 'workspaces/A' / auth.MARKER
        b = self.root / 'workspaces/B' / auth.MARKER
        b.write_bytes(a.read_bytes())
        with self.assertRaises(core.Blocked):
            auth.load(self.config, 'B')
        forged = json.loads(a.read_text()); forged['workspace'] = 'B'
        b.write_text(json.dumps(forged))
        with self.assertRaises(core.Blocked):
            auth.load(self.config, 'B')

    def test_legacy_reference_cannot_be_attached_to_B(self):
        self.legacy_marker()
        auth.migrate_legacy(self.config, 'A')
        auth.configure_oauth(self.config, 'B')
        forged = auth.load(self.config, 'A'); forged['workspace'] = 'B'
        (self.root / 'workspaces/B' / auth.MARKER).write_text(json.dumps(forged))
        with self.assertRaises(core.Blocked):
            auth.load(self.config, 'B')

    def test_native_storage_paths_are_account_specific_and_private(self):
        a, b = auth.auth_directory(self.config, 'A'), auth.auth_directory(self.config, 'B')
        self.assertNotEqual(a, b)
        self.assertEqual(a, self.root / 'workspaces/A/data/Auth')
        self.assertEqual(a.stat().st_mode & 0o777, 0o700)
        a.rmdir(); a.symlink_to(b)
        with self.assertRaises(core.Blocked):
            auth.auth_directory(self.config, 'A')

    def test_native_credential_and_lock_aliases_fail_closed(self):
        store = auth.auth_directory(self.config, "B")
        outside = self.root / "outside"; outside.write_text("synthetic")
        credentials = store / ".credentials.json"; credentials.symlink_to(outside)
        with self.assertRaises(core.Blocked):
            auth.auth_directory(self.config, "B")
        credentials.unlink()
        native_lock = store.with_name(store.name + ".lock")
        native_lock.symlink_to(self.root)
        with self.assertRaises(core.Blocked):
            auth.auth_directory(self.config, "B")

    def test_malformed_or_unsafe_workspace_markers_fail_closed(self):
        auth.configure_oauth(self.config, 'B')
        marker = self.root / 'workspaces/B' / auth.MARKER
        for content in ('broken', '{}', '[]', '{"schema":2,"schema":2}'):
            marker.write_text(content)
            with self.assertRaises(core.Blocked):
                auth.load(self.config, 'B')
        marker.write_text(json.dumps({'schema': 2, 'workspace': 'B', 'enabled': False}))
        marker.chmod(0o644)
        with self.assertRaises(core.Blocked):
            auth.load(self.config, 'B')

    def test_error_does_not_disclose_token(self):
        with patch.object(auth, '_write_native_token', side_effect=RuntimeError(self.token)):
            with self.assertRaises(core.Blocked) as caught:
                auth.store_token(self.config, 'A', self.token)
        self.assertNotIn(self.token, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(auth.load(self.config, 'A'))

    def test_invalid_token_never_touches_native_keychain(self):
        with patch.object(auth, '_write_native_token') as write:
            for value in ('secret', self.token + '\n', self.token + ' ', None):
                with self.assertRaises(core.Blocked):
                    auth.store_token(self.config, 'A', value)
            write.assert_not_called()

    def test_native_store_uses_framework_and_clears_mutable_secret_buffer(self):
        sec, cf = Mock(), Mock()
        sec.SecKeychainFindGenericPassword.return_value = -25300
        captured = []
        def add(*args):
            captured.append(ctypes.string_at(args[6], args[5]).decode("ascii"))
            return 0
        sec.SecKeychainAddGenericPassword.side_effect = add
        with patch.object(auth.ctypes, "CDLL", side_effect=[sec, cf]) as libraries, \
             patch.object(auth.subprocess, "run") as subprocess_run:
            auth._write_native_token(auth.WORKSPACE_SERVICE, "synthetic", self.token)
            subprocess_run.assert_not_called()
        self.assertEqual(captured, [self.token])
        self.assertEqual(libraries.call_args_list[0].args, ("/System/Library/Frameworks/Security.framework/Security",))
        args = sec.SecKeychainAddGenericPassword.call_args.args
        self.assertEqual(ctypes.string_at(args[6], args[5]), b"\0" * len(self.token))
        cf.CFRelease.assert_not_called()

    def test_native_update_uses_existing_item_and_releases_reference(self):
        sec, cf = Mock(), Mock()
        def find(*args):
            ctypes.cast(args[7], ctypes.POINTER(ctypes.c_void_p)).contents.value = 123
            return 0
        sec.SecKeychainFindGenericPassword.side_effect = find
        sec.SecKeychainItemModifyAttributesAndData.return_value = 0
        with patch.object(auth.ctypes, "CDLL", side_effect=[sec, cf]):
            auth._write_native_token(auth.WORKSPACE_SERVICE, "synthetic", self.token)
        sec.SecKeychainAddGenericPassword.assert_not_called()
        self.assertEqual(sec.SecKeychainItemModifyAttributesAndData.call_args.args[0].value, 123)
        self.assertEqual(cf.CFRelease.call_args.args[0].value, 123)



class WorkspaceIsolatedAuthTests(unittest.TestCase):
    def setUp(self):
        WorkspaceAuthTests.setUp(self)
        self.base = self.root / 'isolated'
        self.project_root = self.base / 'projects/example'
        self.home = self.base / '.runtime/example/home'
        self.project_root.mkdir(parents=True, mode=0o700)
        (self.home / '.claude').mkdir(parents=True, mode=0o700)
        self.home.chmod(0o700)
        self.project = isolation.Project('example', self.project_root, self.home)
        auth.migrate_legacy(self.config, 'A')
        self.a = isolation.bind_workspace(self.project, self.config, 'A')
        self.b = isolation.bind_workspace(self.project, self.config, 'B')
        self.native = self.root / 'native'; self.native.write_text('synthetic')
        self.native.chmod(0o700)
        self.hook = Path('/private/tmp/surge-cc-oauth-account-test/browser')

    # Separate from inherited auth tests; these cases exercise project binding.
    def test_project_A_keeps_history_B_gets_fresh_HOME(self):
        self.assertEqual(self.a.home, self.project.home)
        self.assertEqual(self.b.home, self.home.parent / 'accounts/B/home')
        self.assertNotEqual(self.a.config, self.b.config)
        self.assertFalse(self.b.home.exists())

    def test_environment_uses_workspace_auth_not_legacy_shared_auth(self):
        legacy = self.base / '.runtime/auth'
        legacy.mkdir(mode=0o700)
        (legacy / 'enabled.json').write_text('corrupt old shared state')
        a = isolation.environment(self.a, 'http://127.0.0.1:62919', {})
        b = isolation.environment(self.b, 'http://127.0.0.1:62919', {})
        self.assertNotEqual(a['CLAUDE_SECURESTORAGE_CONFIG_DIR'], b['CLAUDE_SECURESTORAGE_CONFIG_DIR'])
        self.assertEqual(a['CLAUDE_SECURESTORAGE_CONFIG_DIR'], str(auth.auth_directory(self.config, 'A')))
        self.assertNotEqual(a['HOME'], b['HOME'])
        self.assertNotEqual(a['CLAUDE_CONFIG_DIR'], b['CLAUDE_CONFIG_DIR'])

    def test_bound_policy_grants_only_own_auth_and_denies_old_project_fallback(self):
        policy = isolation.profile(self.b, self.native, self.hook)
        self.assertIn('(subpath ' + json.dumps(str(auth.auth_directory(self.config, 'B'))) + ')', policy)
        self.assertNotIn('(subpath ' + json.dumps(str(auth.auth_directory(self.config, 'A'))) + ')', policy)
        self.assertIn('(deny file-read* file-write* (subpath ' + json.dumps(str(self.b.config / '.credentials.json')) + '))', policy)
        self.assertNotIn('(subpath ' + json.dumps(str(self.a.home)) + ')', policy)

    def test_scoped_HOME_command_supports_preference_and_trust_validation(self):
        with patch.object(isolation.SANDBOX.__class__, 'is_file', return_value=True):
            command = isolation.command(self.b, self.native, [], self.hook)
        self.assertTrue(self.b.home.is_dir())
        self.assertTrue(self.b.config.is_dir())
        self.assertIn(str(self.b.home), command[2])
        with isolated_preferences._scope(self.b):
            pass

    def test_bound_project_never_rebinds_to_other_account(self):
        with self.assertRaises(core.Blocked):
            isolation.bind_workspace(self.a, self.config, 'B')

    def test_B_linked_worktree_home_is_separate_without_changing_git_scope(self):
        work_root = self.root / "orca/workspaces/example/task"
        work_root.mkdir(parents=True)
        git = self.project_root / ".git/worktrees/task"
        git.mkdir(parents=True)
        linkage = isolation.LinkedWorktree(self.project_root, git)
        home = isolation._worktree_home(self.base, "example", work_root, git)
        project = isolation.Project("example", work_root, home, linkage)
        a = isolation.bind_workspace(project, self.config, "A")
        b = isolation.bind_workspace(project, self.config, "B")
        self.assertEqual(a.home, home)
        self.assertEqual(b.home, home.parent / "accounts/B/home")
        self.assertEqual(b.worktree, linkage)
        self.assertEqual(b.root, a.root)

    def test_account_HOME_symlink_fails_before_create(self):
        accounts = self.home.parent / "accounts"
        accounts.symlink_to(self.root)
        with self.assertRaises(core.Blocked):
            isolation.bind_workspace(self.project, self.config, "B")

    def test_token_auth_never_prepares_oauth_storage(self):
        with patch.object(isolated_auth, 'prepare') as prepare:
            env = isolation.environment(self.b, 'http://127.0.0.1:62919', {}, token_auth=True)
            isolation.profile(self.b, self.native, self.hook, token_auth=True)
            prepare.assert_not_called()
        self.assertEqual(env['CLAUDE_SECURESTORAGE_CONFIG_DIR'], str(self.b.home / '.token-auth-disabled'))


if __name__ == '__main__':
    unittest.main()
