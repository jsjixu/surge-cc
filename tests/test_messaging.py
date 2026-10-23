"""Synthetic-only tests for project/account-local native session IPC admission."""
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_shared_history as fixtures
from surge_cc import core, isolation, messaging


class MessagingTests(unittest.TestCase):
    # Reuse construction helpers, never inherit the transcript test suite.
    mkdir = fixtures.SharedHistoryTests.mkdir
    write = fixtures.SharedHistoryTests.write
    write_json = fixtures.SharedHistoryTests.write_json
    switch = fixtures.SharedHistoryTests.switch

    def setUp(self):
        fixtures.SharedHistoryTests.setUp(self)
        self.marker = self.runtime / messaging.MARKER
        short = tempfile.TemporaryDirectory(prefix="scc-ipc-test-", dir="/private/tmp")
        self.addCleanup(short.cleanup)
        self.ipc_root = Path(short.name).resolve() / "ipc"
        patcher = patch.object(messaging, "IPC_ROOT", self.ipc_root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def enable(self):
        self.write_json(self.marker, self.value)

    def linked(self, name):
        """Use the actual registry admission for a synthetic Orca worktree."""
        orca = self.top / "orca/workspaces"
        root = orca / "vv" / name
        self.mkdir(root)
        patcher = patch.object(isolation, "ORCA_WORKSPACES", orca)
        patcher.start()
        self.addCleanup(patcher.stop)
        admin = self.root / ".git/worktrees" / name
        self.mkdir(admin)
        self.write(root / ".git", ("gitdir: " + str(admin) + "\n").encode())
        self.write(admin / "commondir", b"../..\n")
        self.write(admin / "gitdir", (str(root / ".git") + "\n").encode())
        self.write_json(root / isolation.MARKER_NAME, {
            "schema": 1, "project": "vv", "requires_registered_launcher": True})
        discovered = isolation.for_cwd(self.config, root)
        return isolation.bind_workspace(discovered, self.config, "A")

    def other_project(self):
        root = self.base / "projects/inkclaw"
        home = self.runtime / "inkclaw/home"
        self.mkdir(root)
        self.mkdir(home / ".claude")
        registry = json.loads(self.registry.read_text())
        registry["projects"].append({"id": "inkclaw", "path": str(root), "home": str(home)})
        self.write_json(self.registry, registry)
        self.value["projects"].append({"id": "inkclaw", "path": str(root)})
        self.enable()
        return isolation.bind_workspace(isolation.Project("inkclaw", root, home), self.config, "A")

    def test_disabled_is_read_only_even_without_workspace_binding(self):
        raw = isolation.Project("vv", self.root, self.home)
        self.assertFalse(messaging.enabled(raw))
        self.assertIsNone(messaging.scope(raw))
        self.assertIsNone(messaging.prepare_scope(raw))
        self.assertIsNone(messaging.prepare(raw))
        self.assertFalse(self.ipc_root.exists())
        self.assertFalse((self.home / ".claude/sessions").exists())

    def test_missing_runtime_remains_disabled_without_creating_it(self):
        base = self.top / "unconfigured"
        root = base / "projects/vv"
        self.mkdir(root)
        project = isolation.Project("vv", root, base / ".runtime/vv/home")
        self.assertFalse(messaging.enabled(project))
        self.assertIsNone(messaging.prepare(project))
        self.assertFalse((base / ".runtime").exists())

    def test_unlisted_project_remains_untouched(self):
        self.write_json(self.marker, {"schema": 1, "projects": []})
        self.assertFalse(messaging.enabled(self.project))
        self.assertIsNone(messaging.prepare(self.project))
        self.assertFalse(self.ipc_root.exists())

    def test_marker_rejects_invalid_schema_or_scope(self):
        cases = [{}, {**self.value, "schema": True}, {**self.value, "schema": 2},
                 {**self.value, "extra": 1}, {"schema": 1, "projects": {}},
                 {"schema": 1, "projects": [None]},
                 {"schema": 1, "projects": self.value["projects"] * 2},
                 {"schema": 1, "projects": [{"id": "vv", "path": str(self.base)}]},
                 {"schema": 1, "projects": [{"id": "other", "path": str(self.base / "projects/other")}]},
                 {"schema": 1, "projects": [{"id": "../vv", "path": str(self.root)}]},
                 {"schema": 1, "projects": [{"id": "vv", "path": str(self.root), "extra": 1}]}]
        for value in cases:
            with self.subTest(value=value):
                self.write_json(self.marker, value)
                with self.assertRaises(core.Blocked):
                    messaging.enabled(self.project)
        self.assertFalse(self.ipc_root.exists())

    def test_marker_rejects_duplicate_json_keys(self):
        self.write(self.marker, b'{"schema":1,"schema":1,"projects":[]}')
        with self.assertRaises(core.Blocked):
            messaging.enabled(self.project)

    def test_marker_rejects_symlink_hardlink_or_public_permissions(self):
        target = self.write_json(self.top / "other-marker", self.value)
        for kind in ("symlink", "hardlink", "permissions"):
            with self.subTest(kind=kind):
                if self.marker.exists() or self.marker.is_symlink():
                    self.marker.unlink()
                if kind == "symlink":
                    self.marker.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, self.marker)
                else:
                    self.write_json(self.marker, self.value, 0o644)
                with self.assertRaises(core.Blocked):
                    messaging.enabled(self.project)

    def test_active_registered_workspace_binding_is_required(self):
        self.enable()
        for project in (replace(self.project, workspace=None), replace(self.project, workspace="B"),
                        replace(self.project, home=self.top)):
            with self.subTest(project=project), self.assertRaises(core.Blocked):
                messaging.prepare_scope(project)
        self.assertFalse(self.ipc_root.exists())

    def test_scope_preparation_does_not_change_home_or_native_sessions(self):
        self.enable()
        before = sorted(str(p.relative_to(self.home)) for p in self.home.rglob("*"))
        scope = messaging.prepare_scope(self.project)
        self.assertEqual(before, sorted(str(p.relative_to(self.home)) for p in self.home.rglob("*")))
        self.assertTrue(scope.runtime.is_dir())
        self.assertTrue(scope.sockets.is_dir())
        self.assertTrue(scope.sessions.is_dir())
        for path in (self.ipc_root, scope.runtime, scope.sockets, scope.sessions):
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assertEqual(messaging.scope(self.project), scope)

    def test_prepare_installs_only_exact_sessions_link_and_is_idempotent(self):
        self.enable()
        sentinel = self.write(self.home / ".claude/private-state", b"leave untouched")
        scope = messaging.prepare(self.project)
        link = self.home / ".claude/sessions"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(scope.sessions))
        self.assertEqual(messaging.prepare(self.project), scope)
        self.assertEqual(sentinel.read_bytes(), b"leave untouched")

    def test_same_project_worktrees_share_scope_but_keep_homes_separate(self):
        self.enable()
        first = self.linked("alpha")
        second = self.linked("beta")
        one = messaging.prepare_scope(first)
        two = messaging.prepare_scope(second)
        main = messaging.prepare_scope(self.project)
        self.assertEqual(one, two)
        self.assertEqual(one, main)
        self.assertNotEqual(first.home, second.home)
        self.assertFalse(first.home.exists())
        self.assertFalse(second.home.exists())

    def test_projects_and_accounts_have_distinct_session_and_socket_stores(self):
        self.enable()
        one = messaging.prepare_scope(self.project)
        other = messaging.prepare_scope(self.other_project())
        account = messaging.prepare_scope(self.switch("B"))
        self.assertEqual(len({one.runtime, other.runtime, account.runtime}), 3)
        self.assertEqual(len({one.sessions, other.sessions, account.sessions}), 3)
        self.assertEqual(len({one.sockets, other.sockets, account.sockets}), 3)
        with self.assertRaises(core.Blocked):
            messaging.scope(self.project)

    def test_rejects_ipc_root_symlink(self):
        self.enable()
        target = self.top / "target-ipc"
        self.mkdir(target)
        self.ipc_root.symlink_to(target)
        with self.assertRaises(core.Blocked):
            messaging.prepare_scope(self.project)
        self.assertEqual(list(target.iterdir()), [])

    def test_rejects_ipc_root_group_access(self):
        self.enable()
        self.mkdir(self.ipc_root)
        self.ipc_root.chmod(0o750)
        with self.assertRaises(core.Blocked):
            messaging.prepare_scope(self.project)

    def test_rejects_replaced_scope_sockets_or_sessions(self):
        self.enable()
        scope = messaging.prepare_scope(self.project)
        for path in (scope.sockets, scope.sessions):
            with self.subTest(path=path):
                original = path.with_name(path.name + "-original")
                path.rename(original)
                path.symlink_to(original)
                with self.assertRaises(core.Blocked):
                    messaging.scope(self.project)
                path.unlink()
                original.rename(path)

    def test_rejects_public_scope_subdirectories(self):
        self.enable()
        scope = messaging.prepare_scope(self.project)
        for path in (scope.runtime, scope.sockets, scope.sessions):
            with self.subTest(path=path):
                path.chmod(0o755)
                with self.assertRaises(core.Blocked):
                    messaging.scope(self.project)
                path.chmod(0o700)

    def test_rejects_foreign_owned_scope(self):
        self.enable()
        scope = messaging.prepare_scope(self.project)
        target = scope.runtime.stat()
        real_fstat = os.fstat

        def foreign_owner(fd):
            info = real_fstat(fd)
            if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info

        with patch.object(messaging.os, "fstat", side_effect=foreign_owner), self.assertRaises(core.Blocked):
            messaging.scope(self.project)

    def test_rejects_sessions_link_to_other_location(self):
        self.enable()
        foreign = self.top / "foreign-sessions"
        self.mkdir(foreign)
        link = self.home / ".claude/sessions"
        link.symlink_to(foreign)
        with self.assertRaises(core.Blocked):
            messaging.prepare(self.project)
        self.assertEqual(os.readlink(link), str(foreign))

    def test_rejects_sessions_link_to_other_project(self):
        self.enable()
        other = messaging.prepare_scope(self.other_project())
        link = self.home / ".claude/sessions"
        link.symlink_to(other.sessions)
        with self.assertRaises(core.Blocked):
            messaging.prepare(self.project)
        self.assertEqual(os.readlink(link), str(other.sessions))

    def test_read_only_scope_requires_prepared_namespace(self):
        self.enable()
        with self.assertRaises(core.Blocked):
            messaging.scope(self.project)
        self.assertFalse(self.ipc_root.exists())

    def test_rejects_wrong_scope_binding_without_overwriting_it(self):
        self.enable()
        scope = messaging.prepare_scope(self.project)
        path = scope.runtime / "binding.json"
        binding = json.loads(path.read_text())
        binding["workspace"] = "B"
        self.write_json(path, binding)
        for call in (messaging.scope, messaging.prepare_scope, messaging.prepare):
            with self.subTest(call=call.__name__), self.assertRaises(core.Blocked):
                call(self.project)
        self.assertEqual(json.loads(path.read_text()), binding)

    def test_rejects_binding_permissions_symlink_and_hardlink(self):
        self.enable()
        scope = messaging.prepare_scope(self.project)
        path = scope.runtime / "binding.json"
        binding = json.loads(path.read_text())
        target = self.write_json(self.top / "binding-copy", binding)
        for kind in ("permissions", "symlink", "hardlink"):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == "permissions":
                    self.write_json(path, binding, 0o644)
                elif kind == "symlink":
                    path.symlink_to(target)
                else:
                    os.link(target, path)
                with self.assertRaises(core.Blocked):
                    messaging.scope(self.project)

    def test_rejects_overlong_socket_root_before_creating_it(self):
        self.enable()
        long_root = self.top / ("long" * 30)
        with patch.object(messaging, "IPC_ROOT", long_root), self.assertRaises(core.Blocked):
            messaging.prepare_scope(self.project)
        self.assertFalse(long_root.exists())

    def test_existing_live_pid_registry_is_never_migrated(self):
        self.enable()
        sessions = self.home / ".claude/sessions"
        original = self.write(sessions / (str(os.getpid()) + ".json"), b"not read as configuration")
        with self.assertRaises(core.Blocked):
            messaging.prepare(self.project)
        self.assertFalse(sessions.is_symlink())
        self.assertEqual(original.read_bytes(), b"not read as configuration")
        self.assertEqual(list(sessions.parent.glob("sessions-before-messaging-*")), [])

    def test_stale_registry_is_backed_up_but_never_imported(self):
        self.enable()
        sessions = self.home / ".claude/sessions"
        original = self.write(sessions / "999999999.json", b"synthetic stale session metadata")
        key = self.write(sessions / ("999999999." + "a" * 64 + ".key"), b"synthetic stale key")
        with patch.object(messaging.os, "kill", side_effect=ProcessLookupError):
            scope = messaging.prepare(self.project)
        self.assertTrue(sessions.is_symlink())
        self.assertEqual(list(scope.sessions.iterdir()), [])
        backups = list(sessions.parent.glob("sessions-before-messaging-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
        self.assertEqual((backups[0] / original.name).read_bytes(), b"synthetic stale session metadata")
        self.assertEqual((backups[0] / key.name).read_bytes(), b"synthetic stale key")

    def test_unknown_legacy_content_is_not_moved(self):
        self.enable()
        sessions = self.home / ".claude/sessions"
        original = self.write(sessions / "unexpected.txt", b"leave untouched")
        with self.assertRaises(core.Blocked):
            messaging.prepare(self.project)
        self.assertEqual(original.read_bytes(), b"leave untouched")
        self.assertFalse(sessions.is_symlink())

    def test_unverifiable_pid_is_not_assumed_dead(self):
        self.enable()
        sessions = self.home / ".claude/sessions"
        self.write(sessions / "12345.json", b"synthetic")
        with patch.object(messaging.os, "kill", side_effect=PermissionError), self.assertRaises(core.Blocked):
            messaging.prepare(self.project)
        self.assertFalse(sessions.is_symlink())

    def test_legacy_registry_rejects_linked_files(self):
        self.enable()
        sessions = self.home / ".claude/sessions"
        self.mkdir(sessions)
        outside = self.write(self.top / "stale-pid-metadata", b"synthetic")
        link = sessions / "999999999.json"
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                if link.exists() or link.is_symlink():
                    link.unlink()
                if kind == "symlink":
                    link.symlink_to(outside)
                else:
                    os.link(outside, link)
                with patch.object(messaging.os, "kill", side_effect=ProcessLookupError), self.assertRaises(core.Blocked):
                    messaging.prepare(self.project)
                self.assertFalse(sessions.is_symlink())
        self.assertEqual(outside.read_bytes(), b"synthetic")

    def test_environment_drops_inherited_runtime_and_messaging_overrides(self):
        self.enable()
        inherited = {"XDG_RUNTIME_DIR": "/tmp/foreign-peer",
                     "CLAUDE_CODE_TMPDIR": "/tmp/foreign-temp",
                     "TMPDIR": "/tmp/foreign-temp",
                     "CLAUDE_CONFIG_DIR": "/tmp/foreign-config",
                     "HOME": "/tmp/foreign-home",
                     "CLAUDE_CODE_MESSAGING_TOKEN": "synthetic-untrusted",
                     "CLAUDE_CODE_MESSAGING_SOCKET": "/tmp/foreign.sock",
                     "SSH_AUTH_SOCK": "/tmp/foreign-ssh.sock",
                     "HTTP_PROXY": "http://127.0.0.1:1111",
                     "NO_PROXY": "*", "TERM": "xterm-256color"}
        env = isolation.environment(self.project, "http://127.0.0.1:62919", inherited, token_auth=True)
        scope = messaging.scope(self.project)
        self.assertEqual(env["XDG_RUNTIME_DIR"], str(scope.runtime))
        self.assertEqual(env["HOME"], str(self.home))
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(self.home / ".claude"))
        self.assertEqual(env["CLAUDE_CODE_TMPDIR"], str(self.home / "tmp"))
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:62919")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:62919")
        self.assertEqual(env["NO_PROXY"], "")
        self.assertEqual(env["TERM"], "xterm-256color")
        for name in ("CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_MESSAGING_SOCKET", "SSH_AUTH_SOCK"):
            self.assertNotIn(name, env)

    def test_disabled_environment_never_inherits_external_ipc_root(self):
        env = isolation.environment(self.project, "http://127.0.0.1:62919",
                                    {"XDG_RUNTIME_DIR": "/tmp/foreign-peer"}, token_auth=True)
        self.assertNotIn("XDG_RUNTIME_DIR", env)

    def test_profile_adds_only_own_ipc_scope_without_broadening_tcp_dns_or_signal(self):
        native = self.write(self.top / "native-claude", b"not executed")
        native.chmod(0o700)
        hook = Path("/private/tmp/surge-cc-oauth-messaging/browser")
        before = isolation.profile(self.project, native, hook, token_auth=True)
        self.enable()
        scope = messaging.prepare_scope(self.project)
        other = messaging.prepare_scope(self.other_project())
        after = isolation.profile(self.project, native, hook, token_auth=True)
        added = set(after.splitlines()) - set(before.splitlines())
        removed = set(before.splitlines()) - set(after.splitlines())
        self.assertEqual(removed, set())
        expected_network = ("(allow network-bind network-inbound network-outbound "
                            "(subpath " + json.dumps(str(scope.sockets)) + "))")
        self.assertEqual([line for line in added if "network-" in line], [expected_network])
        self.assertEqual([line for line in after.splitlines() if "signal" in line],
                         ["(allow signal (target same-sandbox))"])
        self.assertIn('(allow network-outbound (remote tcp "localhost:62919"))', after)
        self.assertNotIn(str(other.runtime), after)
        self.assertNotIn('(subpath ' + json.dumps(str(self.ipc_root)) + ')', after)
        self.assertNotIn('(subpath ' + json.dumps(str(scope.runtime)) + ')', after)
        self.assertNotIn('binding.json', after)
        self.assertNotIn('(allow network*)', after)
        self.assertNotIn('remote udp', after)

    def test_command_prepares_new_worktree_home_then_exact_sessions_link(self):
        self.enable()
        project = self.linked("fresh")
        self.assertFalse(project.home.exists())
        native = self.write(self.top / "native-claude", b"not executed")
        native.chmod(0o700)
        sandbox = self.write(self.top / "sandbox-exec", b"not executed")
        hook = Path("/private/tmp/surge-cc-oauth-messaging/browser")
        with patch.object(isolation, "SANDBOX", sandbox):
            command = isolation.command(project, native, ["--model", "opus"], hook, token_auth=True)
        scope = messaging.scope(project)
        self.assertEqual(os.readlink(project.config / "sessions"), str(scope.sessions))
        self.assertEqual(command[:2], [str(sandbox), "-p"])
        self.assertIn('(deny default)', command[2])
        self.assertIn('(allow network-outbound (remote tcp "localhost:62919"))', command[2])
        self.assertEqual(command[-2:], ["--model", "opus"])
        settings = json.loads(command[command.index("--settings") + 1])
        self.assertFalse(settings["disableAllHooks"])
        self.assertFalse(settings["remoteControlAtStartup"])


if __name__ == "__main__":
    unittest.main()
