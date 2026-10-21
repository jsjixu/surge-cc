"""Offline backend rebind contracts; all entries live in a temporary directory."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, terminal


class TerminalBackendUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="terminal-update-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        self.native = self.root / "native-claude"
        self.native.write_text("#!/bin/sh\nprintf '%s\\n' '2.1.296 (Claude Code)'\n")
        self.native.chmod(0o700)
        self.command = self.bin / "claude"
        self.command.symlink_to("../native-claude")
        self.config = self.root / "config.json"
        self.config.write_text("{}\n")
        self.config.chmod(0o600)
        self.backend = self.root / "old-backend.py"
        self.backend.write_text("print('old backend')\n")
        self.backend.chmod(0o600)
        self.new_backend = self.root / "new-backend.py"
        self.new_backend.write_text("print('new backend')\n")
        self.new_backend.chmod(0o600)
        self.python = Path(sys.executable).resolve()
        self.state = self.root / "state"
        terminal.install(self.config, self.backend, self.python,
                         command_path=self.command, state_dir=self.state)
        self.manifest = self.state / "manifest.json"
        self.old_manifest = self.manifest.read_bytes()
        self.old_shim = self.command.read_bytes()
        self.old_data = json.loads(self.old_manifest)

    def update(self, backend=None, python=None):
        return terminal.update_backend(backend or self.new_backend, python, state_dir=self.state)

    def assert_old_intact(self):
        self.assertEqual(self.command.read_bytes(), self.old_shim)
        self.assertEqual(self.manifest.read_bytes(), self.old_manifest)
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])
        self.assertEqual(terminal.original_claude(self.command, state_dir=self.state), self.native)

    def assert_guarded_or_blocked(self):
        self.assertFalse(self.command.is_symlink())
        self.assertIn(terminal.MARKER.encode(), self.command.read_bytes())
        state = terminal.status(state_dir=self.state)
        if state["ok"]:
            self.assertEqual(terminal.original_claude(self.command, state_dir=self.state), self.native)
        else:
            with self.assertRaises(core.Blocked):
                terminal.original_claude(self.command, state_dir=self.state)
        return state["ok"]

    def test_rebind_preserves_native_config_backup_and_supports_uninstall(self):
        native_bytes, native_stat = self.native.read_bytes(), terminal._identity(self.native)
        config_bytes, config_inode = self.config.read_bytes(), self.config.stat().st_ino
        backup_inode = (self.state / "original-link").lstat().st_ino
        with patch.object(terminal.subprocess, "run", side_effect=AssertionError("do not start native")):
            self.assertTrue(self.update()["ok"])
            self.assertEqual(terminal.metadata_version(state_dir=self.state), "2.1.296 (Claude Code)")
        data = json.loads(self.manifest.read_bytes())
        for field in self.old_data.keys() - {"entrypoint", "shim_sha256"}:
            self.assertEqual(data[field], self.old_data[field], field)
        self.assertEqual(data["entrypoint"], str(self.new_backend))
        self.assertEqual(data["shim_sha256"], terminal._digest(self.command.read_bytes()))
        self.assertEqual(self.native.read_bytes(), native_bytes)
        self.assertEqual(terminal._identity(self.native), native_stat)
        self.assertEqual(self.config.read_bytes(), config_bytes)
        self.assertEqual(self.config.stat().st_ino, config_inode)
        self.assertEqual((self.state / "original-link").lstat().st_ino, backup_inode)
        self.assertEqual(os.readlink(self.state / "original-link"), "../native-claude")
        self.assertEqual(self.command.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o600)
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])
        self.assertEqual(terminal.original_claude(self.command, state_dir=self.state), self.native)
        run = subprocess.run([str(self.command), "--print", "hello"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stdout, "new backend\n")
        self.assertTrue(terminal.uninstall(state_dir=self.state)["ok"])
        self.assertEqual(os.readlink(self.command), "../native-claude")
        self.assertFalse(terminal.status(state_dir=self.state)["installed"])

    def test_same_backend_is_noop_preserving_exact_files(self):
        inodes = self.command.stat().st_ino, self.manifest.stat().st_ino
        with patch.object(terminal, "_exchange", side_effect=AssertionError("no swap needed")):
            self.assertTrue(self.update(self.backend)["ok"])
        self.assertEqual((self.command.stat().st_ino, self.manifest.stat().st_ino), inodes)
        self.assert_old_intact()

    def test_optional_python_can_change_without_other_manifest_changes(self):
        alternate = self.root / "python"
        alternate.write_text("#!/bin/sh\nexit 0\n")
        alternate.chmod(0o700)
        self.assertTrue(self.update(python=alternate)["ok"])
        self.assertEqual(json.loads(self.manifest.read_bytes())["python_executable"], str(alternate))
        self.assertEqual(terminal.original_claude(self.command, state_dir=self.state), self.native)

    def test_missing_symlink_insecure_and_relative_backend_are_rejected(self):
        link = self.root / "backend-link.py"
        link.symlink_to(self.new_backend)
        insecure = self.root / "insecure.py"
        insecure.write_text("pass\n")
        insecure.chmod(0o666)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root)
        for path in (self.root / "missing.py", link, insecure, Path("relative.py"),
                     parent_link / self.new_backend.name, self.root):
            with self.subTest(path=path), self.assertRaises(core.Blocked):
                self.update(path)
            self.assert_old_intact()

    def test_invalid_optional_python_is_rejected(self):
        for path in (self.new_backend, self.root / "missing-python", Path("python")):
            with self.subTest(path=path), self.assertRaises(core.Blocked):
                self.update(python=path)
            self.assert_old_intact()

    def test_manifest_write_failure_rolls_back_exact_bytes_and_inodes(self):
        # Preserve serialization too, not just the decoded manifest.
        self.manifest.write_bytes(json.dumps(self.old_data, separators=(",", ":")).encode())
        self.old_manifest = self.manifest.read_bytes()
        inodes = self.command.stat().st_ino, self.manifest.stat().st_ino
        real_write = terminal._write_private
        saw_blocked = []
        def fail_manifest(path, body, **kwargs):
            if path.parent == self.state:
                saw_blocked.append(not self.assert_guarded_or_blocked())
                raise OSError("simulated manifest write failure")
            return real_write(path, body, **kwargs)
        with patch.object(terminal, "_write_private", side_effect=fail_manifest):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assertEqual(saw_blocked, [True])
        self.assert_old_intact()
        self.assertEqual((self.command.stat().st_ino, self.manifest.stat().st_ino), inodes)
        self.assertEqual(set(p.name for p in self.state.iterdir()), {".lock", "manifest.json", "original-link"})
        self.assertEqual(set(p.name for p in self.bin.iterdir()), {"claude"})

    def test_second_exchange_failure_rolls_back_shim(self):
        real_exchange = terminal._exchange
        def fail_manifest(first, second):
            if second == self.manifest:
                raise OSError("simulated exchange failure")
            return real_exchange(first, second)
        with patch.object(terminal, "_exchange", side_effect=fail_manifest):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assert_old_intact()

    def test_post_commit_validation_failure_rolls_back_both_files(self):
        real_verify = terminal._verify_active
        def fail_new(data):
            if data["entrypoint"] == str(self.new_backend):
                raise core.Blocked("simulated verification failure")
            return real_verify(data)
        with patch.object(terminal, "_verify_active", side_effect=fail_new):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assert_old_intact()

    def test_each_exchange_remains_guarded_or_blocked_with_no_native_gap(self):
        real_exchange = terminal._exchange
        states = []
        def observed(first, second):
            states.append(self.assert_guarded_or_blocked())
            result = real_exchange(first, second)
            states.append(self.assert_guarded_or_blocked())
            return result
        with patch.object(terminal, "_exchange", side_effect=observed):
            self.update()
        self.assertEqual(states, [True, False, False, True])

    def test_preexisting_user_shim_edit_is_never_overwritten(self):
        self.command.write_text("user command\n")
        with self.assertRaises(core.Blocked):
            self.update()
        self.assertEqual(self.command.read_text(), "user command\n")
        self.assertEqual(self.manifest.read_bytes(), self.old_manifest)

    def test_concurrent_shim_replacement_is_put_back_exactly(self):
        real_exchange = terminal._exchange
        changed_inode = []
        def concurrent(first, second):
            if second == self.command and not changed_inode:
                second.unlink()
                second.write_text("intervening user command\n")
                second.chmod(0o700)
                changed_inode.append(second.stat().st_ino)
            return real_exchange(first, second)
        with patch.object(terminal, "_exchange", side_effect=concurrent):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assertEqual(self.command.read_text(), "intervening user command\n")
        self.assertEqual(self.command.stat().st_ino, changed_inode[0])
        self.assertEqual(self.manifest.read_bytes(), self.old_manifest)

    def test_concurrent_symlink_replacement_is_preserved_without_reading_target(self):
        target = self.root / "user-owned"
        target.write_text("user target remains unchanged\n")
        real_exchange = terminal._exchange
        replaced = False
        def concurrent(first, second):
            nonlocal replaced
            if second == self.command and not replaced:
                replaced = True
                second.unlink()
                second.symlink_to(target)
            return real_exchange(first, second)
        with patch.object(terminal, "_exchange", side_effect=concurrent):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assertTrue(self.command.is_symlink())
        self.assertEqual(os.readlink(self.command), str(target))
        self.assertEqual(target.read_text(), "user target remains unchanged\n")
        self.assertEqual(self.manifest.read_bytes(), self.old_manifest)

    def test_concurrent_manifest_replacement_is_preserved_and_shim_rolled_back(self):
        real_exchange = terminal._exchange
        replaced = False
        def concurrent(first, second):
            nonlocal replaced
            if second == self.manifest and not replaced:
                replaced = True
                second.unlink()
                second.write_text('{"user":"changed manifest"}\n')
                second.chmod(0o600)
            return real_exchange(first, second)
        with patch.object(terminal, "_exchange", side_effect=concurrent):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assertEqual(self.manifest.read_text(), '{"user":"changed manifest"}\n')
        self.assertEqual(self.command.read_bytes(), self.old_shim)
        self.assertFalse(terminal.status(state_dir=self.state)["ok"])

    def test_shim_edit_during_manifest_failure_is_kept_with_original_backup(self):
        real_write = terminal._write_private
        def concurrent(path, body, **kwargs):
            if path.parent == self.state:
                self.command.write_text("late user command\n")
                raise OSError("simulated manifest write failure")
            return real_write(path, body, **kwargs)
        with patch.object(terminal, "_write_private", side_effect=concurrent):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assertEqual(self.command.read_text(), "late user command\n")
        self.assertEqual(self.manifest.read_bytes(), self.old_manifest)
        backups = list(self.bin.glob(".surge-cc-update-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.old_shim)

    def test_edit_arriving_during_rollback_is_restored_and_original_retained(self):
        real_write, real_exchange = terminal._write_private, terminal._exchange
        command_swaps = 0
        def fail_manifest(path, body, **kwargs):
            if path.parent == self.state:
                raise OSError("simulated manifest write failure")
            return real_write(path, body, **kwargs)
        def concurrent(first, second):
            nonlocal command_swaps
            if second == self.command:
                command_swaps += 1
                if command_swaps == 2:
                    second.write_text("edit arriving during rollback\n")
            return real_exchange(first, second)
        with patch.object(terminal, "_write_private", side_effect=fail_manifest), \
                patch.object(terminal, "_exchange", side_effect=concurrent):
            with self.assertRaises(core.Blocked):
                self.update()
        self.assertEqual(self.command.read_text(), "edit arriving during rollback\n")
        self.assertEqual(self.manifest.read_bytes(), self.old_manifest)
        backups = list(self.bin.glob(".surge-cc-update-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.old_shim)

    def test_native_identity_change_refuses_rebind(self):
        self.native.write_text("#!/bin/sh\necho '2.1.297 (Claude Code)'\n")
        with self.assertRaises(core.Blocked):
            self.update()
        self.assertEqual(self.command.read_bytes(), self.old_shim)
        self.assertEqual(self.manifest.read_bytes(), self.old_manifest)


if __name__ == "__main__":
    unittest.main()
