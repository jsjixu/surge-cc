"""Offline entry-point tests; no personal installation, network or GUI changes."""
from __future__ import annotations
from contextlib import ExitStack
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


class TerminalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-terminal-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        self.original = self.root / "native-2.1.296"
        self.original.write_text("#!/bin/sh\nprintf '%s\\n' '2.1.296 (Claude Code)'\n")
        self.original.chmod(0o700)
        self.command = self.bin / "claude"
        self.command.symlink_to("../native-2.1.296")
        self.link = os.readlink(self.command)
        self.config = self.root / "config.json"
        self.config.write_text("{}")
        self.config.chmod(0o600)
        self.backend = self.root / "backend.py"
        self.backend.write_text("import json, os, sys\nprint(json.dumps({'argv':sys.argv[1:], 'cwd':os.getcwd(), 'entry':os.environ.get('SURGE_CC_TERMINAL_ENTRY')}))\nsys.exit(23)\n")
        self.backend.chmod(0o600)
        self.python = Path(sys.executable).resolve()
        self.state = self.root / "state"

    def install(self):
        return terminal.install(self.config, self.backend, self.python,
                                command_path=self.command, state_dir=self.state)

    def original_path(self):
        return terminal.original_claude(self.command, state_dir=self.state)

    def test_install_preserves_original_and_uninstall_restores_exact_link(self):
        old = self.original.read_bytes()
        info = self.original.stat()
        self.assertTrue(self.install()["ok"])
        self.assertFalse(self.command.is_symlink())
        self.assertEqual(self.original_path(), self.original)
        self.assertEqual(self.original.read_bytes(), old)
        self.assertEqual(self.original.stat().st_ino, info.st_ino)
        self.assertEqual(os.readlink(self.state / "original-link"), self.link)
        self.assertEqual((self.state.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((self.state / "manifest.json").stat().st_mode & 0o777), 0o600)
        self.assertEqual((self.command.stat().st_mode & 0o777), 0o700)
        self.assertTrue(terminal.uninstall(state_dir=self.state)["ok"])
        self.assertTrue(self.command.is_symlink())
        self.assertEqual(os.readlink(self.command), self.link)
        self.assertEqual(self.original_path(), self.command)
        self.assertFalse(terminal.status(state_dir=self.state)["installed"])

    def test_install_and_uninstall_idempotent(self):
        self.install()
        ino = self.command.stat().st_ino
        self.assertTrue(self.install()["installed"])
        self.assertEqual(self.command.stat().st_ino, ino)
        terminal.uninstall(state_dir=self.state)
        self.assertTrue(terminal.uninstall(state_dir=self.state)["ok"])

    def test_shim_preserves_arguments_cwd_and_exit_status(self):
        self.install()
        args = ['--print', 'spaces ; $(touch NO)\nnext', '--output-format', 'stream-json']
        run = subprocess.run([str(self.command), *args], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(run.returncode, 23)
        data = json.loads(run.stdout)
        self.assertEqual(data['argv'], ['--config', str(self.config), 'launch', 'code', '--passthrough', '--', *args])
        self.assertEqual(data['cwd'], str(self.root))
        self.assertEqual(data['entry'], '1')
        self.assertIn('checking protected', run.stderr)
        self.assertFalse((self.root / "NO").exists())

    def test_version_uses_backend_metadata_without_progress_noise(self):
        self.install()
        for flag in ('--version', '-v'):
            run = subprocess.run([str(self.command), flag], capture_output=True, text=True)
            self.assertEqual(json.loads(run.stdout)['argv'], ['--config', str(self.config), 'terminal', 'version'])
            self.assertEqual(run.stderr, '')
        with patch.object(terminal.subprocess, 'run', side_effect=AssertionError('native version must stay cached')):
            self.assertEqual(terminal.metadata_version(state_dir=self.state), '2.1.296 (Claude Code)')

    def test_version_with_other_arguments_must_use_guard(self):
        self.install()
        run = subprocess.run([str(self.command), '--version', '--print', 'hello'], capture_output=True, text=True)
        self.assertIn('--passthrough', json.loads(run.stdout)['argv'])

    def test_missing_backend_blocks_without_native_fallback(self):
        self.install()
        self.backend.unlink()
        run = subprocess.run([str(self.command), '--print', 'hi'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 78)
        self.assertEqual(run.stdout, '')
        self.assertIn('blocked', run.stderr)
        with self.assertRaises(core.Blocked):
            self.original_path()
        # Restore remains available if the app has been removed.
        self.assertTrue(terminal.uninstall(state_dir=self.state)['ok'])

    def test_missing_config_blocks(self):
        self.install()
        self.config.unlink()
        run = subprocess.run([str(self.command)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 78)
        self.assertEqual(run.stdout, '')

    def test_malformed_manifest_does_not_fall_through(self):
        self.install()
        (self.state / 'manifest.json').write_text('{invalid')
        self.assertFalse(terminal.status(state_dir=self.state)['ok'])
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_deleted_manifest_does_not_fall_through(self):
        self.install()
        (self.state / 'manifest.json').unlink()
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_missing_state_with_managed_shim_blocks(self):
        self.install()
        with self.assertRaises(core.Blocked):
            terminal.original_claude(self.command, state_dir=self.root / 'absent')

    def test_changed_native_binary_blocks(self):
        self.install()
        self.original.write_text('#!/bin/sh\necho changed\n')
        with self.assertRaises(core.Blocked):
            self.original_path()
        self.assertFalse(terminal.status(state_dir=self.state)['ok'])

    def change_recorded_mount_device(self):
        manifest = self.state / 'manifest.json'
        data = json.loads(manifest.read_text())
        data['original_stat'][0] += 1
        manifest.write_text(json.dumps(data))

    def test_remounted_device_number_does_not_invalidate_unchanged_native(self):
        self.install()
        self.change_recorded_mount_device()
        before = (self.state / 'manifest.json').read_bytes()
        with patch.object(terminal.subprocess, 'run', side_effect=AssertionError('do not start native')):
            self.assertEqual(self.original_path(), self.original)
            self.assertTrue(terminal.status(state_dir=self.state)['ok'])
            self.assertEqual(terminal.metadata_version(state_dir=self.state), '2.1.296 (Claude Code)')
        self.assertEqual((self.state / 'manifest.json').read_bytes(), before)

    def test_native_inode_change_still_blocks_after_remount(self):
        self.install()
        self.change_recorded_mount_device()
        before = self.original.stat()
        replacement = self.root / 'replacement-native'
        replacement.write_bytes(self.original.read_bytes())
        replacement.chmod(0o700)
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.replace(replacement, self.original)
        after = self.original.stat()
        self.assertNotEqual(after.st_ino, before.st_ino)
        self.assertEqual((after.st_size, after.st_mtime_ns), (before.st_size, before.st_mtime_ns))
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_native_size_change_still_blocks_after_remount(self):
        self.install()
        self.change_recorded_mount_device()
        before = self.original.stat()
        with self.original.open('ab') as stream:
            stream.write(b'\n')
        os.utime(self.original, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.original.stat().st_ino, before.st_ino)
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_native_mtime_change_still_blocks_after_remount(self):
        self.install()
        self.change_recorded_mount_device()
        before = self.original.stat()
        os.utime(self.original, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        self.assertEqual(self.original.stat().st_ino, before.st_ino)
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_native_unsafe_permissions_still_block_after_remount(self):
        self.install()
        self.change_recorded_mount_device()
        self.original.chmod(0o777)
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_wrong_original_link_still_blocks_after_remount(self):
        self.install()
        self.change_recorded_mount_device()
        backup = self.state / 'original-link'
        backup.unlink()
        backup.symlink_to('/different')
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_modified_shim_still_blocks_after_remount(self):
        self.install()
        self.change_recorded_mount_device()
        with self.command.open('ab') as stream:
            stream.write(b'\n# changed\n')
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_changed_shim_or_updater_symlink_is_not_overwritten(self):
        self.install()
        self.command.write_text('#!/bin/sh\necho user command\n')
        with self.assertRaises(core.Blocked):
            terminal.uninstall(state_dir=self.state)
        self.assertIn('user command', self.command.read_text())
        with self.assertRaises(core.Blocked):
            self.install()
        self.command.unlink()
        self.command.symlink_to(self.original)
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_symlinked_state_backend_config_and_parents_rejected(self):
        for item in (self.config, self.backend):
            saved = item.with_suffix('.saved')
            item.rename(saved)
            item.symlink_to(saved)
            with self.assertRaises(core.Blocked):
                self.install()
            item.unlink()
            saved.rename(item)
        real = self.root / 'real'
        real.mkdir(mode=0o700)
        self.state.symlink_to(real)
        with self.assertRaises(core.Blocked):
            self.install()
        self.assertTrue(self.command.is_symlink())

    def test_insecure_state_permissions_rejected(self):
        self.state.mkdir(mode=0o755)
        self.state.chmod(0o755)
        with self.assertRaises(core.Blocked):
            self.install()
        self.assertTrue(self.command.is_symlink())

    def test_regular_command_is_never_overwritten(self):
        self.command.unlink()
        self.command.write_text('user command')
        with self.assertRaises(core.Blocked):
            self.install()
        self.assertEqual(self.command.read_text(), 'user command')

    def test_wrong_native_version_refuses_install(self):
        self.original.write_text('#!/bin/sh\necho unknown\n')
        with self.assertRaises(core.Blocked):
            self.install()
        self.assertTrue(self.command.is_symlink())
        self.assertFalse((self.state / 'manifest.json').exists())

    def test_modified_backup_blocks(self):
        self.install()
        backup = self.state / 'original-link'
        backup.unlink()
        backup.symlink_to('/different')
        with self.assertRaises(core.Blocked):
            self.original_path()

    def test_install_detects_race_and_restores_intervening_entry(self):
        real_exchange = terminal._exchange
        calls = 0
        def concurrent(first, second):
            nonlocal calls
            calls += 1
            if calls == 1:
                second.unlink()
                second.write_text('intervening user edit')
            return real_exchange(first, second)
        with patch.object(terminal, '_exchange', side_effect=concurrent):
            with self.assertRaises(core.Blocked):
                self.install()
        self.assertEqual(self.command.read_text(), 'intervening user edit')
        self.assertFalse((self.state / 'manifest.json').exists())

    def test_uninstall_detects_race_and_restores_intervening_entry(self):
        self.install()
        real_exchange = terminal._exchange
        calls = 0
        def concurrent(first, second):
            nonlocal calls
            calls += 1
            if calls == 1:
                second.unlink()
                second.write_text('intervening user edit')
            return real_exchange(first, second)
        with patch.object(terminal, '_exchange', side_effect=concurrent):
            with self.assertRaises(core.Blocked):
                terminal.uninstall(state_dir=self.state)
        self.assertEqual(self.command.read_text(), 'intervening user edit')
        self.assertTrue((self.state / 'manifest.json').exists())

    def test_core_uses_managed_original_and_fails_closed(self):
        self.install()
        with patch.object(terminal, 'APP_SUPPORT', self.root), patch.object(Path, 'home', return_value=self.root):
            # Production discovery asks its standard primary; map only the lookup.
            with patch.object(terminal, 'original_claude', return_value=self.original) as lookup:
                self.assertEqual(core.default_claude(), self.original)
                lookup.assert_called_once()
            with patch.object(terminal, 'original_claude', side_effect=core.Blocked('bad manifest')):
                with self.assertRaises(core.Blocked):
                    core.default_claude()


if __name__ == '__main__':
    unittest.main()
