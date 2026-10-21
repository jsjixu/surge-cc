import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import browser_locks as locks
from surge_cc.core import Blocked


class BrowserLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.config = self.base / "config.json"
        self.config.write_text("{}")
        self.root = self.base / "workspaces/A"
        self.browser = self.root / "data/Browser"
        self.oauth = self.root / "data/OAuthBrowser"
        for profile in (self.browser, self.oauth):
            (profile / "Default").mkdir(parents=True, mode=0o700)
            (profile / "Default/Preferences").write_text('{"keep":"settings"}')
            (profile / "Default/Cookies").write_text("do not touch")
            (profile / "Default/LOCK").write_text("database lock")
        self.addCleanup(patch.stopall)
        patch.object(locks, "_processes", return_value=[(1, 0, "/sbin/launchd")]).start()
        patch.object(locks, "_pid_absent", return_value=True).start()
        patch.object(locks, "_local_hosts", return_value={"test-host"}).start()

    def stale(self, profile=None):
        profile = profile or self.browser
        targets = {"SingletonLock": "test-host-54321", "SingletonCookie": "123456789",
                   "SingletonSocket": str(self.base / ("socket-" + profile.name) / "SingletonSocket")}
        for name, target in targets.items():
            (profile / name).symlink_to(target)
        return targets

    def test_stale_web_and_oauth_links_are_backed_up_without_profile_changes(self):
        targets = {p.name: self.stale(p) for p in (self.browser, self.oauth)}
        result = locks.repair(self.config, "A")
        self.assertEqual(result["status"], "repaired")
        self.assertEqual(result["removed_count"], 6)
        backup = Path(result["backup_path"])
        self.assertFalse(backup.is_relative_to(self.root))
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        manifest = json.loads((backup / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "completed")
        self.assertEqual((backup / "manifest.json").stat().st_mode & 0o777, 0o600)
        for profile in (self.browser, self.oauth):
            for name, target in targets[profile.name].items():
                self.assertFalse(os.path.lexists(profile / name))
                self.assertEqual(os.readlink(backup / (profile.name + "-" + name)), target)
            self.assertEqual((profile / "Default/Preferences").read_text(), '{"keep":"settings"}')
            self.assertEqual((profile / "Default/Cookies").read_text(), "do not touch")
            self.assertEqual((profile / "Default/LOCK").read_text(), "database lock")
        again = locks.repair(self.config, "A")
        self.assertEqual(again["status"], "no_stale_locks")

    def test_regular_personal_chrome_process_is_not_closed_or_modified(self):
        self.stale()
        with patch.object(locks, "_processes", return_value=[(42, 1,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")]):
            self.assertEqual(locks.repair(self.config, "A")["status"], "repaired")

    def test_live_profile_process_and_dedicated_helper_block_repair(self):
        self.stale()
        commands = ["Chrome --user-data-dir=" + str(self.browser),
                    "Chrome --user-data-dir=" + str(self.oauth),
                    str(self.base / "Browser Runtime/Surge CC Browser.app/Contents/Frameworks/Helper")]
        for command in commands:
            with self.subTest(command=command), patch.object(locks, "_processes", return_value=[(42, 1, command)]):
                with self.assertRaises(Blocked):
                    locks.repair(self.config, "A")
                self.assertTrue((self.browser / "SingletonLock").is_symlink())

    def test_live_pid_or_foreign_host_blocks_even_when_ps_has_no_match(self):
        self.stale()
        with patch.object(locks, "_pid_absent", return_value=False), self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        (self.browser / "SingletonLock").unlink()
        (self.browser / "SingletonLock").symlink_to("other-host-54321")
        with self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        self.assertTrue((self.browser / "SingletonSocket").is_symlink())

    def test_existing_socket_target_blocks_even_if_it_is_not_a_socket(self):
        targets = self.stale()
        path = Path(targets["SingletonSocket"])
        path.parent.mkdir()
        path.write_text("still present")
        with self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        self.assertTrue((self.browser / "SingletonLock").is_symlink())

    def test_incomplete_or_unexpected_link_types_are_never_removed(self):
        (self.browser / "SingletonCookie").symlink_to("123")
        with self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        (self.browser / "SingletonCookie").unlink()
        (self.browser / "SingletonLock").write_text("not a link")
        with self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        self.assertEqual((self.browser / "SingletonLock").read_text(), "not a link")

    def test_active_session_or_oauth_flock_rejects_without_changes(self):
        self.stale()
        for name in (".session.lock", ".oauth.lock"):
            with self.subTest(name=name), (self.root / name).open("a") as handle:
                fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
                with self.assertRaises(Blocked):
                    locks.repair(self.config, "A")
            self.assertTrue((self.browser / "SingletonLock").is_symlink())

    def test_repair_holds_both_exclusive_locks_through_the_move(self):
        self.stale()
        checks = []
        def inspect():
            for name in (".session.lock", ".oauth.lock"):
                with (self.root / name).open("a") as handle:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
                checks.append(name)
            return [(1, 0, "/sbin/launchd")]
        with patch.object(locks, "_processes", side_effect=inspect):
            locks.repair(self.config, "A")
        self.assertGreaterEqual(len(checks), 8)

    def test_symlink_or_hardlink_flock_files_block(self):
        self.stale()
        target = self.base / "target-lock"
        target.write_text("")
        lock = self.root / ".session.lock"
        lock.symlink_to(target)
        with self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        lock.unlink()
        os.link(target, lock)
        with self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        self.assertTrue((self.browser / "SingletonLock").is_symlink())

    def test_symlink_profile_and_symlink_ancestor_block(self):
        self.stale()
        original = self.root / "data/Original"
        self.browser.rename(original)
        self.browser.symlink_to(original)
        with self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        self.browser.unlink()
        original.rename(self.browser)
        alias = self.base / "alias"
        alias.symlink_to(self.base)
        with self.assertRaises(Blocked):
            locks.repair(alias / "config.json", "A")
        self.assertTrue((self.browser / "SingletonLock").is_symlink())

    def test_invalid_name_is_rejected(self):
        for name in ("../B", ".", "A/B", ""):
            with self.subTest(name=name), self.assertRaises(Blocked):
                locks.repair(self.config, name)

    def test_permission_or_process_query_failure_is_not_treated_as_stopped(self):
        self.stale()
        with patch.object(locks, "_processes", side_effect=Blocked("cannot query")):
            with self.assertRaises(Blocked):
                locks.repair(self.config, "A")
        self.assertTrue((self.browser / "SingletonLock").is_symlink())

    def test_new_process_before_move_prevents_all_changes(self):
        self.stale()
        with patch.object(locks, "_processes", side_effect=[[(1, 0, "launchd")],
                [(42, 1, "Chrome --user-data-dir=" + str(self.browser))]]):
            with self.assertRaises(Blocked):
                locks.repair(self.config, "A")
        self.assertTrue((self.browser / "SingletonLock").is_symlink())
        self.assertTrue((self.browser / "SingletonCookie").is_symlink())

    def test_link_replacement_between_checks_is_not_deleted(self):
        self.stale()
        calls = []
        def changed():
            calls.append(1)
            if len(calls) == 1:
                (self.browser / "SingletonCookie").unlink()
                (self.browser / "SingletonCookie").symlink_to("999")
            return [(1, 0, "launchd")]
        with patch.object(locks, "_processes", side_effect=changed), self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        self.assertEqual(os.readlink(self.browser / "SingletonCookie"), "999")
        self.assertTrue((self.browser / "SingletonSocket").is_symlink())

    def test_failure_mid_move_rolls_back_only_owned_links(self):
        targets = self.stale()
        original = locks._write_manifest
        count = []
        def failing(fd, manifest):
            count.append(1)
            if len(count) == 2:
                raise OSError("simulated disk error")
            return original(fd, manifest)
        with patch.object(locks, "_write_manifest", side_effect=failing), self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        for name, target in targets.items():
            self.assertEqual(os.readlink(self.browser / name), target)
        manifests = list((self.base / "browser-lock-backups").glob("*/manifest.json"))
        self.assertEqual(json.loads(manifests[0].read_text())["status"], "rolled_back")

    def test_new_link_during_rollback_is_never_overwritten(self):
        targets = self.stale()
        original_write = locks._write_manifest
        original_symlink = os.symlink
        count = []
        def failing_write(fd, manifest):
            count.append(1)
            if len(count) == 2:
                raise OSError("simulated disk error")
            return original_write(fd, manifest)
        def concurrent_symlink(target, name, **kwargs):
            if name == "SingletonSocket":
                original_symlink("new-active-browser-socket", name, **kwargs)
            return original_symlink(target, name, **kwargs)
        with patch.object(locks, "_write_manifest", side_effect=failing_write), \
                patch.object(locks.os, "symlink", side_effect=concurrent_symlink), self.assertRaises(Blocked):
            locks.repair(self.config, "A")
        self.assertEqual(os.readlink(self.browser / "SingletonSocket"), "new-active-browser-socket")
        manifest_path = next((self.base / "browser-lock-backups").glob("*/manifest.json"))
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["status"], "recovery_required")
        self.assertEqual(manifest["retained"], ["Browser-SingletonSocket"])
        self.assertEqual(os.readlink(manifest_path.parent / "Browser-SingletonSocket"), targets["SingletonSocket"])

    def test_rollback_readlink_failure_keeps_backup_and_records_partial_recovery(self):
        targets = self.stale()
        original_write = locks._write_manifest
        original_readlink = os.readlink
        count = []
        failed = []
        def failing_write(fd, manifest):
            count.append(1)
            if len(count) == 2:
                failed.append(True)
                raise OSError("simulated disk error")
            return original_write(fd, manifest)
        def unreadable(name, **kwargs):
            if name == "Browser-SingletonSocket" and failed:
                raise PermissionError("cannot read backup")
            return original_readlink(name, **kwargs)
        with patch.object(locks, "_write_manifest", side_effect=failing_write), \
                patch.object(locks.os, "readlink", side_effect=unreadable):
            with self.assertRaisesRegex(Blocked, "恢复记录"):
                locks.repair(self.config, "A")
        manifest_path = next((self.base / "browser-lock-backups").glob("*/manifest.json"))
        self.assertEqual(json.loads(manifest_path.read_text())["status"], "recovery_required")
        self.assertEqual(os.readlink(manifest_path.parent / "Browser-SingletonSocket"), targets["SingletonSocket"])

    def test_huge_pid_is_rejected_without_process_probe(self):
        for pid in ("9999999999", "9" * 5000):
            with self.subTest(length=len(pid)), patch.object(locks, "_pid_absent") as probe:
                with self.assertRaises(Blocked):
                    locks._assert_stale({"SingletonLock": {"target": "test-host-" + pid}})
                probe.assert_not_called()

    def test_stale_socket_target_is_probed_repeatedly_without_being_deleted(self):
        targets = self.stale()
        target = Path(targets["SingletonSocket"])
        state = (1, 22, stat.S_IFSOCK | 0o600, os.getuid(), 1, 0, 50, 60)
        with patch.object(locks, "_socket_state", return_value=state) as probe:
            result = locks.repair(self.config, "A")
        self.assertEqual(result["removed_count"], 3)
        self.assertGreaterEqual(probe.call_count, 5)
        self.assertTrue(all(call.args == (target,) for call in probe.call_args_list))

    def test_socket_identity_change_before_move_leaves_links_untouched(self):
        self.stale()
        with patch.object(locks, "_socket_state", side_effect=[(1, 2), (1, 3)]):
            with self.assertRaises(Blocked):
                locks.repair(self.config, "A")
        self.assertTrue((self.browser / "SingletonLock").is_symlink())
        self.assertTrue((self.browser / "SingletonSocket").is_symlink())

    def test_new_profile_during_repair_is_not_ignored(self):
        self.stale()
        for file in self.oauth.glob("Default/*"):
            file.unlink()
        (self.oauth / "Default").rmdir()
        self.oauth.rmdir()
        def new_profile():
            self.oauth.mkdir(exist_ok=True)
            return [(1, 0, "launchd")]
        with patch.object(locks, "_processes", side_effect=new_profile):
            with self.assertRaises(Blocked):
                locks.repair(self.config, "A")
        self.assertTrue((self.browser / "SingletonLock").is_symlink())


class SocketProbeTests(unittest.TestCase):
    def setUp(self):
        self.path = Path("/private/tmp/browser-test/SingletonSocket")
        self.info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFSOCK | 0o600,
                                    st_uid=os.getuid(), st_nlink=1, st_size=0,
                                    st_mtime_ns=4, st_ctime_ns=5)

    def test_refused_socket_is_stale_without_sending_data(self):
        with patch.object(Path, "lstat", return_value=self.info), patch.object(locks.socket, "socket") as factory:
            probe = factory.return_value.__enter__.return_value
            probe.connect.side_effect = ConnectionRefusedError(errno.ECONNREFUSED, "refused")
            self.assertEqual(locks._socket_state(self.path), locks._identity(self.info))
            probe.settimeout.assert_called_once_with(0.3)
            probe.connect.assert_called_once_with(str(self.path))
            probe.send.assert_not_called()
            probe.sendall.assert_not_called()

    def test_success_timeout_or_permissions_are_not_considered_stale(self):
        for error in (None, TimeoutError("timeout"), PermissionError(errno.EACCES, "denied")):
            with self.subTest(error=error), patch.object(Path, "lstat", return_value=self.info), \
                    patch.object(locks.socket, "socket") as factory:
                factory.return_value.__enter__.return_value.connect.side_effect = error
                with self.assertRaises(Blocked):
                    locks._socket_state(self.path)

    def test_socket_owner_type_and_post_probe_identity_are_checked(self):
        for field, value in (("st_uid", os.getuid() + 1), ("st_mode", stat.S_IFREG | 0o600), ("st_nlink", 2)):
            changed = SimpleNamespace(**vars(self.info))
            setattr(changed, field, value)
            with self.subTest(field=field), patch.object(Path, "lstat", return_value=changed), \
                    patch.object(locks.socket, "socket") as factory:
                with self.assertRaises(Blocked):
                    locks._socket_state(self.path)
                factory.assert_not_called()
        changed = SimpleNamespace(**vars(self.info))
        changed.st_ino += 1
        with patch.object(Path, "lstat", side_effect=[self.info, changed]), patch.object(locks.socket, "socket") as factory:
            factory.return_value.__enter__.return_value.connect.side_effect = ConnectionRefusedError(errno.ECONNREFUSED, "refused")
            with self.assertRaises(Blocked):
                locks._socket_state(self.path)


class ProcessQueryTests(unittest.TestCase):
    def test_ps_is_wide_and_validates_failure_or_malformed_output(self):
        with patch.object(locks.subprocess, "run", return_value=subprocess.CompletedProcess([], 0,
                "  1 0 0 /sbin/launchd\n 42 1 501 /Some path/Browser\n", "")) as run:
            self.assertEqual(locks._processes(), [(1, 0, "/sbin/launchd"), (42, 1, "/Some path/Browser")])
            self.assertIn("-ww", run.call_args.args[0])
        for result in (subprocess.CompletedProcess([], 1, "anything", "denied"),
                       subprocess.CompletedProcess([], 0, "", ""),
                       subprocess.CompletedProcess([], 0, "malformed", "")):
            with self.subTest(result=result), patch.object(locks.subprocess, "run", return_value=result):
                with self.assertRaises(Blocked):
                    locks._processes()

    def test_macos_nobody_negative_uid_is_a_valid_process_row(self):
        result = subprocess.CompletedProcess([], 0,
            "  1 0 0 /sbin/launchd\n 642 1 -2 /usr/libexec/example-daemon\n", "")
        with patch.object(locks.subprocess, "run", return_value=result):
            self.assertEqual(locks._processes(),
                             [(1, 0, "/sbin/launchd"), (642, 1, "/usr/libexec/example-daemon")])
        for row in ("-642 1 -2 daemon", "642 -1 -2 daemon", "642 1 nobody daemon", "642 1 --2 daemon"):
            with self.subTest(row=row), patch.object(locks.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, row, "")):
                with self.assertRaises(Blocked):
                    locks._processes()

    def test_pid_permission_denied_is_alive(self):
        with patch.object(locks.os, "kill", side_effect=PermissionError):
            self.assertFalse(locks._pid_absent(42))
        with patch.object(locks.os, "kill", side_effect=ProcessLookupError):
            self.assertTrue(locks._pid_absent(42))


if __name__ == "__main__":
    unittest.main()
