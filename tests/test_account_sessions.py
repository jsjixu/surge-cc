"""Offline account stop requests operate on owned supervisors, never saved PIDs."""
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_core import config
from surge_cc import core, guard, sessions, workspaces
from surge_cc.core import Blocked, load_config, save_config


class AccountSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "config.json"
        self.config = save_config(self.path, config())
        self.loc = workspaces.paths(self.path, "A")

    def update_generation(self):
        workspaces.write_json(self.loc["root"] / ".stop-generation.json",
                              {"generation": "a" * 32})

    def test_generation_is_private_and_stop_never_reads_or_signals_receipt_pid(self):
        receipts = self.path.parent / "sessions"
        receipts.mkdir()
        (receipts / "forged.status.json").write_text('{"pid":12345,"process":"Google Chrome"}')
        with patch.object(os, "kill") as kill, patch.object(os, "killpg") as killpg:
            sessions.stop_workspace(self.path, "A", timeout=0)
        kill.assert_not_called()
        killpg.assert_not_called()
        token = sessions.generation(self.loc["root"])
        self.assertEqual(len(token), 32)
        self.assertEqual((self.loc["root"] / ".stop-generation.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((receipts / "forged.status.json").read_text(),
                         '{"pid":12345,"process":"Google Chrome"}')

    def test_invalid_generation_stops_checks_instead_of_ignoring_request(self):
        file = self.loc["root"] / ".stop-generation.json"
        for data in ({"generation": "wrong"}, {"generation": 123}, [], None):
            with self.subTest(data=data):
                file.write_text(json.dumps(data))
                file.chmod(0o600)
                with self.assertRaises(Blocked):
                    sessions.generation(self.loc["root"])
        self.update_generation()
        file.chmod(0o644)
        with self.assertRaises(Blocked):
            sessions.generation(self.loc["root"])

    def test_symlink_generation_is_not_overwritten(self):
        outside = self.path.parent / "not-owned"
        outside.write_text("unchanged")
        (self.loc["root"] / ".stop-generation.json").symlink_to(outside)
        with self.assertRaises(Blocked):
            sessions.stop_workspace(self.path, "A", timeout=0)
        self.assertEqual(outside.read_text(), "unchanged")

    def test_request_during_underlying_network_check_is_detected(self):
        checker = Mock(suspended=True)
        wrapped = sessions.SessionChecker(checker, self.loc["root"], "")
        checker.check.side_effect = lambda **kwargs: self.update_generation()
        with self.assertRaisesRegex(Blocked, "切换账号"):
            wrapped.check(include_exit=True)
        checker.check.assert_called_once_with(include_exit=True)
        self.assertTrue(wrapped.suspended)

    def test_stop_request_is_seen_before_network_poll_even_in_global_mode(self):
        checker = Mock(suspended=True)
        wrapped = sessions.SessionChecker(checker, self.loc["root"], "")
        self.update_generation()
        child = Mock()
        child.poll.return_value = None
        with self.assertRaisesRegex(Blocked, "切换账号"):
            guard.supervise(child, wrapped, target="code", interval=60, exit_interval=60,
                            clock=lambda: 0, sleep=Mock())
        checker.check.assert_not_called()
        child.poll.assert_not_called()

    def test_global_guard_stops_only_owned_child_on_account_request(self):
        child = Mock(pid=78201)
        child.poll.return_value = None
        stop = Mock()
        checker = Mock(suspended=True)

        def monitor(owned, wrapped, **kwargs):
            self.assertIs(owned, child)
            self.assertIsInstance(wrapped, sessions.SessionChecker)
            self.update_generation()
            return guard.supervise(owned, wrapped, **kwargs, clock=lambda: 0, sleep=Mock())

        report = core._global_mode_report(self.config)
        code = guard.run_guarded(
            ["/test/claude"], env={}, cwd=self.path.parent, config=self.config, target="code",
            preflight=Mock(return_value=report), checker=checker, popen=Mock(return_value=child),
            monitor=monitor, stop=stop, lock_path=self.loc["lock"],
            status_path=self.path.parent / "status.json")
        self.assertEqual(code, 2)
        stop.assert_called_once_with(child)
        state = json.loads((self.path.parent / "status.json").read_text())
        self.assertEqual(state["state"], "blocked")
        self.assertIn("切换账号", state["detail"])
        with self.loc["lock"].open("r+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_switch_waits_until_old_session_releases_before_account_commit(self):
        events = []
        with self.loc["lock"].open("a") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)

            def tick(_duration):
                self.assertEqual(load_config(self.path)["workspace"], "A")
                self.assertTrue(sessions.generation(self.loc["root"]))
                events.append("old-exited")
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

            def activate(old, target):
                self.assertEqual(events, ["old-exited"])
                self.assertEqual(load_config(self.path)["workspace"], "A")
                events.append("route-ready")
                return lambda: None

            with patch.object(sessions.time, "sleep", side_effect=tick):
                result = workspaces.use(self.path, self.config, "B",
                                        stop_sessions=sessions.stop_workspace, apply_route=activate)
        self.assertEqual(events, ["old-exited", "route-ready"])
        self.assertEqual(result["workspace"], "B")

    def test_timeout_keeps_account_and_does_not_change_route(self):
        activate = Mock()
        with self.loc["lock"].open("a") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            with self.assertRaisesRegex(Blocked, "账号保持原状"):
                workspaces.use(self.path, self.config, "B",
                    stop_sessions=lambda path, name: sessions.stop_workspace(path, name, timeout=0),
                    apply_route=activate)
        self.assertEqual(load_config(self.path), self.config)
        activate.assert_not_called()

    def test_unknown_chrome_after_supervisor_exit_prevents_switch(self):
        (self.loc["browser"] / "SingletonLock").symlink_to("unknown-host-12345")
        with patch("surge_cc.browser_locks.repair", side_effect=Blocked("unknown browser")) as repair:
            with self.assertRaisesRegex(Blocked, "unknown browser"):
                workspaces.use(self.path, self.config, "B", stop_sessions=sessions.stop_workspace)
        repair.assert_called_once_with(self.path, "A")
        self.assertEqual(load_config(self.path), self.config)

    def run_guard(self, *, child, stop, popen=None):
        return guard.run_guarded(
            ["/test/claude"], env={}, cwd=self.path.parent, config=self.config, target="code",
            preflight=Mock(return_value={"ok": True}), checker=Mock(suspended=False),
            popen=popen or Mock(return_value=child), monitor=Mock(return_value=0), stop=stop,
            lock_path=self.loc["lock"], status_path=self.path.parent / "status.json")

    def test_owner_latch_is_private_created_before_spawn_and_removed_after_confirmed_stop(self):
        child = Mock(pid=78201)
        def spawn(*args, **kwargs):
            markers = list(self.loc["root"].glob(".stop-failed-*.json"))
            self.assertEqual(len(markers), 1)
            self.assertEqual(markers[0].stat().st_mode & 0o777, 0o600)
            self.assertNotIn("pid", markers[0].read_text())
            self.assertNotIn("token", markers[0].read_text())
            return child
        code = self.run_guard(child=child, stop=Mock(), popen=spawn)
        self.assertEqual(code, 0)
        self.assertEqual(list(self.loc["root"].glob(".stop-failed-*.json")), [])

    def test_failed_stop_keeps_session_lock_until_own_child_really_exits(self):
        child = Mock(pid=78201)
        observations = []
        def poll():
            observations.append("poll")
            self.assertTrue(list(self.loc["root"].glob(".stop-failed-*.json")))
            with self.loc["lock"].open("a") as fd:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = json.loads((self.path.parent / "status.json").read_text())
            self.assertEqual(state["state"], "stop_failed")
            self.assertIn("等待手动关闭", state["detail"])
            return None if len(observations) == 1 else 0
        child.poll.side_effect = poll
        code = self.run_guard(child=child, stop=Mock(side_effect=Blocked("still running")))
        self.assertEqual(code, 2)
        self.assertEqual(len(observations), 2)
        self.assertEqual(list(self.loc["root"].glob(".stop-failed-*.json")), [])
        with self.loc["lock"].open("a") as fd:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_interrupted_failed_stop_latches_switch_with_or_without_close_sessions(self):
        child = Mock(pid=78201)
        child.poll.return_value = None
        with patch.object(sessions, "await_owned_exit", side_effect=KeyboardInterrupt):
            code = self.run_guard(child=child, stop=Mock(side_effect=Blocked("still running")))
        self.assertEqual(code, 2)
        self.assertEqual(len(list(self.loc["root"].glob(".stop-failed-*.json"))), 1)
        # Kernel lock can be released on interrupt; its persistent latch must
        # stop both CLI switch paths rather than interpreting that as exit.
        for callback in (None, sessions.stop_workspace):
            with self.subTest(close_sessions=bool(callback)):
                with self.assertRaisesRegex(Blocked, "未确认退出"):
                    workspaces.use(self.path, self.config, "B", stop_sessions=callback)
        self.assertEqual(load_config(self.path), self.config)

    def test_termination_during_stop_also_keeps_latch_if_wait_is_interrupted(self):
        child = Mock(pid=78201)
        with patch.object(sessions, "await_owned_exit", side_effect=SystemExit):
            self.assertEqual(self.run_guard(child=child, stop=Mock(side_effect=KeyboardInterrupt)), 2)
        with self.assertRaisesRegex(Blocked, "未确认退出"):
            sessions.stop_workspace(self.path, "A", timeout=0)

    def test_clear_only_this_owners_marker_other_orphan_remains_blocking(self):
        mine = sessions.begin_owned_session(self.loc["root"])
        other = sessions.begin_owned_session(self.loc["root"])
        sessions.confirm_owned_exit(mine)
        self.assertFalse(mine.exists())
        self.assertTrue(other.exists())
        with self.assertRaisesRegex(Blocked, "未确认退出"):
            workspaces.use(self.path, self.config, "B")

    def test_unsafe_latch_is_never_ignored_or_used_to_signal_saved_pid(self):
        external = self.path.parent / "outside"
        external.write_text('{"pid":12345}')
        (self.loc["root"] / ".stop-failed-untrusted.json").symlink_to(external)
        with patch.object(os, "kill") as kill, patch.object(os, "killpg") as killpg:
            with self.assertRaises(Blocked):
                workspaces.use(self.path, self.config, "B", stop_sessions=sessions.stop_workspace)
        kill.assert_not_called()
        killpg.assert_not_called()
        self.assertEqual(external.read_text(), '{"pid":12345}')

    def test_failed_or_orphaned_owner_blocks_new_launch_without_spawning(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                marker = sessions.begin_owned_session(self.loc["root"])
                if failed:
                    sessions.mark_stop_failed(marker)
                child = Mock(pid=78201)
                popen = Mock(return_value=child)
                self.assertEqual(self.run_guard(child=child, stop=Mock(), popen=popen), 2)
                popen.assert_not_called()
                self.assertTrue(marker.exists())
                sessions.confirm_owned_exit(marker)

    def test_healthy_parallel_cli_is_allowed_but_failed_parallel_owner_is_not(self):
        with guard.session_lock(self.loc["lock"]):
            marker = sessions.begin_owned_session(self.loc["root"])
            with guard.session_lock(self.loc["lock"]):
                pass
            sessions.mark_stop_failed(marker)
            with self.assertRaisesRegex(Blocked, "未确认退出"):
                with guard.session_lock(self.loc["lock"]):
                    self.fail("failed owner was ignored")
            sessions.confirm_owned_exit(marker)


if __name__ == "__main__":
    unittest.main()
