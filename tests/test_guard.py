"""Offline tests for owned-process-only runtime protection."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import guard
from surge_cc.core import Blocked
from test_core import config, FakeSurge


class RuntimeCheckerTests(unittest.TestCase):
    def setUp(self):
        self.surge = FakeSurge()
        self.listener = Mock(return_value=True)
        self.checker = guard.RuntimeChecker(config(), process="/test/claude",
                                           surge=self.surge, listener=self.listener)

    def test_valid_snapshot_and_all_routes(self):
        self.checker.check(include_exit=False)
        self.assertEqual({host for host, process in self.surge.route_calls}, set(config()["hosts"]))
        self.assertEqual(self.surge.exit_calls, 0)
        self.checker.check(include_exit=True)
        self.assertEqual(self.surge.exit_calls, 1)

    def test_mode_change_blocks(self):
        self.surge.status_value["mode"] = "global"
        with self.assertRaises(Blocked):
            self.checker.check()

    def test_unknown_status_blocks(self):
        self.surge.status = Mock(side_effect=Blocked("offline"))
        with self.assertRaises(Blocked):
            self.checker.check()

    def test_missing_active_profile_blocks(self):
        self.surge.status_value["profile-path"] = None
        with self.assertRaises(Blocked):
            guard.RuntimeChecker(config(), process="/test/claude", surge=self.surge)

    def test_config_edit_blocks_even_when_topology_still_fixed(self):
        self.surge.profile_value += "\n[General]\nipv6=true\n"
        with self.assertRaises(Blocked):
            self.checker.check()

    def test_group_state_change_blocks(self):
        self.surge.group_value["selected"] = "DIRECT"
        with self.assertRaises(Blocked):
            self.checker.check()

    def test_moved_listener_blocks(self):
        self.listener.return_value = False
        with self.assertRaises(Blocked):
            self.checker.check()

    def test_changed_rule_blocks(self):
        self.surge.route_value["final"] = "DIRECT"
        with self.assertRaises(Blocked):
            self.checker.check()

    def test_unknown_or_changed_exit_blocks(self):
        for value in (False, None, Blocked("timeout")):
            with self.subTest(value=value), self.assertRaises(Blocked):
                self.surge.exit_value = value
                self.checker.check(include_exit=True)

    def test_post_exit_configuration_drift_blocks(self):
        def change_after_exit(cfg):
            self.surge.profile_value += "\n[General]\nipv6=true\n"
            return True
        self.surge.exit_matches = change_after_exit
        with self.assertRaises(Blocked):
            self.checker.check(include_exit=True)


class StateTests(unittest.TestCase):
    def test_private_atomic_whitelisted_receipt(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / "state" / "state.json"
            guard.write_state(path, target="web", state="running", ok=True, detail="ready")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            data = json.loads(path.read_text())
            self.assertEqual(set(data), {"schema", "target", "state", "ok", "checked_at", "detail"})
            self.assertNotIn("203.0.113.10", path.read_text())
            self.assertFalse(list(path.parent.glob(".surge-cc-guard-*")))

    def test_symlink_target_and_parent_refused(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("keep")
            link = root / "link"
            link.symlink_to(target)
            for path in (link,):
                with self.assertRaises(Blocked):
                    guard.write_state(path, target="web", state="running", ok=True, detail="ready")
            parent = root / "parent"
            parent.symlink_to(root)
            with self.assertRaises(Blocked):
                guard.write_state(parent / "state.json", target="web", state="running", ok=True, detail="ready")
            self.assertEqual(target.read_text(), "keep")

    def test_session_lock_excludes_snapshot_restore(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / ".session.lock"
            with guard.session_lock(path):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with path.open("r+") as other, self.assertRaises(BlockingIOError):
                    fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with path.open("r+") as other:
                fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(Blocked):
                    with guard.session_lock(path):
                        pass


class StopTests(unittest.TestCase):
    def child(self):
        child = Mock(pid=78201)
        child.poll.return_value = None
        return child

    def test_only_owned_group_terminated(self):
        child = self.child()
        kill = Mock()
        guard.stop_owned_child(child, killpg=kill, getpgid=Mock(return_value=child.pid))
        kill.assert_called_once_with(child.pid, signal.SIGTERM)
        child.wait.assert_called_once()

    def test_exited_child_never_signalled(self):
        child = self.child()
        child.poll.return_value = 0
        kill = Mock()
        guard.stop_owned_child(child, killpg=kill)
        kill.assert_not_called()

    def test_terminal_cancel_and_resize_forward_only_owned_group(self):
        child = self.child()
        kill = Mock()
        previous = signal.getsignal(signal.SIGINT)
        with guard.child_signals(lambda: child, killpg=kill, getpgid=Mock(return_value=child.pid)):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            signal.getsignal(signal.SIGWINCH)(signal.SIGWINCH, None)
            with self.assertRaises(guard.Interrupted):
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)
        self.assertEqual([call.args for call in kill.call_args_list],
                         [(child.pid, signal.SIGINT), (child.pid, signal.SIGWINCH)])

    def test_shared_group_does_not_receive_group_signal(self):
        child = self.child()
        kill = Mock()
        guard.stop_owned_child(child, killpg=kill, getpgid=Mock(return_value=78200))
        kill.assert_not_called()
        child.terminate.assert_called_once()

    def test_kill_escalation_requires_still_live_original_group(self):
        child = self.child()
        child.wait.side_effect = [subprocess.TimeoutExpired("owned", 2), 0]
        kill = Mock()
        guard.stop_owned_child(child, killpg=kill, getpgid=Mock(return_value=child.pid))
        self.assertEqual([call.args for call in kill.call_args_list],
                         [(child.pid, signal.SIGTERM), (child.pid, signal.SIGKILL)])

    def test_cannot_signal_self(self):
        child = self.child()
        child.pid = os.getpid()
        kill = Mock()
        with self.assertRaises(Blocked):
            guard.stop_owned_child(child, killpg=kill)
        kill.assert_not_called()


class RunGuardTests(unittest.TestCase):
    def run_fixture(self, directory, **changes):
        child = Mock(pid=78201)
        child.poll.return_value = None
        checker = Mock()
        options = dict(env={}, cwd=Path(directory), config=config(), target="code",
                       receipt_path=Path(directory) / "receipt.json",
                       status_path=Path(directory) / "status.json",
                       preflight=Mock(return_value={"ok": True}),
                       checker=checker, popen=Mock(return_value=child),
                       monitor=Mock(return_value=0), stop=Mock())
        options.update(changes)
        result = guard.run_guarded(["/test/claude", "SECRET_ARGUMENT"], **options)
        return result, options, child

    def test_starts_only_after_checks_and_owns_separate_session(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(directory)
            self.assertEqual(result, 0)
            options["checker"].check.assert_called_once_with(include_exit=True)
            self.assertTrue(options["popen"].call_args.kwargs["start_new_session"])
            options["stop"].assert_called_once_with(child)
            self.assertTrue(json.loads(options["receipt_path"].read_text())["ok"])
            self.assertNotIn("SECRET_ARGUMENT", options["status_path"].read_text())

    def test_failed_preflight_never_starts_process(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(directory, preflight=Mock(return_value={"ok": False}))
            self.assertEqual(result, 2)
            options["popen"].assert_not_called()
            self.assertFalse(json.loads(options["receipt_path"].read_text())["ok"])

    def test_oauth_owner_hook_receives_the_live_owned_child(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            callback = Mock()
            result, options, child = self.run_fixture(directory, on_started=callback)
            self.assertEqual(result, 0)
            callback.assert_called_once_with(child)

    def test_failed_oauth_owner_hook_stops_child_without_reporting_success(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(
                directory, on_started=Mock(side_effect=Blocked("OAuth owner unavailable")))
            self.assertEqual(result, 2)
            options["stop"].assert_called_once_with(child)
            options["monitor"].assert_not_called()
            self.assertFalse(json.loads(options["receipt_path"].read_text())["ok"])

    def test_runtime_failure_stops_child_and_writes_failed_status(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(directory,
                monitor=Mock(side_effect=Blocked("route changed")))
            self.assertEqual(result, 2)
            options["stop"].assert_called_once_with(child)
            state = json.loads(options["status_path"].read_text())
            self.assertEqual(state["state"], "blocked")
            self.assertFalse(state["ok"])

    def test_unknown_error_does_not_leak_arguments(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(directory,
                monitor=Mock(side_effect=RuntimeError("SECRET_ERROR")))
            self.assertEqual(result, 2)
            self.assertNotIn("SECRET_ERROR", options["status_path"].read_text())
            options["stop"].assert_called_once_with(child)

    def test_signal_stops_owned_child(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(directory,
                monitor=Mock(side_effect=guard.Interrupted(signal.SIGTERM)))
            self.assertEqual(result, 128 + signal.SIGTERM)
            options["stop"].assert_called_once_with(child)

    def test_failed_receipt_prevents_or_cleans_up_launch(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            target = Path(directory) / "target"
            target.write_text("keep")
            link = Path(directory) / "receipt.json"
            link.symlink_to(target)
            result, options, child = self.run_fixture(directory)
            self.assertEqual(result, 2)
            options["stop"].assert_called_once_with(child)
            self.assertEqual(target.read_text(), "keep")

    def test_web_handoff_not_claimed_as_guarded(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(directory, target="web")
            self.assertEqual(result, 2)
            options["monitor"].assert_not_called()
            self.assertFalse(json.loads(options["receipt_path"].read_text())["ok"])

    def test_invalid_interval_does_not_launch(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(directory, interval=0)
            self.assertEqual(result, 2)
            options["popen"].assert_not_called()

    def test_exclusive_workspace_lock_blocks_before_launch(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / ".session.lock"
            with path.open("w+") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                result, options, child = self.run_fixture(directory, lock_path=path)
                self.assertEqual(result, 2)
                options["popen"].assert_not_called()
                self.assertFalse(json.loads(options["receipt_path"].read_text())["ok"])


class SuperviseTests(unittest.TestCase):
    def test_checks_routes_each_interval_and_exit_less_often(self):
        current = [0.0]
        child = Mock()
        child.poll.side_effect = lambda: 0 if current[0] >= 3.2 else None
        def sleep(seconds):
            current[0] += seconds
        checker = Mock()
        result = guard.supervise(child, checker, target="code", interval=1, exit_interval=3,
                                 clock=lambda: current[0], sleep=sleep)
        self.assertEqual(result, 0)
        self.assertEqual([call.kwargs for call in checker.check.call_args_list],
                         [{"include_exit": False}, {"include_exit": False}, {"include_exit": True}])

    def test_check_failure_is_not_swallowed(self):
        child = Mock()
        child.poll.return_value = None
        checker = Mock()
        checker.check.side_effect = Blocked("offline")
        current = [0.0]
        def sleep(seconds):
            current[0] += seconds
        with self.assertRaises(Blocked):
            guard.supervise(child, checker, target="web", interval=1, exit_interval=3,
                            clock=lambda: current[0], sleep=sleep)

    def test_live_owned_process_stopped_without_touching_other_process(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            child_handles = []
            unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            def spawn(command, **kwargs):
                child = subprocess.Popen(command, **kwargs)
                child_handles.append(child)
                return child
            checker = Mock()
            checker.check.side_effect = [None, Blocked("simulated route change")]
            try:
                code = guard.run_guarded(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    env=dict(os.environ), cwd=Path(directory), config=config(), target="code",
                    status_path=Path(directory) / "status.json",
                    preflight=Mock(return_value={"ok": True}), checker=checker,
                    popen=spawn, interval=0.02, exit_interval=0.06,
                )
                self.assertEqual(code, 2)
                self.assertEqual(len(child_handles), 1)
                self.assertIsNotNone(child_handles[0].poll())
                self.assertIsNone(unrelated.poll())
                self.assertEqual(json.loads((Path(directory) / "status.json").read_text())["state"],
                                 "blocked")
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=2)
                for child in child_handles:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=2)

    def test_new_session_preserves_terminal_raw_input(self):
        master, slave = pty.openpty()
        source = (
            "import os,sys,termios,tty;"
            "original=termios.tcgetattr(0);tty.setraw(0);"
            "os.write(1,b'READY\\n');"
            "data=os.read(0,4);termios.tcsetattr(0,termios.TCSANOW,original);"
            "os.write(1,b'RAW_OK\\n' if data==b'test' else b'RAW_FAIL\\n')"
        )
        child = subprocess.Popen([sys.executable, "-c", source], stdin=slave, stdout=slave,
                                 stderr=slave, start_new_session=True)
        os.close(slave)
        output = b""
        deadline = time.monotonic() + 3
        try:
            while b"READY" not in output and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    output += os.read(master, 4096)
            self.assertIn(b"READY", output)
            os.write(master, b"test")
            while b"RAW_OK" not in output and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    output += os.read(master, 4096)
            self.assertIn(b"RAW_OK", output)
            self.assertEqual(child.wait(timeout=2), 0)
        finally:
            os.close(master)
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)


class WorkerTests(unittest.TestCase):
    def test_worker_uses_configured_interval_and_explicit_proxy(self):
        candidate = dict(config(), guard_interval=45)
        with patch.object(guard, "load_config", return_value=candidate), \
                patch.object(guard, "run_guarded", return_value=0) as runner:
            result = guard.main(["--config", "/test/config.json", "--receipt", "/test/receipt.json",
                                 "--status", "/test/status.json", "--cwd", "/test",
                                 "--target", "web", "--lock", "/test/.session.lock",
                                 "--", "/test/Chrome", "--test-fixture"])
        self.assertEqual(result, 0)
        self.assertEqual(runner.call_args.kwargs["interval"], 45)
        self.assertEqual(runner.call_args.kwargs["exit_interval"], 45)
        self.assertEqual(runner.call_args.kwargs["env"]["HTTPS_PROXY"], candidate["proxy_url"])
        self.assertEqual(runner.call_args.args[0], ["/test/Chrome", "--test-fixture"])
        self.assertEqual(runner.call_args.kwargs["lock_path"], Path("/test/.session.lock"))


if __name__ == "__main__":
    unittest.main()
