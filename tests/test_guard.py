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
from surge_cc import core, guard, workspaces
from surge_cc.core import Blocked
from test_core import config, FakeSurge


class RuntimeCheckerTests(unittest.TestCase):
    def setUp(self):
        self.surge = FakeSurge()
        self.listener = Mock(return_value=True)
        self.preflight = Mock(return_value={"ok": True})
        self.checker = guard.RuntimeChecker(config(), process="/test/claude",
                                           surge=self.surge, listener=self.listener,
                                           preflight=self.preflight)

    def test_valid_snapshot_and_all_routes(self):
        self.checker.check(include_exit=False)
        self.assertEqual({host for host, process in self.surge.route_calls}, set(config()["hosts"]))
        self.assertEqual(self.surge.exit_calls, 0)
        self.checker.check(include_exit=True)
        self.assertEqual(self.surge.exit_calls, 1)

    def test_mode_change_blocks(self):
        for mode in ("direct", "global", None):
            with self.subTest(mode=mode):
                self.surge.status_value["mode"] = mode
                with self.assertRaises(Blocked):
                    self.checker.check()

    def test_global_mode_suspends_without_rule_or_exit_checks(self):
        self.surge.status_value["mode"] = "proxy"
        before = self.surge.group_calls
        self.checker.check(include_exit=True)
        self.assertIs(self.checker.suspended, True)
        self.assertEqual(self.surge.group_calls, before)
        self.assertEqual(self.surge.route_calls, [])
        self.assertEqual(self.surge.exit_calls, 0)
        self.listener.assert_not_called()

    def test_global_start_does_not_need_fixed_topology(self):
        self.surge.status_value.update(mode="proxy", **{"profile-path": "/test/other.conf"})
        self.surge.group_value = None
        checker = guard.RuntimeChecker(config(), process="/test/claude", surge=self.surge,
                                       listener=self.listener, preflight=self.preflight)
        checker.check(include_exit=True)
        self.assertTrue(checker.suspended)
        self.assertIsNone(checker.digest)
        self.assertEqual(self.surge.group_calls, 1)  # only setUp's rule-mode baseline
        self.listener.assert_not_called()

    def test_rule_resume_rechecks_full_gate_and_exit_before_restoring_protection(self):
        self.surge.status_value["mode"] = "proxy"
        self.checker.check()
        self.surge.status_value["mode"] = "rule"
        self.checker.check(include_exit=False)
        self.assertFalse(self.checker.suspended)
        self.preflight.assert_called_once_with(config(), surge=self.surge,
                                               claude_path=Path("/test/claude"))
        self.assertEqual(self.surge.exit_calls, 1)

    def test_first_rule_resume_builds_baseline_only_after_full_checks(self):
        self.surge.status_value["mode"] = "proxy"
        checker = guard.RuntimeChecker(config(), process="/test/claude", surge=self.surge,
                                       listener=self.listener, preflight=self.preflight)
        self.surge.status_value["mode"] = "rule"
        self.surge.exit_value = False
        with self.assertRaises(Blocked):
            checker.check()
        self.assertIsNone(checker.digest)
        self.assertTrue(checker.suspended)
        self.surge.exit_value = True
        checker.check()
        self.assertIsNotNone(checker.digest)
        self.assertFalse(checker.suspended)

    def test_resume_rejects_failed_full_gate_changed_baseline_and_direct_mode(self):
        for change in ("preflight", "profile", "direct", "unknown"):
            with self.subTest(change=change):
                self.setUp()
                self.surge.status_value["mode"] = "proxy"
                self.checker.check()
                self.surge.status_value["mode"] = "rule"
                if change == "preflight":
                    self.preflight.return_value = {"ok": False}
                elif change == "profile":
                    self.surge.profile_value += "\n[General]\nipv6=true\n"
                else:
                    self.surge.status_value["mode"] = "direct" if change == "direct" else "unknown"
                with self.assertRaises(Blocked):
                    self.checker.check()

    def test_switch_to_global_during_exit_probe_suspends_instead_of_stopping(self):
        def switch(cfg):
            self.surge.status_value["mode"] = "proxy"
            return False
        self.surge.exit_matches = switch
        self.checker.check(include_exit=True)
        self.assertTrue(self.checker.suspended)

    def test_switch_to_global_during_route_or_scope_probe_suspends(self):
        def switch(*args):
            self.surge.status_value["mode"] = "proxy"
            raise Blocked("rule changed during probe")
        self.surge.route = switch
        self.checker.check()
        self.assertTrue(self.checker.suspended)

    def test_switch_to_global_during_initial_snapshot_suspends(self):
        def switch(*args):
            self.surge.status_value["mode"] = "proxy"
            raise Blocked("group unavailable")
        self.surge.group = switch
        checker = guard.RuntimeChecker(config(), process="/test/claude", surge=self.surge)
        self.assertTrue(checker.suspended)
        self.assertIsNone(checker.digest)

    def test_switch_to_global_at_final_snapshot_suspends(self):
        self.surge.final_mode = "proxy"
        self.surge.status_calls = 0
        self.checker.check()
        self.assertTrue(self.checker.suspended)

    def test_malformed_global_status_does_not_suspend(self):
        self.surge.status_value.update(mode="proxy", features=None)
        with self.assertRaises(Blocked):
            self.checker.check()
        self.assertFalse(self.checker.suspended)

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


class BrowserRuntimeCheckerTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(config(), browser_path="/test/Surge CC Browser.app/Contents/MacOS/Google Chrome",
                           proxy_url="http://127.0.0.1:62919")
        self.surge = FakeSurge()
        self.surge.status_value["features"]["enhanced-mode"] = True
        self.listener = Mock(return_value=True)
        self.exit_probe = Mock(return_value=True)
        scope = patch("surge_cc.containment.validate_scope")
        self.scope = scope.start()
        self.addCleanup(scope.stop)

    def checker(self):
        return guard.BrowserRuntimeChecker(self.config, process=self.config["browser_path"],
                                            surge=self.surge, listener=self.listener,
                                            exit_probe=self.exit_probe)

    def test_warm_check_keeps_scope_and_listener_without_external_exit_query(self):
        checker = self.checker()
        checker.check(include_exit=False)
        self.scope.assert_called_once_with(self.config, self.surge)
        self.listener.assert_called_once_with(self.config)
        self.exit_probe.assert_not_called()
        self.assertEqual(self.surge.exit_calls, 0)
        self.assertEqual({host for host, _ in self.surge.route_calls}, set(self.config["hosts"]))

    def test_cold_check_uses_exactly_one_actual_listener_exit_probe(self):
        self.checker().check(include_exit=True)
        self.exit_probe.assert_called_once_with(self.config)
        self.assertEqual(self.surge.exit_calls, 0)

    def test_default_exit_probe_uses_dedicated_listener_and_general_browser_error(self):
        with patch("surge_cc.oauth_gate.verify_proxy_exit") as actual:
            self.assertTrue(guard.BrowserRuntimeChecker._proxy_exit(self.config))
            actual.assert_called_once_with(self.config)
            actual.side_effect = Blocked("OAuth-specific error")
            with self.assertRaisesRegex(Blocked, "专用浏览器入口"):
                guard.BrowserRuntimeChecker._proxy_exit(self.config)

    def test_no_personal_browser_default(self):
        with self.assertRaisesRegex(Blocked, "专用浏览器路径"):
            guard.BrowserRuntimeChecker(config(), process="/Applications/Google Chrome.app")

    def test_global_direct_or_unknown_mode_cannot_start(self):
        for mode in ("proxy", "direct", None):
            with self.subTest(mode=mode):
                self.surge.status_value["mode"] = mode
                with self.assertRaises(Blocked):
                    self.checker()
        self.exit_probe.assert_not_called()

    def test_global_transition_before_and_after_probe_is_not_suspended(self):
        for phase in ("before", "route", "exit", "final"):
            with self.subTest(phase=phase):
                self.surge = FakeSurge()
                self.surge.status_value["features"]["enhanced-mode"] = True
                checker = self.checker()
                if phase == "before":
                    self.surge.status_value["mode"] = "proxy"
                elif phase == "route":
                    def route(*args):
                        self.surge.status_value["mode"] = "proxy"
                        raise Blocked("scope changed")
                    self.surge.route = route
                elif phase == "exit":
                    def exit_probe(cfg):
                        self.surge.status_value["mode"] = "proxy"
                        return True
                    checker.exit_probe = exit_probe
                else:
                    self.surge.status_calls = 0
                    self.surge.final_mode = "proxy"
                with self.assertRaises(Blocked):
                    checker.check(include_exit=True)
                self.assertFalse(checker.suspended)

    def test_exit_failure_and_post_probe_drift_block(self):
        for outcome in (False, None, Blocked("offline"), "changed"):
            with self.subTest(outcome=outcome):
                checker = self.checker()
                def exit_probe(cfg):
                    if isinstance(outcome, Exception):
                        raise outcome
                    if outcome == "changed":
                        self.surge.profile_value += "\n[General]\nipv6=true\n"
                        return True
                    return outcome
                checker.exit_probe = exit_probe
                with self.assertRaises(Blocked):
                    checker.check(include_exit=True)

    def test_missing_scope_listener_or_enhanced_mode_still_blocks_warm(self):
        for failure in ("scope", "listener", "enhanced"):
            with self.subTest(failure=failure):
                self.scope.side_effect = None
                self.listener.return_value = True
                self.surge.status_value["features"]["enhanced-mode"] = True
                checker = self.checker()
                if failure == "scope":
                    self.scope.side_effect = Blocked("raw path not rejected")
                elif failure == "listener":
                    self.listener.return_value = False
                else:
                    self.surge.status_value["features"]["enhanced-mode"] = False
                with self.assertRaises(Blocked):
                    checker.check(include_exit=False)
        self.exit_probe.assert_not_called()


class StateTests(unittest.TestCase):
    def test_private_atomic_whitelisted_receipt(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / "state" / "state.json"
            guard.write_state(path, target="web", state="running", ok=True, detail="ready")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            data = json.loads(path.read_text())
            self.assertEqual(set(data), {"schema", "target", "state", "ok", "checked_at", "detail", "web_guard_version"})
            self.assertEqual(data["web_guard_version"], 2)
            self.assertNotIn("203.0.113.10", path.read_text())
            self.assertFalse(list(path.parent.glob(".surge-cc-guard-*")))

    def test_web_generation_marker_does_not_change_code_receipts(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / "state.json"
            for state in ("running", "blocked", "exited"):
                guard.write_state(path, target="web", state=state, ok=False, detail="test")
                self.assertEqual(json.loads(path.read_text())["web_guard_version"], 2)
            guard.write_state(path, target="code", state="running", ok=True, detail="test")
            self.assertNotIn("web_guard_version", json.loads(path.read_text()))

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
        command = changes.pop("command", None)
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
        if options["target"] == "web":
            loc = workspaces.paths(Path(directory) / "config.json", "A")
            options.setdefault("lock_path", loc["lock"])
            command = command or core.chrome_args(options["config"], loc["browser"])
        result = guard.run_guarded(command or ["/test/claude", "SECRET_ARGUMENT"], **options)
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

    def test_explicit_global_exception_launches_but_receipt_does_not_claim_protection(self):
        surge = FakeSurge()
        surge.status_value["mode"] = "proxy"
        report = core.run_checks(config(), surge=surge)
        checker = Mock(suspended=True)
        def monitor(child, checked, **kwargs):
            status = json.loads(kwargs["status_path"].read_text())
            self.assertEqual(status["state"], "suspended")
            self.assertIs(status["ok"], False)
            self.assertIn("挂起", status["detail"])
            return 0
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            result, options, child = self.run_fixture(
                directory, preflight=Mock(return_value=report), checker=checker, monitor=monitor)
            self.assertEqual(result, 0)
            options["popen"].assert_called_once()
            receipt = json.loads(options["receipt_path"].read_text())
            self.assertEqual(receipt["state"], "running")
            self.assertIs(receipt["ok"], True)
            self.assertIn("保护已挂起", receipt["detail"])
            self.assertIs(receipt["suspended"], True)
            self.assertIs(receipt["protection_active"], False)

    def test_old_pause_or_incomplete_exception_never_launches(self):
        for report in ({"ok": False, "paused": True, "pause_reason": "surge-mode"},
                       {"ok": False, "paused": True, "launch_allowed": True,
                        "protection_active": False, "surge_mode": "proxy"}):
            with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
                result, options, child = self.run_fixture(directory, preflight=Mock(return_value=report))
                self.assertEqual(result, 2)
                options["popen"].assert_not_called()

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

    def test_web_default_gate_has_one_strict_checker_and_no_redundant_preflight(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            child = Mock(pid=78201)
            child.wait.side_effect = subprocess.TimeoutExpired("browser", .8)
            checker = Mock(suspended=False)
            with patch.object(guard, "BrowserRuntimeChecker", return_value=checker) as factory, \
                    patch.object(guard, "RuntimeChecker") as ordinary, \
                    patch.object(guard, "run_checks") as duplicate:
                result, options, _ = self.run_fixture(
                    directory, target="web", checker=None, preflight=duplicate,
                    popen=Mock(return_value=child))
            self.assertEqual(result, 0)
            duplicate.assert_not_called()
            ordinary.assert_not_called()
            factory.assert_called_once()
            checker.check.assert_called_once_with(include_exit=True)
            receipt = json.loads(options["receipt_path"].read_text())
            self.assertEqual(receipt["web_guard_version"], 2)
            self.assertTrue(receipt["protection_active"])
            self.assertFalse(receipt["suspended"])

    def test_web_custom_preflight_is_honored_but_global_is_never_allowed(self):
        surge = FakeSurge()
        surge.status_value["mode"] = "proxy"
        reports = [core.run_checks(config(), surge=surge), {"ok": False},
                   {"ok": True, "paused": True}, {"ok": True, "suspended": True},
                   {"ok": True, "protection_active": False}, {"ok": True, "surge_mode": "proxy"}]
        for report in reports:
            with self.subTest(report=report), tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
                preflight = Mock(return_value=report)
                result, options, _ = self.run_fixture(directory, target="web", preflight=preflight)
                self.assertEqual(result, 2)
                preflight.assert_called_once()
                options["popen"].assert_not_called()
                options["checker"].check.assert_not_called()

    def test_web_checker_failure_or_suspension_never_spawns(self):
        for failure in ("offline", "suspended"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
                checker = Mock(suspended=failure == "suspended")
                if failure == "offline":
                    checker.check.side_effect = Blocked("dedicated listener offline")
                result, options, _ = self.run_fixture(directory, target="web", checker=checker)
                self.assertEqual(result, 2)
                options["popen"].assert_not_called()
                options["stop"].assert_called_once_with(None)

    def test_web_runtime_failure_only_stops_owned_browser(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            command = [sys.executable, "-c", "import time; time.sleep(60)"]
            unrelated = subprocess.Popen(command)
            owned = []
            def spawn(*args, **kwargs):
                child = subprocess.Popen(*args, **kwargs)
                owned.append(child)
                return child
            try:
                with patch.object(guard, "chrome_args", return_value=command):
                    result, options, _ = self.run_fixture(
                        directory, target="web", command=command, popen=spawn,
                        stop=guard.stop_owned_child,
                        monitor=Mock(side_effect=Blocked("SixtyNet exit offline")))
                self.assertEqual(result, 2)
                self.assertEqual(len(owned), 1)
                self.assertIsNotNone(owned[0].poll())
                self.assertIsNone(unrelated.poll())
                self.assertEqual(json.loads(options["status_path"].read_text())["state"], "blocked")
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=2)
                for child in owned:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=2)

    def test_web_browser_lease_held_from_preferences_through_owned_process_exit(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            root = Path(directory)
            loc = workspaces.paths(root / "config.json", "A")
            child = Mock(pid=78201)
            child.poll.return_value = None
            child.wait.side_effect = subprocess.TimeoutExpired("browser", .8)
            def inspect_lease(*args, **kwargs):
                self.assertTrue((loc["browser"] / "Default/Preferences").exists())
                with self.assertRaisesRegex(Blocked, "关闭专用窗口"):
                    workspaces.prepare_oauth_browser(root / "config.json", config())
                return 0
            result, options, _ = self.run_fixture(
                directory, target="web", popen=Mock(return_value=child),
                preflight=Mock(side_effect=lambda cfg: (inspect_lease() or {"ok": True})),
                monitor=Mock(side_effect=inspect_lease), stop=Mock(side_effect=inspect_lease))
            self.assertEqual(result, 0)
            self.assertIn("--profile-directory=Default", options["popen"].call_args.args[0])
            with workspaces.browser_session(loc["root"], config()):
                pass

    def test_web_rejects_empty_or_changed_profile_before_spawn(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            loc = workspaces.paths(Path(directory) / "config.json", "A")
            original = core.chrome_args(config(), loc["browser"])
            for command in ([v.replace("=Default", "=Profile 1") for v in original],
                            core.chrome_args(config(), loc["data"] / "OAuthBrowser"),
                            original + ["--user-data-dir=/private/empty"]):
                with self.subTest(command=command):
                    result, options, _ = self.run_fixture(directory, target="web", command=command)
                    self.assertEqual(result, 2)
                    options["popen"].assert_not_called()

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

    def test_supervision_records_suspended_then_resumes_without_stopping_child(self):
        current = [0.0]
        child = Mock()
        child.poll.side_effect = lambda: 0 if current[0] >= 2.2 else None
        def sleep(seconds):
            current[0] += seconds
        checker = Mock(suspended=False)
        def check(**kwargs):
            checker.suspended = current[0] < 2
        checker.check.side_effect = check
        with patch.object(guard, "write_state") as record:
            result = guard.supervise(child, checker, target="code", interval=1, exit_interval=3,
                                     clock=lambda: current[0], sleep=sleep)
        self.assertEqual(result, 0)
        states = [call.kwargs for call in record.call_args_list]
        self.assertEqual([s["state"] for s in states], ["suspended", "running", "exited"])
        self.assertFalse(states[0]["ok"])
        self.assertTrue(states[1]["ok"])
        child.terminate.assert_not_called()

    def test_web_supervision_cannot_continue_with_suspended_checker(self):
        current = [0.0]
        child = Mock()
        child.poll.return_value = None
        checker = Mock(suspended=True)
        def sleep(seconds):
            current[0] += seconds
        with self.assertRaisesRegex(Blocked, "固定线路保护已停止"):
            guard.supervise(child, checker, target="web", interval=1, exit_interval=3,
                            clock=lambda: current[0], sleep=sleep)

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

    def test_real_owned_child_survives_global_transition_and_resumes_rule_checks(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            surge = FakeSurge()
            full = Mock(return_value={"ok": True})
            checker = guard.RuntimeChecker(config(), process=sys.executable, surge=surge,
                                           listener=Mock(return_value=True), preflight=full)
            children = []
            def spawn(command, **kwargs):
                child = subprocess.Popen(command, stdin=subprocess.PIPE, **kwargs)
                children.append(child)
                return child
            states = []
            alive_states = []
            released = False
            writer = guard.write_state
            def capture(path, **kwargs):
                nonlocal released
                state = kwargs["state"]
                states.append(state)
                if children and children[0].poll() is None:
                    alive_states.append(state)
                    # Each transition is acknowledged by the real supervisor
                    # before advancing. No short wall-clock mode window can be
                    # missed when the CI runner delays process scheduling.
                    if state == "suspended":
                        surge.status_value["mode"] = "rule"
                    elif state == "running" and "suspended" not in states:
                        surge.status_value["mode"] = "proxy"
                    elif state == "running" and not released:
                        children[0].stdin.write(b"x")
                        children[0].stdin.close()
                        released = True
                return writer(path, **kwargs)
            try:
                with patch.object(guard, "write_state", side_effect=capture):
                    result = guard.run_guarded(
                        [sys.executable, "-c",
                         "import select,sys; ready,_,_=select.select([sys.stdin],[],[],10); "
                         "sys.exit(0 if ready and sys.stdin.buffer.read(1)==b'x' else 3)"],
                        env=dict(os.environ), cwd=Path(directory), config=config(), target="code",
                        preflight=Mock(return_value={"ok": True}), checker=checker,
                        popen=spawn, interval=.01, exit_interval=.03)
            finally:
                for child in children:
                    child.stdin.close()
            self.assertEqual(result, 0)
            self.assertEqual(children[0].returncode, 0)
            self.assertIn("suspended", states)
            self.assertIn("running", states[states.index("suspended") + 1:])
            self.assertIn("suspended", alive_states)
            self.assertIn("running", alive_states[alive_states.index("suspended") + 1:])
            self.assertTrue(released)
            full.assert_called_once()
            self.assertFalse(checker.suspended)

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
