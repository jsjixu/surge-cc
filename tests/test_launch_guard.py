"""Detached worker launch: no unknown receipt may become a successful launch."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import cli, core, workspaces


def config():
    return core.validate_config({"schema": 1, "group": "Claude", "policy": "Home",
                                 "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:6152"})


class WorkerLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.path = self.folder / "config.json"
        self.loc = workspaces.paths(self.path, "A")
        self.worker = Mock()
        self.worker.poll.return_value = None

    def spawn_with_receipt(self, payload, raw=False):
        def spawn(argv, **kwargs):
            receipt = Path(argv[argv.index("--receipt") + 1])
            receipt.write_text(payload if raw else json.dumps(payload))
            return self.worker
        return Mock(side_effect=spawn)

    def test_valid_running_receipt_and_live_worker_succeeds(self):
        payload = {"schema": 1, "target": "web", "state": "running", "ok": True, "web_guard_version": 2,
                   "protection_active": True, "suspended": False}
        spawn = self.spawn_with_receipt(payload)
        result = cli.start_web_guard(config(), self.path, ["/test/Chrome", "--fixture"],
                                     self.loc, popen=spawn, timeout=0.1)
        self.assertEqual(result, payload)
        argv = spawn.call_args.args[0]
        self.assertEqual(argv[-3:], ["--", "/test/Chrome", "--fixture"])
        self.assertEqual(Path(argv[argv.index("--lock") + 1]), self.loc["lock"])
        self.assertEqual(spawn.call_args.kwargs["env"]["HTTPS_PROXY"], config()["proxy_url"])
        self.assertEqual(spawn.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        self.worker.terminate.assert_not_called()

    def test_suspended_runtime_receipt_stops_owned_worker(self):
        payload = {"schema": 1, "target": "web", "state": "running", "ok": True,
                   "web_guard_version": 2, "suspended": True, "protection_active": False}
        with self.assertRaises(core.Blocked):
            cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                               popen=self.spawn_with_receipt(payload), timeout=0.1)
        self.worker.terminate.assert_called_once()

    def test_old_running_receipt_requires_upgrade(self):
        payload = {"schema": 1, "target": "web", "state": "running", "ok": True}
        with self.assertRaises(core.Blocked):
            cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                               popen=self.spawn_with_receipt(payload), timeout=0.1)
        self.worker.terminate.assert_called_once()

    def test_unknown_receipt_never_succeeds_and_stops_owned_worker(self):
        for payload in ([], None, {}, {"schema": 1, "target": "web", "ok": True, "state": "unknown"},
                        {"schema": 2, "target": "web", "ok": True, "state": "running"},
                        {"schema": 1, "target": "code", "ok": True, "state": "running"},
                        {"schema": 1, "target": "web", "ok": 1, "state": "running"}):
            with self.subTest(payload=payload):
                self.worker.reset_mock()
                with self.assertRaises(core.Blocked):
                    cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                                        popen=self.spawn_with_receipt(payload), timeout=0.1)
                self.worker.terminate.assert_called_once()
                self.worker.wait.assert_called_once_with(timeout=5)
                self.worker.kill.assert_not_called()

    def test_malformed_receipt_fails_closed(self):
        with self.assertRaises(core.Blocked):
            cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                                popen=self.spawn_with_receipt("invalid JSON", raw=True), timeout=0.1)
        self.worker.terminate.assert_called_once()
        self.worker.kill.assert_not_called()

    def test_explicit_blocked_receipt_stops_live_worker(self):
        payload = {"schema": 1, "target": "web", "ok": False, "state": "blocked", "detail": "test blocked"}
        with self.assertRaisesRegex(core.Blocked, "test blocked"):
            cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                                popen=self.spawn_with_receipt(payload), timeout=0.1)
        self.worker.terminate.assert_called_once()

    def test_no_receipt_times_out_and_stops_worker(self):
        with self.assertRaisesRegex(core.Blocked, "超时"):
            cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                                popen=Mock(return_value=self.worker), timeout=0)
        self.worker.terminate.assert_called_once()
        self.worker.wait.assert_called_once_with(timeout=5)

    def test_receipt_cannot_override_exited_worker(self):
        self.worker.poll.return_value = 2
        payload = {"schema": 1, "target": "web", "ok": True, "state": "running"}
        with self.assertRaises(core.Blocked):
            cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                                popen=self.spawn_with_receipt(payload), timeout=0.1)
        self.worker.terminate.assert_not_called()

    def test_stuck_worker_is_not_killed_before_child_cleanup(self):
        self.worker.wait.side_effect = subprocess.TimeoutExpired("guard", 5)
        with self.assertRaisesRegex(core.Blocked, "无法确认"):
            cli.start_web_guard(config(), self.path, ["/test/Chrome"], self.loc,
                                popen=Mock(return_value=self.worker), timeout=0)
        self.worker.terminate.assert_called_once()
        self.worker.kill.assert_not_called()


class ShortcutColdLaunchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.binary = self.root / "Surge CC Browser.app/Contents/MacOS/Google Chrome"
        self.binary.parent.mkdir(parents=True)
        self.binary.touch()
        self.cfg = config()
        self.cfg["browser_path"] = str(self.binary)
        self.path = self.root / "config.json"
        core.save_config(self.path, self.cfg)
        self.receipt = {"schema": 1, "target": "web", "state": "running", "ok": True,
                        "web_guard_version": 2, "protection_active": True, "suspended": False}

    def test_one_worker_gate_no_parent_full_diagnostics(self):
        worker = Mock(return_value=self.receipt)
        with patch.object(cli, "full_checks", side_effect=AssertionError("expensive diagnostics")), \
             patch.object(cli, "run_checks", side_effect=AssertionError("duplicate gate")):
            result = cli.launch_shortcut_browser(self.cfg, self.path, web_guard=worker)
        self.assertTrue(result["launched"])
        self.assertTrue(result["protection_active"])
        worker.assert_called_once()
        command = worker.call_args.args[2]
        self.assertIn("--user-data-dir=" + str(self.root / "workspaces/A/data/Browser"), command)
        self.assertIn("--proxy-server=" + self.cfg["proxy_url"], command)

    def test_worker_failure_cannot_claim_launch(self):
        worker = Mock(side_effect=core.Blocked("出口检查失败"))
        with self.assertRaisesRegex(core.Blocked, "出口检查失败"):
            cli.launch_shortcut_browser(self.cfg, self.path, web_guard=worker)

    def test_lock_or_stale_workspace_blocks_before_worker(self):
        loc = workspaces.paths(self.path, "A")
        (loc["browser"] / "SingletonLock").symlink_to("host-123")
        worker = Mock()
        with self.assertRaises(core.Blocked):
            cli.launch_shortcut_browser(self.cfg, self.path, web_guard=worker)
        worker.assert_not_called()
        (loc["browser"] / "SingletonLock").unlink()
        changed = dict(self.cfg, workspace="B")
        with self.assertRaises(core.Blocked):
            cli.launch_shortcut_browser(changed, self.path, web_guard=worker)
        worker.assert_not_called()

    def test_unprotected_receipt_is_not_success(self):
        for change in ({"suspended": True}, {"protection_active": False}, {"web_guard_version": 1}):
            with self.subTest(change=change), self.assertRaises(core.Blocked):
                cli.launch_shortcut_browser(self.cfg, self.path, web_guard=Mock(return_value={**self.receipt, **change}))


if __name__ == "__main__":
    unittest.main()
