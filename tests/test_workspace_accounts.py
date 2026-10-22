"""Account selection transactions never mix routes, browser data or CLI state."""
import fcntl
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_core import config
from surge_cc import workspaces as ws
from surge_cc.core import Blocked, load_config, save_config


class WorkspaceAccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "config.json"
        self.a = save_config(self.path, config())

    def test_legacy_a_browser_and_cli_are_preserved_b_gets_no_login_data(self):
        a = ws.paths(self.path, "A")
        (a["browser"] / "Cookies").write_bytes(b"opaque A cookie")
        (a["claude"] / ".credentials.json").write_bytes(b"opaque A auth")
        b_config = ws.use(self.path, self.a, "B")
        b = ws.paths(self.path, "B")
        self.assertEqual((a["browser"] / "Cookies").read_bytes(), b"opaque A cookie")
        self.assertEqual((a["claude"] / ".credentials.json").read_bytes(), b"opaque A auth")
        self.assertFalse((b["browser"] / "Cookies").exists())
        self.assertFalse((b["claude"] / ".credentials.json").exists())
        self.assertEqual(b_config["policy"], self.a["policy"])
        self.assertEqual((a["root"] / "settings.json").stat().st_mode & 0o777, 0o600)

    def test_route_roundtrip_restores_per_account_values_and_shared_machine_paths(self):
        b = ws.use(self.path, self.a, "B")
        b.update(policy="OtherHome", group="OtherClaude", expected_ip="203.0.113.11",
                 proxy_url="http://127.0.0.1:6153", expected_timezone="UTC",
                 expected_country="CA", expected_asn="AS64500", browser_language="en-CA",
                 privacy_strict=False, guard_interval=20,
                 hosts=[*b["hosts"], "fixture.example"], profile_path="/test/new-machine.conf")
        b = ws.save_settings(self.path, b)
        restored_a = ws.use(self.path, b, "A")
        for key in ws.SETTINGS_FIELDS:
            self.assertEqual(restored_a[key], self.a[key], key)
        self.assertEqual(restored_a["profile_path"], "/test/new-machine.conf")
        restored_b = ws.use(self.path, restored_a, "B")
        for key in ws.SETTINGS_FIELDS:
            self.assertEqual(restored_b[key], b[key], key)
        self.assertEqual(restored_b["profile_path"], "/test/new-machine.conf")

    def test_listing_reports_saved_routes_without_secrets_or_creating_b_profile(self):
        listing = ws.listing(self.path, self.a)
        items = {item["name"]: item for item in listing["workspaces"]}
        self.assertEqual(items["A"]["route"]["policy"], self.a["policy"])
        self.assertIsNone(items["B"]["route"])
        self.assertFalse((self.path.parent / "workspaces/B/data").exists())
        b = ws.use(self.path, self.a, "B")
        b = ws.save_settings(self.path, dict(b, policy="OtherHome"))
        items = {item["name"]: item for item in ws.listing(self.path, b)["workspaces"]}
        self.assertEqual(items["A"]["route"]["policy"], "Home")
        self.assertEqual(items["B"]["route"]["policy"], "OtherHome")
        self.assertEqual(set(items["B"]["route"]), set(ws.SETTINGS_FIELDS))

    def test_stale_launch_and_stale_switch_never_use_old_account(self):
        b = ws.use(self.path, self.a, "B")
        with self.assertRaisesRegex(Blocked, "已变更"):
            with ws.account_session(self.path, self.a):
                self.fail("stale startup accepted")
        stop = Mock()
        with self.assertRaisesRegex(Blocked, "已变更"):
            ws.use(self.path, self.a, "A", stop_sessions=stop)
        stop.assert_not_called()
        self.assertEqual(load_config(self.path), b)

    def test_startup_lease_blocks_switch_and_release_is_idempotent(self):
        with ws.account_session(self.path, self.a) as release:
            with self.assertRaisesRegex(Blocked, "切换工作区或准备启动"):
                ws.use(self.path, self.a, "B")
            release()
            release()
            self.assertEqual(ws.use(self.path, self.a, "B")["workspace"], "B")

    def test_live_workspace_still_blocks_switch_after_startup_gate_released(self):
        a = ws.paths(self.path, "A")
        with a["lock"].open("a") as session:
            fcntl.flock(session.fileno(), fcntl.LOCK_SH)
            with ws.account_session(self.path, self.a) as release:
                release()
                with self.assertRaises(Blocked):
                    ws.use(self.path, self.a, "B")
        self.assertEqual(load_config(self.path), self.a)

    def test_stop_callback_runs_under_exclusive_launch_gate_for_both_workspaces(self):
        stopped = []

        def stop(path, name):
            self.assertEqual(path, self.path)
            stopped.append(name)
            with self.assertRaises(Blocked):
                with ws.account_session(path, self.a):
                    self.fail("startup raced switch")

        ws.use(self.path, self.a, "B", stop_sessions=stop)
        self.assertEqual(stopped, ["A", "B"])

    def test_unknown_chrome_lock_refuses_switch_without_changing_config(self):
        b = ws.paths(self.path, "B")
        (b["browser"] / "SingletonLock").symlink_to("unknown-999")
        with self.assertRaises(Blocked):
            ws.use(self.path, self.a, "B")
        self.assertEqual(load_config(self.path), self.a)
        self.assertFalse((ws.location(self.path, "A") / "settings.json").exists())

    def test_failed_route_activation_preserves_active_config_and_settings(self):
        b = ws.use(self.path, self.a, "B")
        a = ws.use(self.path, b, "A")
        files = [ws.location(self.path, name) / "settings.json" for name in ("A", "B")]
        before = [json.loads(p.read_text()) for p in files]
        with self.assertRaisesRegex(Blocked, "activation failed"):
            ws.use(self.path, a, "B", apply_route=Mock(side_effect=Blocked("activation failed")))
        self.assertEqual(load_config(self.path), a)
        self.assertEqual([json.loads(p.read_text()) for p in files], before)

    def test_failed_config_commit_undoes_route_and_new_settings(self):
        undo = Mock()
        activate = Mock(return_value=undo)
        with patch.object(ws, "save_config", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                ws.use(self.path, self.a, "B", apply_route=activate)
        activate.assert_called_once()
        self.assertEqual(activate.call_args.args[0], self.a)
        self.assertEqual(activate.call_args.args[1]["workspace"], "B")
        undo.assert_called_once_with()
        self.assertEqual(load_config(self.path), self.a)
        for name in ("A", "B"):
            self.assertFalse((ws.location(self.path, name) / "settings.json").exists())

    def test_failed_commit_does_not_copy_credentials_or_cookie_data(self):
        a = ws.paths(self.path, "A")
        secret = a["claude"] / ".credentials.json"
        secret.write_bytes(b"fixture secret")
        with patch.object(ws, "save_config", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                ws.use(self.path, self.a, "B")
        self.assertEqual(secret.read_bytes(), b"fixture secret")
        self.assertFalse((ws.location(self.path, "B") / "data/Claude/.credentials.json").exists())

    def test_configure_rejects_workspace_change_and_live_sessions(self):
        with self.assertRaisesRegex(Blocked, "已变更"):
            ws.save_settings(self.path, dict(self.a, workspace="B"))
        a = ws.paths(self.path, "A")
        with a["lock"].open("a") as session:
            fcntl.flock(session.fileno(), fcntl.LOCK_SH)
            with self.assertRaises(Blocked):
                ws.save_settings(self.path, dict(self.a, policy="Different"))
        self.assertEqual(load_config(self.path), self.a)

    def test_failed_configure_commit_restores_saved_route(self):
        ws.save_settings(self.path, self.a)
        file = ws.location(self.path, "A") / "settings.json"
        before = json.loads(file.read_text())
        with patch.object(ws, "save_config", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                ws.save_settings(self.path, dict(self.a, policy="Different"))
        self.assertEqual(json.loads(file.read_text()), before)
        self.assertEqual(load_config(self.path), self.a)

    def test_invalid_route_and_symlink_never_overwritten(self):
        b = ws.paths(self.path, "B")
        file = b["root"] / "settings.json"
        file.write_text('{"workspace":"B","token":"must not import"}')
        original = file.read_text()
        with self.assertRaises(Blocked):
            ws.use(self.path, self.a, "B")
        self.assertEqual(file.read_text(), original)
        file.unlink()
        elsewhere = self.path.parent / "outside.json"
        elsewhere.write_text("untouched")
        file.symlink_to(elsewhere)
        with self.assertRaises(Blocked):
            ws.use(self.path, self.a, "B")
        self.assertEqual(elsewhere.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
