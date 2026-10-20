import fcntl
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import workspaces as ws
from surge_cc.core import Blocked, save_config
from test_core import config


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "config.json"
        save_config(self.path, config())

    def test_separate_data_and_private_metadata(self):
        a = ws.paths(self.path, "A")
        b = ws.paths(self.path, "B")
        self.assertNotEqual(a["browser"], b["browser"])
        self.assertEqual(a["root"].stat().st_mode & 0o777, 0o700)
        self.assertEqual((a["root"] / "metadata.json").stat().st_mode & 0o777, 0o600)

    def test_switch_preserves_settings_and_history(self):
        a = ws.paths(self.path, "A")
        (a["claude"] / "history.jsonl").write_text("existing history")
        changed = ws.use(self.path, config(), "B")
        self.assertEqual(changed["workspace"], "B")
        self.assertEqual(changed["policy"], config()["policy"])
        self.assertEqual((a["claude"] / "history.jsonl").read_text(), "existing history")

    def test_snapshot_restore_preserves_before_restore_backup(self):
        loc = ws.paths(self.path, "A")
        file = loc["claude"] / "settings.json"
        file.write_text('{"test":"first"}')
        snap = ws.snapshot(self.path, "A")
        file.write_text('{"test":"second"}')
        restored = ws.restore(self.path, "A", snap["id"])
        self.assertEqual(file.read_text(), '{"test":"first"}')
        backup = loc["root"] / "snapshots" / restored["backup"] / "data/Claude/settings.json"
        self.assertEqual(backup.read_text(), '{"test":"second"}')
        self.assertTrue(list(loc["root"].glob("previous-*")))

    def test_tampered_snapshot_rejected_without_changes(self):
        loc = ws.paths(self.path, "A")
        original = loc["claude"] / "x"
        original.write_text("original")
        snap = ws.snapshot(self.path, "A")
        stored = loc["root"] / "snapshots" / snap["id"] / "data/Claude/x"
        stored.write_text("tampered")
        with self.assertRaises(Blocked):
            ws.restore(self.path, "A", snap["id"])
        self.assertEqual(original.read_text(), "original")

    def test_runtime_shared_lock_blocks_snapshot(self):
        loc = ws.paths(self.path, "A")
        with loc["lock"].open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            with self.assertRaises(Blocked):
                ws.snapshot(self.path, "A")

    def test_chrome_lock_even_dangling_blocks_snapshot(self):
        loc = ws.paths(self.path, "A")
        (loc["browser"] / "SingletonLock").symlink_to("missing-target")
        with self.assertRaises(Blocked):
            ws.snapshot(self.path, "A")

    def test_path_traversal_and_symlink_workspace_rejected(self):
        for value in ("../personal", "a/b", ".", ""):
            with self.subTest(value=value), self.assertRaises(Blocked):
                ws.paths(self.path, value)
        outside = self.root / "outside"
        outside.mkdir()
        (ws.safe_root(self.path) / "A").symlink_to(outside)
        with self.assertRaises(Blocked):
            ws.paths(self.path, "A")

    def test_symlink_inside_snapshot_not_dereferenced(self):
        loc = ws.paths(self.path, "A")
        secret = self.root / "private"
        secret.write_text("never copied")
        (loc["claude"] / "link").symlink_to(secret)
        snap = ws.snapshot(self.path, "A")
        copied = loc["root"] / "snapshots" / snap["id"] / "data/Claude/link"
        self.assertTrue(copied.is_symlink())
        self.assertEqual(secret.read_text(), "never copied")

    def test_listing_excludes_data_and_manifest_hashes(self):
        ws.snapshot(self.path, "A")
        payload = ws.listing(self.path, config())
        self.assertEqual(payload["current_workspace"], "A")
        self.assertEqual({w["name"] for w in payload["workspaces"]}, {"A", "B"})
        self.assertNotIn("sha256", json.dumps(payload))
        self.assertNotIn("files", json.dumps(payload))

    def test_web_rtc_preferences_applied_even_without_language(self):
        ws.prepare_browser_language(self.path, dict(config(), workspace="A", browser_language=""))
        prefs = self.root / "workspaces/A/data/Browser/Default/Preferences"
        self.assertEqual(json.loads(prefs.read_text()), {
            "webrtc": {"ip_handling_policy": "disable_non_proxied_udp", "ip_handling_url": []}})
        self.assertEqual(prefs.stat().st_mode & 0o777, 0o600)

    def test_hardening_clears_only_webrtc_url_overrides_and_preserves_other_preferences(self):
        loc = ws.paths(self.path, "A")
        prefs = loc["browser"] / "Default/Preferences"
        prefs.parent.mkdir()
        original = {
            "intl": {"accept_languages": "zh-CN,en-US", "selected_languages": "zh-CN"},
            "profile": {"name": "saved"}, "other": [1, 2],
            "webrtc": {"ip_handling_policy": "default",
                       "ip_handling_url": [{"url": "*", "handling": "default"}],
                       "unrelated": "keep"},
        }
        prefs.write_text(json.dumps(original))
        ws.prepare_browser_language(self.path, dict(config(), workspace="A", browser_language=""))
        changed = json.loads(prefs.read_text())
        original["webrtc"]["ip_handling_policy"] = "disable_non_proxied_udp"
        original["webrtc"]["ip_handling_url"] = []
        self.assertEqual(changed, original)

    def test_explicit_language_is_applied_with_webrtc_hardening(self):
        ws.prepare_browser_language(self.path, dict(config(), workspace="A", browser_language="en-US"))
        prefs = self.root / "workspaces/A/data/Browser/Default/Preferences"
        self.assertEqual(json.loads(prefs.read_text()), {
            "intl": {"accept_languages": "en-US"},
            "webrtc": {"ip_handling_policy": "disable_non_proxied_udp", "ip_handling_url": []}})

    def test_malformed_webrtc_preferences_are_not_overwritten(self):
        loc = ws.paths(self.path, "A")
        prefs = loc["browser"] / "Default/Preferences"
        prefs.parent.mkdir()
        for content in ('{"webrtc":null}', '{"webrtc":[]}', '{"webrtc":"unexpected"}'):
            with self.subTest(content=content):
                prefs.write_text(content)
                with self.assertRaises(Blocked):
                    ws.prepare_browser_language(self.path, dict(config(), workspace="A"))
                self.assertEqual(prefs.read_text(), content)

    def test_no_language_still_obeys_running_workspace_lock(self):
        loc = ws.paths(self.path, "A")
        with loc["lock"].open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            with self.assertRaises(Blocked):
                ws.prepare_browser_language(self.path, dict(config(), workspace="A", browser_language=""))
        self.assertFalse((loc["browser"] / "Default/Preferences").exists())

    def test_oauth_profile_can_prepare_while_cli_holds_shared_workspace_lock(self):
        loc = ws.paths(self.path, "A")
        (loc["browser"] / "existing-web-data").write_text("preserved")
        with loc["lock"].open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            profile = ws.prepare_oauth_browser(self.path, dict(config(), workspace="A"))
        self.assertEqual(profile, loc["data"] / "OAuthBrowser")
        self.assertEqual(json.loads((profile / "Default/Preferences").read_text())["webrtc"],
                         {"ip_handling_policy": "disable_non_proxied_udp", "ip_handling_url": []})
        self.assertEqual((loc["browser"] / "existing-web-data").read_text(), "preserved")

    def test_oauth_profile_never_reuses_unknown_running_instance(self):
        loc = ws.paths(self.path, "A")
        oauth = loc["data"] / "OAuthBrowser"
        oauth.mkdir()
        (oauth / "SingletonLock").symlink_to("unknown-123")
        with self.assertRaises(Blocked):
            ws.prepare_oauth_browser(self.path, dict(config(), workspace="A"))
        with self.assertRaises(Blocked):
            ws.snapshot(self.path, "A")


if __name__ == "__main__":
    unittest.main()
