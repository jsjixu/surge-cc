"""First-install tests use synthetic apps/settings, never personal state or network."""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, onboarding


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-first-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.config = self.home / "Support/config.json"
        self.source = self.root / "Google Chrome.app"
        self.browser(self.source)
        self.native = self.home / ".local/share/claude/versions/2.1.296"
        self.native.parent.mkdir(parents=True)
        self.native.write_bytes(b"\xcf\xfa\xed\xfe" + b"test")
        self.native.chmod(0o700)
        self.profile = self.root / "surge.conf"
        self.profile.write_text("[Proxy]\nHome = ss, example.invalid, 443\nOther = ss, other.invalid, 443\n[Proxy Group]\nClaude = select, Home\n[Rule]\nFINAL,DIRECT\n")
        self.profile.chmod(0o600)
        self.surge = Mock()
        self.surge.status.return_value = {"mode": "rule", "profile-path": str(self.profile), "features": {"enhanced-mode": True}}
        self.surge.profile.return_value = self.profile.read_text()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(Path, "home", return_value=self.home))
        self.stack.enter_context(patch.object(core, "CHROME", self.source / "Contents/MacOS/Google Chrome"))
        self.stack.enter_context(patch.object(core, "default_claude", return_value=self.native))
        self.values = dict(group="Claude", policy="Home", expected_ip="203.0.113.8", surge=self.surge)

    def browser(self, path):
        binary = path / "Contents/MacOS/Google Chrome"
        helper = path / "Contents/Frameworks/Google Chrome Framework.framework/Versions/1.0/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
        for item in (binary, helper):
            item.parent.mkdir(parents=True, exist_ok=True)
            item.write_bytes(b"app")
            item.chmod(0o755)
        with (path / "Contents/Info.plist").open("wb") as file:
            plistlib.dump({"CFBundleIdentifier": "com.google.Chrome", "CFBundleShortVersionString": "1.0"}, file)

    def copy(self, source, destination, runner):
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination, symlinks=True)

    def test_plan_does_not_create_config_browser_or_auth(self):
        before = set(self.home.rglob("*"))
        result = onboarding.plan(self.config, **self.values)
        self.assertEqual(before, set(self.home.rglob("*")))
        self.assertFalse(self.config.exists())
        self.assertEqual(result["settings"]["proxy_url"], onboarding.PROXY)
        self.assertEqual(result["settings"]["cli_process_paths"], [str(self.native.parent) + "/"])
        self.assertEqual(result["settings"]["default_model"], "opus")
        self.assertEqual(result["settings"]["default_effort"], "high")
        self.assertEqual(result["settings"]["browser_start_page"], "newtab")
        self.assertEqual(result["surge"]["nodes"], ["Home", "Other"])
        self.assertNotIn("_state", onboarding.public_plan(result))
        self.assertNotIn("example.invalid", json.dumps(onboarding.public_plan(result)))

    def test_apply_copies_app_and_saves_prepared_config_only(self):
        result = onboarding.plan(self.config, **self.values)
        with patch.object(onboarding, "_copy_browser", side_effect=self.copy) as copied, \
                patch.object(onboarding.repair, "apply") as routes, \
                patch.object(onboarding.terminal, "install") as terminal:
            done = onboarding.apply(self.config, result["plan_id"], **self.values)
        self.assertTrue(done["browser_created"])
        self.assertFalse(done["network_changed"])
        self.assertEqual(core.load_config(self.config), result["settings"])
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        copied.assert_called_once()
        routes.assert_not_called()
        terminal.assert_not_called()
        self.assertEqual(self.profile.read_text(), self.surge.profile.return_value)
        self.assertFalse(list(self.home.rglob("*token*")))

    def test_repeat_preparation_reuses_browser_and_preserves_account_settings(self):
        result = onboarding.plan(self.config, **self.values)
        with patch.object(onboarding, "_copy_browser", side_effect=self.copy):
            onboarding.apply(self.config, result["plan_id"], **self.values)
        config = core.load_config(self.config)
        config["workspace"] = "B"
        config["hosts"].append("example.org")
        config["privacy_strict"] = False
        extra_scope = str(self.home / "other-native/claude")
        config["cli_process_paths"].append(extra_scope)
        core.save_config(self.config, config)
        repeated = onboarding.plan(self.config, **self.values)
        with patch.object(onboarding, "_copy_browser") as copied:
            result = onboarding.apply(self.config, repeated["plan_id"], **self.values)
        self.assertFalse(result["browser_created"])
        self.assertEqual(result["settings"]["workspace"], "B")
        self.assertIn("example.org", result["settings"]["hosts"])
        self.assertFalse(result["settings"]["privacy_strict"])
        self.assertIn(extra_scope, result["settings"]["cli_process_paths"])
        copied.assert_not_called()

    def test_stale_plan_rejects_before_copy(self):
        result = onboarding.plan(self.config, **self.values)
        for mutation in (lambda: self.profile.write_text(self.profile.read_text() + "# changed\n"),
                         lambda: self.surge.status.return_value.update(mode="proxy")):
            with self.subTest(mutation=mutation):
                mutation()
                with patch.object(onboarding, "_copy_browser") as copied, self.assertRaises(Blocked):
                    onboarding.apply(self.config, result["plan_id"], **self.values)
                copied.assert_not_called()
                self.assertFalse(self.config.exists())

    def test_changed_native_binary_invalidates_plan(self):
        result = onboarding.plan(self.config, **self.values)
        self.native.write_bytes(self.native.read_bytes() + b"changed")
        with self.assertRaises(Blocked):
            onboarding.apply(self.config, result["plan_id"], **self.values)
        self.assertFalse(self.config.exists())

    def test_source_browser_change_invalidates_plan(self):
        result = onboarding.plan(self.config, **self.values)
        binary = self.source / "Contents/MacOS/Google Chrome"
        binary.write_bytes(binary.read_bytes() + b"changed")
        with self.assertRaises(Blocked):
            onboarding.apply(self.config, result["plan_id"], **self.values)
        self.assertFalse(self.config.exists())

    def test_destination_appearing_invalidates_plan_never_overwrites(self):
        result = onboarding.plan(self.config, **self.values)
        target = Path(result["_state"]["browser"])
        self.browser(target)
        marker = target / "user-marker"
        marker.write_text("keep")
        with self.assertRaises(Blocked):
            onboarding.apply(self.config, result["plan_id"], **self.values)
        self.assertEqual(marker.read_text(), "keep")

    def test_personal_browser_destination_rejected(self):
        with self.assertRaises(Blocked):
            onboarding.plan(self.config, **dict(self.values, browser_path=str(core.CHROME)))

    def test_config_symlink_rejected_without_following(self):
        self.config.parent.mkdir()
        target = self.root / "unrelated"
        target.write_text("keep")
        self.config.symlink_to(target)
        with self.assertRaises(Blocked):
            onboarding.plan(self.config, **self.values)
        self.assertEqual(target.read_text(), "keep")

    def test_symlink_browser_rejected(self):
        target = self.home / "Applications/Surge CC Browser.app"
        target.parent.mkdir()
        target.symlink_to(self.source)
        with self.assertRaises(Blocked):
            onboarding.plan(self.config, **self.values)

    def test_missing_unknown_or_managed_profile_rejected(self):
        with self.assertRaises(Blocked):
            onboarding.plan(self.config, **dict(self.values, profile_path=str(self.root / "other.conf")))
        self.profile.write_text("#!MANAGED-CONFIG https://example.invalid\n")
        with self.assertRaises(Blocked):
            onboarding.plan(self.config, **self.values)

    def test_missing_node_and_group_rejected(self):
        for field in ("group", "policy"):
            with self.subTest(field=field), self.assertRaises(Blocked):
                onboarding.plan(self.config, **dict(self.values, **{field: "missing"}))

    def test_copy_checks_source_and_staging_then_publishes_without_overwrite(self):
        destination = self.home / "Applications/Surge CC Browser.app"
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            if command[0] == "/usr/bin/ditto":
                shutil.copytree(command[1], command[2], symlinks=True)
            return subprocess.CompletedProcess(command, 0)
        def publish(source, target):
            self.assertFalse(target.exists())
            source.rename(target)
        with patch.object(onboarding, "_exclusive_rename", side_effect=publish):
            onboarding._copy_browser(self.source, destination, run)
        self.assertEqual([c[0] for c in calls], ["/usr/bin/codesign", "/usr/bin/ditto", "/usr/bin/codesign"])
        self.assertTrue((destination / "Contents/MacOS/Google Chrome").exists())
        self.assertFalse(list(destination.parent.glob(".surge-cc-browser-*")))

    def test_copy_failure_does_not_publish(self):
        destination = self.home / "Applications/Surge CC Browser.app"
        run = Mock(return_value=subprocess.CompletedProcess([], 1))
        with self.assertRaises(Blocked):
            onboarding._copy_browser(self.source, destination, run)
        self.assertFalse(destination.exists())
        self.assertFalse(list(destination.parent.glob(".surge-cc-browser-*")))

    def test_copy_does_not_overwrite_existing(self):
        destination = self.home / "Applications/Surge CC Browser.app"
        self.browser(destination)
        with self.assertRaises(Blocked):
            onboarding._copy_browser(self.source, destination, Mock())

    def test_changed_config_during_copy_not_overwritten(self):
        result = onboarding.plan(self.config, **self.values)
        def change(source, destination, runner):
            self.copy(source, destination, runner)
            self.config.parent.mkdir(parents=True)
            self.config.write_text("user changed this")
            self.config.chmod(0o600)
        with patch.object(onboarding, "_copy_browser", side_effect=change), self.assertRaises(Blocked):
            onboarding.apply(self.config, result["plan_id"], **self.values)
        self.assertEqual(self.config.read_text(), "user changed this")

    def test_doctor_no_write_or_launch(self):
        before = set(self.home.rglob("*"))
        surge_cli = self.root / "surge-cli"
        surge_cli.write_text("test")
        surge_cli.chmod(0o700)
        with patch.object(core, "SURGE_CLI", surge_cli), patch.object(sys, "platform", "darwin"), \
                patch.object(onboarding.platform, "mac_ver", return_value=("13.0", (), "")):
            report = onboarding.doctor(self.config, surge=self.surge)
        self.assertTrue(report["ok"])
        self.assertEqual(before, set(self.home.rglob("*")))
        self.assertNotIn("example.invalid", json.dumps(report))
        self.assertFalse(next(c for c in report["checks"] if c["id"] == "configuration")["required"])

    def test_noninteractive_script_requires_explicit_route(self):
        ready = {"schema": 1, "ok": True, "checks": [], "surge": {}}
        with patch.object(onboarding, "doctor", return_value=ready), \
                patch("sys.stdin", io.StringIO()), patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()), \
                patch.object(onboarding, "apply") as apply:
            self.assertEqual(onboarding.main(["--config", str(self.config)]), 2)
        apply.assert_not_called()


    def test_existing_preferences_preserved_when_not_requested(self):
        planned = onboarding.plan(self.config, **self.values)
        custom = dict(planned["settings"], default_model="sonnet", default_effort="medium", browser_language="fr-CA", browser_start_page="claude")
        core.save_config(self.config, custom)
        repeated = onboarding.plan(self.config, **self.values)
        for field in ("default_model", "default_effort", "browser_language", "browser_start_page"):
            self.assertEqual(repeated["settings"][field], custom[field])

    def test_save_reviewed_rechecks_fingerprint_under_lock(self):
        planned = onboarding.plan(self.config, **self.values)
        self.config.parent.mkdir(parents=True)
        self.config.write_text("changed")
        self.config.chmod(0o600)
        with self.assertRaises(Blocked):
            onboarding._save_reviewed(self.config, planned["settings"], None)
        self.assertEqual(self.config.read_text(), "changed")

    def test_optional_projects_and_shortcut_use_reviewed_scoped_parameters(self):
        from surge_cc import projects, shortcuts
        config = onboarding.plan(self.config, **self.values)["settings"]
        answers = iter(["yes", str(self.root / "source"), "sample", "yes", "yes", "yes", "My Browser", str(self.root / "Surge CC.app")])
        with patch("builtins.input", side_effect=lambda _: next(answers)), patch("sys.stdout", io.StringIO()), \
                patch.object(projects, "plan", return_value={"digest": "reviewed", "excluded": []}) as planned, \
                patch.object(projects, "apply", return_value={"ok": True}) as applied, \
                patch.object(shortcuts, "install", return_value={"ok": True}) as installed:
            onboarding.optional_setup(self.config, config)
        self.assertEqual(applied.call_args.kwargs["expected_digest"], "reviewed")
        self.assertTrue(applied.call_args.kwargs["trust"])
        self.assertTrue(applied.call_args.kwargs["share_history"])
        self.assertTrue(applied.call_args.kwargs["local_messaging"])
        self.assertEqual(installed.call_args.args[1:4], ("A", "My Browser", "newtab"))
        self.assertEqual(installed.call_args.kwargs["python_path"], Path(sys.executable).resolve())

    def test_optional_project_failure_does_not_prevent_shortcut(self):
        from surge_cc import projects, shortcuts
        config = onboarding.plan(self.config, **self.values)["settings"]
        answers = iter(["yes", str(self.root / "source"), "sample", "yes", "Launcher", str(self.root / "Surge CC.app")])
        with patch("builtins.input", side_effect=lambda _: next(answers)), patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()), \
                patch.object(projects, "plan", side_effect=Blocked("busy")), \
                patch.object(shortcuts, "install", return_value={"ok": True}) as installed:
            onboarding.optional_setup(self.config, config)
        installed.assert_called_once()

    def test_optional_skipped_does_not_prepare_project_or_shortcut(self):
        from surge_cc import projects, shortcuts
        config = onboarding.plan(self.config, **self.values)["settings"]
        with patch("builtins.input", return_value="no"), \
                patch.object(projects, "plan") as planned, patch.object(shortcuts, "install") as installed:
            onboarding.optional_setup(self.config, config)
        planned.assert_not_called()
        installed.assert_not_called()

    def test_wizard_synthetic_first_run_end_to_end_order(self):
        from surge_cc import cli
        events = []
        ready = {"schema": 1, "ok": True, "checks": [], "surge": {}}
        args = ["--config", str(self.config), "--group", "Claude", "--policy", "Home", "--expected-ip", "203.0.113.8"]
        answers = iter(["yes", "yes", "yes"])
        route_plan = {"plan_id": "route-reviewed", "actions": []}
        real_apply = onboarding.apply
        def copied(source, destination, runner):
            events.append("copy")
            self.copy(source, destination, runner)
        def route_applied(*args):
            events.append("routes")
            self.assertEqual(args[-1], "route-reviewed")
            self.assertTrue(self.config.exists())
            return {"ok": True}
        with patch.object(onboarding, "doctor", return_value=ready), patch.object(core, "Surge", return_value=self.surge), \
                patch("builtins.input", side_effect=lambda _: next(answers)), patch("sys.stdout", io.StringIO()), \
                patch.object(onboarding, "_copy_browser", side_effect=copied), \
                patch.object(onboarding.repair, "plan", return_value=route_plan), \
                patch.object(onboarding.repair, "apply", side_effect=route_applied), \
                patch.object(onboarding.containment, "validate_scope"), \
                patch.object(onboarding.terminal, "status", return_value={"installed": False}), \
                patch.object(onboarding.terminal, "install", side_effect=lambda *args: events.append("terminal") or {"ok": True}), \
                patch.object(cli, "full_checks", side_effect=lambda *args: events.append("check") or {"ok": True}), \
                patch.object(onboarding, "optional_setup", side_effect=lambda *args: events.append("optional")):
            self.assertEqual(onboarding.main(args), 0)
        self.assertEqual(events, ["copy", "routes", "terminal", "check", "optional"])

    def test_wizard_declining_route_review_does_not_install_terminal(self):
        ready = {"schema": 1, "ok": True, "checks": [], "surge": {}}
        args = ["--config", str(self.config), "--group", "Claude", "--policy", "Home", "--expected-ip", "203.0.113.8"]
        answers = iter(["yes", "no"])
        with patch.object(onboarding, "doctor", return_value=ready), patch.object(core, "Surge", return_value=self.surge), \
                patch("builtins.input", side_effect=lambda _: next(answers)), patch("sys.stdout", io.StringIO()), \
                patch.object(onboarding, "_copy_browser", side_effect=self.copy), \
                patch.object(onboarding.repair, "plan", return_value={"plan_id": "r", "actions": []}), \
                patch.object(onboarding.repair, "apply") as routes, \
                patch.object(onboarding.terminal, "install") as installed:
            self.assertEqual(onboarding.main(args), 0)
        self.assertTrue(self.config.exists())
        routes.assert_not_called()
        installed.assert_not_called()


Blocked = core.Blocked
if __name__ == "__main__":
    unittest.main()
