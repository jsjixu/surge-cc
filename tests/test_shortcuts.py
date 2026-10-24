import contextlib
import datetime as dt
import tempfile
import json
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import shortcuts as module


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.config = {"workspace": "A", "browser_start_page": "newtab"}
        self.process = NS(pid=123, started=(500, 200), executable="/dedicated/Chrome")
        self.locked = False
        @contextlib.contextmanager
        def session(*args):
            self.locked = True
            try:
                yield
            finally:
                self.locked = False
        self.core = NS(Blocked=module.LauncherError, load_config=Mock(return_value=self.config),
                       global_mode_allowed=Mock(return_value=False))
        self.cli = NS(full_checks=Mock(return_value={"ok": True}),
                      launch=Mock(return_value={"ok": True, "launched": True}))
        self.workspaces = NS(account_session=session, assert_current=Mock(),
                             use=Mock(return_value={"workspace": "A"}))
        self.workspaces.name_ok = lambda value: value
        self.workspaces.listing = Mock(return_value={"workspaces": [
            {"name": "A", "route_configured": True, "route": {"browser_start_page": "newtab"}},
            {"name": "B", "route_configured": True, "route": {"browser_start_page": "claude"}}]})
        self.workspaces.use.return_value = {"workspace": "A", "browser_start_page": "newtab"}
        self.sessions = NS(stop_workspace=Mock())
        self.routes = NS(activate=Mock())
        for name, value in (("core", self.core), ("cli", self.cli), ("workspaces", self.workspaces),
                            ("sessions", self.sessions), ("workspace_routes", self.routes)):
            mocker = patch.object(module, name, value)
            mocker.start()
            self.addCleanup(mocker.stop)

    def open(self, confirmed_from=None, workspace="A", start_page="newtab"):
        return module.open_browser(Path("/support/config.json"), workspace, start_page,
                                   Path("/Shortcut.app/Contents/MacOS/SurgeCCShortcut"), confirmed_from)

    def test_b_needs_confirmation_without_changes_or_network(self):
        self.config["workspace"] = "B"
        with patch.object(module, "existing_browser") as existing, patch.object(module, "focus_native") as focus:
            value = self.open()
        self.assertEqual(value["action"], "needs_switch")
        self.assertEqual(value["current"], "B")
        self.workspaces.use.assert_not_called()
        self.cli.full_checks.assert_not_called()
        existing.assert_not_called()
        focus.assert_not_called()

    def test_confirmation_for_different_workspace_is_not_authorization(self):
        self.config["workspace"] = "C"
        self.assertEqual(self.open("B")["action"], "needs_switch")
        self.workspaces.use.assert_not_called()

    def test_confirmed_switch_calls_standard_switch(self):
        self.config["workspace"] = "B"
        with patch.object(module, "existing_browser", return_value=self.process), patch.object(module, "focus_native"):
            self.open("B")
        self.workspaces.use.assert_called_once()
        self.assertEqual(self.workspaces.use.call_args.args[2], "A")
        self.assertIs(self.workspaces.use.call_args.kwargs["stop_sessions"], self.sessions.stop_workspace)

    def test_existing_window_is_checked_and_focused_under_lock(self):
        with patch.object(module, "existing_browser", return_value=self.process) as existing:
            with patch.object(module, "focus_native", side_effect=lambda p, native: self.assertTrue(self.locked)) as focus:
                result = self.open()
        self.assertTrue(result["focused"])
        self.assertFalse(result["launched"])
        self.assertEqual(existing.call_count, 2)
        self.cli.full_checks.assert_called_once()
        self.cli.launch.assert_not_called()
        focus.assert_called_once_with(self.process, Path("/Shortcut.app/Contents/MacOS/SurgeCCShortcut"))
        self.assertFalse(self.locked)

    def test_failed_route_does_not_focus_or_launch(self):
        self.cli.full_checks.return_value = {"ok": False, "checks": [{"status": "fail", "detail": "线路异常"}]}
        with patch.object(module, "existing_browser", return_value=self.process), patch.object(module, "focus_native") as focus:
            with self.assertRaisesRegex(module.LauncherError, "线路异常"):
                self.open()
        focus.assert_not_called()
        self.cli.launch.assert_not_called()

    def test_only_canonical_global_exception_is_accepted(self):
        self.cli.full_checks.return_value = {"ok": False, "paused": True, "protection_active": False}
        with patch.object(module, "existing_browser", return_value=self.process), patch.object(module, "focus_native") as focus:
            with self.assertRaises(module.LauncherError):
                self.open()
            focus.assert_not_called()
            self.core.global_mode_allowed.return_value = True
            result = self.open()
        self.assertTrue(result["suspended"])

    def test_changed_window_between_probes_is_blocked(self):
        with patch.object(module, "existing_browser", side_effect=[self.process, None]), patch.object(module, "focus_native") as focus:
            with self.assertRaises(module.LauncherError):
                self.open()
        focus.assert_not_called()

    def test_new_window_uses_original_launch_and_focus(self):
        with patch.object(module, "existing_browser", side_effect=[None, self.process]), patch.object(module, "focus_native") as focus:
            result = self.open()
        self.assertTrue(result["launched"])
        self.cli.launch.assert_called_once()
        self.assertEqual(self.cli.launch.call_args.args[2:5], ("web", False, []))
        focus.assert_called_once_with(self.process, Path("/Shortcut.app/Contents/MacOS/SurgeCCShortcut"))

    def test_failed_launch_never_focuses(self):
        self.cli.launch.return_value = {"ok": False, "summary": "线路失败"}
        with patch.object(module, "existing_browser", return_value=None), patch.object(module, "focus_native") as focus:
            with self.assertRaisesRegex(module.LauncherError, "线路失败"):
                self.open()
        focus.assert_not_called()

    def test_account_change_before_focus_blocks(self):
        self.workspaces.assert_current.side_effect = module.LauncherError("changed")
        with patch.object(module, "existing_browser", return_value=self.process), patch.object(module, "focus_native") as focus:
            with self.assertRaises(module.LauncherError):
                self.open()
        focus.assert_not_called()

    def test_guard_arguments_cannot_reference_other_profile(self):
        expected = ["/dedicated/Chrome", "--user-data-dir=/A"]
        argv = ["/python", "-B", "-m", "surge_cc.guard", "--config", "/session", "--", "/dedicated/Chrome", "--user-data-dir=/B"]
        with self.assertRaises(module.LauncherError):
            module.guard_arguments(argv, expected)

    def test_duplicate_guard_option_rejected(self):
        command = ["/dedicated/Chrome"]
        argv = ["/python", "-B", "-m", "surge_cc.guard", "--config", "1", "--config", "2", "--", *command]
        with self.assertRaises(module.LauncherError):
            module.guard_arguments(argv, command)

    def test_unexpected_focus_response_blocked(self):
        with patch.object(module.subprocess, "run", return_value=NS(returncode=0, stdout=b'{"focused":false}')):
            with self.assertRaises(module.LauncherError):
                module.focus_native(self.process, Path("/shortcut"))

    def test_startup_identity_pending_is_retried_before_focus(self):
        with patch.object(module, "existing_browser", side_effect=[
                None, module.LauncherError("identity pending"), self.process
        ]), patch.object(module.time, "sleep"), patch.object(module, "focus_native") as focus:
            result = self.open()
        self.assertTrue(result["launched"])
        focus.assert_called_once_with(self.process, Path("/Shortcut.app/Contents/MacOS/SurgeCCShortcut"))

    def test_persistent_startup_mismatch_never_focuses(self):
        with patch.object(module, "existing_browser", side_effect=module.LauncherError("wrong profile")), \
             patch.object(module.time, "monotonic", side_effect=[0, 0, 13]), \
             patch.object(module.time, "sleep"), patch.object(module, "focus_native") as focus:
            with self.assertRaisesRegex(module.LauncherError, "wrong profile"):
                module.wait_for_browser(Path("/support/config.json"), self.config)
        focus.assert_not_called()

    def test_cancel_during_startup_observation_is_never_swallowed(self):
        with patch.object(module, "existing_browser", side_effect=module.LauncherStopped("stopped")) as existing, \
             patch.object(module.time, "sleep") as sleep:
            with self.assertRaises(module.LauncherStopped):
                module.wait_for_browser(Path("/support/config.json"), self.config)
        existing.assert_called_once()
        sleep.assert_not_called()

    def test_unknown_existing_window_is_not_adopted_or_relaunched(self):
        with patch.object(module, "existing_browser", side_effect=module.LauncherError("wrong profile")), \
             patch.object(module, "focus_native") as focus:
            with self.assertRaisesRegex(module.LauncherError, "wrong profile"):
                self.open()
        self.cli.launch.assert_not_called()
        focus.assert_not_called()

    def test_only_exact_canonical_command_is_accepted(self):
        neutral = ["/Chrome", "--user-data-dir=/A", "--proxy-server=localhost:1234", "chrome://newtab/"]
        self.assertEqual(module.accepted_browser_command(neutral, neutral), neutral)
        for invalid in ([*neutral[:-1], "https://example.com/"],
                        [*neutral[:-1], "https://claude.ai/"],
                        ["/Chrome", "--user-data-dir=/B", *neutral[2:]],
                        [*neutral, "--no-proxy-server"]):
            self.assertIsNone(module.accepted_browser_command(invalid, neutral))

    def test_mismatched_start_page_blocks_before_switch_or_launch(self):
        self.config["workspace"] = "B"
        with self.assertRaises(module.LauncherError):
            self.open("B", start_page="claude")
        self.workspaces.use.assert_not_called()
        self.cli.launch.assert_not_called()

    def test_target_workspace_uses_its_own_saved_page(self):
        self.config.update(workspace="B", browser_start_page="claude")
        with patch.object(module, "existing_browser", return_value=self.process), patch.object(module, "focus_native"):
            result = self.open(workspace="B", start_page="claude")
        self.assertTrue(result["focused"])
        self.workspaces.use.assert_not_called()

    def test_missing_target_configuration_is_not_invented(self):
        with self.assertRaises(module.LauncherError):
            self.open(workspace="missing")
        self.workspaces.use.assert_not_called()
        self.cli.launch.assert_not_called()

    def open_url(self, url="https://example.com/private?id=fixture", **kwargs):
        return module.open_url(Path("/support/config.json"), "A", url,
                               Path("/Shortcut.app/Contents/MacOS/SurgeCCShortcut"), **kwargs)

    def test_url_delivery_reuses_verified_window_while_account_lock_held(self):
        url = "https://example.com/private?id=fixture"
        def deliver(process, native, requested_url):
            self.assertTrue(self.locked)
            self.assertEqual(process, self.process)
            self.assertEqual(requested_url, url)
        with patch.object(module, "existing_browser", return_value=self.process), \
             patch.object(module, "focus_native") as focus, \
             patch.object(module, "open_url_native", side_effect=deliver) as opener:
            result = self.open_url(url)
        opener.assert_called_once()
        focus.assert_not_called()
        self.cli.launch.assert_not_called()
        self.assertTrue(result["ok"])
        self.assertTrue(result["opened"])
        self.assertNotIn(url, json.dumps(result))

    def test_cold_url_open_keeps_canonical_startup_command(self):
        with patch.object(module, "existing_browser", side_effect=[None, self.process]), \
             patch.object(module, "open_url_native") as opener:
            result = self.open_url()
        self.assertTrue(result["launched"])
        self.assertEqual(self.cli.launch.call_args.args[2:5], ("web", False, []))
        opener.assert_called_once()
        self.assertNotIn("example.com", repr(self.cli.launch.call_args))

    def test_url_route_failure_never_delivers_to_any_browser(self):
        self.cli.full_checks.return_value = {"ok": False, "summary": "route failed"}
        with patch.object(module, "existing_browser", return_value=self.process), \
             patch.object(module, "open_url_native") as opener, \
             patch.object(module, "focus_native") as focus:
            with self.assertRaises(module.LauncherError):
                self.open_url()
        opener.assert_not_called()
        focus.assert_not_called()

    def test_url_workspace_switch_is_never_silent(self):
        self.config["workspace"] = "B"
        with patch.object(module, "open_url_native") as opener:
            result = self.open_url()
        self.assertEqual(result["action"], "needs_switch")
        self.workspaces.use.assert_not_called()
        self.cli.launch.assert_not_called()
        opener.assert_not_called()

    def test_url_account_or_window_changed_before_delivery_blocks(self):
        with patch.object(module, "existing_browser", side_effect=[self.process, None]), \
             patch.object(module, "open_url_native") as opener:
            with self.assertRaises(module.LauncherError):
                self.open_url()
        opener.assert_not_called()

    def test_url_owner_exited_during_checks_blocks_delivery(self):
        def expired():
            self.assertTrue(self.locked)
            raise module.LauncherError("owner exited")
        with patch.object(module, "existing_browser", return_value=self.process), \
             patch.object(module, "open_url_native") as opener:
            with self.assertRaisesRegex(module.LauncherError, "owner exited"):
                self.open_url(before_delivery=expired)
        self.cli.full_checks.assert_called_once()
        opener.assert_not_called()

    def test_native_url_uses_stdin_only_and_requires_confirmed_delivery(self):
        url = "https://example.com/?private=fixture"
        with patch.object(module.subprocess, "run", return_value=NS(
                returncode=0, stdout=b'{"schema":1,"opened":true,"focused":true}')) as run:
            self.assertTrue(module.open_url_native(self.process, Path("/shortcut"), url))
        self.assertEqual(run.call_args.args[0], ["/shortcut", "--open-url-stdin"])
        self.assertEqual(json.loads(run.call_args.kwargs["input"])["url"], url)
        self.assertNotIn(url, repr(run.call_args.args))

    def test_native_accepted_url_without_focus_succeeds_without_retry(self):
        with patch.object(module.subprocess, "run", return_value=NS(
                returncode=0, stdout=b'{"schema":1,"opened":true,"focused":false}')) as run:
            self.assertFalse(module.open_url_native(self.process, Path("/shortcut"), "https://example.com/"))
        run.assert_called_once()

    def test_open_url_reports_delivery_and_focus_independently(self):
        with patch.object(module, "existing_browser", return_value=self.process), \
             patch.object(module, "open_url_native", return_value=False) as opener:
            result = self.open_url()
        self.assertTrue(result["ok"])
        self.assertTrue(result["opened"])
        self.assertFalse(result["focused"])
        opener.assert_called_once()
        self.cli.launch.assert_not_called()

    def test_native_url_failure_does_not_leak_url_or_fallback(self):
        failures = [NS(returncode=2, stdout=b'{}'),
                    NS(returncode=2, stdout=b'{"schema":1,"opened":true,"focused":false}'),
                    NS(returncode=0, stdout=b'{"schema":1,"opened":false,"focused":true}'),
                    NS(returncode=0, stdout=b'{"schema":1,"opened":true,"focused":"false"}'),
                    NS(returncode=0, stdout=b'{"opened":true,"focused":false}'),
                    NS(returncode=0, stdout=b'[]'),
                    NS(returncode=0, stdout=b'invalid'), OSError("private-test-url"),
                    module.subprocess.TimeoutExpired(["private-test-url"], 15)]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch.object(module.subprocess, "run") as run:
                if isinstance(failure, Exception):
                    run.side_effect = failure
                else:
                    run.return_value = failure
                with self.assertRaises(module.LauncherError) as caught:
                    module.open_url_native(self.process, Path("/shortcut"), "https://example.com/private-test-url")
                self.assertNotIn("private-test-url", str(caught.exception))
                run.assert_called_once()


class GuardEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config_path = Path(self.temporary.name).resolve() / "config.json"
        self.config = {"workspace": "A", "guard_interval": 10}
        self.core = NS(validate_config=lambda value: value)
        mocker = patch.object(module, "core", self.core)
        mocker.start()
        self.addCleanup(mocker.stop)
        session = self.config_path.parent / "sessions" / ("A-" + "a" * 32)
        session.parent.mkdir()
        self.arguments = {
            "--lock": str(self.config_path.parent / "workspaces/A/.session.lock"),
            "--target": "web",
            "--config": str(session) + ".config.json",
            "--status": str(session) + ".status.json",
            "--receipt": str(session) + ".receipt.json",
        }
        self.write("--config", self.config)
        self.write("--receipt", {"schema": 1, "target": "web", "state": "running", "ok": True})

    def write(self, key, value):
        path = Path(self.arguments[key])
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def status(self, state="running", ok=True, age=0):
        self.write("--status", {"schema": 1, "target": "web", "state": state, "ok": ok,
                                 "checked_at": (dt.datetime.now(dt.timezone.utc) -
                                                dt.timedelta(seconds=age)).isoformat()})

    def validate(self):
        module.validate_guard_files(self.arguments, self.config_path, self.config)

    def test_canonical_running_and_suspended_are_accepted(self):
        for state, ok in (("running", True), ("suspended", False)):
            with self.subTest(state=state):
                self.status(state, ok)
                self.validate()

    def test_contradictory_guard_state_is_rejected(self):
        for state, ok in (("running", False), ("suspended", True), ("running", None)):
            with self.subTest(state=state, ok=ok):
                self.status(state, ok)
                with self.assertRaises(module.LauncherError):
                    self.validate()

    def test_stale_or_future_guard_evidence_is_rejected(self):
        for age in (91, -30):
            with self.subTest(age=age):
                self.status(age=age)
                with self.assertRaises(module.LauncherError):
                    self.validate()

    def test_other_workspace_guard_is_rejected(self):
        self.status()
        self.arguments["--lock"] = str(self.config_path.parent / "workspaces/B/.session.lock")
        with self.assertRaises(module.LauncherError):
            self.validate()

    def test_session_config_must_equal_active_config(self):
        self.status()
        self.write("--config", {**self.config, "guard_interval": 20})
        with self.assertRaises(module.LauncherError):
            self.validate()

    def test_malformed_guard_schema_or_target_is_rejected(self):
        for change in ({"schema": 2}, {"target": "code"}, {"state": "exited"}):
            with self.subTest(change=change):
                self.status()
                path = Path(self.arguments["--status"])
                value = json.loads(path.read_text())
                self.write("--status", {**value, **change})
                with self.assertRaises(module.LauncherError):
                    self.validate()

    def test_receipt_must_identify_same_session_and_success(self):
        self.status()
        self.write("--receipt", {"schema": 1, "target": "web", "state": "running", "ok": False})
        with self.assertRaises(module.LauncherError):
            self.validate()
        self.arguments["--receipt"] = self.arguments["--receipt"].replace("a" * 32, "b" * 32)
        with self.assertRaises(module.LauncherError):
            self.validate()


class ParentArgumentsTests(unittest.TestCase):
    def setUp(self):
        self.command = ["/dedicated/Chrome", "--user-data-dir=/support/workspaces/A/data/Browser",
                        "--proxy-server=http://127.0.0.1:6152", "https://claude.ai/"]
        self.pairs = ["--config", "/sessions/A.config.json", "--receipt", "/sessions/A.receipt.json",
                      "--status", "/sessions/A.status.json", "--cwd", "/cwd", "--target", "web",
                      "--lock", "/support/workspaces/A/.session.lock"]
        self.prefix = ["/installed/python", "-B", "-m", "surge_cc.guard"]

    def test_canonical_guard_arguments_are_accepted(self):
        actual = module.guard_arguments(self.prefix + self.pairs + ["--"] + self.command, self.command)
        self.assertEqual(actual["--target"], "web")
        self.assertEqual(actual["--lock"], "/support/workspaces/A/.session.lock")

    def test_wrong_module_or_missing_separator_is_rejected(self):
        cases = [self.prefix[:-1] + ["other.guard"] + self.pairs + ["--"] + self.command,
                 self.prefix + self.pairs + self.command]
        for argv in cases:
            with self.subTest(argv=argv):
                with self.assertRaises(module.LauncherError):
                    module.guard_arguments(argv, self.command)

    def test_changed_proxy_in_guard_child_command_is_rejected(self):
        changed = [value.replace("6152", "8888") for value in self.command]
        with self.assertRaises(module.LauncherError):
            module.guard_arguments(self.prefix + self.pairs + ["--"] + changed, self.command)

    def test_unknown_or_duplicate_guard_option_is_rejected(self):
        for change in (["--unknown", "x"], ["--config", "/duplicate"]):
            with self.subTest(change=change):
                with self.assertRaises(module.LauncherError):
                    module.guard_arguments(self.prefix + self.pairs + change + ["--"] + self.command,
                                             self.command)



class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.config_path = self.root / 'support/config.json'
        self.config_path.parent.mkdir(mode=0o700)
        self.config = module.core.validate_config({
            'schema': 1, 'group': 'Claude', 'policy': 'Home',
            'expected_ip': '203.0.113.10', 'proxy_url': 'http://127.0.0.1:6152',
            'profile_path': '/fixture/profile.conf', 'browser_start_page': 'newtab'})
        module.core.save_config(self.config_path, self.config)
        self.app = self.root / 'Surge CC.app'
        resources = self.app / 'Contents/Resources'
        (resources / 'scripts').mkdir(parents=True)
        for name in ('SurgeCCShortcut', 'SurgeCCIcon.icns', 'scripts/surge-cc'):
            file = resources / name
            file.write_bytes(b'fixture-component')
            file.chmod(0o755)
        self.apps = self.root / 'Applications'
        self.python = Path(sys.executable).resolve()
        self.sign = patch.object(module.subprocess, 'run', return_value=NS(returncode=0))
        self.sign_mock = self.sign.start()
        self.addCleanup(self.sign.stop)
        self.publish = patch.object(module, '_publish', side_effect=lambda src, dst: src.rename(dst))
        self.publish_mock = self.publish.start()
        self.addCleanup(self.publish.stop)

    def install(self, **changes):
        args = {'config_path': self.config_path, 'workspace': 'A', 'name': 'Work Browser',
                'start_page': 'newtab', 'app_path': self.app,
                'python_path': self.python, 'applications_dir': self.apps}
        args.update(changes)
        return module.install(**args)

    def test_installs_only_frontend_and_paths_no_private_profile_or_backend(self):
        result = self.install()
        output = Path(result['app'])
        config = output / 'Contents/Resources/launcher.json'
        value = module.load_launcher(config)
        self.assertEqual(set(value), {'schema', 'name', 'workspace', 'start_page', 'python', 'config', 'app'})
        self.assertEqual(value['app'], str(self.app))
        self.assertEqual(value['workspace'], 'A')
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual({str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}, {
            'Contents/MacOS/SurgeCCShortcut', 'Contents/Info.plist',
            'Contents/Resources/SurgeCCIcon.icns', 'Contents/Resources/launcher.json'})
        self.assertFalse(result['pinned'])
        self.assertEqual(self.sign_mock.call_count, 2)
        self.assertEqual(module.core.load_config(self.config_path), self.config)

    def test_same_name_is_never_overwritten(self):
        result = self.install()
        before = (Path(result['app']) / 'Contents/Resources/launcher.json').read_bytes()
        with self.assertRaises(module.LauncherError):
            self.install()
        self.assertEqual((Path(result['app']) / 'Contents/Resources/launcher.json').read_bytes(), before)
        self.assertEqual(self.publish_mock.call_count, 1)

    def test_rejects_unsafe_names(self):
        for name in ('', '../Browser', '.hidden', 'x/y', 'x\\y', 'x:y', 'x\n', 'X.app', ' X', 'x' * 61):
            with self.subTest(name=name), self.assertRaises(module.LauncherError):
                self.install(name=name)
        self.publish_mock.assert_not_called()

    def test_unicode_name_is_portable_metadata_not_shell(self):
        import plistlib
        result = self.install(name='工作 浏览器')
        value = plistlib.loads((Path(result['app']) / 'Contents/Info.plist').read_bytes())
        self.assertEqual(value['CFBundleDisplayName'], '工作 浏览器')

    def test_rejects_unsupported_start_page(self):
        with self.assertRaises(module.LauncherError):
            self.install(start_page='https://example.com')
        self.publish_mock.assert_not_called()

    def test_requires_saved_page_before_installation(self):
        with self.assertRaises(module.LauncherError):
            self.install(start_page='claude')
        self.publish_mock.assert_not_called()

    def test_missing_template_does_not_publish(self):
        (self.app / 'Contents/Resources/SurgeCCShortcut').unlink()
        with self.assertRaises(module.LauncherError):
            self.install()
        self.publish_mock.assert_not_called()

    def test_signing_failure_leaves_no_partial_app(self):
        self.sign_mock.side_effect = module.subprocess.CalledProcessError(1, 'codesign')
        with self.assertRaises(module.LauncherError):
            self.install()
        self.assertEqual(list(self.apps.iterdir()), [])
        self.publish_mock.assert_not_called()

    def test_missing_config_is_not_recreated(self):
        self.config_path.unlink()
        with self.assertRaises(module.core.Blocked):
            self.install()
        self.assertFalse(self.config_path.exists())

    def test_parent_symlink_rejected(self):
        target = self.root / 'real-apps'
        target.mkdir()
        self.apps.symlink_to(target, target_is_directory=True)
        with self.assertRaises(module.LauncherError):
            self.install()
        self.assertEqual(list(target.iterdir()), [])

    def test_shared_writable_app_directory_rejected(self):
        self.apps.mkdir(mode=0o777)
        self.apps.chmod(0o777)
        with self.assertRaises(module.LauncherError):
            self.install()
        self.publish_mock.assert_not_called()

    def test_config_schema_rejects_embedded_backend_or_token(self):
        result = self.install()
        path = Path(result['app']) / 'Contents/Resources/launcher.json'
        value = json.loads(path.read_text())
        module.workspaces.write_json(path, dict(value, token='synthetic'))
        with self.assertRaises(module.LauncherError):
            module.load_launcher(path)

    def test_private_json_rejects_symlink_and_hardlink(self):
        import os
        source = self.root / 'private.json'
        source.write_text('{}')
        source.chmod(0o600)
        link = self.root / 'link.json'
        link.symlink_to(source)
        with self.assertRaises(module.LauncherError):
            module.private_json(link)
        link.unlink()
        os.link(source, link)
        with self.assertRaises(module.LauncherError):
            module.private_json(source)

    def test_open_uses_self_bundle_focus_helper_and_shared_backend(self):
        result = self.install()
        path = Path(result['app']) / 'Contents/Resources/launcher.json'
        with patch.object(module, 'open_browser', return_value={'action': 'focus'}) as opener:
            value = module.open_launcher(path, 'B')
        self.assertEqual(value['action'], 'focus')
        opener.assert_called_once_with(self.config_path, 'A', 'newtab',
                                       Path(result['app']) / 'Contents/MacOS/SurgeCCShortcut', 'B')

    def test_actual_launcher_config_cannot_change_requested_account_store(self):
        result = self.install()
        path = Path(result['app']) / 'Contents/Resources/launcher.json'
        with patch.object(module, 'open_browser') as opener:
            with self.assertRaises(module.LauncherError):
                module.open_launcher(path, expected_config=self.root / 'other/config.json')
        opener.assert_not_called()

    def test_workspace_pages_do_not_bleed(self):
        from copy import deepcopy
        b = deepcopy(self.config)
        b.update(workspace='B', browser_start_page='claude')
        module.workspaces.write_json(self.config_path.parent / 'workspaces/B/settings.json',
                                    module.workspaces._settings_value('B', module.workspaces._route(b)))
        result = self.install(workspace='B', start_page='claude')
        self.assertEqual(result['workspace'], 'B')
        self.assertEqual(module.core.load_config(self.config_path), self.config)
        with self.assertRaises(module.LauncherError):
            self.install(name='Wrong', workspace='B', start_page='newtab')


class ShortcutSourceContractTests(unittest.TestCase):
    def test_native_launcher_uses_shared_backend_and_cancel_does_not_confirm(self):
        source = (Path(__file__).resolve().parents[1] / 'app/shortcut.swift').read_text()
        self.assertIn('configuration.backend', source)
        self.assertIn('Contents/Resources/scripts/surge-cc', source)
        self.assertIn('"shortcut", "open", "--launcher-config"', source)
        self.assertNotIn('launcher.py', source)
        self.assertNotIn('Lia', source)
        self.assertIn('if alert.runModal() == .alertSecondButtonReturn', source)
        self.assertIn('matchesKernelIdentity(request)', source)
        self.assertIn('candidate.isFinishedLaunching', source)
        self.assertNotIn('kill(', source)


class ExistingWindowIdentityTests(unittest.TestCase):
    def setUp(self):
        import os
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.config_path = self.root / 'config.json'
        self.config = module.core.validate_config({
            'schema': 1, 'group': 'Claude', 'policy': 'Home',
            'expected_ip': '203.0.113.10', 'proxy_url': 'http://127.0.0.1:6152',
            'profile_path': '/fixture/profile.conf', 'browser_start_page': 'newtab'})
        self.profile = self.root / 'workspaces/A/data/Browser'
        self.profile.mkdir(parents=True)
        (self.profile / 'SingletonLock').symlink_to(module.browser_locks.socket.gethostname() + '-123')
        self.command = module.core.chrome_args(self.config, self.profile)
        session = self.root / 'sessions' / ('A-' + 'a' * 32)
        session.parent.mkdir()
        settings = Path(str(session) + '.config.json')
        receipt = Path(str(session) + '.receipt.json')
        status = Path(str(session) + '.status.json')
        self.guard_file = settings
        for path, value in ((settings, self.config),
                            (receipt, {'schema': 1, 'target': 'web', 'state': 'running', 'ok': True}),
                            (status, {'schema': 1, 'target': 'web', 'state': 'running', 'ok': True,
                                      'checked_at': dt.datetime.now(dt.timezone.utc).isoformat()})):
            module.workspaces.write_json(path, value)
        self.parent_args = ['/fixture/python', '-B', '-m', 'surge_cc.guard',
                            '--config', str(settings), '--receipt', str(receipt), '--status', str(status),
                            '--cwd', '/fixture', '--target', 'web',
                            '--lock', str(self.root / 'workspaces/A/.session.lock'), '--', *self.command]
        self.browser = NS(pid=123, uid=os.getuid(), argv=tuple(self.command),
                          executable=self.command[0], started=(500, 200))
        self.parent = NS(pid=456, uid=os.getuid(), argv=tuple(self.parent_args),
                         executable='/fixture/python', started=(499, 100))
        self.pid_patch = patch.object(module, 'parent_pid', return_value=456)
        self.pid_patch.start()
        self.addCleanup(self.pid_patch.stop)
        self.owned_patch = patch.object(module.browser_locks, '_owned_browser', return_value=True)
        self.owned_patch.start()
        self.addCleanup(self.owned_patch.stop)

    def observe(self, snapshots=None):
        with patch.object(module.browser_locks, '_process_snapshot',
                          side_effect=snapshots or [self.browser, self.parent, self.browser, self.parent]):
            return module.existing_browser(self.config_path, self.config)

    def test_exact_browser_guard_and_fresh_receipts_are_required(self):
        self.assertEqual(self.observe(), self.browser)

    def test_changed_process_identity_is_rejected_after_receipt_check(self):
        with self.assertRaises(module.LauncherError):
            self.observe([self.browser, self.parent, None])

    def test_guard_saved_page_cannot_differ_from_current_workspace(self):
        module.workspaces.write_json(self.guard_file, dict(self.config, browser_start_page='claude'))
        with self.assertRaises(module.LauncherError):
            self.observe()

    def test_parent_not_running_guard_is_rejected(self):
        self.parent.argv = ('/fixture/python', '-B', '-m', 'other.module', *self.parent_args[4:])
        with self.assertRaises(module.LauncherError):
            self.observe()

    def test_oauth_url_window_is_not_adopted_as_regular_browser(self):
        self.browser.argv = (*self.command[:-1], 'https://claude.ai/oauth/authorize?code=fixture')
        with self.assertRaises(module.LauncherError):
            self.observe([self.browser])


if __name__ == '__main__':
    unittest.main()
