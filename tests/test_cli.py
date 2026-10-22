"""Offline launcher tests: every process creation is mocked."""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import cli, core


def config():
    return core.validate_config({"schema": 1, "group": "Claude", "policy": "Home",
                                 "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:6152"})


def report(ok=True):
    return {"ok": ok, "summary": "test report", "checks": [], "checked_at": "test"}


def suspended_report():
    return {"schema": 1, "ok": False, "summary": "global suspended", "checked_at": core.now(),
            "paused": True, "pause_reason": "surge-global-mode", "surge_mode": "proxy",
            "launch_allowed": True, "protection_active": False,
            "checks": [core.row("surge", "Surge", True, "connected"),
                       core.row("mode", "mode", False, "global")]}


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-tests-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.config_path = self.folder / "config.json"
        self.claude = self.folder / "claude"
        self.claude.write_text("#!/bin/sh\nexit 99\n")
        self.claude.chmod(0o700)
        self.chrome = self.folder / "Chrome"
        self.chrome.write_text("not executed")
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(cli, "default_claude", return_value=self.claude))
        self.stack.enter_context(patch.object(cli, "CHROME", self.chrome))
        self.stack.enter_context(patch.object(core, "CHROME", self.chrome))
        self.stack.enter_context(patch.object(cli, "code_settings_ok", return_value=True))
        self.oauth_factory = self.stack.enter_context(patch.object(cli, "OAuthSession"))
        self.oauth = self.oauth_factory.return_value.__enter__.return_value
        self.oauth.browser_hook = self.folder / "private-oauth-opener"
        self.stack.enter_context(patch.dict(os.environ, {"NO_PROXY": "*"}, clear=True))

    def test_every_code_launch_runs_fresh_check_and_failure_never_popen(self):
        checker = Mock(side_effect=[report(True), report(False)])
        def completed_session(*args, **kwargs):
            receipt = kwargs["receipt_path"]
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_text(json.dumps({"schema": 1, "target": "code", "ok": True, "state": "running"}))
            return 0
        guarded, spawn, release = Mock(side_effect=completed_session), Mock(), Mock()
        first = cli.launch(config(), self.config_path, "code", False, [], checker=checker,
                           popen=spawn, guarded=guarded, startup_release=release)
        second = cli.launch(config(), self.config_path, "code", False, [], checker=checker,
                            popen=spawn, guarded=guarded)
        self.assertTrue(first["launched"])
        self.assertFalse(second["ok"])
        self.assertEqual(checker.call_count, 2)
        guarded.assert_called_once()
        self.assertEqual(guarded.call_args.kwargs["env"]["NO_PROXY"], "")
        self.assertEqual(guarded.call_args.kwargs["env"]["CLAUDE_CONFIG_DIR"],
                         str(self.folder / "workspaces/A/data/Claude"))
        self.assertEqual(guarded.call_args.kwargs["lock_path"], self.folder / "workspaces/A/.session.lock")
        self.assertEqual(guarded.call_args.kwargs["interval"], config()["guard_interval"])
        self.assertIs(guarded.call_args.kwargs["popen"], spawn)
        self.assertEqual(guarded.call_args.kwargs["env"]["BROWSER"], str(self.oauth.browser_hook))
        self.oauth.set_child.assert_not_called()
        release.assert_not_called()
        child = Mock(name="owned-child")
        guarded.call_args.kwargs["on_started"](child)
        self.oauth.set_child.assert_called_once_with(child)
        release.assert_called_once_with()
        self.oauth_factory.return_value.__exit__.assert_called_once()
        spawn.assert_not_called()

    def test_cli_startup_lease_releases_only_after_oauth_owns_child(self):
        events = []
        child = Mock(name="owned-child")
        self.oauth.set_child.side_effect = lambda value: events.append(("bound", value))
        release = Mock(side_effect=lambda: events.append(("released", None)))
        def completed(command, **kwargs):
            self.assertEqual(events, [])
            kwargs["on_started"](child)
            self.assertEqual(events, [("bound", child), ("released", None)])
            receipt = kwargs["receipt_path"]
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_text(json.dumps({"schema": 1, "target": "code", "ok": True, "state": "running"}))
            return 0
        result = cli.launch(config(), self.config_path, "code", False, [],
                            checker=Mock(return_value=report()), guarded=completed,
                            startup_release=release)
        self.assertTrue(result["launched"])
        release.assert_called_once_with()

    def test_cli_failed_child_binding_never_releases_startup_lease_early(self):
        release = Mock()
        self.oauth.set_child.side_effect = core.Blocked("child ownership not established")
        def guarded(command, **kwargs):
            kwargs["on_started"](Mock())
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "code", False, [],
                       checker=Mock(return_value=report()), guarded=guarded,
                       startup_release=release)
        release.assert_not_called()

    def test_web_startup_lease_releases_only_after_guard_receipt(self):
        events = []
        release = Mock(side_effect=lambda: events.append("released"))
        def started(*args, **kwargs):
            self.assertEqual(events, [])
            events.append("guard-ready")
            return {"schema": 1, "target": "web", "ok": True, "state": "running"}
        result = cli.launch(config(), self.config_path, "web", False, [],
                            checker=Mock(return_value=report()), web_guard=started,
                            startup_release=release)
        self.assertTrue(result["launched"])
        self.assertEqual(events, ["guard-ready", "released"])
        release.assert_called_once_with()
        release.reset_mock()
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "web", False, [],
                       checker=Mock(return_value=report()),
                       web_guard=Mock(side_effect=core.Blocked("no guard receipt")),
                       startup_release=release)
        release.assert_not_called()

    def test_guard_failure_before_spawn_is_not_reported_as_launched(self):
        output = cli.launch(config(), self.config_path, "code", False, [],
                            checker=Mock(return_value=report(True)), guarded=Mock(return_value=2))
        self.assertFalse(output["ok"])
        self.assertFalse(output["launched"])
        self.assertEqual(output["checks"][-1]["id"], "runtime")

    def test_missing_receipt_cannot_turn_zero_exit_into_launch_success(self):
        output = cli.launch(config(), self.config_path, "code", False, [],
                            checker=Mock(return_value=report(True)), guarded=Mock(return_value=0))
        self.assertFalse(output["ok"])
        self.assertFalse(output["launched"])

    def test_failed_web_check_does_not_start_browser_or_create_profile(self):
        spawn = Mock()
        output = cli.launch(config(), self.config_path, "web", False, [],
                            checker=Mock(return_value=report(False)), popen=spawn)
        self.assertFalse(output["ok"])
        spawn.assert_not_called()
        self.assertFalse((self.folder / "workspaces/A/data/Browser").exists())

    def test_paused_mode_does_not_launch_web_code_or_terminal(self):
        paused = {**report(False), "paused": True, "pause_reason": "surge-mode"}
        for target, terminal in (("web", False), ("code", False), ("code", True)):
            with self.subTest(target=target, terminal=terminal):
                spawn, guarded, terminal_open = Mock(), Mock(), Mock()
                outcome = cli.launch(config(), self.config_path, target, terminal, [],
                                     checker=Mock(return_value=paused), popen=spawn, guarded=guarded,
                                     terminal_open=terminal_open)
                self.assertTrue(outcome["paused"])
                self.assertFalse(outcome["ok"])
                spawn.assert_not_called()
                guarded.assert_not_called()
                terminal_open.assert_not_called()
                self.oauth_factory.assert_not_called()
        self.assertFalse((self.folder / "workspaces/A/data").exists())

    def test_checker_exception_never_launches(self):
        spawn = Mock()
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "code", False, [],
                       checker=Mock(side_effect=core.Blocked("unavailable")), popen=spawn)
        spawn.assert_not_called()

    def test_explicit_global_mode_launches_web_using_same_profile_and_proxy(self):
        web_guard = Mock()
        output = cli.launch(config(), self.config_path, "web", False, [],
                            checker=Mock(side_effect=lambda _: suspended_report()), web_guard=web_guard)
        self.assertTrue(output["ok"])
        self.assertTrue(output["launched"])
        self.assertTrue(output["paused"])
        self.assertFalse(output["protection_active"])
        args = web_guard.call_args.args[2]
        self.assertIn("--user-data-dir=" + str(self.folder / "workspaces/A/data/Browser"), args)
        self.assertIn("--proxy-server=" + config()["proxy_url"], args)

    def test_gui_global_launch_keeps_json_transport_free_of_stderr_notice(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            output = cli.launch(config(), self.config_path, "web", False, [],
                                checker=Mock(return_value=suspended_report()), web_guard=Mock())
        self.assertTrue(output["launched"])
        self.assertEqual(stderr.getvalue(), "")

    def test_terminal_global_launch_writes_notice_only_to_stderr(self):
        stderr = io.StringIO()
        with patch.dict(os.environ, {"SURGE_CC_TERMINAL_ENTRY": "1"}), \
                redirect_stderr(stderr), patch.object(cli, "code_settings_ok", return_value=True):
            output = cli.launch(config(), self.config_path, "web", False, [],
                                checker=Mock(return_value=suspended_report()), web_guard=Mock())
        self.assertTrue(output["launched"])
        self.assertIn("线路保护已挂起", stderr.getvalue())

    def test_explicit_global_mode_allows_terminal_without_bypassing_fresh_inner_gate(self):
        terminal = Mock()
        output = cli.launch(config(), self.config_path, "code", True, ["--continue"],
                            checker=Mock(return_value=suspended_report()), terminal_open=terminal)
        terminal.assert_called_once_with(self.config_path, ["--continue"], Path.cwd())
        self.assertTrue(output["ok"])
        self.assertTrue(output["paused"])
        self.assertEqual(output["target"], "code-terminal")

    def test_explicit_global_code_keeps_oauth_workspace_and_native_exit_code(self):
        def completed(*args, **kwargs):
            receipt = kwargs["receipt_path"]
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_text(json.dumps({"schema": 1, "target": "code", "ok": True, "state": "running"}))
            return 7
        guarded = Mock(side_effect=completed)
        output = cli.launch(config(), self.config_path, "code", False, ["--help"],
                            checker=Mock(return_value=suspended_report()), guarded=guarded)
        self.assertTrue(output["launched"])
        self.assertFalse(output["ok"])
        self.assertEqual(output["child_exit_code"], 7)
        env = guarded.call_args.kwargs["env"]
        self.assertEqual(env["BROWSER"], str(self.oauth.browser_hook))
        self.assertEqual(env["HTTPS_PROXY"], config()["proxy_url"])
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(self.folder / "workspaces/A/data/Claude"))

    def test_incomplete_global_exception_still_blocks(self):
        for changes in ({"surge_mode": "direct"}, {"protection_active": True},
                        {"pause_reason": "surge-mode"}, {"launch_allowed": 1}):
            web = Mock()
            output = cli.launch(config(), self.config_path, "web", False, [],
                                checker=Mock(return_value={**suspended_report(), **changes}), web_guard=web)
            self.assertFalse(output["ok"])
            web.assert_not_called()

    def test_worker_receipt_updates_rule_to_global_launch_status(self):
        initial = core.result([core.row(key, key, True, "pass") for key in sorted(core.CHECK_IDS)], config())
        receipt = {"schema": 1, "target": "web", "ok": True, "state": "running",
                   "suspended": True, "protection_active": False}
        output = cli.launch(config(), self.config_path, "web", False, [],
                            checker=Mock(return_value=initial), web_guard=Mock(return_value=receipt))
        self.assertTrue(output["launched"])
        self.assertTrue(output["paused"])
        self.assertFalse(output["protection_active"])
        self.assertEqual(next(c for c in output["checks"] if c["id"] == "mode")["status"], "fail")

    def test_temporary_settings_overrides_rejected_before_check_or_launch(self):
        for args in (["--settings", "settings.json"], ["--settings=[]"],
                     ["--setting-sources", "remote"], ["--setting-sources=user,user"],
                     ["--settings", '{"env":{"BROWSER":"open"}}']):
            with self.subTest(args=args):
                checker, spawn = Mock(), Mock()
                with self.assertRaises(core.Blocked):
                    cli.launch(config(), self.config_path, "code", False, args, checker=checker, popen=spawn)
                checker.assert_not_called()
                spawn.assert_not_called()

    def test_orca_inline_settings_are_validated_without_blocking_safe_flags(self):
        cli.validate_launch_arguments(config(), ["--setting-sources=user,project,local",
            "--settings", '{"disableAllHooks":true}', "--strict-mcp-config"])
        for field, value in (("HTTPS_PROXY", "http://127.0.0.1:6153"),
                             ("NO_PROXY", "*"), ("BROWSER", "open"),
                             ("DISABLE_UPDATES", "0"), ("CLAUDE_CONFIG_DIR", "/tmp/other")):
            with self.subTest(field=field), self.assertRaises(core.Blocked):
                cli.validate_launch_arguments(config(), ["--settings=" + json.dumps({"env": {field: value}})])

    def test_update_cannot_replace_guarded_entry(self):
        for command in ("install", "update", "upgrade"):
            checker = Mock()
            with self.subTest(command=command), self.assertRaises(core.Blocked):
                cli.launch(config(), self.config_path, "code", False, [command], checker=checker)
            checker.assert_not_called()

    def test_conflicting_provider_settings_rejected_before_launch(self):
        checker, spawn = Mock(), Mock()
        with patch.object(cli, "code_settings_ok", return_value=False), self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "code", False, [], checker=checker, popen=spawn)
        checker.assert_not_called()
        spawn.assert_not_called()

    def test_remote_attacher_not_claimed_as_protected_local_cli(self):
        for args in ([command] for command in (
                "attach", "remote-control", "rc", "teleport", "remote",
                "--remote-control", "--remote", "--teleport", "--cloud",
                "--environment", "--desktop", "--bg", "--background", "--tmux",
                "--remote-control=name", "--teleport=session", "--cloud=work")):
            checker, spawn = Mock(), Mock()
            with self.subTest(args=args), self.assertRaises(core.Blocked):
                cli.launch(config(), self.config_path, "code", False, ["--debug", *args],
                           checker=checker, popen=spawn)
            checker.assert_not_called()
            spawn.assert_not_called()

    def test_web_extra_flags_rejected(self):
        spawn = Mock()
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "web", False, ["--proxy-server=direct://"],
                       checker=Mock(return_value=report()), popen=spawn)
        spawn.assert_not_called()

    def test_web_launch_uses_app_owned_profile_and_fixed_proxy(self):
        web_guard, spawn = Mock(), Mock()
        output = cli.launch(config(), self.config_path, "web", False, [],
                            checker=Mock(return_value=report()), popen=spawn, web_guard=web_guard)
        self.assertTrue(output["launched"])
        args = web_guard.call_args.args[2]
        self.assertIn("--user-data-dir=" + str(self.folder / "workspaces/A/data/Browser"), args)
        self.assertIn("--proxy-server=" + config()["proxy_url"], args)
        self.assertNotIn("direct://", " ".join(args).lower())
        self.assertEqual((self.folder / "workspaces/A/data/Browser").stat().st_mode & 0o777, 0o700)
        self.assertIs(web_guard.call_args.kwargs["popen"], spawn)
        spawn.assert_not_called()

    def test_existing_browser_lock_or_symlink_is_not_reused(self):
        folder = self.folder / "workspaces/A/data/Browser"
        folder.mkdir(parents=True)
        lock = folder / "SingletonLock"
        lock.symlink_to(self.folder / "nonexistent-lock-owner")
        spawn = Mock()
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "web", False, [],
                       checker=Mock(return_value=report()), popen=spawn)
        spawn.assert_not_called()
        lock.unlink()
        folder.rmdir()
        folder.symlink_to(self.folder / "PersonalProfile")
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "web", False, [],
                       checker=Mock(return_value=report()), popen=spawn)
        spawn.assert_not_called()

    def test_browser_immediate_exit_is_not_reported_as_success(self):
        web_guard = Mock(side_effect=core.Blocked("worker exited"))
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "web", False, [],
                       checker=Mock(return_value=report()), web_guard=web_guard)

    def test_terminal_request_does_not_directly_spawn_claude(self):
        terminal, spawn = Mock(), Mock()
        output = cli.launch(config(), self.config_path, "code", True, ["--", "--continue"],
                            checker=Mock(return_value=report()), popen=spawn, terminal_open=terminal)
        self.assertTrue(output["launched"])
        spawn.assert_not_called()
        self.assertEqual(terminal.call_args.args[1], ["--continue"])

    def test_terminal_script_rechecks_and_shell_quotes_user_arguments(self):
        opener = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        arg = "literal; $(touch never-executed)"
        cwd = self.folder / "space and ' quote"
        cli.terminal_launcher(self.config_path, [arg], cwd, opener=opener)
        files = list((self.folder / "launchers").glob("*.command"))
        self.assertEqual(len(files), 1)
        text = files[0].read_text()
        self.assertIn("launch code --", text)
        self.assertIn("'literal; $(touch never-executed)'", text)
        self.assertIn("cd -- ", text)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o700)
        self.assertEqual(opener.call_args.args[0][:3], ["/usr/bin/open", "-a", "Terminal"])


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-settings-tests-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.home = self.folder / "home"
        self.cwd = self.folder / "project" / "subdir"
        self.home.mkdir()
        self.cwd.mkdir(parents=True)
        self.home_patch = patch.object(Path, "home", return_value=self.home)
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)

    def write_settings(self, path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))

    def test_clear_environment_and_missing_settings_accepted(self):
        self.assertTrue(cli.code_settings_ok(config(), self.cwd, {}))

    def test_environment_provider_override_rejected(self):
        self.assertFalse(cli.code_settings_ok(config(), self.cwd, {"CLAUDE_CODE_USE_VERTEX": "1"}))

    def test_parent_project_settings_cannot_override_proxy_or_provider(self):
        path = self.cwd.parent / ".claude/settings.local.json"
        for env in ({"NO_PROXY": "*"}, {"HTTPS_PROXY": "http://203.0.113.20:8080"},
                    {"BROWSER": "/usr/bin/open"}, {"BROWSER": ""},
                    {"ANTHROPIC_BASE_URL": "https://other.invalid"}, {"CLAUDE_CODE_USE_BEDROCK": "1"}):
            with self.subTest(env=env):
                self.write_settings(path, {"env": env})
                self.assertFalse(cli.code_settings_ok(config(), self.cwd, {}))

    def test_home_settings_conflict_rejected(self):
        self.write_settings(self.home / ".claude/settings.json", {"env": {"ALL_PROXY": "http://203.0.113.20:8080"}})
        self.assertFalse(cli.code_settings_ok(config(), self.cwd, {}))

    def test_custom_config_directory_is_checked(self):
        custom = self.folder / "custom"
        self.write_settings(custom / "settings.json", {"env": {"NO_PROXY": "*"}})
        self.assertFalse(cli.code_settings_ok(config(), self.cwd, {"CLAUDE_CONFIG_DIR": str(custom)}))

    def test_malformed_settings_rejected(self):
        path = self.home / ".claude/settings.json"
        path.parent.mkdir()
        for content in ("invalid", "[]", '{"env":[]}'):
            with self.subTest(content=content):
                path.write_text(content)
                self.assertFalse(cli.code_settings_ok(config(), self.cwd, {}))

    def test_matching_proxy_and_nonprovider_settings_accepted(self):
        self.write_settings(self.home / ".claude/settings.json", {
            "env": {"HTTPS_PROXY": config()["proxy_url"], "NO_PROXY": ""}, "theme": "dark"})
        self.assertTrue(cli.code_settings_ok(config(), self.cwd, {}))


class MainTests(unittest.TestCase):
    def test_mode_change_during_audit_only_allows_explicit_global_exception(self):
        basic = core.result([core.row(key, key, True, "pass") for key in core.CHECK_IDS], config())
        for fresh in (suspended_report(), {"ok": True}):
            with patch.object(cli, "run_checks", side_effect=[basic, fresh]), \
                    patch("surge_cc.audit.audit_checks", return_value=[core.row("privacy", "privacy", False, "changed")]), \
                    patch.object(cli, "Surge") as surge:
                surge.return_value.status.return_value = {"mode": "proxy"}
                actual = cli.full_checks(config())
            self.assertFalse(actual["ok"])
            self.assertEqual(actual.get("launch_allowed", False), fresh.get("launch_allowed", False))

    def test_guard_status_distinguishes_suspended_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            folder = path.parent / "sessions"
            folder.mkdir()
            (folder / "A-test.status.json").write_text(json.dumps({"schema": 1,
                "target": "web", "state": "suspended", "ok": False,
                "checked_at": core.now(), "detail": "global suspended"}))
            overview = cli.guard_status(config(), path)["guard"]
            self.assertFalse(overview["running"])
            self.assertFalse(overview["protection_active"])
            self.assertTrue(overview["suspended"])
            self.assertEqual(overview["suspended_sessions"], 1)
            self.assertEqual(overview["state"], "suspended")

    def test_full_checks_preserves_pause_and_never_starts_privacy_probes(self):
        paused = {**report(False), "paused": True, "pause_reason": "surge-mode", "surge_mode": "proxy"}
        with patch.object(cli, "run_checks", return_value=paused), \
                patch("surge_cc.audit.audit_checks") as audit:
            self.assertEqual(cli.full_checks(config()), paused)
        audit.assert_not_called()

    def test_paused_check_remains_nonzero_and_does_not_mutate_surge(self):
        paused = {**report(False), "paused": True, "pause_reason": "surge-mode", "surge_mode": "proxy"}
        out = io.StringIO()
        with patch.object(cli, "load_config", return_value=config()), \
                patch.object(cli, "migrate_accounts"), \
                patch.object(cli, "full_checks", return_value=paused), \
                patch.object(cli, "Surge") as surge, redirect_stdout(out):
            status = cli.main(["--config", "/test/config.json", "check", "--json"])
        self.assertEqual(status, 2)
        self.assertTrue(json.loads(out.getvalue())["paused"])
        surge.assert_not_called()

    def test_check_failure_returns_nonzero_json(self):
        out = io.StringIO()
        with patch.object(cli, "load_config", return_value=config()), \
                patch.object(cli, "migrate_accounts"), \
                patch.object(cli, "full_checks", return_value=report(False)), redirect_stdout(out):
            code = cli.main(["--config", "/test/config.json", "check", "--json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out.getvalue())["ok"])

    def test_blocked_exception_is_safe_structured_failure(self):
        out = io.StringIO()
        with patch.object(cli, "load_config", side_effect=core.Blocked("not configured")), redirect_stdout(out):
            code = cli.main(["check", "--json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
