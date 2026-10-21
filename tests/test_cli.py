"""Offline launcher tests: every process creation is mocked."""
from contextlib import ExitStack, redirect_stdout
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
        guarded, spawn = Mock(side_effect=completed_session), Mock()
        first = cli.launch(config(), self.config_path, "code", False, [], checker=checker,
                           popen=spawn, guarded=guarded)
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
        self.assertEqual(guarded.call_args.kwargs["on_started"], self.oauth.set_child)
        self.oauth_factory.return_value.__exit__.assert_called_once()
        spawn.assert_not_called()

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

    def test_checker_exception_never_launches(self):
        spawn = Mock()
        with self.assertRaises(core.Blocked):
            cli.launch(config(), self.config_path, "code", False, [],
                       checker=Mock(side_effect=core.Blocked("unavailable")), popen=spawn)
        spawn.assert_not_called()

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
    def test_check_failure_returns_nonzero_json(self):
        out = io.StringIO()
        with patch.object(cli, "load_config", return_value=config()), \
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
