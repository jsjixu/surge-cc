"""Offline isolation policy tests; no native Claude, credentials, or network used."""
from contextlib import ExitStack, redirect_stderr
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import cli, core, guard, isolation


class IsolationFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-isolation-tests-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.temp_root = Path(self.temp.name).resolve()
        self.base = self.temp_root / "isolated"
        self.project_root = self.base / "projects" / "vv"
        self.home = self.base / ".runtime" / "vv" / "home"
        self.project_root.mkdir(parents=True, mode=0o700)
        self.home.mkdir(parents=True, mode=0o700)
        self.config_root = self.temp_root / "trusted-launcher"
        self.config_root.mkdir(mode=0o700)
        self.config_path = self.config_root / "config.json"
        self.registry = self.config_root / isolation.REGISTRY_NAME
        self.project = isolation.Project("vv", self.project_root, self.home)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(isolation, "DEFAULT_ROOT", self.base))
        self.data = {"schema": 1, "root": str(self.base), "projects": [
            {"id": "vv", "path": str(self.project_root), "home": str(self.home)}]}

    def write_registry(self, data=None):
        self.registry.write_text(json.dumps(self.data if data is None else data))
        self.registry.chmod(0o600)


class RegistryTests(IsolationFixture):
    def test_registry_missing_outside_reserved_root_is_ordinary_launch(self):
        self.assertIsNone(isolation.for_cwd(self.config_path, self.temp_root))

    def test_registry_missing_inside_reserved_root_fails_closed(self):
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)

    def test_external_marked_copy_without_registry_fails_closed(self):
        copied = self.temp_root / "external-marked-copy"
        nested = copied / "src"
        nested.mkdir(parents=True)
        (copied / ".surge-cc-isolated.json").write_text('{"project":"vv"}')
        for cwd in (copied, nested):
            with self.subTest(cwd=cwd), self.assertRaises(core.Blocked):
                isolation.for_cwd(self.config_path, cwd)

    def test_external_marked_copy_with_unrelated_registry_fails_closed(self):
        self.write_registry()
        copied = self.temp_root / "external-marked-copy"
        nested = copied / "src"
        nested.mkdir(parents=True)
        (copied / ".surge-cc-isolated.json").write_text('{"project":"vv"}')
        for cwd in (copied, nested):
            with self.subTest(cwd=cwd), self.assertRaises(core.Blocked):
                isolation.for_cwd(self.config_path, cwd)

    def test_valid_root_and_nested_cwd_select_exact_project(self):
        self.write_registry()
        nested = self.project_root / "src" / "nested"
        nested.mkdir(parents=True)
        for cwd in (self.project_root, nested):
            with self.subTest(cwd=cwd):
                self.assertEqual(isolation.for_cwd(self.config_path, cwd), self.project)

    def test_valid_registry_outside_any_project_does_not_enforce_global_change(self):
        self.write_registry()
        self.assertIsNone(isolation.for_cwd(self.config_path, self.temp_root))

    def test_unregistered_sibling_and_runtime_cwd_never_fall_back(self):
        self.write_registry()
        sibling = self.base / "projects" / "vv-other"
        sibling.mkdir()
        for cwd in (sibling, self.base, self.home):
            with self.subTest(cwd=cwd), self.assertRaises(core.Blocked):
                isolation.for_cwd(self.config_path, cwd)

    def test_malformed_schema_and_duplicate_project_fail_closed(self):
        cases = [[], None, {"schema": 2, "projects": []},
                 {**self.data, "projects": "not-a-list"},
                 {**self.data, "projects": self.data["projects"] * 2}]
        for value in cases:
            with self.subTest(value=value):
                self.write_registry(value)
                # write_registry(None) intentionally writes default; explicitly
                # represent JSON null for this malformed-input case.
                if value is None:
                    self.registry.write_text("null")
                with self.assertRaises(core.Blocked):
                    isolation.for_cwd(self.config_path, self.project_root)
        self.registry.write_text("{broken")
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)

    def test_project_and_home_scope_cannot_be_broadened_in_registry(self):
        for field, value in (("path", str(self.base)), ("home", str(self.base)),
                             ("id", "../vv"), ("id", "VV")):
            with self.subTest(field=field, value=value):
                data = {**self.data, "projects": [{**self.data["projects"][0], field: value}]}
                self.write_registry(data)
                with self.assertRaises(core.Blocked):
                    isolation.for_cwd(self.config_path, self.project_root)

    def test_registry_symlink_and_hardlink_rejected(self):
        target = self.temp_root / "registry-copy.json"
        target.write_text(json.dumps(self.data))
        target.chmod(0o600)
        self.registry.symlink_to(target)
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)
        self.registry.unlink()
        os.link(target, self.registry)
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)

    def test_registry_permissions_and_foreign_owner_rejected(self):
        self.write_registry()
        self.registry.chmod(0o644)
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)
        self.registry.chmod(0o600)
        with patch.object(isolation.os, "getuid", return_value=os.getuid() + 10000), self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)

    def test_project_cwd_alias_and_writable_root_rejected(self):
        self.write_registry()
        alias = self.temp_root / "project-alias"
        alias.symlink_to(self.project_root, target_is_directory=True)
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, alias)
        self.project_root.chmod(0o777)
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)

    def test_home_symlink_rejected(self):
        self.home.rmdir()
        elsewhere = self.temp_root / "outside-home"
        elsewhere.mkdir()
        self.home.symlink_to(elsewhere, target_is_directory=True)
        self.write_registry()
        with self.assertRaises(core.Blocked):
            isolation.for_cwd(self.config_path, self.project_root)


class EnvironmentAndArgumentsTests(IsolationFixture):
    def test_environment_whitelist_replaces_home_proxy_and_state(self):
        inherited = {key: "SYNTHETIC-DO-NOT-INHERIT" for key in (
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS", "GH_TOKEN", "SSH_AUTH_SOCK", "NODE_OPTIONS", "PYTHONPATH",
            "DYLD_INSERT_LIBRARIES", "ORCA_SOCKET", "GIT_CONFIG_COUNT", "HOME", "CLAUDE_CONFIG_DIR",
            "PATH", "BROWSER", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")}
        inherited.update(TERM="xterm-256color", COLORTERM="truecolor", NO_COLOR="1")
        before = dict(inherited)
        env = isolation.environment(self.project, "http://127.0.0.1:62919", inherited)
        self.assertEqual(inherited, before)
        self.assertNotIn("SYNTHETIC-DO-NOT-INHERIT", env.values())
        for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "AWS_SECRET_ACCESS_KEY",
                    "GOOGLE_APPLICATION_CREDENTIALS", "GH_TOKEN", "SSH_AUTH_SOCK", "NODE_OPTIONS", "PYTHONPATH",
                    "DYLD_INSERT_LIBRARIES", "ORCA_SOCKET", "GIT_CONFIG_COUNT", "BROWSER"):
            self.assertNotIn(key, env)
        self.assertEqual(env["HOME"], str(self.home))
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(self.home / ".claude"))
        self.assertEqual(env["TMPDIR"], str(self.home / "tmp") + "/")
        self.assertEqual(env["CLAUDE_CODE_TMPDIR"], str(self.home / "tmp"))
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:62919")
        self.assertEqual(env["HTTPS_PROXY"], env["http_proxy"])
        self.assertEqual(env["NO_PROXY"], "")
        self.assertEqual(env["no_proxy"], "")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["TERM"], "xterm-256color")
        self.assertEqual(env["DISABLE_AUTOUPDATER"], "1")

    def test_unmatched_proxy_is_refused_instead_of_silently_unreachable(self):
        for proxy in ("http://127.0.0.1:6152", "http://localhost:62919", "socks5://127.0.0.1:62919"):
            with self.subTest(proxy=proxy), self.assertRaises(core.Blocked):
                isolation.environment(self.project, proxy, {})

    def test_args_reject_external_integrations_and_override_forms(self):
        flags = ("--settings", "--setting-sources", "--mcp-config", "--plugin-dir", "--plugin-url",
                 "--chrome", "--ide", "--add-dir", "--worktree", "-w")
        for flag in flags:
            for values in ([flag, "synthetic"], [flag + "=synthetic"]):
                with self.subTest(values=values), self.assertRaises(core.Blocked):
                    isolation.arguments(values)

    def test_safe_cli_protocol_arguments_keep_order_with_forced_no_integrations(self):
        values = ["--print", "synthetic prompt", "--output-format", "stream-json", "--verbose"]
        result = isolation.arguments(values)
        self.assertEqual(result[-len(values):], values)
        self.assertEqual(result[:2], ["--setting-sources", ""])
        settings = json.loads(result[result.index("--settings") + 1])
        self.assertTrue(settings["disableAllHooks"])
        self.assertFalse(settings["remoteControlAtStartup"])
        self.assertIn("--strict-mcp-config", result)
        self.assertEqual(json.loads(result[result.index("--mcp-config") + 1]), {"mcpServers": {}})
        self.assertIn("--no-chrome", result)

    def test_resume_is_scoped_to_new_state_instead_of_importing_old_state(self):
        self.assertEqual(isolation.arguments(["--continue"])[-1:], ["--continue"])
        env = isolation.environment(self.project, "http://127.0.0.1:62919", {})
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(self.project.config))


class ProfileTests(IsolationFixture):
    def setUp(self):
        super().setUp()
        self.native = self.temp_root / "native-claude"
        self.native.write_text("not executed")
        self.hook = Path("/private/tmp/surge-cc-oauth-synthetic/browser")

    def test_deny_default_and_only_current_project_home_are_writable(self):
        policy = isolation.profile(self.project, self.native, self.hook)
        self.assertIn("(deny default)", policy)
        self.assertNotIn("(allow default)", policy)
        exact = '(allow file-read* file-write* (subpath ' + json.dumps(str(self.project_root)) + ') (subpath ' + json.dumps(str(self.home)) + '))'
        self.assertIn(exact, policy)
        for broad in ("/System", "/System/Volumes", "/System/Volumes/Data", "/Users", str(Path.home()),
                      str(self.base), str(self.base / "projects"), str(self.base / ".runtime"), "/private/tmp", "/Library"):
            self.assertNotIn("(subpath " + json.dumps(broad) + ")", policy)
        self.assertIn('(subpath "/System/Library")', policy)

    def test_network_and_mach_access_not_broadly_opened(self):
        policy = isolation.profile(self.project, self.native, self.hook)
        self.assertIn('(allow network-outbound (remote tcp "localhost:62919"))', policy)
        self.assertIn('(allow network-outbound (literal "/private/tmp/surge-cc-oauth-synthetic/s"))', policy)
        for unsafe in ("(allow network*)", "(allow network-outbound)", "(allow mach-lookup", "(allow appleevent-send",
                       "securityd", 'remote tcp "localhost:*"', '(subpath "/private/tmp/surge-cc-oauth-synthetic")'):
            self.assertNotIn(unsafe, policy)

    def test_only_current_terminal_devices_are_granted(self):
        with patch.object(isolation.os, "ttyname", side_effect=["/dev/ttys007", OSError(), OSError()]):
            policy = isolation.profile(self.project, self.native, self.hook)
        self.assertIn('(literal "/dev/ttys007")', policy)
        self.assertNotIn('/dev/ttys[', policy)
        self.assertNotIn('(subpath "/dev")', policy)
        self.assertNotIn('(literal "/dev/ttys008")', policy)

    def test_native_hook_and_probe_allowed_as_exact_files(self):
        probe = self.temp_root / "probe.py"
        probe.write_text("not executed")
        policy = isolation.profile(self.project, self.native, self.hook, probe=probe)
        for file in (self.native, self.hook, probe):
            self.assertIn("(literal " + json.dumps(str(file.resolve())) + ")", policy)
        self.assertNotIn("(subpath " + json.dumps(str(self.native.parent)) + ")", policy)

    def test_non_session_hook_rejected(self):
        for hook in (Path("/tmp/another/browser"), Path("/private/tmp/browser"), self.project_root / "browser"):
            with self.subTest(hook=hook), self.assertRaises(core.Blocked):
                isolation.profile(self.project, self.native, hook)

    def test_sandbox_missing_is_blocked_without_native_fallback(self):
        with patch.object(isolation, "SANDBOX", self.temp_root / "missing"), self.assertRaises(core.Blocked):
            isolation.command(self.project, self.native, ["--help"], self.hook)

    def test_command_uses_sandbox_and_new_private_directories(self):
        sandbox = self.temp_root / "sandbox-exec"
        sandbox.write_text("not executed")
        with patch.object(isolation, "SANDBOX", sandbox):
            command = isolation.command(self.project, self.native, ["--help"], self.hook)
        self.assertEqual(command[:2], [str(sandbox), "-p"])
        self.assertEqual(command[3], str(self.native))
        self.assertIn("(deny default)", command[2])
        self.assertEqual(command[-1], "--help")
        for folder in (self.project.config, self.home / "tmp", self.home / ".cache", self.home / ".config"):
            self.assertTrue(folder.is_dir())
            self.assertFalse(folder.stat().st_mode & 0o077)

    def test_existing_state_symlink_is_not_accepted(self):
        outside = self.temp_root / "outside"
        outside.mkdir()
        self.project.config.symlink_to(outside, target_is_directory=True)
        sandbox = self.temp_root / "sandbox-exec"
        sandbox.write_text("not executed")
        with patch.object(isolation, "SANDBOX", sandbox), self.assertRaises(core.Blocked):
            isolation.command(self.project, self.native, [], self.hook)


class CLIIntegrationTests(IsolationFixture):
    def setUp(self):
        super().setUp()
        self.write_registry()
        from surge_cc import keychain_auth
        keychain_auth.migrate_legacy(self.config_path, "A")
        self.native = self.temp_root / "native-claude"
        self.native.write_text("not executed")
        self.native.chmod(0o700)
        self.config = core.validate_config({"schema": 1, "group": "Claude", "policy": "Home",
             "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:62919"})
        self.stack.enter_context(patch.object(cli, "default_claude", return_value=self.native))
        self.cwd_patch = self.stack.enter_context(patch.object(cli.Path, "cwd", return_value=self.project_root))
        self.settings_check = self.stack.enter_context(patch.object(cli, "code_settings_ok", return_value=True))
        self.oauth_factory = self.stack.enter_context(patch.object(cli, "OAuthSession"))
        self.oauth = self.oauth_factory.return_value.__enter__.return_value
        self.oauth.browser_hook = Path("/private/tmp/surge-cc-oauth-synthetic/browser")
        self.runtime_factory = self.stack.enter_context(patch.object(guard, "RuntimeChecker"))
        self.stack.enter_context(patch.dict(os.environ, {"ANTHROPIC_API_KEY": "SYNTHETIC-KEY", "NO_PROXY": "*"}, clear=True))
        self.checker = Mock(return_value={"ok": True, "checks": [], "summary": "synthetic"})
        self.spawn = Mock()
        self.guarded = Mock(side_effect=self.completed)
        sandbox = self.temp_root / "sandbox-exec"
        sandbox.write_text("not executed")
        self.stack.enter_context(patch.object(isolation, "SANDBOX", sandbox))

    def completed(self, command, **kwargs):
        receipt = kwargs["receipt_path"]
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({"schema": 1, "target": "code", "state": "running", "ok": True}))
        return 0

    def launch(self, values=None):
        with redirect_stderr(io.StringIO()):
            return cli.launch(self.config, self.config_path, "code", False, values or [],
                              checker=self.checker, popen=self.spawn, guarded=self.guarded)

    def test_isolated_launch_uses_policy_clean_env_native_route_and_oauth_hook(self):
        report = self.launch(["--help"])
        self.assertTrue(report["ok"])
        self.assertEqual(report["file_isolation"]["project"], "vv")
        self.settings_check.assert_not_called()
        call = self.guarded.call_args
        self.assertEqual(call.args[0][0], str(isolation.SANDBOX))
        self.assertEqual(call.args[0][3], str(self.native))
        self.assertEqual(call.kwargs["cwd"], self.project_root)
        self.assertNotIn("ANTHROPIC_API_KEY", call.kwargs["env"])
        self.assertEqual(call.kwargs["env"]["HOME"], str(self.home))
        self.assertEqual(call.kwargs["env"]["CLAUDE_CONFIG_DIR"], str(self.project.config))
        self.assertEqual(call.kwargs["env"]["BROWSER"], str(self.oauth.browser_hook))
        child = Mock()
        call.kwargs["on_started"](child)
        self.oauth.set_child.assert_called_once_with(child)
        self.runtime_factory.assert_called_once_with(self.config, process=str(self.native))
        self.assertIs(call.kwargs["checker"], self.runtime_factory.return_value)
        self.spawn.assert_not_called()

    def test_ordinary_project_keeps_previous_native_launch_path(self):
        from surge_cc import isolated_trust
        self.cwd_patch.return_value = self.temp_root
        with patch.object(isolated_trust, "prepare") as trust:
            report = self.launch(["--help"])
            trust.assert_not_called()
        self.assertTrue(report["ok"])
        self.assertNotIn("file_isolation", report)
        self.settings_check.assert_called_once()
        self.runtime_factory.assert_not_called()
        self.assertEqual(self.guarded.call_args.args[0][0], str(self.native))
        self.assertEqual(self.guarded.call_args.kwargs["env"]["CLAUDE_CONFIG_DIR"],
                         str(self.config_root / "workspaces/A/data/Claude"))

    def test_missing_registry_fails_before_checks_oauth_or_process(self):
        self.registry.unlink()
        with self.assertRaises(core.Blocked):
            self.launch()
        self.checker.assert_not_called()
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()

    def test_isolated_override_rejected_before_network_and_process(self):
        with self.assertRaises(core.Blocked):
            self.launch(["--settings", '{"env":{"HOME":"/synthetic-old-home"}}'])
        self.checker.assert_not_called()
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()

    def test_failed_route_check_never_builds_or_starts_child(self):
        self.checker.return_value = {"ok": False, "checks": [], "summary": "synthetic failure"}
        result = self.launch(["--help"])
        self.assertFalse(result["ok"])
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()


if __name__ == "__main__":
    unittest.main()
