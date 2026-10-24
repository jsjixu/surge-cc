"""Token-mode integration boundaries; all credentials here are synthetic."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
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
from surge_cc import cli, core, dev_proxy, guard, isolated_auth, isolation, keychain_auth, oauth, orca_titles


TOKEN = "sk-ant-oat01-" + "synthetic-keychain-token-for-tests-only-123456789"
OUTSIDE = "synthetic-untrusted-environment-value"


def config():
    return core.validate_config({"schema": 1, "group": "Claude", "policy": "Home",
        "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:62919"})


def report(ok=True):
    return {"ok": ok, "summary": "synthetic route report", "checks": [], "checked_at": "test"}


def completed(*args, **kwargs):
    receipt = kwargs["receipt_path"]
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps({"schema": 1, "target": "code", "ok": True, "state": "running"}))
    return 0


class KeychainLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-keychain-launch-",
                                                 dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / "config.json"
        keychain_auth.migrate_legacy(self.config_path, "A")
        self.native = self.root / "native-unused"
        self.native.write_text("#!/bin/sh\nexit 99\n")
        self.native.chmod(0o700)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(patch.object(cli, "default_claude", return_value=self.native))
        self.stack.enter_context(patch.object(cli.isolation, "for_cwd", return_value=None))
        self.settings = self.stack.enter_context(patch.object(cli, "code_settings_ok", return_value=True))
        self.mode = {"enabled": True, "service": keychain_auth.SERVICE, "account": "synthetic"}
        self.load = self.stack.enter_context(patch.object(keychain_auth, "load", return_value=self.mode))
        self.read = self.stack.enter_context(patch.object(keychain_auth, "read_token", return_value=TOKEN))
        self.oauth_factory = self.stack.enter_context(patch.object(cli, "OAuthSession"))
        self.session = self.oauth_factory.return_value.__enter__.return_value
        self.session.browser_hook = self.root / "private-browser-hook"
        self.session.child_environment.side_effect = lambda env: dict(env, BROWSER=str(self.session.browser_hook),
            PATH=str(self.session.browser_hook.parent) + ":" + env.get("PATH", "/usr/bin:/bin"))
        self.development_factory = self.stack.enter_context(patch.object(dev_proxy, "Session"))
        self.development = self.development_factory.return_value.__enter__.return_value
        self.development.port = 49152
        self.development.proxy_url = "http://127.0.0.1:49152"
        self.strict_factory = self.stack.enter_context(patch.object(dev_proxy, "StrictRuntimeChecker"))
        self.guarded = Mock(side_effect=completed)
        self.output, self.errors = io.StringIO(), io.StringIO()
        self.stack.enter_context(redirect_stdout(self.output))
        self.stack.enter_context(redirect_stderr(self.errors))

    def launch(self, arguments=None, *, checker=None, terminal=False):
        return cli.launch(config(), self.config_path, "code", terminal, arguments or [],
                          checker=checker or Mock(return_value=report()), guarded=self.guarded)

    def test_failed_route_reads_only_opt_in_not_keychain_or_browser(self):
        result = self.launch(checker=Mock(return_value=report(False)))
        self.assertFalse(result["ok"])
        self.load.assert_called_once_with(self.config_path, "A")
        self.read.assert_not_called()
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()

    def test_route_exception_never_reads_token_or_launches(self):
        with self.assertRaises(core.Blocked):
            self.launch(checker=Mock(side_effect=core.Blocked("synthetic route unavailable")))
        self.read.assert_not_called()
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()

    def test_keychain_read_follows_route_check_and_failure_cannot_fallback(self):
        events = []
        self.read.side_effect = lambda *_: events.append("read") or TOKEN
        checked = lambda *_: events.append("route") or report()
        self.launch(checker=checked)
        self.assertEqual(events, ["route", "read"])
        self.read.side_effect = core.Blocked("synthetic keychain unavailable")
        self.oauth_factory.reset_mock()
        self.guarded.reset_mock()
        with self.assertRaises(core.Blocked):
            self.launch(checker=checked)
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()

    def test_child_receives_only_selected_token_no_secret_in_argv_or_report(self):
        inherited = {name: OUTSIDE for name in (
            "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_SECURESTORAGE_CONFIG_DIR")}
        with patch.dict(os.environ, inherited):
            result = self.launch(["--help"])
        invocation = self.guarded.call_args
        env = invocation.kwargs["env"]
        self.assertEqual(env["CLAUDE_CODE_OAUTH_TOKEN"], TOKEN)
        self.assertNotIn(OUTSIDE, env.values())
        self.assertEqual(env["HTTPS_PROXY"], config()["proxy_url"])
        self.assertEqual(env["CLAUDE_SECURESTORAGE_CONFIG_DIR"],
                         str(self.root / "workspaces/A/data/Claude/.token-auth-disabled"))
        self.assertEqual(env["BROWSER"], str(self.session.browser_hook))
        child = Mock(name="owned-token-child")
        invocation.kwargs["on_started"](child)
        self.session.set_child.assert_called_once_with(child)
        self.assertFalse(self.oauth_factory.call_args.kwargs["allow_authorization"])
        for exposed in (repr(invocation.args), json.dumps(result),
                        self.output.getvalue(), self.errors.getvalue()):
            self.assertNotIn(TOKEN, exposed)
            self.assertNotIn(OUTSIDE, exposed)
        for file in self.root.rglob("*.json"):
            self.assertNotIn(TOKEN, file.read_text())
        self.assertEqual(result["authentication"],
                         {"source": "keychain-setup-token", "automatic_browser_login": False})

    def test_gui_terminal_handoff_does_not_fetch_secret(self):
        terminal = Mock()
        result = cli.launch(config(), self.config_path, "code", True, [],
                            checker=Mock(return_value=report()), terminal_open=terminal,
                            guarded=self.guarded)
        self.assertTrue(result["launched"])
        terminal.assert_called_once()
        self.read.assert_not_called()
        self.oauth_factory.assert_not_called()

    def test_disabled_opt_in_keeps_existing_oauth_mode(self):
        self.load.return_value = None
        result = self.launch()
        self.read.assert_not_called()
        self.assertNotIn("authentication", result)
        self.assertNotIn("allow_authorization", self.oauth_factory.call_args.kwargs)

    def test_web_launch_never_reads_token_marker_or_secret(self):
        with patch.object(cli, "browser_executable", return_value=self.native):
            result = cli.launch(config(), self.config_path, "web", False, [],
                                checker=Mock(return_value=report()), web_guard=Mock())
        self.assertTrue(result["launched"])
        self.load.assert_not_called()
        self.read.assert_not_called()

    def test_account_changing_commands_block_before_route_and_keychain(self):
        commands = (["setup-token"], ["auth", "login"], ["auth", "logout"],
                    ["--bare"], ["--bare=true"], ["auth", "login", "--print", "hello"])
        for arguments in commands:
            with self.subTest(arguments=arguments):
                checker = Mock(return_value=report())
                with self.assertRaises(core.Blocked):
                    self.launch(arguments, checker=checker)
                checker.assert_not_called()
        self.read.assert_not_called()
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()

    def test_account_command_word_as_print_prompt_is_not_a_command(self):
        result = self.launch(["-p", "setup-token"])
        self.assertTrue(result["launched"])
        self.read.assert_called_once()

    def test_local_auth_status_remains_available(self):
        result = self.launch(["auth", "status", "--json"])
        self.assertTrue(result["launched"])
        self.assertIn("auth", self.guarded.call_args.args[0])

    def test_existing_disabled_storage_path_blocks_native_launch(self):
        storage = self.root / "workspaces/A/data/Claude/.token-auth-disabled"
        storage.mkdir(parents=True)
        with self.assertRaises(core.Blocked):
            self.launch()
        self.oauth_factory.assert_not_called()
        self.guarded.assert_not_called()

    def test_inline_auth_override_rejected_before_keychain(self):
        settings = [{"env": {name: OUTSIDE}} for name in (
            "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_SECURESTORAGE_CONFIG_DIR",
            "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "claude_code_oauth_token")]
        settings += [{name: OUTSIDE} for name in ("apiKeyHelper", "forceLoginMethod", "forceLoginOrgUUID")]
        for setting in settings:
            with self.subTest(keys=list(setting)):
                checker = Mock(return_value=report())
                with self.assertRaises(core.Blocked):
                    self.launch(["--settings=" + json.dumps(setting)], checker=checker)
                checker.assert_not_called()
        self.read.assert_not_called()
        self.guarded.assert_not_called()

    def test_isolated_cli_propagates_token_mode_to_environment_policy_and_report(self):
        base = self.root / "isolated"
        project_root = base / "projects/example"
        home = base / ".runtime/example/home"
        project_root.mkdir(parents=True, mode=0o700)
        home.mkdir(parents=True, mode=0o700)
        home.chmod(0o700)
        project = isolation.Project("example", project_root, home)
        self.session.browser_hook = Path("/private/tmp/surge-cc-oauth-keychain-cli-test/browser")
        with patch.object(cli.isolation, "for_cwd", return_value=project), \
                patch.object(cli.isolation, "bind_workspace", return_value=project) as bind, \
                patch.object(cli.Path, "cwd", return_value=project_root), \
                patch.object(isolated_auth, "prepare") as shared_prepare, \
                patch.object(guard, "RuntimeChecker") as runtime, \
                patch.object(isolation, "SANDBOX", self.native):
            result = self.launch(["--help"])
        bind.assert_called_once_with(project, self.config_path, "A")
        shared_prepare.assert_not_called()
        self.settings.assert_not_called()
        invocation = self.guarded.call_args
        args = invocation.args[0]
        self.assertEqual(args[0], str(self.native))
        self.assertEqual(args[1], "-p")
        self.assertIn('(deny file-read* file-write*', args[2])
        self.assertIn(str(home / ".token-auth-disabled"), args[2])
        self.assertIn(str(project.config / ".credentials.json"), args[2])
        self.assertEqual(invocation.kwargs["env"]["CLAUDE_CODE_OAUTH_TOKEN"], TOKEN)
        self.assertEqual(invocation.kwargs["env"]["CLAUDE_SECURESTORAGE_CONFIG_DIR"],
                         str(home / ".token-auth-disabled"))
        self.assertEqual(invocation.kwargs["cwd"], project_root)
        runtime.assert_not_called()
        self.assertEqual(self.strict_factory.call_count, 2)
        self.strict_factory.assert_called_with(config(), process=str(self.native))
        self.assertIs(invocation.kwargs["checker"], self.strict_factory.return_value)
        self.assertEqual(invocation.kwargs["env"]["HTTPS_PROXY"], self.development.proxy_url)
        self.assertTrue(result["ok"])
        self.assertFalse(result["file_isolation"]["shared_login_storage"])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(TOKEN, repr(args))

    def title_project(self):
        base = self.root / "isolated"
        project_root = base / "projects/example"
        home = base / ".runtime/example/home"
        project_root.mkdir(parents=True, mode=0o700)
        home.mkdir(parents=True, mode=0o700)
        home.chmod(0o700)
        project = isolation.Project("example", project_root, home)
        self.session.browser_hook = Path("/private/tmp/surge-cc-oauth-keychain-title-test/browser")
        self.stack.enter_context(patch.object(cli.isolation, "for_cwd", return_value=project))
        self.stack.enter_context(patch.object(cli.isolation, "bind_workspace", return_value=project))
        self.stack.enter_context(patch.object(cli.Path, "cwd", return_value=project_root))
        self.stack.enter_context(patch.object(isolation, "SANDBOX", self.native))
        self.stack.enter_context(patch.dict(os.environ, {
            "ORCA_PANE_KEY": "synthetic-pane", "ORCA_TAB_ID": "synthetic-tab",
            "ORCA_WORKTREE_ID": "synthetic-worktree", "ORCA_AGENT_HOOK_TOKEN": OUTSIDE,
            "ORCA_AGENT_HOOK_PORT": "54321", "ORCA_AGENT_LAUNCH_TOKEN": OUTSIDE,
        }))
        return project

    def test_verified_orca_title_bridge_preserves_child_isolation_and_runtime_guard(self):
        project = self.title_project()
        temp = tempfile.TemporaryDirectory(prefix="surge-cc-title-launch-test-", dir="/private/tmp")
        self.addCleanup(temp.cleanup)
        hook = Path(temp.name) / "hook"
        hook.write_text("#!/bin/sh\nprintf '{}\\n'\n")
        hook.chmod(0o500)
        child = Mock(name="single-native-child")
        binding = object()

        def started_and_completed(*args, **kwargs):
            kwargs["on_started"](child)
            return completed(*args, **kwargs)

        self.guarded.side_effect = started_and_completed
        with patch.object(orca_titles, "bind", return_value=binding) as bind, \
                patch.object(orca_titles, "Session") as title_factory, \
                patch.object(isolation, "command", wraps=isolation.command) as command, \
                patch.object(guard, "RuntimeChecker") as runtime:
            title_session = title_factory.return_value.__enter__.return_value
            title_session.hook = hook
            result = self.launch(["--help"])

        bind.assert_called_once_with(project)
        title_factory.assert_called_once_with(binding, project)
        title_session.set_child.assert_called_once_with(child)
        self.session.set_child.assert_called_once_with(child)
        title_factory.return_value.__exit__.assert_called_once()
        self.assertEqual(command.call_args.kwargs["title_hook"], hook)
        invocation = self.guarded.call_args
        args, env = invocation.args[0], invocation.kwargs["env"]
        self.assertFalse(any(key.startswith("ORCA_") for key in env))
        self.assertNotIn(OUTSIDE, env.values())
        self.assertEqual(env["CLAUDE_CODE_OAUTH_TOKEN"], TOKEN)
        self.assertEqual(args[:2], [str(self.native), "-p"])
        self.assertIn('(deny default)', args[2])
        self.assertIn('(allow network-outbound (literal ' + json.dumps(str(hook.parent / "s")) + '))', args[2])
        self.assertNotIn('localhost:54321', args[2])
        settings = json.loads(args[args.index("--settings") + 1])
        self.assertFalse(settings["disableAllHooks"])
        self.assertEqual(set(settings["hooks"]), {"SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"})
        self.assertEqual(args[args.index("--setting-sources") + 1], "user,project,local")
        self.assertIn("--strict-mcp-config", args)
        self.assertIn("--no-chrome", args)
        runtime.assert_not_called()
        self.assertEqual(self.strict_factory.call_count, 2)
        self.strict_factory.assert_called_with(config(), process=str(self.native))
        self.assertIs(invocation.kwargs["checker"], self.strict_factory.return_value)
        self.development.set_child.assert_called_once_with(child)
        self.assertTrue(result["ok"])
        for exposed in (repr(args), json.dumps(result), self.output.getvalue(), self.errors.getvalue()):
            self.assertNotIn(TOKEN, exposed)
            self.assertNotIn(OUTSIDE, exposed)

    def test_unverified_orca_title_bridge_warns_without_host_hook_or_network_fallback(self):
        self.title_project()
        child = Mock(name="still-isolated-native-child")

        def started_and_completed(*args, **kwargs):
            kwargs["on_started"](child)
            return completed(*args, **kwargs)

        self.guarded.side_effect = started_and_completed
        with patch.object(orca_titles, "bind", side_effect=core.Blocked(OUTSIDE)), \
                patch.object(orca_titles, "Session") as title_factory, \
                patch.object(isolation, "command", wraps=isolation.command) as command, \
                patch.object(guard, "RuntimeChecker") as runtime:
            result = self.launch(["--help"])

        title_factory.assert_not_called()
        self.assertNotIn("title_hook", command.call_args.kwargs)
        self.session.set_child.assert_called_once_with(child)
        invocation = self.guarded.call_args
        args, env = invocation.args[0], invocation.kwargs["env"]
        self.assertEqual(args[:2], [str(self.native), "-p"])
        self.assertIn('(deny default)', args[2])
        self.assertNotIn("surge-cc-title-", args[2])
        self.assertNotIn('localhost:54321', args[2])
        self.assertFalse(any(key.startswith("ORCA_") for key in env))
        self.assertNotIn(OUTSIDE, env.values())
        settings = json.loads(args[args.index("--settings") + 1])
        self.assertFalse(settings["disableAllHooks"])
        self.assertNotIn("hooks", settings)
        self.assertEqual(args[args.index("--setting-sources") + 1], "user,project,local")
        runtime.assert_not_called()
        self.assertEqual(self.strict_factory.call_count, 2)
        self.strict_factory.assert_called_with(config(), process=str(self.native))
        self.assertIs(invocation.kwargs["checker"], self.strict_factory.return_value)
        self.assertTrue(result["ok"])
        self.assertIn("Orca 标题通知未连接", self.errors.getvalue())
        self.assertNotIn(OUTSIDE, self.errors.getvalue())
        self.assertNotIn(TOKEN, self.errors.getvalue())


class TokenOAuthBrokerTests(unittest.TestCase):
    def test_disabled_authorization_never_checks_route_callback_or_opens_browser(self):
        checker, popen = Mock(), Mock()
        session = oauth.OAuthSession(config(), Path("/private/tmp/synthetic-config.json"),
                                     checker=checker, popen=popen, allow_authorization=False)
        with patch.object(oauth, "callback_owned_by") as callback, \
                patch.object(oauth, "validate_authorization_url") as validator:
            for value in ("https://claude.ai/oauth/authorize?synthetic=1", "invalid URL"):
                with self.subTest(value=value), self.assertRaises(core.Blocked):
                    session._open_authorization(value)
            validator.assert_not_called()
            callback.assert_not_called()
        checker.assert_not_called()
        popen.assert_not_called()


class TokenIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-token-isolation-",
                                                 dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve() / "isolated"
        root = self.base / "projects/example"
        home = self.base / ".runtime/example/home"
        root.mkdir(parents=True, mode=0o700)
        (home / ".claude").mkdir(parents=True, mode=0o700)
        home.chmod(0o700)
        self.project = isolation.Project("example", root, home)
        self.local = self.project.config / ".credentials.json"
        self.local.write_text("synthetic-local-credential")
        self.shared = self.base / ".runtime/auth/store/.credentials.json"
        self.shared.parent.mkdir(parents=True, mode=0o700)
        self.shared.write_text("synthetic-shared-credential")
        self.disabled = home / ".token-auth-disabled"
        self.disabled.mkdir()
        (self.disabled / ".credentials.json").write_text("synthetic-disabled-store-credential")
        self.native = self.base.parent / "native-unused"
        self.native.write_text("not executed")
        self.hook = Path("/private/tmp/surge-cc-oauth-token-isolation-test/browser")

    def test_token_environment_filters_inherited_values_without_preparing_shared_auth(self):
        with patch.object(isolated_auth, "prepare") as prepare:
            env = isolation.environment(self.project, "http://127.0.0.1:62919",
                {"CLAUDE_CODE_OAUTH_TOKEN": OUTSIDE, "ANTHROPIC_API_KEY": OUTSIDE,
                 "CLAUDE_SECURESTORAGE_CONFIG_DIR": OUTSIDE, "TERM": "xterm-256color"}, token_auth=True)
            prepare.assert_not_called()
        self.assertNotIn(OUTSIDE, env.values())
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", env)
        self.assertEqual(env["CLAUDE_SECURESTORAGE_CONFIG_DIR"], str(self.disabled))
        self.assertEqual(env["HOME"], str(self.project.home))
        self.assertEqual(env["TERM"], "xterm-256color")

    def test_token_policy_denies_credentials_and_keeps_network_scope(self):
        with patch.object(isolated_auth, "prepare", return_value=None) as prepare:
            policy = isolation.profile(self.project, self.native, self.hook, token_auth=True)
            prepare.assert_not_called()
            previous = isolation.profile(self.project, self.native, self.hook)
        for path in (self.disabled, self.disabled.with_name(self.disabled.name + ".lock"),
                     self.local, self.base / ".runtime/auth"):
            self.assertIn('(subpath ' + json.dumps(str(path)) + ')', policy)
        self.assertNotIn('(allow file-read* file-write* (subpath ' + json.dumps(str(self.shared.parent)), policy)
        network = lambda value: [line for line in value.splitlines() if "(allow network" in line]
        self.assertEqual(network(policy), network(previous))

    @unittest.skipUnless(sys.platform == "darwin", "macOS Seatbelt required")
    def test_kernel_allows_session_files_but_denies_local_shared_and_disabled_credentials(self):
        policy = isolation.profile(self.project, self.native, self.hook, token_auth=True)
        env = isolation.environment(self.project, "http://127.0.0.1:62919", {}, token_auth=True)
        denied = [str(self.local), str(self.shared), str(self.disabled / ".credentials.json")]
        code = 'DENIED=' + repr(denied) + '\n' + '''import os,pathlib
home=pathlib.Path(os.environ['HOME'])
session=home/'.claude'/'synthetic-session.jsonl'
session.write_text('synthetic-session-data')
assert session.read_text()=='synthetic-session-data'
for value in DENIED:
 path=pathlib.Path(value)
 for operation in ('read','write'):
  try:
   path.read_bytes() if operation=='read' else path.write_text('must-not-write')
  except PermissionError: pass
  else: raise AssertionError(operation+' credential access unexpectedly allowed')
print('token-only-storage: passed')
'''
        result = subprocess.run([str(isolation.SANDBOX), '-p', policy, sys.executable, '-c', code],
                                env=env, cwd=self.project.root, capture_output=True, text=True, timeout=20)
        if 'sandbox_apply: Operation not permitted' in result.stderr:
            self.skipTest('host must run outside an enclosing sandbox')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('token-only-storage: passed', result.stdout)
        self.assertEqual(self.local.read_text(), "synthetic-local-credential")
        self.assertEqual(self.shared.read_text(), "synthetic-shared-credential")


if __name__ == '__main__':
    unittest.main()
