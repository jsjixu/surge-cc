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
            "PATH", "BROWSER", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "CLAUDE_CODE_EFFORT_LEVEL")}
        inherited.update(TERM="xterm-256color", COLORTERM="truecolor", NO_COLOR="1")
        before = dict(inherited)
        env = isolation.environment(self.project, "http://127.0.0.1:62919", inherited)
        self.assertEqual(inherited, before)
        self.assertNotIn("SYNTHETIC-DO-NOT-INHERIT", env.values())
        for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "AWS_SECRET_ACCESS_KEY",
                    "GOOGLE_APPLICATION_CREDENTIALS", "GH_TOKEN", "SSH_AUTH_SOCK", "NODE_OPTIONS", "PYTHONPATH",
                    "DYLD_INSERT_LIBRARIES", "ORCA_SOCKET", "GIT_CONFIG_COUNT", "BROWSER",
                    "ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL",
                    "CLAUDE_CODE_EFFORT_LEVEL"):
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

    def test_model_defaults_do_not_enable_native_settings_or_integrations(self):
        result = isolation.arguments([], default_model="claude-opus-5-5", default_effort="high")
        self.assertEqual(result[:2], ["--setting-sources", ""])
        settings = json.loads(result[result.index("--settings") + 1])
        self.assertEqual(settings, {
            "disableAllHooks": True, "remoteControlAtStartup": False,
            "forceLoginMethod": "claudeai", "model": "claude-opus-5-5",
            "effortLevel": "high"})
        # Defaults are settings, not competing CLI flags or environment
        # overrides that could prevent the user's explicit session choice.
        self.assertNotIn("--model", result)
        self.assertNotIn("--effort", result)
        self.assertIn("--strict-mcp-config", result)
        self.assertIn("--no-chrome", result)

    def test_explicit_model_and_effort_override_flags_survive_without_competitors(self):
        for values in (["--model", "sonnet", "--effort", "medium"],
                       ["--model=claude-sonnet-5-5", "--effort=low"],
                       ["--continue", "--model", "opus", "--effort", "max"]):
            with self.subTest(values=values):
                result = isolation.arguments(values, default_model="claude-opus-5-5", default_effort="high")
                self.assertEqual(result[-len(values):], values)
                overrides = [value for value in result
                             if value.split("=", 1)[0] in ("--model", "--effort")]
                self.assertEqual(overrides, [value for value in values
                                            if value.split("=", 1)[0] in ("--model", "--effort")])
                settings = json.loads(result[result.index("--settings") + 1])
                self.assertEqual(settings["model"], "claude-opus-5-5")
                self.assertEqual(settings["effortLevel"], "high")


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

    @unittest.skipUnless(sys.platform == "darwin", "macOS PTY policy")
    def test_paste_terminal_grants_only_allocated_child_device(self):
        master, slave = os.openpty()
        try:
            device = Path(os.ttyname(slave))
            with patch.object(isolation.os, "ttyname", return_value="/dev/ttys999") as parent:
                policy = isolation.profile(self.project, self.native, self.hook, terminal_device=device)
            parent.assert_not_called()
            self.assertIn('(literal ' + json.dumps(str(device)) + ')', policy)
            self.assertNotIn('/dev/ttys999', policy)
            self.assertNotIn('(subpath "/dev")', policy)
            self.assertIn('(allow network-outbound (remote tcp "localhost:62919"))', policy)
        finally:
            os.close(master)
            os.close(slave)

    def test_paste_terminal_rejects_arbitrary_file_or_missing_device(self):
        for device in (self.native, Path('/dev/ttysnot-real')):
            with self.subTest(device=device), self.assertRaises(core.Blocked):
                isolation.profile(self.project, self.native, self.hook, terminal_device=device)

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


class SharedHistoryIsolationTests(IsolationFixture):
    """Exercise real opt-in/binding across the isolation launch boundary."""

    def setUp(self):
        super().setUp()
        from surge_cc import keychain_auth, shared_history
        self.shared = shared_history
        self.keychain = keychain_auth
        self.write_registry()
        self.home.parent.chmod(0o700)
        self.select_account("A")
        keychain_auth.migrate_legacy(self.config_path, "A")
        self.bound = isolation.bind_workspace(self.project, self.config_path, "A")
        self.native = self.temp_root / "native-claude"
        self.native.write_text("never executed")
        self.sandbox = self.temp_root / "sandbox-exec"
        self.sandbox.write_text("never executed")
        self.hook = Path("/private/tmp/surge-cc-oauth-shared-history/browser")
        self.stack.enter_context(patch.object(isolation, "SANDBOX", self.sandbox))

    def select_account(self, name):
        self.config_path.write_text(json.dumps({"workspace": name}))
        self.config_path.chmod(0o600)

    def enable(self):
        self.shared.initialize(self.bound)
        marker = self.base / ".runtime" / self.shared.MARKER
        marker.write_text(json.dumps({"schema": 1, "projects": [
            {"id": "vv", "path": str(self.project_root)}]}))
        marker.chmod(0o600)
        return self.shared.history(self.bound)

    def command(self, project=None, values=None):
        return isolation.command(project or self.bound, self.native,
                                 ["--resume"] if values is None else values,
                                 self.hook, token_auth=True)

    def linked(self, name):
        """Create the exact local Git pointer metadata checked by admission."""
        orca = self.temp_root / "orca" / "workspaces"
        root = orca / "vv" / name
        root.mkdir(parents=True)
        self.stack.enter_context(patch.object(isolation, "ORCA_WORKSPACES", orca))
        admin = self.project_root / ".git" / "worktrees" / name
        admin.mkdir(parents=True)
        (root / ".git").write_text("gitdir: " + str(admin) + "\n")
        (admin / "commondir").write_text("../..\n")
        (admin / "gitdir").write_text(str(root / ".git") + "\n")
        (root / isolation.MARKER_NAME).write_text(json.dumps({
            "schema": 1, "project": "vv", "requires_registered_launcher": True}))
        discovered = isolation.for_cwd(self.config_path, root)
        return isolation.bind_workspace(discovered, self.config_path, "A")

    def test_opt_out_keeps_private_state_and_ignores_inherited_bucket_override(self):
        env = isolation.environment(self.bound, "http://127.0.0.1:62919",
                                    {"CLAUDE_CODE_PROJECT_DIR_NAME": "foreign"}, token_auth=True)
        self.assertNotIn("CLAUDE_CODE_PROJECT_DIR_NAME", env)
        self.assertEqual(env["HOME"], str(self.bound.home))
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(self.bound.config))
        command = self.command()
        settings = json.loads(command[command.index("--settings") + 1])
        self.assertNotIn("autoMemoryDirectory", settings)
        self.assertNotIn("conversation-history", command[2])
        self.assertEqual(command[-1], "--resume")
        self.assertFalse((self.bound.config / "projects" / self.shared.bucket(self.bound)).exists())

    def test_enabled_bucket_does_not_replace_home_auth_or_proxy(self):
        self.enable()
        env = isolation.environment(self.bound, "http://127.0.0.1:62919",
                                    {"CLAUDE_CODE_PROJECT_DIR_NAME": "foreign"}, token_auth=True)
        self.assertEqual(env["CLAUDE_CODE_PROJECT_DIR_NAME"], self.shared.bucket(self.bound))
        self.assertEqual(env["HOME"], str(self.bound.home))
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(self.bound.config))
        self.assertEqual(env["CLAUDE_CODE_TMPDIR"], str(self.bound.home / "tmp"))
        self.assertEqual(env["CLAUDE_SECURESTORAGE_CONFIG_DIR"],
                         str(self.bound.home / ".token-auth-disabled"))
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:62919")
        self.assertEqual(env["NO_PROXY"], "")

    def test_command_links_conversations_but_keeps_existing_memory_private(self):
        history = self.enable()
        self.bound.config.mkdir(mode=0o700)
        memory = isolation.private_memory(self.bound)
        memory.mkdir(parents=True, mode=0o700)
        existing = memory / "MEMORY.md"
        existing.write_text("synthetic private project note\n")
        command = self.command(values=["--resume", "synthetic-session", "--fork-session"])
        settings = json.loads(command[command.index("--settings") + 1])
        self.assertEqual(settings["autoMemoryDirectory"], str(memory))
        self.assertTrue(settings["disableAllHooks"])
        self.assertFalse(settings["remoteControlAtStartup"])
        self.assertEqual(existing.read_text(), "synthetic private project note\n")
        link = self.bound.config / "projects" / self.shared.bucket(self.bound)
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), history)
        self.assertFalse(isolation.within(memory, history))
        self.assertEqual(command[-3:], ["--resume", "synthetic-session", "--fork-session"])

    def test_policy_grants_only_selected_history_data_not_management_or_other_scopes(self):
        history = self.enable()
        policy = self.command()[2]
        self.assertIn('(allow file-read* file-write* (subpath ' + json.dumps(str(history)) + '))', policy)
        self.assertIn('(deny file-read* file-write* (subpath ' + json.dumps(str(history / "memory")) + '))', policy)
        other_account = history.parent.parent / "B" / "data"
        other_project = self.base / ".runtime" / "inkclaw" / "conversation-history" / "A" / "data"
        for path in (history.parent, history.parent.parent, self.base / ".runtime",
                     other_account, other_project, Path.home() / ".claude"):
            self.assertNotIn("(subpath " + json.dumps(str(path)) + ")", policy)
        self.assertNotIn('(literal ' + json.dumps(str(history.parent / self.shared.RECEIPT)) + ')', policy)
        self.assertIn('(allow network-outbound (remote tcp "localhost:62919"))', policy)
        self.assertNotIn("(allow network-outbound)", policy)

    def test_same_project_worktrees_share_bucket_but_not_home_memory_or_source_access(self):
        history = self.enable()
        first, second = self.linked("branch-one"), self.linked("branch-two")
        first_command, second_command = self.command(first), self.command(second)
        first_env = isolation.environment(first, "http://127.0.0.1:62919", {}, token_auth=True)
        second_env = isolation.environment(second, "http://127.0.0.1:62919", {}, token_auth=True)
        self.assertEqual(first_env["CLAUDE_CODE_PROJECT_DIR_NAME"], second_env["CLAUDE_CODE_PROJECT_DIR_NAME"])
        self.assertNotEqual(first_env["HOME"], second_env["HOME"])
        self.assertNotEqual(first_env["CLAUDE_CONFIG_DIR"], second_env["CLAUDE_CONFIG_DIR"])
        self.assertNotEqual(isolation.private_memory(first), isolation.private_memory(second))
        for project, other, command in ((first, second, first_command), (second, first, second_command)):
            link = project.config / "projects" / self.shared.bucket(project)
            self.assertEqual(link.resolve(), history)
            settings = json.loads(command[command.index("--settings") + 1])
            self.assertEqual(settings["autoMemoryDirectory"], str(isolation.private_memory(project)))
            self.assertNotIn("(subpath " + json.dumps(str(other.root)) + ")", command[2])
            self.assertNotIn("(subpath " + json.dumps(str(other.home)) + ")", command[2])

    def test_account_switch_uses_a_separate_store_and_does_not_rebind_old_home(self):
        history_a = self.enable()
        self.command()
        home_a = self.bound.home
        self.select_account("B")
        bound_b = isolation.bind_workspace(self.project, self.config_path, "B")
        self.shared.initialize(bound_b)
        history_b = self.shared.history(bound_b)
        command_b = self.command(bound_b)
        env_b = isolation.environment(bound_b, "http://127.0.0.1:62919", {}, token_auth=True)
        self.assertNotEqual(history_a, history_b)
        self.assertNotEqual(home_a, bound_b.home)
        self.assertEqual(env_b["HOME"], str(bound_b.home))
        self.assertEqual((bound_b.config / "projects" / self.shared.bucket(bound_b)).resolve(), history_b)
        self.assertEqual((self.bound.config / "projects" / self.shared.bucket(self.bound)).resolve(), history_a)
        self.assertNotIn("(subpath " + json.dumps(str(history_a)) + ")", command_b[2])
        with self.assertRaises(core.Blocked):
            self.command(self.bound)

    def test_unlisted_registered_project_does_not_inherit_another_projects_history(self):
        history = self.enable()
        root = self.base / "projects" / "inkclaw"
        home = self.base / ".runtime" / "inkclaw" / "home"
        root.mkdir(mode=0o700)
        home.mkdir(parents=True, mode=0o700)
        home.parent.chmod(0o700)
        self.data["projects"].append({"id": "inkclaw", "path": str(root), "home": str(home)})
        self.write_registry()
        other = isolation.bind_workspace(isolation.for_cwd(self.config_path, root), self.config_path, "A")
        env = isolation.environment(other, "http://127.0.0.1:62919", {}, token_auth=True)
        command = self.command(other)
        self.assertNotIn("CLAUDE_CODE_PROJECT_DIR_NAME", env)
        self.assertNotIn("autoMemoryDirectory", json.loads(command[command.index("--settings") + 1]))
        self.assertNotIn("(subpath " + json.dumps(str(history)) + ")", command[2])
        self.assertNotIn("conversation-history", command[2])

    def test_uninitialized_enabled_store_blocks_instead_of_falling_back_to_private_history(self):
        marker = self.base / ".runtime" / self.shared.MARKER
        marker.write_text(json.dumps({"schema": 1, "projects": [
            {"id": "vv", "path": str(self.project_root)}]}))
        marker.chmod(0o600)
        with self.assertRaises(core.Blocked):
            self.command()
        with self.assertRaises(core.Blocked):
            isolation.profile(self.bound, self.native, self.hook, token_auth=True)


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

    def test_interactive_detection_excludes_pipes_print_and_subcommands(self):
        with patch.object(cli.os, 'isatty', return_value=True):
            self.assertTrue(cli.interactive_paste_enabled(['--permission-mode', 'auto']))
            self.assertTrue(cli.interactive_paste_enabled(['--resume', 'session-id']))
            for args in (['-p', 'hello'], ['--print'], ['-phello'], ['--output-format=json'],
                         ['--input-format', 'stream-json'], ['auth', 'login'], ['setup-token'],
                         ['--help'], ['--version']):
                with self.subTest(args=args):
                    self.assertFalse(cli.interactive_paste_enabled(args))
        with patch.object(cli.os, 'isatty', side_effect=[True, False]):
            self.assertFalse(cli.interactive_paste_enabled([]))

    def test_isolated_interactive_bridge_preserves_native_guard_and_oauth_owner(self):
        from surge_cc import paste_terminal, pasted_images
        relay = Mock()
        relay.tty_path = '/dev/ttys123'
        child = Mock()
        command = ['/synthetic/sandbox', 'native']

        def completed(command, **kwargs):
            kwargs['on_started'](child)
            return self.completed(command, **kwargs)

        self.guarded.side_effect = completed
        with patch.object(cli, 'interactive_paste_enabled', return_value=True), \
                patch.object(pasted_images, 'ImageImporter') as importer, \
                patch.object(paste_terminal, 'PasteTerminal') as bridge, \
                patch.object(cli.isolation, 'command', return_value=command) as sandbox:
            bridge.return_value.__enter__.return_value = relay
            report = self.launch(['--permission-mode', 'auto'])
        self.assertTrue(report['ok'])
        importer.assert_called_once_with(self.home)
        bridge.assert_called_once_with(importer.return_value, popen_factory=self.spawn)
        bound = isolation.bind_workspace(self.project, self.config_path, 'A')
        sandbox.assert_called_once_with(bound, self.native, ['--permission-mode', 'auto'],
                                        self.oauth.browser_hook, token_auth=False,
                                    default_model='', default_effort='',
                                        terminal_device=Path('/dev/ttys123'))
        call = self.guarded.call_args
        self.assertEqual(call.args[0], command)
        self.assertIs(call.kwargs['popen'], relay.popen)
        self.assertIs(call.kwargs['monitor'], relay.monitor)
        self.assertIs(call.kwargs['checker'], self.runtime_factory.return_value)
        relay.start.assert_called_once_with(child)
        self.oauth.set_child.assert_called_once_with(child)
        bridge.return_value.__exit__.assert_called_once()

    def test_noninteractive_and_ordinary_launches_do_not_construct_bridge(self):
        from surge_cc import paste_terminal
        with patch.object(paste_terminal, 'PasteTerminal') as bridge:
            self.assertTrue(self.launch(['--help'])['ok'])
            self.cwd_patch.return_value = self.temp_root
            with patch.object(cli, 'interactive_paste_enabled', return_value=True):
                self.assertTrue(self.launch([])['ok'])
        bridge.assert_not_called()

    def test_preflight_failure_never_constructs_bridge(self):
        from surge_cc import paste_terminal
        self.checker.return_value = {'ok': False, 'checks': [], 'summary': 'blocked'}
        with patch.object(cli, 'interactive_paste_enabled', return_value=True), \
                patch.object(paste_terminal, 'PasteTerminal') as bridge:
            self.assertFalse(self.launch([])['ok'])
        bridge.assert_not_called()
        self.guarded.assert_not_called()

    def test_bridge_setup_failure_never_falls_back_to_unfiltered_launch(self):
        from surge_cc import paste_terminal, pasted_images
        with patch.object(cli, 'interactive_paste_enabled', return_value=True), \
                patch.object(pasted_images, 'ImageImporter'), \
                patch.object(paste_terminal, 'PasteTerminal', side_effect=core.Blocked('bridge refused')):
            with self.assertRaises(core.Blocked):
                self.launch([])
        self.guarded.assert_not_called()


if __name__ == "__main__":
    unittest.main()
