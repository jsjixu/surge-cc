"""Project-local plugin support without real credentials or model requests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import development
from surge_cc.core import Blocked


class CommandTests(unittest.TestCase):
    def test_only_top_level_binary_maintenance_is_blocked(self):
        for args in (["install"], ["update"], ["upgrade", "--print"],
                     ["--model", "opus", "install"], ["--verbose", "update"],
                     ["--model=opus", "upgrade"], ["--effort", "high", "update"],
                     ["--debug", "update"], ["--debug", "upgrade"],
                     ["--debug", "install", "--print"], ["--debug", "--model", "opus", "update"],
                     ["--debug", "api,hooks", "update"]):
            with self.subTest(args=args):
                self.assertTrue(development.maintenance_command(args))

    def test_plugin_management_and_option_values_are_not_binary_maintenance(self):
        for args in (["plugin", "install", "fixture@local"], ["plugins", "update", "fixture"],
                     ["--model", "opus", "plugin", "install", "fixture"],
                     ["--verbose", "plugin", "marketplace", "update"],
                     ["--print", "install"], ["-p", "update"],
                     ["--model", "install", "--help"], ["--name", "update", "plugin", "list"],
                     ["--settings", '{"model":"update"}', "plugin", "list"],
                     ["--", "install"], ["--print=install"], [], ["--version"],
                     ["--debug", "plugin", "install", "fixture"],
                     ["--debug", "api,hooks", "plugin", "install", "fixture"],
                     ["--debug", "--print", "update"], ["--debug", "explain this code"]):
            with self.subTest(args=args):
                self.assertFalse(development.maintenance_command(args))


class ProjectFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="surge-development-", dir="/private/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "isolated-home"
        self.project_root = self.root / "project"
        self.home.mkdir()
        self.project_root.mkdir()
        self.config = self.home / ".claude"
        self.config.mkdir()
        (self.project_root / ".claude").mkdir()
        self.project = SimpleNamespace(home=self.home, root=self.project_root, config=self.config)

    def settings(self, value, *, project=False):
        path = (self.project_root / ".claude" if project else self.config) / "settings.json"
        path.write_text(json.dumps(value))
        return path


class SettingsTests(ProjectFixture):
    def test_only_scoped_user_project_files_and_regular_development_variables(self):
        self.settings({"env": {"NODE_ENV": "development"}, "enabledPlugins": {"fixture@local": True}})
        self.settings({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo local"}]}]}}, project=True)
        # A malicious host/ancestor settings file must never be inspected.
        (self.root / ".claude").mkdir()
        (self.root / ".claude/settings.json").write_text('{"env":{"ANTHROPIC_API_KEY":"host-secret"}}')
        paths = development.validate_settings(self.project)
        self.assertEqual(len(paths), 4)
        self.assertNotIn(self.root / ".claude/settings.json", paths)

    def test_rejects_protected_overrides_without_printing_values(self):
        for key in ("ANTHROPIC_API_KEY", "claude_code_oauth_token", "HOME", "BROWSER",
                    "HTTPS_PROXY", "no_proxy", "CLAUDE_CONFIG_DIR", "DYLD_INSERT_LIBRARIES",
                    "CLAUDE_SECURESTORAGE_CONFIG_DIR", "ORCA_HOOK_TOKEN", "NPM_CONFIG_PROXY"):
            self.settings({"env": {key: "sensitive-value"}})
            with self.subTest(key=key), self.assertRaises(Blocked) as caught:
                development.validate_settings(self.project)
            self.assertNotIn("sensitive-value", str(caught.exception))

    def test_rejects_auth_remote_and_malformed_settings(self):
        for value in ({"apiKeyHelper": "cat host"}, {"forceLoginMethod": "console"},
                      {"forceLoginOrgUUID": "other"}, {"remoteControlAtStartup": True},
                      {"autoUploadSessions": True}, {"env": []}, {"env": {"NORMAL": 1}}, []):
            self.settings(value)
            with self.subTest(value=value), self.assertRaises(Blocked):
                development.validate_settings(self.project)

    def test_refuses_settings_symlink_into_other_project(self):
        outside = self.root / "other-account.json"
        outside.write_text('{"theme":"dark"}')
        (self.config / "settings.json").symlink_to(outside)
        with self.assertRaises(Blocked):
            development.validate_settings(self.project)

    def test_fixed_settings_preserve_title_bridge_without_serializing_auth_token(self):
        titles = {"SessionStart": [{"hooks": [{"type": "command", "command": "/private/tmp/title/hook"}]}]}
        fixed = {"hooks": titles, "model": "opus", "effortLevel": "high", "disableAllHooks": True}
        env = {"HTTPS_PROXY": "http://127.0.0.1:49123", "BROWSER": "/private/tmp/oauth/hook",
               "CLAUDE_CODE_OAUTH_TOKEN": "never-write-this", "TERM": "xterm"}
        result = development.runtime_settings(self.project, fixed, env)
        self.assertFalse(result["disableAllHooks"])
        self.assertEqual(result["hooks"], titles)
        self.assertEqual(result["model"], "opus")
        self.assertEqual(result["env"]["HTTPS_PROXY"], env["HTTPS_PROXY"])
        self.assertEqual(result["env"]["HOME"], str(self.home))
        self.assertNotIn("never-write-this", json.dumps(result))
        self.assertTrue(result["disableRemoteControl"])
        self.assertFalse(result["autoUploadSessions"])
        self.assertTrue(fixed["disableAllHooks"], "caller's defaults should not be mutated")


class ShimTests(ProjectFixture):
    def run_shim(self, helper, args, **kwargs):
        if sys.platform != "darwin":
            self.skipTest("native macOS sandbox helper")
        # Keep these synthetic native commands inside an actual sandbox even
        # when the test runner itself is unsandboxed on macOS CI.
        return subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", str(helper), *args], **kwargs)

    def native(self):
        native = self.root / "native-claude"
        native.write_text("#!" + str(Path(sys.executable).resolve()) + "\nimport json,os,sys\n"
                          "print(json.dumps({'argv':sys.argv[1:],'home':os.environ['HOME'],'config':os.environ['CLAUDE_CONFIG_DIR'],"
                          "'proxy':os.environ.get('HTTPS_PROXY'),'updater':os.environ.get('DISABLE_AUTOUPDATER')}))\n")
        native.chmod(0o700)
        return native

    def test_child_plugin_commands_preserve_dynamic_proxy_and_isolated_home(self):
        helper = development.prepare(self.project, self.native())
        for args in (["plugin", "marketplace", "add", "/tmp/local-market"],
                     ["plugin", "install", "fixture@local"], ["plugins", "list", "--json"],
                     ["--help"], ["--version"]):
            result = self.run_shim(helper, args, capture_output=True, text=True,
                                    env={"HOME": "/wrong", "CLAUDE_CONFIG_DIR": "/wrong",
                                         "HTTPS_PROXY": "http://127.0.0.1:49123"}, timeout=5)
            with self.subTest(args=args):
                self.assertEqual(result.returncode, 0, result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual(value["home"], str(self.home))
                self.assertEqual(value["config"], str(self.config))
                self.assertEqual(value["proxy"], "http://127.0.0.1:49123")
                self.assertEqual(value["updater"], "1")
                self.assertEqual(value["argv"][-len(args):], args)
                self.assertIn("--strict-mcp-config", value["argv"])
                self.assertIn("--no-chrome", value["argv"])
                self.assertEqual(value["argv"][:2], ["--setting-sources", "user,project,local"])

    def test_child_refuses_interactive_sessions_auth_binary_updates_and_overrides(self):
        helper = development.prepare(self.project, self.native())
        for args in ([], ["-p", "hello"], ["auth", "login"], ["update"], ["install"],
                     ["plugin", "eval", "fixture"], ["plugin", "test", "fixture"],
                     ["plugin", "list", "--settings", "{}"], ["plugin", "list", "--chrome"],
                     ["plugin", "list", "--mcp-config={}"], ["remote-control"]):
            result = subprocess.run([str(helper), *args], capture_output=True, text=True, timeout=5)
            with self.subTest(args=args):
                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout, "")

    def test_no_auth_tokens_or_host_dependencies_are_embedded(self):
        helper = development.prepare(self.project, self.native())
        content = helper.read_text()
        self.assertNotIn("security find", content)
        self.assertNotIn("terminal-manifest", content)
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", content)
        self.assertEqual(helper.stat().st_mode & 0o777, 0o700)

    def test_helper_refuses_execution_outside_a_sandbox(self):
        if sys.platform != "darwin":
            self.skipTest("native macOS sandbox helper")
        import ctypes
        check = ctypes.CDLL("/usr/lib/libsandbox.dylib").sandbox_check
        check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        check.restype = ctypes.c_int
        if check(os.getpid(), None, 0) != 0:
            self.skipTest("runner already sandboxed; run this test outside the outer sandbox")
        helper = development.prepare(self.project, self.native())
        result = subprocess.run([str(helper), "plugin", "list"], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stdout, "")

    def test_native_and_local_bin_symlinks_are_rejected(self):
        native = self.native()
        link = self.root / "link"
        link.symlink_to(native)
        with self.assertRaises(Blocked):
            development.prepare(self.project, link)
        (self.home / ".local").symlink_to(self.root)
        with self.assertRaises(Blocked):
            development.prepare(self.project, native)


if __name__ == "__main__":
    unittest.main()
