"""Shared login boundary tests with synthetic credentials only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, isolated_auth, isolation


class SharedLoginIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve() / "isolated"
        self.projects = []
        for name in ("first", "second"):
            root = self.base / "projects" / name
            home = self.base / ".runtime" / name / "home"
            root.mkdir(parents=True, mode=0o700)
            (home / ".claude").mkdir(parents=True, mode=0o700)
            home.chmod(0o700)
            self.projects.append(isolation.Project(name, root, home))
        self.source, self.target = self.projects
        self.source_credentials = self.source.config / ".credentials.json"
        self.source_credentials.write_text(json.dumps({"claudeAiOauth": {
            "accessToken": "synthetic-access-token", "refreshToken": "synthetic-refresh-token",
            "expiresAt": 1900000000000, "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "pro", "rateLimitTier": "default_claude_pro"}}))
        self.source_credentials.chmod(0o600)
        isolated_auth.migrate(self.source, source_home=self.source.home, confirmed_new_isolated_home=True)
        self.store = self.base / ".runtime/auth/store"
        self.native = self.base.parent / "native-unused"
        self.native.write_text("not executed")
        self.hook = Path("/private/tmp/surge-cc-oauth-shared-login-test/browser")

    def test_same_store_but_distinct_home_session_and_cache_directories(self):
        first = isolation.environment(self.source, "http://127.0.0.1:62919", {})
        second = isolation.environment(self.target, "http://127.0.0.1:62919", {})
        self.assertEqual(first["CLAUDE_SECURESTORAGE_CONFIG_DIR"], str(self.store))
        self.assertEqual(first["CLAUDE_SECURESTORAGE_CONFIG_DIR"], second["CLAUDE_SECURESTORAGE_CONFIG_DIR"])
        for key in ("HOME", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
            self.assertNotEqual(first[key], second[key])

    def test_inherited_account_overrides_cannot_replace_shared_storage(self):
        inherited = {key: "outside-secret" for key in ("CLAUDE_SECURESTORAGE_CONFIG_DIR",
            "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "ANTHROPIC_API_KEY")}
        env = isolation.environment(self.target, "http://127.0.0.1:62919", inherited)
        self.assertNotIn("outside-secret", env.values())
        self.assertEqual(env["CLAUDE_SECURESTORAGE_CONFIG_DIR"], str(self.store))

    def test_policy_adds_store_and_exact_legacy_lock_without_changing_network(self):
        policy = isolation.profile(self.target, self.native, self.hook)
        self.assertIn('(subpath ' + json.dumps(str(self.store)) + ')', policy)
        self.assertIn('(subpath ' + json.dumps(str(self.store) + '.lock') + ')', policy)
        for path in (self.store.parent, self.base / ".runtime", self.source.home):
            self.assertNotIn('(subpath ' + json.dumps(str(path)) + ')', policy)
        with patch.object(isolated_auth, "prepare", return_value=None):
            previous = isolation.profile(self.target, self.native, self.hook)
        network = lambda value: [line for line in value.splitlines() if "(allow network" in line]
        self.assertEqual(network(policy), network(previous))
        self.assertIn('(deny file-link)', policy)

    def test_logout_keeps_shared_path_and_never_selects_local_credentials(self):
        local = self.target.config / '.credentials.json'
        local.write_bytes(self.source_credentials.read_bytes())
        local.chmod(0o600)
        (self.store / '.credentials.json').unlink()
        env = isolation.environment(self.target, "http://127.0.0.1:62919", {})
        self.assertEqual(env["CLAUDE_SECURESTORAGE_CONFIG_DIR"], str(self.store))
        self.assertFalse(isolated_auth.status(self.target)["credential_present"])

    def test_missing_marker_blocks_environment_and_policy(self):
        (self.store.parent / isolated_auth.MARKER).unlink()
        with self.assertRaises(core.Blocked):
            isolation.environment(self.target, "http://127.0.0.1:62919", {})
        with self.assertRaises(core.Blocked):
            isolation.profile(self.target, self.native, self.hook)

    @unittest.skipUnless(sys.platform == "darwin", "macOS Seatbelt required")
    def test_kernel_grants_only_store_locks_and_current_home(self):
        policy = isolation.profile(self.target, self.native, self.hook)
        env = isolation.environment(self.target, "http://127.0.0.1:62919", {})
        code = '''import json,os,pathlib
store=pathlib.Path(os.environ['CLAUDE_SECURESTORAGE_CONFIG_DIR'])
assert json.loads((store/'.credentials.json').read_text())['claudeAiOauth']['accessToken']=='synthetic-access-token'
temp=store/'synthetic.tmp';temp.write_text('synthetic');os.replace(temp,store/'synthetic.done')
for path in (store/'.storage-write.lock',store/'.oauth_refresh.lock',store.with_name('store.lock')):
 path.mkdir();path.rmdir()
denied=[]
for path in DENIED:
 try:
  p=pathlib.Path(path)
  list(p.iterdir()) if p.is_dir() else p.read_bytes()
 except PermissionError: denied.append(path)
assert denied==DENIED, denied
print('shared-storage-only: passed')
'''
        denied = [str(self.store.parent / isolated_auth.MARKER), str(self.store.parent),
                  str(self.source_credentials)]
        code = 'DENIED=' + repr(denied) + '\n' + code
        result = subprocess.run([str(isolation.SANDBOX), '-p', policy, sys.executable, '-c', code],
                                env=env, cwd=self.target.root, capture_output=True, text=True, timeout=20)
        if 'sandbox_apply: Operation not permitted' in result.stderr:
            self.skipTest('host must run outside an enclosing sandbox')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('shared-storage-only: passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
