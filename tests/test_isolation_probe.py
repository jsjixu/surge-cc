"""The shipped diagnostic must match development grants, using synthetic files."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import isolation, isolation_probe


class GitBoundaryProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-probe-tests-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.main = self.base / "isolated/projects/sample"
        self.root = self.base / "orca/sample/worker"
        self.home = self.base / "isolated/.runtime/sample/home"
        self.common = self.main / ".git"
        self.admin = self.common / "worktrees/worker"
        for folder in (self.root, self.home, self.admin, self.common / "objects",
                       self.common / "refs", self.common / "hooks"):
            folder.mkdir(parents=True, mode=0o700)
        self.protected = {
            self.common / "config": b"[core]\nrepositoryformatversion = 0\n",
            self.admin / "commondir": b"../..\n",
            self.admin / "gitdir": (str(self.root / ".git") + "\n").encode(),
        }
        for path, value in self.protected.items():
            path.write_bytes(value)
        self.project = isolation.Project("sample", self.root, self.home,
                                         isolation.LinkedWorktree(self.main, self.admin))
        self.native = Path("/usr/bin/true")
        self.hook = Path("/private/tmp/surge-cc-oauth-probe-test/browser")

    def assert_unchanged_and_clean(self):
        for path, value in self.protected.items():
            self.assertEqual(path.read_bytes(), value)
        self.assertEqual(list(self.root.iterdir()), [])
        for directory in ("objects", "refs", "hooks"):
            self.assertEqual(list((self.common / directory).iterdir()), [])

    def test_unrestricted_policy_fails_protected_checks_and_cleans_canaries(self):
        results = {}
        isolation_probe.git_boundary_checks(self.root, self.common, self.admin, results.__setitem__)
        self.assertTrue(results["shared_git_objects_write_allowed"])
        self.assertTrue(results["shared_git_refs_write_allowed"])
        for key, value in results.items():
            if key.endswith("_denied"):
                self.assertFalse(value, key)
        self.assert_unchanged_and_clean()

    def run_sandbox(self, extra=""):
        source = Path(isolation_probe.__file__).resolve()
        policy = isolation.profile(self.project, self.native, self.hook, probe=source, token_auth=True) + extra
        code = (
            "import json,runpy,sys;from pathlib import Path;"
            "namespace=runpy.run_path(sys.argv[1]);results={};"
            "namespace['git_boundary_checks'](*map(Path,sys.argv[2:5]),results.__setitem__);"
            "print(json.dumps(results))"
        )
        env = isolation.environment(self.project, "http://127.0.0.1:62919", {}, token_auth=True)
        result = subprocess.run([str(isolation.SANDBOX), "-p", policy, str(Path(sys.executable).resolve()),
                                 "-c", code, str(source), str(self.root), str(self.common), str(self.admin)],
                                env=env, cwd=self.root, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_unchanged_and_clean()
        return json.loads(result.stdout)

    @unittest.skipUnless(isolation.SANDBOX.is_file(), "macOS Seatbelt unavailable")
    def test_real_development_policy_passes_every_git_probe(self):
        results = self.run_sandbox()
        self.assertEqual(len(results), 7)
        self.assertTrue(all(results.values()), results)

    @unittest.skipUnless(isolation.SANDBOX.is_file(), "macOS Seatbelt unavailable")
    def test_old_readonly_grants_are_reported_as_missing_development_access(self):
        extra = "\n(deny file-write* " + " ".join(
            "(subpath " + json.dumps(str(self.common / part)) + ")" for part in ("objects", "refs")) + ")\n"
        results = self.run_sandbox(extra)
        self.assertFalse(results["shared_git_objects_write_allowed"])
        self.assertFalse(results["shared_git_refs_write_allowed"])
        self.assertTrue(all(value for key, value in results.items() if key.endswith("_denied")), results)


if __name__ == "__main__":
    unittest.main()
