"""Linked-worktree policy tests using only disposable local Git repositories."""
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, isolation


@unittest.skipUnless(shutil.which("git"), "local Git is unavailable")
class LinkedWorktreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-worktree-tests-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.temp_root = Path(self.temp.name).resolve()
        self.base = self.temp_root / "isolated"
        self.main = self.base / "projects/sample-project"
        self.main_home = self.base / ".runtime/sample-project/home"
        self.main.mkdir(parents=True)
        self.main_home.mkdir(parents=True, mode=0o700)
        self.orca = self.temp_root / "orca/workspaces"
        self.root = self.orca / "sample-project/branch-a"
        self.root.parent.mkdir(parents=True)
        self.config_path = self.temp_root / "launcher/config.json"
        self.config_path.parent.mkdir(mode=0o700)
        self.registry = self.config_path.parent / isolation.REGISTRY_NAME
        self.registry_data = {"schema": 1, "root": str(self.base), "projects": [
            {"id": "sample-project", "path": str(self.main), "home": str(self.main_home)}]}
        self.registry.write_text(json.dumps(self.registry_data))
        self.registry.chmod(0o600)
        self.git("init", str(self.main))
        self.git("-C", str(self.main), "config", "user.name", "Synthetic Test")
        self.git("-C", str(self.main), "config", "user.email", "synthetic@example.invalid")
        self.marker = {"schema": 1, "project": "sample-project", "requires_registered_launcher": True}
        (self.main / isolation.MARKER_NAME).write_text(json.dumps(self.marker))
        (self.main / "tracked.txt").write_text("synthetic original\n")
        self.git("-C", str(self.main), "add", ".")
        self.git("-C", str(self.main), "-c", "core.hooksPath=/dev/null", "commit", "-m", "synthetic fixture")
        self.git("-C", str(self.main), "worktree", "add", "-b", "synthetic-worktree", str(self.root))
        self.admin = Path((self.root / ".git").read_text().strip().removeprefix("gitdir: "))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(isolation, "DEFAULT_ROOT", self.base))
        self.stack.enter_context(patch.object(isolation, "ORCA_WORKSPACES", self.orca))
        self.hook = Path("/private/tmp/surge-cc-oauth-worktree-test/browser")
        self.native = self.temp_root / "synthetic-native"
        self.native.write_text("never executed")
        self.native.chmod(0o700)
        self.fake_sandbox = self.temp_root / "synthetic-sandbox"
        self.fake_sandbox.write_text("never executed")

    def git(self, *args):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.temp_root),
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
        return subprocess.run([shutil.which("git"), *args], check=True, capture_output=True, text=True, env=env).stdout

    def discover(self, root=None):
        return isolation.for_cwd(self.config_path, self.root if root is None else root)

    def command(self, project):
        with patch.object(isolation, "SANDBOX", self.fake_sandbox):
            return isolation.command(project, self.native, ["--help"], self.hook)

    def assert_blocked(self, root=None):
        with self.assertRaises(core.Blocked):
            self.discover(root)

    def test_real_git_worktree_is_recognized_without_subprocess_or_home_creation(self):
        nested = self.root / "src/nested"
        nested.mkdir(parents=True)
        with patch.object(isolation.subprocess, "run", side_effect=AssertionError("discovery must not run Git")):
            project = self.discover(nested)
        self.assertEqual(project.root, self.root)
        self.assertEqual(project.worktree.main_root, self.main)
        self.assertEqual(project.worktree.git_dir, self.admin)
        self.assertEqual(project.worktree.common_dir, self.main / ".git")
        self.assertEqual(project.base, self.base)
        self.assertEqual(project.registered_root, self.main)
        self.assertNotEqual(project.home, self.main_home)
        self.assertEqual(project.home.parent.parent, self.base / ".runtime/sample-project/worktrees")
        self.assertFalse(project.home.parent.parent.exists())
        self.assertEqual(self.discover(), project)

    def test_same_basename_in_two_orca_repositories_has_distinct_state(self):
        second = self.orca / "another-repo/branch-a"
        second.parent.mkdir()
        self.git("-C", str(self.main), "worktree", "add", "-b", "synthetic-second", str(second))
        first_project, second_project = self.discover(), self.discover(second)
        self.assertNotEqual(first_project.home, second_project.home)
        self.assertNotEqual(first_project.worktree.git_dir, second_project.worktree.git_dir)

    def test_relative_git_and_backlink_pointers_are_valid(self):
        (self.root / ".git").write_text("gitdir: " + os.path.relpath(self.admin, self.root) + "\n")
        (self.admin / "gitdir").write_text(os.path.relpath(self.root / ".git", self.admin) + "\n")
        self.assertEqual(self.discover().worktree.git_dir, self.admin)

    def test_absent_marker_never_falls_back_for_registered_link(self):
        (self.root / isolation.MARKER_NAME).unlink()
        self.assert_blocked()
        child = self.root / "child"
        child.mkdir()
        self.assert_blocked(child)

    def test_malformed_mismatched_or_ambiguous_markers_are_blocked(self):
        marker = self.root / isolation.MARKER_NAME
        for value in ("{broken", "null", "{}", json.dumps({**self.marker, "schema": 2}),
                      json.dumps({**self.marker, "project": "other"}),
                      json.dumps({**self.marker, "requires_registered_launcher": False})):
            with self.subTest(value=value):
                marker.write_text(value)
                self.assert_blocked()
        marker.write_text(json.dumps(self.marker))
        child = self.root / "nested"
        child.mkdir()
        (child / isolation.MARKER_NAME).write_text(json.dumps(self.marker))
        self.assert_blocked(child)

    def test_plain_external_marked_copy_has_clear_error(self):
        copied = self.orca / "sample-project/copied"
        shutil.copytree(self.root, copied)
        (copied / ".git").unlink()
        with self.assertRaisesRegex(core.Blocked, "普通外部副本"):
            self.discover(copied)

    def test_linked_worktree_outside_supported_orca_layout_is_blocked(self):
        outside = self.temp_root / "outside"
        self.git("-C", str(self.main), "worktree", "add", "-b", "synthetic-outside", str(outside))
        self.assert_blocked(outside)

    def test_unrelated_unmarked_git_worktree_stays_ordinary(self):
        outside = self.temp_root / "ordinary"
        outside.mkdir()
        self.git("init", str(outside))
        self.assertIsNone(self.discover(outside))

    def test_gitdir_must_be_exact_child_of_registered_worktrees(self):
        pointer = self.root / ".git"
        for target in (self.main / ".git", self.main / ".git/worktrees", self.admin / "nested", self.temp_root / "foreign"):
            with self.subTest(target=target):
                pointer.write_text("gitdir: " + str(target) + "\n")
                self.assert_blocked()

    def test_common_dir_and_backlink_must_match_exactly(self):
        common, backlink = self.admin / "commondir", self.admin / "gitdir"
        original_common, original_backlink = common.read_text(), backlink.read_text()
        for target in (self.temp_root, self.main, self.admin, self.main / ".git/objects"):
            with self.subTest(common=target):
                common.write_text(str(target) + "\n")
                self.assert_blocked()
        common.write_text(original_common)
        for target in (self.root, self.main / ".git", self.orca / "sample-project/sibling/.git"):
            with self.subTest(backlink=target):
                backlink.write_text(str(target) + "\n")
                self.assert_blocked()
        backlink.write_text(original_backlink)
        self.assertIsNotNone(self.discover())

    def test_git_pointer_files_reject_symlink_hardlink_unsafe_mode_and_oversize(self):
        for pointer in (self.root / ".git", self.root / isolation.MARKER_NAME,
                        self.admin / "gitdir", self.admin / "commondir"):
            original = pointer.read_bytes()
            for attack in ("symlink", "hardlink", "writable", "oversize", "multiline"):
                with self.subTest(pointer=pointer.name, attack=attack):
                    external = self.temp_root / "metadata-copy"
                    external.write_bytes(original)
                    pointer.unlink()
                    if attack == "symlink":
                        pointer.symlink_to(external)
                    elif attack == "hardlink":
                        os.link(external, pointer)
                    else:
                        pointer.write_bytes(original)
                        if attack == "writable":
                            pointer.chmod(0o666)
                        elif attack == "oversize":
                            pointer.write_bytes(b"x" * 16385)
                        else:
                            pointer.write_bytes(original + b"unexpected second line\n")
                    self.assert_blocked()
                    pointer.unlink()
                    external.unlink()
                    pointer.write_bytes(original)

    def test_linkage_rejects_foreign_owner(self):
        with patch.object(isolation.os, "getuid", return_value=os.getuid() + 10000):
            self.assert_blocked()

    def test_missing_linkage_files_are_blocked(self):
        for pointer in (self.root / ".git", self.admin / "commondir", self.admin / "gitdir"):
            data = pointer.read_bytes()
            pointer.unlink()
            self.assert_blocked()
            pointer.write_bytes(data)

    def test_git_directory_symlink_and_unsafe_permissions_are_blocked(self):
        for directory in (self.main / ".git/objects", self.main / ".git/refs", self.admin):
            backup = directory.with_name(directory.name + "-saved")
            directory.rename(backup)
            directory.symlink_to(backup, target_is_directory=True)
            self.assert_blocked()
            directory.unlink()
            backup.rename(directory)
            directory.chmod(0o777)
            self.assert_blocked()
            directory.chmod(0o755)

    def test_shared_config_or_writable_index_links_are_blocked(self):
        for leaf in (self.main / ".git/config", self.admin / "index", self.admin / "index.lock"):
            original = leaf.read_bytes() if leaf.exists() else None
            for link in ("symlink", "hardlink"):
                with self.subTest(leaf=leaf.name, link=link):
                    external = self.temp_root / "external-leaf"
                    external.write_bytes(original or b"synthetic lock")
                    leaf.unlink(missing_ok=True)
                    if link == "symlink":
                        leaf.symlink_to(external)
                    else:
                        os.link(external, leaf)
                    self.assert_blocked()
                    leaf.unlink()
                    external.unlink()
                    if original is not None:
                        leaf.write_bytes(original)

    def test_command_creates_private_state_without_copying_main_login_or_history(self):
        (self.main_home / ".claude").mkdir(mode=0o700)
        (self.main_home / ".claude/.credentials.json").write_text("synthetic credential never copied")
        (self.main_home / ".claude/history.jsonl").write_text("synthetic history never copied")
        project = self.discover()
        self.command(project)
        for folder in (project.home.parent.parent, project.home.parent, project.home,
                       project.config, project.home / "tmp", project.home / ".cache", project.home / ".config"):
            self.assertTrue(folder.is_dir())
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(project.config.iterdir()), [])
        env = isolation.environment(project, "http://127.0.0.1:62919", {})
        self.assertEqual(env["HOME"], str(project.home))
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(project.config))

    def test_discovery_and_preparation_reject_unsafe_runtime_parents(self):
        project = self.discover()
        worktrees = project.home.parent.parent
        outside = self.temp_root / "outside-home"
        outside.mkdir()
        worktrees.symlink_to(outside, target_is_directory=True)
        self.assert_blocked()
        with self.assertRaises(core.Blocked):
            self.command(project)
        self.assertEqual(list(outside.iterdir()), [])
        worktrees.unlink()
        worktrees.mkdir(mode=0o777)
        worktrees.chmod(0o777)
        self.assert_blocked()

    def test_command_revalidates_changed_linkage_and_marker(self):
        project = self.discover()
        backlink = self.admin / "gitdir"
        original = backlink.read_text()
        backlink.write_text(str(self.main / ".git") + "\n")
        with self.assertRaises(core.Blocked):
            self.command(project)
        backlink.write_text(original)
        (self.root / isolation.MARKER_NAME).unlink()
        with self.assertRaises(core.Blocked):
            self.command(project)

    def test_auto_trust_runs_only_after_final_worktree_validation(self):
        from surge_cc import isolated_trust
        project = self.discover()
        (self.admin / "gitdir").write_text(str(self.main / ".git") + "\n")
        with patch.object(isolated_trust, "prepare") as trust:
            with self.assertRaises(core.Blocked):
                self.command(project)
            trust.assert_not_called()

    def test_auto_trust_keeps_same_sandbox_environment_and_native_arguments(self):
        project = self.discover()
        before = self.command(project)
        env = isolation.environment(project, "http://127.0.0.1:62919", {}, token_auth=True)
        trust_file = self.base / ".runtime/trust.json"
        trust_file.write_text(json.dumps({"schema": 1, "enabled": True, "projects": [
            {"id": project.name, "path": str(self.main)}]}))
        trust_file.chmod(0o600)
        after = self.command(project)
        self.assertEqual(before, after)
        self.assertEqual(env, isolation.environment(project, "http://127.0.0.1:62919", {}, token_auth=True))
        data = json.loads((project.config / ".claude.json").read_text())
        self.assertEqual(data, {"projects": {str(self.main): {"hasTrustDialogAccepted": True}}})
        self.assertFalse((project.config / ".credentials.json").exists())
        self.assertFalse((project.config / "projects").exists())
        self.assertNotIn(str(trust_file), after[2])
        self.assertNotIn('(subpath ' + json.dumps(str(trust_file.parent)) + ')', after[2])

    def test_command_rejects_substituted_main_home(self):
        project = replace(self.discover(), home=self.main_home)
        with self.assertRaises(core.Blocked):
            self.command(project)
        self.assertEqual(list(self.main_home.iterdir()), [])

    def test_worktree_cannot_encompass_trusted_launcher_state(self):
        self.config_path = self.root / "trusted-launcher/config.json"
        self.config_path.parent.mkdir(mode=0o700)
        registry = self.config_path.parent / isolation.REGISTRY_NAME
        registry.write_text(json.dumps(self.registry_data))
        registry.chmod(0o600)
        self.assert_blocked()

    def test_external_cwd_alias_and_writable_workspace_parent_are_blocked(self):
        alias = self.temp_root / "worktree-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assert_blocked(alias)
        self.root.parent.chmod(0o777)
        self.assert_blocked()

    def test_policy_shares_git_data_but_protects_configuration_and_other_worktrees(self):
        project = self.discover()
        policy = isolation.profile(project, self.native, self.hook)
        q = lambda p: json.dumps(str(p))
        self.assertIn('(subpath ' + q(project.root) + ')', policy)
        self.assertIn('(subpath ' + q(project.home) + ')', policy)
        for path in (self.main, self.main / ".git", self.main / ".git/worktrees", self.admin,
                     self.main_home, self.base, self.orca):
            self.assertNotIn('(subpath ' + q(path) + ')', policy)
        for path in (self.main / ".git/objects", self.main / ".git/refs"):
            self.assertIn('(subpath ' + q(path) + ')', policy)
        write_lines = [line for line in policy.splitlines() if "(allow" in line and "file-write" in line]
        git_lines = [line for line in write_lines if str(self.main / ".git") in line]
        self.assertTrue(git_lines)
        for path in (self.admin / "index", self.admin / "index.lock", self.admin / "HEAD.lock",
                     self.main / ".git/packed-refs.lock"):
            self.assertTrue(any('(literal ' + q(path) + ')' in line for line in git_lines))
        for path in (self.main / ".git/objects", self.main / ".git/refs", self.main / ".git/logs/refs"):
            self.assertTrue(any('(subpath ' + q(path) + ')' in line for line in git_lines))
        for path in (self.main / ".git/hooks", self.main / ".git/config", self.main / ".git/config.lock",
                     self.admin / "config", self.admin / "config.worktree", self.admin / "commondir",
                     self.main / ".git/objects/info/alternates"):
            self.assertTrue(any('(subpath ' + q(path) + ')' in line for line in policy.splitlines()
                                if line.startswith('(deny file-write* file-link ')))
        self.assertNotIn("(allow mach-lookup", policy)
        self.assertNotIn("(allow network*)", policy)
        self.assertIn("(deny file-link)", policy)
        self.assertIn('(allow file-link (subpath ' + q(project.root) + ') (subpath ' + q(project.home) + '))', policy)

    @unittest.skipUnless(sys.platform == "darwin" and isolation.SANDBOX.is_file(), "macOS Seatbelt unavailable")
    def test_real_sandbox_git_commit_fetch_push_and_shared_control_write_denial(self):
        project = self.discover()
        self.command(project)
        (self.root / "tracked.txt").write_text("synthetic changed\n")
        native = Path("/usr/bin/git")
        policy = isolation.profile(project, native, self.hook)
        env = isolation.environment(project, "http://127.0.0.1:62919", {})

        def sandbox(*args):
            return subprocess.run([str(isolation.SANDBOX), "-p", policy, *map(str, args)],
                                  cwd=project.root, env=env, capture_output=True, text=True, timeout=15)

        status = sandbox(native, "status", "--short")
        if status.returncode == 71 and "sandbox_apply: Operation not permitted" in status.stderr:
            self.skipTest("host prevents nesting Seatbelt; run this test outside the enclosing sandbox")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("tracked.txt", status.stdout)
        diff = sandbox(native, "diff", "--no-ext-diff", "--no-textconv")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        self.assertIn("synthetic changed", diff.stdout)
        history = sandbox(native, "log", "-1", "--oneline")
        self.assertEqual(history.returncode, 0, history.stderr)
        self.assertIn("synthetic fixture", history.stdout)
        normal_git = sandbox("/bin/sh", "-c", "git status --short")
        self.assertEqual(normal_git.returncode, 0, normal_git.stderr)
        stage = sandbox(native, "add", "tracked.txt")
        self.assertEqual(stage.returncode, 0, stage.stderr)
        commit = sandbox(native, "commit", "-m", "synthetic sandbox commit")
        self.assertEqual(commit.returncode, 0, commit.stderr)
        branch = sandbox(native, "branch", "synthetic-shared-branch")
        self.assertEqual(branch.returncode, 0, branch.stderr)
        # A disposable local bare remote is inside this worktree; this verifies
        # real Git transfer/write behavior without credentials or the network.
        remote = self.root / "synthetic-remote.git"
        self.git("clone", "--bare", "--no-hardlinks", str(self.main), str(remote))
        fetched = sandbox(native, "fetch", "--no-tags", str(remote),
                          "refs/heads/synthetic-worktree:refs/remotes/synthetic/worktree")
        self.assertEqual(fetched.returncode, 0, fetched.stderr)
        pushed = sandbox(native, "push", str(remote), "HEAD:refs/heads/from-sandbox")
        self.assertEqual(pushed.returncode, 0, pushed.stderr)
        for path in (self.main / "tracked.txt", self.main_home):
            command = "/bin/ls" if path.is_dir() else "/bin/cat"
            result = sandbox(command, path)
            self.assertNotEqual(result.returncode, 0, str(path))
            self.assertIn("Operation not permitted", result.stderr)
        for path in (self.main / ".git/config", self.admin / "commondir", self.admin / "gitdir"):
            before = path.read_bytes()
            result = sandbox("/bin/sh", "-c", 'printf synthetic-denied >> "$1"', "sh", path)
            self.assertNotEqual(result.returncode, 0, str(path))
            self.assertEqual(path.read_bytes(), before)
        # A readonly shared inode must not become writable through a new link
        # into the otherwise writable project (or private HOME).
        for destination in (self.root / "linked-shared-config", project.home / "linked-shared-config"):
            result = sandbox("/bin/ln", self.main / ".git/config", destination)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(destination.exists())
        internal = project.home / "internal-link"
        result = sandbox("/bin/ln", self.root / "tracked.txt", internal)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(internal.stat().st_ino, (self.root / "tracked.txt").stat().st_ino)
        # Both endpoints matter, even if the destination is another granted
        # writable area (the shared Git object store).
        destination = self.main / ".git/objects/forbidden-project-link"
        result = sandbox("/bin/ln", self.root / "tracked.txt", destination)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse(destination.exists())
        index_lock = self.admin / "index.lock"
        result = sandbox("/bin/sh", "-c", 'printf synthetic-lock > "$1"', "sh", index_lock)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(index_lock.read_text(), "synthetic-lock")


if __name__ == "__main__":
    unittest.main()
