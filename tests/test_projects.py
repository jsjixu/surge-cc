"""Fresh-install and migration coverage using only disposable synthetic projects."""
import hashlib
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
from surge_cc import core, isolation, keychain_auth, projects, shared_history, workspaces


SID_A = "11111111-1111-4111-8111-111111111111"
SID_B = "22222222-2222-4222-8222-222222222222"


@unittest.skipUnless(shutil.which("git"), "local Git unavailable")
class ProjectSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="surge-cc-projects-test-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name).resolve()
        self.source = self.top / "engineering"
        self.base = self.top / "isolated"
        self.config = self.top / "launcher/config.json"
        self.mkdir(self.source)
        self.write_json(self.config, {"workspace": "A"})
        self.write(self.source / "README.md", b"# Synthetic project\n")
        self.write(self.source / "src/main.py", b"print('synthetic')\n")
        self.write(self.source / "package.json", b'{"name":"fixture"}')
        self.registry = self.config.parent / isolation.REGISTRY_NAME
        self.patcher = patch.object(isolation, "DEFAULT_ROOT", self.base)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def mkdir(self, path):
        missing = []
        while not path.exists():
            missing.append(path)
            path = path.parent
        for path in reversed(missing):
            path.mkdir(mode=0o700)

    def write(self, path, data, mode=0o600):
        self.mkdir(path.parent)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def write_json(self, path, data):
        return self.write(path, json.dumps(data).encode())

    def plan(self, name="fixture"):
        return projects.plan(self.config, self.source, name)

    def apply(self, name="fixture", **kwargs):
        preview = self.plan(name)
        return projects.apply(self.config, self.source, name, expected_digest=preview["digest"], **kwargs)

    def bound(self, name="fixture", workspace="A"):
        project = isolation.for_cwd(self.config, self.base / "projects" / name)
        return isolation.bind_workspace(project, self.config, workspace)

    def source_fingerprints(self):
        return {str(path.relative_to(self.source)): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                for path in self.source.rglob("*") if path.is_file() and not path.is_symlink()}

    def test_preview_read_only_with_deterministic_digest(self):
        before = self.source_fingerprints()
        one, two = self.plan(), self.plan()
        self.assertEqual(one, two)
        self.assertEqual(one["file_count"], 3)
        self.assertFalse(self.base.exists())
        self.assertFalse(self.registry.exists())
        self.assertEqual(before, self.source_fingerprints())
        self.assertIn("embedded", one["review_notice"])

    def test_excludes_accounts_logs_keys_git_symlinks_and_hardlinks(self):
        for name in (".env", ".env.example", ".claude.json", "id_ed25519", "deploy.key", "tokens.json", "server.log",
                     ".git/config", ".claude/projects/secret.jsonl", "node_modules/pkg/index.js", "Browser/Cookies"):
            self.write(self.source / name, b"DO NOT IMPORT")
        (self.source / "escape").symlink_to(self.config.parent, target_is_directory=True)
        external = self.write(self.top / "external.json", b"hardlinked synthetic data")
        os.link(external, self.source / "hardlinked.json")
        result = self.plan()
        self.assertEqual(result["file_count"], 3)
        excluded = {item["path"]: item["reason"] for item in result["excluded"]}
        self.assertIn(".env", excluded)
        self.assertIn(".git", excluded)
        self.assertIn("escape", excluded)
        self.assertIn("hardlinked.json", excluded)
        copied = self.apply()
        target = Path(copied["path"])
        self.assertFalse((target / ".env").exists())
        self.assertFalse((target / "escape").exists())
        self.assertTrue((target / ".git").is_dir())  # Fresh local history only.

    def test_fresh_install_registers_copy_and_account_scoped_features(self):
        before = self.source_fingerprints()
        result = self.apply(trust=True)
        target = Path(result["path"])
        self.assertEqual(before, self.source_fingerprints())
        self.assertEqual((target / "src/main.py").read_bytes(), (self.source / "src/main.py").read_bytes())
        self.assertIn("package.json", (target / projects.HANDOFF).read_text())
        self.assertNotIn(str(self.source), (target / projects.HANDOFF).read_text())
        self.assertTrue((target / isolation.MARKER_NAME).is_file())
        state = projects.status(self.config)
        self.assertEqual(len(state["projects"]), 1)
        for field in ("shared_history", "history_initialized", "local_messaging", "default_trust"):
            self.assertTrue(state["projects"][0][field], field)
        self.assertEqual(keychain_auth.legacy_workspace(self.config), "A")
        self.assertEqual(result["projects"][0]["history"]["sessions"], 0)
        git = subprocess.run(["/usr/bin/git", "-C", str(target), "log", "--format=%s"], capture_output=True, text=True, check=True)
        self.assertEqual(git.stdout.strip(), "Create isolated engineering snapshot")

    def test_executable_preserved_without_running_setup(self):
        marker = self.top / "must-not-exist"
        self.write(self.source / "setup.sh", ("#!/bin/sh\ntouch " + str(marker) + "\n").encode(), 0o700)
        self.apply()
        self.assertTrue((self.base / "projects/fixture/setup.sh").stat().st_mode & 0o111)
        self.assertFalse(marker.exists())

    def test_digest_change_requires_fresh_review(self):
        reviewed = self.plan()
        self.write(self.source / "src/main.py", b"new source")
        with self.assertRaises(core.Blocked):
            projects.apply(self.config, self.source, "fixture", expected_digest=reviewed["digest"])
        self.assertFalse(self.registry.exists())
        self.assertFalse(self.base.exists())

    def test_changed_exclusion_list_invalidates_plan(self):
        reviewed = self.plan()
        self.write(self.source / ".env", b"secret fixture")
        with self.assertRaises(core.Blocked):
            projects.apply(self.config, self.source, "fixture", expected_digest=reviewed["digest"])
        self.assertFalse(self.base.exists())

    def test_changed_active_account_invalidates_plan(self):
        reviewed = self.plan()
        self.write_json(self.config, {"workspace": "B"})
        with self.assertRaises(core.Blocked):
            projects.apply(self.config, self.source, "fixture", expected_digest=reviewed["digest"])
        self.assertFalse(self.registry.exists())

    def test_source_change_during_copy_cleans_stage(self):
        reviewed = self.plan()
        actual = projects._scan
        calls = []
        def change(source, destination=None):
            calls.append(destination)
            if destination is not None:
                self.write(self.source / "README.md", b"changed during review")
            return actual(source, destination)
        with patch.object(projects, "_scan", side_effect=change):
            with self.assertRaises(core.Blocked):
                projects.apply(self.config, self.source, "fixture", expected_digest=reviewed["digest"])
        self.assertFalse(self.registry.exists())
        self.assertEqual(list((self.base / "projects").iterdir()), [])

    def test_copy_failure_rolls_back_registry_and_new_targets(self):
        with patch.object(shared_history, "initialize", side_effect=core.Blocked("synthetic failure")):
            with self.assertRaises(core.Blocked):
                self.apply()
        self.assertFalse(self.registry.exists())
        self.assertFalse((self.base / "projects/fixture").exists())
        self.assertFalse((self.base / ".runtime/fixture").exists())
        self.assertEqual(self.source_fingerprints().keys(), {"README.md", "src/main.py", "package.json"})

    def test_failed_second_import_preserves_existing_registry_and_features(self):
        self.apply()
        before = self.registry.read_bytes()
        marker = self.base / ".runtime" / shared_history.MARKER
        old_marker = marker.read_bytes()
        with patch.object(shared_history, "initialize", side_effect=core.Blocked("synthetic failure")):
            with self.assertRaises(core.Blocked):
                self.apply("other")
        self.assertEqual(self.registry.read_bytes(), before)
        self.assertEqual(marker.read_bytes(), old_marker)
        self.assertFalse((self.base / "projects/other").exists())

    def test_existing_target_never_overwritten(self):
        self.apply()
        target = self.base / "projects/fixture/src/main.py"
        self.write(target, b"user change")
        with self.assertRaises(core.Blocked):
            self.plan()
        self.assertEqual(target.read_bytes(), b"user change")

    def test_enable_repeated_is_idempotent_preserves_history_and_source(self):
        self.apply()
        before = self.source_fingerprints()
        history = self.base / ".runtime/fixture/conversation-history/A/data" / (SID_A + ".jsonl")
        self.write(history, b"synthetic new account transcript")
        result = projects.enable(self.config, ["fixture"], trust=True)
        self.assertTrue(result["projects"][0]["history"]["already_initialized"])
        self.assertEqual(history.read_bytes(), b"synthetic new account transcript")
        self.assertEqual(before, self.source_fingerprints())

    def test_existing_history_migration_only_current_account_and_keeps_originals(self):
        self.apply(share_history=False, local_messaging=False)
        parent = self.base / ".runtime/fixture"
        a = self.write(parent / "home/.claude/projects/original" / (SID_A + ".jsonl"), b"A transcript\n")
        b = self.write(parent / "accounts/B/home/.claude/projects/original" / (SID_B + ".jsonl"), b"B transcript\n")
        first = projects.enable(self.config, ["fixture"])
        self.assertEqual(first["projects"][0]["history"]["sessions"], 1)
        self.assertTrue((parent / "conversation-history/A/data" / a.name).exists())
        self.assertFalse((parent / "conversation-history/A/data" / b.name).exists())
        self.write_json(self.config, {"workspace": "B"})
        pending = projects.status(self.config)["projects"][0]
        self.assertFalse(pending["history_initialized"])
        second = projects.enable(self.config, ["fixture"])
        self.assertEqual(second["projects"][0]["history"]["sessions"], 1)
        self.assertTrue((parent / "conversation-history/B/data" / b.name).exists())
        self.assertFalse((parent / "conversation-history/B/data" / a.name).exists())
        self.assertEqual(a.read_bytes(), b"A transcript\n")
        self.assertEqual(b.read_bytes(), b"B transcript\n")

    def test_enable_requires_current_workspace_exclusive_lease(self):
        self.apply(share_history=False, local_messaging=False)
        with workspaces._lock(workspaces.location(self.config, "A"), exclusive=False):
            with self.assertRaises(core.Blocked):
                projects.enable(self.config, ["fixture"])
        self.assertFalse((self.base / ".runtime" / shared_history.MARKER).exists())

    def test_apply_refuses_busy_browser_without_creating_copy(self):
        loc = workspaces.paths(self.config, "A")
        (loc["browser"] / "SingletonLock").symlink_to("synthetic-host-123")
        with self.assertRaises(core.Blocked):
            self.apply()
        self.assertFalse(self.base.exists())

    def test_enable_refuses_unrepaired_browser_lock(self):
        self.apply(share_history=False, local_messaging=False)
        loc = workspaces.paths(self.config, "A")
        (loc["browser"] / "SingletonLock").symlink_to("synthetic-host-123")
        with self.assertRaises(core.Blocked):
            projects.enable(self.config, ["fixture"])
        self.assertFalse((self.base / ".runtime" / shared_history.MARKER).exists())

    def test_forged_marker_scope_blocks_instead_of_broadening(self):
        self.apply(share_history=False, local_messaging=False)
        self.write_json(self.base / ".runtime" / shared_history.MARKER,
                        {"schema": 1, "projects": [{"id": "fixture", "path": str(self.top)}]})
        with self.assertRaises(core.Blocked):
            projects.enable(self.config, ["fixture"])
        self.assertFalse((self.base / ".runtime/fixture/conversation-history").exists())

    def test_names_and_broad_source_paths_rejected(self):
        for name in ("../x", "Foo", "", "a/b", "a" * 41):
            with self.subTest(name=name), self.assertRaises(core.Blocked):
                self.plan(name)
        with self.assertRaises(core.Blocked):
            projects.plan(self.config, Path.home(), "fixture")
        with self.assertRaises(core.Blocked):
            projects.plan(self.config, self.top, "fixture")  # Includes managed support/base.

    def test_source_symlink_and_managed_overlap_rejected(self):
        alias = self.top / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(core.Blocked):
            projects.plan(self.config, alias, "fixture")
        self.apply()
        with self.assertRaises(core.Blocked):
            projects.plan(self.config, self.base / "projects/fixture", "other")

    def test_empty_filtered_project_and_size_limits_rejected(self):
        shutil.rmtree(self.source)
        self.mkdir(self.source)
        self.write(self.source / ".env", b"synthetic secret")
        with self.assertRaises(core.Blocked):
            self.plan()
        self.write(self.source / "code.py", b"safe source")
        with patch.object(projects, "MAX_FILE", 1), self.assertRaises(core.Blocked):
            self.plan()

    def test_registry_symlink_rejected(self):
        ordinary = self.write_json(self.top / "other.json", {"schema": 1, "root": str(self.base), "projects": []})
        self.registry.symlink_to(ordinary)
        with self.assertRaises(core.Blocked):
            self.plan()

    def test_worktree_admission_and_shared_features_from_fresh_copy(self):
        self.apply(trust=True)
        main = self.base / "projects/fixture"
        orca = self.top / "orca/workspaces"
        linked = orca / "fixture/new-agent"
        self.mkdir(linked.parent)
        subprocess.run(["/usr/bin/git", "-C", str(main), "-c", "core.hooksPath=/dev/null", "worktree", "add",
                        "-b", "new-agent", str(linked)], check=True, capture_output=True)
        with patch.object(isolation, "ORCA_WORKSPACES", orca):
            discovered = isolation.for_cwd(self.config, linked)
            project = isolation.bind_workspace(discovered, self.config, "A")
            self.assertEqual(project.registered_root, main)
            self.assertNotEqual(project.home, self.bound().home)
            self.assertTrue(shared_history.enabled(project))
            self.assertEqual(shared_history.history(project), shared_history.history(self.bound()))

    def test_migration_preview_is_read_only_and_selected_account_only(self):
        self.apply(share_history=False, local_messaging=False)
        parent = self.base / ".runtime/fixture"
        self.write(parent / "home/.claude/projects/original" / (SID_A + ".jsonl"), b"A transcript\n")
        self.write(parent / "accounts/B/home/.claude/projects/original" / (SID_B + ".jsonl"), b"B transcript\n")
        preview = projects.preview_enable(self.config, ["fixture"])
        self.assertEqual(preview["workspace"], "A")
        self.assertEqual(preview["projects"][0]["candidate_files"], 1)
        self.assertEqual(preview["projects"][0]["candidate_bytes"], len(b"A transcript\n"))
        self.assertFalse((parent / "conversation-history").exists())
        self.assertFalse((self.base / ".runtime" / shared_history.MARKER).exists())

    def test_unbound_existing_histories_are_never_assigned_by_guess(self):
        self.apply(share_history=False, local_messaging=False)
        parent = self.base / ".runtime/fixture"
        self.write(parent / "home/.claude/projects/original" / (SID_A + ".jsonl"), b"unknown account history\n")
        (self.config.parent / "terminal" / keychain_auth.MIGRATION).unlink()
        self.write_json(self.config, {"workspace": "B"})
        with self.assertRaises(core.Blocked):
            projects.preview_enable(self.config, ["fixture"])
        with self.assertRaises(core.Blocked):
            projects.enable(self.config, ["fixture"])
        self.assertFalse((parent / "conversation-history").exists())
        self.assertIsNone(keychain_auth.legacy_workspace(self.config))


    def test_marker_publish_failure_restores_preexisting_markers(self):
        self.apply(share_history=False, local_messaging=False)
        old = {"schema": 1, "projects": []}
        history_marker = self.write_json(self.base / ".runtime" / shared_history.MARKER, old)
        original = projects._write
        def fail(path, value):
            if path.name == "messaging.json":
                raise OSError("synthetic failure")
            return original(path, value)
        with patch.object(projects, "_write", side_effect=fail), self.assertRaises(core.Blocked):
            projects.enable(self.config, ["fixture"])
        self.assertEqual(json.loads(history_marker.read_text()), old)
        self.assertFalse((self.base / ".runtime/messaging.json").exists())
        # Prepared migration is retained privately, never reimported or lost.
        self.assertTrue((self.base / ".runtime/fixture/conversation-history/A/data").is_dir())


if __name__ == "__main__":
    unittest.main()
