"""Synthetic-only transcript migration tests; no user chats or model calls."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, isolation, keychain_auth, shared_history as history


SID = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
LOG = b'{"type":"user","message":{"content":"synthetic fixture"}}\n'


class SharedHistoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temp.cleanup)
        self.top = Path(temp.name).resolve()
        self.base = self.top / "isolated"
        self.root = self.base / "projects/vv"
        self.runtime = self.base / ".runtime"
        self.home = self.runtime / "vv/home"
        self.config = self.top / "launcher/config.json"
        for path in (self.root, self.home / ".claude", self.config.parent / "terminal"):
            self.mkdir(path)
        self.write_json(self.config, {"workspace": "A"})
        self.registry = self.config.parent / isolation.REGISTRY_NAME
        self.write_json(self.registry, {"schema": 1, "root": str(self.base), "projects": [
            {"id": "vv", "path": str(self.root), "home": str(self.home)}]})
        self.write_json(self.config.parent / "terminal" / keychain_auth.MIGRATION,
                        {"schema": 1, "workspace": "A", "legacy_marker_present": False})
        self.project = isolation.bind_workspace(isolation.Project("vv", self.root, self.home), self.config, "A")
        self.marker = self.runtime / history.MARKER
        self.value = {"schema": 1, "projects": [{"id": "vv", "path": str(self.root)}]}
        self.store = self.runtime / "vv/conversation-history/A"
        self.data = self.store / "data"

    def mkdir(self, path):
        missing = []
        current = path
        while not current.exists():
            missing.append(current)
            current = current.parent
        for current in reversed(missing):
            current.mkdir(mode=0o700)

    def write(self, path, content, mode=0o600):
        self.mkdir(path.parent)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def write_json(self, path, value, mode=0o600):
        return self.write(path, json.dumps(value).encode(), mode)

    def enable(self):
        self.write_json(self.marker, self.value)

    def session(self, home=None, sid=SID, content=LOG, bucket="fixture"):
        return self.write((home or self.home) / ".claude/projects" / bucket / (sid + ".jsonl"), content)

    def orphan(self, digit="a", account="A"):
        parent = self.runtime / "vv/worktrees" / (digit * 64)
        home = parent / "home" if account == "A" else parent / "accounts" / account / "home"
        self.mkdir(home)
        return home

    def switch(self, workspace):
        self.write_json(self.config, {"workspace": workspace})
        return isolation.bind_workspace(isolation.Project("vv", self.root, self.home), self.config, workspace)

    def test_disabled_is_read_only_and_does_not_require_bound_workspace(self):
        raw = isolation.Project("vv", self.root, self.home)
        self.assertFalse(history.enabled(raw))
        self.assertIsNone(history.history(raw))
        self.assertIsNone(history.prepare(raw))
        self.assertFalse(self.store.exists())

    def test_missing_runtime_directory_is_disabled(self):
        other = self.top / "empty-isolated"
        root = other / "projects/vv"
        self.mkdir(root)
        project = isolation.Project("vv", root, other / ".runtime/vv/home")
        self.assertFalse(history.enabled(project))
        self.assertIsNone(history.history(project))
        self.assertIsNone(history.prepare(project))
        self.assertFalse((other / ".runtime").exists())

    def test_initialize_without_marker_then_enable_and_prepare(self):
        original = self.session()
        result = history.initialize(self.project)
        self.assertTrue(result["initialized"])
        self.assertEqual((result["sessions"], result["files"], result["bytes"]), (1, 1, len(LOG)))
        self.assertEqual(original.read_bytes(), LOG)
        self.assertFalse(self.marker.exists())
        self.enable()
        self.assertTrue(history.enabled(self.project))
        self.assertEqual(history.history(self.project), self.data)
        self.assertEqual(history.prepare(self.project), self.data)
        link = self.home / ".claude/projects/surge-cc-vv"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(self.data))
        self.assertEqual(history.prepare(self.project), self.data)
        self.assertEqual(original.read_bytes(), LOG)

    def test_enabled_uninitialized_fails_closed(self):
        self.enable()
        self.assertTrue(history.enabled(self.project))
        for call in (history.history, history.prepare):
            with self.assertRaises(core.Blocked):
                call(self.project)
        self.assertFalse(self.store.exists())

    def test_empty_store_is_explicitly_supported(self):
        result = history.initialize(self.project)
        self.assertEqual((result["sessions"], result["files"], result["bytes"]), (0, 0, 0))
        self.assertTrue(self.data.is_dir())

    def test_unlisted_project_remains_untouched(self):
        self.write_json(self.marker, {"schema": 1, "projects": []})
        self.assertFalse(history.enabled(self.project))
        self.assertIsNone(history.prepare(self.project))

    def test_malformed_marker_fails_closed(self):
        cases = [{}, {**self.value, "schema": True}, {**self.value, "schema": 2},
                 {**self.value, "extra": 1}, {"schema": 1, "projects": {}},
                 {"schema": 1, "projects": [None]},
                 {"schema": 1, "projects": self.value["projects"] * 2},
                 {"schema": 1, "projects": [{"id": "vv", "path": str(self.base)}]},
                 {"schema": 1, "projects": [{"id": "other", "path": str(self.base / "projects/other")}]},
                 {"schema": 1, "projects": [{"id": "../vv", "path": str(self.root)}]},
                 {"schema": 1, "projects": [{"id": "vv", "path": str(self.root), "extra": 1}]}]
        for value in cases:
            with self.subTest(value=value):
                self.write_json(self.marker, value)
                with self.assertRaises(core.Blocked):
                    history.enabled(self.project)

    def test_marker_duplicate_json_keys_rejected(self):
        self.write(self.marker, b'{"schema":1,"schema":1,"projects":[]}')
        with self.assertRaises(core.Blocked):
            history.enabled(self.project)

    def test_marker_symlink_hardlink_permissions_rejected(self):
        target = self.write_json(self.top / "marker", self.value)
        for kind in ("symlink", "hardlink", "permissions"):
            with self.subTest(kind=kind):
                if self.marker.exists() or self.marker.is_symlink():
                    self.marker.unlink()
                if kind == "symlink":
                    self.marker.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, self.marker)
                else:
                    self.write_json(self.marker, self.value, 0o644)
                with self.assertRaises(core.Blocked):
                    history.enabled(self.project)

    def test_bound_active_workspace_is_required(self):
        self.enable()
        for project in (replace(self.project, workspace=None), replace(self.project, workspace="B"),
                        replace(self.project, home=self.top)):
            with self.subTest(project=project), self.assertRaises(core.Blocked):
                history.enabled(project)
        with self.assertRaises(core.Blocked):
            history.initialize(replace(self.project, root=self.top))

    def test_deleted_worktree_homes_included_without_live_repository(self):
        first = self.session()
        orphan = self.orphan()
        second = self.session(orphan, OTHER, LOG + b"\n")
        result = history.initialize(self.project)
        self.assertEqual(result["sessions"], 2)
        self.assertEqual(result["source_homes"], 2)
        self.assertEqual((self.data / (SID + ".jsonl")).read_bytes(), first.read_bytes())
        self.assertEqual((self.data / (OTHER + ".jsonl")).read_bytes(), second.read_bytes())

    def test_account_and_project_boundaries(self):
        self.session()
        self.session(self.orphan("a"), OTHER)
        b_home = self.runtime / "vv/accounts/B/home"
        self.session(b_home, SID, b"synthetic B\n")
        self.session(self.orphan("b", "B"), OTHER, b"synthetic B worktree\n")
        foreign = self.runtime / "inkclaw/home"
        self.session(foreign, SID, b"unrelated project\n")
        project_b = self.switch("B")
        result = history.initialize(project_b)
        data_b = self.runtime / "vv/conversation-history/B/data"
        self.assertEqual(result["sessions"], 2)
        self.assertEqual((data_b / (SID + ".jsonl")).read_bytes(), b"synthetic B\n")
        self.assertFalse(self.data.exists())
        self.project = self.switch("A")
        history.initialize(self.project)
        self.assertEqual((self.data / (SID + ".jsonl")).read_bytes(), LOG)

    def test_legacy_owner_can_be_b(self):
        self.write_json(self.config.parent / "terminal" / keychain_auth.MIGRATION,
                        {"schema": 1, "workspace": "B", "legacy_marker_present": False})
        self.session()
        project_b = self.switch("B")
        self.assertEqual(project_b.home, self.home)
        result = history.initialize(project_b)
        self.assertEqual(result["sessions"], 1)
        self.assertTrue((self.runtime / "vv/conversation-history/B/data" / (SID + ".jsonl")).exists())

    def test_new_account_no_homes_initializes_empty(self):
        self.session()
        project_b = self.switch("B")
        result = history.initialize(project_b)
        self.assertEqual(result["sessions"], 0)
        self.assertEqual(result["source_homes"], 0)

    def test_admin_initialize_nonactive_account_does_not_switch_selection(self):
        project_b = isolation.bind_workspace(isolation.Project("vv", self.root, self.home), self.config, "B")
        result = history.initialize(project_b)
        self.assertEqual(result["workspace"], "B")
        self.assertEqual(json.loads(self.config.read_text()), {"workspace": "A"})
        self.enable()
        with self.assertRaises(core.Blocked):
            history.history(project_b)

    def test_only_transcripts_and_owned_session_artifacts_are_copied(self):
        source = self.session().parent
        self.write(source / SID / "subagents/agent-one.jsonl", b"synthetic subagent\n")
        self.write(source / SID / "tool-results/result.txt", b"synthetic result\n")
        ignored = [source / "memory/MEMORY.md", source / "sessions-index.json",
                   source / SID / "unknown.json", self.home / ".claude/.credentials.json",
                   self.home / ".claude/debug/log.txt", self.home / ".claude/history.jsonl"]
        for file in ignored:
            self.write(file, b"synthetic ignored bytes")
        result = history.initialize(self.project)
        self.assertEqual(result["files"], 3)
        self.assertEqual(sorted(str(p.relative_to(self.data)) for p in self.data.rglob("*") if p.is_file()),
                         [SID + ".jsonl", SID + "/subagents/agent-one.jsonl", SID + "/tool-results/result.txt"])
        for file in ignored:
            self.assertEqual(file.read_bytes(), b"synthetic ignored bytes")

    def test_orphan_session_artifacts_without_transcript_not_imported(self):
        self.write(self.home / ".claude/projects/fixture" / SID / "tool-results/result.txt", b"synthetic")
        result = history.initialize(self.project)
        self.assertEqual(result["files"], 0)

    def test_identical_duplicate_session_deduplicated(self):
        self.session()
        self.session(self.orphan())
        result = history.initialize(self.project)
        self.assertEqual(result["sessions"], 1)
        self.assertEqual(result["bytes"], len(LOG))

    def test_conflicting_uuid_does_not_publish_or_modify_source(self):
        a = self.session()
        b = self.session(self.orphan(), content=b"different synthetic log\n")
        with self.assertRaises(core.Blocked) as caught:
            history.initialize(self.project)
        self.assertNotIn("different synthetic", str(caught.exception))
        self.assertEqual(a.read_bytes(), LOG)
        self.assertEqual(b.read_bytes(), b"different synthetic log\n")
        self.assertFalse(self.store.exists())
        self.assertEqual(list(self.store.parent.iterdir()), [])

    def test_subagent_conflict_rejected(self):
        a = self.session()
        b = self.session(self.orphan())
        self.write(a.parent / SID / "subagents/agent-x.jsonl", b"one")
        self.write(b.parent / SID / "subagents/agent-x.jsonl", b"two")
        with self.assertRaises(core.Blocked):
            history.initialize(self.project)
        self.assertFalse(self.store.exists())

    def test_idempotent_initialization_never_reimports_or_overwrites(self):
        source = self.session()
        history.initialize(self.project)
        self.write(self.data / (SID + ".jsonl"), LOG + b"new shared conversation\n")
        source.write_bytes(b"changed legacy log\n")
        result = history.initialize(self.project)
        self.assertTrue(result["already_initialized"])
        self.assertFalse(result["initialized"])
        self.assertEqual((self.data / (SID + ".jsonl")).read_bytes(), LOG + b"new shared conversation\n")

    def test_source_links_and_hardlinks_rejected(self):
        path = self.session()
        target = self.write(self.top / "outside.jsonl", LOG)
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                path.unlink()
                path.symlink_to(target) if kind == "symlink" else os.link(target, path)
                with self.assertRaises(core.Blocked):
                    history.initialize(self.project)
                self.assertFalse(self.store.exists())

    def test_parent_symlink_rejected(self):
        target = self.top / "external"
        self.mkdir(target)
        (self.home / ".claude/projects").symlink_to(target)
        with self.assertRaises(core.Blocked):
            history.initialize(self.project)

    def test_source_writable_by_others_rejected(self):
        source = self.session()
        source.chmod(0o666)
        with self.assertRaises(core.Blocked):
            history.initialize(self.project)

    def test_non_private_source_file_read_mode_is_accepted_and_tightened(self):
        source = self.session()
        source.chmod(0o644)
        history.initialize(self.project)
        self.assertEqual((self.data / (SID + ".jsonl")).stat().st_mode & 0o777, 0o600)
        self.assertEqual(source.stat().st_mode & 0o777, 0o644)

    def test_source_special_file_rejected_without_blocking(self):
        path = self.home / ".claude/projects/fixture" / (SID + ".jsonl")
        self.mkdir(path.parent)
        os.mkfifo(path)
        with self.assertRaises(core.Blocked):
            history.initialize(self.project)

    def test_source_mutation_after_copy_aborts_atomic_publication(self):
        source = self.session()
        original = history._copy
        def mutate(*args):
            result = original(*args)
            source.write_bytes(LOG + b"changed\n")
            return result
        with patch.object(history, "_copy", side_effect=mutate), self.assertRaises(core.Blocked):
            history.initialize(self.project)
        self.assertFalse(self.store.exists())
        self.assertEqual(list(self.store.parent.iterdir()), [])

    def test_source_added_after_scan_aborts(self):
        self.session()
        original = history._copy
        def mutate(*args):
            result = original(*args)
            self.session(sid=OTHER)
            return result
        with patch.object(history, "_copy", side_effect=mutate), self.assertRaises(core.Blocked):
            history.initialize(self.project)
        self.assertFalse(self.store.exists())

    def test_previously_absent_source_created_after_scan_aborts(self):
        original = history._copy
        def mutate(*args):
            result = original(*args)
            self.session()
            return result
        with patch.object(history, "_copy", side_effect=mutate), self.assertRaises(core.Blocked):
            history.initialize(self.project)
        self.assertFalse(self.store.exists())

    def test_limits_are_enforced(self):
        self.session()
        for constant, limit in (("MAX_FILE", 1), ("MAX_BYTES", 1), ("MAX_FILES", 0),
                                ("MAX_HOMES", 0), ("MAX_ENTRIES", 0)):
            with self.subTest(constant=constant), patch.object(history, constant, limit), self.assertRaises(core.Blocked):
                history.initialize(self.project)

    def test_data_and_receipt_are_private_and_metadata_is_outside_data(self):
        self.session()
        history.initialize(self.project)
        for directory in (self.store.parent, self.store, self.data):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        receipt = self.store / history.RECEIPT
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.data / history.RECEIPT).exists())

    def test_invalid_receipt_or_store_is_not_replaced(self):
        self.session()
        history.initialize(self.project)
        self.enable()
        receipt = self.store / history.RECEIPT
        old = receipt.read_bytes()
        for bad in ({}, {**json.loads(old), "workspace": "B"}, {**json.loads(old), "sessions": True}):
            self.write_json(receipt, bad)
            for call in (history.history, history.initialize):
                with self.assertRaises(core.Blocked):
                    call(self.project)
        self.assertEqual((self.data / (SID + ".jsonl")).read_bytes(), LOG)

    def test_wrong_existing_bucket_never_replaced(self):
        history.initialize(self.project)
        self.enable()
        path = self.home / ".claude/projects/surge-cc-vv"
        self.mkdir(path)
        self.write(path / "keep", b"synthetic")
        with self.assertRaises(core.Blocked):
            history.prepare(self.project)
        self.assertEqual((path / "keep").read_bytes(), b"synthetic")

    def test_wrong_bucket_symlink_never_replaced(self):
        history.initialize(self.project)
        self.enable()
        parent = self.home / ".claude/projects"
        self.mkdir(parent)
        (parent / "surge-cc-vv").symlink_to(self.top)
        with self.assertRaises(core.Blocked):
            history.prepare(self.project)
        self.assertEqual(os.readlink(parent / "surge-cc-vv"), str(self.top))

    def test_safe_bucket_length(self):
        self.assertEqual(history.bucket(self.project), "surge-cc-vv")
        self.assertLessEqual(len(history.bucket(replace(self.project, name="a" * 40))), 64)
        for invalid in ("../vv", "", "a" * 41):
            with self.assertRaises(core.Blocked):
                history.bucket(replace(self.project, name=invalid))


if __name__ == "__main__":
    unittest.main()
