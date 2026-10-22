"""Offline release and install transactions; never contact GitHub or real apps."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import updates as u, workspaces, terminal, core


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "config.json"
        core.save_config(self.config, core.validate_config({"schema": 1, "group": "AI", "policy": "Home",
                         "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:62919"}))
        self.sentinels = {self.config: self.config.read_bytes()}
        for name in ("A", "B"):
            paths = workspaces.paths(self.config, name)
            for kind in ("browser", "claude"):
                marker = paths[kind] / "account-marker"
                marker.write_bytes((name + kind).encode())
                self.sentinels[marker] = marker.read_bytes()
        self.zip = self.package("1.2.3")
        self.meta = self.metadata("1.2.3")
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(u.platform, "machine", return_value="arm64"))
        self.stack.enter_context(patch.object(u.platform, "mac_ver", return_value=("26.0", (), "")))
        self.codesign = self.stack.enter_context(patch.object(u.subprocess, "run", return_value=Mock(returncode=0, stdout="arm64")))

    def unchanged(self):
        for file, value in self.sentinels.items():
            self.assertEqual(file.read_bytes(), value)

    def package(self, version, extra=None):
        data = io.BytesIO()
        info = {"CFBundleIdentifier": "local.surgecc.app", "CFBundleShortVersionString": version,
                "CFBundleExecutable": "SurgeCC", "LSMinimumSystemVersion": "13.0"}
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("Surge CC.app/Contents/Info.plist", plistlib.dumps(info))
            for relative in ("MacOS/SurgeCC", "Resources/scripts/surge-cc", "Resources/src/surge_cc/cli.py"):
                archive.writestr("Surge CC.app/Contents/" + relative, version)
            if extra:
                for name, value in extra:
                    archive.writestr(name, value)
        return data.getvalue()

    def metadata(self, version):
        name = "Surge-CC-" + version + "-arm64.zip"
        return {"draft": False, "prerelease": False, "tag_name": "v" + version,
                "html_url": u.BASE + "tag/v" + version, "body": "Release notes",
                "assets": [{"name": n, "size": size, "browser_download_url": u.BASE + "download/v" + version + "/" + n}
                           for n, size in ((name, len(self.zip)), (name + ".sha256", 91))]}

    def fetch(self, url, limit, **kwargs):
        if url.startswith(u.API):
            return json.dumps(self.meta).encode()
        if url.endswith(".sha256"):
            return (hashlib.sha256(self.zip).hexdigest() + "  " + self.meta["assets"][0]["name"]).encode()
        return self.zip

    def download(self):
        return u.download(self.config, "1.2.3", current="1.2.2", fetch=self.fetch)

    def test_check_current_newer_and_ahead(self):
        for current, expected in (("1.2.2", "available"), ("1.2.3", "current"), ("2.0.0", "ahead")):
            data = u.check(current=current, fetch=self.fetch)
            self.assertEqual(data["state"], expected)
            self.assertEqual(data["can_download"], expected == "available")
        self.unchanged()

    def test_rejects_draft_prerelease_and_wrong_repo(self):
        for key, value in (("draft", True), ("prerelease", True), ("html_url", "https://evil.test/tag/v1.2.3")):
            with patch.dict(self.meta, {key: value}):
                with self.assertRaises(core.Blocked):
                    u.release(fetch=self.fetch)

    def test_rejects_unknown_or_duplicate_asset(self):
        self.meta["assets"].append(self.meta["assets"][0])
        with self.assertRaises(core.Blocked):
            u.release(fetch=self.fetch)
        self.meta["assets"].pop()
        self.meta["assets"][0]["browser_download_url"] = "https://evil.test/install"
        with self.assertRaises(core.Blocked):
            u.release(fetch=self.fetch)

    def test_version_cannot_contain_shell_or_path(self):
        for value in ("../1", "1.2.3; id", "v1.2.3", "1.2.3-beta", None):
            with self.assertRaises(core.Blocked):
                u.version(value)

    def test_download_checks_package_and_preserves_accounts(self):
        data = self.download()
        self.assertTrue(data["can_install"])
        self.assertEqual(Path(data["package_path"]).read_bytes(), self.zip)
        self.assertEqual(stat.S_IMODE(Path(data["package_path"]).parent.parent.stat().st_mode), 0o700)
        self.unchanged()

    def test_download_checksum_mismatch_does_not_leave_package(self):
        def fetch(url, *a, **kw):
            value = self.fetch(url, *a, **kw)
            return b"0" * 64 + value[64:] if url.endswith(".sha256") else value
        with self.assertRaises(core.Blocked):
            u.download(self.config, "1.2.3", fetch=fetch)
        self.assertEqual(list((self.root / "updates").iterdir()), [])
        self.unchanged()

    def test_failed_signature_does_not_install(self):
        self.codesign.return_value.returncode = 1
        with self.assertRaises(core.Blocked):
            self.download()
        self.unchanged()

    def test_install_cannot_downgrade(self):
        for target in ("1.2.3", "1.2.2"):
            with self.assertRaises(core.Blocked):
                u.install(self.config, target, current="1.2.3")

    def test_zip_rejects_traversal_outside_files_and_symlinks(self):
        symlink = zipfile.ZipInfo("Surge CC.app/link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for name in ("Surge CC.app/../../escape", "/escape", "other/file", "Surge CC.app/a\\b", symlink):
            with self.subTest(name=str(name)):
                package = self.root / "test.zip"
                package.write_bytes(self.package("1.2.3", [(name, "target")]))
                destination = self.root / ("extract-" + str(len(list(self.root.iterdir()))))
                destination.mkdir()
                with self.assertRaises(core.Blocked):
                    u._extract(package, destination)
        self.assertFalse((self.root / "escape").exists())

    def test_cache_revalidation_detects_modified_zip(self):
        data = self.download()
        Path(data["package_path"]).write_bytes(b"tampered")
        with self.assertRaises(core.Blocked):
            u._cached(self.config, "1.2.3")

    def test_unsafe_cache_symlink_rejected(self):
        (self.root / "updates").symlink_to(self.root / "elsewhere")
        with self.assertRaises(core.Blocked):
            self.download()

    def job(self):
        data = self.download()
        oldzip = self.root / "old.zip"
        oldzip.write_bytes(self.package("1.2.2"))
        app = u._extract(oldzip, self.root)
        job = self.root / "job"
        job.mkdir(mode=0o700)
        workspaces.write_json(job / "job.json", {"schema": 1, "config": str(self.config), "app": str(app),
            "current": "1.2.2", "version": "1.2.3", "package": data["package_path"],
            "package_sha256": data["sha256"], "app_digest": u._tree_digest(app), "gui_pid": None})
        workspaces.write_json(job / "ack.json", {"accepted": True})
        return app, job

    def test_worker_installs_and_retains_previous_app(self):
        app, job = self.job()
        self.assertEqual(u._worker(job / "job.json"), 0)
        result = json.loads((job / "result.json").read_text())
        self.assertEqual(result["state"], "installed")
        self.assertEqual(plistlib.loads((app / "Contents/Info.plist").read_bytes())["CFBundleShortVersionString"], "1.2.3")
        backup = Path(result["backup_path"])
        self.assertEqual(plistlib.loads((backup / "Contents/Info.plist").read_bytes())["CFBundleShortVersionString"], "1.2.2")
        self.unchanged()

    def test_worker_selftest_failure_rolls_back(self):
        app, job = self.job()
        before = u._tree_digest(app)
        def run(args, **kwargs):
            return Mock(returncode=1 if args[-1] == "--help" else 0, stdout="arm64")
        self.codesign.side_effect = run
        self.assertEqual(u._worker(job / "job.json"), 2)
        result = json.loads((job / "result.json").read_text())
        self.assertEqual(result["state"], "rolled-back")
        self.assertEqual(u._tree_digest(app), before)
        self.unchanged()

    def test_worker_refuses_active_workspace(self):
        app, job = self.job()
        before = u._tree_digest(app)
        with workspaces._lock(workspaces.location(self.config, "B"), exclusive=False):
            self.assertEqual(u._worker(job / "job.json"), 2)
        self.assertEqual(u._tree_digest(app), before)
        self.unchanged()

    def test_worker_refuses_files_changed_after_preflight(self):
        app, job = self.job()
        (app / "Contents/MacOS/SurgeCC").write_text("changed-by-user")
        self.assertEqual(u._worker(job / "job.json"), 2)
        self.assertEqual((app / "Contents/MacOS/SurgeCC").read_text(), "changed-by-user")
        self.unchanged()

    def test_worker_waits_for_gui_and_never_replaces_running_app(self):
        app, job = self.job()
        data = json.loads((job / "job.json").read_text())
        data["gui_pid"] = 1234
        workspaces.write_json(job / "job.json", data)
        before = u._tree_digest(app)
        with patch.object(u.os, "kill"), patch.object(u.time, "sleep"):
            self.assertEqual(u._worker(job / "job.json"), 2)
        self.assertEqual(u._tree_digest(app), before)

    def test_worker_without_parent_ack_cannot_install(self):
        app, job = self.job()
        (job / "ack.json").unlink()
        before = u._tree_digest(app)
        with patch.object(u.time, "sleep"):
            self.assertEqual(u._worker(job / "job.json"), 2)
        self.assertEqual(u._tree_digest(app), before)

    def test_worker_honors_cancellation(self):
        app, job = self.job()
        workspaces.write_json(job / "cancel.json", {"cancelled": True})
        before = u._tree_digest(app)
        self.assertEqual(u._worker(job / "job.json"), 2)
        self.assertEqual(u._tree_digest(app), before)

    def test_installer_timeout_cancels_unacknowledged_worker(self):
        app, _ = self.job()
        child = Mock()
        with patch.object(u.time, "sleep"):
            with self.assertRaisesRegex(core.Blocked, "已取消"):
                u.install(self.config, "1.2.3", current="1.2.2", app=app, popen=Mock(return_value=child))
        child.terminate.assert_called_once()
        self.assertEqual(len(list((self.root / "updates").glob("install-*/cancel.json"))), 1)
        self.assertEqual(len(list((self.root / "updates").glob("install-*/ack.json"))), 0)
        self.unchanged()

    def test_running_other_gui_refuses_install(self):
        app, _ = self.job()
        spawn = Mock()
        with patch.object(u, "_app_pids", return_value=[9999]):
            with self.assertRaises(core.Blocked):
                u.install(self.config, "1.2.3", current="1.2.2", app=app, popen=spawn)
        spawn.assert_not_called()

    def test_incompatible_architecture_or_os_refuses(self):
        self.codesign.return_value.stdout = "x86_64"
        with self.assertRaisesRegex(core.Blocked, "处理器"):
            self.download()
        self.codesign.return_value.stdout = "arm64"
        with patch.object(u.platform, "mac_ver", return_value=("12.0", (), "")):
            with self.assertRaisesRegex(core.Blocked, "macOS"):
                self.download()

    def test_failed_network_still_returns_last_result_without_private_paths(self):
        folder = self.root / "updates/install-test"
        folder.mkdir(parents=True, mode=0o700)
        workspaces.write_json(folder / "result.json", {"state": "rolled-back", "backup_path": "/private-path"})
        result = u.check(self.config, fetch=Mock(side_effect=core.Blocked("network")))
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["last_install"]["state"], "rolled-back")
        self.assertNotIn("private-path", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
