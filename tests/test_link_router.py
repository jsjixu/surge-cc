import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch, call

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import link_router as module


class RouterFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.main = self.app("Surge CC", "local.surgecc.main", "SurgeCC")
        resources = self.main / "Contents/Resources"
        (resources / "scripts").mkdir(parents=True)
        for name in ("SurgeCCLinkRouter", "SurgeCCShortcut", "SurgeCCIcon.icns", "scripts/surge-cc"):
            (resources / name).write_text("fixture")
            (resources / name).chmod(0o700)
        self.orca = self.app("Orca", "com.stablyai.orca", "Orca")
        self.chrome = self.app("Google Chrome", "com.google.Chrome", "Google Chrome")
        self.safari = self.app("Safari", "com.apple.Safari", "Safari")
        self.config = self.root / "config.json"
        self.config.write_text("{}")
        self.python = self.root / "python"
        self.python.write_text("fixture")
        self.python.chmod(0o700)
        self.destination = self.root / "Applications"
        self.ident = module._app_identity(self.orca)
        self.old = {"http": module._app_identity(self.chrome), "https": module._app_identity(self.safari)}
        self.data = {"schema": 1, "python": str(self.python), "config": str(self.config),
                     "app": str(self.main), "workspace": "A", "previous": self.old, "sources": [self.ident]}
        self.router_config = self.destination / (module.APP_NAME + ".app") / "Contents/Resources/router.json"

    def app(self, name, identifier, executable):
        app = self.root / (name + ".app")
        binary = app / "Contents/MacOS" / executable
        binary.parent.mkdir(parents=True)
        binary.write_text("fixture")
        binary.chmod(0o700)
        with (app / "Contents/Info.plist").open("wb") as handle:
            plistlib.dump({"CFBundleIdentifier": identifier, "CFBundleExecutable": executable}, handle)
        return app

    def write_config(self):
        self.router_config.parent.mkdir(parents=True, exist_ok=True)
        self.router_config.write_text(json.dumps(self.data))
        self.router_config.chmod(0o600)

    def test_load_requires_private_native_config(self):
        self.write_config()
        self.assertEqual(module.load(self.router_config), self.data)
        self.router_config.chmod(0o666)
        with self.assertRaises(module.core.Blocked):
            module.load(self.router_config)

    def test_load_rejects_router_as_prior_browser(self):
        self.data["previous"]["http"]["bundle_id"] = module.BUNDLE_ID
        self.write_config()
        with self.assertRaises(module.core.Blocked):
            module.load(self.router_config)

    def test_load_rejects_changed_source_bundle(self):
        self.write_config()
        with (self.orca / "Contents/Info.plist").open("wb") as handle:
            plistlib.dump({"CFBundleIdentifier": "example.other", "CFBundleExecutable": "Orca"}, handle)
        with self.assertRaises(module.core.Blocked):
            module.load(self.router_config)

    def test_load_rejects_missing_fallback_app(self):
        self.write_config()
        shutil.rmtree(self.safari)
        with self.assertRaises(OSError):
            module.load(self.router_config)

    def test_install_records_both_schemes_without_setting_defaults(self):
        defaults = {key: {"app": item["app"], "bundle_id": item["bundle_id"]} for key, item in self.old.items()}
        with patch.object(module.core, "load_config", return_value={"workspace": "B"}), \
                patch.object(module, "_native", return_value={"ok": True, "handlers": defaults}) as native, \
                patch.object(module.subprocess, "run") as run, \
                patch.object(module.shortcuts, "_publish", side_effect=lambda stage, dest: os.rename(stage, dest)):
            result = module.install(self.config, self.main, python_path=self.python,
                                    applications_dir=self.destination, orca_app=self.orca)
        self.assertFalse(result["default_changed"])
        self.assertEqual(native.call_args_list, [
            call(self.main / "Contents/Resources/SurgeCCLinkRouter", "--defaults"),
            call(self.router_config.parents[2] / "Contents/MacOS/SurgeCCLinkRouter", "--register", timeout=20)])
        self.assertTrue(result["registered"])
        self.assertEqual(module.load(self.router_config)["previous"], self.old)
        self.assertEqual(module.load(self.router_config)["workspace"], "A")
        with (self.router_config.parents[1] / "Info.plist").open("rb") as handle:
            info = plistlib.load(handle)
        self.assertEqual(info["CFBundleURLTypes"][0]["CFBundleURLSchemes"], ["http", "https"])
        self.assertIn("NSAppleEventsUsageDescription", info)
        self.assertEqual(info["CFBundleDocumentTypes"][0]["LSItemContentTypes"], ["public.html", "public.xhtml"])
        self.assertEqual(info["CFBundleDocumentTypes"][0]["LSHandlerRank"], "Alternate")
        self.assertEqual(run.call_count, 2)

    def test_install_does_not_replace_existing_saved_mapping(self):
        self.write_config()
        original = self.router_config.read_bytes()
        defaults = {key: {"app": item["app"], "bundle_id": item["bundle_id"]} for key, item in self.old.items()}
        with patch.object(module.core, "load_config", return_value={}), \
                patch.object(module, "_native", return_value={"ok": True, "handlers": defaults}):
            with self.assertRaisesRegex(module.core.Blocked, "已存在"):
                module.install(self.config, self.main, python_path=self.python,
                               applications_dir=self.destination, orca_app=self.orca)
        self.assertEqual(self.router_config.read_bytes(), original)


class KernelIdentityTests(unittest.TestCase):
    def identity(self, *, executable="/usr/bin/login", uid=0, ruid=501, changed=None):
        first = {"pid": 301, "ppid": 200, "uid": uid, "ruid": ruid, "start_sec": 10, "start_usec": 2}
        snapshots = iter([first, dict(first, **(changed or {}))])
        library = Mock()
        def info(pid, flavor, arg, pointer, size):
            record = module.ctypes.cast(pointer, module.ctypes.POINTER(module.browser_locks._BSDInfo)).contents
            for key, value in next(snapshots).items():
                setattr(record, key, value)
            return size
        def path(pid, buffer, capacity):
            buffer.value = os.fsencode(executable)
            return len(buffer.value)
        library.proc_pidinfo.side_effect = info
        library.proc_pidpath.side_effect = path
        with patch.object(module.sys, "platform", "darwin"), patch.object(module.os, "getuid", return_value=501), \
                patch.object(module.ctypes, "CDLL", return_value=library):
            return module._identity(301)

    def test_exact_system_login_with_current_real_user_is_traceable(self):
        self.assertEqual(self.identity(), {"pid": 301, "parent": 200, "started": [10, 2],
                                         "executable": "/usr/bin/login"})

    def test_ordinary_current_user_process_remains_traceable(self):
        self.assertEqual(self.identity(executable="/bin/zsh", uid=501)["executable"], "/bin/zsh")

    def test_other_root_programs_and_same_named_copies_are_rejected(self):
        for executable in ("/usr/bin/sudo", "/tmp/login", "/tmp/usr/bin/login", "/bin/zsh"):
            with self.subTest(executable=executable):
                self.assertIsNone(self.identity(executable=executable))

    def test_login_from_other_real_user_is_rejected(self):
        for ruid in (0, 502):
            with self.subTest(ruid=ruid):
                self.assertIsNone(self.identity(ruid=ruid))

    def test_login_effective_user_must_be_root_or_current_user(self):
        self.assertIsNone(self.identity(uid=502))

    def test_process_change_during_capture_is_rejected(self):
        for changed in ({"pid": 302}, {"ppid": 1}, {"uid": 501}, {"ruid": 502},
                        {"start_sec": 11}, {"start_usec": 3}):
            with self.subTest(changed=changed):
                self.assertIsNone(self.identity(changed=changed))


class LoginBridgeFallbackTests(unittest.TestCase):
    def identity(self, *, path="/usr/bin/login", uid=0, ruid=501, changed=None,
                 starts=None, short_read=False, final_path=None):
        first = {"pid": 301, "ppid": 200, "uid": uid, "ruid": ruid}
        snapshots = iter([first, dict(first, **(changed or {}))])
        paths = iter([path, final_path or path])
        library = Mock()
        def info(pid, flavor, arg, pointer, size):
            if flavor == 3:
                return 0  # Actual root login denies PROC_PIDTBSDINFO.
            self.assertEqual(flavor, 13)
            if short_read:
                return 0
            record = module.ctypes.cast(pointer, module.ctypes.POINTER(module._BSDShortInfo)).contents
            for key, value in next(snapshots).items():
                setattr(record, key, value)
            return size
        def executable(pid, buffer, capacity):
            buffer.value = os.fsencode(next(paths))
            return len(buffer.value)
        library.proc_pidinfo.side_effect = info
        library.proc_pidpath.side_effect = executable
        with patch.object(module.sys, "platform", "darwin"), patch.object(module.os, "getuid", return_value=501), \
                patch.object(module.ctypes, "CDLL", return_value=library), \
                patch.object(module, "_kernel_started", side_effect=starts or [[10, 2], [10, 2]]):
            return module._identity(301)

    def test_bsdinfo_denied_system_login_uses_stable_kernel_fallback(self):
        self.assertEqual(self.identity(), {"pid": 301, "parent": 200, "started": [10, 2],
                                         "executable": "/usr/bin/login"})

    def test_fallback_is_exact_root_login_for_current_real_user(self):
        for values in ({"path": "/usr/bin/sudo"}, {"path": "/tmp/login"}, {"ruid": 502},
                       {"ruid": 0}, {"uid": 501}, {"short_read": True}):
            with self.subTest(values=values):
                self.assertIsNone(self.identity(**values))

    def test_snapshot_and_executable_changes_are_rejected(self):
        for values in ({"changed": {"pid": 302}}, {"changed": {"ppid": 1}},
                       {"changed": {"uid": 501}}, {"changed": {"ruid": 502}},
                       {"starts": [[10, 2], [11, 0]]}, {"starts": [None]},
                       {"starts": [[10, 2], None]}, {"final_path": "/usr/bin/sudo"}):
            with self.subTest(values=values):
                self.assertIsNone(self.identity(**values))

    def test_kernel_start_reader_validates_pid_time_and_buffer_length(self):
        for pid, sec, usec, size, rc, expected in (
                (301, 10, 2, 648, 0, [10, 2]), (302, 10, 2, 648, 0, None),
                (301, 0, 2, 648, 0, None), (301, 10, -1, 648, 0, None),
                (301, 10, 1_000_000, 648, 0, None), (301, 10, 2, 0, 0, None),
                (301, 10, 2, 648, -1, None)):
            library = Mock()
            def read(mib, count, buffer, length, new, newlen):
                self.assertEqual(list(mib), [1, 14, 1, 301])
                value = module._KernProcPrefix.from_buffer(buffer)
                value.pid, value.started.sec, value.started.usec = pid, sec, usec
                module.ctypes.cast(length, module.ctypes.POINTER(module.ctypes.c_size_t)).contents.value = size
                return rc
            library.sysctl.side_effect = read
            with self.subTest(pid=pid, sec=sec, usec=usec, size=size, rc=rc), \
                    patch.object(module.ctypes, "CDLL", return_value=library):
                self.assertEqual(module._kernel_started(301), expected)


class SourceRoutingTests(unittest.TestCase):
    def setUp(self):
        self.orca = {"pid": 100, "parent": 1, "started": [10, 2], "executable": "/Applications/Orca.app/Contents/MacOS/Orca"}
        self.open = {"pid": 101, "parent": 100, "started": [20, 3], "executable": "/usr/bin/open"}
        self.data = {"sources": [{"executable": self.orca["executable"]}], "config": "/support/config.json"}
        patcher = patch.object(module, "_controlled_claude", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def matches(self, chain, identities):
        with patch.object(module, "_identity", side_effect=lambda pid: identities.get(pid)):
            return module._source_matches(self.data, {"source": {"chain": chain}})

    def test_direct_orca_exact_kernel_identity(self):
        self.assertTrue(self.matches([self.orca], {100: self.orca}))

    def test_short_lived_open_keeps_captured_live_orca_origin(self):
        self.assertTrue(self.matches([self.open, self.orca], {100: self.orca}))

    def test_open_still_alive_orca_parent(self):
        self.assertTrue(self.matches([self.open, self.orca], {100: self.orca, 101: self.open}))

    def test_pid_reuse_never_routes_to_lia(self):
        changed = dict(self.open, started=[25, 0])
        with self.assertRaises(module.core.Blocked):
            self.matches([self.open, self.orca], {100: self.orca, 101: changed})

    def test_parent_chain_must_be_contiguous(self):
        unrelated = dict(self.open, parent=200)
        with self.assertRaises(module.core.Blocked):
            self.matches([unrelated, self.orca], {100: self.orca, 101: unrelated})

    def test_unrelated_browser_does_not_match_by_name(self):
        browser = dict(self.orca, executable="/tmp/Orca")
        self.assertFalse(self.matches([browser], {100: browser}))

    def test_expired_protected_source_never_uses_personal_browser(self):
        with self.assertRaises(module.core.Blocked):
            self.matches([self.open, self.orca], {})

    def test_null_unknown_or_malformed_source_is_not_attributed(self):
        for source in (None, {}, {"chain": []}, {"chain": [self.orca] * 17}):
            with self.subTest(source=source):
                self.assertFalse(module._source_matches(self.data, {"source": source}))

    def test_malformed_protected_trace_is_blocked(self):
        with self.assertRaises(module.core.Blocked):
            module._source_matches(self.data, {"source": {"chain": [dict(self.orca, pid=True)]}})

    def test_controlled_claude_can_be_recognized_outside_orca(self):
        claude = dict(self.open, executable="/private/claude")
        with patch.object(module, "_controlled_claude", return_value=True):
            self.assertTrue(self.matches([claude], {101: claude}))

    def test_login_is_only_a_bridge_and_never_a_protected_source(self):
        login = dict(self.open, executable="/usr/bin/login", parent=1)
        with patch.object(module, "_controlled_claude", return_value=True):
            self.assertFalse(self.matches([login], {101: login}))

    def test_unrelated_terminal_login_chains_keep_original_browser(self):
        for executable in ("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                           "/Applications/Ghostty.app/Contents/MacOS/ghostty",
                           "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"):
            terminal = dict(self.orca, executable=executable)
            login = dict(self.open, executable="/usr/bin/login")
            with self.subTest(executable=executable):
                self.assertFalse(self.matches([login, terminal], {101: login, 100: terminal}))


class OpenRequestTests(RouterFixture):
    def test_unattributed_open_returns_explicit_original_app(self):
        self.write_config()
        result = module.open_request(self.router_config, {"url": "https://example.com/private?token=SECRET", "source": None})
        self.assertEqual(result["action"], "fallback")
        self.assertEqual(result["app"], str(self.safari))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_orca_open_is_fixed_a_and_forward_confirmation(self):
        self.write_config()
        expected = {"schema": 1, "action": "focus", "message": "opened"}
        with patch.object(module, "_source_matches", return_value=True), \
                patch.object(module.shortcuts, "open_url", return_value=expected) as opening:
            result = module.open_request(self.router_config, {"url": "https://example.com/", "source": None}, confirmed_from="B")
        self.assertEqual(result, expected)
        opening.assert_called_once_with(self.config, "A", "https://example.com/",
                                        self.main / "Contents/Resources/SurgeCCShortcut", confirmed_from="B")

    def test_protected_failure_never_falls_back_personal_browser(self):
        self.write_config()
        with patch.object(module, "_source_matches", return_value=True), \
                patch.object(module.shortcuts, "open_url", side_effect=module.core.Blocked("route blocked")):
            with self.assertRaisesRegex(module.core.Blocked, "route blocked"):
                module.open_request(self.router_config, {"url": "https://example.com/", "source": None})

    def test_invalid_url_rejected_even_for_personal_browser(self):
        self.write_config()
        for url in ("file:///private/data", "https://user:secret@example.com/", "https://example.com/%0a"):
            with self.subTest(url=url), self.assertRaises(module.core.Blocked):
                module.open_request(self.router_config, {"url": url, "source": None})

    def test_unexpected_request_fields_rejected(self):
        self.write_config()
        with self.assertRaises(module.core.Blocked):
            module.open_request(self.router_config, {"url": "https://example.com/", "source": None, "app": "evil"})


class TerminalHostRoutingTests(RouterFixture):
    def setUp(self):
        super().setUp()
        self.packaged = self.orca / "Contents/Helpers/Orca Terminal Host.app"
        self.runtime = (self.root / "Library/Application Support/orca/daemon-host/macos"
                        / ("terminal-host-" + "a" * 40) / "app.noindex/Orca Terminal Host.app")
        for app in (self.packaged, self.runtime):
            binary = app / "Contents/MacOS/orca-terminal-host"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"official current host fixture")
            binary.chmod(0o700)
            (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.stablyai.orca", "CFBundleExecutable": "orca-terminal-host"}))
        self.host = {"pid": 200, "parent": 1, "started": [30, 4],
                     "executable": str(self.runtime / "Contents/MacOS/orca-terminal-host")}
        self.opener = {"pid": 201, "parent": 200, "started": [40, 5], "executable": "/usr/bin/open"}
        patcher = patch.object(module.Path, "home", return_value=self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def matches(self, chain=None, identities=None):
        chain = chain if chain is not None else [self.opener, self.host]
        identities = identities if identities is not None else {200: self.host}
        with patch.object(module, "_identity", side_effect=lambda pid: identities.get(pid)), \
                patch.object(module, "_controlled_claude", return_value=False):
            return module._source_matches(self.data, {"source": {"chain": chain}})

    def test_detached_official_host_matches_after_short_lived_open_exits(self):
        self.assertTrue(self.matches())

    def test_detached_host_is_reachable_through_system_login(self):
        login = {"pid": 202, "parent": 200, "started": [35, 4], "executable": "/usr/bin/login"}
        shell = {"pid": 203, "parent": 202, "started": [36, 4], "executable": "/bin/zsh"}
        opener = dict(self.opener, parent=203)
        self.assertTrue(self.matches(chain=[opener, shell, login, self.host],
                                     identities={203: shell, 202: login, 200: self.host}))

    def test_login_pid_reuse_or_parent_change_blocks_protected_origin(self):
        login = {"pid": 202, "parent": 200, "started": [35, 4], "executable": "/usr/bin/login"}
        opener = dict(self.opener, parent=202)
        for changed in (dict(login, started=[36, 4]), dict(login, parent=1)):
            with self.subTest(changed=changed), self.assertRaises(module.core.Blocked):
                self.matches(chain=[opener, login, self.host], identities={202: changed, 200: self.host})

    def test_expired_host_is_blocked_without_personal_fallback(self):
        with self.assertRaises(module.core.Blocked):
            self.matches(identities={})

    def test_host_pid_reuse_is_blocked(self):
        with self.assertRaises(module.core.Blocked):
            self.matches(identities={200: dict(self.host, started=[31, 4])})

    def test_different_runtime_binary_is_blocked(self):
        Path(self.host["executable"]).write_bytes(b"different host")
        with self.assertRaises(module.core.Blocked):
            self.matches()

    def test_changed_packaged_reference_is_blocked(self):
        (self.packaged / "Contents/MacOS/orca-terminal-host").write_bytes(b"new official version")
        with self.assertRaises(module.core.Blocked):
            self.matches()

    def test_group_writable_host_is_blocked(self):
        Path(self.host["executable"]).chmod(0o770)
        with self.assertRaises(module.core.Blocked):
            self.matches()

    def test_symlink_to_official_host_is_blocked(self):
        binary = Path(self.host["executable"])
        binary.unlink()
        binary.symlink_to(self.packaged / "Contents/MacOS/orca-terminal-host")
        with self.assertRaises(module.core.Blocked):
            self.matches()

    def test_unrelated_same_named_copy_is_not_accepted(self):
        unrelated = dict(self.host, executable=str(self.root / "Orca Terminal Host.app/Contents/MacOS/orca-terminal-host"))
        self.assertFalse(self.matches(chain=[unrelated], identities={200: unrelated}))

    def test_foreign_owner_is_blocked(self):
        original = module.Path.lstat
        binary = Path(self.host["executable"])
        def foreign(path):
            info = original(path)
            if path == binary:
                values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                values["st_uid"] = os.getuid() + 1
                return SimpleNamespace(**values)
            return info
        with patch.object(module.Path, "lstat", foreign), self.assertRaises(module.core.Blocked):
            self.matches()


class NativeContractTests(unittest.TestCase):
    def test_login_bridge_is_scoped_to_source_ancestry_and_checks_real_user(self):
        source = (Path(__file__).parents[1] / "app/link-router.swift").read_text()
        identity = source.split("private func sourceIdentity", 1)[1].split("private func captureSource", 1)[0]
        self.assertIn("allowLoginBridge: Bool = false", identity)
        self.assertIn("before.pbi_ruid == getuid()", identity)
        self.assertIn("before.pbi_ruid == after.pbi_ruid", identity)
        self.assertIn('allowLoginBridge && before.pbi_uid == 0 && executable == "/usr/bin/login"', identity)
        self.assertEqual(source.count("allowLoginBridge: true"), 1)
        self.assertIn("sourceIdentity(current, allowLoginBridge: true)", source)

    def test_native_receives_readonly_sender_attribute_and_no_url_argv(self):
        source = (Path(__file__).parents[1] / "app/link-router.swift").read_text()
        self.assertIn("attributeDescriptor(forKeyword: AEKeyword(keySenderPIDAttr))", source)
        self.assertIn("captureSource(pid)", source)
        self.assertIn("JSONEncoder().encode(request)", source)
        self.assertNotIn('child.arguments! += [request.url]', source)
        self.assertIn('identifier != routerIdentifier', source)
        self.assertIn('queue.count < 32', source)

    def test_personal_browser_delivery_uses_verified_process_not_bundle_forwarding(self):
        source = (Path(__file__).parents[1] / "app/link-router.swift").read_text()
        fallback = source.split("private final class PersonalBrowserDelivery", 1)[1].split("private final class RouterDelegate", 1)[0]
        self.assertIn("application.bundleURL?.path == saved.app", fallback)
        self.assertIn("application.executableURL?.path == saved.executable", fallback)
        self.assertIn("application.bundleIdentifier == saved.bundle_id", fallback)
        self.assertIn("candidates.count <= 1", fallback)
        self.assertIn("options.createsNewApplicationInstance = true", fallback)
        self.assertIn("NSWorkspace.shared.openApplication(at:", fallback)
        self.assertNotIn("NSWorkspace.shared.open([", source)
        self.assertNotIn("options.arguments", fallback)
        self.assertIn("current.started == identity.started", fallback)
        self.assertIn('child.arguments = ["--open-url-stdin"]', fallback)
        self.assertIn("JSONEncoder().encode(payload)", fallback)

    def test_default_mutation_uses_app_event_loop_and_bounded_watchdog(self):
        source = (Path(__file__).parents[1] / "app/link-router.swift").read_text()
        self.assertIn("DispatchQueue.main.async { operation.start() }", source)
        self.assertIn("application.run()", source)
        self.assertIn("deadline: .now() + 90", source)
        self.assertNotIn("while !complete", source)
        self.assertIn("LSRegisterURL(Bundle.main.bundleURL as CFURL, true)", source)
        self.assertIn('let requiredSchemes = restore ? changed : ["http", "https"]', source)
        self.assertIn("requiredSchemes.allSatisfy", source)



class NativeResultTests(unittest.TestCase):
    def test_error_message_preserved_without_claiming_unchanged_defaults(self):
        result = SimpleNamespace(returncode=1, stdout=json.dumps({"ok": False, "message": "用户尚未确认，请在系统设置中检查。"}))
        with patch.object(module.subprocess, "run", return_value=result), self.assertRaisesRegex(module.core.Blocked, "用户尚未确认"):
            module._native(Path("/router"), "--set-default")

    def test_timeout_reports_unknown_state(self):
        with patch.object(module.subprocess, "run", side_effect=module.subprocess.TimeoutExpired("router", 120)):
            with self.assertRaisesRegex(module.core.Blocked, "当前默认状态尚未确认"):
                module._native(Path("/router"), "--set-default", timeout=120)

    def test_setter_timeout_exceeds_native_watchdog(self):
        path = Path("/apps/Surge CC Links.app/Contents/Resources/router.json")
        with patch.object(module, "load"), patch.object(module, "_native", return_value={"ok": True}) as native:
            module.set_default(path)
        self.assertEqual(native.call_args.kwargs["timeout"], 120)


class ControlledClaudeTests(unittest.TestCase):
    def setUp(self):
        self.data = {"config": "/support/config.json"}
        self.process = {"executable": "/native/claude", "parent": 123}
        self.manifest = {"original_path": "/native/claude", "config_path": "/support/config.json",
                         "python_executable": "/runtime/python", "entrypoint": "/app/scripts/surge-cc"}
        self.parent = SimpleNamespace(uid=os.getuid(), executable="/runtime/python", argv=(
            "/runtime/python", "/app/scripts/surge-cc", "--config", "/support/config.json", "launch", "code",
            "--passthrough", "--"))

    def check(self):
        from surge_cc import terminal
        with patch.object(terminal, "_read", return_value=self.manifest), \
                patch.object(terminal, "_verify_active"), \
                patch.object(module.browser_locks, "_process_snapshot", return_value=self.parent):
            return module._controlled_claude(self.data, self.process)

    def test_exact_controlled_native_and_parent_are_accepted(self):
        self.assertTrue(self.check())

    def test_arbitrary_native_claude_in_terminal_is_not_attributed(self):
        self.parent.executable = "/bin/zsh"
        self.assertFalse(self.check())

    def test_unrelated_backend_command_is_not_a_session(self):
        self.parent.argv = self.parent.argv[:4] + ("check",)
        self.assertFalse(self.check())

    def test_old_native_or_different_config_not_attributed(self):
        self.process["executable"] = "/native/old-claude"
        self.assertFalse(self.check())
        self.process["executable"] = "/native/claude"
        self.manifest["config_path"] = "/different/config.json"
        self.assertFalse(self.check())


if __name__ == "__main__":
    unittest.main()
