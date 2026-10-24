"""Opt-in macOS HTTP(S) dispatch, preserving the previous browser per scheme.

Only the native Apple Event receiver supplies source process identities. URLs
travel through stdin, are never written to the configuration, and are not
included in results. Unattributed opens use the saved browser explicitly.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from . import browser_locks, core, shortcuts, workspaces


APP_NAME = "Surge CC Links"
BUNDLE_ID = "local.surgecc.link-router"
_FIELDS = {"schema", "python", "config", "app", "workspace", "previous", "sources"}


def _app_identity(path: Path) -> dict:
    path = shortcuts.absolute_path(path)
    shortcuts.no_links(path)
    if path.suffix != ".app":
        raise core.Blocked("链接入口的应用位置无效。")
    with (path / "Contents/Info.plist").open("rb") as handle:
        value = plistlib.load(handle)
    identifier, executable = value.get("CFBundleIdentifier"), value.get("CFBundleExecutable")
    if (not isinstance(identifier, str) or not identifier or len(identifier) > 255
            or any(ord(c) < 33 for c in identifier)
            or not isinstance(executable, str) or not executable
            or "/" in executable or executable in (".", "..")):
        raise core.Blocked("无法确认链接入口的应用身份。")
    binary = path / "Contents/MacOS" / executable
    shortcuts.no_links(binary)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise core.Blocked("链接入口的应用程序无法执行。")
    return {"app": str(path), "bundle_id": identifier, "executable": str(binary)}


def load(path: Path) -> dict:
    path = shortcuts.absolute_path(path)
    data = shortcuts.private_json(path, 32768)
    if (not isinstance(data, dict) or set(data) != _FIELDS
            or type(data.get("schema")) is not int or data["schema"] != 1
            or path.parts[-3:] != ("Contents", "Resources", "router.json")
            or path.parents[2].name != APP_NAME + ".app"):
        raise core.Blocked("链接分流器配置无效，请重新安装。")
    for key in ("python", "config", "app"):
        shortcuts.absolute_path(data[key])
        shortcuts.no_links(Path(data[key]))
    workspaces.name_ok(data["workspace"])
    if (not isinstance(data["previous"], dict)
            or set(data["previous"]) != {"http", "https"}
            or not isinstance(data["sources"], list) or not 1 <= len(data["sources"]) <= 4):
        raise core.Blocked("链接分流器的来源或原浏览器记录无效。")
    for saved in list(data["previous"].values()) + data["sources"]:
        if not isinstance(saved, dict) or set(saved) != {"app", "bundle_id", "executable"}:
            raise core.Blocked("链接分流器的应用记录无效。")
        if saved["bundle_id"] == BUNDLE_ID:
            raise core.Blocked("原浏览器不能是链接分流器自身。")
        actual = _app_identity(Path(saved["app"]))
        if actual != saved:
            raise core.Blocked("浏览器或来源应用身份发生变化，请检查链接分流器。")
    if any(source["bundle_id"] != "com.stablyai.orca" for source in data["sources"]):
        # The executable is recorded at installation and revalidated above;
        # this field is intentionally not an arbitrary source-app allowlist.
        raise core.Blocked("链接分流器来源必须是已安装的 Orca。")
    return data


def _native(binary: Path, *arguments, payload=None, timeout=45) -> dict:
    try:
        result = subprocess.run([str(binary), *arguments],
                                input=json.dumps(payload) if payload is not None else None,
                                stdin=subprocess.DEVNULL if payload is None else None,
                                text=True, capture_output=True, timeout=timeout, check=False)
        data = json.loads(result.stdout)
        if isinstance(data, dict) and data.get("ok") is False:
            message = data.get("message")
            if isinstance(message, str) and 0 < len(message) <= 1024:
                raise core.Blocked(message)
        if not isinstance(data, dict) or data.get("ok") is not True or result.returncode != 0:
            raise ValueError()
        return data
    except (OSError, ValueError, subprocess.SubprocessError):
        raise core.Blocked("系统链接入口操作未完成；当前默认状态尚未确认，请在系统设置中检查。") from None


def install(config_path: Path, app_path: Path, *, python_path: Path | None = None,
            applications_dir: Path | None = None, orca_app: Path | None = None) -> dict:
    """Install an HTTP(S) candidate. Setting it as default is a separate action."""
    config_path = shortcuts.absolute_path(config_path)
    app_path = shortcuts.absolute_path(app_path)
    python_path = shortcuts.absolute_path(python_path or Path(sys.executable).resolve())
    applications_dir = shortcuts.absolute_path(applications_dir or Path.home() / "Applications")
    for path in (config_path, app_path, python_path, applications_dir):
        shortcuts.no_links(path)
    config = core.load_config(config_path)
    # This personal entry is deliberately anchored to workspace A. Switching
    # away from a current B still requires the normal explicit confirmation.
    workspaces.name_ok("A")
    source = _app_identity(orca_app or Path("/Applications/Orca.app"))
    if source["bundle_id"] != "com.stablyai.orca":
        raise core.Blocked("没有找到可验证的 Orca 应用。")
    resources = app_path / "Contents/Resources"
    template = resources / "SurgeCCLinkRouter"
    for path in (template, resources / "SurgeCCShortcut", resources / "SurgeCCIcon.icns",
                 resources / "scripts/surge-cc"):
        shortcuts.no_links(path)
        if not path.is_file():
            raise core.Blocked("主应用缺少链接分流器组件，请先安装完整新版。")
    defaults = _native(template, "--defaults").get("handlers", {})
    if set(defaults) != {"http", "https"}:
        raise core.Blocked("无法读取原默认浏览器，未安装链接分流器。")
    previous = {}
    for scheme, saved in defaults.items():
        actual = _app_identity(Path(saved["app"]))
        if actual["bundle_id"] != saved.get("bundle_id") or actual["bundle_id"] == BUNDLE_ID:
            raise core.Blocked("原默认浏览器无效或已经是分流器，未覆盖其恢复记录。")
        previous[scheme] = actual
    applications_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = applications_dir.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise core.Blocked("应用目录所有者或权限异常。")
    destination = applications_dir / (APP_NAME + ".app")
    if os.path.lexists(destination):
        raise core.Blocked("链接分流器已存在，未覆盖已保存的原浏览器记录。")
    stage_root = Path(tempfile.mkdtemp(prefix=".surge-cc-links-", dir=applications_dir))
    try:
        stage = stage_root / destination.name
        binary = stage / "Contents/MacOS/SurgeCCLinkRouter"
        binary.parent.mkdir(parents=True, mode=0o700)
        output = stage / "Contents/Resources"
        output.mkdir(mode=0o700)
        shutil.copyfile(template, binary)
        binary.chmod(0o755)
        shutil.copyfile(resources / "SurgeCCIcon.icns", output / "SurgeCCIcon.icns")
        workspaces.write_json(output / "router.json", {
            "schema": 1, "python": str(python_path), "config": str(config_path),
            "app": str(app_path), "workspace": "A", "previous": previous, "sources": [source]})
        with (stage / "Contents/Info.plist").open("wb") as handle:
            plistlib.dump({"CFBundleExecutable": "SurgeCCLinkRouter", "CFBundleIdentifier": BUNDLE_ID,
                          "CFBundleName": APP_NAME, "CFBundleDisplayName": APP_NAME,
                          "CFBundlePackageType": "APPL", "CFBundleIconFile": "SurgeCCIcon",
                          "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1",
                          "LSMinimumSystemVersion": "13.0", "LSUIElement": True,
                          "NSAppleEventsUsageDescription": "Open requested webpages in the verified Surge CC browser window.",
                          "NSPrincipalClass": "NSApplication", "NSHighResolutionCapable": True,
                          "CFBundleDocumentTypes": [{"CFBundleTypeName": "HTML document",
                                                     "CFBundleTypeRole": "Viewer",
                                                     "LSHandlerRank": "Alternate",
                                                     "LSItemContentTypes": ["public.html", "public.xhtml"]}],
                          "CFBundleURLTypes": [{"CFBundleURLName": "Web links",
                                                "CFBundleTypeRole": "Viewer",
                                                "CFBundleURLSchemes": ["http", "https"]}]}, handle)
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(stage)],
                       stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(stage)],
                       stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
        shortcuts._publish(stage, destination)
    finally:
        shutil.rmtree(stage_root)
    _native(destination / "Contents/MacOS/SurgeCCLinkRouter", "--register", timeout=20)
    return {"ok": True, "app": str(destination), "configuration": str(destination / "Contents/Resources/router.json"),
            "default_changed": False, "registered": True,
            "detail": "链接分流器已安装并登记为网页入口候选，原默认浏览器已保存。"}


class _BSDShortInfo(ctypes.Structure):
    # Public Darwin sys/proc_info.h: struct proc_bsdshortinfo.
    _fields_ = [(name, ctypes.c_uint32) for name in ("pid", "ppid", "pgid", "status")] + [
        ("comm", ctypes.c_char * 16)] + [(name, ctypes.c_uint32) for name in (
            "flags", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved")]


class _TimeValue(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("usec", ctypes.c_int32)]


class _KernProcPrefix(ctypes.Structure):
    # Public Darwin sys/proc.h: kinfo_proc starts with extern_proc; its first
    # union is two pointers / timeval, followed by the fields through p_pid.
    # This LP64 prefix avoids interpreting opaque kernel fields later in the
    # record. Runtime size gates reject unsupported ABIs.
    _fields_ = [("started", _TimeValue), ("vmspace", ctypes.c_void_p),
                ("sigacts", ctypes.c_void_p), ("flags", ctypes.c_int),
                ("status", ctypes.c_char), ("pid", ctypes.c_int)]


def _kernel_started(pid: int):
    if (ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(_TimeValue) != 16 or _KernProcPrefix.pid.offset != 40):
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    mib = (ctypes.c_int * 4)(1, 14, 1, pid)  # CTL_KERN, KERN_PROC, KERN_PROC_PID.
    size = ctypes.c_size_t(4096)
    buffer = ctypes.create_string_buffer(size.value)
    if (libc.sysctl(mib, 4, buffer, ctypes.byref(size), None, 0) != 0
            or not ctypes.sizeof(_KernProcPrefix) <= size.value <= len(buffer)):
        return None
    value = _KernProcPrefix.from_buffer_copy(buffer)
    if value.pid != pid or value.started.sec <= 0 or not 0 <= value.started.usec < 1_000_000:
        return None
    return [value.started.sec, value.started.usec]


def _login_bridge_identity(pid: int, lib):
    """Only the real user's root-effective system login can bridge ancestry."""
    def snapshot():
        value = _BSDShortInfo()
        if (lib.proc_pidinfo(pid, 13, 0, ctypes.byref(value), ctypes.sizeof(value)) != ctypes.sizeof(value)
                or value.pid != pid or value.uid != 0 or value.ruid != os.getuid()):
            return None
        started = _kernel_started(pid)
        return (value.pid, value.ppid, value.uid, value.ruid, started) if started is not None else None

    before = snapshot()
    if before is None:
        return None
    executable = ctypes.create_string_buffer(4096)
    if lib.proc_pidpath(pid, executable, len(executable)) <= 0 or executable.value != b"/usr/bin/login":
        return None
    if snapshot() != before:
        return None
    if lib.proc_pidpath(pid, executable, len(executable)) <= 0 or executable.value != b"/usr/bin/login":
        return None
    return {"pid": pid, "started": before[4], "executable": "/usr/bin/login", "parent": before[1]}


def _identity(pid: int):
    """Kernel identity including parent; no command arguments or environment."""
    if sys.platform != "darwin" or type(pid) is not int or not 2 <= pid < 2**31:
        return None
    lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    before, after = browser_locks._BSDInfo(), browser_locks._BSDInfo()
    size = ctypes.sizeof(before)
    lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(before), size) != size:
        return _login_bridge_identity(pid, lib)
    executable = ctypes.create_string_buffer(4096)
    if lib.proc_pidpath(pid, executable, len(executable)) <= 0:
        return None
    if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(after), size) != size:
        return None
    path = os.fsdecode(executable.value)
    # A detached Orca terminal uses the system login binary with effective
    # root and our real UID. Allow only this exact kernel path as a bridge;
    # it never grants protected-source status by itself.
    if (before.pid != pid or before.ruid != os.getuid()
            or not (before.uid == os.getuid() or (before.uid == 0 and path == "/usr/bin/login"))
            or (before.pid, before.ppid, before.uid, before.ruid, before.start_sec, before.start_usec)
            != (after.pid, after.ppid, after.uid, after.ruid, after.start_sec, after.start_usec)):
        return None
    return {"pid": pid, "started": [before.start_sec, before.start_usec],
            "executable": path, "parent": before.ppid}


def _terminal_host_paths(data: dict, executable: str):
    """Recognize only Orca's specific detached-host cache layout, not its name."""
    try:
        path = shortcuts.absolute_path(executable)
        base = Path.home() / "Library/Application Support/orca/daemon-host/macos"
        relative = path.relative_to(base).parts
        if (len(relative) != 6
                or re.fullmatch(r"terminal-host-(?:[0-9a-f]{40}|[0-9a-f]{64})", relative[0]) is None
                or relative[1:] != ("app.noindex", "Orca Terminal Host.app", "Contents", "MacOS", "orca-terminal-host")):
            return None
        for source in data["sources"]:
            if source.get("bundle_id") != "com.stablyai.orca" or "app" not in source:
                continue
            main = shortcuts.absolute_path(source["app"])
            packaged = main / "Contents/Helpers/Orca Terminal Host.app"
            return path.parents[2], packaged, base, main
    except (ValueError, TypeError, KeyError, core.Blocked):
        return None
    return None


def _host_bundle_safe(app: Path, boundary: Path, owners: set[int]) -> dict:
    shortcuts.no_links(app)
    shortcuts.no_links(app / "Contents/Info.plist")
    identity = _app_identity(app)
    if (identity["bundle_id"] != "com.stablyai.orca"
            or Path(identity["executable"]).name != "orca-terminal-host"):
        raise ValueError("unexpected host bundle")
    # Check every mutable directory from the known boundary, as well as both
    # files consulted. No symlinks, shared-writable copies or foreign owners.
    for leaf in (Path(identity["executable"]), app / "Contents/Info.plist"):
        shortcuts.no_links(leaf)
        current = leaf
        while True:
            info = current.lstat()
            if info.st_uid not in owners or info.st_mode & 0o022:
                raise ValueError("unsafe host ownership")
            if current == leaf:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("unsafe host file")
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError("unsafe host directory")
            if current == boundary:
                break
            current = current.parent
            if current == current.parent:
                raise ValueError("host outside boundary")
    return identity


def _stable_binary_digest(path: Path, owners: set[int]) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in owners
                or before.st_mode & 0o022 or before.st_nlink != 1
                or not 0 < before.st_size <= 512 * 1024 * 1024):
            raise ValueError("unsafe host binary")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > before.st_size:
                raise ValueError("host grew during verification")
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(value, field) for value in (after, current) for field in fields):
            raise ValueError("host changed during verification")
        return digest.digest()
    finally:
        os.close(descriptor)


def _controlled_terminal_host(data: dict, process: dict) -> bool:
    paths = _terminal_host_paths(data, process["executable"])
    if paths is None:
        return False
    runtime, packaged, cache, main = paths
    try:
        # The current registered Orca bundle is the reference. Old or changed
        # cache copies are not silently trusted just because their name fits.
        active = _host_bundle_safe(runtime, cache, {os.getuid()})
        reference = _host_bundle_safe(packaged, main, {0, os.getuid()})
        if _stable_binary_digest(Path(active["executable"]), {os.getuid()}) != _stable_binary_digest(
                Path(reference["executable"]), {0, os.getuid()}):
            return False
        return _identity(process["pid"]) == process
    except (OSError, ValueError, TypeError, KeyError, core.Blocked):
        return False


def _source_matches(data: dict, request: dict) -> bool:
    """No guessed app name, active window or fallback domain-based attribution."""
    source = request.get("source")
    if not isinstance(source, dict) or set(source) != {"chain"}:
        return False
    chain = source["chain"]
    if not isinstance(chain, list) or not 1 <= len(chain) <= 16:
        return False
    allowed = {item["executable"] for item in data["sources"]}
    protected_paths = set(allowed)
    try:
        from . import terminal
        manifest = terminal._read_registration(Path(data["config"]).parent / "terminal")
        if manifest["config_path"] == data["config"]:
            protected_paths.add(manifest["original_path"])
    except (OSError, ValueError, TypeError, KeyError, core.Blocked):
        pass
    protected_origin = any(isinstance(item, dict) and isinstance(item.get("executable"), str)
                           and (item["executable"] in protected_paths
                                or _terminal_host_paths(data, item["executable"]) is not None) for item in chain)

    def unverified():
        if protected_origin:
            raise core.Blocked("打开链接的 Orca／Claude 会话无法重新验证，请从原会话重试；未改用个人浏览器。")
        return False

    seen = set()
    previous = None
    # The native event receiver captures this chain synchronously, while a
    # short-lived /usr/bin/open sender is still present. This private stdin
    # interface is not an OS authorization boundary. Recheck every remaining
    # live process so PID reuse or reparenting never selects a different app.
    matched = False
    for item in chain:
        if (not isinstance(item, dict) or set(item) != {"pid", "started", "executable", "parent"}
                or type(item["pid"]) is not int or not 2 <= item["pid"] < 2**31
                or type(item["parent"]) is not int or not 0 <= item["parent"] < 2**31
                or item["pid"] in seen or not isinstance(item["started"], list)
                or len(item["started"]) != 2 or any(type(v) is not int for v in item["started"])
                or item["started"][0] <= 0 or not 0 <= item["started"][1] < 1_000_000
                or not isinstance(item["executable"], str) or not item["executable"].startswith("/")
                or (previous is not None and previous["parent"] != item["pid"])):
            return unverified()
        current = _identity(item["pid"])
        if current is not None and current != item:
            return unverified()
        if current is not None and item["executable"] != "/usr/bin/login" and (
                item["executable"] in allowed or _controlled_claude(data, current)
                or _controlled_terminal_host(data, current)):
            matched = True
        seen.add(item["pid"])
        previous = item
    return matched or unverified()


def _controlled_claude(data: dict, process: dict) -> bool:
    """Recognize native Claude only under our verified live launch command."""
    from . import terminal
    try:
        manifest = terminal._read(Path(data["config"]).parent / "terminal")
        if process["executable"] != manifest["original_path"] or manifest["config_path"] != data["config"]:
            return False
        terminal._verify_active(manifest)
        parent = browser_locks._process_snapshot(process["parent"])
        if parent is None or parent.uid != os.getuid():
            return False
        expected = [manifest["python_executable"], manifest["entrypoint"], "--config", data["config"], "launch", "code"]
        return (parent.executable == manifest["python_executable"]
                and list(parent.argv[:len(expected)]) == expected)
    except (OSError, ValueError, TypeError, KeyError, core.Blocked):
        return False


def open_request(router_config: Path, request: dict, confirmed_from=None) -> dict:
    """Classify source and perform only protected opens; native forwards others."""
    from .web_urls import validate_url
    data = load(router_config)
    if not isinstance(request, dict) or set(request) != {"url", "source"}:
        raise core.Blocked("链接打开请求无效。")
    url = validate_url(request["url"])
    if not _source_matches(data, request):
        saved = data["previous"][urlsplit(url).scheme.lower()]
        return {"schema": 1, "ok": True, "action": "fallback", "app": saved["app"],
                "bundle_id": saved["bundle_id"], "message": "使用原默认浏览器。"}
    helper = Path(data["app"]) / "Contents/Resources/SurgeCCShortcut"
    return shortcuts.open_url(Path(data["config"]), data["workspace"], url, helper,
                              confirmed_from=confirmed_from)


def status(router_config: Path) -> dict:
    data = load(router_config)
    binary = router_config.parents[2] / "Contents/MacOS/SurgeCCLinkRouter"
    defaults = _native(binary, "--defaults")["handlers"]
    active = {scheme: defaults.get(scheme, {}).get("bundle_id") == BUNDLE_ID for scheme in ("http", "https")}
    return {"ok": True, "active": all(active.values()), "schemes": active,
            "workspace": data["workspace"], "previous": {k: v["bundle_id"] for k, v in data["previous"].items()}}


def set_default(router_config: Path, *, restore=False) -> dict:
    load(router_config)
    binary = router_config.parents[2] / "Contents/MacOS/SurgeCCLinkRouter"
    return _native(binary, "--restore-default" if restore else "--set-default", timeout=120)
