"""Portable Dock shortcuts using the installed app's current protected backend."""
from __future__ import annotations

import ctypes
import datetime as dt
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
import time

from . import core, workspaces, browser_locks, sessions, workspace_routes
from .web_urls import validate_url as validate_web_url
# cli imports this module only within its shortcut command branch.
from . import cli
from .guard import BrowserRuntimeChecker


class LauncherError(core.Blocked):
    pass


class LauncherStopped(LauncherError):
    pass


def page_ok(value):
    if value not in ("claude", "newtab"):
        raise LauncherError("启动页只能选择 Claude 或新标签页。")
    return value


def name_ok(value):
    if (not isinstance(value, str) or not value or len(value) > 60 or value != value.strip()
            or value.startswith(".") or value.endswith(".app")
            or any(c in '/\\:' or ord(c) < 32 or ord(c) == 127 for c in value)):
        raise LauncherError("快捷入口名称须为 1–60 个可见字符，不能含路径分隔符或 .app 后缀。")
    return value


def absolute_path(value):
    if not isinstance(value, (str, Path)) or "\0" in str(value):
        raise LauncherError("快捷入口安装路径无效。")
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise LauncherError("快捷入口需要绝对路径。")
    return path


def no_links(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise LauncherError("快捷入口安装路径不能使用符号链接。")


def private_json(path: Path, maximum: int = 1024 * 1024):
    no_links(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > maximum):
            raise LauncherError("启动资料的所有者、权限或大小异常，已停止。")
        return json.loads(os.read(fd, maximum + 1))
    finally:
        os.close(fd)


def load_launcher(path: Path) -> dict:
    path = absolute_path(path)
    data = private_json(path, 16384)
    fields = {"schema", "name", "workspace", "start_page", "python", "config", "app"}
    if (not isinstance(data, dict) or set(data) != fields or type(data.get("schema")) is not int
            or data["schema"] != 1):
        raise LauncherError("快捷入口配置版本不支持。")
    name_ok(data["name"])
    workspaces.name_ok(data["workspace"])
    page_ok(data["start_page"])
    for key in ("python", "config", "app"):
        absolute_path(data[key])
    if path.parts[-3:] != ("Contents", "Resources", "launcher.json"):
        raise LauncherError("快捷入口配置必须位于独立应用内。")
    if not path.parents[2].name.endswith(".app"):
        raise LauncherError("快捷入口应用位置不支持。")
    app = Path(data["app"])
    no_links(app)
    backend = app / "Contents/Resources/scripts/surge-cc"
    if not app.name.endswith(".app") or not backend.is_file():
        raise LauncherError("找不到已安装的 Surge CC。请重新创建快捷入口。")
    return data


def _publish(stage: Path, destination: Path):
    """Atomic no-replace publication on macOS; never nest in an existing app."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renamex_np", None)
    if rename is None:
        raise LauncherError("安装快捷入口需要 macOS 的安全发布接口。")
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(os.fsencode(stage), os.fsencode(destination), 0x00000004):
        raise LauncherError("快捷入口已存在或无法写入；未覆盖现有应用。")


def install(config_path: Path, workspace: str, name: str, start_page: str,
            app_path: Path, *, python_path: Path | None = None,
            applications_dir: Path | None = None) -> dict:
    """Create one portable app without compiler, credentials, or backend copies."""
    config_path = absolute_path(config_path)
    workspace = workspaces.name_ok(workspace)
    name = name_ok(name)
    start_page = page_ok(start_page)
    app_path = absolute_path(app_path)
    python_path = absolute_path(python_path or Path(sys.executable).resolve())
    applications_dir = absolute_path(applications_dir or Path.home() / "Applications")
    for path in (config_path, app_path, applications_dir):
        no_links(path)
    config = core.load_config(config_path)
    assert_start_page(config_path, config, workspace, start_page)
    resources = app_path / "Contents/Resources"
    template = resources / "SurgeCCShortcut"
    icon = resources / "SurgeCCIcon.icns"
    backend = resources / "scripts/surge-cc"
    for path in (template, icon, backend):
        no_links(path)
        if not path.is_file():
            raise LauncherError("主应用缺少快捷入口组件，请安装完整的新版 Surge CC。")
    if not os.access(template, os.X_OK) or not os.access(python_path, os.X_OK):
        raise LauncherError("快捷入口组件或 Python 无法执行。")
    applications_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = applications_dir.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise LauncherError("应用目录的所有者或写入权限异常。")
    destination = applications_dir / (name + ".app")
    if os.path.lexists(destination):
        raise LauncherError("同名快捷入口已存在，请选择新名称；未覆盖现有应用。")
    stage_root = Path(tempfile.mkdtemp(prefix=".surge-cc-shortcut-", dir=applications_dir))
    try:
        stage = stage_root / destination.name
        binary = stage / "Contents/MacOS/SurgeCCShortcut"
        binary.parent.mkdir(parents=True, mode=0o700)
        output = stage / "Contents/Resources"
        output.mkdir(mode=0o700)
        shutil.copyfile(template, binary)
        binary.chmod(0o755)
        shutil.copyfile(icon, output / "SurgeCCIcon.icns")
        settings = {"schema": 1, "name": name, "workspace": workspace, "start_page": start_page,
                    "python": str(python_path), "config": str(config_path), "app": str(app_path)}
        workspaces.write_json(output / "launcher.json", settings)
        digest = hashlib.sha256((str(config_path) + "\0" + workspace + "\0" + name).encode()).hexdigest()[:24]
        with (stage / "Contents/Info.plist").open("wb") as handle:
            plistlib.dump({"CFBundleExecutable": "SurgeCCShortcut",
                          "CFBundleIdentifier": "local.surgecc.shortcut." + digest,
                          "CFBundleName": name, "CFBundleDisplayName": name,
                          "CFBundlePackageType": "APPL", "CFBundleIconFile": "SurgeCCIcon",
                          "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1",
                          "LSMinimumSystemVersion": "13.0", "NSHighResolutionCapable": True,
                          "NSAppleEventsUsageDescription": "Send requested web links to the verified dedicated browser window.",
                          "NSPrincipalClass": "NSApplication",
                          "CFBundleURLTypes": [{"CFBundleURLName": "Web links",
                                                "CFBundleTypeRole": "Viewer",
                                                "CFBundleURLSchemes": ["http", "https"]}]}, handle)
        try:
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(stage)],
                           stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
            subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(stage)],
                           stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise LauncherError("快捷入口签名验证未完成；未安装不完整的应用。") from None
        no_links(applications_dir)
        _publish(stage, destination)
    finally:
        shutil.rmtree(stage_root)
    return {"ok": True, "app": str(destination), "name": name, "workspace": workspace,
            "start_page": start_page, "pinned": False,
            "detail": "快捷入口已创建。打开后可在 Dock 图标菜单中选择保留在程序坞；主应用须保留在当前安装位置。"}


def parent_pid(pid):
    lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    info = browser_locks._BSDInfo()
    lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidinfo.restype = ctypes.c_int
    if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
        raise LauncherError("浏览器状态已改变，请重试。")
    return info.ppid


def guard_arguments(argv, expected_command):
    if len(argv) < 5 or tuple(argv[1:4]) != ("-B", "-m", "surge_cc.guard"):
        raise LauncherError("现有窗口不是由 Surge CC 守护启动的，请从 Surge CC 检查窗口。")
    try:
        separator = argv.index("--", 4)
    except ValueError:
        raise LauncherError("无法核对现有浏览器的守护参数。") from None
    if list(argv[separator + 1:]) != expected_command:
        raise LauncherError("现有窗口的账号或代理参数与指定工作区不一致，请先在 Surge CC 中处理。")
    values = argv[4:separator]
    if len(values) % 2:
        raise LauncherError("守护参数不完整，未切换窗口。")
    pairs = list(zip(values[::2], values[1::2]))
    allowed = {"--config", "--receipt", "--status", "--cwd", "--target", "--lock"}
    if len(pairs) != len(allowed) or {key for key, _ in pairs} != allowed:
        raise LauncherError("守护参数无法验证，未切换窗口。")
    return dict(pairs)


def validate_guard_files(arguments, config_path, config):
    workspace = workspaces.name_ok(config["workspace"])
    root = config_path.parent / "workspaces" / workspace
    if arguments["--lock"] != str(root / ".session.lock") or arguments["--target"] != "web":
        raise LauncherError("现有窗口不属于指定工作区的网页会话。请完成授权或关闭该窗口后重试。")
    session_config = Path(arguments["--config"])
    if (session_config.parent != config_path.parent / "sessions"
            or not re.fullmatch(re.escape(workspace) + r"-[0-9a-f]{32}\.config\.json", session_config.name)):
        raise LauncherError("现有浏览器的守护配置来源无法验证。")
    identifier = session_config.name.removesuffix(".config.json")
    saved_config = core.validate_config(private_json(session_config))
    if saved_config != config:
        raise LauncherError("现有窗口使用的线路设置已改变，请在 Surge CC 中重新打开。")
    for key, suffix in (("--status", ".status.json"), ("--receipt", ".receipt.json")):
        path = session_config.parent / (identifier + suffix)
        if arguments[key] != str(path):
            raise LauncherError("浏览器守护回执不匹配。")
        value = private_json(path, 8192)
        if value.get("schema") != 1 or value.get("target") != "web":
            raise LauncherError("浏览器守护回执无法验证。")
        if value.get("web_guard_version") != 2:
            raise LauncherError("现有 Lia 窗口仍使用旧版守护，请正常退出该专用浏览器后重新打开；个人 Chrome 无需退出。")
        if key == "--receipt":
            if (value.get("state") != "running" or value.get("ok") is not True
                    or value.get("protection_active") is not True or value.get("suspended") is not False):
                raise LauncherError("未找到成功启动浏览器的守护回执。")
        else:
            if value.get("state") != "running":
                raise LauncherError("浏览器线路守护已停止，请在 Surge CC 中检查。")
            if value.get("ok") is not True:
                raise LauncherError("浏览器守护状态互相矛盾，未切换窗口。")
            checked = dt.datetime.fromisoformat(value["checked_at"])
            age = (dt.datetime.now(dt.timezone.utc) - checked).total_seconds()
            if not 0 <= age <= max(90, config["guard_interval"] * 3):
                raise LauncherError("浏览器守护回执已过期，未将窗口视为受保护。")
    return saved_config


def existing_browser(config_path, config):
    profile = config_path.parent / "workspaces" / workspaces.name_ok(config["workspace"]) / "data/Browser"
    if any(p.is_symlink() for p in (profile, *profile.parents)):
        raise LauncherError("指定工作区的浏览器资料目录异常，未打开其他资料。")
    lock = profile / "SingletonLock"
    if not os.path.lexists(lock):
        return None
    if not lock.is_symlink():
        raise LauncherError("浏览器锁格式异常，请使用 Surge CC 的浏览器修复功能。")
    pid = browser_locks._lock_pid({"SingletonLock": {"target": os.readlink(lock)}})
    process = browser_locks._process_snapshot(pid)
    if process is None:
        raise LauncherError("指定工作区留有已退出窗口的锁。请打开 Surge CC，点击检查并修复浏览器锁。")
    executable = core.browser_executable(config)
    if not browser_locks._owned_browser(process, executable, profile):
        raise LauncherError("尚无法确认该进程是指定工作区的专用浏览器；未操作个人 Chrome 或其他工作区。")
    expected = accepted_browser_command(process.argv, core.chrome_args(config, profile))
    if expected is None:
        raise LauncherError("指定工作区中可能有授权窗口，或现有窗口参数不同。请完成授权或在 Surge CC 中处理后重试。")
    parent_id = parent_pid(pid)
    parent = browser_locks._process_snapshot(parent_id)
    if parent is None or parent.uid != os.getuid():
        raise LauncherError("现有浏览器没有可验证的运行守护，未切换窗口。")
    if os.path.realpath(parent.argv[0]) != os.path.realpath(parent.executable):
        raise LauncherError("浏览器守护程序身份不匹配。")
    arguments = guard_arguments(parent.argv, expected)
    saved_config = validate_guard_files(arguments, config_path, config)
    if expected != core.chrome_args(saved_config, profile):
        raise LauncherError("浏览器启动页面与守护配置不匹配。")
    if (browser_locks._process_snapshot(pid) != process
            or browser_locks._process_snapshot(parent_id) != parent
            or parent_pid(pid) != parent_id):
        raise LauncherError("浏览器或守护进程已改变，请重试。")
    return process


def accepted_browser_command(actual, expected):
    """The complete canonical browser command, including startup page, must match."""
    pages = {"chrome://newtab/", "https://claude.ai/"}
    if not expected or expected[-1] not in pages:
        raise LauncherError("快捷入口的启动页面不支持。")
    actual = list(actual)
    return actual if actual == expected else None


def wait_for_browser(config_path, config, timeout=12):
    """A startup receipt precedes Chromium/LaunchServices becoming fully ready.

    Retry observation only. No window is accepted or focused until all identity,
    exact argv, parent-guard and fresh receipt checks pass on the same process.
    Existing windows are validated directly, outside this new-launch wait.
    """
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            process = existing_browser(config_path, config)
            if process is not None:
                return process
        except LauncherStopped:
            raise
        except (LauncherError, core.Blocked) as exc:
            last_error = exc
        time.sleep(0.1)
    if last_error is not None:
        raise LauncherError("浏览器已启动，但未能完成身份核对：" + str(last_error))
    raise LauncherError("浏览器已开始启动，但窗口尚未就绪，请稍后再点一次。")


def failure_message(report):
    failed = [item for item in report.get("checks", [])
              if item.get("required", True) and item.get("status") != "pass"]
    if failed:
        return "\n".join(str(item.get("detail", "线路检查未通过。"))[:512] for item in failed[:3])
    return str(report.get("summary", "线路检查未通过，未打开浏览器。"))[:1024]


def check_running_browser(config):
    """Local, current boundary checks, not another privacy or internet probe.

    The owning guard continues checking the actual proxy exit periodically.
    No cached full-diagnostic pass is used to authorize an unverified window.
    """
    checker = BrowserRuntimeChecker(config, process=str(core.browser_executable(config)))
    checker.check(include_exit=False)


def focus_native(process, native):
    """Called while the original account gate remains held."""
    request = {"pid": process.pid, "started": list(process.started), "executable": process.executable}
    completed = subprocess.run([str(native), "--focus-only", json.dumps(request)],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=12)
    try:
        result = json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        result = {}
    if completed.returncode != 0 or result.get("focused") is not True:
        raise LauncherError("已确认指定工作区的浏览器，但未能切到窗口；请查看 Dock 中已打开的专用浏览器。")


def open_url_native(process, native, url):
    """Deliver to the verified PID and return focus status, without URL argv.

    Chrome accepting the event is distinct from staying in the foreground.
    Never retry an accepted request merely because focus was unavailable.
    """
    request = {"pid": process.pid, "started": list(process.started),
               "executable": process.executable, "url": validate_web_url(url)}
    try:
        completed = subprocess.run([str(native), "--open-url-stdin"],
                                   input=json.dumps(request).encode("utf-8"),
                                   capture_output=True, timeout=15)
        result = json.loads(completed.stdout)
        if (completed.returncode == 0 and isinstance(result, dict)
                and type(result.get("schema")) is int and result["schema"] == 1
                and result.get("opened") is True and type(result.get("focused")) is bool):
            return result["focused"]
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
        pass
    raise LauncherError("未能确认网页已在专用浏览器中打开；未转交默认浏览器。请检查 Surge CC 的自动化权限后重试。")


def assert_start_page(config_path: Path, config: dict, workspace: str, start_page: str):
    entries = workspaces.listing(config_path, config)["workspaces"]
    target = next((item for item in entries if item["name"] == workspace), None)
    if target is None or not target.get("route_configured"):
        raise LauncherError("请先在 Surge CC 中配置指定工作区。")
    saved = target["route"].get("browser_start_page", "claude")
    if saved != start_page:
        raise LauncherError("快捷入口的启动页与工作区设置不同，请先在 Surge CC 中保存所选启动页，再创建入口。")


def open_browser(config_path: Path, workspace: str, start_page: str,
                 focus_executable: Path, confirmed_from=None) -> dict:
    """Use the shared backend and account gate; a cancelled switch does nothing."""
    return _open_browser(config_path, workspace, start_page, focus_executable, confirmed_from)


def open_url(config_path: Path, workspace: str, url: str,
             focus_executable: Path, confirmed_from=None, *, before_delivery=None) -> dict:
    """Open an ordinary page in the account's canonical browser after checks.

    The page is delivered after startup, so it cannot change browser argv,
    callback bypasses, profile identity, or the parent guard's receipt.
    """
    url = validate_web_url(url)
    workspace = workspaces.name_ok(workspace)
    config = core.load_config(config_path)
    entries = workspaces.listing(config_path, config)["workspaces"]
    target = next((item for item in entries if item["name"] == workspace), None)
    if target is None or not target.get("route_configured"):
        raise LauncherError("请先在 Surge CC 中配置指定工作区。")
    start_page = target["route"].get("browser_start_page", "claude")
    return _open_browser(config_path, workspace, start_page, focus_executable, confirmed_from,
                         requested_url=url, before_delivery=before_delivery)


def _open_browser(config_path: Path, workspace: str, start_page: str,
                  focus_executable: Path, confirmed_from=None, *, requested_url=None,
                  before_delivery=None) -> dict:
    workspace = workspaces.name_ok(workspace)
    start_page = page_ok(start_page)
    config = core.load_config(config_path)
    assert_start_page(config_path, config, workspace, start_page)
    if config["workspace"] != workspace:
        if confirmed_from != config["workspace"]:
            return {"schema": 1, "action": "needs_switch", "current": config["workspace"],
                    "target": workspace, "message": "切换将结束当前工作区的专用网页、授权和 CLI 会话，请先保存工作。"}
        config = workspaces.use(config_path, config, workspace, stop_sessions=sessions.stop_workspace,
                                apply_route=lambda old, new: workspace_routes.activate(config_path, old, new))
    with workspaces.account_session(config_path, config):
        if config.get("browser_start_page", "claude") != start_page:
            raise LauncherError("工作区启动页面已改变，请重新配置快捷入口。")
        process = existing_browser(config_path, config)
        launched = process is None
        if process is not None:
            check_running_browser(config)
            fresh = existing_browser(config_path, config)
            if fresh != process:
                raise LauncherError("检查期间窗口已经退出或改变，请再点击一次。")
        else:
            report = cli.launch_shortcut_browser(config, config_path)
            if report.get("launched") is not True:
                raise LauncherError(failure_message(report))
            process = wait_for_browser(config_path, config)
        workspaces.assert_current(config_path, config)
        focused = True
        if requested_url is None:
            focus_native(process, focus_executable)
        else:
            if before_delivery is not None:
                before_delivery()
            focused = open_url_native(process, focus_executable, requested_url) is True
        result = {"schema": 1, "ok": True, "action": "focus", "pid": process.pid,
                "started": list(process.started), "executable": process.executable,
                "launched": launched, "suspended": False, "focused": focused,
                "message": "必要线路检查通过，已启动专用浏览器。" if launched
                           else "窗口与本地线路保护已核验，已切回专用浏览器。"}
        if requested_url is not None:
            result["opened"] = True
        return result


def open_launcher(launcher_config: Path, confirmed_from=None, *, expected_config: Path | None = None) -> dict:
    settings = load_launcher(launcher_config)
    if expected_config is not None and Path(settings["config"]) != Path(expected_config):
        raise LauncherError("快捷入口配置与请求不匹配。")
    native = launcher_config.parent.parent / "MacOS/SurgeCCShortcut"
    return open_browser(Path(settings["config"]), settings["workspace"], settings["start_page"],
                        native, confirmed_from)


def open_launcher_url(launcher_config: Path, request: dict, confirmed_from=None, *,
                      expected_config: Path | None = None) -> dict:
    """The default-browser entry always uses its own registered workspace.

    The native launcher sends the URL through stdin. Never accept an account,
    browser path or proxy from the incoming request, or fall back to another app.
    """
    if not isinstance(request, dict) or set(request) != {"url"}:
        raise LauncherError("网页请求无效；未打开网页。")
    url = validate_web_url(request["url"])
    settings = load_launcher(launcher_config)
    config_path = Path(settings["config"])
    if expected_config is not None and config_path != Path(expected_config):
        raise LauncherError("快捷入口配置与请求不匹配。")
    assert_start_page(config_path, core.load_config(config_path),
                      settings["workspace"], settings["start_page"])
    native = launcher_config.parent.parent / "MacOS/SurgeCCShortcut"
    return open_url(config_path, settings["workspace"], url, native, confirmed_from)
