"""Local first-run preparation and an optional terminal wizard.

No dependency download, account login, model request or global permission change.
Surge repair remains a separate reviewed transaction using repair.plan/apply.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile

from . import containment, core, repair, terminal, workspaces
from .core import Blocked

PROXY = "http://127.0.0.1:62919"
BROWSER_NAME = "Surge CC Browser.app"


def _plain(path: Path) -> Path:
    path = Path(path).expanduser().absolute()
    if (str(path) != os.path.normpath(str(path)) or any(ord(c) < 32 for c in str(path))
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise Blocked("安装位置必须是未经过符号链接的规范化绝对路径。")
    return path


def _file_state(path: Path):
    path = _plain(path)
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o022 or info.st_size > 4 * 1024 * 1024):
        raise Blocked("现有设置文件的权限、类型或大小不适合自动准备。")
    raw = path.read_bytes()
    after = path.stat()
    stamp = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_mode)
    if stamp(info) != stamp(after):
        raise Blocked("设置文件正在变化，请重新预览。")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "stat": stamp(after)}


def _browser_state(bundle: Path):
    bundle = _plain(bundle)
    if not bundle.exists():
        return None
    binary = bundle / "Contents/MacOS/Google Chrome"
    info_file = bundle / "Contents/Info.plist"
    if not bundle.is_dir() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise Blocked("Chrome 应用不完整；请安装官方 Chrome，或先检查现有专用副本。")
    if binary.resolve() != binary or info_file.is_symlink():
        raise Blocked("Chrome 主程序和应用信息不能指向应用外部。")
    try:
        with info_file.open("rb") as file:
            value = plistlib.load(file)
        if value.get("CFBundleIdentifier") != "com.google.Chrome":
            raise ValueError("wrong application")
    except (OSError, ValueError, plistlib.InvalidFileException):
        raise Blocked("无法确认这是 Google Chrome 应用。") from None
    binary_info = binary.stat()
    bundle_info = bundle.stat()
    if (bundle_info.st_uid not in (0, os.getuid()) or bundle_info.st_mode & 0o022
            or binary_info.st_uid not in (0, os.getuid()) or binary_info.st_mode & 0o022):
        raise Blocked("Chrome 应用允许其他用户修改，请先修正应用安装权限。")
    return {"version": str(value.get("CFBundleShortVersionString", "")),
            "binary": [binary_info.st_dev, binary_info.st_ino, binary_info.st_size, binary_info.st_mtime_ns],
            "info": _file_state(info_file)}


def _labels(profile, section):
    labels = []
    for line in core.profile_sections(profile).get(section, []):
        if "=" not in line:
            continue
        name = line.split("=", 1)[0].strip().strip('"')
        if core.safe_name(name):
            labels.append(name)
    return sorted(set(labels))


def _observe(surge):
    status = surge.status()
    if not isinstance(status, dict) or status.get("mode") not in {"rule", "proxy", "direct"}:
        raise Blocked("无法读取 Surge 状态，请先启动 Surge。")
    text = surge.profile()
    features = status.get("features", {})
    return {"mode": status["mode"], "profile_path": status.get("profile-path", ""),
            "enhanced": isinstance(features, dict) and features.get("enhanced-mode") is True,
            "nodes": _labels(text, "proxy"), "groups": _labels(text, "proxy group"),
            "profile_sha256": hashlib.sha256(text.encode()).hexdigest()}


def doctor(config_path: Path, *, surge=None) -> dict:
    """Read-only prerequisites and available node/group names. Never starts Claude."""
    checks = []
    def add(name, good, detail, required=True):
        checks.append({"id": name, "ok": bool(good), "required": required, "detail": detail})
    mac_version = platform.mac_ver()[0]
    try:
        mac_ok = sys.platform == "darwin" and int(mac_version.split(".")[0]) >= 13
    except (IndexError, ValueError):
        mac_ok = False
    add("macos", mac_ok, "需要 macOS 13 或更新版本。")
    add("python", sys.version_info >= (3, 9), "Python " + platform.python_version())
    add("surge", core.SURGE_CLI.is_file() and os.access(core.SURGE_CLI, os.X_OK),
        "需要 /Applications/Surge.app 及其 surge-cli。")
    try:
        native = core.default_claude().resolve(strict=True)
        native_ok = containment._is_native_cli(native)
        add("claude", native_ok, "已找到本机原生 Claude Code。" if native_ok else "需要官方原生 Claude Code 安装。")
    except (OSError, Blocked):
        add("claude", False, "未找到可验证的原生 Claude Code；请先完成官方安装。")
    try:
        current = core.load_config(Path(config_path)) if Path(config_path).is_file() else {}
        existing_browser = Path(current["browser_path"]).parents[2] if current.get("browser_path") else None
        chrome = _browser_state(existing_browser) if existing_browser is not None else None
        if chrome is not None:
            containment._browser_identity(current, require_files=True)
        else:
            chrome = _browser_state(core.CHROME.parents[2])
        add("chrome", chrome is not None, "需要官方 Chrome，或已验证完整的专用 Chrome 副本。")
    except Blocked as error:
        add("chrome", False, str(error))
    try:
        observed = _observe(surge or core.Surge())
        add("surge-running", True, "已读取 Surge 当前本地配置。")
        add("enhanced", observed["enhanced"], "请在 Surge 开启增强模式。")
    except (OSError, Blocked, ValueError):
        observed = {}
        add("surge-running", False, "未能连接 Surge 控制接口。")
    configured = Path(config_path).is_file()
    add("configuration", configured, "已保存本工具配置。" if configured else "尚未保存配置，下一步填写线路即可。", False)
    return {"schema": 1, "ok": all(c["ok"] for c in checks if c["required"]),
            "checks": checks, "surge": observed,
            "summary": "首次配置依赖检查；不会启动浏览器、Claude 或登录账号。"}


def plan(config_path: Path, group: str, policy: str, expected_ip: str,
         profile_path=None, model=None, effort=None, browser_language=None,
         browser_start_page=None, browser_path=None, *, surge=None) -> dict:
    """Plan app-local settings and browser copy; Surge routing is a later review."""
    config_path = _plain(config_path)
    observed = _observe(surge or core.Surge())
    if group not in observed["groups"]:
        raise Blocked("请先在 Surge 建立一个可查询的手动策略组，再用该组名称预览。")
    if policy not in observed["nodes"]:
        raise Blocked("指定节点不在当前 Surge 配置中，请选择现有节点。")
    selected_profile = str(profile_path or observed["profile_path"])
    if not selected_profile or selected_profile != observed["profile_path"]:
        raise Blocked("必须指定 Surge 当前使用的普通本地配置文件。")
    profile_file = _plain(Path(selected_profile))
    profile_state = _file_state(profile_file)
    if profile_state is None or profile_file.read_text().lstrip().startswith("#!MANAGED-CONFIG"):
        raise Blocked("首次配置只支持当前普通本地 Surge 配置；托管订阅请先使用本地副本。")
    original_state = _file_state(config_path)
    existing = core.load_config(config_path) if original_state else {}
    model = model if model is not None else existing.get("default_model", "opus")
    effort = effort if effort is not None else existing.get("default_effort", "high")
    browser_language = browser_language if browser_language is not None else existing.get("browser_language", "en-US")
    browser_start_page = browser_start_page if browser_start_page is not None else existing.get("browser_start_page", "newtab")
    native = core.default_claude().resolve(strict=True)
    if not containment._is_native_cli(native):
        raise Blocked("终端保护需要官方原生 Claude Code，不能把通用解释器加入拒绝范围。")
    versions = Path.home() / ".local/share/claude/versions"
    scope = str(versions) + "/" if native.parent == versions else str(native)
    containment.validate_cli_process_paths([scope], require_files=True)
    selected_browser = (browser_path or existing.get("browser_path") or
                        str(Path.home() / "Applications" / BROWSER_NAME / "Contents/MacOS/Google Chrome"))
    candidate = core.validate_config({**existing, "schema": 1,
        "group": group, "policy": policy, "expected_ip": expected_ip,
        "proxy_url": PROXY, "profile_path": selected_profile,
        "browser_path": str(selected_browser),
        "cli_process_paths": list(dict.fromkeys([*existing.get("cli_process_paths", []), scope])),
        "browser_language": browser_language, "privacy_strict": existing.get("privacy_strict", True),
        "default_model": model, "default_effort": effort,
        "browser_start_page": browser_start_page})
    _, browser, _ = containment._browser_identity(candidate, require_files=False)
    destination_state = _browser_state(browser)
    source = core.CHROME.parents[2]
    source_state = _browser_state(source) if destination_state is None else None
    if destination_state is None and source_state is None:
        raise Blocked("未找到官方 Chrome 应用，无法准备专用副本。")
    if destination_state is not None:
        containment._browser_identity(candidate, require_files=True)
    actions = [{"id": "browser-create" if destination_state is None else "browser-reuse",
                "title": "创建独立 Chrome 完整副本" if destination_state is None else "复用现有独立 Chrome 应用",
                "detail": str(browser) + "；不复制个人 Chrome 的登录资料。"},
               {"id": "settings", "title": "保存当前账号的线路与启动默认值",
                "detail": "专用端口 62919；默认模型 " + model + "，Effort " + effort + "。"},
               {"id": "review-routes", "title": "下一步单独预览并应用 Surge 规则",
                "detail": "此准备操作不会重载 Surge、安装终端接管或登录账号。"}]
    state = {"schema": 1, "candidate": candidate, "config_state": original_state,
             "surge": observed, "profile_state": profile_state,
             "browser": str(browser), "destination": destination_state,
             "source": str(source), "source_state": source_state,
             "native": [str(native), *_native_stamp(native)]}
    identifier = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    return {"schema": 1, "ok": True, "plan_id": identifier, "settings": candidate,
            "actions": actions, "surge": observed,
            "summary": "仅准备本工具和专用浏览器；线路修复需下一步独立确认。",
            "_state": state}


def _native_stamp(path):
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def public_plan(value):
    return {k: v for k, v in value.items() if not k.startswith("_")}


def _exclusive_rename(source, destination):
    if sys.platform != "darwin":
        raise Blocked("浏览器副本的原子安装需要 macOS。")
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renamex_np", None)
    if rename is None:
        raise Blocked("当前系统缺少原子安装接口，尚未安装副本。")
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(os.fsencode(source), os.fsencode(destination), 0x00000004):
        raise Blocked("专用浏览器位置已改变或无法写入；未覆盖现有应用。")


def _copy_browser(source, destination, runner):
    source, destination = _plain(source), _plain(destination)
    _browser_state(source)
    if os.path.lexists(destination):
        raise Blocked("专用浏览器已存在，未覆盖；请重新预览。")
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _plain(parent)
    info = parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise Blocked("专用浏览器安装目录必须由当前用户持有且不可被其他用户修改。")
    temporary = Path(tempfile.mkdtemp(prefix=".surge-cc-browser-", dir=parent))
    staged = temporary / BROWSER_NAME
    try:
        for command in (("/usr/bin/codesign", "--verify", "--deep", "--strict", str(source)),
                        ("/usr/bin/ditto", str(source), str(staged)),
                        ("/usr/bin/codesign", "--verify", "--deep", "--strict", str(staged))):
            outcome = runner(list(command), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=180, check=False)
            if outcome.returncode:
                raise Blocked("Chrome 应用签名校验或完整复制失败；未安装副本。")
        _browser_state(staged)
        containment._browser_identity({"browser_path": str(staged / "Contents/MacOS/Google Chrome")}, require_files=True)
        _exclusive_rename(staged, destination)
    finally:
        shutil.rmtree(temporary)


def apply(config_path: Path, plan_id: str, group: str, policy: str, expected_ip: str,
          profile_path=None, model=None, effort=None, browser_language=None,
          browser_start_page=None, browser_path=None, *, surge=None, runner=None) -> dict:
    """Apply reviewed local preparation. Never invokes Surge repair or account auth."""
    runner = runner or subprocess.run
    config_path = _plain(config_path)
    current = plan(config_path, group, policy, expected_ip, profile_path, model, effort,
                   browser_language, browser_start_page, browser_path, surge=surge)
    if not plan_id or current["plan_id"] != plan_id:
        raise Blocked("首次配置计划已变化，请重新预览；未应用本次准备。")
    state = current["_state"]
    created = False
    if state["destination"] is None:
        _copy_browser(Path(state["source"]), Path(state["browser"]), runner)
        created = True
    # Browser creation is intentionally additive. If settings saving is blocked
    # by a live workspace, the complete app may remain for a later retry; never
    # remove an app which another launcher could have started in the meantime.
    if _file_state(Path(config_path)) != state["config_state"]:
        raise Blocked("设置在准备期间发生变化；专用应用已保留，请重新预览。")
    config = _save_reviewed(Path(config_path), current["settings"], state["config_state"])
    return {"schema": 1, "ok": True, "settings": config,
            "browser_created": created, "network_changed": False,
            "summary": "专用应用和本工具设置已准备；尚未修改 Surge 规则或安装终端接管。",
            "next_steps": ["repair-plan", "repair --plan-id <已预览的计划编号>",
                           "terminal install", "check", "project plan（按需登记隔离项目）"]}


def _save_reviewed(config_path, candidate, expected):
    # Same locks and atomic workspace bookkeeping as save_settings, with the
    # reviewed config fingerprint checked while launch/switch are excluded.
    candidate = core.validate_config(candidate)
    with workspaces.account_switch(config_path):
        if _file_state(config_path) != expected:
            raise Blocked("设置在准备期间发生变化，请重新预览；未覆盖新的设置。")
        if expected is not None and core.load_config(config_path) == candidate:
            return candidate
        name = candidate["workspace"]
        with workspaces.exclusive(config_path, name):
            file = workspaces._settings_path(config_path, name)
            workspaces._read_settings(config_path, name, candidate)
            previous = {file: workspaces._remember_file(file)}
            try:
                workspaces.write_json(file, workspaces._settings_value(name, workspaces._route(candidate)))
                return core.save_config(config_path, candidate)
            except Exception:
                workspaces._rollback_settings(previous)
                raise


def _confirmed(prompt):
    return input(prompt + " [yes/No]: ").strip().lower() == "yes"


def _show(value):
    print(json.dumps(public_plan(value), ensure_ascii=False, indent=2))


def optional_setup(config_path, config):
    """Project copy and Dock launcher are explicit opt-ins after route checks."""
    from . import projects, shortcuts
    if _confirmed("需要为一个项目创建隔离副本，并启用同项目历史与智能体通信？"):
        try:
            source = Path(input("原项目完整路径（原目录保持不变）: ").strip()).expanduser()
            name = input("隔离项目简称（小写字母开头，可含数字和短横线）: ").strip()
            project_plan = projects.plan(config_path, source, name)
            _show(project_plan)
            if _confirmed("已查看保留与排除清单，创建以上隔离副本？"):
                trust = _confirmed("仅默认信任这个隔离副本及其经过核验的 Orca 工作树？")
                _show(projects.apply(config_path, source, name, expected_digest=project_plan["digest"],
                                     trust=trust, share_history=True, local_messaging=True))
                print("请把返回的隔离副本路径添加到 Orca；原项目不会自动替换。")
        except (Blocked, OSError, ValueError) as error:
            print(str(error) if isinstance(error, Blocked) else "项目准备未完成，已有配置保留。", file=sys.stderr)
    if _confirmed("创建当前工作区的专用浏览器 Dock 入口？"):
        try:
            name = input("入口名称 [Surge CC Browser Launcher]: ").strip() or "Surge CC Browser Launcher"
            resource = Path(__file__).resolve().parents[2]
            app = resource.parent.parent if resource.name == "Resources" and resource.parent.name == "Contents" else None
            if app is None or app.suffix != ".app":
                app = Path(input("已安装的 Surge CC.app 完整路径: ").strip()).expanduser()
            _show(shortcuts.install(config_path, config["workspace"], name,
                                    config["browser_start_page"], app,
                                    python_path=Path(sys.executable).resolve()))
            print("打开新入口后，在 Dock 菜单选择“选项 → 在程序坞中保留”。")
        except (Blocked, OSError, ValueError) as error:
            print(str(error) if isinstance(error, Blocked) else "Dock 入口未完成，已有配置保留。", file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="surge-cc-setup", description="Surge CC 首次配置：检查依赖，准备独立浏览器，再逐步确认线路与终端接管。")
    parser.add_argument("--config", type=Path, default=core.DEFAULT_CONFIG)
    parser.add_argument("--doctor", action="store_true", help="只检查依赖，不修改文件或线路")
    parser.add_argument("--plan", action="store_true", help="只显示准备计划，需提供线路参数")
    for key in ("group", "policy", "expected-ip", "profile"):
        parser.add_argument("--" + key)
    parser.add_argument("--model")
    parser.add_argument("--effort")
    parser.add_argument("--browser-language")
    parser.add_argument("--browser-start-page", choices=("claude", "newtab"))
    options = parser.parse_args(argv)
    options.config = options.config.expanduser().absolute()
    try:
        report = doctor(options.config)
        _show(report)
        if options.doctor:
            return 0 if report["ok"] else 2
        if not report["ok"]:
            print("请先完成上面未通过的依赖项，然后重跑本脚本。", file=sys.stderr)
            return 2
        current = core.load_config(options.config) if options.config.exists() else {}
        values = {"group": options.group or current.get("group"),
                  "policy": options.policy or current.get("policy"),
                  "expected_ip": options.expected_ip or current.get("expected_ip"),
                  "profile_path": options.profile, "model": options.model, "effort": options.effort,
                  "browser_language": options.browser_language, "browser_start_page": options.browser_start_page}
        for key, label in (("group", "Surge 策略组名称"), ("policy", "固定节点名称"), ("expected_ip", "已知的准确公网出口 IP")):
            if not values[key]:
                if options.plan or not sys.stdin.isatty():
                    raise Blocked("请提供 --group、--policy 和 --expected-ip；不会自动猜测线路。")
                values[key] = input(label + ": ").strip()
        planned = plan(options.config, **values)
        _show(planned)
        if options.plan or not _confirmed("应用以上本机准备计划？"):
            return 0
        _show(apply(options.config, planned["plan_id"], **values))
        config = core.load_config(options.config)
        routes = repair.plan(config)
        _show(repair.public_plan(routes))
        if not _confirmed("应用这份 Surge 修复计划（可能短暂重连）？"):
            return 0
        with workspaces.account_switch(options.config):
            workspaces.assert_current(options.config, config)
            _show(repair.apply(config, options.config, routes["plan_id"]))
        if _confirmed("把本机 claude 命令接入 Surge CC 启动保护？"):
            containment.validate_scope(config, core.Surge())
            native = core.default_claude()
            if not containment.cli_scope_covers(config, native):
                raise Blocked("原生 Claude 程序没有被已生效的拒绝范围覆盖。")
            entrypoint = Path(__file__).resolve().parents[2] / "scripts/surge-cc"
            current_terminal = terminal.status()
            if current_terminal.get("installed"):
                if not current_terminal.get("ok"):
                    raise Blocked(current_terminal["summary"])
                metadata = terminal._read(terminal._state_dir())
                if Path(metadata["config_path"]) != options.config.expanduser().absolute():
                    raise Blocked("现有终端接管属于另一份配置，未改变它。")
                _show(terminal.update_backend(entrypoint, Path(sys.executable).resolve()))
            else:
                _show(terminal.install(options.config, entrypoint, Path(sys.executable).resolve()))
        from .cli import full_checks
        final_check = full_checks(config)
        _show(final_check)
        if final_check.get("ok") is not True:
            print("本机准备已保存，但线路检查尚未通过；请处理检查项后再启动。", file=sys.stderr)
            return 2
        optional_setup(options.config, config)
        print("配置完成。首次使用请从 Surge CC 自行完成 OAuth，或在工作区安全保存已有 setup-token。")
        return 0
    except (Blocked, OSError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, Blocked) else "系统操作未完成；已完成的准备保留，可检查后重试。"
        print(message, file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("已停止；未自动登录或执行后续步骤。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
