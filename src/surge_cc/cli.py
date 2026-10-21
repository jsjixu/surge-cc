from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import datetime as dt
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import uuid

from .core import (
    APP_SUPPORT, CHROME, DEFAULT_CONFIG, Blocked, BrowserProfileBusy, Surge, chrome_args, default_claude,
    load_config, now, provider_environment_ok, proxy_env, result, row, run_checks, save_config, browser_executable,
)
from . import workspaces, repair, isolation
from .guard import run_guarded
from .oauth import OAuthSession


def full_checks(config: dict, browser: bool = True, external_dns: bool = True) -> dict:
    basic = run_checks(config)
    if not basic["ok"]:
        basic["checks"].append({"id": "privacy_pending", "title": "扩展隐私检测", "status": "unknown",
                                "required": True, "detail": "先修复基础线路；未启动浏览器探针。"})
        return result(basic["checks"], config)
    from .audit import audit_checks
    try:
        extras = audit_checks(config, browser=browser, external_dns=external_dns)
    except Exception:
        extras = [{"id": "audit_error", "title": "扩展检测", "status": "unknown", "required": True,
                   "detail": "扩展检测未完成，不能视为通过。"}]
    return result(basic["checks"] + extras, config)


def oauth_checks(config: dict) -> dict:
    """Check the browser scope plus the entrance actually used by OAuth."""
    from .oauth_gate import verify_proxy_exit
    from .guard import RuntimeChecker
    # OAuth rechecks all mandatory protections before and after opening. Avoid
    # repeating the optional third-party DNS service during that short handshake.
    report = full_checks(config, external_dns=False)
    if report.get("ok") is not True:
        return report
    verify_proxy_exit(config)
    RuntimeChecker(config, process=str(browser_executable(config))).check(include_exit=False)
    return report


def command_result(summary: str, config: dict, **fields) -> dict:
    return {"schema": 1, "ok": True, "summary": summary, "checked_at": now(),
            "checks": [], "settings": config, **fields}


def print_result(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=False))
        return
    print(report["summary"])
    for item in report.get("checks", []):
        marker = {"pass": "✓", "fail": "✗", "unknown": "?", "warn": "!", "info": "·"}.get(item["status"], "?")
        print(f'{marker} {item["title"]}：{item["detail"]}')


def code_settings_ok(config: dict, cwd: Path, env: dict) -> bool:
    if not provider_environment_ok(env):
        return False
    custom = env.get("CLAUDE_CONFIG_DIR")
    home_settings = Path(custom).expanduser() if custom else Path.home() / ".claude"
    paths = [home_settings / "settings.json", home_settings / "settings.local.json"]
    managed_root = Path("/Library/Application Support/ClaudeCode")
    paths.append(managed_root / "managed-settings.json")
    paths.extend(sorted((managed_root / "managed-settings.d").glob("*.json")))
    for parent in (cwd, *cwd.parents):
        paths += [parent / ".claude/settings.json", parent / ".claude/settings.local.json"]
    for path in dict.fromkeys(paths):
        if not path.exists():
            continue
        try:
            settings = json.loads(path.read_text())
            if isinstance(settings, dict):
                # User/project auto-remote preference is overridden only in this
                # protected child. Enterprise-managed policy can outrank CLI
                # settings, so refuse a managed request to auto-enable remote.
                if managed_root in path.parents and settings.get("remoteControlAtStartup") is True:
                    return False
                settings = {**settings, "remoteControlAtStartup": False}
            if not launch_settings_safe(config, settings):
                return False
        except (OSError, ValueError, AttributeError, TypeError):
            return False
    return True


def launch_settings_safe(config: dict, settings: object) -> bool:
    """Inspect settings without executing hooks; keep protected env immutable."""
    if not isinstance(settings, dict) or settings.get("remoteControlAtStartup") is True:
        return False
    values = settings.get("env", {})
    if (not isinstance(values, dict) or
            any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()) or
            not provider_environment_ok(values)):
        return False
    for name, value in values.items():
        if name.upper() in {"BROWSER", "CLAUDE_CONFIG_DIR"}:
            return False
        if name.upper() in {"DISABLE_UPDATES", "DISABLE_AUTOUPDATER"} and value != "1":
            return False
        if name.lower() in {"http_proxy", "https_proxy", "all_proxy", "npm_config_proxy", "npm_config_https_proxy"} and value != config["proxy_url"]:
            return False
        if name.lower() in {"no_proxy", "npm_config_noproxy"} and value:
            return False
    return True


def validate_launch_arguments(config: dict, arguments: list[str]) -> None:
    """Orca's inline settings are allowed only after semantic validation.

    Files are deliberately not accepted here: checking one then handing its path
    to another process leaves a race with edits after the gate.
    """
    for index, arg in enumerate(arguments):
        flag, sep, value = arg.partition("=")
        if flag not in {"--settings", "--setting-sources"}:
            continue
        if not sep:
            if index + 1 >= len(arguments):
                raise Blocked("启动设置缺少参数。")
            value = arguments[index + 1]
        if flag == "--settings":
            try:
                safe = launch_settings_safe(config, json.loads(value))
            except (ValueError, TypeError):
                safe = False
            if not safe:
                raise Blocked("启动设置必须是有效的内联 JSON，且不能覆盖代理、浏览器或工作区保护。")
        else:
            sources = value.split(",") if value else []
            if not sources or len(set(sources)) != len(sources) or set(sources) - {"user", "project", "local"}:
                raise Blocked("无法确认 Claude 设置来源；只接受 user、project、local。")


def protected_code_arguments(arguments: list[str]) -> list[str]:
    """Merge validated inline settings, then force local-only startup in the child.

    The caller must validate each settings object before this transformation.
    Never edit home/project settings; preserve unrelated Orca settings and env.
    """
    settings: dict = {}
    remaining = []
    index = 0
    while index < len(arguments):
        arg = arguments[index]
        flag, sep, value = arg.partition("=")
        if flag != "--settings":
            remaining.append(arg)
            index += 1
            continue
        if not sep:
            index += 1
            if index >= len(arguments):
                raise Blocked("启动设置缺少参数。")
            value = arguments[index]
        try:
            incoming = json.loads(value)
        except (ValueError, TypeError):
            raise Blocked("启动设置必须是有效的内联 JSON。") from None
        if not isinstance(incoming, dict):
            raise Blocked("启动设置必须是内联 JSON 对象。")
        if "env" in incoming:
            if not isinstance(incoming["env"], dict):
                raise Blocked("启动设置环境字段无效。")
            incoming = {**incoming, "env": {**settings.get("env", {}), **incoming["env"]}}
        settings.update(incoming)
        index += 1
    settings["remoteControlAtStartup"] = False
    return ["--settings", json.dumps(settings, ensure_ascii=False, separators=(",", ":")), *remaining]


def terminal_launcher(config_path: Path, arguments: list[str], cwd: Path,
                      opener=subprocess.run) -> None:
    # This script re-runs the gate inside Terminal. Never trust a cached GUI pass.
    folder = config_path.parent / "launchers"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    entrypoint = Path(__file__).resolve().parents[2] / "scripts/surge-cc"
    command = [sys.executable, "-B", str(entrypoint), "--config", str(config_path),
               "launch", "code", "--", *arguments]
    fd, path = tempfile.mkstemp(prefix="Claude-Code-", suffix=".command", dir=folder)
    content = (
        "#!/bin/zsh\n"
        "cd -- " + shlex.quote(str(cwd)) + " || exit 1\n" +
        shlex.join(command) + "\n"
        "launch_status=$?\n"
        'if [ "$launch_status" -ne 0 ]; then\n'
        "  printf '\\n启动已停止。按回车关闭此窗口。\\n'\n"
        "  read -r reply\n"
        "fi\n"
        "rm -- " + shlex.quote(path) + "\n"
        'exit "$launch_status"\n'
    )
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), 0o700)
        handle.write(content)
    try:
        launched = opener(["/usr/bin/open", "-a", "Terminal", path], capture_output=True, timeout=10)
        if launched.returncode:
            raise Blocked("无法打开终端启动器。")
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("终端启动器未能启动。") from None


def start_web_guard(config: dict, config_path: Path, command: list[str], loc: dict,
                    popen=subprocess.Popen, timeout: float = 90) -> dict:
    folder = (config_path.parent / "sessions").absolute()
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    identifier = config["workspace"] + "-" + uuid.uuid4().hex
    receipt = folder / (identifier + ".receipt.json")
    status = folder / (identifier + ".status.json")
    session_config = folder / (identifier + ".config.json")
    save_config(session_config, config)
    env = proxy_env(config["proxy_url"])
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    worker = popen(
        [sys.executable, "-B", "-m", "surge_cc.guard", "--config", str(session_config),
         "--receipt", str(receipt), "--status", str(status), "--cwd", str(Path.cwd()),
         "--target", "web", "--lock", str(loc["lock"].absolute()), "--", *command],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env, start_new_session=True)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if receipt.is_symlink():
                raise Blocked("启动回执位置异常，无法确认运行监控。")
            if receipt.exists():
                try:
                    if receipt.stat().st_size > 8192:
                        raise ValueError("oversized receipt")
                    state = json.loads(receipt.read_text())
                except (OSError, ValueError):
                    raise Blocked("启动回执无法读取，未确认浏览器受监控。") from None
                if (not isinstance(state, dict) or state.get("schema") != 1 or
                        state.get("target") != "web" or type(state.get("ok")) is not bool):
                    raise Blocked("启动回执格式未知，未确认浏览器受监控。")
                if state["ok"] is True and state.get("state") == "running":
                    if worker.poll() is None:
                        return state
                    raise Blocked("运行监控提前退出，浏览器启动未得到确认。")
                if state["ok"] is False and state.get("state") in {"blocked", "stopped", "stop_failed"}:
                    detail = state.get("detail")
                    raise Blocked(detail[:512] if isinstance(detail, str) and detail
                                  else "运行监控未能启动。")
                raise Blocked("启动回执状态未知，未确认浏览器受监控。")
            if worker.poll() is not None:
                raise Blocked("运行监控提前退出，浏览器启动未得到确认。")
            time.sleep(0.1)
        raise Blocked("等待运行监控超时，已停止启动。")
    except BaseException:
        # Keep the Popen handle as the ownership proof. Never take a PID from a
        # status file, and never kill a worker before it can clean up its child.
        if worker.poll() is None:
            try:
                worker.terminate()
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise Blocked("运行监控未在停止期限内退出，无法确认专用浏览器已关闭，请手动检查。") from None
            except OSError:
                if worker.poll() is None:
                    raise Blocked("无法确认运行监控已停止，请手动检查专用浏览器。") from None
        raise


def launch(config: dict, config_path: Path, target: str, terminal: bool, args: list[str],
           checker=full_checks, popen=subprocess.Popen, terminal_open=terminal_launcher,
           guarded=run_guarded, web_guard=start_web_guard) -> dict:
    arguments = args[1:] if args[:1] == ["--"] else args
    isolated = isolation.for_cwd(config_path, Path.cwd()) if target == "code" else None
    if target == "code" and arguments == ["--surge-cc-isolation-check"]:
        if not isolated:
            raise Blocked("当前目录不是已登记的隔离项目。")
        report = isolation.diagnose(isolated, default_claude(), config, config_path)
        # The terminal shim uses passthrough; keep this explicitly requested
        # diagnostic report on stdout, without triggering native Claude login.
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return {**report, "checks": [], "launched": True, "child_exit_code": 0 if report.get("ok") else 1}
    if target == "code":
        if os.environ.get("SURGE_CC_TERMINAL_ENTRY") == "1" and (
                not config.get("cli_process_paths") or not config.get("browser_path")):
            raise Blocked("终端接管所需的 Claude 进程规则或专用浏览器配置缺失，已阻止启动。")
        claude = default_claude()
        if not claude.is_file() or not os.access(claude, os.X_OK):
            raise Blocked("没有找到 Claude Code 可执行文件，请先完成官方安装。")
        validate_launch_arguments(config, arguments)
        # A maintenance word used as the immediate print prompt is harmless;
        # a later --print flag must not pardon an earlier update subcommand.
        maintenance = any(a in {"update", "upgrade", "install"} and not (
            i > 0 and arguments[i - 1] in {"-p", "--print"}) for i, a in enumerate(arguments))
        if maintenance:
            raise Blocked("终端接管期间不能由 Claude 更新或覆盖命令入口；请先卸载接管，更新后重新安装。")
        if config.get("cli_process_paths"):
            from .containment import cli_scope_covers
            if not cli_scope_covers(config, claude):
                raise Blocked("当前 Claude 可执行文件不在旁路拒绝范围内，已阻止启动。")
        remote_commands = {"remote-control", "rc", "remote", "attach", "teleport", "respawn"}
        remote_flags = {"--remote-control", "--remote", "--teleport", "--cloud",
                        "--environment", "--desktop", "--bg", "--background", "--tmux"}
        if any(a in remote_commands or a.split("=", 1)[0] in remote_flags for a in arguments):
            raise Blocked("OAuth 接管仅支持本机独立 CLI；远端或附着会话尚未验证，未启动。")
        if isolated:
            # Only new settings are supplied explicitly below. Do not inspect or
            # propagate original home/ancestor project settings into this child.
            isolation.arguments(arguments)
        else:
            code_env = dict(os.environ)
            code_env["CLAUDE_CONFIG_DIR"] = str(workspaces.location(config_path, config["workspace"]) / "data/Claude")
            external_home = os.environ.get("CLAUDE_CONFIG_DIR")
            if external_home and Path(external_home).expanduser().resolve() != Path(code_env["CLAUDE_CONFIG_DIR"]).resolve():
                raise Blocked("调用方指定了另一份 Claude 账号目录；请将 Orca 的 CLAUDE_CONFIG_DIR 与当前 Surge CC 工作区对齐后重试。")
            if not code_settings_ok(config, Path.cwd(), code_env):
                raise Blocked("Claude 的环境或项目配置包含冲突的代理、浏览器或其他模型服务设置，请先检查。")
    else:
        if arguments:
            raise Blocked("网页入口不接受额外浏览器参数。")
        if not browser_executable(config).is_file():
            raise Blocked("没有找到 Google Chrome。")
    # Terminal/Orca launches retain all mandatory checks but skip the optional
    # external DNS measurement service, whose latency can stall host handshakes.
    report = (full_checks(config, external_dns=False)
              if os.environ.get("SURGE_CC_TERMINAL_ENTRY") == "1" and checker is full_checks
              else checker(config))
    if not report.get("ok"):
        return report
    loc = workspaces.paths(config_path, config["workspace"])
    if target == "web":
        profile = loc["browser"]
        # Existing sessions may retain old flags; do not silently reuse one.
        if profile.is_symlink():
            raise Blocked("专用网页资料目录异常，未启动浏览器。")
        if os.path.lexists(profile / "SingletonLock"):
            raise BrowserProfileBusy("专用网页窗口仍在运行，或退出后留有锁。可点击检查并修复；不会操作个人 Chrome。")
        workspaces.prepare_browser_language(config_path, config)
        profile.mkdir(parents=True, mode=0o700, exist_ok=True)
        web_guard(config, config_path, chrome_args(config, profile), loc, popen=popen)
        report.update(launched=True, target="web", summary="已打开独立网页窗口并启动运行期线路监控")
    elif terminal:
        terminal_open(config_path, arguments, Path.cwd())
        report.update(launched=True, target="code-terminal", summary="已打开终端；终端将再次检查后启动 Claude Code")
    else:
        env = (isolation.environment(isolated, config["proxy_url"]) if isolated
               else proxy_env(config["proxy_url"]))
        env["CLAUDE_CONFIG_DIR"] = str(isolated.config if isolated else loc["claude"])
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # Native updates replace ~/.local/bin/claude, which is our guarded shim.
        # Scope this to the child; never change the user's global environment.
        env["DISABLE_AUTOUPDATER"] = "1"
        env["DISABLE_UPDATES"] = "1"
        identifier = config["workspace"] + "-" + uuid.uuid4().hex
        folder = (config_path.parent / "sessions").absolute()
        status_path = folder / (identifier + ".status.json")
        receipt_path = folder / (identifier + ".receipt.json")
        with OAuthSession(config, config_path, checker=oauth_checks) as oauth:
            env["BROWSER"] = str(oauth.browser_hook)
            native = default_claude()
            command = (isolation.command(isolated, native, arguments, oauth.browser_hook) if isolated
                       else [str(native), *protected_code_arguments(arguments)])
            guard_options = {}
            if isolated:
                from .guard import RuntimeChecker
                guard_options["checker"] = RuntimeChecker(config, process=str(native))
                detail = ("当前 Orca 工作树和独立 HOME 可读写，共享 Git 数据只读；提交和推送请在 Orca 完成。"
                          if isolated.worktree else "用户文件仅开放当前副本和独立 HOME，系统工具只读。")
                print(f"[Surge CC] 文件隔离已启用：{isolated.name}；{detail}", file=sys.stderr)
            status = guarded(command, env=env, cwd=Path.cwd(),
                             config=config, target="code", status_path=status_path, popen=popen,
                             receipt_path=receipt_path, on_started=oauth.set_child,
                             lock_path=loc["lock"].absolute(), interval=config["guard_interval"],
                             exit_interval=max(30, config["guard_interval"]), **guard_options)
        try:
            receipt = json.loads(receipt_path.read_text()) if receipt_path.is_file() and not receipt_path.is_symlink() else {}
        except (OSError, ValueError):
            receipt = {}
        launched = (isinstance(receipt, dict) and receipt.get("schema") == 1 and
                    receipt.get("target") == "code" and receipt.get("state") == "running" and
                    receipt.get("ok") is True)
        report.update(launched=launched, target="code", child_exit_code=status,
                      ok=launched and status == 0,
                      summary=("Claude Code 受监控会话已结束" if status == 0 else "Claude Code 已停止；请查看保护状态")
                      if launched else "启动前复核或运行监控未建立，未确认 Claude Code 启动")
        if isolated:
            report["file_isolation"] = {"project": isolated.name, "root": str(isolated.root),
                                        "home": str(isolated.home), "backend": "macOS Seatbelt",
                                        "linked_worktree": isolated.worktree is not None}
        if not launched or status != 0:
            report["checks"].append(row("runtime", "运行监控", False,
                                        "未建立受监控会话。" if not launched else "受监控会话以非零状态结束。"))
    return report


def guard_status(config: dict, config_path: Path) -> dict:
    guards = []
    current = dt.datetime.now(dt.timezone.utc)
    for file in (config_path.parent / "sessions").glob("*.status.json"):
        if file.is_symlink():
            continue
        try:
            item = json.loads(file.read_text())
            if (not isinstance(item, dict) or item.get("schema") != 1 or
                    item.get("target") not in {"web", "code"} or
                    not isinstance(item.get("checked_at"), str)):
                continue
            updated = dt.datetime.fromisoformat(item["checked_at"])
            age = (current - updated).total_seconds()
            item["running"] = item.get("state") == "running" and 0 <= age <= max(90, config["guard_interval"] * 3)
            if item.get("state") == "running" and not item["running"]:
                item["detail"] = "状态回执已过期，无法确认监控仍在运行。"
            item["workspace"] = file.name.rsplit("-", 1)[0]
            guards.append(item)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    guards.sort(key=lambda item: item["checked_at"], reverse=True)
    active = [item for item in guards if item["running"]]
    latest = guards[0] if guards else {}
    overview = {"running": bool(active), "interval": config["guard_interval"],
                "last_checked_at": latest.get("checked_at", ""),
                "detail": f"最近 {max(90, config['guard_interval'] * 3)} 秒收到 {len(active)} 个会话的保护回执；"
                          "只覆盖本工具启动的程序，进程当前状态仍可能变化。" if active
                else latest.get("detail", "尚无有效保护回执。启动网页或 CLI 时建立监控。")}
    return command_result("运行期保护状态", config, guard=overview, guards=guards)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Surge CC：核验固定线路后启动 Claude")
    value.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    commands = value.add_subparsers(dest="command", required=True)
    for name in ("check", "status", "checkdetail", "pin", "repair-plan", "guard-status"):
        sub = commands.add_parser(name)
        sub.add_argument("--json", action="store_true")
    configure = commands.add_parser("configure")
    for flag in ("group", "policy", "expected-ip", "proxy-url"):
        configure.add_argument("--" + flag, required=True)
    configure.add_argument("--profile", default="")
    for flag in ("expected-timezone", "expected-locale", "expected-country", "expected-asn", "browser-language", "browser-path"):
        configure.add_argument("--" + flag)
    configure.add_argument("--privacy-strict", choices=("true", "false"))
    configure.add_argument("--guard-interval", type=int)
    configure.add_argument("--json", action="store_true")
    fix = commands.add_parser("repair")
    fix.add_argument("--plan-id", required=True)
    fix.add_argument("--json", action="store_true")
    workspace = commands.add_parser("workspace")
    workspace.add_argument("action", choices=("list", "create", "use", "snapshot", "restore"))
    workspace.add_argument("--name")
    workspace.add_argument("--label", default="")
    workspace.add_argument("--snapshot")
    workspace.add_argument("--json", action="store_true")
    browser_locks = commands.add_parser("browser-locks")
    browser_locks.add_argument("action", choices=("repair",))
    browser_locks.add_argument("--workspace", required=True)
    browser_locks.add_argument("--json", action="store_true")
    start = commands.add_parser("launch")
    start.add_argument("target", choices=("code", "web"))
    start.add_argument("--terminal", action="store_true")
    start.add_argument("--json", action="store_true")
    start.add_argument("--passthrough", action="store_true",
                       help="Keep child stdin/stdout intact; send diagnostics to stderr.")
    terminal = commands.add_parser("terminal")
    terminal.add_argument("action", choices=("install", "uninstall", "status", "version"))
    terminal.add_argument("--json", action="store_true")
    # parse_known_args below accepts extra arguments only after an explicit "--".
    return value


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    arguments = []
    if "--" in argv:
        split = argv.index("--")
        arguments, argv = argv[split + 1:], argv[:split]
    options = parser().parse_args(argv)
    config = None
    def emit(report):
        with redirect_stdout(sys.stderr if getattr(options, "passthrough", False) else sys.stdout):
            print_result(report, options.json)
    try:
        config_path = options.config.expanduser().absolute()
        if arguments and options.command != "launch":
            raise Blocked("只有启动命令接受额外参数。")
        if options.command == "terminal":
            from . import terminal
            if options.action == "version":
                print(terminal.metadata_version())
                return 0
            if options.action == "install":
                config = load_config(config_path)
                if not config.get("cli_process_paths"):
                    raise Blocked("请先配置并验证 Claude 进程旁路拒绝规则，再安装终端接管。")
                from .containment import validate_scope, cli_scope_covers
                if not cli_scope_covers(config, default_claude()):
                    raise Blocked("当前 Claude 程序未被旁路拒绝规则覆盖。")
                validate_scope(config, Surge())
                data = terminal.install(config_path, Path(__file__).resolve().parents[2] / "scripts/surge-cc", Path(sys.executable).resolve())
            elif options.action == "uninstall":
                data = terminal.uninstall()
            else:
                data = terminal.status()
            report = command_result("Claude 终端入口操作完成", config or {}, terminal=data)
            if data.get("ok") is False:
                report.update(ok=False, summary=data.get("summary", "终端入口检查未通过"))
        elif options.command == "configure":
            existing = load_config(config_path) if config_path.exists() else {}
            candidate = {**existing,
                "schema": 1, "group": options.group, "policy": options.policy,
                "expected_ip": options.expected_ip, "proxy_url": options.proxy_url,
                "profile_path": options.profile,
            }
            for key in ("expected_timezone", "expected_locale", "expected_country", "expected_asn", "browser_language", "browser_path", "guard_interval"):
                if getattr(options, key) is not None:
                    candidate[key] = getattr(options, key)
            if options.privacy_strict is not None:
                candidate["privacy_strict"] = options.privacy_strict == "true"
            config = save_config(config_path, candidate)
            report = {"schema": 1, "ok": True, "summary": "配置已保存，尚未检查",
                      "checked_at": now(), "checks": [], "settings": config}
        else:
            config = load_config(config_path)
            if options.command == "browser-locks":
                # A stale GUI response must never target a newly selected workspace.
                if options.workspace != config["workspace"]:
                    raise Blocked("当前工作区已变更，请刷新后检查当前工作区的浏览器锁。")
                from . import browser_locks
                recovery = browser_locks.repair(config_path, options.workspace)
                report = command_result(recovery["message"], config, recovery=recovery)
            elif options.command == "workspace":
                name = options.name or config["workspace"]
                extra = {}
                if options.action == "create":
                    workspaces.create(config_path, name, options.label)
                elif options.action == "use":
                    config = workspaces.use(config_path, config, name)
                elif options.action == "snapshot":
                    extra["snapshot"] = workspaces.snapshot(config_path, name, options.label)
                elif options.action == "restore":
                    if not options.snapshot:
                        raise Blocked("请选择快照编号后再恢复。")
                    extra.update(workspaces.restore(config_path, name, options.snapshot))
                report = command_result("工作区操作完成", config, **workspaces.listing(config_path, config), **extra)
            elif options.command == "repair-plan":
                planned = repair.public_plan(repair.plan(config))
                summary = ("请核对修复计划后确认" if planned["actions"]
                           else "Claude 策略组、域名规则和出站模式无需修复；其他隐私项目请查看完整检查。")
                report = command_result(summary, config, **planned)
            elif options.command == "repair":
                applied = repair.apply(config, config_path, options.plan_id)
                report = command_result(applied.pop("summary"), config, **applied)
            elif options.command == "guard-status":
                report = guard_status(config, config_path)
            elif options.command == "pin":
                Surge().pin(config)
                report = full_checks(config)
            elif options.command == "launch":
                report = launch(config, config_path, options.target, options.terminal, arguments)
            else:
                report = full_checks(config)
        if not (getattr(options, "passthrough", False) and report.get("launched") and report.get("ok")):
            emit(report)
        if getattr(options, "passthrough", False) and report.get("launched"):
            status = int(report.get("child_exit_code", 2))
            return status if status >= 0 else 128 - status
        return (int(report.get("child_exit_code", 0)) if report["ok"] else 2)
    except Blocked as exc:
        report = result([row("error", "操作停止", False, str(exc))], config)
        current_workspace = (config or {}).get("workspace")
        error_workspace = (getattr(options, "name", None) or current_workspace
                           if options.command == "workspace" else current_workspace)
        if isinstance(exc, BrowserProfileBusy) and error_workspace == current_workspace:
            report["recovery_action"] = "repair-browser-locks"
        elif (options.command == "browser-locks" and config and
              options.workspace == current_workspace):
            report["recovery_action"] = "repair-browser-locks"
        emit(report)
        return 2
    except (OSError, ValueError, TypeError, KeyError):
        report = result([row("error", "操作停止", False, "遇到未完成的系统操作；未自动更改其他网络设置。")], config)
        emit(report)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
