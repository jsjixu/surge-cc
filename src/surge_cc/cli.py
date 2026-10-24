from __future__ import annotations

import argparse
from contextlib import redirect_stdout, ExitStack
import datetime as dt
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from .core import (
    APP_SUPPORT, CHROME, DEFAULT_CONFIG, Blocked, BrowserProfileBusy, Surge, chrome_args, default_claude,
    load_config, now, provider_environment_ok, proxy_env, result, row, run_checks, save_config, browser_executable,
    global_mode_allowed,
)
from . import workspaces, repair, isolation, keychain_auth
from .guard import run_guarded
from .oauth import OAuthSession


def full_checks(config: dict, browser: bool = True, external_dns: bool = True) -> dict:
    basic = run_checks(config)
    if not basic["ok"]:
        if basic.get("paused") is True:
            # Global proxy mode suspends route enforcement; direct/unknown
            # modes still block. Preserve the exact metadata for each caller.
            return basic
        basic["checks"].append({"id": "privacy_pending", "title": "扩展隐私检测", "status": "unknown",
                                "required": True, "detail": "先修复基础线路；未启动浏览器探针。"})
        return result(basic["checks"], config)
    from .audit import audit_checks
    try:
        extras = audit_checks(config, browser=browser, external_dns=external_dns)
    except Exception:
        extras = [{"id": "audit_error", "title": "扩展检测", "status": "unknown", "required": True,
                   "detail": "扩展检测未完成，不能视为通过。"}]
    report = result(basic["checks"] + extras, config)
    if not report["ok"]:
        try:
            # The optional browser/DNS phase can overlap a deliberate switch
            # to global mode. Only that explicit exception may replace failure.
            if Surge().status().get("mode") == "proxy":
                fresh = run_checks(config)
                if global_mode_allowed(fresh):
                    return fresh
        except (Blocked, AttributeError, TypeError):
            pass
    return report


def oauth_checks(config: dict) -> dict:
    """Check the browser scope plus the entrance actually used by OAuth."""
    from .oauth_gate import verify_proxy_exit
    from .guard import RuntimeChecker
    # OAuth rechecks all mandatory protections before and after opening. Avoid
    # repeating the optional third-party DNS service during that short handshake.
    report = full_checks(config, external_dns=False)
    if report.get("ok") is not True:
        return report
    try:
        verify_proxy_exit(config)
        runtime = RuntimeChecker(config, process=str(browser_executable(config)))
        runtime.check(include_exit=False)
        if runtime.suspended is True:
            return run_checks(config)
    except Blocked:
        # A mode change during the asynchronous probes is intentional only
        # when a fresh, complete global-mode report explicitly allows it.
        fresh = run_checks(config)
        if global_mode_allowed(fresh):
            return fresh
        raise
    return report


def command_result(summary: str, config: dict, **fields) -> dict:
    return {"schema": 1, "ok": True, "summary": summary, "checked_at": now(),
            "checks": [], "settings": config, **fields}


def apply_launch_suspension(report: dict, receipt: dict, target: str) -> bool:
    """A last-moment mode change must not be shown as protected startup."""
    suspended = global_mode_allowed(report)
    if (isinstance(receipt, dict) and receipt.get("schema") == 1 and
            receipt.get("target") == target and receipt.get("state") == "running" and
            receipt.get("ok") is True and receipt.get("suspended") is True and
            receipt.get("protection_active") is False):
        report.update(paused=True, pause_reason="surge-global-mode", surge_mode="proxy",
                      launch_allowed=True, protection_active=False)
        report["checks"] = [item for item in report.get("checks", []) if item.get("id") != "mode"]
        report["checks"].append(row("mode", "规则模式", False,
                                   "启动时已切换到全局代理模式；线路保护挂起，允许启动。"))
        suspended = True
    return suspended


def print_result(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=False))
        return
    print(report["summary"])
    for item in report.get("checks", []):
        marker = {"pass": "✓", "fail": "✗", "unknown": "?", "warn": "!", "info": "·"}.get(item["status"], "?")
        print(f'{marker} {item["title"]}：{item["detail"]}')


def credential_override(name: str) -> bool:
    name = name.upper()
    return (name.startswith("ANTHROPIC_") or name.startswith("CLAUDE_CODE_OAUTH_")
            or name.startswith("CLAUDE_CODE_USE_") or name.startswith("CLAUDE_CODE_API_KEY")
            or name == "CLAUDE_SECURESTORAGE_CONFIG_DIR")


def token_base_environment(values: dict) -> dict:
    """Drop inherited credentials before injecting the explicitly selected one."""
    return {key: value for key, value in values.items() if not credential_override(key)}


def code_settings_ok(config: dict, cwd: Path, env: dict, *, token_auth: bool = False) -> bool:
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
            if not launch_settings_safe(config, settings, token_auth=token_auth):
                return False
        except (OSError, ValueError, AttributeError, TypeError):
            return False
    return True


def launch_settings_safe(config: dict, settings: object, *, token_auth: bool = False) -> bool:
    """Inspect settings without executing hooks; keep protected env immutable."""
    if not isinstance(settings, dict) or settings.get("remoteControlAtStartup") is True:
        return False
    if token_auth and any(key in settings for key in ("apiKeyHelper", "forceLoginMethod", "forceLoginOrgUUID")):
        return False
    values = settings.get("env", {})
    if (not isinstance(values, dict) or
            any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()) or
            not provider_environment_ok(values)):
        return False
    for name, value in values.items():
        if token_auth and credential_override(name):
            return False
        if name.upper() in {"BROWSER", "CLAUDE_CONFIG_DIR"}:
            return False
        if name.upper() in {"DISABLE_UPDATES", "DISABLE_AUTOUPDATER"} and value != "1":
            return False
        if name.lower() in {"http_proxy", "https_proxy", "all_proxy", "npm_config_proxy", "npm_config_https_proxy"} and value != config["proxy_url"]:
            return False
        if name.lower() in {"no_proxy", "npm_config_noproxy"} and value:
            return False
    return True


def validate_launch_arguments(config: dict, arguments: list[str], *, token_auth: bool = False) -> None:
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
                safe = launch_settings_safe(config, json.loads(value), token_auth=token_auth)
            except (ValueError, TypeError):
                safe = False
            if not safe:
                raise Blocked("启动设置必须是有效的内联 JSON，且不能覆盖代理、浏览器或工作区保护。")
        else:
            sources = value.split(",") if value else []
            if not sources or len(set(sources)) != len(sources) or set(sources) - {"user", "project", "local"}:
                raise Blocked("无法确认 Claude 设置来源；只接受 user、project、local。")


def protected_code_arguments(arguments: list[str], config: dict | None = None) -> list[str]:
    """Merge validated inline settings, then force local-only startup in the child.

    The caller must validate each settings object before this transformation.
    Never edit home/project settings; preserve unrelated Orca settings and env.
    """
    settings: dict = {}
    for source, target in (("default_model", "model"), ("default_effort", "effortLevel")):
        if (config or {}).get(source):
            settings[target] = config[source]
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
    # Console browser SSO may live outside CLAUDE_CONFIG_DIR. This account
    # manager deliberately supports claude.ai subscription OAuth/setup-token.
    settings["forceLoginMethod"] = "claudeai"
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


def interactive_paste_enabled(arguments: list[str]) -> bool:
    """Do not alter pipes, print/JSON protocols or maintenance/auth commands."""
    noninteractive = {"-p", "--print", "--input-format", "--output-format", "--version", "-v",
                      "--help", "-h"}
    commands = {"auth", "setup-token", "mcp", "plugin", "plugins", "doctor", "install",
                "update", "upgrade", "agents", "config", "completion"}
    if any(value.split("=", 1)[0] in noninteractive or value in commands
           or (value.startswith("-p") and not value.startswith("--")) for value in arguments):
        return False
    return os.isatty(0) and os.isatty(1)


def launch(config: dict, config_path: Path, target: str, terminal: bool, args: list[str],
           checker=full_checks, popen=subprocess.Popen, terminal_open=terminal_launcher,
           guarded=run_guarded, web_guard=start_web_guard, startup_release=lambda: None) -> dict:
    arguments = args[1:] if args[:1] == ["--"] else args
    isolated = isolation.for_cwd(config_path, Path.cwd()) if target == "code" else None
    if isolated:
        isolated = isolation.bind_workspace(isolated, config_path, config["workspace"])
    token_config = keychain_auth.load(config_path, config["workspace"]) if target == "code" else None
    token_auth = token_config is not None
    if target == "code" and arguments == ["--surge-cc-isolation-check"]:
        if not isolated:
            raise Blocked("当前目录不是已登记的隔离项目。")
        report = isolation.diagnose(isolated, default_claude(), config, config_path, token_auth=token_auth)
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
        # A project/env credential must never silently override the selected
        # workspace, including when that workspace uses native OAuth.
        validate_launch_arguments(config, arguments, token_auth=True)
        if token_auth:
            for index, arg in enumerate(arguments):
                if index > 0 and arguments[index - 1] in {"-p", "--print"}:
                    continue
                if (arg == "setup-token" or arg.split("=", 1)[0] == "--bare"
                        or (arg == "auth" and arguments[index + 1:index + 2] in (["login"], ["logout"]))):
                    raise Blocked("当前使用钥匙串长效 Token；此命令需要先显式切回 OAuth 模式，不会自动打开网页登录。")
        # Only native executable maintenance is blocked. Plugin install/update
        # manage the current isolated plugin directory, not the guarded entry.
        from .development import maintenance_command
        if maintenance_command(arguments):
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
            code_env = token_base_environment(os.environ)
            code_env["CLAUDE_CONFIG_DIR"] = str(workspaces.location(config_path, config["workspace"]) / "data/Claude")
            if not code_settings_ok(config, Path.cwd(), code_env, token_auth=True):
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
    suspended = global_mode_allowed(report)
    if isolated and suspended:
        raise Blocked("隔离开发会话需要 Surge 规则模式；不会跟随全局代理更换出口。")
    if not report.get("ok") and not suspended:
        return report
    if suspended and os.environ.get("SURGE_CC_TERMINAL_ENTRY") == "1":
        print("[Surge CC] 全局代理模式：线路保护已挂起，允许启动；出口由 Surge 全局策略决定。",
              file=sys.stderr)
    loc = workspaces.paths(config_path, config["workspace"])
    if target == "web":
        profile = loc["browser"]
        # Existing sessions may retain old flags; do not silently reuse one.
        if profile.is_symlink():
            raise Blocked("专用网页资料目录异常，未启动浏览器。")
        if os.path.lexists(profile / "SingletonLock"):
            raise BrowserProfileBusy("专用网页窗口仍在运行，或退出后留有锁。可点击检查并修复；不会操作个人 Chrome。")
        # The worker acquires the shared web/OAuth browser lease before writing
        # preferences and retains it through process exit. Preparing here would
        # leave a race between the preference write and detached-worker start.
        receipt = web_guard(config, config_path, chrome_args(config, profile), loc, popen=popen)
        startup_release()
        suspended = apply_launch_suspension(report, receipt, "web")
        report.update(ok=True, launched=True, target="web", summary=(
            "已打开专用网页窗口；全局代理模式下线路保护已挂起，使用 Surge 全局策略"
            if suspended else "已打开独立网页窗口并启动运行期线路监控"))
    elif terminal:
        terminal_open(config_path, arguments, Path.cwd())
        report.update(ok=True, launched=True, target="code-terminal", summary=(
            "已打开终端；终端将再次确认 Surge 模式，全局模式允许启动且挂起线路保护"
            if suspended else "已打开终端；终端将再次检查后启动 Claude Code"))
    else:
        env = (isolation.environment(isolated, config["proxy_url"], token_auth=token_auth) if isolated
               else proxy_env(config["proxy_url"], base=token_base_environment(os.environ)))
        if config.get("default_effort"):
            env.pop("CLAUDE_CODE_EFFORT_LEVEL", None)
        env["CLAUDE_CONFIG_DIR"] = str(isolated.config if isolated else loc["claude"])
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # Native updates replace ~/.local/bin/claude, which is our guarded shim.
        # Scope this to the child; never change the user's global environment.
        env["DISABLE_AUTOUPDATER"] = "1"
        env["DISABLE_UPDATES"] = "1"
        if not isolated and not token_auth:
            env["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = str(keychain_auth.auth_directory(config_path, config["workspace"]))
        if token_auth:
            # Read only after successful route checks. Never place this value in
            # argv, settings, receipts, the child HOME, or a returned report.
            env["CLAUDE_CODE_OAUTH_TOKEN"] = keychain_auth.read_token(token_config)
            if not isolated:
                disabled_storage = loc["claude"] / ".token-auth-disabled"
                if os.path.lexists(disabled_storage):
                    raise Blocked("Token 模式的禁用凭据路径已被占用，未启动；不会回退其他登录。")
                env["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = str(disabled_storage)
            print("[Surge CC] 使用钥匙串长效 Token；不会自动切换登录或打开授权网页。", file=sys.stderr)
        identifier = config["workspace"] + "-" + uuid.uuid4().hex
        folder = (config_path.parent / "sessions").absolute()
        status_path = folder / (identifier + ".status.json")
        receipt_path = folder / (identifier + ".receipt.json")
        oauth_options = {"allow_authorization": False} if token_auth else {}
        with OAuthSession(config, config_path, checker=oauth_checks, **oauth_options) as oauth, ExitStack() as io_stack:
            development_proxy = None
            if isolated:
                from .dev_proxy import Session as DevelopmentProxy, StrictRuntimeChecker
                native_path = str(default_claude())
                development_proxy = io_stack.enter_context(DevelopmentProxy(
                    config, checker=StrictRuntimeChecker(config, process=native_path)))
                # All development tools use the per-launch gate. Internet still
                # has only one upstream; local previews require child ownership.
                env = proxy_env(development_proxy.proxy_url, base=env)
                env["npm_config_proxy"] = env["npm_config_https_proxy"] = development_proxy.proxy_url
                env["npm_config_noproxy"] = ""
                env["NODE_USE_ENV_PROXY"] = "1"
            titles = None
            if isolated:
                from . import orca_titles
                try:
                    binding = orca_titles.bind(isolated)
                    if binding is not None:
                        titles = io_stack.enter_context(orca_titles.Session(binding, isolated))
                except (Blocked, OSError, ValueError):
                    # Optional UI integration must never fall back to the host
                    # hooks, broad credentials or an unisolated Claude launch.
                    print("[Surge CC] Orca 标题通知未连接；文件隔离和线路保护保持启用。", file=sys.stderr)
            paste = None
            if isolated and interactive_paste_enabled(arguments):
                from .pasted_images import ImageImporter
                from .paste_terminal import PasteTerminal
                importer = ImageImporter(isolated.home)
                io_stack.callback(importer.close)
                paste = io_stack.enter_context(PasteTerminal(importer, popen_factory=popen))
            def started(child):
                oauth.set_child(child)
                if development_proxy is not None:
                    development_proxy.set_child(child)
                if titles is not None:
                    titles.set_child(child)
                if paste is not None:
                    paste.start(child)
                startup_release()
            env = oauth.child_environment(env)
            native = default_claude()
            terminal_options = {"terminal_device": Path(paste.tty_path)} if paste is not None else {}
            if development_proxy is not None:
                terminal_options["development_port"] = development_proxy.port
                terminal_options["protected_env"] = {
                    key: value for key, value in env.items()
                    if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy",
                                       "npm_config_proxy", "npm_config_https_proxy", "npm_config_noproxy"}
                    or key in {"BROWSER", "PATH", "NODE_USE_ENV_PROXY"}}
            if titles is not None:
                terminal_options["title_hook"] = titles.hook
                print("[Surge CC] Orca 自动标题已接通，仅通知当前标签页。", file=sys.stderr)
            command = (isolation.command(isolated, native, arguments, oauth.browser_hook,
                                         token_auth=token_auth,
                                         default_model=config.get("default_model", ""),
                                         default_effort=config.get("default_effort", ""),
                                         **terminal_options) if isolated
                       else [str(native), *protected_code_arguments(arguments, config)])
            guard_options = {}
            if paste is not None:
                guard_options["monitor"] = paste.monitor
            if isolated:
                from .dev_proxy import StrictRuntimeChecker
                guard_options["checker"] = StrictRuntimeChecker(config, process=str(native))
                detail = ("当前工作树、同项目 Git 数据和独立 HOME 可用；其他项目与账号保持隔离。"
                          if isolated.worktree else "用户文件仅开放当前副本和独立 HOME，系统工具只读。")
                print(f"[Surge CC] 文件隔离已启用：{isolated.name}；{detail}", file=sys.stderr)
                if not token_auth and env.get("CLAUDE_SECURESTORAGE_CONFIG_DIR"):
                    from . import shared_history
                    detail = ("同项目同账号共享对话；工作树记忆和其他日志仍独立。"
                              if shared_history.enabled(isolated) else "当前工作树的会话、记忆和日志仍独立。")
                    print("[Surge CC] 登录存储共用；" + detail, file=sys.stderr)
            status = guarded(command, env=env, cwd=Path.cwd(),
                             config=config, target="code", status_path=status_path,
                             popen=paste.popen if paste is not None else popen,
                             receipt_path=receipt_path, on_started=started,
                             lock_path=loc["lock"].absolute(), interval=config["guard_interval"],
                             exit_interval=max(30, config["guard_interval"]), **guard_options)
        if isolated:
            from . import isolated_preferences
            try:
                isolated_preferences.record(isolated)
            except Blocked:
                # A completed session remains completed even if an optional UI
                # preference could not be saved. Never retry with wider access.
                report["preferences_warning"] = "未能保存共享界面偏好；当前会话和账号资料未被覆盖。"
                print("[Surge CC] " + report["preferences_warning"], file=sys.stderr)
        try:
            receipt = json.loads(receipt_path.read_text()) if receipt_path.is_file() and not receipt_path.is_symlink() else {}
        except (OSError, ValueError):
            receipt = {}
        launched = (isinstance(receipt, dict) and receipt.get("schema") == 1 and
                    receipt.get("target") == "code" and receipt.get("state") == "running" and
                    receipt.get("ok") is True)
        suspended = apply_launch_suspension(report, receipt, "code")
        report.update(launched=launched, target="code", child_exit_code=status,
                      ok=launched and status == 0,
                      summary=(("Claude Code 会话已结束；启动时全局模式的线路保护处于挂起状态"
                                if suspended else "Claude Code 受监控会话已结束") if status == 0
                               else "Claude Code 已停止；请查看保护状态")
                      if launched else "启动前复核或运行监控未建立，未确认 Claude Code 启动")
        if token_auth:
            report["authentication"] = {"source": "keychain-setup-token", "automatic_browser_login": False}
        if isolated:
            report["file_isolation"] = {"project": isolated.name, "root": str(isolated.root),
                                        "home": str(isolated.home), "backend": "macOS Seatbelt",
                                        "linked_worktree": isolated.worktree is not None,
                                        "shared_login_storage": not token_auth and bool(env.get("CLAUDE_SECURESTORAGE_CONFIG_DIR"))}
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
            fresh = 0 <= age <= max(90, config["guard_interval"] * 3)
            item["running"] = item.get("state") == "running" and fresh
            item["suspended"] = item.get("state") == "suspended" and fresh
            item["protection_active"] = item["running"]
            if item.get("state") in {"running", "suspended"} and not fresh:
                item["detail"] = "状态回执已过期，无法确认监控仍在运行。"
            item["workspace"] = file.name.rsplit("-", 1)[0]
            guards.append(item)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    guards.sort(key=lambda item: item["checked_at"], reverse=True)
    active = [item for item in guards if item["running"]]
    suspended = [item for item in guards if item["suspended"]]
    latest = guards[0] if guards else {}
    overview = {"running": bool(active), "protection_active": bool(active),
                "state": "running" if active else "suspended" if suspended else "inactive",
                "suspended": bool(suspended), "suspended_sessions": len(suspended),
                "interval": config["guard_interval"],
                "last_checked_at": latest.get("checked_at", ""),
                "detail": f"最近 {max(90, config['guard_interval'] * 3)} 秒收到 {len(active)} 个会话的保护回执；"
                          f"另有 {len(suspended)} 个会话挂起线路保护。只覆盖本工具启动的程序，进程当前状态仍可能变化。" if active
                else (f"{len(suspended)} 个会话仍在运行，线路保护因全局代理模式挂起；出口由 Surge 全局策略决定。"
                      if suspended else latest.get("detail", "尚无有效保护回执。启动网页或 CLI 时建立监控。"))}
    return command_result("运行期保护状态", config, guard=overview, guards=guards)


def workspace_inventory(config_path: Path, config: dict) -> dict:
    data = workspaces.listing(config_path, config)
    for item in data["workspaces"]:
        name = item["name"]
        item["auth"] = keychain_auth.status(config_path, name)
        profile = workspaces.location(config_path, name) / "data/Browser/Default"
        item["browser"] = {"has_profile": profile.is_dir() and not profile.is_symlink()}
    return data


def migrate_accounts(config_path: Path, config: dict) -> None:
    # Bind the pre-upgrade credential reference before any account switch.
    # This never reads the token value or clones browser/CLI login databases.
    with workspaces.account_switch(config_path):
        workspaces.assert_current(config_path, config)
        keychain_auth.migrate_legacy(config_path, config["workspace"])


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
    configure.add_argument("--default-model")
    configure.add_argument("--default-effort", choices=("", "low", "medium", "high", "max"))
    configure.add_argument("--browser-start-page", choices=("claude", "newtab"))
    configure.add_argument("--cli-process-path", dest="cli_process_paths", action="append")
    configure.add_argument("--json", action="store_true")
    configure.add_argument("--expected-workspace")
    fix = commands.add_parser("repair")
    fix.add_argument("--plan-id", required=True)
    fix.add_argument("--json", action="store_true")
    workspace = commands.add_parser("workspace")
    workspace.add_argument("action", choices=("list", "create", "use", "snapshot", "restore"))
    workspace.add_argument("--name")
    workspace.add_argument("--label", default="")
    workspace.add_argument("--snapshot")
    workspace.add_argument("--json", action="store_true")
    workspace.add_argument("--close-sessions", action="store_true")
    auth = commands.add_parser("workspace-auth")
    auth.add_argument("action", choices=("status", "store", "oauth"))
    auth.add_argument("--workspace", required=True)
    auth.add_argument("--stdin", action="store_true")
    auth.add_argument("--json", action="store_true")
    browser_locks = commands.add_parser("browser-locks")
    browser_locks.add_argument("action", choices=("repair", "recover"))
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
    maintenance = commands.add_parser("maintenance", help="检查、预览并维护受控 Claude Code 入口")
    maintenance.add_argument("action", choices=("status", "plan", "apply"))
    maintenance.add_argument("--operation", choices=("repair-terminal", "update-claude"))
    maintenance.add_argument("--plan-id")
    maintenance.add_argument("--json", action="store_true")
    updates = commands.add_parser("updates", help="检查、下载校验并安装正式版本")
    updates.add_argument("action", choices=("check", "download", "install"))
    updates.add_argument("--version")
    updates.add_argument("--json", action="store_true")
    orca = commands.add_parser("orca", help="检查 Orca 启动入口")
    orca.add_argument("action", choices=("status", "open-terminal"))
    orca.add_argument("--project")
    orca.add_argument("--json", action="store_true")
    project = commands.add_parser("project", help="预览并建立隔离工程，或管理同范围共享")
    project.add_argument("action", choices=("status", "plan", "apply", "enable", "enable-plan"))
    project.add_argument("--source", type=Path)
    project.add_argument("--name", action="append")
    project.add_argument("--root", type=Path)
    project.add_argument("--plan-id")
    project.add_argument("--trust", action="store_true")
    project.add_argument("--no-shared-history", action="store_true")
    project.add_argument("--no-messaging", action="store_true")
    project.add_argument("--json", action="store_true")
    setup = commands.add_parser("setup", help="首次配置依赖与本机准备")
    setup.add_argument("action", choices=("doctor", "plan", "apply"))
    for flag in ("group", "policy", "expected-ip", "profile", "browser-path", "plan-id"):
        setup.add_argument("--" + flag)
    setup.add_argument("--default-model")
    setup.add_argument("--default-effort", choices=("", "low", "medium", "high", "max"))
    setup.add_argument("--browser-language")
    setup.add_argument("--browser-start-page", choices=("claude", "newtab"))
    setup.add_argument("--json", action="store_true")
    shortcut = commands.add_parser("shortcut", help="安装或打开专用 Dock 入口")
    shortcut.add_argument("action", choices=("install", "open"))
    shortcut.add_argument("--name")
    shortcut.add_argument("--workspace")
    shortcut.add_argument("--start-page", choices=("claude", "newtab"))
    shortcut.add_argument("--app", type=Path)
    shortcut.add_argument("--applications-dir", type=Path)
    shortcut.add_argument("--launcher-config", type=Path)
    shortcut.add_argument("--confirm-switch-from")
    shortcut.add_argument("--json", action="store_true")
    links = commands.add_parser("links", help="Orca 网页分流与原默认浏览器恢复")
    links.add_argument("action", choices=("install", "status", "enable", "disable", "open",
                                        "shell-install", "shell-status", "shell-remove",
                                        "shell-eligible", "shell-open"))
    links.add_argument("--app", type=Path)
    links.add_argument("--applications-dir", type=Path)
    links.add_argument("--router-config", type=Path,
                       default=Path.home() / "Applications/Surge CC Links.app/Contents/Resources/router.json")
    links.add_argument("--confirm-switch-from")
    links.add_argument("--json", action="store_true")
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
    def emit(report, error=None):
        from .remediation import attach
        attach(report, command=options.command, error=error)
        with redirect_stdout(sys.stderr if getattr(options, "passthrough", False) else sys.stdout):
            print_result(report, options.json)
    try:
        config_path = options.config.expanduser().absolute()
        if arguments and options.command != "launch":
            raise Blocked("只有启动命令接受额外参数。")
        if options.command == "links":
            from . import link_router, shortcuts
            if options.action.startswith("shell-"):
                from . import terminal_links
                previous = signal.getsignal(signal.SIGTERM)
                def interrupted_shell_link(*_):
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    raise shortcuts.LauncherStopped("终端网页打开已取消。")
                if options.action == "shell-open":
                    signal.signal(signal.SIGTERM, interrupted_shell_link)
                try:
                    settings = link_router.load(options.router_config)
                    if Path(settings["config"]) != config_path:
                        raise Blocked("终端链接入口的配置不匹配，未打开网页。")
                    if options.action == "shell-eligible":
                        data = terminal_links.eligible(options.router_config)
                    elif options.action == "shell-open":
                        raw = sys.stdin.buffer.read(65537)
                        if len(raw) > 65536:
                            raise Blocked("终端网页请求过长，未打开网页。")
                        data = terminal_links.dispatch(options.router_config, raw)
                    else:
                        operation = {"shell-install": terminal_links.install,
                                     "shell-status": terminal_links.status,
                                     "shell-remove": terminal_links.remove}[options.action]
                        data = operation(options.router_config)
                    if not isinstance(data, dict):
                        raise ValueError("invalid terminal links result")
                except Blocked as exc:
                    data = {"ok": False, "action": "blocked", "message": str(exc), "exit_code": 78}
                except Exception:
                    # Never echo a malformed NUL payload, private URL/query,
                    # command arguments or a raw lower-level exception.
                    data = {"ok": False, "action": "blocked", "message": "终端网页入口无法验证，未打开网页。", "exit_code": 78}
                finally:
                    if options.action == "shell-open":
                        signal.signal(signal.SIGTERM, previous)
                if options.action in {"shell-eligible", "shell-open"}:
                    status = data.get("exit_code")
                    if type(status) is not int or not 0 <= status <= 255:
                        status = 78
                        data = {"ok": False, "action": "blocked", "message": "终端网页入口返回无效结果，未确认打开。", "exit_code": status}
                    if options.action == "shell-open":
                        print(json.dumps(data, ensure_ascii=False))
                    return status
                report = command_result(data.get("message", "终端网页入口操作完成"), {},
                                        links=data, ok=data.get("ok") is True)
                emit(report)
                return 0 if report["ok"] else 2
            if options.action == "open":
                previous = signal.getsignal(signal.SIGTERM)
                def interrupted_link(*_):
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    raise shortcuts.LauncherStopped("网页打开已取消。")
                signal.signal(signal.SIGTERM, interrupted_link)
                try:
                    settings = link_router.load(options.router_config)
                    if Path(settings["config"]) != config_path:
                        raise Blocked("链接入口的配置不匹配，未打开网页。")
                    raw = sys.stdin.read(32769)
                    if len(raw.encode("utf-8")) > 32768:
                        raise ValueError()
                    data = link_router.open_request(options.router_config, json.loads(raw),
                                                    confirmed_from=options.confirm_switch_from)
                except Blocked as exc:
                    data = {"schema": 1, "action": "blocked", "message": str(exc)}
                except Exception:
                    data = {"schema": 1, "action": "blocked", "message": "链接请求无法验证，未打开网页。"}
                finally:
                    signal.signal(signal.SIGTERM, previous)
                print(json.dumps(data, ensure_ascii=False))
                return 0 if data.get("action") in {"focus", "needs_switch", "fallback"} else 2
            if options.action == "install":
                if not options.app:
                    raise Blocked("安装链接分流器需要主应用路径。")
                data = link_router.install(config_path, options.app, applications_dir=options.applications_dir)
            elif options.action == "status":
                data = link_router.status(options.router_config)
            else:
                data = link_router.set_default(options.router_config, restore=options.action == "disable")
            report = command_result("网页分流设置操作完成", {}, links=data)
        elif options.command == "shortcut":
            from . import shortcuts
            if options.action == "open":
                previous = signal.getsignal(signal.SIGTERM)
                def interrupted(*_):
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    raise shortcuts.LauncherStopped("启动已取消。")
                signal.signal(signal.SIGTERM, interrupted)
                try:
                    if not options.launcher_config:
                        raise Blocked("请指定快捷入口资料。")
                    data = shortcuts.open_launcher(options.launcher_config, options.confirm_switch_from,
                                                   expected_config=config_path)
                except Blocked as exc:
                    data = {"schema": 1, "action": "blocked", "message": str(exc)}
                except Exception:
                    data = {"schema": 1, "action": "blocked", "message": "快捷入口资料无法验证，未启动。请重新检查安装。"}
                finally:
                    signal.signal(signal.SIGTERM, previous)
                print(json.dumps(data, ensure_ascii=False))
                return 0 if data.get("action") in {"focus", "needs_switch"} else 2
            if not all((options.name, options.workspace, options.start_page, options.app)):
                raise Blocked("安装快捷入口需要名称、工作区、启动页和主应用路径。")
            data = shortcuts.install(config_path, options.workspace, options.name, options.start_page,
                                     options.app, applications_dir=options.applications_dir)
            report = command_result("专用快捷入口已创建", {}, shortcut=data)
        elif options.command == "setup":
            from . import onboarding
            if options.action == "doctor":
                data = onboarding.doctor(config_path)
            else:
                if not all((options.group, options.policy, options.expected_ip)):
                    raise Blocked("配置计划需要策略组、节点和预期出口 IP。")
                kwargs = dict(profile_path=options.profile, model=options.default_model,
                              effort=options.default_effort, browser_language=options.browser_language,
                              browser_start_page=options.browser_start_page, browser_path=options.browser_path)
                if options.action == "plan":
                    data = onboarding.public_plan(onboarding.plan(config_path, options.group, options.policy,
                                                                  options.expected_ip, **kwargs))
                else:
                    if not options.plan_id:
                        raise Blocked("请先预览，并传入本次配置计划编号。")
                    data = onboarding.apply(config_path, options.plan_id, options.group, options.policy,
                                            options.expected_ip, **kwargs)
            report = command_result("首次配置检查完成" if options.action == "doctor" else "本机准备计划操作完成", {}, setup=data)
            if options.action == "doctor" and data.get("ok") is not True:
                report.update(ok=False, summary="首次配置依赖尚未齐备，请查看检查结果。")
        elif options.command == "project":
            from . import projects
            names = options.name or []
            flags = dict(trust=options.trust, share_history=not options.no_shared_history,
                         local_messaging=not options.no_messaging)
            if options.action == "status":
                data = projects.status(config_path)
            elif options.action in ("enable", "enable-plan"):
                if not names:
                    raise Blocked("请明确选择要启用功能的项目名称。")
                data = (projects.enable(config_path, names, **flags) if options.action == "enable"
                        else projects.preview_enable(config_path, names))
            else:
                if len(names) != 1 or not options.source:
                    raise Blocked("请指定一个源项目目录和一个项目名称。")
                if options.action == "plan":
                    data = projects.plan(config_path, options.source, names[0], root=options.root)
                else:
                    if not options.plan_id:
                        raise Blocked("请先预览，并传入项目计划的 digest。")
                    data = projects.apply(config_path, options.source, names[0], root=options.root,
                                          expected_digest=options.plan_id, **flags)
            report = command_result("项目隔离操作完成", {}, project=data)
        elif options.command == "maintenance":
            from . import maintenance
            config = load_config(config_path)
            if options.action == "status":
                data = maintenance.status(config_path)
                report = command_result(data.get("summary", "维护检查完成"), config, maintenance=data)
            elif options.action == "plan":
                if not options.operation:
                    raise Blocked("请先选择要预览的维护操作。")
                data = maintenance.plan(config_path, options.operation)
                report = command_result(data.pop("summary", "请确认维护计划"), config, **data)
            else:
                if not options.plan_id:
                    raise Blocked("请先预览维护计划，再执行对应计划。")
                data = maintenance.apply(config_path, options.plan_id)
                report = command_result(data.pop("summary", "维护完成，请重新检查线路"), config, maintenance=data)
        elif options.command == "updates":
            from . import updates
            config = load_config(config_path) if config_path.exists() else {}
            if options.action == "check":
                data = updates.check(config_path)
            else:
                if not options.version:
                    raise Blocked("请先选择正式版本。")
                data = (updates.download(config_path, options.version) if options.action == "download"
                        else updates.install(config_path, options.version))
            report = command_result(data.get("summary", "版本检查完成"), config, update=data)
        elif options.command == "orca":
            from . import orca_integration
            config = load_config(config_path)
            if options.action == "status":
                data = orca_integration.integration_status(config_path)
            else:
                if not options.project:
                    raise Blocked("请明确选择 Orca 工作区后打开受控终端。")
                data = orca_integration.open_protected_terminal(config_path, options.project)
            report = command_result(data.get("summary", "Orca 入口检查完成"), config, orca=data, ok=data.get("ok") is True)
        elif options.command == "terminal":
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
            if (options.expected_workspace is not None and
                    options.expected_workspace != existing.get("workspace", "A")):
                raise Blocked("设置窗口对应的工作区已改变，请刷新后再保存。")
            candidate = {**existing,
                "schema": 1, "group": options.group, "policy": options.policy,
                "expected_ip": options.expected_ip, "proxy_url": options.proxy_url,
                "profile_path": options.profile,
            }
            for key in ("expected_timezone", "expected_locale", "expected_country", "expected_asn", "browser_language", "browser_path", "guard_interval", "default_model", "default_effort", "browser_start_page", "cli_process_paths"):
                if getattr(options, key) is not None:
                    candidate[key] = getattr(options, key)
            if options.privacy_strict is not None:
                candidate["privacy_strict"] = options.privacy_strict == "true"
            config = workspaces.save_settings(config_path, candidate)
            report = {"schema": 1, "ok": True, "summary": "配置已保存，尚未检查",
                      "checked_at": now(), "checks": [], "settings": config}
        else:
            config = load_config(config_path)
            migrate_accounts(config_path, config)
            if options.command == "browser-locks":
                # A stale GUI response must never target a newly selected workspace.
                if options.workspace != config["workspace"]:
                    raise Blocked("当前工作区已变更，请刷新后检查当前工作区的浏览器锁。")
                from . import browser_locks
                recover = browser_locks.recover if options.action == "recover" else browser_locks.repair
                recovery = recover(config_path, options.workspace)
                report = command_result(recovery["message"], config, recovery=recovery)
            elif options.command == "workspace":
                name = options.name or config["workspace"]
                extra = {}
                if options.action == "create":
                    workspaces.create(config_path, name, options.label)
                elif options.action == "use":
                    from . import sessions, workspace_routes
                    config = workspaces.use(
                        config_path, config, name,
                        stop_sessions=sessions.stop_workspace if options.close_sessions else None,
                        apply_route=lambda old, target: workspace_routes.activate(config_path, old, target))
                elif options.action == "snapshot":
                    extra["snapshot"] = workspaces.snapshot(config_path, name, options.label)
                elif options.action == "restore":
                    if not options.snapshot:
                        raise Blocked("请选择快照编号后再恢复。")
                    extra.update(workspaces.restore(config_path, name, options.snapshot))
                report = command_result("工作区操作完成；网页和 CLI 的下一次启动使用当前账号环境", config,
                                        **workspace_inventory(config_path, config), **extra)
            elif options.command == "workspace-auth":
                name = workspaces.name_ok(options.workspace)
                if options.action == "store" and not options.stdin:
                    raise Blocked("Token 只能从安全输入读取，不能放入命令参数。")
                with workspaces.account_switch(config_path):
                    workspaces.assert_current(config_path, config)
                    # Inactive accounts may be configured; live sessions must
                    # finish before their credential reference can change.
                    if options.action != "status":
                        with workspaces.exclusive(config_path, name):
                            if options.action == "store":
                                raw = sys.stdin.buffer.read(keychain_auth.MAX_TOKEN + 3)
                                try:
                                    token = raw.decode("ascii").rstrip("\r\n")
                                except UnicodeError:
                                    raise Blocked("Token 格式不正确，未保存。") from None
                                keychain_auth.store_token(config_path, name, token)
                                del token, raw
                            else:
                                keychain_auth.configure_oauth(config_path, name)
                report = command_result("工作区登录方式已更新；没有发起登录或授权" if options.action != "status"
                                        else "工作区登录方式", config,
                                        **workspace_inventory(config_path, config))
            elif options.command == "repair-plan":
                planned = repair.public_plan(repair.plan(config))
                summary = ("请核对修复计划后确认" if planned["actions"]
                           else "Claude 策略组、域名规则和出站模式无需修复；其他隐私项目请查看完整检查。")
                report = command_result(summary, config, **planned)
            elif options.command == "repair":
                with workspaces.account_switch(config_path):
                    workspaces.assert_current(config_path, config)
                    applied = repair.apply(config, config_path, options.plan_id)
                report = command_result(applied.pop("summary"), config, **applied)
            elif options.command == "guard-status":
                report = guard_status(config, config_path)
            elif options.command == "pin":
                with workspaces.account_switch(config_path):
                    workspaces.assert_current(config_path, config)
                    Surge().pin(config)
                    report = full_checks(config)
            elif options.command == "launch":
                with workspaces.account_session(config_path, config) as release:
                    report = launch(config, config_path, options.target, options.terminal, arguments,
                                    startup_release=release)
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
            report["recovery_action"] = "recover-browser"
        elif (options.command == "browser-locks" and config and
              options.workspace == current_workspace):
            report["recovery_action"] = ("recover-browser" if options.action == "recover"
                                         else "repair-browser-locks")
        emit(report)
        return 2
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report = result([row("error", "操作停止", False, "遇到未完成的系统操作；未自动更改其他网络设置。")], config)
        emit(report, error=exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
