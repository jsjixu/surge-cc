"""Read-only Orca diagnostics and an explicit, local protected-terminal entry.

Orca's Native Chat and managed-account stores are independent of Surge CC's
workspaces. We never silently treat their account selector as our A/B selector,
read credentials, or change Orca's global settings. The fallback uses Orca's
documented terminal API and the verified absolute Claude shim, so a custom
agent executable or shell alias cannot skip Surge CC's launch gate.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys

from .core import Blocked, now
from . import terminal

_MAX_OUTPUT = 1024 * 1024
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?")
_HANDLE = re.compile(r"term_[A-Za-z0-9_-]{1,100}")


def _local_env() -> dict:
    # A GUI inherited from a remote Orca terminal must still target this Mac.
    return {key: value for key, value in os.environ.items()
            if key not in {"ORCA_ENVIRONMENT", "ORCA_PAIRING_CODE"}}


def _cli_path(explicit=None) -> Path:
    if explicit is not None:
        candidate = str(explicit)
    elif os.environ.get("ORCA_CLI_COMMAND"):
        candidate = os.environ["ORCA_CLI_COMMAND"]
    elif os.environ.get("ORCA_DEV_REPO_ROOT"):
        candidate = shutil.which("orca-dev") or ""
    else:
        candidate = shutil.which("orca" if sys.platform == "darwin" else "orca-ide") or ""
        # Finder launch services do not inherit the interactive shell PATH.
        if not candidate and sys.platform == "darwin":
            candidate = "/usr/local/bin/orca"
    if not candidate or any(ord(c) < 32 for c in candidate):
        raise Blocked("未找到 Orca 命令行入口；请先安装或更新 Orca。")
    path = Path(candidate).expanduser()
    if not path.is_absolute():
        resolved = shutil.which(candidate)
        if not resolved:
            raise Blocked("Orca 命令行入口不可用；未尝试其他客户端。")
        path = Path(resolved)
    try:
        path = path.resolve(strict=True)
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK)
                or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022):
            raise OSError("unsafe executable")
    except (OSError, ValueError):
        raise Blocked("Orca 命令行入口不可用或权限不安全。") from None
    return path


def _request(cli: Path, args: list[str], runner, *, timeout: int = 10) -> dict:
    try:
        completed = runner([str(cli), *args, "--json"], capture_output=True,
                           text=True, timeout=timeout, env=_local_env())
        if (completed.returncode != 0 or not isinstance(completed.stdout, str)
                or len(completed.stdout) > _MAX_OUTPUT):
            raise ValueError("request failed")
        payload = json.loads(completed.stdout)
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise ValueError("invalid response")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise ValueError("invalid result")
        return result
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
        # Orca errors/output may include terminal text, local paths or tokens.
        raise Blocked("无法确认 Orca 操作结果；请检查 Orca 是否运行。未自动重复启动。") from None


def _installation(config_path: Path, *, state_dir=None) -> dict:
    data = terminal.status(state_dir=state_dir)
    if data.get("ok") is not True or data.get("installed") is not True:
        raise Blocked("Claude 终端接管尚未就绪；请先在维护中心检查并修复终端入口。")
    try:
        manifest = terminal._read(terminal._state_dir(state_dir))
        terminal._verify_active(manifest)
        if Path(manifest["config_path"]) != Path(config_path).absolute():
            raise Blocked("终端入口绑定了另一份配置；请修复为当前 Surge CC 配置后重试。")
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise Blocked("无法验证 Claude 终端接管记录。") from None
    return manifest


def integration_status(config_path: Path, *, cli_path=None, state_dir=None,
                       runner=subprocess.run) -> dict:
    """Never launch Orca/Claude, inspect terminal history, or access credentials."""
    checks = []
    installed = False
    try:
        _installation(config_path, state_dir=state_dir)
        installed = True
        checks.append({"id": "orca_shim", "title": "Claude 受控入口", "status": "pass",
                       "detail": "当前入口与 Surge CC 配置一致；启动后仍需实时检查线路。"})
    except Blocked as error:
        checks.append({"id": "orca_shim", "title": "Claude 受控入口", "status": "fail",
                       "detail": str(error), "action": "repair-terminal"})
    available = running = False
    version = None
    try:
        cli = _cli_path(cli_path)
        available = True
        result = _request(cli, ["status"], runner)
        target = result.get("target", {})
        runtime = result.get("runtime", {})
        if not isinstance(target, dict) or target.get("kind") != "local" or not isinstance(runtime, dict):
            raise Blocked("Orca 未返回本机运行状态；未确认远端环境接管。")
        running = runtime.get("reachable") is True
        raw_version = runtime.get("appVersion")
        version = raw_version if isinstance(raw_version, str) and _VERSION.fullmatch(raw_version) else None
        checks.append({"id": "orca_runtime", "title": "Orca 本机连接",
                       "status": "pass" if running else "info",
                       "detail": "Orca 正在运行。" if running else "Orca 尚未运行；打开受控终端时会启动它。"})
    except Blocked as error:
        checks.append({"id": "orca_runtime", "title": "Orca 本机连接", "status": "warn", "detail": str(error)})
    modes = [
        {"id": "protected-terminal", "title": "从 Surge CC 打开 Orca 受控终端",
         "status": "pass" if installed and available else "fail",
         "detail": "使用已核验的绝对命令路径，不依赖 Orca 自定义启动路径或 shell alias。"},
        {"id": "shell", "title": "Orca 内置终端直接输入 claude", "status": "info",
         "detail": "发布前已在 Orca 1.4.237 实测；仍须解析到被接管入口，自定义别名或路径需单独确认。"},
        {"id": "new-agent-terminal", "title": "Orca 新建 Claude（终端模式）", "status": "info",
         "detail": "发布前已实测 Orca 1.4.237 标准终端启动路径进入检查；自定义可执行路径需单独确认。"},
        {"id": "native-chat", "title": "Orca Native Chat", "status": "info",
         "detail": "发布前已在 Orca 1.4.237 实测标准新建聊天和最小请求经过受控入口；恢复旧聊天和托管账号需单独确认。"},
        {"id": "managed-account", "title": "Orca 管理的账号", "status": "warn",
         "detail": "Orca 账号选择不等于 Surge CC A/B；受控启动以 Surge CC 当前工作区为准，不导入 Orca 凭据。"},
        {"id": "remote", "title": "远端 Orca / SSH", "status": "warn",
         "detail": "本机接管不覆盖其他机器；需在目标机器单独配置和验证。"},
    ]
    ready = installed and available and not any(item["status"] == "warn" for item in checks)
    return {"schema": 1, "ok": ready, "checked_at": now(),
            "summary": "Orca 受控终端入口可用" if ready else "Orca 入口需要处理",
            "installed": installed, "available": available, "running": running,
            "version": version, "checks": checks, "modes": modes,
            "launch_ready": ready, "action": "open-orca-terminal" if ready else "repair-terminal"}


def open_protected_terminal(config_path: Path, project_path: Path, *, cli_path=None,
                            state_dir=None, runner=subprocess.run) -> dict:
    """Create one new local terminal. It does not send to any existing session.

    A successful Orca receipt proves only terminal creation; the shim performs
    the actual route check inside the new terminal. Never report connection or
    authentication success here, and never retry an ambiguous creation.
    """
    project = Path(project_path)
    if not project.is_absolute() or any(ord(c) < 32 for c in str(project)):
        raise Blocked("请选择已有 Orca 项目的绝对目录。")
    try:
        project = project.resolve(strict=True)
        if not project.is_dir():
            raise OSError("not a directory")
    except (OSError, ValueError):
        raise Blocked("所选项目目录不存在。") from None
    manifest = _installation(config_path, state_dir=state_dir)
    cli = _cli_path(cli_path)
    state = _request(cli, ["status"], runner)
    target, runtime = state.get("target", {}), state.get("runtime", {})
    if not isinstance(target, dict) or target.get("kind") != "local" or not isinstance(runtime, dict):
        raise Blocked("只能为本机 Orca 打开受控终端。")
    if runtime.get("reachable") is not True:
        _request(cli, ["open"], runner, timeout=30)
    workspace = _request(cli, ["worktree", "show", "--worktree", "path:" + str(project)], runner)
    record = workspace.get("worktree", {})
    if (not isinstance(record, dict) or record.get("hostId") != "local"
            or record.get("path") != str(project)):
        raise Blocked("所选目录不是已登记的本机 Orca 工作区；请先在 Orca 中打开该项目。")
    # Recheck the shim after Orca startup/discovery, before putting a command in
    # a terminal. Explicit shell quoting handles spaces and metacharacters.
    manifest = _installation(config_path, state_dir=state_dir)
    command = shlex.quote(manifest["command_path"])
    result = _request(cli, ["terminal", "create", "--worktree", "path:" + str(project),
                           "--title", "Surge CC", "--command", command, "--focus"], runner, timeout=30)
    receipt = result.get("terminal", {})
    handle = receipt.get("handle") if isinstance(receipt, dict) else None
    if (not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
            or receipt.get("executionHostId") != "local"):
        raise Blocked("Orca 可能已创建终端，但回执不完整；请查看 Orca，未重复启动。")
    return {"schema": 1, "ok": True, "checked_at": now(), "handle": handle,
            "summary": "已创建 Orca 受控终端；终端内将检查线路后启动 Claude。",
            "launched": False, "terminal_created": True, "route_checked": False}
