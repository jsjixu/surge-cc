"""Project-scoped development integrations inside the existing Seatbelt.

These helpers do not launch an unguarded session. The child ``claude`` command
only manages plugins or prints help; it inherits the parent's OS sandbox and
process group. Real HOME, host hooks and host credentials are never consulted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from .core import Blocked


# Native global options whose next argv item is data, not a subcommand. Unknown
# flags do not consume a word: fail closed for an unfamiliar maintenance form.
_VALUE_OPTIONS = frozenset({
    "--agent", "--agents", "--append-system-prompt", "--append-system-prompt-file",
    "--autocompact", "--debug-file", "--effort", "--input-format", "--json-schema",
    "--max-budget-usd", "--model", "--name", "-n", "--output-format",
    "--permission-mode", "--permission-prompts", "--permission-prompt-tool",
    "--session-id", "--setting-sources", "--settings", "--system-prompt",
    "--system-prompt-file", "--system-prompt-snapshot", "--fallback-model",
    "--remote-control-session-name-prefix", "--allowedTools", "--allowed-tools",
    "--disallowedTools", "--disallowed-tools", "--tools", "--betas", "--file",
    "--add-dir", "--mcp-config", "--plugin-dir", "--plugin-url",
})
_OPTIONAL_VALUE_OPTIONS = frozenset({"--debug", "-d", "--resume", "-r", "--from-pr", "--prompt-suggestions"})
_NATIVE_COMMANDS = frozenset({
    "agents", "attach", "auth", "auto-mode", "doctor", "gateway", "import", "install",
    "logs", "mcp", "plugin", "plugins", "purge", "respawn", "rm", "setup-token",
    "stop", "kill", "ultrareview", "update", "upgrade", "remote-control", "rc",
})


def top_level_command(values: list[str]) -> str | None:
    """Return a native positional command, excluding flags and print prompts."""
    index = 0
    printing = False
    while index < len(values):
        value = values[index]
        if value == "--":
            return None
        flag, separator, _ = value.partition("=")
        if flag in {"--print", "-p"} or (value.startswith("-p") and not value.startswith("--")):
            printing = True
        elif not value.startswith("-"):
            return None if printing else value
        elif flag in _OPTIONAL_VALUE_OPTIONS and not separator:
            # Optional filters cannot swallow a following native subcommand
            # (or another flag). In ambiguous maintenance forms, fail closed.
            following = values[index + 1:index + 2]
            if following and not following[0].startswith("-") and following[0] not in _NATIVE_COMMANDS:
                index += 1
        elif flag in _VALUE_OPTIONS and not separator:
            index += 1
        index += 1
    return None


def maintenance_command(values: list[str]) -> bool:
    """Plugin install/update are not native executable maintenance commands."""
    return top_level_command(values) in {"install", "update", "upgrade"}


_PROTECTED_ENV = frozenset({
    "HOME", "CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR", "BROWSER",
    "TMPDIR", "CLAUDE_CODE_TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
    "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "CLAUDE_CODE_PROJECT_DIR_NAME",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NPM_CONFIG_PROXY",
    "NPM_CONFIG_HTTPS_PROXY", "NPM_CONFIG_NOPROXY", "DISABLE_UPDATES",
    "DISABLE_AUTOUPDATER", "NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO", "GIT_CONFIG", "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
})


def protected_environment_name(name: str) -> bool:
    upper = name.upper()
    return (upper in _PROTECTED_ENV or upper.startswith((
        "ANTHROPIC_", "CLAUDE_CODE_OAUTH_", "CLAUDE_CODE_USE_", "CLAUDE_CODE_API_KEY",
        "DYLD_", "SURGE_CC_", "ORCA_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")))


def _read_settings(path: Path, roots: tuple[Path, ...]) -> dict:
    if not os.path.lexists(path):
        return {}
    # Do not follow a project setting symlink into another account/project.
    try:
        resolved = path.resolve(strict=True)
        if resolved != path or not any(resolved == root or root in resolved.parents for root in roots):
            raise ValueError("settings path escapes scope")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
            raise ValueError("invalid settings file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "r") as stream:
            value = json.load(stream)
        if not isinstance(value, dict):
            raise ValueError("settings must be object")
        return value
    except (OSError, ValueError, TypeError):
        raise Blocked("当前隔离环境的 Claude 设置无效或路径越界，未加载宿主设置。") from None


def validate_settings(project) -> list[Path]:
    """Check only new account HOME and this worktree, never real HOME/parents.

    Native watches these files after startup. Highest-priority inline fixed
    settings below remain authoritative; Seatbelt remains the file/network
    boundary even for hooks and plugins that run arbitrary commands.
    """
    roots = (project.home, project.root)
    paths = [project.config / "settings.json", project.config / "settings.local.json",
             project.root / ".claude/settings.json", project.root / ".claude/settings.local.json"]
    for path in paths:
        value = _read_settings(path, roots)
        if any(key in value for key in ("apiKeyHelper", "forceLoginMethod", "forceLoginOrgUUID")):
            raise Blocked("隔离设置不能覆盖当前账号的鉴权方式；请使用 Surge CC 管理账号。")
        if value.get("remoteControlAtStartup") or value.get("autoUploadSessions"):
            raise Blocked("隔离设置不能自动开启远程控制或会话上传。")
        env = value.get("env", {})
        if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
            raise Blocked("隔离设置的 env 必须是字符串映射。")
        if any(protected_environment_name(key) for key in env):
            raise Blocked("隔离设置不能覆盖账号、代理、浏览器或隔离目录；普通开发环境变量仍可使用。")
    return paths


def runtime_settings(project, fixed_settings: dict, protected_env: dict | None = None) -> dict:
    """Keep title hooks/startup defaults while admitting scoped native settings.

    Pass this as native ``--settings`` together with
    ``--setting-sources user,project,local``. Native merges hook arrays, so the
    Orca title bridge is appended rather than replacing ordinary plugin hooks.
    The caller must still supply --strict-mcp-config with an empty MCP map and
    --no-chrome: MCP/unsandboxed host integrations are not opened by this change.
    """
    validate_settings(project)
    result = dict(fixed_settings)
    result.update(disableAllHooks=False, remoteControlAtStartup=False,
                  disableRemoteControl=True, autoUploadSessions=False,
                  forceLoginMethod="claudeai")
    # Do not place tokens in argv/settings, including the setup OAuth token.
    # Only the already-selected inherited account can supply credentials.
    copied = {key: value for key, value in (protected_env or {}).items()
              if key.upper() in _PROTECTED_ENV and "TOKEN" not in key.upper()}
    copied.update(HOME=str(project.home), CLAUDE_CONFIG_DIR=str(project.config),
                  DISABLE_UPDATES="1", DISABLE_AUTOUPDATER="1")
    result["env"] = copied
    return result


_SHIM_TEMPLATE = r'''#!__PYTHON__
# Surge CC isolated development entry. Not a general unguarded Claude launcher.
import ctypes, json, os, sys
NATIVE = __NATIVE__
HOME = __HOME__
CONFIG = __CONFIG__
args = sys.argv[1:]
bad = {"--settings", "--setting-sources", "--managed-settings", "--mcp-config",
       "--plugin-dir", "--plugin-dir-no-mcp", "--plugin-url", "--chrome", "--ide",
       "--remote-control", "--remote", "--teleport", "--cloud", "--environment",
       "--desktop", "--bg", "--background", "--tmux", "--add-dir", "--worktree", "-w"}
management = {"configure", "details", "disable", "enable", "help", "init", "new", "install", "i", "list",
              "marketplace", "prune", "autoremove", "tag", "uninstall", "remove", "update", "validate", "--help", "-h"}
allowed = bool(args) and (args in (["--help"], ["-h"], ["--version"], ["-v"]) or
    (args[0] in ("plugin", "plugins") and (len(args) == 1 or args[1] in management)))
if not allowed or any(arg.split("=", 1)[0] in bad for arg in args):
    print("Surge CC: 此隔离内命令只支持 plugin 管理与 --help/--version；新会话请从 Orca/Ghostty 的受控入口启动。", file=sys.stderr)
    sys.exit(64)
try:
    library = ctypes.CDLL("/usr/lib/libsandbox.dylib", use_errno=True)
    check = library.sandbox_check
    check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    check.restype = ctypes.c_int
    if check(os.getpid(), None, 0) != 1:
        raise RuntimeError("not sandboxed")
except Exception:
    print("Surge CC: 此插件命令只能在已启动的隔离会话内使用；请从 Orca/Ghostty 的受控 claude 入口运行。", file=sys.stderr)
    sys.exit(77)
os.environ["HOME"] = HOME
os.environ["CLAUDE_CONFIG_DIR"] = CONFIG
os.environ["DISABLE_UPDATES"] = "1"
os.environ["DISABLE_AUTOUPDATER"] = "1"
fixed = {"remoteControlAtStartup": False, "disableRemoteControl": True,
         "autoUploadSessions": False, "forceLoginMethod": "claudeai"}
# Runtime proxy/browser values are inherited from this exact parent launch;
# no token, broad Orca capability, or host configuration is stored in this file.
names = __ENV_NAMES__
fixed["env"] = {key: value for key, value in os.environ.items() if key.upper() in names}
os.execve(NATIVE, [NATIVE, "--setting-sources", "user,project,local", "--settings", json.dumps(fixed),
                  "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--no-chrome", *args], os.environ)
'''


def prepare(project, native: Path, *, python: Path | None = None) -> Path:
    """Create a local command helper; call only after HOME has been validated.

    The parent has already verified native's identity/containment. This helper
    repeats basic path checks and never discovers native through PATH or reads
    the host terminal manifest. Add ``home/.local/bin`` to the child's PATH.
    """
    native = Path(native)
    python = Path(sys.executable).resolve() if python is None else Path(python)
    try:
        for executable in (native, python):
            if (not executable.is_absolute() or executable.resolve(strict=True) != executable
                    or not executable.is_file() or not os.access(executable, os.X_OK)
                    or "\n" in str(executable)):
                raise ValueError("invalid executable")
        if project.home.resolve(strict=True) != project.home:
            raise ValueError("invalid home")
        target = project.home / ".local/bin/claude"
        for folder in (project.home / ".local", target.parent):
            if os.path.lexists(folder):
                if folder.is_symlink() or not folder.is_dir() or folder.resolve(strict=True) != folder:
                    raise ValueError("invalid local bin")
            else:
                folder.mkdir(mode=0o700)
        if os.path.lexists(target) and (target.is_symlink() or not target.is_file()):
            raise ValueError("invalid command entry")
        source = (_SHIM_TEMPLATE.replace("__PYTHON__", str(python))
                  .replace("__NATIVE__", repr(str(native)))
                  .replace("__HOME__", repr(str(project.home)))
                  .replace("__CONFIG__", repr(str(project.config)))
                  .replace("__ENV_NAMES__", repr(sorted(_PROTECTED_ENV))))
        fd, temporary = tempfile.mkstemp(prefix=".claude-", dir=target.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(source)
            os.chmod(temporary, 0o700)
            os.replace(temporary, target)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
        return target
    except (OSError, ValueError, TypeError):
        raise Blocked("无法准备隔离环境的 Claude 插件命令，未调用宿主入口。") from None
