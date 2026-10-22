"""Opt-in, deny-by-default filesystem boundary for registered project copies.

The trusted launcher and OAuth broker stay outside Seatbelt. Only the native
Claude process and its descendants enter it. This is not a machine-wide policy.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import fcntl
import os
from pathlib import Path
import re
import stat
import sys
import subprocess
import tempfile

from .core import Blocked, proxy_env


DEFAULT_ROOT = Path.home() / "Documents/Codex/Claude-Isolated"
ORCA_WORKSPACES = Path.home() / "orca/workspaces"
REGISTRY_NAME = "isolation.json"
MARKER_NAME = ".surge-cc-isolated.json"
SANDBOX = Path("/usr/bin/sandbox-exec")


def within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def clean_path(path: Path) -> Path:
    path = Path(path).absolute()
    if path.resolve() != path or not path.is_dir():
        raise Blocked("隔离目录不存在或经过软链接，已阻止启动。")
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o022:
        raise Blocked("隔离目录所有者或写入权限不安全，已阻止启动。")
    return path


@dataclass(frozen=True)
class LinkedWorktree:
    main_root: Path
    git_dir: Path

    @property
    def common_dir(self) -> Path:
        return self.main_root / ".git"


@dataclass(frozen=True)
class Project:
    name: str
    root: Path
    home: Path
    worktree: LinkedWorktree | None = None
    workspace: str | None = None
    workspace_config: Path | None = None
    original_home: Path | None = None

    @property
    def config(self) -> Path:
        return self.home / ".claude"

    @property
    def registered_root(self) -> Path:
        return self.worktree.main_root if self.worktree else self.root

    @property
    def base(self) -> Path:
        return self.registered_root.parent.parent


def bind_workspace(project: Project, config_path: Path, workspace: str) -> Project:
    """Bind project auth to the active account without moving legacy A data.

    Existing project HOME remains with the recorded pre-migration workspace.
    Other accounts get fresh per-project/per-worktree HOME and session data.
    The original project source files are shared deliberately.
    """
    from . import keychain_auth
    try:
        workspace = keychain_auth._workspace(workspace)
        config_path = Path(config_path).absolute()
        keychain_auth._config_root(config_path)
        owner = keychain_auth.legacy_workspace(config_path)
        if owner is None:
            raise ValueError("account migration must precede launch")
        original = project.original_home or project.home
        if project.workspace is not None and (project.workspace != workspace or project.workspace_config != config_path):
            raise ValueError("project already bound to a different account")
        home = original if workspace == owner else original.parent / "accounts" / workspace / "home"
        _validate_runtime(home, project.base, create=False)
        return replace(project, home=home, workspace=workspace,
                       workspace_config=config_path, original_home=original)
    except (OSError, ValueError, TypeError):
        raise Blocked("隔离项目的工作区身份无法验证，已阻止启动；不会使用其他账号目录。") from None


def _expected_home(project: Project, original: Path) -> Path:
    if project.workspace is None:
        return original
    from . import keychain_auth
    keychain_auth._workspace(project.workspace)
    if project.workspace_config is None or project.original_home != original:
        raise ValueError("invalid bound project metadata")
    owner = keychain_auth.legacy_workspace(project.workspace_config)
    if owner is None:
        raise ValueError("missing account migration owner")
    return original if project.workspace == owner else original.parent / "accounts" / project.workspace / "home"


def _safe_file(path: Path, *, private: bool = False, limit: int = 16384) -> str:
    """Read bounded, owned metadata without following a replaced final symlink."""
    path = path.absolute()
    if path.resolve() != path:
        raise ValueError("metadata symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022)
                or info.st_size > limit):
            raise ValueError("unsafe metadata file")
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise ValueError("metadata file too large")
        # The open descriptor and directory entry must still name the same file.
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("metadata changed while reading")
        return raw.decode("utf-8")
    finally:
        os.close(fd)


def _git_path(path: Path, *, prefix: str = "") -> Path:
    text = _safe_file(path)
    if text.endswith("\n"):
        text = text[:-1]
    if not text.startswith(prefix):
        raise ValueError("invalid git pointer")
    value = text[len(prefix):]
    if not value or any(c in value for c in "\x00\r\n"):
        raise ValueError("invalid git pointer")
    target = Path(value)
    if not target.is_absolute():
        target = path.parent / target
    # Git supports relative linkage. Normalize '..', but never accept symlinks.
    normalized = Path(os.path.abspath(target))
    if normalized.resolve() != normalized:
        raise ValueError("git pointer traverses a symlink")
    return normalized


def _worktree_home(base: Path, name: str, root: Path, git_dir: Path) -> Path:
    key = hashlib.sha256(os.fsencode(root) + b"\0" + os.fsencode(git_dir)).hexdigest()
    return base / ".runtime" / name / "worktrees" / key / "home"


def _check_tree_path(path: Path, root: Path) -> None:
    if not within(path, root):
        raise ValueError("path outside validated tree")
    for folder in (path, *path.parents):
        clean_path(folder)
        if folder == root:
            break


def _optional_git_entry(path: Path, *, directory: bool = False) -> None:
    if os.path.lexists(path):
        if directory:
            clean_path(path)
        else:
            # Contents need not be text (the index is binary).
            if path.resolve() != path:
                raise ValueError("git metadata symlink")
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError("unsafe git metadata")


def _git_access(worktree: LinkedWorktree) -> tuple[list[Path], list[Path], list[Path]]:
    """Only repository data and this worktree's metadata; never hooks or siblings."""
    common, admin = worktree.common_dir, worktree.git_dir
    dirs = [common / "objects", common / "refs", admin / "refs"]
    files = [common / name for name in (
        "HEAD", "config", "config.worktree", "packed-refs", "shallow", "info/grafts", "info/exclude")]
    files += [admin / name for name in (
        "HEAD", "index", "commondir", "gitdir", "config.worktree", "ORIG_HEAD", "FETCH_HEAD",
        "MERGE_HEAD", "MERGE_MSG", "MERGE_MODE", "CHERRY_PICK_HEAD", "REVERT_HEAD",
        "AUTO_MERGE", "shallow", "info/sparse-checkout", "logs/HEAD")]
    writes = [admin / "index", admin / "index.lock"]
    return dirs, files, writes


def _validate_worktree(root: Path, name: str, main_root: Path) -> LinkedWorktree:
    clean_path(root)
    # Restrict automatic admission to Orca's two-component workspace layout.
    if root.parent.parent != ORCA_WORKSPACES.absolute():
        raise ValueError("not an Orca workspace")
    _check_tree_path(root, ORCA_WORKSPACES.absolute())
    marker = json.loads(_safe_file(root / MARKER_NAME))
    if (not isinstance(marker, dict) or marker.get("schema") != 1
            or marker.get("project") != name or marker.get("requires_registered_launcher") is not True):
        raise ValueError("worktree marker mismatch")
    clean_path(main_root)
    common = clean_path(main_root / ".git")
    worktrees = clean_path(common / "worktrees")
    admin = _git_path(root / ".git", prefix="gitdir: ")
    if admin.parent != worktrees:
        raise ValueError("gitdir is not an immediate registered worktree")
    clean_path(admin)
    if _git_path(admin / "commondir") != common:
        raise ValueError("common repository mismatch")
    if _git_path(admin / "gitdir") != root / ".git":
        raise ValueError("worktree backlink mismatch")
    result = LinkedWorktree(main_root, admin)
    dirs, files, writes = _git_access(result)
    for directory in dirs:
        _optional_git_entry(directory, directory=True)
    # Validate intermediate metadata directories even for currently absent leaves.
    for directory in (common / "info", admin / "info", admin / "logs"):
        _optional_git_entry(directory, directory=True)
    for file in set(files + writes):
        _optional_git_entry(file)
    return result


def _validate_runtime(home: Path, base: Path, *, create: bool) -> None:
    """Walk with directory descriptors so mkdir never follows an untrusted link."""
    clean_path(base)
    relative = home.relative_to(base)
    if not relative.parts or relative.parts[0] != ".runtime":
        raise ValueError("invalid runtime scope")
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = base
    try:
        for component in relative.parts:
            current = current / component
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    return
                raise
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            private = "worktrees" in current.relative_to(base).parts or current == home
            if (info.st_uid != os.getuid() or info.st_mode & (0o077 if private else 0o022)
                    or current.resolve() != current):
                raise ValueError("unsafe runtime directory")
            entry = current.lstat()
            if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("runtime directory replaced")
    finally:
        os.close(fd)


def for_cwd(config_path: Path, cwd: Path) -> Project | None:
    """No registry is normal outside the reserved root; never fall back inside."""
    cwd = cwd.absolute()
    path = config_path.parent / REGISTRY_NAME
    ancestors = (cwd, *cwd.parents)
    markers = [p for p in ancestors if os.path.lexists(p / MARKER_NAME)]
    reserved = (within(cwd.resolve(), DEFAULT_ROOT.resolve()) or within(cwd, DEFAULT_ROOT) or bool(markers))
    if not os.path.lexists(path):
        if reserved:
            raise Blocked("隔离项目注册信息缺失，已阻止启动。")
        return None
    try:
        data = json.loads(_safe_file(path, private=True, limit=1024 * 1024))
        if data.get("schema") != 1 or not isinstance(data.get("projects"), list):
            raise ValueError("invalid registry")
        base = clean_path(Path(data["root"]))
        reserved = reserved or within(cwd.resolve(), base)
        matches = []
        registered = {}
        for item in data["projects"]:
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", item["id"]):
                raise ValueError("invalid project")
            if item["id"] in registered:
                raise ValueError("duplicate project")
            root = clean_path(Path(item["path"]))
            home = clean_path(Path(item["home"]))
            if (root != base / "projects" / item["id"]
                    or home != base / ".runtime" / item["id"] / "home"):
                raise ValueError("scope too wide")
            registered[item["id"]] = Project(item["id"], root, home)
            if within(cwd.resolve(), root):
                _check_tree_path(cwd, root)
                matches.append(registered[item["id"]])
        if len(matches) == 1:
            return matches[0]
        # A removed marker must not turn a linked isolated repository into an
        # ordinary unsandboxed launch. Inspect pointers without invoking Git.
        linked = []
        for candidate in ancestors:
            git_file = candidate / ".git"
            if not os.path.lexists(git_file) or git_file.is_dir():
                continue
            try:
                target = _git_path(git_file, prefix="gitdir: ")
            except (OSError, ValueError):
                if (candidate.parent.parent == ORCA_WORKSPACES.absolute()
                        and candidate.parent.name in registered):
                    reserved = True
                continue
            for entry in registered.values():
                if within(target, entry.root / ".git/worktrees"):
                    reserved = True
                    linked.append((candidate, entry))
        if len(markers) == 1 and len(linked) == 1 and markers[0] == linked[0][0]:
            root, entry = linked[0]
            # A grant must not encompass trusted launcher state or any main
            # project/runtime, including a malicious ancestor workspace.
            protected = [base, config_path.parent.absolute(), *(p.root for p in registered.values())]
            if any(within(root, p) or within(p, root) for p in protected):
                raise ValueError("worktree overlaps protected state")
            _check_tree_path(cwd, root)
            worktree = _validate_worktree(root, entry.name, entry.root)
            home = _worktree_home(base, entry.name, root, worktree.git_dir)
            # Discovery is read-only. Existing ancestors must already be safe;
            # command() creates the remaining private directories later.
            _validate_runtime(home, base, create=False)
            return Project(entry.name, root, home, worktree)
        if matches or reserved:
            raise Blocked("隔离标记或 Git worktree 关联无法验证：仅支持已注册主项目的 Orca worktree；普通外部副本不能启动，且不会退回普通启动。")
        return None
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise Blocked("文件隔离注册信息无效，已阻止启动；不会退回普通启动。") from None


def environment(project: Project, proxy: str, inherited: dict | None = None, *, token_auth: bool = False) -> dict:
    if proxy != "http://127.0.0.1:62919":
        raise Blocked("当前文件沙箱只允许专用代理 127.0.0.1:62919；代理设置不匹配，未启动。")
    inherited = os.environ if inherited is None else inherited
    # Deliberately do not inherit provider tokens, SSH sockets, IDE/Orca handles,
    # DYLD/NODE/PYTHON injection flags, Git config, or any real-home paths.
    base = {k: inherited[k] for k in ("TERM", "COLORTERM", "NO_COLOR") if k in inherited}
    base.update({
        "HOME": str(project.home), "CLAUDE_CONFIG_DIR": str(project.config),
        "TMPDIR": str(project.home / "tmp") + "/",
        # Native settings processing uses this override, not TMPDIR, for its
        # claude-UID scratch tree. Never grant the old shared /tmp/claude-UID.
        "CLAUDE_CODE_TMPDIR": str(project.home / "tmp"),
        "XDG_CONFIG_HOME": str(project.home / ".config"),
        "XDG_CACHE_HOME": str(project.home / ".cache"),
        "XDG_DATA_HOME": str(project.home / ".local/share"),
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1", "DISABLE_AUTOUPDATER": "1", "DISABLE_UPDATES": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
    })
    from . import shared_history
    if shared_history.enabled(project):
        # The native, documented override keeps the picker on this project's
        # account-scoped transcript bucket, independent of the Orca worktree.
        base["CLAUDE_CODE_PROJECT_DIR_NAME"] = shared_history.bucket(project)
    from . import messaging
    peers = messaging.prepare_scope(project)
    if peers is not None:
        base["XDG_RUNTIME_DIR"] = str(peers.runtime)
    from . import isolated_auth
    shared_auth = None if token_auth else isolated_auth.prepare(project)
    if token_auth:
        # The environment token is the sole credential. This path is denied in
        # the child policy, so an expired token cannot fall back to disk login.
        base["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = str(project.home / ".token-auth-disabled")
    elif shared_auth is not None:
        # Share only native secure storage, never the HOME/config/session tree.
        # The inherited environment cannot choose a different credential store.
        base["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = str(shared_auth)
    # /usr/bin/git is an xcode-select shim. Use only these already-readable
    # developer installations, avoiding access to global selection/GUI services.
    for developer in (Path("/Library/Developer/CommandLineTools"),
                      Path("/Applications/Xcode.app/Contents/Developer")):
        if developer.resolve() == developer and (developer / "usr/bin/git").is_file():
            base["DEVELOPER_DIR"] = str(developer)
            base["PATH"] = str(developer / "usr/bin") + ":" + base["PATH"]
            break
    return proxy_env(proxy, base=base)


def arguments(values: list[str], *, theme: str | None = None,
              memory_directory: Path | None = None, local_messaging: bool = False,
              default_model: str = "", default_effort: str = "") -> list[str]:
    # Custom integrations may read outside the copy using an unsandboxed host.
    # Re-enable integrations only after a separate boundary review.
    forbidden = {"--settings", "--setting-sources", "--mcp-config", "--plugin-dir",
                 "--plugin-url", "--chrome", "--ide", "--add-dir", "--worktree", "-w"}
    if any(v.split("=", 1)[0] in forbidden for v in values):
        raise Blocked("隔离项目暂不允许额外设置、目录、插件、MCP 或 IDE/Chrome 集成。")
    # Native user/project settings remain disabled at this boundary. Supply
    # the requested startup defaults here instead of inheriting a mutable
    # settings file or a higher-priority effort environment variable. Native
    # --model/--effort flags and in-session choices can still override them.
    settings = {"disableAllHooks": True, "remoteControlAtStartup": False,
                "forceLoginMethod": "claudeai"}
    if default_model:
        settings["model"] = default_model
    if default_effort:
        settings["effortLevel"] = default_effort
    if theme is not None:
        from .isolated_preferences import THEMES
        if theme not in THEMES:
            raise Blocked("隔离终端主题不受支持。")
        settings["theme"] = theme
    if memory_directory is not None:
        settings["autoMemoryDirectory"] = str(memory_directory)
    if local_messaging:
        # This grant is for local Unix sockets only. Native cross-machine
        # messaging must never silently inherit the local approval scope.
        settings["isolatePeerMachines"] = True
        settings["disableRemoteControl"] = True
        settings["autoUploadSessions"] = False
    return ["--setting-sources", "", "--settings", json.dumps(settings),
            "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--no-chrome", *values]


def private_memory(project: Project) -> Path:
    # Preserve the native repository-memory location within this HOME. Long
    # path hashing is native-version-specific, so keep a private fallback there.
    name = re.sub(r"[^A-Za-z0-9]", "-", str(project.registered_root))
    if len(name) <= 200:
        return project.config / "projects" / name / "memory"
    return project.config / "isolated-memory"


def _q(value: Path | str) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def profile(project: Project, native: Path, browser_hook: Path, *, probe: Path | None = None,
            token_auth: bool = False, terminal_device: Path | None = None) -> str:
    hook = browser_hook.resolve()
    if hook.parent.parent != Path("/private/tmp") or not hook.parent.name.startswith("surge-cc-oauth-"):
        raise Blocked("授权桥目录不符合隔离要求。")
    read_dirs = ["/System/Library", "/usr/lib", "/usr/bin", "/bin", "/sbin", "/usr/share",
                 "/Library/Developer/CommandLineTools", "/Applications/Xcode.app",
                 "/opt/homebrew/Cellar", "/opt/homebrew/opt", "/opt/homebrew/bin",
                 "/opt/homebrew/lib", "/opt/homebrew/share"]
    read_files = ["/", "/private/etc/localtime", "/private/etc/passwd", "/private/etc/group",
                  "/private/etc/hosts", "/dev/null", "/dev/urandom", "/dev/random",
                  native.resolve(), hook, Path(sys.executable).resolve()]
    if probe is not None:
        read_files.append(probe.resolve())
    metadata = {Path("/private"), Path("/private/etc"), Path("/private/var"), Path("/opt"),
                Path("/opt/homebrew"), Path("/System"), Path("/dev"), hook.parent}
    for path in (project.root, project.home, native.resolve(), hook, Path(sys.executable).resolve()):
        metadata.update(path.parents)
    from . import isolated_auth
    shared_auth = None if token_auth else isolated_auth.prepare(project)
    auth_writes = ""
    if token_auth:
        # Preserve every existing credential file, but make none available to
        # this child, even when its HOME contains a prior isolated OAuth login.
        denied_auth = [project.home / ".token-auth-disabled",
                       project.home / ".token-auth-disabled.lock",
                       project.config / ".credentials.json",
                       project.base / ".runtime/auth"]
        auth_writes = "(deny file-read* file-write* " + " ".join(
            "(subpath " + _q(path) + ")" for path in denied_auth) + ")\n"
    if shared_auth is not None:
        metadata.update(shared_auth.parents)
        # Native secure storage uses atomic replacement and refresh/storage
        # locks inside this directory, plus a legacy sibling lock directory.
        # The enabling marker in the parent remains outside the child sandbox.
        legacy_lock = shared_auth.with_name(shared_auth.name + ".lock")
        auth_writes = "(allow file-read* file-write* (subpath " + _q(shared_auth) + ") (subpath " + _q(legacy_lock) + "))\n"
        if project.workspace is not None:
            # Old per-project fallback credentials are retained for rollback but
            # never readable by a process bound to a workspace auth store.
            auth_writes += "(deny file-read* file-write* (subpath " + _q(project.config / ".credentials.json") + "))\n"
    git_writes = ""
    if project.worktree:
        git_dirs, git_files, writable = _git_access(project.worktree)
        read_dirs.extend(git_dirs)
        read_files.extend(git_files)
        for path in [*git_dirs, *git_files, *writable]:
            metadata.update(path.parents)
        git_writes = "(allow file-read* file-write* " + " ".join(
            "(literal " + _q(path) + ")" for path in writable) + ")\n"
    from . import shared_history
    history = shared_history.history(project)
    history_rules = ""
    if history is not None:
        metadata.update(history.parents)
        history_rules = "(allow file-read* file-write* (subpath " + _q(history) + "))\n"
        # Only conversations are shared. Native automatic memory stays in the
        # current HOME even though the transcript bucket is common.
        history_rules += "(deny file-read* file-write* (subpath " + _q(history / "memory") + "))\n"
    from . import messaging
    peers = messaging.scope(project)
    peer_rules = ""
    if peers is not None:
        metadata.update(peers.sockets.parents)
        peer_rules = (
            f"(allow file-read* file-write* (subpath {_q(peers.sockets)}) (subpath {_q(peers.sessions)}))\n"
            f"(allow network-bind network-inbound network-outbound (subpath {_q(peers.sockets)}))\n"
        )
    reads = "\n".join("  (subpath " + _q(p) + ")" for p in read_dirs)
    reads += "\n" + "\n".join("  (literal " + _q(p) + ")" for p in read_files)
    metas = "\n".join("  (literal " + _q(p) + ")" for p in sorted(metadata))
    terminals = {"/dev/tty"}
    if terminal_device is not None:
        # With a trusted paste bridge, the child must not reopen the outer
        # Orca terminal and inject input into (or bypass) that bridge.
        terminal_device = Path(terminal_device)
        try:
            info = terminal_device.lstat()
            if (not re.fullmatch(r"/dev/ttys[0-9A-Za-z]{3,6}", str(terminal_device))
                    or terminal_device.resolve() != terminal_device
                    or not stat.S_ISCHR(info.st_mode) or info.st_uid != os.getuid()):
                raise ValueError("invalid child terminal")
        except (OSError, ValueError):
            raise Blocked("截图导入终端无法验证，已阻止隔离程序启动。") from None
        terminals.add(str(terminal_device))
    else:
        for fd in (0, 1, 2):
            try:
                terminals.add(os.ttyname(fd))
            except OSError:
                pass
    tty_rules = " ".join("(literal " + _q(p) + ")" for p in sorted(terminals))
    # Do NOT allow all /System: /System/Volumes/Data aliases user data on APFS.
    # No Mach services, AppleEvents, securityd, global Unix sockets, DNS or UDP.
    # macOS does not reliably restrict the bind interface using localhost:*;
    # the trusted OAuth broker separately verifies the actual loopback listener.
    return f'''(version 1)
(deny default)
(deny file-link)
(allow process-exec process-fork)
(allow process-info* (target self))
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow file-read*
{reads})
(allow file-read-metadata
{metas})
(allow file-read* file-write* (subpath {_q(project.root)}) (subpath {_q(project.home)}))
{git_writes}{auth_writes}{history_rules}{peer_rules}(allow file-write-data (literal "/dev/null"))
(allow file-read* file-write-data file-ioctl {tty_rules})
(allow network-outbound (remote tcp "localhost:62919"))
(allow network-outbound (literal {_q(hook.parent / 's')}))
(allow network-bind network-inbound (local tcp "localhost:*"))
'''


def command(project: Project, native: Path, values: list[str], browser_hook: Path, *,
            token_auth: bool = False, terminal_device: Path | None = None,
            default_model: str = "", default_effort: str = "") -> list[str]:
    if not SANDBOX.is_file():
        raise Blocked("本机缺少文件沙箱，已阻止隔离项目启动。")
    arguments(values)  # Validate before creating or changing runtime state.
    try:
        original_home = (_worktree_home(project.base, project.name, project.root, project.worktree.git_dir)
                         if project.worktree else project.base / ".runtime" / project.name / "home")
        if project.home != _expected_home(project, original_home):
            raise ValueError("incorrect project/workspace runtime scope")
        _validate_runtime(project.home, project.base, create=True)
        for folder in (project.config, project.home / "tmp", project.home / ".config", project.home / ".cache"):
            _validate_runtime(folder, project.base, create=True)
        # Repeat after preparing HOME, immediately before producing the launch
        # policy. A worktree moved/relinked during route checks must fail closed.
        if project.worktree:
            current = _validate_worktree(project.root, project.name, project.worktree.main_root)
            expected_home = _expected_home(project, _worktree_home(
                project.base, project.name, project.root, current.git_dir))
            if current != project.worktree or expected_home != project.home:
                raise ValueError("worktree linkage changed")
        else:
            clean_path(project.root)
    except (OSError, ValueError, TypeError):
        raise Blocked("隔离 HOME 或 Git worktree 关联已变更或权限不安全，已阻止启动。") from None
    from . import isolated_preferences, isolated_trust, shared_history, messaging
    isolated_preferences.prepare(project)
    # Trust is a separate, exact-project opt-in. Apply only after the repeated
    # worktree linkage checks; it never changes the Seatbelt or proxy policy.
    isolated_trust.prepare(project)
    history = shared_history.prepare(project)
    peers = messaging.prepare(project)
    args = arguments(values, theme=isolated_preferences.theme(project),
                     memory_directory=private_memory(project) if history is not None else None,
                     local_messaging=peers is not None,
                     default_model=default_model, default_effort=default_effort)
    return [str(SANDBOX), "-p", profile(project, native, browser_hook, token_auth=token_auth,
                                      terminal_device=terminal_device), str(native), *args]


def diagnose(project: Project, native: Path, config: dict, config_path: Path, *, token_auth: bool = False) -> dict:
    """Run local synthetic probes; no login, authorization URL, or model call."""
    from .oauth import OAuthSession
    from .core import run_checks
    checked = run_checks(config)
    if not checked.get("ok"):
        return checked
    parent = project.base
    denied_paths = [Path.home() / "Documents/Claude/Projects", Path.home() / "orca",
                    Path.home() / ".claude", Path.home() / "Library/Keychains",
                    Path.home() / "Library/Logs", config_path.parent]
    denied_paths += [p for p in (parent / "projects").iterdir() if p.is_dir() and p != project.root]
    if project.worktree:
        denied_paths += [p for p in project.root.parent.iterdir() if p.is_dir() and p != project.root]
        # Main working files stay private; shared Git metadata has separate,
        # explicitly limited grants and must not be labeled as wholly denied.
        denied_paths += [p for p in project.registered_root.iterdir() if p.name != ".git"]
    for runtime in (parent / ".runtime").iterdir():
        if runtime.is_dir():
            denied_paths.append(runtime / "home")
            accounts = runtime / "accounts"
            if accounts.is_dir():
                denied_paths += [p / "home" for p in accounts.iterdir() if p.is_dir()]
            worktrees = runtime / "worktrees"
            if worktrees.is_dir():
                denied_paths += [p / "home" for p in worktrees.iterdir() if p.is_dir()]
                for worktree in worktrees.iterdir():
                    accounts = worktree / "accounts"
                    if accounts.is_dir():
                        denied_paths += [p / "home" for p in accounts.iterdir() if p.is_dir()]
    # Only existing paths are tested; ENOENT must never count as access denial.
    denied = [{"path": str(p), "directory": p.is_dir()} for p in dict.fromkeys(denied_paths)
              if p != project.home and p.exists()]
    probe = Path(__file__).with_name("isolation_probe.py").resolve()
    # The canary is outside every project/home but contains no real data.
    with tempfile.NamedTemporaryFile(prefix="surge-cc-isolation-canary-", dir="/private/tmp") as canary:
        canary.write(b"synthetic-external-canary\n")
        canary.flush()
        inherited_fd = fcntl.fcntl(canary.fileno(), fcntl.F_DUPFD, 1000)
        os.set_inheritable(inherited_fd, True)
        try:
            with OAuthSession(config, config_path) as oauth:
                command(project, native, [], oauth.browser_hook, token_auth=token_auth)  # prepare and validate homes
                env = environment(project, config["proxy_url"], token_auth=token_auth)
                spec = {
                    "project": project.name, "root": str(project.root), "native": str(native),
                    "native_help_args": arguments(["--help"]),
                    "denied": denied, "outside_canary": canary.name, "outside_fd": inherited_fd}
                if project.worktree:
                    spec["git"] = {"common_dir": str(project.worktree.common_dir),
                                   "git_dir": str(project.worktree.git_dir)}
                env["SURGE_CC_ISOLATION_PROBE"] = json.dumps(spec)
                tested = subprocess.run([str(SANDBOX), "-p", profile(project, native, oauth.browser_hook, probe=probe, token_auth=token_auth),
                                         str(Path(sys.executable).resolve()), str(probe)],
                                        cwd=project.root, env=env, capture_output=True, text=True,
                                        timeout=60, close_fds=True)
                if tested.returncode not in (0, 1):
                    raise Blocked("文件隔离探针未完成，不能确认隔离生效。")
                try:
                    report = json.loads(tested.stdout)
                except ValueError:
                    raise Blocked("文件隔离探针没有产生有效报告。") from None
                report["denied_path_labels"] = [d["path"] for d in denied]
                report["summary"] = "文件隔离实测通过" if report.get("ok") else "文件隔离实测有失败项"
                report["network_config_changed"] = False
                return report
        finally:
            os.close(inherited_fd)
