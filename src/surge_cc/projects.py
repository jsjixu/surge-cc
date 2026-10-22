"""Reviewed, local-only onboarding for isolated engineering project copies.

The source is never written, its Git history and application state are not
imported, and no installer or project hook runs. Shared history migration uses
the normal account and workspace exclusion gates; a busy workspace is an error,
not a reason to bypass its lock. This is a conservative filename filter, not a
claim that arbitrary source code contains no embedded credentials.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from .core import Blocked
from . import isolation, isolated_preferences as safe, isolated_trust
from . import keychain_auth, messaging, shared_history, workspaces


MAX_FILES = 50000
MAX_ENTRIES = 100000
MAX_FILE = 256 * 1024 * 1024
MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_DEPTH = 40
HANDOFF = "SURGE-CC-HANDOFF.md"
RECEIPT = "project-import.json"
_ID = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
_ERROR = "项目导入计划或隔离配置无法验证；原项目未改动。请重新预览后重试。"
_EXCLUDED_DIRS = {
    ".git", ".claude", ".codex", ".cursor", ".grok", ".gemini", ".orca",
    ".ssh", ".aws", ".azure", ".config", ".local", ".cache", ".runtime",
    ".venv", "venv", "node_modules", "__pycache__", ".next", ".nuxt",
    ".turbo", ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage",
    "dist", "build", "target", "logs", "debug", "sessions", "transcripts",
    "browser", "oauthbrowser", "chrome", "credentials", "secrets",
}
_EXCLUDED_FILES = {
    ".ds_store", ".claude.json", ".credentials.json", ".netrc", ".npmrc",
    ".pypirc", ".gitconfig", ".git-credentials", ".gitmodules", "auth.json",
    "credentials.json", "credentials", "cookies", "cookies.sqlite",
    "cookies.txt", "login data", "local state", "preferences", "history",
    "history.jsonl", "token", "token.json", "token.txt", "tokens.json",
    "secrets.json", "secrets.yaml", "secrets.yml", "secrets.toml",
    isolation.MARKER_NAME.lower(), HANDOFF.lower(),
}


def _name(value):
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise Blocked("项目名称请使用 1–40 位小写字母、数字或连字符，并以字母开头。")
    return value


def _path(value):
    result = Path(value).expanduser().absolute()
    if (".." in result.parts or result.resolve() != result
            or any(ord(char) < 32 for char in str(result))):
        raise ValueError("noncanonical path")
    return result


def _json(path, *, optional=False, limit=1024 * 1024):
    if optional and not os.path.lexists(path):
        return None
    return json.loads(isolation._safe_file(path, private=True, limit=limit),
                      object_pairs_hook=safe._unique_object)


def _registry(config_path, root=None):
    config_path = _path(config_path)
    keychain_auth._selected(config_path, None)  # A saved, owned active account is required.
    data = _json(config_path.parent / isolation.REGISTRY_NAME, optional=True)
    if data is None:
        base = _path(root if root is not None else isolation.DEFAULT_ROOT)
        return {"schema": 1, "root": str(base), "projects": []}
    if (not isinstance(data, dict) or set(data) != {"schema", "root", "projects"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or not isinstance(data["projects"], list)):
        raise ValueError("invalid registry")
    base = isolation.clean_path(_path(data["root"]))
    if root is not None and _path(root) != base:
        raise ValueError("different isolation root")
    names = set()
    for entry in data["projects"]:
        if not isinstance(entry, dict) or set(entry) != {"id", "path", "home"}:
            raise ValueError("invalid registration")
        name = _name(entry["id"])
        if (name in names or entry["path"] != str(base / "projects" / name)
                or entry["home"] != str(base / ".runtime" / name / "home")):
            raise ValueError("registry scope mismatch")
        names.add(name)
        actual = isolation.for_cwd(config_path, Path(entry["path"]))
        if actual is None or actual.name != name:
            raise ValueError("unregistered project")
    return data


def _source(source, base, config_path):
    source = isolation.clean_path(_path(source))
    home = Path.home().resolve()
    broad = {home, home / "Documents", home / "Desktop", home / "Downloads", home / "Library"}
    if source in broad or source in home.parents or len(source.parts) < 3:
        raise ValueError("source is not a project folder")
    for protected in (base, config_path.parent):
        if isolation.within(source, protected) or isolation.within(protected, source):
            raise ValueError("source overlaps managed state")
    return source


def _excluded(name, info):
    value = name.lower()
    if stat.S_ISLNK(info.st_mode):
        return "symbolic link (not followed)"
    if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
        return "special file"
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        return "foreign owner or writable by others"
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        return "hard-linked file"
    if value in _EXCLUDED_DIRS or value in _EXCLUDED_FILES:
        return "account/history/cache/build or managed metadata"
    if (value.startswith((".env", ".claude.json.", "id_rsa", "id_ed25519", "id_ecdsa"))
            or value.endswith((".pem", ".key", ".p12", ".pfx", ".keystore", ".log", ".log.gz"))
            or re.search(r"(?:^|[._-])(?:credentials?|tokens?|secrets?)(?:[._-]|$)", value)):
        return "potential credential or runtime log filename"
    return None


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)


def _scan(source, destination=None):
    files, excluded, directories, seen = [], [], [], []
    total = entries = 0
    with shared_history._tree(source) as tree:
        def visit(fd, parts, depth):
            nonlocal total, entries
            if depth > MAX_DEPTH:
                raise ValueError("project directory depth limit")
            before = _fingerprint(os.fstat(fd))
            names = sorted(os.listdir(fd))
            entries += len(names)
            if entries > MAX_ENTRIES:
                raise ValueError("project entry limit")
            for name in names:
                if any(ord(char) < 32 for char in name):
                    raise ValueError("unsafe filename")
                rel = Path(*parts, name)
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                reason = _excluded(name, info)
                if reason:
                    excluded.append({"path": str(rel), "reason": reason})
                    continue
                if stat.S_ISDIR(info.st_mode):
                    child = tree.open(fd, name)
                    if destination is not None:
                        (destination / rel).mkdir(mode=0o700)
                    directories.append(str(rel))
                    visit(child, (*parts, name), depth + 1)
                    continue
                total += info.st_size
                if info.st_size > MAX_FILE or len(files) >= MAX_FILES or total > MAX_BYTES:
                    raise ValueError("project size limit")
                opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                output = None
                try:
                    expected = _fingerprint(info)
                    if _fingerprint(os.fstat(opened)) != expected:
                        raise ValueError("source replaced")
                    mode = 0o700 if info.st_mode & 0o111 else 0o600
                    if destination is not None:
                        output = os.open(destination / rel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
                    digest, size = hashlib.sha256(), 0
                    while True:
                        chunk = os.read(opened, 65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                        size += len(chunk)
                        if size > info.st_size:
                            raise ValueError("source grew")
                        if output is not None:
                            view = memoryview(chunk)
                            while view:
                                written = os.write(output, view)
                                if written <= 0:
                                    raise OSError("short copy")
                                view = view[written:]
                    if size != info.st_size or _fingerprint(os.fstat(opened)) != expected:
                        raise ValueError("source changed")
                    if output is not None:
                        os.fsync(output)
                    files.append({"path": str(rel), "size": size, "sha256": digest.hexdigest(),
                                  "executable": bool(mode & 0o111)})
                    seen.append((fd, name, expected))
                finally:
                    os.close(opened)
                    if output is not None:
                        os.close(output)
            if _fingerprint(os.fstat(fd)) != before:
                raise ValueError("source listing changed")
            seen.append((fd, None, before))
        visit(tree.root, (), 0)
        tree.verify()
        for fd, name, expected in seen:
            info = os.fstat(fd) if name is None else os.stat(name, dir_fd=fd, follow_symlinks=False)
            if _fingerprint(info) != expected:
                raise ValueError("source changed during scan")
    if not files:
        raise ValueError("no engineering files remain")
    return {"files": files, "directories": directories, "excluded": excluded, "bytes": total}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _plan(config_path, source, name, root=None, destination=None):
    config_path = _path(config_path)
    name = _name(name)
    registry = _registry(config_path, root)
    base = _path(registry["root"])
    source = _source(source, base, config_path)
    target = base / "projects" / name
    if any(entry["id"] == name for entry in registry["projects"]) or os.path.lexists(target):
        raise Blocked("目标项目已存在；不会覆盖。已注册项目请使用项目功能启用命令。")
    if os.path.lexists(base / ".runtime" / name):
        raise ValueError("unregistered runtime exists")
    scanned = _scan(source, destination)
    result = {"schema": 1, "source": str(source), "name": name, "root": str(base),
              "target": str(target), "workspace": keychain_auth._selected(config_path, None), **scanned}
    result["digest"] = _digest(result)
    result["file_count"] = len(result["files"])
    result["review_notice"] = (
        "Review the retained files and exclusions before applying. Filename filtering cannot "
        "detect secrets embedded in ordinary source files. Source files are not changed; "
        "Git history, old credentials and excluded application data are not imported.")
    return result


def plan(config_path, source, name, *, root=None):
    """Read-only, bounded preview. Pass its digest to apply after review."""
    try:
        return _plan(config_path, source, name, root)
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise Blocked(_ERROR) from None


def _mkdir(path):
    missing, current = [], path
    while not os.path.lexists(current):
        missing.append(current.name)
        current = current.parent
    if current.resolve() != current or not current.is_dir():
        raise ValueError("unsafe parent")
    isolation.clean_path(current)
    # Pin the existing ancestor and create children relative to descriptors;
    # another process cannot redirect mkdir through a substituted symlink.
    with shared_history._tree(current) as tree:
        fd = tree.root
        for component in reversed(missing):
            fd = tree.open(fd, component, private=True, create=True)
        tree.verify()
    isolation.clean_path(path)


def _write(path, value):
    with shared_history._tree(path.parent) as tree:
        previous, state = safe._read(tree.root, path.name, private=True, limit=1024 * 1024)
        safe._write(tree.root, path.name, value, state)
        tree.verify()
    return previous if state is not None else None


def _restore(path, previous):
    if previous is not None:
        _write(path, previous)
    elif os.path.lexists(path):
        isolation._safe_file(path, private=True, limit=1024 * 1024)
        path.unlink()


def _allowlist(base, registry, filename):
    path = base / ".runtime" / filename
    value = _json(path, optional=True)
    if value is None:
        return {"schema": 1, "projects": []}
    if filename == isolated_trust.MARKER:
        if value == {"schema": 1, "enabled": False}:
            return {"schema": 1, "projects": []}
        required = {"schema", "enabled", "projects"}
        if not isinstance(value, dict) or set(value) != required or value["enabled"] is not True:
            raise ValueError("invalid trust marker")
        value = {"schema": value["schema"], "projects": value["projects"]}
    if (not isinstance(value, dict) or set(value) != {"schema", "projects"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["projects"], list)):
        raise ValueError("invalid feature marker")
    registered = {entry["id"]: entry["path"] for entry in registry["projects"]}
    seen = set()
    for entry in value["projects"]:
        if (not isinstance(entry, dict) or set(entry) != {"id", "path"}
                or entry.get("id") in seen or registered.get(entry.get("id")) != entry.get("path")):
            raise ValueError("unregistered marker entry")
        seen.add(entry["id"])
    return value


def _enable_locked(config_path, registry, names, *, trust, share_history, local_messaging):
    """Caller owns account_switch and the current workspace's exclusive lease."""
    if any(type(flag) is not bool for flag in (trust, share_history, local_messaging)):
        raise ValueError("feature flags must be boolean")
    workspace = keychain_auth._selected(config_path, None)
    base = Path(registry["root"])
    if keychain_auth.legacy_workspace(config_path) is None:
        # Unknown pre-account data cannot be attributed by guessing that the
        # currently selected account owns it. Empty freshly imported HOME is safe.
        with shared_history._tree(base) as tree:
            runtime_fd = tree.open(tree.root, ".runtime")
            for item in registry["projects"]:
                project_fd = tree.open(runtime_fd, item["id"], private=True)
                for legacy_name in ("worktrees", "accounts", "conversation-history"):
                    if tree.open(project_fd, legacy_name, optional=True) is not None:
                        raise Blocked("已有隔离数据尚未绑定账号；请先完成原账号迁移，不能按当前账号猜测历史归属。")
                home_fd = tree.open(project_fd, "home", private=True)
                claude_fd = tree.open(home_fd, ".claude", optional=True)
                if claude_fd is not None and os.listdir(claude_fd):
                    raise Blocked("已有隔离数据尚未绑定账号；请先完成原账号迁移，不能按当前账号猜测历史归属。")
            tree.verify()
    keychain_auth.migrate_legacy(config_path, workspace)
    entries = {item["id"]: item for item in registry["projects"]}
    if not names or len(set(names)) != len(names) or any(_name(name) not in entries for name in names):
        raise ValueError("unknown project selection")
    flags = ((shared_history.MARKER, share_history), (messaging.MARKER, local_messaging),
             (isolated_trust.MARKER, trust))
    # Validate all metadata before copying any existing native history.
    values = {marker: _allowlist(base, registry, marker) for marker, flag in flags if flag}
    reports = []
    for name in names:
        project = isolation.bind_workspace(isolation.for_cwd(config_path, Path(entries[name]["path"])), config_path, workspace)
        isolation._validate_runtime(project.home, base, create=True)
        report = {"name": name, "workspace": workspace}
        if share_history:
            report["history"] = shared_history.initialize(project)
        reports.append(report)
    originals = {}
    try:
        for marker, flag in flags:
            if not flag:
                continue
            current = {entry["id"]: entry for entry in values[marker]["projects"]}
            current.update({name: {"id": name, "path": entries[name]["path"]} for name in names})
            value = {"schema": 1, "projects": [current[name] for name in sorted(current)]}
            if marker == isolated_trust.MARKER:
                value["enabled"] = True
            path = base / ".runtime" / marker
            originals[path] = _json(path, optional=True)
            _write(path, value)
        return {"workspace": workspace, "projects": reports, "shared_history": share_history,
                "local_messaging": local_messaging, "default_trust": trust}
    except Exception:
        for path, previous in reversed(list(originals.items())):
            _restore(path, previous)
        raise


def preview_enable(config_path, names):
    """Count current-account native transcripts without importing or opting in.

    A missing account ownership receipt refuses historical migration rather than
    attributing existing logs to whichever account happens to be selected.
    Source integrity is rechecked independently when enable obtains its locks.
    """
    try:
        config_path = _path(config_path)
        registry = _registry(config_path)
        workspace = keychain_auth._selected(config_path, None)
        owner = keychain_auth.legacy_workspace(config_path)
        entries = {item["id"]: item for item in registry["projects"]}
        names = list(names)
        if not names or len(set(names)) != len(names) or any(_name(name) not in entries for name in names):
            raise ValueError("unknown project selection")
        if owner is None:
            raise Blocked("已有隔离项目尚未绑定账号；请先完成原账号迁移，再预览会话共享。")
        reports = []
        base = Path(registry["root"])
        for name in names:
            project = isolation.bind_workspace(isolation.for_cwd(config_path, Path(entries[name]["path"])), config_path, workspace)
            with shared_history._tree(base) as tree:
                runtime_fd = tree.open(tree.root, ".runtime")
                project_fd = tree.open(runtime_fd, name, private=True)
                existing = shared_history._existing(tree, project_fd, project)
                if existing is not None:
                    reports.append({"name": name, "already_initialized": True,
                                    **{field: existing[field] for field in ("sessions", "files", "bytes", "source_homes")}})
                else:
                    inventory = shared_history._collect(tree, project_fd, project, owner)
                    inventory.verify()
                    reports.append({"name": name, "already_initialized": False,
                                    "candidate_files": len(inventory.files), "candidate_bytes": inventory.total,
                                    "source_homes": inventory.homes})
        return {"workspace": workspace, "projects": reports,
                "notice": "Only the selected account's registered isolated histories are candidates. "
                          "Original transcripts are retained. Stop managed Claude and browser sessions before enable."}
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise Blocked(_ERROR) from None


def enable(config_path, names, *, trust=False, share_history=True, local_messaging=True):
    """Enable selected existing copies; original transcript trees stay intact.

    Existing validated stores are idempotent. When changing accounts, run this
    once in the newly selected account to initialize *its own* history store.
    An active Claude, browser, or unrepaired browser lock blocks this operation.
    """
    try:
        config_path = _path(config_path)
        with workspaces.account_switch(config_path):
            workspace = keychain_auth._selected(config_path, None)
            with workspaces.exclusive(config_path, workspace):
                registry = _registry(config_path)
                return _enable_locked(config_path, registry, list(names), trust=trust,
                                      share_history=share_history, local_messaging=local_messaging)
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise Blocked(_ERROR) from None


def _git(target):
    binary = "/usr/bin/git"
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(target),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "GIT_AUTHOR_NAME": "Surge CC Import", "GIT_AUTHOR_EMAIL": "local@surge-cc.invalid",
           "GIT_COMMITTER_NAME": "Surge CC Import", "GIT_COMMITTER_EMAIL": "local@surge-cc.invalid"}
    for args in (("init", "--initial-branch=main", str(target)), ("-C", str(target), "add", "--force", "--all"),
                 ("-C", str(target), "commit", "-m", "Create isolated engineering snapshot")):
        completed = subprocess.run([binary, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
                                   env=env, capture_output=True, timeout=90)
        if completed.returncode != 0:
            raise Blocked("无法建立隔离副本的全新 Git 历史；原项目未改动。请先安装 macOS 命令行开发工具。")


def _handoff(preview):
    retained = [item["path"] for item in preview["files"]]
    docs = [name for name in retained if name.lower().endswith((".md", ".rst", ".txt"))][:40]
    manifests = [name for name in retained if Path(name).name in
                 ("package.json", "pnpm-lock.yaml", "pyproject.toml", "Cargo.toml", "go.mod", "Package.swift", "Makefile")][:40]
    lines = ["# Isolated project handoff", "", "This is an engineering snapshot with fresh Git history.",
             "The source project was left unchanged. No packages, setup scripts or hooks were executed.",
             "", f"Project: `{preview['name']}`", f"Retained files: {preview['file_count']}",
             f"Excluded entries: {len(preview['excluded'])}", "", "## Useful starting points", ""]
    lines.extend("- `" + name.replace("`", "\\`") + "`" for name in dict.fromkeys(manifests + docs))
    if not (manifests or docs):
        lines.append("Inspect the source tree and identify its build and test entry points.")
    lines.extend(["", "## Working safely", "", "Open this copy in Orca and create linked worktrees from it.",
                  "Use the Surge CC managed `claude` command. Shared conversation history and local peer messaging",
                  "are limited to this registered project and the selected Surge CC account.",
                  "Authentication, old sessions, browser state and source Git history were not imported.",
                  "Review source files for embedded secrets before sharing their contents with any service.",
                  "Configure development secrets separately; they were not copied from excluded files.", ""])
    return "\n".join(lines)


def apply(config_path, source, name, *, expected_digest, root=None, trust=False,
          share_history=True, local_messaging=True):
    """Create a sanitized copy from an unchanged reviewed preview, then register."""
    try:
        if not isinstance(expected_digest, str) or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
            raise ValueError("review digest required")
        config_path = _path(config_path)
        with workspaces.account_switch(config_path):
            workspace = keychain_auth._selected(config_path, None)
            with workspaces.exclusive(config_path, workspace):
                preview = _plan(config_path, source, name, root)
                if preview["digest"] != expected_digest:
                    raise Blocked("源项目、排除清单或当前账号已改变；请重新预览，未导入旧计划。")
                base, target = Path(preview["root"]), Path(preview["target"])
                _mkdir(base / "projects")
                _mkdir(base / ".runtime")
                stage = Path(tempfile.mkdtemp(prefix=".import-", dir=base / "projects"))
                runtime = base / ".runtime" / name
                registry_path = config_path.parent / isolation.REGISTRY_NAME
                original_registry = _json(registry_path, optional=True)
                published = runtime_created = registry_changed = False
                try:
                    copied = _plan(config_path, source, name, root, destination=stage)
                    if copied["digest"] != expected_digest:
                        raise Blocked("复制过程中源项目发生变化；未发布副本，原项目未改动。")
                    marker = {"schema": 1, "project": name, "requires_registered_launcher": True}
                    _write(stage / isolation.MARKER_NAME, marker)
                    with (stage / HANDOFF).open("x", encoding="utf-8") as handle:
                        handle.write(_handoff(preview))
                    (stage / HANDOFF).chmod(0o600)
                    _git(stage)
                    registry = _registry(config_path, root)
                    # A failed prior import is never silently adopted or overwritten.
                    if os.path.lexists(target) or os.path.lexists(runtime):
                        raise ValueError("target appeared")
                    os.rename(stage, target)
                    published = True
                    os.mkdir(runtime, 0o700)
                    runtime_created = True
                    _mkdir(runtime / "home/.claude")
                    _write(runtime / RECEIPT, {"schema": 1, "name": name, "source": preview["source"],
                                             "digest": expected_digest, "files": preview["file_count"],
                                             "excluded": len(preview["excluded"]), "bytes": preview["bytes"]})
                    registry["projects"].append({"id": name, "path": str(target), "home": str(runtime / "home")})
                    registry_changed = True
                    _write(registry_path, registry)
                    enabled = _enable_locked(config_path, registry, [name], trust=trust,
                                             share_history=share_history, local_messaging=local_messaging)
                    return {"created": True, "name": name, "path": str(target), "source_unchanged": True,
                            "handoff": str(target / HANDOFF), "file_count": preview["file_count"],
                            "excluded": preview["excluded"], **enabled}
                except Exception:
                    # The launch gate remains held until all references are rolled
                    # back. Only this call's newly created trees are removed.
                    if registry_changed:
                        _restore(registry_path, original_registry)
                    if runtime_created:
                        shutil.rmtree(runtime)
                    if published:
                        shutil.rmtree(target)
                    raise
                finally:
                    if stage.exists():
                        shutil.rmtree(stage)
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        raise Blocked(_ERROR) from None


def status(config_path):
    """Read only; no launch, credential read, configuration change or migration."""
    try:
        config_path = _path(config_path)
        registry = _registry(config_path)
        workspace = keychain_auth._selected(config_path, None)
        owner = keychain_auth.legacy_workspace(config_path)
        base = Path(registry["root"])
        result = []
        for entry in registry["projects"]:
            item = {"name": entry["id"], "path": entry["path"], "workspace": workspace,
                    "shared_history": False, "history_initialized": False, "local_messaging": False,
                    "default_trust": False}
            if owner is not None:
                project = isolation.bind_workspace(isolation.for_cwd(config_path, Path(entry["path"])), config_path, workspace)
                item["shared_history"] = shared_history.enabled(project)
                if item["shared_history"]:
                    try:
                        item["history_initialized"] = shared_history.history(project) is not None
                    except Blocked:
                        item["history_needs_initialization"] = True
                item["local_messaging"] = messaging.enabled(project)
            trust = _allowlist(base, registry, isolated_trust.MARKER)
            item["default_trust"] = any(allowed["id"] == entry["id"] for allowed in trust["projects"])
            result.append(item)
        return {"root": registry["root"], "workspace": workspace, "projects": result,
                "account_binding_initialized": owner is not None}
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise Blocked(_ERROR) from None
