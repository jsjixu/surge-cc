"""Explicit, project/account-scoped transcript sharing for isolated worktrees.

Only a trusted management call may initialize a store. Its caller must hold the
account-switch and session exclusion locks, so no legacy writer remains alive.
The native child gets access to ``data`` only; markers, receipts, authentication,
automatic memory, and the original HOME trees remain outside that grant.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .core import Blocked
from . import isolation, isolated_preferences as safe, keychain_auth


MARKER = "shared-history.json"
RECEIPT = "initialized.json"
MAX_MARKER = 1024 * 1024
MAX_HOMES = 4096
MAX_FILES = 50000
MAX_FILE = 256 * 1024 * 1024
MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_DEPTH = 8
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I)
HASH = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")
_ERROR = "同项目会话共享状态无效、尚未初始化或文件正在变化，已阻止启动；原对话未改动。"


def bucket(project) -> str:
    if not isinstance(project.name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", project.name):
        raise Blocked(_ERROR)
    return "surge-cc-" + project.name


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


class _Directories:
    """Pin and recheck all traversed components; never follow a source link."""

    def __init__(self, base):
        self.base = Path(base)
        self.nodes = []
        self.cache = {}
        if self.base.absolute() != self.base or self.base.resolve() != self.base:
            raise ValueError("aliased root")
        self.root = safe._open_dir(self.base)
        self.nodes.append((self.root, None, self.base, _identity(os.fstat(self.root))))

    def open(self, parent, name, *, private=False, create=False, optional=False):
        if not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\x00" in name:
            raise ValueError("unsafe path component")
        cached = self.cache.get((parent, name))
        if cached is not None:
            fd, expected = cached
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            safe._check(current, directory=True, private=private)
            if _identity(current) != expected or _identity(os.fstat(fd)) != expected:
                raise ValueError("directory changed before reuse")
            return fd
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        try:
            fd = safe._open_dir(name, parent=parent, private=private)
        except FileNotFoundError:
            if optional:
                return None
            raise
        expected = _identity(os.fstat(fd))
        self.nodes.append((fd, parent, name, expected))
        self.cache[(parent, name)] = (fd, expected)
        return fd

    def verify(self):
        if self.base.resolve() != self.base:
            raise ValueError("root changed")
        for fd, parent, name, expected in self.nodes:
            opened = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _identity(opened) != expected or _identity(current) != expected:
                raise ValueError("directory replaced")

    def close(self):
        for fd, _, _, _ in reversed(self.nodes):
            os.close(fd)
        self.nodes.clear()


@contextmanager
def _tree(base):
    tree = _Directories(base)
    try:
        yield tree
    finally:
        tree.close()


def _binding(project, *, require_active=True):
    """Do not trust a hand-constructed Project or a stale account selection."""
    bucket(project)
    workspace = keychain_auth._workspace(project.workspace)
    config = Path(project.workspace_config)
    if require_active and keychain_auth._selected(config, None) != workspace:
        raise ValueError("inactive account")
    actual = isolation.for_cwd(config, project.root)
    if actual is None or isolation.bind_workspace(actual, config, workspace) != project:
        raise ValueError("unregistered scope")
    owner = keychain_auth.legacy_workspace(config)
    return workspace, owner


def _marker(tree, runtime, project):
    value, state = safe._read(runtime, MARKER, private=True, limit=MAX_MARKER)
    if state is None:
        return False
    if (set(value) != {"schema", "projects"} or type(value.get("schema")) is not int
            or value["schema"] != 1 or not isinstance(value.get("projects"), list)):
        raise ValueError("bad marker")
    workspace, owner = _binding(project)
    registry = json.loads(isolation._safe_file(
        Path(project.workspace_config).parent / isolation.REGISTRY_NAME,
        private=True, limit=MAX_MARKER), object_pairs_hook=safe._unique_object)
    if (type(registry.get("schema")) is not int or registry["schema"] != 1
            or registry.get("root") != str(project.base) or not isinstance(registry.get("projects"), list)):
        raise ValueError("bad registry")
    registered = {item["id"]: item for item in registry["projects"]}
    if len(registered) != len(registry["projects"]):
        raise ValueError("duplicate registry")
    seen = set()
    for entry in value["projects"]:
        if (not isinstance(entry, dict) or set(entry) != {"id", "path"}
                or not isinstance(entry.get("id"), str)
                or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", entry["id"])
                or entry["id"] in seen):
            raise ValueError("bad project marker")
        name = entry["id"]
        expected = str(project.base / "projects" / name)
        if (entry["path"] != expected or name not in registered
                or registered[name].get("path") != expected
                or registered[name].get("home") != str(project.base / ".runtime" / name / "home")):
            raise ValueError("marker scope mismatch")
        seen.add(name)
    tree.verify()
    safe._unchanged(runtime, MARKER, state)
    return project.name in seen


def _store_path(project):
    return project.base / ".runtime" / project.name / "conversation-history" / project.workspace


def _receipt(store, project):
    data, state = safe._read(store, RECEIPT, private=True, limit=MAX_MARKER)
    required = {"schema", "project", "root", "workspace", "bucket", "sessions", "files", "bytes", "source_homes"}
    if (state is None or set(data) != required or type(data.get("schema")) is not int
            or data["schema"] != 1 or data.get("project") != project.name
            or data.get("root") != str(project.registered_root)
            or data.get("workspace") != project.workspace or data.get("bucket") != bucket(project)):
        raise ValueError("invalid store receipt")
    for field, limit in (("sessions", MAX_FILES), ("files", MAX_FILES),
                         ("bytes", MAX_BYTES), ("source_homes", MAX_HOMES)):
        if type(data.get(field)) is not int or not 0 <= data[field] <= limit:
            raise ValueError("invalid counts")
    return data, state


def _existing(tree, project_fd, project):
    shared = tree.open(project_fd, "conversation-history", private=True, optional=True)
    if shared is None:
        return None
    store = tree.open(shared, project.workspace, private=True, optional=True)
    if store is None:
        return None
    data, state = _receipt(store, project)
    tree.open(store, "data", private=True)
    tree.verify()
    safe._unchanged(store, RECEIPT, state)
    return data


def enabled(project) -> bool:
    """Read-only opt-in validation; works before the selected HOME is created."""
    try:
        with _tree(project.base) as tree:
            runtime = tree.open(tree.root, ".runtime", private=False, optional=True)
            if runtime is None:
                return False
            return _marker(tree, runtime, project)
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Blocked(_ERROR) from None


def history(project) -> Path | None:
    try:
        with _tree(project.base) as tree:
            runtime = tree.open(tree.root, ".runtime", optional=True)
            if runtime is None:
                return None
            if not _marker(tree, runtime, project):
                return None
            project_fd = tree.open(runtime, project.name, private=True)
            if _existing(tree, project_fd, project) is None:
                raise ValueError("explicit initialization required")
            return _store_path(project) / "data"
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Blocked(_ERROR) from None


def prepare(project) -> Path | None:
    """Link only the stable transcript bucket, preserving every old bucket."""
    try:
        target = history(project)
        if target is None:
            return None
        with _tree(project.base) as tree:
            current = tree.root
            for part in project.home.relative_to(project.base).parts:
                current = tree.open(current, part)
            current = tree.open(current, ".claude", private=True)
            projects = tree.open(current, "projects", create=True)
            name = bucket(project)
            try:
                os.symlink(str(target), name, dir_fd=projects)
            except FileExistsError:
                pass
            entry = os.stat(name, dir_fd=projects, follow_symlinks=False)
            if (not stat.S_ISLNK(entry.st_mode) or entry.st_uid != os.getuid()
                    or os.readlink(name, dir_fd=projects) != str(target)):
                raise ValueError("unexpected history bucket")
            tree.verify()
            if history(project) != target:
                raise ValueError("history changed")
            return target
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Blocked(_ERROR) from None


class _Inventory:
    def __init__(self, tree, project):
        self.tree = tree
        self.project = project
        self.directories = []
        self.files = []
        self.absent = []
        self.entries = 0
        self.total = 0
        self.homes = 0

    def optional(self, parent, name, *, private=False):
        result = self.tree.open(parent, name, private=private, optional=True)
        if result is None:
            self.absent.append((parent, name))
        return result

    def listing(self, fd):
        before = safe._fingerprint(os.fstat(fd))
        names = sorted(os.listdir(fd))
        self.entries += len(names)
        if self.entries > MAX_ENTRIES:
            raise ValueError("too many entries")
        if before != safe._fingerprint(os.fstat(fd)):
            raise ValueError("source directory changed")
        self.directories.append((fd, before))
        return names

    def check_entry(self, fd, name):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        safe._check(info, directory=stat.S_ISDIR(info.st_mode), limit=MAX_FILE)
        return info

    def add_file(self, fd, name, destination):
        info = self.check_entry(fd, name)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("expected transcript file")
        self.total += info.st_size
        if len(self.files) >= MAX_FILES or self.total > MAX_BYTES:
            raise ValueError("migration limit")
        self.files.append((fd, name, safe._fingerprint(info), destination))

    def attachments(self, fd, prefix, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("attachment depth")
        for name in self.listing(fd):
            if not NAME.fullmatch(name):
                raise ValueError("unsafe attachment name")
            info = self.check_entry(fd, name)
            if stat.S_ISDIR(info.st_mode):
                child = self.tree.open(fd, name)
                self.attachments(child, (*prefix, name), depth + 1)
            else:
                self.add_file(fd, name, (*prefix, name))

    def home(self, home):
        self.homes += 1
        if self.homes > MAX_HOMES:
            raise ValueError("too many homes")
        claude = self.optional(home, ".claude")
        if claude is None:
            return
        projects = self.optional(claude, "projects")
        if projects is None:
            return
        for name in self.listing(projects):
            info = os.stat(name, dir_fd=projects, follow_symlinks=False)
            # An earlier prepared link is known launcher state, never a source.
            if name == bucket(self.project) and stat.S_ISLNK(info.st_mode):
                if (info.st_uid != os.getuid() or os.readlink(name, dir_fd=projects)
                        != str(_store_path(self.project) / "data")):
                    raise ValueError("untrusted shared link")
                continue
            self.check_entry(projects, name)
            if not stat.S_ISDIR(info.st_mode):
                continue
            source = self.tree.open(projects, name)
            names = self.listing(source)
            sessions = set()
            for entry in names:
                item = self.check_entry(source, entry)
                if entry.endswith(".jsonl") and UUID.fullmatch(entry[:-6]):
                    session = entry[:-6].lower()
                    self.add_file(source, entry, (session + ".jsonl",))
                    sessions.add(session)
            for entry in names:
                if not UUID.fullmatch(entry) or entry.lower() not in sessions:
                    continue
                session_dir = self.tree.open(source, entry)
                for child in self.listing(session_dir):
                    self.check_entry(session_dir, child)
                    if child in ("subagents", "tool-results"):
                        source_dir = self.tree.open(session_dir, child)
                        self.attachments(source_dir, (entry.lower(), child))

    def verify(self):
        self.tree.verify()
        for parent, name in self.absent:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("source appeared after inventory")
        for fd, before in self.directories:
            if safe._fingerprint(os.fstat(fd)) != before:
                raise ValueError("source listing changed")
        for fd, name, before, _ in self.files:
            if safe._fingerprint(os.stat(name, dir_fd=fd, follow_symlinks=False)) != before:
                raise ValueError("source file changed")


def _collect(tree, project_fd, project, owner):
    inventory = _Inventory(tree, project)

    def account_home(parent):
        if project.workspace != owner:
            accounts = inventory.optional(parent, "accounts", private=True)
            if accounts is None:
                return
            parent = inventory.optional(accounts, project.workspace, private=True)
            if parent is None:
                return
        home = inventory.optional(parent, "home", private=True)
        if home is not None:
            inventory.home(home)

    account_home(project_fd)
    worktrees = inventory.optional(project_fd, "worktrees", private=True)
    if worktrees is not None:
        for name in inventory.listing(worktrees):
            if not HASH.fullmatch(name):
                raise ValueError("unknown worktree runtime")
            folder = tree.open(worktrees, name, private=True)
            account_home(folder)
    return inventory


def _destination(tree, data, path):
    parent = data
    for name in path[:-1]:
        parent = tree.open(parent, name, private=True, create=True)
    return parent, path[-1]


def _copy(inventory, tree, data):
    written = {}
    total = 0
    for source, name, expected, destination in inventory.files:
        source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source)
        output = None
        try:
            if safe._fingerprint(os.fstat(source_fd)) != expected:
                raise ValueError("source changed before copy")
            parent, leaf = _destination(tree, data, destination)
            if destination not in written:
                output = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
            digest = hashlib.sha256()
            length = 0
            while True:
                chunk = os.read(source_fd, 65536)
                if not chunk:
                    break
                length += len(chunk)
                if length > MAX_FILE or length > expected[2]:
                    raise ValueError("source grew")
                digest.update(chunk)
                if output is not None:
                    view = memoryview(chunk)
                    while view:
                        count = os.write(output, view)
                        if count <= 0:
                            raise OSError("short write")
                        view = view[count:]
            if (length != expected[2] or safe._fingerprint(os.fstat(source_fd)) != expected
                    or safe._fingerprint(os.stat(name, dir_fd=source, follow_symlinks=False)) != expected):
                raise ValueError("source changed while copying")
            signature = (length, digest.hexdigest())
            if destination in written:
                if written[destination] != signature:
                    raise ValueError("conflicting session content")
            else:
                os.fsync(output)
                written[destination] = signature
                total += length
        finally:
            os.close(source_fd)
            if output is not None:
                os.close(output)
    inventory.verify()
    return {"sessions": sum(len(path) == 1 and path[0].endswith(".jsonl") for path in written),
            "files": len(written), "bytes": total, "source_homes": inventory.homes}


def _remove_stage(parent, name):
    """Delete only our private temporary tree, using no-follow descriptors."""
    fd = safe._open_dir(name, parent=parent, private=True)
    try:
        for entry in os.listdir(fd):
            info = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                _remove_stage(fd, entry)
            else:
                os.unlink(entry, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent)


def initialize(project) -> dict:
    """Atomically import legacy isolated logs. Caller MUST exclude all writers.

    This management API does not require an opt-in marker; publish that marker
    only after all desired account/project stores have initialized successfully.
    Existing stores are validated, never reimported or replaced.
    """
    try:
        workspace, owner = _binding(project, require_active=False)
        with _tree(project.base) as tree:
            runtime = tree.open(tree.root, ".runtime")
            project_fd = tree.open(runtime, project.name, private=True)
            existing = _existing(tree, project_fd, project)
            if existing is not None:
                return dict(existing, initialized=False, already_initialized=True)
            inventory = _collect(tree, project_fd, project, owner)
            shared = tree.open(project_fd, "conversation-history", private=True, create=True)
            temporary = ".initialize-" + secrets.token_hex(16)
            os.mkdir(temporary, 0o700, dir_fd=shared)
            stage = tree.open(shared, temporary, private=True)
            published = False
            try:
                data = tree.open(stage, "data", private=True, create=True)
                counts = _copy(inventory, tree, data)
                receipt = {"schema": 1, "project": project.name, "root": str(project.registered_root),
                           "workspace": workspace, "bucket": bucket(project), **counts}
                safe._write(stage, RECEIPT, receipt, None)
                os.fsync(data)
                os.fsync(stage)
                inventory.verify()
                # rename cannot replace a validated nonempty initialized store.
                # The caller's exclusion lock prevents concurrent initialization.
                try:
                    os.stat(workspace, dir_fd=shared, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("store appeared during initialization")
                os.rename(temporary, workspace, src_dir_fd=shared, dst_dir_fd=shared)
                published = True
                os.fsync(shared)
                return dict(receipt, initialized=True, already_initialized=False)
            finally:
                if not published:
                    _remove_stage(shared, temporary)
    except Blocked:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Blocked(_ERROR) from None
