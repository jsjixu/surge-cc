"""App-owned working data and reversible snapshots; never reads personal credentials."""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

from .core import Blocked, BrowserProfileBusy, load_config, now, save_config, validate_config


# The active config remains the runtime view. Each workspace owns a separate
# copy of these fields; machine paths and installation metadata stay shared.
SETTINGS_FIELDS = (
    "group", "policy", "expected_ip", "proxy_url", "hosts", "expected_timezone",
    "expected_locale", "expected_country", "expected_asn", "browser_language",
    "privacy_strict", "guard_interval", "default_model", "default_effort", "browser_start_page",
)
OPTIONAL_SETTINGS = {"default_model": "", "default_effort": "", "browser_start_page": "claude"}


@contextmanager
def account_lock(config_path: Path, exclusive: bool = False):
    """Serialize account changes against launch preparation, not live sessions.

    A launcher releases its shared gate only after the supervisor owns the
    workspace session lock. A switch can then take the exclusive gate, stop
    owned sessions, and commit without another launcher entering halfway.
    """
    parent = config_path.parent
    if parent.is_symlink() or any(p.is_symlink() for p in parent.parents if p.exists()):
        raise Blocked("账号切换锁的位置不能使用符号链接。")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(parent / ".account.lock", os.O_RDWR | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    released = False

    def release():
        nonlocal released
        if not released:
            released = True
            os.close(fd)

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise Blocked("账号切换锁文件的类型或所有者异常。")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Blocked("正在切换工作区或准备启动，请稍后重试。") from None
        yield release
    finally:
        release()


def assert_current(config_path: Path, config: dict) -> dict:
    """Reject a stale GUI request or launcher rather than mix two accounts."""
    current = load_config(config_path)
    if current != validate_config(config):
        raise Blocked("当前工作区或设置已变更，请刷新后重试；未使用旧账号配置启动。")
    return current


@contextmanager
def account_session(config_path: Path, config: dict):
    with account_lock(config_path) as release:
        assert_current(config_path, config)
        yield release


@contextmanager
def account_switch(config_path: Path):
    with account_lock(config_path, exclusive=True):
        yield


def name_ok(name: str) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
        raise Blocked("工作区名称只能使用 1–32 位字母、数字、下划线或连字符。")
    return name


def safe_root(config_path: Path) -> Path:
    root = config_path.parent / "workspaces"
    if root.is_symlink() or any(p.is_symlink() for p in root.parents if p.exists()):
        raise Blocked("工作区目录不能通过符号链接访问。")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def location(config_path: Path, name: str) -> Path:
    root = safe_root(config_path)
    path = root / name_ok(name)
    if any(p.name.casefold() == name.casefold() and p.name != name for p in root.iterdir()):
        raise Blocked("已有仅大小写不同的工作区；请使用原名称，避免共享同一目录。")
    if path.is_symlink():
        raise Blocked("工作区目录不能使用符号链接。")
    return path


def write_json(path: Path, value: dict) -> None:
    if path.is_symlink():
        raise Blocked("不能覆盖符号链接元数据。")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".metadata-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _initialize(path: Path, name: str, label: str = "") -> None:
    data = path / "data"
    if data.is_symlink():
        raise Blocked("工作区数据目录不能使用符号链接。")
    if not data.exists() and any(path.glob("previous-*")):
        raise Blocked("检测到上次恢复中断；原数据保留在 previous-*，请先恢复原数据，未创建空工作区。")
    data.mkdir(exist_ok=True, mode=0o700)
    for child in ("Browser", "Claude"):
        directory = data / child
        if directory.is_symlink():
            raise Blocked("工作区应用目录不能使用符号链接。")
        directory.mkdir(exist_ok=True, mode=0o700)
    if not (path / "metadata.json").exists():
        write_json(path / "metadata.json", {"name": name, "label": label[:100] or name, "created_at": now()})


@contextmanager
def _lock(path: Path, exclusive: bool):
    path.mkdir(exist_ok=True, mode=0o700)
    lock = path / ".session.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise Blocked("工作区锁文件的类型或所有者异常。")
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Blocked("工作区正在运行、备份或恢复，请完成当前操作后重试。") from None
        yield
    finally:
        os.close(fd)


def create(config_path: Path, name: str, label: str = "") -> Path:
    path = location(config_path, name)
    with _lock(path, exclusive=False):
        _initialize(path, name, label)
    return path


def paths(config_path: Path, name: str) -> dict[str, Path]:
    path = create(config_path, name)
    return {"root": path, "data": path / "data", "browser": path / "data/Browser",
            "claude": path / "data/Claude", "lock": path / ".session.lock"}


@contextmanager
def exclusive(config_path: Path, name: str):
    path = location(config_path, name)
    with _lock(path, exclusive=True):
        from .sessions import assert_no_stop_failures
        assert_no_stop_failures(path)
        _initialize(path, name)
        loc = {"root": path, "data": path / "data", "browser": path / "data/Browser",
               "claude": path / "data/Claude", "lock": path / ".session.lock"}
        if (os.path.lexists(loc["browser"] / "SingletonLock") or
                os.path.lexists(path / "data/OAuthBrowser/SingletonLock")):
            raise BrowserProfileBusy("这个工作区的专用浏览器仍在运行，或退出后留有锁。可点击检查并修复浏览器锁。")
        yield loc


def inventory(data: Path) -> dict:
    values = {}
    for path in sorted(data.rglob("*")):
        relative = str(path.relative_to(data))
        if path.is_symlink():
            values[relative] = {"link": os.readlink(path)}
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            values[relative] = {"size": path.stat().st_size, "sha256": digest.hexdigest()}
        elif path.is_dir():
            values[relative] = {"directory": True}
        else:
            raise Blocked("工作区包含运行时套接字或其他特殊文件，请关闭程序后重试。")
    return values


def _snapshot(loc: dict, name: str, label: str) -> dict:
    parent = loc["root"] / "snapshots"
    if parent.is_symlink():
        raise Blocked("快照目录不能使用符号链接。")
    parent.mkdir(exist_ok=True, mode=0o700)
    identifier = uuid.uuid4().hex
    stage = Path(tempfile.mkdtemp(prefix=".pending-", dir=parent))
    try:
        before = inventory(loc["data"])
        shutil.copytree(loc["data"], stage / "data", symlinks=True)
        if before != inventory(stage / "data") or before != inventory(loc["data"]):
            raise Blocked("复制期间工作区数据发生变化；未保存不完整快照。")
        metadata = {"id": identifier, "name": name, "label": label[:100],
                    "created_at": now(), "files": before}
        write_json(stage / "manifest.json", metadata)
        os.replace(stage, parent / identifier)
        return {k: v for k, v in metadata.items() if k != "files"}
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def snapshot(config_path: Path, name: str, label: str = "") -> dict:
    with exclusive(config_path, name) as loc:
        return _snapshot(loc, name, label or "手动快照")


def restore(config_path: Path, name: str, identifier: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise Blocked("快照编号格式不正确。")
    with exclusive(config_path, name) as loc:
        source = loc["root"] / "snapshots" / identifier
        if (source.parent.is_symlink() or source.is_symlink()
                or (source / "data").is_symlink()
                or (source / "manifest.json").is_symlink()):
            raise Blocked("快照不能使用符号链接目录。")
        try:
            manifest = json.loads((source / "manifest.json").read_text())
            if manifest["name"] != name or manifest["id"] != identifier:
                raise Blocked("快照所属工作区不匹配。")
            if inventory(source / "data") != manifest["files"]:
                raise Blocked("快照校验失败，未恢复。")
        except (OSError, ValueError, KeyError, TypeError):
            raise Blocked("无法读取完整快照。") from None
        backup = _snapshot(loc, name, "恢复前自动备份")
        stage = Path(tempfile.mkdtemp(prefix=".restore-", dir=loc["root"]))
        rollback = loc["root"] / ("previous-" + uuid.uuid4().hex)
        try:
            shutil.copytree(source / "data", stage / "data", symlinks=True)
            if inventory(stage / "data") != manifest["files"]:
                raise Blocked("恢复副本校验失败。")
            os.replace(loc["data"], rollback)
            try:
                os.replace(stage / "data", loc["data"])
            except OSError:
                os.replace(rollback, loc["data"])
                raise
            # Both the automatic snapshot and previous directory are retained.
            return {"restored": identifier, "backup": backup["id"]}
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def _route(config: dict) -> dict:
    normalized = validate_config(config)
    # Copy nested hosts too: later changes to one workspace must not mutate the
    # initial same-route snapshot of another workspace in memory.
    return json.loads(json.dumps({key: normalized[key] for key in SETTINGS_FIELDS}))


def _settings_path(config_path: Path, name: str) -> Path:
    return location(config_path, name) / "settings.json"


def _read_settings(config_path: Path, name: str, base: dict) -> dict | None:
    file = _settings_path(config_path, name)
    if file.is_symlink():
        raise Blocked("工作区线路设置不能使用符号链接。")
    if not file.exists():
        return None
    try:
        info = file.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("invalid settings owner")
        value = json.loads(file.read_text(encoding="utf-8"))
        if (not isinstance(value, dict) or set(value) != {"schema", "workspace", "settings"}
                or value["schema"] != 1 or value["workspace"] != name
                or not isinstance(value["settings"], dict)
                or set(value["settings"]) - set(SETTINGS_FIELDS)
                or (set(SETTINGS_FIELDS) - set(OPTIONAL_SETTINGS)) - set(value["settings"])):
            raise ValueError("invalid settings metadata")
        # Older account snapshots do not inherit another account's new defaults.
        return _route({**base, **OPTIONAL_SETTINGS, **value["settings"], "workspace": name})
    except (OSError, ValueError, TypeError):
        raise Blocked("工作区线路设置无法完整读取；未切换账号，也未覆盖原设置。") from None


def _settings_value(name: str, route: dict) -> dict:
    return {"schema": 1, "workspace": name, "settings": route}


def _remember_file(path: Path) -> dict | None:
    if path.is_symlink():
        raise Blocked("工作区线路设置不能使用符号链接。")
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Blocked("工作区线路设置无法完整读取，未覆盖。") from None


def _rollback_settings(originals: dict[Path, dict | None]) -> None:
    for path, original in originals.items():
        if original is None:
            if path.is_symlink():
                raise Blocked("工作区设置回滚时发现符号链接；已停止。")
            path.unlink(missing_ok=True)
        else:
            write_json(path, original)


def save_settings(config_path: Path, candidate: dict) -> dict:
    """Save the active account's route and shared machine settings atomically.

    A caller wanting to change accounts must use use(); configure cannot change
    workspace accidentally through an old GUI form. Active sessions must stop
    first, so a launch never observes a half-updated account/route pairing.
    """
    candidate = validate_config(candidate)
    with account_switch(config_path):
        current = load_config(config_path) if config_path.exists() else None
        if current and current["workspace"] != candidate["workspace"]:
            raise Blocked("当前工作区已变更，请刷新设置后保存；未覆盖其他账号的线路。")
        name = candidate["workspace"]
        with exclusive(config_path, name):
            file = _settings_path(config_path, name)
            # Validate before allowing a malformed saved route to be replaced.
            _read_settings(config_path, name, candidate)
            previous = {file: _remember_file(file)}
            try:
                write_json(file, _settings_value(name, _route(candidate)))
                return save_config(config_path, candidate)
            except Exception:
                _rollback_settings(previous)
                raise


def listing(config_path: Path, config: dict) -> dict:
    root = safe_root(config_path)
    names = {"A", "B", config.get("workspace", "A")}
    names.update(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink()
                 and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", p.name))
    items = []
    for name in sorted(names):
        loc = location(config_path, name)
        label = name
        if (loc / "metadata.json").is_file():
            try:
                label = json.loads((loc / "metadata.json").read_text()).get("label", name)
            except (OSError, ValueError, AttributeError):
                pass
        snapshots = []
        if not (loc / "snapshots").is_symlink():
            for file in (loc / "snapshots").glob("*/manifest.json"):
                if file.parent.is_symlink() or file.is_symlink():
                    continue
                try:
                    value = json.loads(file.read_text())
                    snapshots.append({k: value[k] for k in ("id", "label", "created_at")})
                except (OSError, ValueError, KeyError, TypeError):
                    continue
        # Legacy active data already belongs to the selected account, even
        # before the first per-workspace settings file has been written.
        route = (_route(config) if name == config.get("workspace", "A")
                 else _read_settings(config_path, name, config))
        items.append({"name": name, "label": label, "route": route,
                      "route_configured": route is not None,
                      "snapshots": sorted(snapshots, key=lambda s: s["created_at"], reverse=True)})
    return {"current_workspace": config.get("workspace", "A"), "workspaces": items}


def use(config_path: Path, config: dict, name: str, *, stop_sessions=None, apply_route=None) -> dict:
    """Commit browser, CLI account selection and route as one active config.

    stop_sessions(path, name) may gracefully close app-owned supervisors while
    the global launch gate is closed. apply_route(old, new) may activate only
    the app-owned route and return an undo callable for a later commit failure.
    It must roll back its own partial effects if it raises. Unknown sessions
    and Chrome locks remain fail-closed; no personal browser data is touched.
    """
    name = name_ok(name)
    with account_switch(config_path):
        current = assert_current(config_path, config)
        old_name = current["workspace"]
        names = list(dict.fromkeys((old_name, name)))
        if stop_sessions is not None:
            for workspace in names:
                stop_sessions(config_path, workspace)
        with ExitStack() as stack:
            for workspace in sorted(names):
                stack.enter_context(exclusive(config_path, workspace))
            old_file = _settings_path(config_path, old_name)
            new_file = _settings_path(config_path, name)
            _read_settings(config_path, old_name, current)
            target = _read_settings(config_path, name, current)
            # First use creates independent route settings only. Login data,
            # cookies, CLI credentials and keychain references are never copied.
            target = _route(current) if target is None or name == old_name else target
            updated = validate_config(dict(current, **target, workspace=name))
            originals = {file: _remember_file(file) for file in (old_file, new_file)}
            undo = None
            try:
                write_json(old_file, _settings_value(old_name, _route(current)))
                write_json(new_file, _settings_value(name, target))
                if apply_route is not None:
                    undo = apply_route(current, updated)
                    if undo is not None and not callable(undo):
                        raise Blocked("线路切换没有返回有效回滚操作，未提交账号切换。")
                return save_config(config_path, updated)
            except Exception:
                try:
                    if callable(undo):
                        undo()
                finally:
                    _rollback_settings(originals)
                raise


@contextmanager
def browser_session(path: Path, config: dict):
    """Lease the canonical Browser/Default from preparation through process exit.

    Web and OAuth share this profile and therefore this exclusive lease. The
    shared workspace lock still permits CLI work but excludes snapshots/restore.
    Chrome's own lock is checked after leasing, before any preference write.
    """
    path = Path(path)
    if (not path.is_absolute() or path.is_symlink() or
            any(p.is_symlink() for p in path.parents if p.exists())):
        raise Blocked("专用浏览器工作区位置异常。")
    with _lock(path, exclusive=False):
        _initialize(path, config["workspace"])
        fd = os.open(path / ".browser.lock", os.O_RDWR | os.O_CREAT |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise Blocked("专用浏览器锁文件的类型或所有者异常。")
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BrowserProfileBusy(
                    "专用网页或授权窗口正在使用同一份登录资料。请关闭专用窗口后重试；不会改用空白资料或个人 Chrome。") from None
            profile = path / "data/Browser"
            if os.path.lexists(profile / "SingletonLock"):
                raise BrowserProfileBusy(
                    "专用网页或授权窗口仍在运行，或退出后留有锁。请关闭专用窗口后重试，或点击检查并修复浏览器锁。")
            _prepare_browser_preferences(profile, config)
            yield profile
        finally:
            os.close(fd)


def prepare_browser_language(config_path: Path, config: dict) -> None:
    """Prepare only this app's stopped browser profile, preserving other data.

    The historical name remains for CLI compatibility. WebRTC preferences are
    always applied; language is changed only when explicitly configured. These
    stored preferences alone do not prove effective runtime containment.
    """
    with browser_session(location(config_path, config["workspace"]), config):
        pass


def prepare_oauth_browser(config_path: Path, config: dict) -> Path:
    """Compatibility preparation helper; OAuth runtime holds browser_session.

    The legacy OAuthBrowser directory is left untouched. Login data is neither
    copied nor merged: both entry points use the existing Browser/Default.
    """
    with browser_session(location(config_path, config["workspace"]), config) as profile:
        return profile


def _prepare_browser_preferences(profile: Path, config: dict) -> None:
    language = config.get("browser_language", "")
    if language and (not isinstance(language, str) or
                     not re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", language)):
        raise Blocked("专用浏览器语言设置格式不正确，未修改。")
    default = profile / "Default"
    if default.is_symlink():
        raise Blocked("专用浏览器 Default 目录不能使用符号链接。")
    prefs = default / "Preferences"
    if prefs.is_symlink():
        raise Blocked("专用浏览器设置不能使用符号链接。")
    try:
        data = json.loads(prefs.read_text()) if prefs.exists() else {}
        if (not isinstance(data, dict) or
                not isinstance(data.get("webrtc", {}), dict) or
                (language and not isinstance(data.get("intl", {}), dict))):
            raise ValueError("invalid preferences")
    except (OSError, ValueError):
        raise Blocked("专用浏览器设置无法完整读取，未修改。") from None
    if language:
        intl = data.setdefault("intl", {})
        intl["accept_languages"] = language
        # Chrome derives its language list from selected_languages on startup.
        # Keep both preferences aligned so an older selection cannot return.
        intl["selected_languages"] = language
    webrtc = data.setdefault("webrtc", {})
    webrtc["ip_handling_policy"] = "disable_non_proxied_udp"
    # Chromium's actual preference key is singular: webrtc.ip_handling_url.
    webrtc["ip_handling_url"] = []
    write_json(prefs, data)
