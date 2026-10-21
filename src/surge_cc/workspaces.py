"""App-owned working data and reversible snapshots; never reads personal credentials."""
from __future__ import annotations

from contextlib import contextmanager
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

from .core import Blocked, BrowserProfileBusy, now, save_config


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
        items.append({"name": name, "label": label, "snapshots": sorted(snapshots, key=lambda s: s["created_at"], reverse=True)})
    return {"current_workspace": config.get("workspace", "A"), "workspaces": items}


def use(config_path: Path, config: dict, name: str) -> dict:
    create(config_path, name)
    updated = dict(config, workspace=name)
    return save_config(config_path, updated)


def prepare_browser_language(config_path: Path, config: dict) -> None:
    """Prepare only this app's stopped browser profile, preserving other data.

    The historical name remains for CLI compatibility. WebRTC preferences are
    always applied; language is changed only when explicitly configured. These
    stored preferences alone do not prove effective runtime containment.
    """
    with exclusive(config_path, config["workspace"]) as loc:
        _prepare_browser_preferences(loc["browser"], config)


def prepare_oauth_browser(config_path: Path, config: dict) -> Path:
    """Prepare only the stopped OAuth profile while a CLI may hold a shared lock.

    The caller owns .oauth.lock for this profile's full browser lifetime.
    The ordinary webpage profile and personal Chrome are never touched.
    """
    path = location(config_path, config["workspace"])
    with _lock(path, exclusive=False):
        _initialize(path, config["workspace"])
        profile = path / "data/OAuthBrowser"
        if profile.is_symlink():
            raise Blocked("专用授权资料目录异常，未启动浏览器。")
        if os.path.lexists(profile / "SingletonLock"):
            raise BrowserProfileBusy("专用授权窗口仍在运行，或退出后留有锁。请在 Surge CC 中检查并修复浏览器锁。")
        profile.mkdir(mode=0o700, exist_ok=True)
        _prepare_browser_preferences(profile, config)
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
