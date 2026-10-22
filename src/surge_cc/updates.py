"""Explicit stable-release updates. Never reads account data or changes routing.

GitHub is the distribution trust root until Developer ID releases are available.
Checksums detect corrupt downloads, not a compromised publisher. Installation is
same-path, with a retained rollback bundle and exclusive workspace launch locks.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid
import zipfile

from . import __version__, workspaces
from .core import Blocked

REPO = "jsjixu/surge-cc"
API = "https://api.github.com/repos/" + REPO + "/releases/"
BASE = "https://github.com/" + REPO + "/releases/"
MAX_ZIP = 250 * 1024 * 1024
MAX_EXPANDED = 500 * 1024 * 1024


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", value):
        raise Blocked("更新版本号无效；仅接受正式版本。")
    return tuple(map(int, value.split(".")))


def _safe_path(path, *, directory=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in str(path)):
        raise Blocked("更新目录路径无效。")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise Blocked("更新目录不能经过符号链接。")
    if path.exists():
        info = path.stat()
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise Blocked("更新文件的所有者或写入权限异常。")
        if directory and not path.is_dir():
            raise Blocked("更新目录不可用。")
    return path


def _root(config_path):
    root = _safe_path(Path(config_path).parent / "updates", directory=True)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise Blocked("更新缓存必须属于当前用户，权限为 700。")
    return root


def _get(url, limit, *, timeout=30):
    allowed = {"api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
    def valid(value):
        parsed = urlsplit(value)
        return (parsed.scheme == "https" and parsed.hostname in allowed and parsed.port in (None, 443)
                and not parsed.username and not parsed.password)
    class Redirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not valid(newurl):
                raise Blocked("下载重定向到了未经允许的地址，已停止。")
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    if not valid(url):
        raise Blocked("更新下载地址不可信。")
    request = urllib.request.Request(url, headers={"User-Agent": "Surge-CC-Updater", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.build_opener(Redirects()).open(request, timeout=timeout) as response:
            if not valid(response.url):
                raise Blocked("更新下载来源无法确认。")
            chunks, total = [], 0
            while True:
                block = response.read(min(1024 * 1024, limit + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > limit:
                    raise Blocked("更新文件超过允许大小，已停止。")
            return b"".join(chunks)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise Blocked("暂时无法连接 GitHub 更新服务；现有版本和账号资料未改变。") from None


def release(requested=None, *, fetch=_get):
    if requested is not None:
        version(requested)
    raw = json.loads(fetch(API + ("tags/v" + requested if requested else "latest"), 1024 * 1024))
    if not isinstance(raw, dict) or raw.get("draft") is not False or raw.get("prerelease") is not False:
        raise Blocked("更新服务未返回可验证的正式发布。")
    tag = raw.get("tag_name", "")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise Blocked("正式发布版本无效。")
    value = tag[1:]
    version(value)
    if requested and value != requested:
        raise Blocked("返回的版本与所选版本不一致。")
    if raw.get("html_url") != BASE + "tag/" + tag:
        raise Blocked("发布页面来源不一致。")
    name = "Surge-CC-" + value + "-arm64.zip"
    assets = raw.get("assets", [])
    if not isinstance(assets, list):
        raise Blocked("发布资产清单无效。")
    selected = {}
    for expected in (name, name + ".sha256"):
        matches = [a for a in assets if isinstance(a, dict) and a.get("name") == expected]
        if len(matches) != 1:
            raise Blocked("该版本缺少唯一的安装包或校验清单。")
        asset = matches[0]
        expected_url = BASE + "download/" + tag + "/" + expected
        size = asset.get("size")
        if (asset.get("browser_download_url") != expected_url or type(size) is not int
                or not 0 < size <= (MAX_ZIP if expected == name else 4096)):
            raise Blocked("发布文件来源或大小无效。")
        selected[expected] = asset
    return {"version": value, "release_url": raw["html_url"], "asset_name": name,
            "size": selected[name]["size"], "notes": str(raw.get("body") or "")[:12000],
            "url": selected[name]["browser_download_url"],
            "sha_url": selected[name + ".sha256"]["browser_download_url"]}


def last_install(config_path):
    if config_path is None:
        return None
    root = Path(config_path).parent / "updates"
    if not root.is_dir():
        return None
    try:
        _safe_path(root, directory=True)
        for file in sorted(root.glob("install-*/result.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:1]:
            _safe_path(file)
            if file.stat().st_size > 16384:
                return None
            value = json.loads(file.read_text())
            state = value.get("state")
            labels = {"installed": "上次安装成功，账号与线路设置保留。",
                      "rolled-back": "上次更新自检失败，已恢复旧版应用。",
                      "failed": "上次更新未完成；可重新检查版本后重试。"}
            if state not in labels:
                return None
            return {"state": state, "summary": labels[state],
                    "backup_available": state == "installed" and bool(value.get("backup_path"))}
    except (OSError, ValueError, TypeError, AttributeError, Blocked):
        return None


def check(config_path=None, *, current=__version__, fetch=_get):
    previous = last_install(config_path)
    try:
        data = release(fetch=fetch)
    except (Blocked, ValueError, TypeError, KeyError):
        return {"state": "unavailable", "current_version": current,
                "summary": "暂时无法确认 GitHub 最新版本；现有安装未改变。",
                "last_install": previous, "can_download": False}
    order = (version(data["version"]) > version(current)) - (version(data["version"]) < version(current))
    return {**{k: v for k, v in data.items() if k not in {"url", "sha_url"}},
            "state": "available" if order > 0 else "ahead" if order < 0 else "current",
            "current_version": current, "latest_version": data["version"],
            "last_install": previous,
            "summary": "发现可下载的新版本。" if order > 0 else "已安装当前正式版。" if order == 0 else "本地版本高于当前 GitHub 正式版。",
            "can_download": order > 0 and platform.machine() == "arm64"}


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _extract(package, destination):
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > 2500 or sum(i.file_size for i in infos) > MAX_EXPANDED:
            raise Blocked("安装包文件数量或展开大小异常。")
        seen = set()
        for info in infos:
            path = PurePosixPath(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if (path.is_absolute() or ".." in path.parts or "\\" in info.filename
                    or not path.parts or any(ord(c) < 32 for c in info.filename)
                    or path.parts[0] != "Surge CC.app" or info.filename.casefold() in seen
                    or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise Blocked("安装包包含不支持的路径、链接或特殊文件。")
            seen.add(info.filename.casefold())
            target = destination.joinpath(*path.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if mode & 0o111 else 0o644)
    return destination / "Surge CC.app"


def verify_app(app, expected, *, run=None):
    run = run or subprocess.run
    _safe_path(app, directory=True)
    info_path = app / "Contents/Info.plist"
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException):
        raise Blocked("安装包的应用信息无效。") from None
    if (info.get("CFBundleIdentifier") != "local.surgecc.app"
            or info.get("CFBundleShortVersionString") != expected
            or info.get("CFBundleExecutable") != "SurgeCC"):
        raise Blocked("安装包的应用标识或版本不匹配。")
    for relative in ("Contents/MacOS/SurgeCC", "Contents/Resources/scripts/surge-cc",
                     "Contents/Resources/src/surge_cc/cli.py"):
        if not (app / relative).is_file() or (app / relative).is_symlink():
            raise Blocked("安装包缺少必要程序。")
    checked = run(["/usr/bin/codesign", "--verify", "--strict", str(app)],
                  capture_output=True, timeout=30)
    if checked.returncode:
        raise Blocked("应用代码签名校验失败，未安装。")
    arch = run(["/usr/bin/lipo", "-archs", str(app / "Contents/MacOS/SurgeCC")],
               capture_output=True, text=True, timeout=15)
    if arch.returncode or platform.machine() not in arch.stdout.split():
        raise Blocked("安装包不支持当前 Mac 的处理器。")
    minimum = info.get("LSMinimumSystemVersion")
    if not isinstance(minimum, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", minimum):
        raise Blocked("安装包缺少有效的系统版本要求。")
    actual = platform.mac_ver()[0]
    def os_version(value):
        return tuple(int(n) for n in value.split(".")) + (0,) * (3 - len(value.split(".")))
    if not actual or os_version(actual) < os_version(minimum):
        raise Blocked("当前 macOS 版本不满足新版要求，保留原应用。")
    return info


def download(config_path, requested, *, current=__version__, fetch=_get, verify=verify_app):
    if platform.machine() != "arm64":
        raise Blocked("目前发布安装包仅适用于 Apple Silicon；此机器请使用源码构建。")
    data = release(requested, fetch=fetch)
    root = _root(config_path)
    stage = Path(tempfile.mkdtemp(prefix=".download-", dir=root))
    try:
        checksum = fetch(data["sha_url"], 4096).decode("ascii").strip()
        match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?" + re.escape(data["asset_name"]), checksum)
        if not match:
            raise Blocked("安装包校验清单格式或文件名不一致。")
        package = stage / data["asset_name"]
        package.write_bytes(fetch(data["url"], MAX_ZIP, timeout=90))
        if package.stat().st_size != data["size"] or _sha(package) != match[1].lower():
            raise Blocked("安装包大小或 SHA-256 不匹配，已丢弃下载。")
        app = _extract(package, stage)
        verify(app, requested)
        saved = {"schema": 1, "version": requested, "asset_name": data["asset_name"],
                 "sha256": match[1].lower(), "release_url": data["release_url"]}
        workspaces.write_json(stage / "manifest.json", saved)
        target = root / requested
        _safe_path(target, directory=True)
        if target.exists():
            # Keep the previous verified copy until the replacement is ready.
            target.rename(root / ("previous-download-" + uuid.uuid4().hex))
        stage.rename(target)
        return {**saved, "state": "downloaded", "package_path": str(target / data["asset_name"]),
                "can_install": version(requested) > version(current)}
    except (zipfile.BadZipFile, UnicodeError, ValueError, OSError):
        raise Blocked("更新下载或解压未完成；当前安装未改变。") from None
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _tree_digest(app):
    digest = hashlib.sha256()
    for path in sorted(app.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise Blocked("更新应用目录包含链接或特殊文件。")
        info = path.stat()
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise Blocked("更新应用文件权限异常。")
        digest.update(str(path.relative_to(app)).encode())
        digest.update(str(stat.S_IMODE(info.st_mode)).encode())
        if path.is_file():
            digest.update(_sha(path).encode())
    return digest.hexdigest()


def installed_app():
    for parent in Path(__file__).absolute().parents:
        if parent.suffix == ".app" and (parent / "Contents/Info.plist").is_file():
            return _safe_path(parent, directory=True)
    raise Blocked("应用内升级需要从已安装的 Surge CC.app 运行；源码目录请手动构建。")


def _cached(config_path, requested):
    version(requested)
    folder = _safe_path(_root(config_path) / requested, directory=True)
    file = _safe_path(folder / "manifest.json")
    if not file.is_file() or file.stat().st_size > 4096:
        raise Blocked("请先下载并校验所选版本。")
    data = json.loads(file.read_text())
    name = "Surge-CC-" + requested + "-arm64.zip"
    if (not isinstance(data, dict) or data.get("schema") != 1 or data.get("version") != requested
            or data.get("asset_name") != name or data.get("release_url") != BASE + "tag/v" + requested
            or not re.fullmatch(r"[a-f0-9]{64}", str(data.get("sha256")))):
        raise Blocked("更新缓存记录无效，请重新下载。")
    package = _safe_path(folder / name)
    if not package.is_file() or package.stat().st_size > MAX_ZIP or _sha(package) != data["sha256"]:
        raise Blocked("下载缓存已变化，请重新下载。")
    # Re-extract the checked archive; never trust an editable staging directory.
    return package


def _all_idle(config_path, stack):
    stack.enter_context(workspaces.account_switch(config_path))
    root = workspaces.safe_root(config_path)
    for path in sorted(root.iterdir()):
        if path.is_dir():
            stack.enter_context(workspaces.exclusive(config_path, path.name))


def _app_pids(app):
    checked = subprocess.run(["/bin/ps", "-axo", "pid=,comm="], capture_output=True, text=True, timeout=10)
    if checked.returncode:
        raise Blocked("无法确认应用进程状态，未替换应用。")
    expected = str(app / "Contents/MacOS/SurgeCC")
    return [int(line.strip().split(None, 1)[0]) for line in checked.stdout.splitlines()
            if len(line.strip().split(None, 1)) == 2 and line.strip().split(None, 1)[1] == expected]


def install(config_path, requested, *, current=__version__, app=None, popen=subprocess.Popen):
    if version(requested) <= version(current):
        raise Blocked("应用内更新只安装更新的正式版本；不会自动降级。")
    app = installed_app() if app is None else _safe_path(app, directory=True)
    package = _cached(config_path, requested)
    verify_app(app, current)
    with ExitStack() as stack:
        _all_idle(config_path, stack)
    if not os.access(app.parent, os.W_OK):
        raise Blocked("安装目录不可写；请将应用放入当前用户可管理的位置后再更新。")
    job = Path(tempfile.mkdtemp(prefix="install-", dir=_root(config_path)))
    # Copy the trusted updater before replacing its parent bundle.
    shutil.copytree(Path(__file__).parent, job / "src/surge_cc", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    pid = os.getppid()
    comm = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True).stdout.strip()
    gui_pid = pid if comm == str(app / "Contents/MacOS/SurgeCC") else None
    if any(p != gui_pid for p in _app_pids(app)):
        raise Blocked("请从正在运行的 Surge CC 维护中心安装，或先正常退出应用再安装。")
    receipt = {"schema": 1, "config": str(config_path), "app": str(app), "version": requested,
               "current": current, "package": str(package), "package_sha256": _sha(package),
               "app_digest": _tree_digest(app), "gui_pid": gui_pid}
    workspaces.write_json(job / "job.json", receipt)
    env = {k: v for k, v in os.environ.items() if k in {"HOME", "PATH", "TMPDIR", "LANG"}}
    env.update(PYTHONPATH=str(job / "src"), PYTHONDONTWRITEBYTECODE="1")
    child = popen([sys.executable, "-B", "-m", "surge_cc.updates", str(job / "job.json")],
          env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
          start_new_session=True, close_fds=True)
    for _ in range(1200):
        if (job / "ready.json").exists():
            workspaces.write_json(job / "ack.json", {"accepted": True})
            return {"state": "installing", "version": requested, "receipt_path": str(job / "result.json"),
                    "summary": "更新已准备，将关闭并重新打开 Surge CC；登录资料保留。macOS 可能需要重新授权。"}
        if (job / "result.json").exists():
            raise Blocked("升级准备未通过；当前应用未替换。请结束受控会话后重试。")
        time.sleep(.1)
    workspaces.write_json(job / "cancel.json", {"cancelled": True})
    try:
        child.terminate()
    except ProcessLookupError:
        pass
    raise Blocked("升级准备超时并已取消；现有应用未替换。")


def _worker(file):
    """Detached helper, containing no shell interpolation or remote executable code."""
    job = file.parent
    stage = None
    swapped = False
    result = {"ok": False, "state": "failed", "summary": "更新未完成，现有账号资料未改变。"}
    try:
        _safe_path(file)
        if file.stat().st_uid != os.getuid() or file.stat().st_mode & 0o077 or file.stat().st_size > 16384:
            raise Blocked("更新任务记录无效。")
        data = json.loads(file.read_text())
        if (not isinstance(data, dict) or data.get("schema") != 1
                or version(data.get("version")) <= version(data.get("current"))
                or (data.get("gui_pid") is not None and (type(data["gui_pid"]) is not int or data["gui_pid"] <= 1))):
            raise Blocked("更新任务记录无效。")
        config = _safe_path(Path(data["config"]))
        app = _safe_path(Path(data["app"]), directory=True)
        package = _safe_path(Path(data["package"]))
        if _sha(package) != data["package_sha256"] or _tree_digest(app) != data["app_digest"]:
            raise Blocked("升级准备后文件发生变化。")
        with ExitStack() as stack:
            _all_idle(config, stack)
            stage = Path(tempfile.mkdtemp(prefix=".surgecc-update-", suffix=".noindex", dir=app.parent))
            fresh = _extract(package, stage)
            verify_app(fresh, data["version"])
            workspaces.write_json(job / "ready.json", {"ready": True})
            for _ in range(600):
                if (job / "cancel.json").exists():
                    raise Blocked("更新已取消。")
                if (job / "ack.json").is_file():
                    if json.loads((job / "ack.json").read_text()) == {"accepted": True}:
                        break
                    raise Blocked("安装确认无效。")
                time.sleep(.1)
            else:
                raise Blocked("未收到安装确认，未替换应用。")
            gui_pid = data.get("gui_pid")
            for _ in range(600):
                if gui_pid is None:
                    break
                try:
                    os.kill(gui_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.1)
            else:
                raise Blocked("等待 Surge CC 退出超时，未替换应用。")
            if (job / "cancel.json").exists() or _app_pids(app):
                raise Blocked("更新已取消或应用仍运行，未替换应用。")
            if _tree_digest(app) != data["app_digest"] or _sha(package) != data["package_sha256"]:
                raise Blocked("安装前文件发生变化，已停止。")
            from .terminal import _exchange
            _exchange(fresh, app)
            swapped = True
            try:
                verify_app(app, data["version"])
                check = subprocess.run([sys.executable, "-B", str(app / "Contents/Resources/scripts/surge-cc"), "--help"],
                                       capture_output=True, timeout=20)
                if check.returncode:
                    raise Blocked("新版基础自检失败。")
            except Exception:
                _exchange(fresh, app)
                swapped = False
                result["state"] = "rolled-back"
                raise
            # Keep a rollback copy out of normal app discovery, on the same volume.
            backup = stage / "previous.noindex"
            try:
                fresh.rename(backup)
            except OSError:
                # A cosmetic backup rename must not turn a verified successful
                # replacement into an ambiguous failure. The private noindex
                # staging directory still retains the complete previous app.
                backup = fresh
            result = {"ok": True, "state": "installed", "version": data["version"],
                      "backup_path": str(backup), "summary": "已更新应用；账号、个人 Chrome 和 Surge 配置未修改。"}
    except Exception:
        # No raw OS/network errors (which may include paths/credentials) in UI receipts.
        pass
    finally:
        workspaces.write_json(job / "result.json", result)
        if stage is not None and stage.exists() and not swapped:
            shutil.rmtree(stage)
    if result["state"] in {"installed", "rolled-back"}:
        try:
            opened = subprocess.run(["/usr/bin/open", "-a", str(app)], capture_output=True, timeout=15)
            if opened.returncode:
                result["summary"] += " 应用未能自动重开，请手动打开。"
                workspaces.write_json(job / "result.json", result)
        except (OSError, subprocess.SubprocessError):
            pass
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(_worker(Path(sys.argv[1])))
