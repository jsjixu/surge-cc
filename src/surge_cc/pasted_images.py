"""Import only explicitly pasted Orca PNGs into one isolated Claude HOME.

The caller must supply bytes from the user's terminal input, never from child
output. This trusted parent-side bridge grants the sandbox no tempdir access.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import threading
import zlib

from .core import Blocked

MAX_IMAGE = 20 * 1024 * 1024
MAX_PIXELS = 100_000_000
MAX_DIMENSION = 32768
MAX_CHUNKS = 65536
_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_NAME = re.compile(rb"orca-paste-[0-9]{10,17}-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\.png\Z")
_ERROR = "截图导入失败：文件位置、内容或权限不符合隔离要求；未开放系统临时目录。"


def _identity(info):
    return info.st_dev, info.st_ino


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)


def _directory(info, *, leaf=False, private=False):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}:
        raise ValueError("unsafe directory")
    if leaf and info.st_uid != os.getuid():
        raise ValueError("unowned directory")
    # Root-owned sticky ancestors such as /private/tmp are safe to traverse;
    # leaf directories and user-owned ancestors must not be writable by others.
    if info.st_mode & 0o022 and not (not leaf and info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
        raise ValueError("writable directory")
    if private and info.st_mode & 0o077:
        raise ValueError("nonprivate directory")


def _regular(info, *, private=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022)
            or not 0 < info.st_size <= MAX_IMAGE):
        raise ValueError("unsafe image")


class _DirectoryChain:
    """Pin every path component and detect symlink/rename replacements."""
    def __init__(self, path):
        self.path = Path(path)
        self.entries = []
        self.fds = []
        if (not self.path.is_absolute() or str(self.path) != os.path.normpath(str(self.path))
                or self.path.resolve() != self.path):
            raise ValueError("noncanonical directory")
        try:
            current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(current)
            _directory(os.fstat(current))
            for part in self.path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                self.fds.append(child)
                info = os.fstat(child)
                _directory(info, leaf=len(self.fds) == len(self.path.parts))
                self.entries.append((current, part, child, _identity(info)))
                current = child
            self.fd = current
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        if not self.fds:
            raise ValueError("closed image scope")
        for index, (parent, name, fd, identity) in enumerate(self.entries):
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            opened = os.fstat(fd)
            leaf = index == len(self.entries) - 1
            _directory(entry, leaf=leaf)
            _directory(opened, leaf=leaf)
            if _identity(entry) != identity or _identity(opened) != identity:
                raise ValueError("replaced image scope")

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []


def _validate_png(data):
    """Validate bounded PNG structure and CRCs, without decoding untrusted pixels."""
    if not 0 < len(data) <= MAX_IMAGE or not data.startswith(_SIGNATURE):
        raise ValueError("not PNG")
    offset, count = len(_SIGNATURE), 0
    seen_header = seen_palette = seen_data = ended_data = False
    color = None
    while offset < len(data):
        count += 1
        if count > MAX_CHUNKS or len(data) - offset < 12:
            raise ValueError("invalid PNG chunks")
        length = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + length
        if (end > len(data) or not re.fullmatch(rb"[A-Za-z]{4}", kind)
                or kind[2] & 32):
            raise ValueError("invalid PNG chunk")
        payload = data[offset + 8:offset + 8 + length]
        expected = struct.unpack_from(">I", data, offset + 8 + length)[0]
        if zlib.crc32(kind + payload) & 0xffffffff != expected:
            raise ValueError("bad PNG CRC")
        if not seen_header and kind != b"IHDR":
            raise ValueError("missing PNG header")
        if kind == b"IHDR":
            if seen_header or length != 13:
                raise ValueError("invalid PNG header")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
            if (not 0 < width <= MAX_DIMENSION or not 0 < height <= MAX_DIMENSION
                    or width * height > MAX_PIXELS or depth not in depths.get(color, set())
                    or compression != 0 or filtering != 0 or interlace not in {0, 1}):
                raise ValueError("invalid PNG dimensions or format")
            seen_header = True
        elif kind == b"PLTE":
            if seen_palette or seen_data or color in {0, 4} or not 3 <= length <= 768 or length % 3:
                raise ValueError("invalid PNG palette")
            seen_palette = True
        elif kind == b"IDAT":
            if ended_data or (color == 3 and not seen_palette):
                raise ValueError("invalid PNG data order")
            seen_data = True
        elif kind == b"IEND":
            if not seen_data or length != 0 or end != len(data):
                raise ValueError("invalid PNG end")
            return
        elif not kind[0] & 32:
            raise ValueError("unknown critical PNG chunk")
        elif seen_data:
            ended_data = True
        offset = end
    raise ValueError("missing PNG end")


def _os_temp_root():
    """Ask macOS directly; Python 3.9 omits this name from os.confstr_names."""
    try:
        value = os.confstr("CS_DARWIN_USER_TEMP_DIR")
    except (AttributeError, OSError, ValueError):
        try:
            result = subprocess.run(
                ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=3, check=True)
            raw = result.stdout
            if not isinstance(raw, bytes) or not 1 <= len(raw) <= 4096:
                raise ValueError("invalid OS temp result")
            if raw.endswith(b"\n"):
                raw = raw[:-1]
            value = os.fsdecode(raw)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("OS temp lookup failed") from None
    if (not isinstance(value, str) or not value.startswith("/") or len(os.fsencode(value)) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError("invalid OS temp root")
    path = Path(value)
    if str(path).startswith("/var/"):
        path = Path("/private" + str(path))
    return path


class ImageImporter:
    """One trusted launch's importer; imported files persist for session resume."""
    def __init__(self, home, source_root=None):
        self._home = self._source = None
        self._folder_fd = None
        self._folder_name = None
        self._folder_identity = None
        self._lock = threading.RLock()
        try:
            if source_root is None:
                source_root = _os_temp_root()
            self.home = Path(home)
            self.source_root = Path(source_root)
            # Fresh worktree HOME is prepared by isolation.command after the
            # PTY is allocated. Pin it only when the first paste is imported.
            self._source = _DirectoryChain(self.source_root)
            roots = [os.fsencode(self.source_root)]
            if str(self.source_root).startswith("/private/var/"):
                roots.append(os.fsencode(str(self.source_root)[len("/private"):]))
            self._prefixes = tuple(root.rstrip(b"/") + b"/" for root in roots)
        except (OSError, ValueError, TypeError, AttributeError):
            self.close()
            raise Blocked(_ERROR) from None

    def matches_path(self, payload):
        """Pure lexical check; no filesystem reads or imports."""
        return (isinstance(payload, bytes) and any(
            payload.startswith(prefix) and _NAME.fullmatch(payload[len(prefix):]) is not None
            for prefix in self._prefixes))

    def _verify(self):
        if self._home is None:
            self._home = _DirectoryChain(self.home)
        self._home.verify()
        self._source.verify()
        if self._folder_fd is not None:
            entry = os.stat(self._folder_name, dir_fd=self._home.fd, follow_symlinks=False)
            opened = os.fstat(self._folder_fd)
            _directory(entry, leaf=True, private=True)
            _directory(opened, leaf=True, private=True)
            if _identity(entry) != self._folder_identity or _identity(opened) != self._folder_identity:
                raise ValueError("replaced import folder")

    def _read(self, basename):
        fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._source.fd)
        try:
            before = os.fstat(fd)
            _regular(before)
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, min(65536, MAX_IMAGE + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_IMAGE:
                    raise ValueError("oversized image")
            after = os.fstat(fd)
            entry = os.stat(basename, dir_fd=self._source.fd, follow_symlinks=False)
            if _fingerprint(before) != _fingerprint(after) or _fingerprint(after) != _fingerprint(entry):
                raise ValueError("changed image")
            self._verify()
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _folder(self):
        if self._folder_fd is None:
            name = ".surge-cc-images-" + secrets.token_hex(16)
            os.mkdir(name, 0o700, dir_fd=self._home.fd)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._home.fd)
            try:
                info = os.fstat(fd)
                _directory(info, leaf=True, private=True)
                self._folder_fd, self._folder_name = fd, name
                self._folder_identity = _identity(info)
                self._verify()
            except BaseException:
                if self._folder_fd is None:
                    os.close(fd)
                raise
        return self._folder_fd

    def _write(self, data):
        directory = self._folder()
        name = "image-" + secrets.token_hex(16) + ".png"
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        complete = False
        identity = _identity(os.fstat(fd))
        try:
            remaining = memoryview(data)
            while remaining:
                count = os.write(fd, remaining)
                if count <= 0:
                    raise ValueError("failed image write")
                remaining = remaining[count:]
            os.fsync(fd)
            before = os.fstat(fd)
            _regular(before, private=True)
            os.lseek(fd, 0, os.SEEK_SET)
            copied = bytearray()
            while len(copied) <= len(data):
                chunk = os.read(fd, min(65536, len(data) + 1 - len(copied)))
                if not chunk:
                    break
                copied.extend(chunk)
            after = os.fstat(fd)
            entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (bytes(copied) != data or _fingerprint(before) != _fingerprint(after)
                    or _fingerprint(after) != _fingerprint(entry)):
                raise ValueError("changed imported image")
            self._verify()
            complete = True
            return os.fsencode(self.home / self._folder_name / name)
        finally:
            os.close(fd)
            if not complete:
                try:
                    entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if _identity(entry) == identity:
                        os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def import_path(self, payload):
        """Copy exactly one user-pasted PNG, or fail without widening access."""
        with self._lock:
            try:
                if not self.matches_path(payload):
                    raise ValueError("unexpected pasted path")
                self._verify()
                basename = payload.rsplit(b"/", 1)[1]
                data = self._read(basename)
                _validate_png(data)
                return self._write(data)
            except (OSError, ValueError, TypeError, AttributeError, struct.error):
                raise Blocked(_ERROR) from None

    def close(self):
        with self._lock:
            if self._folder_fd is not None:
                os.close(self._folder_fd)
                self._folder_fd = None
            for chain in (self._source, self._home):
                if chain is not None:
                    chain.close()

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.close()
