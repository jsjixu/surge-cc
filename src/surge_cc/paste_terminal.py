"""Interactive PTY transport for explicitly pasted, isolated image imports.

Only terminal input is inspected, and only complete bracketed-paste frames can
request an import. The route guard remains the owner of the actual child.
"""
import errno
import fcntl
import os
from pathlib import Path
import select
import signal
import subprocess
import termios
import threading
import time
import tty

from .core import Blocked


START = b"\x1b[200~"
END = b"\x1b[201~"
FAILED_IMAGE = b"[Surge CC: image import failed; paste the screenshot again]"
MAX_PASTE = 65536
MAX_QUEUE = 1024 * 1024
READ_SIZE = 16384


def _suffix(data, delimiter):
    """Length of a trailing, incomplete delimiter, without losing any bytes."""
    for size in range(min(len(data), len(delimiter) - 1), 0, -1):
        if data.endswith(delimiter[:size]):
            return size
    return 0


class InputFilter:
    def __init__(self, importer, *, max_paste=MAX_PASTE):
        if not isinstance(max_paste, int) or max_paste < len(START) + len(END):
            raise ValueError("invalid paste limit")
        self.importer = importer
        self.max_paste = max_paste
        self.pending = b""
        self.state = "text"
        self.imported = 0
        self.failed = 0

    def _import(self, payload):
        if not self.importer.matches_path(payload):
            return payload
        try:
            result = self.importer.import_path(payload)
            if (not isinstance(result, bytes) or not result.startswith(b"/") or
                    any(value in result for value in (b"\0", b"\r", b"\n", b"\x1b"))):
                raise Blocked("图片导入结果无效。")
        except (Blocked, OSError, ValueError):
            self.failed += 1
            return FAILED_IMAGE
        self.imported += 1
        return result

    def feed(self, data):
        if not isinstance(data, bytes):
            raise TypeError("terminal input must be bytes")
        self.pending += data
        output = bytearray()
        while self.pending:
            if self.state == "text":
                found = self.pending.find(START)
                if found >= 0:
                    output.extend(self.pending[:found])
                    self.pending = self.pending[found + len(START):]
                    self.state = "paste"
                    continue
                tail = _suffix(self.pending, START)
                cut = len(self.pending) - tail
                output.extend(self.pending[:cut])
                self.pending = self.pending[cut:]
                break
            found = self.pending.find(END)
            if found >= 0:
                payload = self.pending[:found]
                if self.state == "paste":
                    # A single large feed must observe the same cap as small
                    # chunks; overflow is ordinary paste, never an import.
                    output.extend(START)
                    output.extend(self._import(payload) if len(payload) <= self.max_paste else payload)
                else:
                    output.extend(payload)
                output.extend(END)
                self.pending = self.pending[found + len(END):]
                self.state = "text"
                continue
            if self.state == "paste" and len(self.pending) <= self.max_paste:
                break
            if self.state == "paste":
                output.extend(START)
                self.state = "overflow"
            tail = _suffix(self.pending, END)
            cut = len(self.pending) - tail
            output.extend(self.pending[:cut])
            self.pending = self.pending[cut:]
            break
        return bytes(output)

    def finish(self):
        output = (START if self.state == "paste" else b"") + self.pending
        self.pending = b""
        self.state = "text"
        return output

    def flush_idle_text(self):
        # A standalone Escape key is also a possible delimiter prefix. Do not
        # hold it indefinitely when there is no paste frame in progress.
        if self.state != "text":
            return b""
        output, self.pending = self.pending, b""
        return output


class _RelayChecker:
    def __init__(self, relay, checker):
        self.relay, self.checker = relay, checker

    def __getattr__(self, name):
        return getattr(self.checker, name)

    def check_stop(self):
        self.relay.check()
        check = getattr(self.checker, "check_stop", None)
        if check is not None:
            check()

    def check(self, **kwargs):
        self.relay.check()
        result = self.checker.check(**kwargs)
        self.relay.check()
        return result


class PasteTerminal:
    def __init__(self, importer, *, input_fd=0, output_fd=1,
                 popen_factory=subprocess.Popen):
        self.importer = importer
        self.input_fd, self.output_fd = input_fd, output_fd
        self.popen_factory = popen_factory
        self.filter = InputFilter(importer)
        self.master = self.slave = None
        self.tty_path = None
        self.child = None
        self._attributes = None
        self._flags = {}
        self._window = None
        self._thread = None
        self._closing = threading.Event()
        self._error = None
        self._entered = False
        self._raw = False

    def __enter__(self):
        if self._entered or not os.isatty(self.input_fd) or not os.isatty(self.output_fd):
            raise Blocked("图片粘贴通道需要独立的交互终端。")
        self._entered = True
        try:
            self._attributes = termios.tcgetattr(self.input_fd)
            self.master, self.slave = os.openpty()
            os.set_inheritable(self.master, False)
            os.set_inheritable(self.slave, False)
            self.tty_path = Path(os.ttyname(self.slave))
            termios.tcsetattr(self.slave, termios.TCSANOW, self._attributes)
            self._resize()
            return self
        except BaseException:
            self.close()
            raise

    def _resize(self):
        if self.master is None or self._closing.is_set():
            return
        window = fcntl.ioctl(self.input_fd, termios.TIOCGWINSZ, b"\0" * 8)
        if window == self._window:
            return
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, window)
        self._window = window
        child = self.child
        if child is not None and child.poll() is None:
            try:
                if child.pid > 1 and os.getpgid(child.pid) == child.pid:
                    os.killpg(child.pid, signal.SIGWINCH)
            except ProcessLookupError:
                pass

    def popen(self, command, **kwargs):
        if (self.slave is None or self.child is not None or self._raw or
                kwargs.get("start_new_session") is not True or
                kwargs.get("close_fds") is not True or
                any(key in kwargs for key in ("stdin", "stdout", "stderr", "preexec_fn", "pass_fds"))):
            raise Blocked("图片粘贴通道的进程隔离参数无效。")
        try:
            tty.setraw(self.input_fd, termios.TCSANOW)
            self._raw = True
            # stdin/stdout may be distinct descriptors of the same open-file
            # description. Capture all original flags before changing any.
            self._flags = {descriptor: fcntl.fcntl(descriptor, fcntl.F_GETFL)
                           for descriptor in {self.input_fd, self.output_fd, self.master}}
            for descriptor, flags in self._flags.items():
                fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            return self.popen_factory(command, stdin=self.slave, stdout=self.slave,
                                      stderr=self.slave, **kwargs)
        except BaseException:
            self._restore_terminal()
            raise

    def start(self, child):
        if self._thread is not None or not self._raw or self.slave is None:
            raise Blocked("图片粘贴通道未正确建立。")
        self.child = child
        os.close(self.slave)
        self.slave = None
        self._thread = threading.Thread(target=self._relay, name="surge-cc-image-paste", daemon=True)
        self._thread.start()

    def _relay(self):
        to_child, to_output = bytearray(), bytearray()
        master_eof = False
        eof_at = None
        closing_at = None
        last_input = time.monotonic()
        try:
            while True:
                closing = self._closing.is_set()
                if closing and closing_at is None:
                    closing_at = time.monotonic()
                if closing_at is not None and time.monotonic() - closing_at >= 0.75:
                    return
                if not closing and time.monotonic() - last_input >= 0.05:
                    to_child.extend(self.filter.flush_idle_text())
                if master_eof and not to_output:
                    if not closing and self.child.poll() is None:
                        # Closing the last slave precedes waitpid visibility
                        # during normal process exit. Allow a short reap gap.
                        if eof_at is None:
                            eof_at = time.monotonic()
                        if time.monotonic() - eof_at < 0.5:
                            self._closing.wait(0.01)
                            continue
                        raise Blocked("专用终端连接意外关闭，已停止受保护会话。")
                    return
                readers = []
                if not closing and not master_eof and len(to_child) < MAX_QUEUE:
                    readers.append(self.input_fd)
                if not master_eof and len(to_output) < MAX_QUEUE:
                    readers.append(self.master)
                writers = []
                if to_child and not master_eof:
                    writers.append(self.master)
                if to_output:
                    writers.append(self.output_fd)
                ready_read, ready_write, _ = select.select(readers, writers, [], 0.05)
                for descriptor in ready_read:
                    try:
                        data = os.read(descriptor, READ_SIZE)
                    except OSError as exc:
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                            continue
                        if descriptor == self.master and exc.errno == errno.EIO:
                            data = b""
                        else:
                            raise
                    if descriptor == self.master:
                        if data:
                            to_output.extend(data)  # Never parse child output.
                        else:
                            master_eof = True
                            to_child.clear()
                    elif not data:
                        raise Blocked("专用终端输入已关闭，已停止受保护会话。")
                    else:
                        last_input = time.monotonic()
                        to_child.extend(self.filter.feed(data))
                for descriptor in ready_write:
                    buffer = to_child if descriptor == self.master else to_output
                    if not buffer or (descriptor == self.master and master_eof):
                        continue
                    try:
                        count = os.write(descriptor, buffer[:READ_SIZE])
                    except OSError as exc:
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                            continue
                        if descriptor == self.master and exc.errno == errno.EIO:
                            master_eof = True
                            to_child.clear()
                            continue
                        raise
                    if count <= 0:
                        raise Blocked("专用终端转发中断，已停止受保护会话。")
                    del buffer[:count]
        except BaseException:
            if not self._closing.is_set():
                self._error = Blocked("图片粘贴终端转发异常，已停止受保护会话。")

    def check(self):
        if self._error is not None:
            raise self._error
        try:
            self._resize()
        except (OSError, ValueError, termios.error):
            raise Blocked("专用终端状态无法确认，已停止受保护会话。") from None

    def monitor(self, child, checker, **kwargs):
        from .guard import supervise
        return supervise(child, _RelayChecker(self, checker), **kwargs)

    def _restore_terminal(self):
        for descriptor, flags in self._flags.items():
            try:
                fcntl.fcntl(descriptor, fcntl.F_SETFL, flags)
            except OSError:
                pass
        self._flags.clear()
        if self._raw and self._attributes is not None:
            try:
                termios.tcsetattr(self.input_fd, termios.TCSANOW, self._attributes)
            except (OSError, termios.error):
                pass
        self._raw = False

    def close(self):
        self._closing.set()
        if self._thread is not None:
            self._thread.join(1.5)
        self._restore_terminal()
        for name in ("master", "slave"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, None)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(0.25)
            self._error = Blocked("图片粘贴通道未能正常停止，请关闭此专用终端。")

    def __exit__(self, kind, value, trace):
        self.close()
        if kind is None and self._error is not None:
            raise self._error
