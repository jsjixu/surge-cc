"""No model, clipboard, credentials or network needed for paste transport tests."""
import base64
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc.core import Blocked
from surge_cc.paste_terminal import (END, FAILED_IMAGE, START, InputFilter,
                                    PasteTerminal, _RelayChecker)


SOURCE = b"/var/folders/ab/user/T/orca-paste-1792665408955-d83d574a-82d3-48bb-ae09-557ecbd35da3.png"
DESTINATION = b"/isolated/home/attachments/image.png"


class Importer:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def matches_path(self, payload):
        return payload == SOURCE

    def import_path(self, payload):
        self.calls.append(payload)
        if self.fail:
            raise Blocked("private-source-details")
        return DESTINATION


class PasteInputTests(unittest.TestCase):
    def filtered(self, parts, *, fail=False, limit=65536):
        importer = Importer(fail)
        adapter = InputFilter(importer, max_paste=limit)
        result = b"".join(adapter.feed(part) for part in parts) + adapter.finish()
        return result, importer, adapter

    def test_every_single_chunk_boundary_and_one_byte_chunks(self):
        data = b"prefix:" + START + SOURCE + END + b"\r\x1b[A tail"
        expected = data.replace(SOURCE, DESTINATION)
        for index in range(len(data) + 1):
            with self.subTest(boundary=index):
                result, importer, adapter = self.filtered([data[:index], data[index:]])
                self.assertEqual(result, expected)
                self.assertEqual(importer.calls, [SOURCE])
                self.assertEqual(adapter.imported, 1)
        self.assertEqual(self.filtered([bytes([byte]) for byte in data])[0], expected)

    def test_plain_typed_path_and_terminal_controls_remain_exact(self):
        data = SOURCE + b"\r\x03\x04\x1b[A\x1b[B\x1b[6n\xe4\xb8\xad"
        result, importer, _ = self.filtered([bytes([byte]) for byte in data])
        self.assertEqual(result, data)
        self.assertEqual(importer.calls, [])

    def test_other_pastes_are_not_imported(self):
        for payload in (b"hello", b"", b"look at " + SOURCE, SOURCE + b" ",
                        b"'" + SOURCE + b"'", b"/etc/passwd", b"\x00" + SOURCE):
            with self.subTest(payload=payload):
                data = START + payload + END
                result, importer, _ = self.filtered([data])
                self.assertEqual(result, data)
                self.assertEqual(importer.calls, [])

    def test_multiple_pastes_one_chunk(self):
        data = START + SOURCE + END + b" " + START + b"text" + END + START + SOURCE + END
        result, importer, adapter = self.filtered([data])
        self.assertEqual(result, data.replace(SOURCE, DESTINATION))
        self.assertEqual(importer.calls, [SOURCE, SOURCE])
        self.assertEqual(adapter.imported, 2)

    def test_failed_import_replaces_only_frame_payload_preserves_enter(self):
        data = b"look " + START + SOURCE + END + b"\r"
        result, importer, adapter = self.filtered([data], fail=True)
        self.assertEqual(result, b"look " + START + FAILED_IMAGE + END + b"\r")
        self.assertNotIn(SOURCE, result)
        self.assertNotIn(b"private-source-details", result)
        self.assertEqual(adapter.failed, 1)

    def test_unfinished_frames_and_delimiters_preserved_at_eof(self):
        for data in (b"\x1b", b"x\x1b[20", START, START + SOURCE,
                     START + b"hello\x1b[201", b"x\x1b[200x"):
            with self.subTest(data=data):
                result, importer, _ = self.filtered([bytes([byte]) for byte in data])
                self.assertEqual(result, data)
                self.assertEqual(importer.calls, [])

    def test_oversized_paste_never_imported_or_accumulated_unboundedly(self):
        data = START + b"a" * 500 + END + START + SOURCE + END
        importer = Importer()
        adapter = InputFilter(importer, max_paste=128)
        result = bytearray()
        for byte in data:
            result.extend(adapter.feed(bytes([byte])))
            self.assertLessEqual(len(adapter.pending), 129)
        result.extend(adapter.finish())
        self.assertEqual(bytes(result), data.replace(SOURCE, DESTINATION))
        self.assertEqual(importer.calls, [SOURCE])
        # A complete oversized candidate arriving in one read is also refused.
        result, importer, _ = self.filtered([START + SOURCE + END], limit=12)
        self.assertEqual(result, START + SOURCE + END)
        self.assertEqual(importer.calls, [])

    def test_overflow_split_end_and_incomplete_end_are_preserved(self):
        for suffix in (END, END[:4], END + b"after"):
            data = START + b"x" * 100 + suffix
            for index in range(len(data) + 1):
                result, _, _ = self.filtered([data[:index], data[index:]], limit=16)
                self.assertEqual(result, data)

    def test_importer_cannot_inject_control_sequences(self):
        importer = Importer()
        importer.import_path = Mock(return_value=b"/new/path\rmalicious")
        adapter = InputFilter(importer)
        self.assertEqual(adapter.feed(START + SOURCE + END), START + FAILED_IMAGE + END)

    def test_idle_flush_releases_escape_but_not_in_progress_paste(self):
        adapter = InputFilter(Importer())
        self.assertEqual(adapter.feed(b"\x1b"), b"")
        self.assertEqual(adapter.flush_idle_text(), b"\x1b")
        self.assertEqual(adapter.feed(START + SOURCE), b"")
        self.assertEqual(adapter.flush_idle_text(), b"")
        self.assertEqual(adapter.feed(END), START + DESTINATION + END)


class PastePTYTests(unittest.TestCase):
    def setUp(self):
        self.outer_master, self.outer_slave = os.openpty()
        self.outer_output = os.dup(self.outer_slave)
        self.children = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
        for descriptor in (self.outer_master, self.outer_slave, self.outer_output):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def relay(self, importer=None, **kwargs):
        return PasteTerminal(importer or Importer(), input_fd=self.outer_slave,
                             output_fd=self.outer_output, **kwargs)

    def assert_termios_restored(self, before):
        after = termios.tcgetattr(self.outer_slave)
        # macOS sets its internal PENDIN bookkeeping bit when returning from
        # noncanonical mode; it is not a changed user terminal preference.
        after[3] &= ~getattr(termios, "PENDIN", 0)
        expected = list(before)
        expected[3] &= ~getattr(termios, "PENDIN", 0)
        self.assertEqual(after, expected)

    def read_until(self, needle, timeout=4):
        output = bytearray()
        deadline = time.monotonic() + timeout
        while needle not in output and time.monotonic() < deadline:
            readable, _, _ = select.select([self.outer_master], [], [], 0.1)
            if readable:
                try:
                    data = os.read(self.outer_master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                output.extend(data)
        self.assertIn(needle, output)
        return bytes(output)

    def spawn(self, relay, source):
        child = relay.popen([sys.executable, "-u", "-c", source],
                            start_new_session=True, close_fds=True, env=os.environ.copy())
        self.children.append(child)
        relay.start(child)
        return child

    def test_real_pty_transforms_input_preserves_actual_child_and_restores_terminal(self):
        before = termios.tcgetattr(self.outer_slave)
        flags = [fcntl.fcntl(fd, fcntl.F_GETFL) for fd in (self.outer_slave, self.outer_output)]
        source = """import os, tty, base64
tty.setraw(0)
os.write(1, b'READY\\n')
data = b''
while not data.endswith(b'\\r'):
    data += os.read(0, 4096)
os.write(1, b'RECEIVED:' + base64.b64encode(data) + b':DONE\\n')
"""
        importer = Importer()
        with self.relay(importer) as relay:
            self.assertTrue(str(relay.tty_path).startswith("/dev/"))
            child = self.spawn(relay, source)
            self.assertEqual(os.getpgid(child.pid), child.pid)
            self.read_until(b"READY")
            os.write(self.outer_master, START + SOURCE + END + b"\r")
            expected = b"RECEIVED:" + base64.b64encode(START + DESTINATION + END + b"\r") + b":DONE"
            self.read_until(expected)
            self.assertEqual(child.wait(timeout=3), 0)
            relay.check()
        self.assertEqual(importer.calls, [SOURCE])
        self.assert_termios_restored(before)
        # Darwin adds the kernel-only FWASWRITTEN bit on first terminal output.
        # Compare settable behavior flags rather than that internal history.
        mask = os.O_NONBLOCK | os.O_APPEND | getattr(os, "O_ASYNC", 0)
        self.assertEqual([fcntl.fcntl(fd, fcntl.F_GETFL) & mask
                          for fd in (self.outer_slave, self.outer_output)],
                         [value & mask for value in flags])

    def test_child_output_is_never_imported(self):
        importer = Importer()
        with self.relay(importer) as relay:
            source = "import os; os.write(1, " + repr(START + SOURCE + END + b":DONE") + ")"
            child = self.spawn(relay, source)
            self.read_until(START + SOURCE + END + b":DONE")
            self.assertEqual(child.wait(timeout=3), 0)
        self.assertEqual(importer.calls, [])

    def test_large_output_drains_under_backpressure(self):
        with self.relay() as relay:
            source = "import os; data=b'x'*(2*1024*1024)+b':DONE'; " \
                     "\nwhile data:\n data=data[os.write(1,data):]"
            child = self.spawn(relay, source)
            output = self.read_until(b":DONE")
            self.assertEqual(output, b"x" * (2 * 1024 * 1024) + b":DONE")
            self.assertEqual(child.wait(timeout=3), 0)
            relay.check()

    def test_unexpected_importer_error_is_visible_to_guard(self):
        importer = Importer()
        importer.import_path = Mock(side_effect=RuntimeError("private error"))
        relay = self.relay(importer)
        with self.assertRaises(Blocked):
            with relay:
                child = self.spawn(relay, "import os,tty,time; tty.setraw(0); os.write(1,b'READY'); time.sleep(5)")
                self.read_until(b"READY")
                os.write(self.outer_master, START + SOURCE + END)
                deadline = time.monotonic() + 2
                while relay._error is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                with self.assertRaises(Blocked) as raised:
                    relay.check()
                self.assertNotIn("private", str(raised.exception))
                # Guard, not relay, owns child termination.
                self.assertIsNone(child.poll())
                child.terminate()
                child.wait(timeout=3)

    def test_resize_changes_slave_dimensions(self):
        with self.relay() as relay:
            desired = struct.pack("HHHH", 41, 119, 0, 0)
            fcntl.ioctl(self.outer_slave, termios.TIOCSWINSZ, desired)
            relay.check()
            self.assertEqual(fcntl.ioctl(relay.slave, termios.TIOCGWINSZ, b"\0" * 8), desired)

    def test_spawn_failure_restores_flags_and_termios(self):
        before = termios.tcgetattr(self.outer_slave)
        flags = fcntl.fcntl(self.outer_slave, fcntl.F_GETFL)
        with self.relay(popen_factory=Mock(side_effect=OSError("failed"))) as relay:
            with self.assertRaises(OSError):
                relay.popen(["/missing"], start_new_session=True, close_fds=True)
            self.assert_termios_restored(before)
            self.assertEqual(fcntl.fcntl(self.outer_slave, fcntl.F_GETFL), flags)

    def test_forbids_unsafe_spawn_parameters_and_non_tty(self):
        with self.relay() as relay:
            for kwargs in ({}, {"start_new_session": True, "close_fds": False},
                           {"start_new_session": True, "close_fds": True, "pass_fds": ()}):
                with self.assertRaises(Blocked):
                    relay.popen(["/bin/cat"], **kwargs)
        read, write = os.pipe()
        try:
            with self.assertRaises(Blocked):
                with PasteTerminal(Importer(), input_fd=read, output_fd=write):
                    self.fail("must not enter")
        finally:
            os.close(read)
            os.close(write)

    def test_monitor_checker_checks_transport_every_poll_and_preserves_suspension(self):
        relay, underlying = Mock(), Mock()
        underlying.suspended = True
        checker = _RelayChecker(relay, underlying)
        self.assertTrue(checker.suspended)
        checker.check_stop()
        underlying.check_stop.assert_called_once_with()
        relay.check.assert_called_once_with()
        checker.check(include_exit=True)
        underlying.check.assert_called_once_with(include_exit=True)
        self.assertEqual(relay.check.call_count, 3)
        relay.check.side_effect = Blocked("closed")
        with self.assertRaises(Blocked):
            checker.check_stop()

    def test_monitor_delegates_guard_supervisor(self):
        with self.relay() as relay:
            child, checker = Mock(), Mock()
            with patch("surge_cc.guard.supervise", return_value=7) as supervise:
                self.assertEqual(relay.monitor(child, checker, target="code"), 7)
            self.assertIs(supervise.call_args.args[0], child)
            self.assertIs(supervise.call_args.args[1].checker, checker)
            self.assertEqual(supervise.call_args.kwargs, {"target": "code"})


if __name__ == "__main__":
    unittest.main()
