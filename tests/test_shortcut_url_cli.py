"""Default-browser requests use bounded stdin and never expose URL payloads."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from surge_cc import cli, shortcuts


class ShortcutURLCLITests(unittest.TestCase):
    config = Path('/private/tmp/synthetic-shortcut/config.json')
    launcher = Path('/private/tmp/synthetic-shortcut/Browser.app/Contents/Resources/launcher.json')

    def invoke(self, raw, *extra, action='open', with_url=True):
        output = io.StringIO()
        error = io.StringIO()
        argv = ['--config', str(self.config), 'shortcut', action,
                '--launcher-config', str(self.launcher), '--json', *extra]
        if with_url:
            argv.append('--url-stdin')
        with patch.object(sys, 'stdin', io.StringIO(raw)), redirect_stdout(output), redirect_stderr(error):
            code = cli.main(argv)
        return code, output.getvalue(), error.getvalue()

    def test_stdin_url_reaches_protected_opener_without_echo(self):
        url = 'https://example.com/private?auth=synthetic-secret'
        reply = {'schema': 1, 'action': 'focus', 'opened': True, 'focused': False}
        with patch.object(shortcuts, 'open_launcher_url', return_value=reply) as opener, \
                patch.object(shortcuts, 'open_launcher') as dock:
            code, output, error = self.invoke(json.dumps({'url': url}), '--confirm-switch-from', 'B')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), reply)
        opener.assert_called_once_with(self.launcher, {'url': url}, 'B', expected_config=self.config)
        dock.assert_not_called()
        self.assertNotIn(url, output + error)

    def test_normal_dock_open_does_not_read_stdin(self):
        with patch.object(shortcuts, 'open_launcher', return_value={'schema': 1, 'action': 'focus'}) as dock, \
                patch.object(shortcuts, 'open_launcher_url') as opener:
            code, output, error = self.invoke('not JSON', with_url=False)
        self.assertEqual(code, 0)
        dock.assert_called_once_with(self.launcher, None, expected_config=self.config)
        opener.assert_not_called()

    def test_invalid_and_oversized_stdin_stops_before_opener(self):
        for raw in ('{private-invalid-json', 'x' * 32769, '中文' * 6000):
            with self.subTest(length=len(raw)), patch.object(shortcuts, 'open_launcher_url') as opener:
                code, output, error = self.invoke(raw)
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output)['action'], 'blocked')
                opener.assert_not_called()
                self.assertNotIn(raw[:100], output + error)

    def test_exception_does_not_echo_private_url(self):
        url = 'https://example.com/private?auth=synthetic-secret'
        with patch.object(shortcuts, 'open_launcher_url', side_effect=RuntimeError(url)), \
                patch.object(shortcuts, 'open_launcher') as dock:
            code, output, error = self.invoke(json.dumps({'url': url}))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)['action'], 'blocked')
        self.assertNotIn(url, output + error)
        dock.assert_not_called()

    def test_route_failure_and_switch_prompt_preserve_existing_protocol(self):
        for reply, expected in (({'schema': 1, 'action': 'blocked', 'message': '线路不可用'}, 2),
                                ({'schema': 1, 'action': 'needs_switch', 'current': 'B'}, 0)):
            with self.subTest(reply=reply), patch.object(shortcuts, 'open_launcher_url', return_value=reply):
                before = signal.getsignal(signal.SIGTERM)
                code, output, error = self.invoke('{"url":"https://example.com/"}')
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(output), reply)
                self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_url_stdin_cannot_be_used_to_install(self):
        with patch.object(shortcuts, 'install') as install:
            code, output, error = self.invoke('{"url":"https://example.com/"}', action='install')
        self.assertEqual(code, 2)
        install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
