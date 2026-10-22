"""Independent terminal/Orca launch contracts, with no network or personal data."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from surge_cc import cli, core


def configuration():
    return core.validate_config({'schema': 1, 'group': 'Claude', 'policy': 'Fixed',
                                 'expected_ip': '203.0.113.10', 'proxy_url': 'http://127.0.0.1:62919'})


def checked(ok=True):
    return {'ok': ok, 'summary': 'checked' if ok else 'route failed', 'checks': []}


class TerminalLaunchContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='terminal-launch-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / 'config.json'
        self.config = configuration()
        core.save_config(self.config_path, self.config)
        self.native = self.root / 'native-claude'
        self.native.write_text('#!/bin/sh\nexit 99\n')
        self.native.chmod(0o700)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(patch.object(cli, 'default_claude', return_value=self.native))
        self.real_settings_check = cli.code_settings_ok
        self.settings_check = self.stack.enter_context(patch.object(cli, 'code_settings_ok', return_value=True))
        factory = self.stack.enter_context(patch.object(cli, 'OAuthSession'))
        self.oauth = factory.return_value.__enter__.return_value
        self.oauth.browser_hook = self.root / 'oauth-hook'
        self.checker = Mock(return_value=checked())
        self.guarded = Mock(side_effect=self.completed_guard)
        self.original_launch = cli.launch
        self.stdin_data = None
        self.stream_output = ''
        self.child_exit = 0
        self.child = Mock(name='owned-claude-child')

    def completed_guard(self, command, **kwargs):
        kwargs['on_started'](self.child)
        self.stdin_data = sys.stdin.read() if isinstance(sys.stdin, io.StringIO) else None
        if self.stream_output:
            sys.stdout.write(self.stream_output)
        receipt = kwargs['receipt_path']
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({'schema': 1, 'target': 'code', 'state': 'running', 'ok': True}))
        return self.child_exit

    def launch(self, args, **overrides):
        values = {'checker': self.checker, 'guarded': self.guarded}
        values.update(overrides)
        return self.original_launch(self.config, self.config_path, 'code', False, args, **values)

    def main(self, args=None):
        out, err, input_stream = io.StringIO(), io.StringIO(), io.StringIO('{"type":"user","message":"hello"}\n')
        def protected(config, config_path, target, terminal, arguments, *, startup_release):
            return self.original_launch(config, config_path, target, terminal, arguments,
                                        checker=self.checker, guarded=self.guarded,
                                        startup_release=startup_release)
        with patch.object(cli, 'launch', side_effect=protected), patch.object(sys, 'stdin', input_stream), redirect_stdout(out), redirect_stderr(err):
            code = cli.main(['--config', str(self.config_path), 'launch', 'code', '--passthrough', '--', *(args or [])])
        return code, out.getvalue(), err.getvalue()

    def test_passthrough_preserves_stdout_stream_and_stdin_exactly(self):
        self.stream_output = '{"type":"system","session_id":"test"}\n{"type":"result","result":"hello"}\n'
        code, out, err = self.main(['--print', '--output-format', 'stream-json', '--input-format', 'stream-json'])
        self.assertEqual(code, 0)
        self.assertEqual(out, self.stream_output)
        self.assertEqual(err, '')
        self.assertEqual(self.stdin_data, '{"type":"user","message":"hello"}\n')

    def test_passthrough_guard_failure_uses_stderr_only_and_never_starts(self):
        self.checker.return_value = checked(False)
        code, out, err = self.main(['--print', 'hello'])
        self.assertEqual(code, 2)
        self.assertEqual(out, '')
        self.assertIn('route failed', err)
        self.guarded.assert_not_called()

    def test_passthrough_keeps_native_nonzero_exit_and_stdout(self):
        self.child_exit = 42
        self.stream_output = '{"type":"result","is_error":true}\n'
        code, out, err = self.main(['--print', '--output-format', 'stream-json'])
        self.assertEqual(code, 42)
        self.assertEqual(out, self.stream_output)
        self.assertTrue(err)
        self.assertNotIn('session_id', err)

    def test_passthrough_blocked_exception_uses_stderr_only(self):
        self.checker.side_effect = core.Blocked('route validation refused')
        code, out, err = self.main(['auth', 'login'])
        self.assertEqual(code, 2)
        self.assertEqual(out, '')
        self.assertIn('route validation refused', err)
        self.guarded.assert_not_called()

    def test_passthrough_system_exception_is_sanitized_on_stderr(self):
        self.checker.side_effect = OSError('secret-token-and-private-path')
        code, out, err = self.main()
        self.assertEqual(code, 1)
        self.assertEqual(out, '')
        self.assertNotIn('secret-token', err)
        self.assertTrue(err)
        self.guarded.assert_not_called()

    def test_orca_inline_settings_and_sources_reach_child_intact(self):
        settings = json.dumps({'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': 'true'}]}]}, 'env': {'EDITOR': 'code'}})
        args = ['--print', '--output-format', 'stream-json', '--input-format', 'stream-json',
                '--setting-sources', 'user,project,local', '--settings', settings]
        report = self.launch(args)
        self.assertTrue(report['launched'])
        actual = self.guarded.call_args.args[0]
        self.assertEqual(actual[:2], [str(self.native), '--settings'])
        merged = json.loads(actual[2])
        self.assertEqual(merged, {**json.loads(settings), 'remoteControlAtStartup': False, 'forceLoginMethod': 'claudeai'})
        self.assertEqual(actual[3:], args[:-2])
        env = self.guarded.call_args.kwargs['env']
        self.assertEqual(env['BROWSER'], str(self.oauth.browser_hook))
        self.assertEqual(env['CLAUDE_CONFIG_DIR'], str(self.root / 'workspaces/A/data/Claude'))
        self.assertEqual(env['HTTP_PROXY'], self.config['proxy_url'])
        self.assertEqual(env['HTTPS_PROXY'], self.config['proxy_url'])
        self.assertEqual(env['NO_PROXY'], '')
        self.assertEqual(env['DISABLE_AUTOUPDATER'], '1')
        self.assertEqual(env['DISABLE_UPDATES'], '1')
        self.oauth.set_child.assert_called_once_with(self.child)
        self.assertNotIn('BROWSER', os.environ)
        self.assertNotIn('HTTP_PROXY', os.environ)

    def test_matching_workspace_environment_is_accepted(self):
        selected = str(self.root / 'workspaces/A/data/Claude')
        with patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': selected}):
            self.assertTrue(self.launch([])['launched'])
        self.assertEqual(self.guarded.call_args.kwargs['env']['CLAUDE_CONFIG_DIR'], selected)

    def test_inherited_other_workspace_is_replaced_with_active_account(self):
        inherited = str(self.root / 'other-workspace')
        selected = str(self.root / 'workspaces/A/data/Claude')
        with patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': inherited}):
            self.assertTrue(self.launch([])['launched'])
            self.assertEqual(os.environ['CLAUDE_CONFIG_DIR'], inherited)
        self.checker.assert_called_once_with(self.config)
        self.assertEqual(self.guarded.call_args.kwargs['env']['CLAUDE_CONFIG_DIR'], selected)
        self.assertEqual(self.settings_check.call_args.args[2]['CLAUDE_CONFIG_DIR'], selected)

    def test_inherited_relative_workspace_cannot_select_child_account(self):
        selected = str(self.root / 'workspaces/A/data/Claude')
        with patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': 'custom-config'}):
            self.assertTrue(self.launch([])['launched'])
            self.assertEqual(os.environ['CLAUDE_CONFIG_DIR'], 'custom-config')
        self.assertEqual(self.guarded.call_args.kwargs['env']['CLAUDE_CONFIG_DIR'], selected)
        self.assertEqual(self.settings_check.call_args.args[2]['CLAUDE_CONFIG_DIR'], selected)

    def test_maintenance_commands_with_leading_flags_are_refused(self):
        for args in (['--debug', 'update'], ['--verbose', 'install'], ['--debug', 'upgrade'],
                     ['update'], ['install'], ['upgrade'],
                     ['update', '--print'], ['--debug', 'install', '--print']):
            with self.subTest(args=args), self.assertRaises(core.Blocked):
                self.launch(args)
        self.checker.assert_not_called()
        self.guarded.assert_not_called()

    def test_inline_settings_flags_equal_forms_and_fixed_proxy_allowed(self):
        value = json.dumps({'env': {'HTTP_PROXY': self.config['proxy_url'], 'NO_PROXY': '', 'DISABLE_AUTOUPDATER': '1'}})
        self.assertTrue(self.launch(['--setting-sources=user,project', '--settings=' + value])['launched'])

    def test_settings_cannot_replace_proxy_browser_workspace_or_provider(self):
        overrides = (
            {'HTTP_PROXY': 'http://127.0.0.1:6152'}, {'http_proxy': 'http://127.0.0.1:6152'},
            {'NO_PROXY': '*'}, {'npm_config_noproxy': 'anthropic.com'}, {'BROWSER': '/usr/bin/open'},
            {'CLAUDE_CONFIG_DIR': '/tmp/other'}, {'DISABLE_AUTOUPDATER': '0'},
            {'DISABLE_UPDATES': '0'}, {'ANTHROPIC_BASE_URL': 'https://example.com'},
        )
        for env in overrides:
            with self.subTest(env=env), self.assertRaises(core.Blocked):
                self.launch(['--settings', json.dumps({'env': env})])
        self.checker.assert_not_called()
        self.guarded.assert_not_called()

    def test_settings_file_path_malformed_and_nonobject_are_refused(self):
        file = self.root / 'settings.json'
        file.write_text('{}')
        for value in (str(file), '{broken', '[]', 'null', '{"env": []}', '{"remoteControlAtStartup":true}'):
            with self.subTest(value=value), self.assertRaises(core.Blocked):
                self.launch(['--settings', value])
        self.guarded.assert_not_called()

    def test_all_settings_occurrences_are_checked(self):
        safe = json.dumps({'env': {'EDITOR': 'code'}})
        unsafe = json.dumps({'env': {'BROWSER': '/usr/bin/open'}})
        for args in (['--settings', safe, '--settings', unsafe],
                     ['--settings=' + unsafe, '--settings=' + safe]):
            with self.subTest(args=args), self.assertRaises(core.Blocked):
                self.launch(args)
        self.guarded.assert_not_called()

    def test_setting_sources_invalid_duplicate_empty_and_missing_refused(self):
        for args in (['--setting-sources', 'user,unknown'], ['--setting-sources', 'user,user'],
                     ['--setting-sources', ''], ['--setting-sources'], ['--settings']):
            with self.subTest(args=args), self.assertRaises(core.Blocked):
                self.launch(args)
        self.guarded.assert_not_called()

    def test_oauth_login_keeps_arguments_and_installs_private_browser_hook(self):
        self.assertTrue(self.launch(['auth', 'login'])['launched'])
        actual = self.guarded.call_args.args[0]
        self.assertEqual(actual[:2], [str(self.native), '--settings'])
        self.assertEqual(json.loads(actual[2]), {'remoteControlAtStartup': False, 'forceLoginMethod': 'claudeai'})
        self.assertEqual(actual[3:], ['auth', 'login'])
        self.assertEqual(self.guarded.call_args.kwargs['env']['BROWSER'], str(self.oauth.browser_hook))
        self.oauth.set_child.assert_called_once_with(self.child)

    def test_remote_startup_user_file_is_overridden_without_writing(self):
        folder = self.root / '.claude'
        folder.mkdir()
        path = folder / 'settings.json'
        original = '{"remoteControlAtStartup":true,"model":"sonnet"}\n'
        path.write_text(original)
        # Call the original helper, bypassing only this fixture's launch mock.
        self.assertTrue(self.real_settings_check(self.config, self.root, {'CLAUDE_CONFIG_DIR': str(self.root / 'isolated')}))
        self.launch([])
        actual = self.guarded.call_args.args[0]
        self.assertEqual(json.loads(actual[2]), {'remoteControlAtStartup': False, 'forceLoginMethod': 'claudeai'})
        self.assertEqual(path.read_text(), original)

    def test_settings_merge_preserves_orca_hooks_and_env(self):
        first = {'env': {'EDITOR': 'code'}, 'hooks': {'Stop': []}, 'model': 'sonnet'}
        second = {'env': {'VISUAL': 'vim'}, 'permissionMode': 'default'}
        args = ['--print', '--settings', json.dumps(first), '--setting-sources', 'user,project',
                '--settings=' + json.dumps(second), '--output-format', 'stream-json']
        self.launch(args)
        actual = self.guarded.call_args.args[0]
        merged = json.loads(actual[2])
        self.assertEqual(merged['env'], {'EDITOR': 'code', 'VISUAL': 'vim'})
        self.assertEqual(merged['hooks'], first['hooks'])
        self.assertEqual(merged['model'], 'sonnet')
        self.assertEqual(merged['permissionMode'], 'default')
        self.assertIs(merged['remoteControlAtStartup'], False)
        self.assertEqual(merged['forceLoginMethod'], 'claudeai')
        self.assertEqual(actual[3:], ['--print', '--setting-sources', 'user,project', '--output-format', 'stream-json'])
        self.assertEqual(actual.count('--settings'), 1)

    def test_remote_startup_project_does_not_hide_conflicting_proxy(self):
        folder = self.root / '.claude'
        folder.mkdir()
        (folder / 'settings.json').write_text(json.dumps({'remoteControlAtStartup': True,
                                                         'env': {'HTTP_PROXY': 'http://127.0.0.1:6152'}}))
        self.assertFalse(self.real_settings_check(self.config, self.root, {'CLAUDE_CONFIG_DIR': str(self.root / 'isolated')}))

    def test_terminal_marker_skips_only_optional_external_dns(self):
        from surge_cc import containment
        self.config['cli_process_paths'] = [str(self.native)]
        self.config['browser_path'] = str(self.root / 'Private.app/Contents/MacOS/Google Chrome')
        with patch.dict(os.environ, {'SURGE_CC_TERMINAL_ENTRY': '1'}), \
                patch.object(containment, 'cli_scope_covers', return_value=True), \
                patch.object(cli, 'full_checks', return_value=checked()) as mandatory:
            self.assertTrue(self.launch([], checker=mandatory)['launched'])
            mandatory.assert_called_once_with(self.config, external_dns=False)
        self.guarded.assert_called_once()

    def test_managed_remote_startup_is_not_assumed_overridable(self):
        managed = Path('/Library/Application Support/ClaudeCode/managed-settings.json')
        with patch.object(Path, 'exists', autospec=True, side_effect=lambda path: path == managed), \
                patch.object(Path, 'glob', return_value=[]), \
                patch.object(Path, 'read_text', return_value='{"remoteControlAtStartup":true}'):
            self.assertFalse(self.real_settings_check(self.config, self.root, {'CLAUDE_CONFIG_DIR': str(self.root / 'isolated')}))

    def test_explicit_remote_startup_request_is_still_rejected(self):
        with self.assertRaises(core.Blocked):
            self.launch(['--settings', '{"remoteControlAtStartup":true}'])
        self.guarded.assert_not_called()

    def test_cli_cannot_switch_to_unowned_remote_session(self):
        for args in (['--remote'], ['--background'], ['remote-control'], ['--cloud'], ['attach']):
            with self.subTest(args=args), self.assertRaises(core.Blocked):
                self.launch(args)
        self.guarded.assert_not_called()


if __name__ == '__main__':
    unittest.main()
