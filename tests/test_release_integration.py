"""Offline release integration: the public CLI, native argv, and account upgrades."""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from surge_cc import cli, core, guard, isolation, keychain_auth, shortcuts, workspaces


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='scc-release-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config_path = self.root / 'support/config.json'
        self.config = core.validate_config({
            'schema': 1, 'group': 'Claude', 'policy': 'Fixed',
            'expected_ip': '203.0.113.10', 'proxy_url': 'http://127.0.0.1:62919',
            'default_model': 'claude-opus-5-5', 'default_effort': 'high',
            'browser_start_page': 'newtab'})
        core.save_config(self.config_path, self.config)

    def call(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(['--config', str(self.config_path), *args])
        return code, json.loads(out.getvalue()), err.getvalue()


class PublicCommandTests(Fixture):
    def test_shortcut_install_forwards_current_release_parameters(self):
        app = self.root / 'Surge CC.app'
        with patch.object(shortcuts, 'install', return_value={'ok': True, 'app': '/fixture/Browser.app'}) as install:
            code, value, _ = self.call('shortcut', 'install', '--name', 'Work Browser', '--workspace', 'A',
                                     '--start-page', 'newtab', '--app', str(app), '--json')
        self.assertEqual(code, 0)
        self.assertTrue(value['ok'])
        self.assertEqual(value['shortcut']['app'], '/fixture/Browser.app')
        install.assert_called_once_with(self.config_path, 'A', 'Work Browser', 'newtab', app, applications_dir=None)

    def test_custom_workspace_is_supported_by_shortcut_cli(self):
        with patch.object(shortcuts, 'install', return_value={'ok': True}) as install:
            code, _, _ = self.call('shortcut', 'install', '--name', 'Work Browser', '--workspace', 'Work-2',
                                  '--start-page', 'newtab', '--app', str(self.root / 'Surge CC.app'), '--json')
        self.assertEqual(code, 0)
        self.assertEqual(install.call_args.args[1], 'Work-2')

    def test_shortcut_raw_focus_reply_and_signal_handler_restored(self):
        before = signal.getsignal(signal.SIGTERM)
        launcher = self.root / 'Browser.app/Contents/Resources/launcher.json'
        reply = {'schema': 1, 'action': 'focus', 'focused': True, 'message': 'verified'}
        with patch.object(shortcuts, 'load_launcher', return_value={'config': str(self.config_path)}), \
                patch.object(shortcuts, 'open_launcher', return_value=reply) as opened:
            code, result, _ = self.call('shortcut', 'open', '--launcher-config', str(launcher), '--json')
        self.assertEqual(code, 0)
        self.assertEqual(result, reply)
        opened.assert_called_once_with(launcher, None, expected_config=self.config_path)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_shortcut_switch_prompt_is_raw_and_not_an_error(self):
        reply = {'schema': 1, 'action': 'needs_switch', 'message': 'confirm', 'current': 'B'}
        with patch.object(shortcuts, 'load_launcher', return_value={'config': str(self.config_path)}), \
                patch.object(shortcuts, 'open_launcher', return_value=reply):
            code, result, _ = self.call('shortcut', 'open', '--launcher-config', '/fixture/launcher.json', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(result['action'], 'needs_switch')

    def test_shortcut_configuration_mismatch_does_not_open(self):
        with patch.object(shortcuts, 'load_launcher', return_value={'config': '/other/config.json'}), \
                patch.object(shortcuts, 'open_browser') as opened:
            code, result, _ = self.call('shortcut', 'open', '--launcher-config', '/fixture/launcher.json', '--json')
        self.assertEqual(code, 2)
        self.assertEqual(result['action'], 'blocked')
        opened.assert_not_called()

    def test_shortcut_all_system_errors_use_sanitized_native_reply(self):
        before = signal.getsignal(signal.SIGTERM)
        for failure in (FileNotFoundError('sensitive-path'), ValueError('secret-json'), RuntimeError('private-state')):
            with self.subTest(error=type(failure).__name__), \
                    patch.object(shortcuts, 'load_launcher', side_effect=failure), \
                    patch.object(shortcuts, 'open_browser') as opened:
                code, result, err = self.call('shortcut', 'open', '--launcher-config', '/fixture/launcher.json', '--json')
            self.assertEqual(code, 2)
            self.assertEqual(result['schema'], 1)
            self.assertEqual(result['action'], 'blocked')
            self.assertTrue(result['message'])
            self.assertNotIn(str(failure), json.dumps(result) + err)
            self.assertEqual(signal.getsignal(signal.SIGTERM), before)
            opened.assert_not_called()

    def test_configure_saves_preferences_in_the_active_workspace(self):
        code, value, _ = self.call('configure', '--group', 'Claude', '--policy', 'Fixed',
                                  '--expected-ip', '203.0.113.10', '--proxy-url', 'http://127.0.0.1:62919',
                                  '--default-model', 'opus', '--default-effort', 'high',
                                  '--browser-start-page', 'newtab', '--expected-workspace', 'A', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(value['settings']['default_model'], 'opus')
        self.assertEqual(core.load_config(self.config_path)['default_effort'], 'high')
        settings = json.loads((self.config_path.parent / 'workspaces/A/settings.json').read_text())
        self.assertEqual(settings['settings']['browser_start_page'], 'newtab')

    def test_configure_invalid_model_leaves_settings_unchanged(self):
        before = self.config_path.read_bytes()
        code, value, _ = self.call('configure', '--group', 'Claude', '--policy', 'Fixed',
                                  '--expected-ip', '203.0.113.10', '--proxy-url', 'http://127.0.0.1:62919',
                                  '--default-model', 'bad model; command', '--json')
        self.assertEqual(code, 2)
        self.assertFalse(value['ok'])
        self.assertEqual(before, self.config_path.read_bytes())

    def test_setup_doctor_command_uses_public_envelope(self):
        from surge_cc import onboarding
        with patch.object(onboarding, 'doctor', return_value={'schema': 1, 'ok': True, 'checks': []}) as doctor:
            code, result, _ = self.call('setup', 'doctor', '--json')
        self.assertEqual(code, 0)
        doctor.assert_called_once_with(self.config_path)
        self.assertEqual(result['setup'], {'schema': 1, 'ok': True, 'checks': []})

    def test_setup_doctor_missing_dependency_sets_outer_failure(self):
        from surge_cc import onboarding
        report = {'schema': 1, 'ok': False, 'checks': [
            {'id': 'claude', 'ok': False, 'required': True, 'detail': 'missing fixture'}]}
        with patch.object(onboarding, 'doctor', return_value=report):
            code, result, _ = self.call('setup', 'doctor', '--json')
        self.assertEqual(code, 2)
        self.assertFalse(result['ok'])
        self.assertEqual(result['setup'], report)

    def test_project_status_command_uses_public_envelope(self):
        from surge_cc import projects
        with patch.object(projects, 'status', return_value={'projects': []}) as status:
            code, result, _ = self.call('project', 'status', '--json')
        self.assertEqual(code, 0)
        status.assert_called_once_with(self.config_path)
        self.assertEqual(result['project'], {'projects': []})


class AccountUpgradeTests(Fixture):
    def legacy_workspace_b(self):
        old_fields = set(workspaces.SETTINGS_FIELDS) - set(workspaces.OPTIONAL_SETTINGS)
        b = core.validate_config(dict(self.config, workspace='B', group='BGroup', policy='BNode',
                                      expected_ip='203.0.113.20'))
        file = self.config_path.parent / 'workspaces/B/settings.json'
        workspaces.write_json(file, {'schema': 1, 'workspace': 'B',
                                    'settings': {name: b[name] for name in old_fields}})
        return file

    def test_legacy_workspace_does_not_inherit_current_account_defaults(self):
        old = self.legacy_workspace_b()
        before = old.read_bytes()
        info = workspaces.listing(self.config_path, self.config)
        b = next(item for item in info['workspaces'] if item['name'] == 'B')
        self.assertEqual(b['route']['default_model'], '')
        self.assertEqual(b['route']['default_effort'], '')
        self.assertEqual(b['route']['browser_start_page'], 'claude')
        self.assertEqual(old.read_bytes(), before)

    def test_switching_old_account_back_preserves_distinct_preferences(self):
        self.legacy_workspace_b()
        b = workspaces.use(self.config_path, self.config, 'B')
        self.assertEqual((b['policy'], b['expected_ip']), ('BNode', '203.0.113.20'))
        self.assertEqual((b['default_model'], b['default_effort'], b['browser_start_page']), ('', '', 'claude'))
        a = workspaces.use(self.config_path, b, 'A')
        self.assertEqual((a['default_model'], a['default_effort'], a['browser_start_page']),
                         ('claude-opus-5-5', 'high', 'newtab'))
        self.assertEqual((a['policy'], a['expected_ip']), ('Fixed', '203.0.113.10'))

    def test_old_account_does_not_gain_current_token_config(self):
        self.legacy_workspace_b()
        owned = self.config_path.parent / 'workspaces/A/data/Claude/current-only.json'
        owned.parent.mkdir(parents=True)
        owned.write_text('{"synthetic": "account-A-only"}')
        workspaces.use(self.config_path, self.config, 'B')
        self.assertFalse((self.config_path.parent / 'workspaces/B/data/Claude/current-only.json').exists())
        self.assertEqual(owned.read_text(), '{"synthetic": "account-A-only"}')


class NativeLaunchIntegrationTests(Fixture):
    def setUp(self):
        super().setUp()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.native = self.root / 'claude'
        self.native.write_text('#!/bin/sh\nexit 99\n')
        self.native.chmod(0o700)
        self.stack.enter_context(patch.object(cli, 'default_claude', return_value=self.native))
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(patch.object(cli, 'migrate_accounts'))
        self.stack.enter_context(patch.object(guard, 'RuntimeChecker'))
        self.stack.enter_context(patch.object(keychain_auth, 'load', return_value=None))
        self.stack.enter_context(patch.object(cli, 'code_settings_ok', return_value=True))
        factory = self.stack.enter_context(patch.object(cli, 'OAuthSession'))
        self.oauth = factory.return_value.__enter__.return_value
        self.oauth.browser_hook = Path('/private/tmp/surge-cc-oauth-release-fixture/browser')
        self.guarded = Mock(side_effect=self.completed)
        self.checker = Mock(return_value={'ok': True, 'checks': [], 'summary': 'synthetic'})
        original = cli.launch
        self.stack.enter_context(patch.object(cli, 'launch', side_effect=lambda config, path, target, terminal, args, startup_release:
            original(config, path, target, terminal, args, startup_release=startup_release,
                     checker=self.checker, guarded=self.guarded)))
        self.cwd = self.root / 'project'
        self.cwd.mkdir()
        self.stack.enter_context(patch.object(cli.Path, 'cwd', return_value=self.cwd))

    def completed(self, command, **kwargs):
        receipt = kwargs['receipt_path']
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({'schema': 1, 'target': 'code', 'state': 'running', 'ok': True}))
        return 0

    def enable_isolated_fixture(self):
        base = self.root / 'isolated'
        project = base / 'projects/demo'
        home = base / '.runtime/demo/home'
        project.mkdir(parents=True, mode=0o700)
        home.mkdir(parents=True, mode=0o700)
        registry = self.config_path.parent / isolation.REGISTRY_NAME
        workspaces.write_json(registry, {'schema': 1, 'root': str(base), 'projects': [
            {'id': 'demo', 'path': str(project), 'home': str(home)}]})
        keychain_auth.migrate_legacy(self.config_path, 'A')
        self.stack.enter_context(patch.object(isolation, 'DEFAULT_ROOT', base))
        self.stack.enter_context(patch.object(cli.Path, 'cwd', return_value=project))
        return home

    def test_default_model_effort_reach_ordinary_native_guard(self):
        code, value, _ = self.call('launch', 'code', '--json', '--', '--help')
        self.assertEqual(code, 0)
        self.assertTrue(value['launched'])
        command = self.guarded.call_args.args[0]
        settings = json.loads(command[command.index('--settings') + 1])
        self.assertEqual((settings['model'], settings['effortLevel']), ('claude-opus-5-5', 'high'))
        self.assertEqual(command[0], str(self.native))
        self.assertFalse(settings['remoteControlAtStartup'])
        self.assertEqual(self.guarded.call_args.kwargs['env']['HTTP_PROXY'], self.config['proxy_url'])

    def test_isolated_native_guard_gets_defaults_and_keeps_clean_home(self):
        home = self.enable_isolated_fixture()
        code, value, _ = self.call('launch', 'code', '--json', '--', '--help')
        self.assertEqual(code, 0)
        self.assertTrue(value['launched'])
        call = self.guarded.call_args
        command = call.args[0]
        self.assertEqual(command[0], str(isolation.SANDBOX))
        self.assertEqual(command[3], str(self.native))
        settings = json.loads(command[command.index('--settings') + 1])
        self.assertEqual((settings['model'], settings['effortLevel']), ('claude-opus-5-5', 'high'))
        self.assertTrue(settings['disableAllHooks'])
        self.assertEqual(call.kwargs['env']['HOME'], str(home))
        self.assertEqual(call.kwargs['env']['HTTPS_PROXY'], self.config['proxy_url'])
        self.assertEqual(call.kwargs['env']['NO_PROXY'], '')
        self.assertIn('--strict-mcp-config', command)

    def test_explicit_native_model_and_effort_flags_survive_default_injection(self):
        self.enable_isolated_fixture()
        code, _, _ = self.call('launch', 'code', '--json', '--', '--model', 'sonnet', '--effort', 'low', '--help')
        self.assertEqual(code, 0)
        command = self.guarded.call_args.args[0]
        self.assertEqual(command[-5:], ['--model', 'sonnet', '--effort', 'low', '--help'])

    def test_failed_route_never_spawns_default_model(self):
        self.checker.return_value = {'ok': False, 'checks': [], 'summary': 'synthetic blocked'}
        code, value, _ = self.call('launch', 'code', '--json', '--', '--help')
        self.assertEqual(code, 2)
        self.assertFalse(value['ok'])
        self.guarded.assert_not_called()


@unittest.skipUnless(os.environ.get('SURGE_CC_TEST_APP'), 'Set SURGE_CC_TEST_APP to validate a release bundle.')
class BundleReleaseIntegrationTests(Fixture):
    def setUp(self):
        super().setUp()
        self.app = Path(os.environ['SURGE_CC_TEST_APP']).resolve()
        self.resources = self.app / 'Contents/Resources'
        self.backend = self.resources / 'scripts/surge-cc'

    def invoke(self, *args):
        child = subprocess.run([sys.executable, '-I', '-B', str(self.backend), '--config', str(self.config_path), *args],
                               capture_output=True, text=True, timeout=20)
        return child.returncode, json.loads(child.stdout), child.stderr

    def test_bundle_contains_complete_onboarding_and_shortcut_runtime(self):
        for file in ('scripts/surge-cc', 'scripts/first-run.sh', 'SurgeCCShortcut', 'SurgeCCIcon.icns',
                     'src/surge_cc/onboarding.py', 'src/surge_cc/projects.py', 'src/surge_cc/shortcuts.py',
                     'src/surge_cc/messaging.py', 'src/surge_cc/shared_history.py',
                     'src/surge_cc/paste_terminal.py', 'src/surge_cc/pasted_images.py'):
            self.assertTrue((self.resources / file).is_file(), file)
        info = plistlib.loads((self.app / 'Contents/Info.plist').read_bytes())
        from surge_cc import __version__
        self.assertEqual(info['CFBundleShortVersionString'], __version__)
        self.assertFalse(any(self.app.rglob('launcher.json')))
        self.assertFalse(any(self.app.rglob('.local')))

    def test_bundled_cli_uses_supplied_config_and_saves_new_defaults(self):
        code, value, err = self.invoke('configure', '--group', 'FixtureGroup', '--policy', 'FixtureNode',
                                       '--expected-ip', '203.0.113.40', '--proxy-url', 'http://127.0.0.1:62919',
                                       '--default-model', 'opus', '--default-effort', 'high',
                                       '--browser-start-page', 'newtab', '--json')
        self.assertEqual(code, 0, err)
        self.assertEqual(value['settings']['group'], 'FixtureGroup')
        self.assertEqual(value['settings']['default_model'], 'opus')
        self.assertEqual(value['settings']['default_effort'], 'high')
        self.assertEqual(value['settings']['browser_start_page'], 'newtab')
        self.assertEqual(core.load_config(self.config_path)['expected_ip'], '203.0.113.40')

    def test_bundled_cli_missing_shortcut_keeps_native_protocol(self):
        code, value, err = self.invoke('shortcut', 'open', '--launcher-config', str(self.root / 'missing.json'), '--json')
        self.assertEqual(code, 2, err)
        self.assertEqual(value['action'], 'blocked')
        self.assertEqual(value['schema'], 1)
        self.assertNotIn(str(self.root), value['message'])

    def test_bundled_first_run_help_needs_no_compiler_or_browser(self):
        child = subprocess.run(['/bin/bash', str(self.resources / 'scripts/first-run.sh'), '--help'],
                               capture_output=True, text=True, timeout=20)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertIn('--config', child.stdout)

    def test_bundled_native_shortcut_rejects_invalid_focus_without_ui(self):
        child = subprocess.run([str(self.resources / 'SurgeCCShortcut'), '--focus-only', '{}'],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 2)
        self.assertEqual(json.loads(child.stdout), {'schema': 1, 'focused': False})

    def test_bundle_signature_is_valid(self):
        child = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(self.app)], capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 0)


if __name__ == '__main__':
    unittest.main()
