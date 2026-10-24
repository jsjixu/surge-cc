"""URL stdin protocol keeps links and tokens out of results and errors."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from surge_cc import cli, link_router

class LinkCLITests(unittest.TestCase):
    config = Path('/private/tmp/synthetic-links/config.json')
    router = Path('/private/tmp/synthetic-links/Surge CC Links.app/Contents/Resources/router.json')

    def invoke(self, value, **kwargs):
        output = io.StringIO()
        with patch('sys.stdin', io.StringIO(value)), redirect_stdout(output):
            code = cli.main(['--config', str(self.config), 'links', 'open', '--router-config', str(self.router), '--json'])
        return code, json.loads(output.getvalue())

    def test_open_uses_stdin_and_no_url_in_reply(self):
        request = {'url':'https://example.com/private?token=synthetic', 'source':None}
        reply = {'schema':1,'action':'fallback','message':'previous browser','app':'/Applications/Browser.app'}
        with patch.object(link_router,'load',return_value={'config':str(self.config)}), \
             patch.object(link_router,'open_request',return_value=reply) as opened:
            code, result = self.invoke(json.dumps(request))
        self.assertEqual(code,0)
        opened.assert_called_once_with(self.router, request, confirmed_from=None)
        self.assertNotIn('synthetic',json.dumps(result))

    def test_invalid_oversize_or_mismatched_request_does_not_open(self):
        for content in ('not json', 'x'*32769):
            with patch.object(link_router,'load',return_value={'config':str(self.config)}), \
                 patch.object(link_router,'open_request') as opened:
                code,result=self.invoke(content)
                self.assertEqual(code,2)
                opened.assert_not_called()
                self.assertEqual(result['action'],'blocked')
        with patch.object(link_router,'load',return_value={'config':'/different/config.json'}), \
             patch.object(link_router,'open_request') as opened:
            self.assertEqual(self.invoke('{}')[0],2)
            opened.assert_not_called()

    def test_unexpected_error_is_redacted_and_never_fallback(self):
        with patch.object(link_router,'load',return_value={'config':str(self.config)}), \
             patch.object(link_router,'open_request',side_effect=RuntimeError('sensitive-url-query')):
            code,result=self.invoke('{"url":"https://example.com/","source":null}')
        self.assertEqual(code,2)
        self.assertNotIn('sensitive',json.dumps(result))
        self.assertEqual(result['action'],'blocked')
