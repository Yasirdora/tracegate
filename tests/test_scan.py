import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from tracegate.scan import scan
from tracegate.cli import main


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def text(self, content, suffix='.trace'):
        p = self.root / ('input' + suffix)
        p.write_text(content)
        return p

    def archive(self, entries):
        p = self.root / 'trace.zip'
        with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, data in entries:
                z.writestr(name, data)
        return p

    def test_clean(self):
        self.assertEqual(scan(self.text('{"method":"click"}'))['status'], 'no-findings-in-scope')

    def test_header_without_value_disclosure(self):
        result = scan(self.text('{"headers":[{"name":"Authorization","value":"Bearer supersecret123"}]}'))
        self.assertEqual(result['status'], 'findings')
        self.assertNotIn('supersecret123', json.dumps(result))

    def test_pretty_json(self):
        result = scan(self.text(json.dumps({'password': 'synthetic'}, indent=2)))
        self.assertEqual(result['findings'][0]['rule'], 'credential-field')

    def test_jsonl_line(self):
        result = scan(self.text('{}\n{"apiKey":"synthetic"}'))
        self.assertEqual(result['findings'][0]['line'], 2)

    def test_cookie(self):
        result = scan(self.text('{"cookies":[{"name":"session","value":"synthetic"}]}'))
        self.assertEqual(result['findings'][0]['rule'], 'cookie-value')

    def test_exact_secret_and_encoding(self):
        for content in ['hello a/b?c', 'a%2Fb%3Fc']:
            self.assertTrue(scan(self.text(content), known=['a/b?c'])['findings'])

    def test_archive_does_not_extract_traversal(self):
        p = self.archive([('../escape.txt', '{"password":"synthetic"}')])
        self.assertEqual(scan(p)['status'], 'findings')
        self.assertFalse((self.root.parent / 'escape.txt').exists())

    def test_member_names_not_disclosed(self):
        result = scan(self.archive([('secret-in-name.txt', 'ordinary')]))
        self.assertNotIn('secret-in-name', json.dumps(result))

    def test_media_requires_explicit_scope(self):
        p = self.archive([('test.trace', '{}'), ('screen.png', b'\x89PNG')])
        self.assertEqual(scan(p)['status'], 'incomplete')
        result = scan(p, text_only=True)
        self.assertEqual(result['status'], 'no-findings-in-scope')
        self.assertEqual(len(result['uninspected']), 1)

    def test_media_only_never_clean(self):
        self.assertEqual(scan(self.archive([('x.png', b'png')]), text_only=True)['status'], 'incomplete')

    def test_binary(self):
        self.assertEqual(scan(self.archive([('resource', b'\xff')]))['status'], 'incomplete')

    def test_size_budget(self):
        p = self.archive([('a', 'a'*20), ('b', 'b'*20)])
        self.assertEqual(scan(p, max_total=25)['status'], 'incomplete')
        self.assertEqual(scan(p, max_member=10)['scannedMembers'], 0)

    def test_count_budget(self):
        self.assertEqual(scan(self.archive([('a','a'), ('b','b')]), max_members=1)['status'], 'incomplete')

    def test_missing_and_corrupt(self):
        self.assertEqual(scan(self.root/'missing')['status'], 'incomplete')
        self.assertEqual(scan(self.text('not zip', '.zip'))['status'], 'incomplete')

    def test_symlink(self):
        p = self.text('{}')
        link = self.root/'link.trace'
        link.symlink_to(p)
        self.assertEqual(scan(link)['status'], 'incomplete')

    def test_nested_archive(self):
        self.assertEqual(scan(self.archive([('inner.zip', b'PK\x03\x04data')]))['status'], 'incomplete')

    def test_incomplete_takes_precedence_but_retains_findings(self):
        result = scan(self.archive([('a', '{"password":"synthetic"}'), ('b', b'\xff')]))
        self.assertEqual(result['status'], 'incomplete')
        self.assertTrue(result['findings'])

    def test_cli_codes_and_no_secret_output(self):
        with patch.dict(os.environ, {'TG_TEST': 'synthetic-secret'}):
            for content, code in [('ordinary', 0), ('synthetic-secret', 1)]:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    actual = main([str(self.text(content)), '--secret-env', 'TG_TEST', '--format', 'json'])
                self.assertEqual(actual, code)
                self.assertNotIn('synthetic-secret', output.getvalue())
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.text('{}')), '--secret-env', 'ABSENT']), 2)

if __name__ == '__main__':
    unittest.main()
