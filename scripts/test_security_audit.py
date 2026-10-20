"""Regression cases for executable template code and literal property access."""
import tempfile
import unittest
from pathlib import Path

import security_audit as audit


class ScannerTests(unittest.TestCase):
    def names(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'case.js'
            path.write_text(source)
            return {finding.name for finding in audit.audit_javascript(path)}

    def test_executable_templates(self):
        for source in [
            'const x = `${el.innerHTML = input}`;',
            'const x = `${({a: `${fetch(url)}`})}`;',
            'const x = `${/* } */ ({a: "}"}), el.outerHTML = value}`;',
            'const x = `prefix\n${document.write(value)}\nsuffix`;',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self.names(source))

    def test_static_computed_properties(self):
        cases = {
            'el["innerHTML"] = value': 'innerHTML',
            "el['outerHTML'] = value": 'outerHTML',
            "el[/* comment */ 'insertAdjacentHTML']('beforeend', value)": 'insertAdjacentHTML',
            "document['write'](value)": 'document.write',
            "location['hash']": 'location.hash',
            r"el['\u0069nnerHTML'] = value": 'innerHTML',
            r"el['\x69nnerHTML'] = value": 'innerHTML',
            r"el['\u{69}nnerHTML'] = value": 'innerHTML',
        }
        for source, name in cases.items():
            with self.subTest(source=source):
                self.assertIn(name, self.names(source))

    def test_nonexecutable_text_is_ignored(self):
        for source in [
            '// el.innerHTML = input;\nconst safe = 1;',
            '/* fetch(url) */ const safe = "innerHTML";',
            'const prose = `el.innerHTML = input; fetch(url)`;',
            r'const escaped = `\${el.innerHTML = input}`;',
            'const safe = el["textContent"];',
        ]:
            with self.subTest(source=source):
                self.assertEqual(self.names(source), set())

    def test_template_finding_keeps_line_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'case.js'
            path.write_text('const text = `first\n${el.innerHTML = value}`;')
            self.assertEqual(audit.audit_javascript(path)[0].line, 2)

    def test_nonlocal_active_resource_schemes(self):
        for value in ['https://example.com/x.js', '//example.com/x.js', 'data:text/javascript,x', 'blob:https://example.com/id', '\\evil.example/x.js']:
            with self.subTest(value=value):
                parser = audit.HTMLSecurityAudit(Path('case.html'))
                parser.feed('<script src="' + value + '"></script>')
                self.assertIn('external-script', {finding.name for finding in parser.findings})
        self.assertFalse(audit.is_external_url('/js/main.js'))
        self.assertFalse(audit.is_external_url('js/main.js'))


if __name__ == '__main__':
    unittest.main()
