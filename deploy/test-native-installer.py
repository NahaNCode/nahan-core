"""Isolated installer tests; never invokes systemd or modifies the machine."""
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'install.sh'
CODE = SOURCE.read_text().split("<<'NAHAN_INSTALL_PY'\n", 1)[1].rsplit('\nNAHAN_INSTALL_PY', 1)[0]
m = types.ModuleType('installer_test')
exec(compile(CODE, str(SOURCE), 'exec'), m.__dict__)

def config():
    return {'Log': {'Level': 'warning'}, 'ControlPlane': {
        'ApiHost': 'https://192.0.2.1', 'ServerName': 'panel.example.invalid',
        'CoreID': '11111111-1111-4111-8111-111111111111', 'KeyFile': './core.key'}, 'Nodes': []}

class NativeInstallerTest(unittest.TestCase):
    def test_shell_and_help(self):
        subprocess.run(['bash', '-n', str(SOURCE)], check=True)
        result = subprocess.run(['bash', str(SOURCE), '--help'], capture_output=True, check=True)
        self.assertIn(b'never overwritten', result.stdout)

    def test_valid_config_preserves_tls_identity_and_uses_absolute_key(self):
        result = m.validate_config(config())
        self.assertEqual(result['ControlPlane']['ServerName'], 'panel.example.invalid')
        self.assertEqual(result['ControlPlane']['ApiHost'], 'https://192.0.2.1')
        self.assertEqual(result['ControlPlane']['KeyFile'], '/opt/nahan/runtime/core.key')
        self.assertEqual(result['Nodes'], [])

    def test_config_rejects_legacy_custom_or_insecure_input(self):
        invalid = [None, [], {}, {**config(), 'RouteConfigPath': '/etc/secret'},
                   {**config(), 'Nodes': [{'id': 1}]}]
        for field, value in [('ApiHost', 'http://panel.example.invalid'), ('ApiHost', 'https://user:password@example.invalid'),
                             ('ApiHost', 'https://example.invalid/?secret=x'), ('CoreID', 'not-a-uuid'),
                             ('KeyFile', '/etc/shadow'), ('ServerName', 'name\nheader')]:
            item = config()
            item['ControlPlane'][field] = value
            invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(m.InstallError):
                m.validate_config(item)

    def test_single_and_multiline_paste_are_both_accepted(self):
        class Terminal(io.StringIO):
            def __init__(self, data):
                super().__init__()
                self.lines = iter(data.splitlines(True))
            def readline(self):
                return next(self.lines, '')
        for indent in [None, 2]:
            result = m.read_config(Terminal(json.dumps(config(), indent=indent) + '\n'))
            self.assertEqual(result['ControlPlane']['CoreID'], config()['ControlPlane']['CoreID'])
        with self.assertRaises(m.InstallError):
            m.read_config(Terminal('/cancel\n'))

    def test_only_official_https_release_assets_are_accepted(self):
        m.secure_url('https://github.com/NahaNCode/nahan-core/releases/download/v1.6.12/NahaN-linux-amd64', asset=True)
        for value in ['http://github.com/anything', 'https://evil.invalid/file',
                      'https://github.com/Other/core/releases/download/v1.0.0/NahaN-linux-amd64',
                      'https://github.com/NahaNCode/nahan-core/releases/download/v1.0.0/NahaN-linux-amd64?token=x']:
            with self.subTest(value=value), self.assertRaises(m.InstallError):
                m.secure_url(value, asset=True)

    def test_catalog_requires_real_signature_and_fresh_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(work / 'key')], capture_output=True, check=True)
            public = subprocess.run(['openssl', 'pkey', '-in', str(work / 'key'), '-pubout', '-outform', 'DER'], capture_output=True, check=True).stdout[-32:]
            release = {'version': 'v1.2.3', 'commit': 'a' * 40, 'publishedAt': 1000, 'expiresAt': 3000,
                       'assets': {'linux-amd64': {'url': 'https://github.com/NahaNCode/nahan-core/releases/download/v1.2.3/NahaN-linux-amd64',
                                                  'size': 10, 'sha256': hashlib.sha256(b'test').hexdigest()}}}
            payload = json.dumps(release).encode()
            (work / 'input').write_bytes(payload)
            subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(work / 'key'), '-rawin', '-in', str(work / 'input'), '-out', str(work / 'sig')], capture_output=True, check=True)
            envelope = {'payload': base64.b64encode(payload).decode(), 'signature': base64.b64encode((work / 'sig').read_bytes()).decode()}
            with patch.object(m, 'PUBLIC_KEY', base64.b64encode(public).decode()):
                self.assertEqual(m.verify_catalog(json.dumps(envelope).encode(), work, now=1500)['version'], 'v1.2.3')
                with self.assertRaises(m.InstallError):
                    m.verify_catalog(json.dumps(envelope).encode(), work, now=4000)
                envelope['payload'] = base64.b64encode(payload + b' ').decode()
                with self.assertRaises(m.InstallError):
                    m.verify_catalog(json.dumps(envelope).encode(), work, now=1500)

    def test_existing_installation_is_never_touched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'nahan'
            root.mkdir()
            sentinel = root / 'existing.key'
            sentinel.write_text('preserve')
            with patch.object(m, 'ROOT', root), patch.object(m, 'UNIT', Path(temp) / 'unit'), patch.object(m, 'run') as run:
                with self.assertRaises(m.InstallError):
                    m.install(Path(temp) / 'binary', config(), 'fake-key', io.StringIO())
                run.assert_not_called()
                self.assertEqual(sentinel.read_text(), 'preserve')

    def test_install_files_modes_service_and_updater(self):
        self.simulate_install(False)

    def test_failed_service_removes_only_the_new_installation(self):
        self.simulate_install(True)

    def simulate_install(self, fail):
        with tempfile.TemporaryDirectory() as temp:
            root, unit = Path(temp) / 'nahan', Path(temp) / 'nahan.service'
            binary = Path(temp) / 'verified-binary'
            binary.write_bytes(b'verified fixture')
            calls = []
            def run(args, check=True):
                calls.append(args)
                return types.SimpleNamespace(returncode=1 if fail and 'is-active' in args else 0,
                                             stdout=b'not-found\n' if 'show' in args else b'')
            account = types.SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_shell='/usr/sbin/nologin')
            with patch.object(m, 'ROOT', root), patch.object(m, 'UNIT', unit), patch.object(m, 'run', run), \
                 patch.object(m.pwd, 'getpwnam', return_value=account), patch.object(m.os, 'chown'), patch.object(m.time, 'sleep'):
                if fail:
                    with self.assertRaises(m.InstallError):
                        m.install(binary, config(), 'fake-key', io.StringIO())
                    self.assertFalse(root.exists())
                    self.assertFalse(unit.exists())
                else:
                    terminal = io.StringIO()
                    m.install(binary, config(), 'fake-key', terminal)
                    self.assertEqual((root / 'runtime/core.key').stat().st_mode & 0o777, 0o600)
                    self.assertEqual((root / 'runtime/config.json').stat().st_mode & 0o777, 0o600)
                    self.assertEqual((root / 'runtime').stat().st_mode & 0o777, 0o700)
                    self.assertIn('User=nahan', unit.read_text())
                    self.assertIn('CAP_NET_BIND_SERVICE', unit.read_text())
                    self.assertIn([str(root / 'NahaN'), 'update', 'register', '--service', 'nahan.service'], calls)
                    self.assertNotIn('fake-key', terminal.getvalue())
                    self.assertTrue(all('fake-key' not in str(call) for call in calls))

if __name__ == '__main__':
    unittest.main()
