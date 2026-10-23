"""Isolated installer tests; never invokes systemd or modifies the machine."""
import base64
import hashlib
import io
import json
import os
import pty
import select
import signal
from pathlib import Path
import subprocess
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'install.sh'
CODE = SOURCE.read_text().split("<<'NAHAN_INSTALL_PY'\n", 1)[1].rsplit('\nNAHAN_INSTALL_PY', 1)[0]
m = types.ModuleType('installer_test')
exec(compile(CODE, str(SOURCE), 'exec'), m.__dict__)

def config():
    return {'Log': {'Level': 'warning'}, 'ControlPlane': {
        'ApiHost': 'https://192.0.2.1', 'ServerName': 'panel.example.invalid',
        'CoreID': '11111111-1111-4111-8111-111111111111', 'KeyFile': './core.key'}, 'Nodes': []}

class NativeInstallerTest(unittest.TestCase):
    def test_repair_mode_never_calls_fresh_install_or_restarts_core(self):
        for owner, mode, exit_code in [(0, 0o100755, 0), (1000, 0o100755, 0), (0, 0o100777, 0), (0, 0o100755, 1)]:
            with self.subTest(owner=owner, mode=mode, exit_code=exit_code), tempfile.TemporaryFile() as lock:
                root, binary = MagicMock(), MagicMock()
                root.__truediv__.return_value = binary
                binary.is_file.return_value = True
                binary.is_symlink.return_value = False
                binary.stat.return_value = types.SimpleNamespace(st_uid=owner, st_mode=mode)
                with patch.object(m, 'ROOT', root), patch.object(m.os, 'geteuid', return_value=0), \
                     patch.object(m.os, 'open', return_value=lock.fileno()), \
                     patch.object(m.sys, 'argv', ['installer', '--repair-updater']), \
                     patch.object(m.sys, 'stdout', io.StringIO()), \
                     patch.object(m, 'register_updater', return_value=types.SimpleNamespace(returncode=exit_code)) as register, \
                     patch.object(m, 'fresh_install') as fresh, patch.object(m, 'install') as install:
                    if owner == 0 and mode == 0o100755 and exit_code == 0:
                        m.main()
                        register.assert_called_once_with(binary)
                    else:
                        with self.assertRaises(m.InstallError):
                            m.main()
                    if owner != 0 or mode == 0o100777:
                        register.assert_not_called()
                    fresh.assert_not_called()
                    install.assert_not_called()

    def test_updater_registration_uses_a_private_copy_and_cleans_it_up(self):
        subprocess.run(['bash', '-n'], input=m.REPAIR_COMMAND.encode(), check=True)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'running-core'
            binary.write_bytes(b'fixture-original-binary')
            helpers = []
            def run(args, check=True):
                helper = Path(args[0])
                helpers.append(helper)
                self.assertNotEqual(helper, binary)
                self.assertEqual(helper.read_bytes(), binary.read_bytes())
                self.assertEqual(helper.stat().st_mode & 0o777, 0o700)
                self.assertEqual(helper.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(args[1:], ['update', 'register', '--service', 'nahan.service'])
                return types.SimpleNamespace(returncode=0)
            with patch.object(m, 'run', run):
                self.assertEqual(m.register_updater(binary).returncode, 0)
            self.assertTrue(all(not helper.exists() for helper in helpers))
            self.assertEqual(binary.read_bytes(), b'fixture-original-binary')

    def test_updater_failure_preserves_successful_core_installation(self):
        self.simulate_install(False, updater_failure=True)

    def test_actionable_errors_never_expose_arbitrary_exception_details(self):
        secret = 'fixture-private-value-do-not-print'
        cases = [
            (m.urllib.error.HTTPError('https://github.com/' + secret, 403, secret, None, None), 'HTTP 403'),
            (m.urllib.error.URLError(m.socket.gaierror(-2, secret)), 'DNS'),
            (m.urllib.error.URLError(m.ssl.SSLCertVerificationError(1, secret)), 'certificate'),
            (TimeoutError(secret), 'timed out'),
            (OSError(28, secret), 'errno 28'),
            (ValueError(secret), 'ValueError'),
        ]
        for error, expected in cases:
            with self.subTest(expected=expected):
                message = m.explain_error(error)
                self.assertIn(expected, message)
                self.assertNotIn(secret, message)
                if isinstance(error, m.urllib.error.HTTPError):
                    error.close()

    def test_fullscreen_restores_terminal_after_failure_and_plain_mode_has_no_escapes(self):
        for plain in [False, True]:
            output = io.StringIO()
            terminal = m.Terminal(io.StringIO(), output)
            with patch.dict(os.environ, {'TERM': 'xterm-256color'}), \
                 patch.object(m.shutil, 'get_terminal_size', return_value=os.terminal_size((40, 24))):
                with self.assertRaises(RuntimeError):
                    with m.InstallerScreen(terminal, plain=plain) as screen:
                        screen.page(3, 'Verify', ['A long explanation that wraps on a narrow SSH terminal safely.'])
                        raise RuntimeError('fixture')
            value = output.getvalue()
            self.assertIn('N A H A N', value)
            self.assertIn('[ >> ] VERIFY', value)
            if plain:
                self.assertNotIn('\033', value)
            else:
                self.assertIn('\033[?1049h', value)
                self.assertTrue(value.endswith('\033[0m\033[?25h\033[?1049l'))

    def test_full_interactive_flow_in_real_pty_without_installing_anything(self):
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.environ['TERM'] = 'xterm-256color'
                data = b'verified-fixture-binary'
                release = {'version': 'v1.2.3', 'assets': {'linux-amd64': {
                    'url': 'https://github.com/NahaNCode/nahan-core/releases/download/v1.2.3/NahaN-linux-amd64',
                    'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}}}
                def fetch(url, maximum, output=None, progress=None):
                    if output is None:
                        return b'fixture-signed-envelope'
                    output.write_bytes(data)
                    if progress:
                        progress(len(data), maximum)
                    return len(data)
                with open('/dev/tty', 'r') as reader, open('/dev/tty', 'w', buffering=1) as writer, \
                     patch.object(m, 'fetch', fetch), patch.object(m, 'verify_catalog', return_value=release), \
                     patch.object(m, 'install', return_value=False) as install:
                    terminal = m.Terminal(reader, writer)
                    with m.InstallerScreen(terminal) as screen:
                        m.interactive_install(terminal, screen, 'amd64')
                    if install.call_args.args[2] != 'fixture-interactive-private-key':
                        os._exit(4)
                    print('FULL_FLOW_OK', file=terminal, flush=True)
                os._exit(0)
            except Exception:
                os._exit(3)
        transcript = b''
        def until(marker):
            nonlocal transcript
            deadline = time.monotonic() + 8
            while marker not in transcript and time.monotonic() < deadline:
                if select.select([fd], [], [], .1)[0]:
                    try:
                        transcript += os.read(fd, 16384)
                    except OSError:
                        break
            self.assertIn(marker, transcript)
        try:
            until(b'1/4 CONFIGURATION:')
            os.write(fd, json.dumps(config()).encode() + b'\n')
            until(b'core.key: ')
            os.write(fd, b'fixture-interactive-private-key\n')
            until(b'Type INSTALL to continue')
            os.write(fd, b'INSTALL\n')
            until(b'Press Enter to return')
            os.write(fd, b'\n')
            until(b'FULL_FLOW_OK')
            self.assertIn(b'100%', transcript)
            self.assertIn(b'WARNING: updater registration failed', transcript)
            self.assertNotIn(b'fixture-interactive-private-key', transcript)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            pid = None
        finally:
            os.close(fd)
            if pid:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    def test_actual_terminal_accepts_json_and_hides_the_key(self):
        pid, fd = pty.fork()
        if pid == 0:
            try:
                with open('/dev/tty', 'r', encoding='utf-8') as reader, open('/dev/tty', 'w', encoding='utf-8', buffering=1) as writer:
                    terminal = m.Terminal(reader, writer)
                    value = m.read_config(terminal)
                    secret = m.getpass.getpass('PRIVATE_KEY_PROMPT: ', stream=terminal)
                    if value['ControlPlane']['CoreID'] == config()['ControlPlane']['CoreID'] and secret == 'fixture-pty-private-value':
                        print('ROUNDTRIP_OK', file=terminal, flush=True)
                    else:
                        os._exit(2)
                os._exit(0)
            except Exception:
                os._exit(3)
        transcript = b''
        def until(marker):
            nonlocal transcript
            deadline = time.monotonic() + 5
            while marker not in transcript and time.monotonic() < deadline:
                if select.select([fd], [], [], .1)[0]:
                    try:
                        transcript += os.read(fd, 8192)
                    except OSError:
                        break
            self.assertIn(marker, transcript)
        try:
            until(b'CONFIGURATION')
            os.write(fd, json.dumps(config()).encode() + b'\n')
            until(b'PRIVATE_KEY_PROMPT: ')
            os.write(fd, b'fixture-pty-private-value\n')
            until(b'ROUNDTRIP_OK')
            self.assertNotIn(b'fixture-pty-private-value', transcript)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            pid = None
        finally:
            os.close(fd)
            if pid:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

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

    def simulate_install(self, fail, updater_failure=False):
        with tempfile.TemporaryDirectory() as temp:
            root, unit = Path(temp) / 'nahan', Path(temp) / 'nahan.service'
            binary = Path(temp) / 'verified-binary'
            binary.write_bytes(b'verified fixture')
            calls = []
            def run(args, check=True):
                calls.append(args)
                if updater_failure and args[1:3] == ['update', 'register']:
                    raise subprocess.TimeoutExpired('fixture-registrar', 120)
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
                    registered = m.install(binary, config(), 'fake-key', terminal)
                    self.assertEqual(registered, not updater_failure)
                    if updater_failure:
                        self.assertIn('Core is running; updater needs repair', terminal.getvalue())
                    self.assertEqual((root / 'runtime/core.key').stat().st_mode & 0o777, 0o600)
                    self.assertEqual((root / 'runtime/config.json').stat().st_mode & 0o777, 0o600)
                    self.assertEqual((root / 'runtime').stat().st_mode & 0o777, 0o700)
                    self.assertEqual(root.stat().st_mode & 0o777, 0o755)
                    self.assertIn('User=nahan', unit.read_text())
                    self.assertIn('CAP_NET_BIND_SERVICE', unit.read_text())
                    registration = [call for call in calls if call[1:3] == ['update', 'register']]
                    self.assertEqual(len(registration), 1)
                    self.assertNotEqual(registration[0][0], str(root / 'NahaN'))
                    self.assertEqual(registration[0][1:], ['update', 'register', '--service', 'nahan.service'])
                    self.assertFalse(Path(registration[0][0]).exists(), 'private registrar must be cleaned up')
                    self.assertNotIn('fake-key', terminal.getvalue())
                    self.assertTrue(all('fake-key' not in str(call) for call in calls))

if __name__ == '__main__':
    unittest.main()
