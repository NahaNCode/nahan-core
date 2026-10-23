#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "${1:-}" = --help ]; then
  printf '%s\n' 'NahaN fresh native installer (Linux + systemd, amd64/arm64).' 'Run from a terminal as root. Paste panel config.json, then core.key when prompted.' 'Full-screen terminal wizard; --plain disables screen switching; NO_COLOR=1 disables colors.' '--repair-updater registers an existing native installation without reinstalling or restarting its core.' 'Existing installations are never overwritten. No customer ports or tunnels are opened.'
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then printf '%s\n' 'Run this installer with sudo bash install.sh.' >&2; exit 1; fi
if [ "$(uname -s)" != Linux ] || ! command -v systemctl >/dev/null || [ ! -d /run/systemd/system ]; then
  printf '%s\n' 'A Linux server running systemd is required. Containers without systemd are not supported.' >&2; exit 1
fi
if ! ( : </dev/tty ) 2>/dev/null; then printf '%s\n' 'An interactive terminal is required. Download the script, then run sudo bash install.sh; do not pipe it into bash.' >&2; exit 1; fi
missing=()
for tool in python3 openssl useradd; do command -v "$tool" >/dev/null || missing+=("$tool"); done
if [ "${#missing[@]}" -gt 0 ]; then
  command -v apt-get >/dev/null || { printf '%s\n' 'Install python3, openssl, ca-certificates and useradd using your distribution package manager, then run again.' >&2; exit 1; }
  printf '%s\n' 'Required packages are missing. Install python3, openssl, ca-certificates and passwd with apt? [y/N]' >/dev/tty
  read -r answer </dev/tty
  case "$answer" in y|Y) apt-get update -qq; apt-get install -y --no-install-recommends python3 openssl ca-certificates passwd ;; *) exit 1 ;; esac
fi
exec python3 - "$@" <<'NAHAN_INSTALL_PY'
import base64
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import ssl
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid
import textwrap

PUBLIC_KEY = 'xiql0i80KrTc6ehKNhMQJuhnANSK7Q368RcCAoFO5Bc='
CATALOG = 'https://github.com/NahaNCode/nahan-core/releases/latest/download/updates.json'
ROOT = Path('/opt/nahan')
UNIT = Path('/etc/systemd/system/nahan.service')
REDIRECT_HOSTS = {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
STAGE = 'preflight'
REPAIR_COMMAND = '''(set -eu; work="$(mktemp -d)"; trap 'rm -rf -- "$work"' EXIT; install -m 700 /opt/nahan/NahaN "$work/NahaN"; "$work/NahaN" update register --service nahan.service)'''

def stage(value):
    global STAGE
    STAGE = value

def explain_error(error):
    # Never echo arbitrary exception strings: they may contain pasted credentials.
    if isinstance(error, InstallError):
        return str(error)
    if isinstance(error, urllib.error.HTTPError):
        return 'GitHub HTTPS returned HTTP ' + str(error.code) + '. Check release access; ping alone does not test HTTPS.'
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        return 'HTTPS certificate verification failed. Check timedatectl and ca-certificates; do not disable TLS verification.'
    if isinstance(reason, socket.gaierror):
        return 'DNS lookup failed. Check DNS for github.com and release-assets.githubusercontent.com.'
    if isinstance(reason, (TimeoutError, socket.timeout, subprocess.TimeoutExpired)):
        return 'Operation timed out. Check outbound HTTPS and systemd; retry only after checking the failed stage.'
    if isinstance(reason, OSError):
        return 'System operation failed (errno ' + str(reason.errno) + '). Check disk space, permissions and outbound HTTPS.'
    return 'Unexpected ' + type(error).__name__ + '. No private inputs were logged. Report the stage and error type, not keys or raw logs.'

class InstallError(Exception):
    pass

def require(condition, message):
    if not condition:
        raise InstallError(message)

def run(args, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120)
    if check and result.returncode:
        action = ' ' + args[1] if Path(args[0]).name == 'systemctl' and len(args) > 1 else ''
        raise InstallError('Command failed: ' + Path(args[0]).name + action + ' (exit ' + str(result.returncode) + '). Check systemctl status nahan.service locally. No command output or credentials were logged.')
    return result

def secure_url(value, asset=False):
    require(isinstance(value, str), 'Invalid download address.')
    url = urllib.parse.urlsplit(value)
    require(url.scheme == 'https' and url.hostname in REDIRECT_HOSTS
            and not url.username and not url.password and url.port in (None, 443)
            and not url.fragment, 'Untrusted download address.')
    if asset:
        require(url.netloc == 'github.com' and not url.query
                and re.fullmatch(r'/NahaNCode/nahan-core/releases/download/v\d+\.\d+\.\d+/NahaN-linux-(amd64|arm64)', url.path),
                'Untrusted release asset.')

class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        secure_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)

def fetch(value, maximum, output=None, progress=None):
    secure_url(value)
    opener = urllib.request.build_opener(Redirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(value, headers={'User-Agent': 'NahaN-Native-Installer/1'})
    with opener.open(request, timeout=60) as response:
        require(response.status == 200, 'Download was not accepted.')
        if output is None:
            data = response.read(maximum + 1)
            require(len(data) <= maximum, 'Download exceeded its size limit.')
            return data
        size = 0
        with output.open('xb') as target:
            while True:
                chunk = response.read(128 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= maximum, 'Release asset exceeded its signed size.')
                target.write(chunk)
                if progress:
                    progress(size, maximum)
        return size

def verify_catalog(data, work, now=None):
    require(len(data) <= 65536, 'Release catalog is too large.')
    try:
        envelope = json.loads(data)
        payload = base64.b64decode(envelope['payload'], validate=True)
        signature = base64.b64decode(envelope['signature'], validate=True)
        require(len(signature) == 64, 'Invalid release signature.')
        (work / 'catalog.payload').write_bytes(payload)
        (work / 'catalog.signature').write_bytes(signature)
        (work / 'catalog.public.der').write_bytes(bytes.fromhex('302a300506032b6570032100') + base64.b64decode(PUBLIC_KEY))
        result = run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
                      '-inkey', str(work / 'catalog.public.der'), '-rawin',
                      '-in', str(work / 'catalog.payload'), '-sigfile', str(work / 'catalog.signature')], check=False)
        require(result.returncode == 0, 'Release signature verification failed. Nothing installed.')
        release = json.loads(payload)
        now = time.time() if now is None else now
        require(re.fullmatch(r'v\d+\.\d+\.\d+', release['version'])
                and re.fullmatch(r'[a-f0-9]{40}', release['commit'])
                and isinstance(release['publishedAt'], int) and isinstance(release['expiresAt'], int)
                and release['publishedAt'] <= now + 300 < release['expiresAt']
                and 0 < release['expiresAt'] - release['publishedAt'] <= 180 * 86400,
                'Release catalog expired or server clock is incorrect. Check timedatectl.')
        require(isinstance(release['assets'], dict) and 0 < len(release['assets']) <= 16, 'Invalid release assets.')
        return release
    except InstallError:
        raise
    except Exception:
        raise InstallError('Invalid signed release catalog.') from None

def validate_config(config):
    require(isinstance(config, dict) and set(config) <= {'Log', 'ControlPlane', 'Nodes'}, 'Paste the fresh panel installation config, not a legacy or custom configuration.')
    require(config.get('Nodes') == [], 'Fresh managed installations require Nodes: [].')
    cp = config.get('ControlPlane')
    require(isinstance(cp, dict) and set(cp) <= {'ApiHost', 'ServerName', 'CoreID', 'KeyFile'}, 'Invalid panel connection configuration.')
    try:
        require(str(uuid.UUID(cp['CoreID'])) == cp['CoreID'], 'Invalid core identity.')
        url = urllib.parse.urlsplit(cp['ApiHost'])
        require(url.scheme == 'https' and url.hostname and not url.username and not url.password
                and not url.query and not url.fragment and url.path in ('', '/'), 'The panel API address must be an HTTPS origin.')
        require(isinstance(cp['ServerName'], str) and re.fullmatch(r'[A-Za-z0-9.-]{1,253}', cp['ServerName']), 'Invalid TLS server name.')
        require(cp['KeyFile'] in ('./core.key', 'core.key'), 'Use the unmodified panel installation package.')
    except (KeyError, ValueError, TypeError):
        raise InstallError('Incomplete panel connection configuration.') from None
    log = config.get('Log', {'Level': 'warning'})
    require(isinstance(log, dict) and set(log) <= {'Level'} and log.get('Level') in {'none', 'error', 'warning', 'info', 'debug'}, 'Invalid log configuration.')
    return {'Log': log, 'ControlPlane': {**cp, 'KeyFile': str(ROOT / 'runtime/core.key')}, 'Nodes': []}

def read_config(tty):
    print('\n1/4 CONFIGURATION: click Copy config.json in the panel, paste here, then press Enter.\nSingle-line or multi-line JSON is accepted. Type /cancel to stop.', file=tty, flush=True)
    text = ''
    while len(text) <= 32768:
        line = tty.readline()
        require(bool(line), 'Installation canceled: no configuration received.')
        require(line.strip() != '/cancel', 'Installation canceled.')
        text += line
        try:
            return validate_config(json.loads(text))
        except json.JSONDecodeError:
            continue
    raise InstallError('Configuration is too large. Paste only config.json from the panel.')

class Terminal:
    # Separate streams avoid BufferedRandom's seek requirement on real TTY devices.
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
    def readline(self):
        return self.reader.readline()
    def write(self, value):
        return self.writer.write(value)
    def flush(self):
        return self.writer.flush()

class InstallerScreen:
    STEPS = ('CONFIGURATION', 'KEY', 'VERIFY', 'INSTALL', 'COMPLETE')
    def __init__(self, terminal, plain=False):
        self.terminal = terminal
        self.styled = not plain and os.environ.get('TERM', 'dumb') != 'dumb'
        self.color = self.styled and 'NO_COLOR' not in os.environ
    def __enter__(self):
        if self.styled:
            self.terminal.write('\033[?1049h')
            self.terminal.flush()
        return self
    def __exit__(self, *_):
        if self.styled:
            self.terminal.write('\033[0m\033[?25h\033[?1049l')
            self.terminal.flush()
    def page(self, step, title, lines=()):
        stage(self.STEPS[step - 1].lower())
        width = max(24, min(shutil.get_terminal_size((88, 30)).columns - 2, 100))
        teal = '\033[1;36m' if self.color else ''
        amber = '\033[1;33m' if self.color else ''
        reset = '\033[0m' if self.color else ''
        out = self.terminal
        if self.styled:
            out.write('\033[2J\033[H')
        print(teal + '+' + '-' * (width - 2) + '+' + reset, file=out)
        print(teal + '  N A H A N' + reset, file=out)
        for line in textwrap.wrap('CORE / SECURE SERVER ENROLLMENT', width=width - 4):
            print('  ' + line, file=out)
        print(teal + '+' + '-' * (width - 2) + '+' + reset, file=out)
        print('', file=out)
        for index, name in enumerate(self.STEPS, 1):
            mark = '[done]' if index < step else '[ >> ]' if index == step else '[    ]'
            print((amber if index == step else '') + '  ' + mark + ' ' + name + reset, file=out)
        print('', file=out)
        for line in textwrap.wrap(title, width=width - 4):
            print('  ' + amber + line + reset, file=out)
        print('  ' + '-' * (width - 4), file=out)
        for line in lines:
            for wrapped in textwrap.wrap(line, width=width - 4) or ['']:
                print('  ' + wrapped, file=out)
        print('', file=out, flush=True)

def fresh_install():
    require(not ROOT.exists() and not ROOT.is_symlink() and not UNIT.exists() and not UNIT.is_symlink(),
            'An installation already exists at /opt/nahan or nahan.service. Nothing overwritten. For an existing core use: sudo nahan-core update')
    require(run(['systemctl', 'show', 'nahan.service', '--property=LoadState', '--value'], check=False).stdout.strip() in (b'', b'not-found'), 'A nahan.service unit is already registered. Nothing overwritten.')

def write_private(path, value, uid, gid):
    with path.open('x') as target:
        target.write(value)
    path.chmod(0o600)
    os.chown(path, uid, gid)

def register_updater(binary):
    # Older signed cores count their own registrar as a second live core process.
    # A private copy preserves the uniqueness guard without replacing or restarting the core.
    with tempfile.TemporaryDirectory(prefix='nahan-register-') as temporary:
        helper = Path(temporary) / 'NahaN'
        shutil.copyfile(binary, helper)
        helper.chmod(0o700)
        return run([str(helper), 'update', 'register', '--service', 'nahan.service'], check=False)

def install(binary, config, key, tty):
    fresh_install()
    account = None
    try:
        account = pwd.getpwnam('nahan')
    except KeyError:
        run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'nahan'])
        account = pwd.getpwnam('nahan')
    require(account.pw_uid != 0 and account.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'), 'The existing nahan account is not a dedicated non-login service account.')
    created = False
    unit_created = False
    try:
        ROOT.mkdir(mode=0o755)
        created = True
        ROOT.chmod(0o755)
        runtime = ROOT / 'runtime'
        runtime.mkdir(mode=0o700)
        os.chown(runtime, account.pw_uid, account.pw_gid)
        shutil.copyfile(binary, ROOT / 'NahaN')
        (ROOT / 'NahaN').chmod(0o755)
        write_private(runtime / 'config.json', json.dumps(config, indent=2) + '\n', account.pw_uid, account.pw_gid)
        write_private(runtime / 'core.key', key + '\n', account.pw_uid, account.pw_gid)
        # NET_BIND_SERVICE permits customer listeners below 1024 without running the engine as root.
        unit = '''[Unit]
Description=NahaN Core
After=network-online.target
Wants=network-online.target
[Service]
User=nahan
WorkingDirectory=/opt/nahan/runtime
ExecStart=/opt/nahan/NahaN --config /opt/nahan/runtime/config.json
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/nahan/runtime
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
'''
        with UNIT.open('x') as target:
            unit_created = True
            target.write(unit)
        UNIT.chmod(0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', 'nahan.service'])
        time.sleep(3)
        require(run(['systemctl', 'is-active', '--quiet', 'nahan.service'], check=False).returncode == 0,
                'Core service did not stay active. The fresh installation will be rolled back.')
    except Exception:
        if created:
            if unit_created:
                run(['systemctl', 'disable', '--now', 'nahan.service'], check=False)
            if unit_created and UNIT.exists():
                UNIT.unlink()
            shutil.rmtree(ROOT)
            run(['systemctl', 'daemon-reload'], check=False)
        raise
    registered = False
    stage('updater-registration')
    try:
        registered = register_updater(ROOT / 'NahaN').returncode == 0
    except (OSError, subprocess.SubprocessError) as error:
        print('Updater registration: ' + explain_error(error), file=tty)
    print('\n4/4 INSTALLED: nahan.service is active and starts after reboot.', file=tty)
    print('Updater registered.' if registered else 'Core is running; updater needs repair. As root, run:\n' + REPAIR_COMMAND, file=tty)
    print('Return to the panel and click Check core report. Expect a fresh heartbeat and matching desired/applied revisions.\nNo customer listener or tunnel has been created. The core remains LAB until panel validation.\nDiagnostics: sudo systemctl status nahan.service\nLogs: sudo journalctl -u nahan.service -n 40 --no-pager\nNever share core.key or unredacted logs.', file=tty, flush=True)
    return registered

def main():
    require(os.geteuid() == 0, 'Run as root.')
    lock = os.open('/run/lock/nahan-core-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise InstallError('Another NahaN installer is already running.') from None
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    require(arch is not None, 'Supported architectures: Linux x86_64 and arm64.')
    if '--repair-updater' in sys.argv:
        stage('updater-repair')
        binary = ROOT / 'NahaN'
        require(binary.is_file() and not binary.is_symlink() and binary.stat().st_uid == 0
                and binary.stat().st_mode & 0o022 == 0, 'An existing root-owned protected native binary is required. No installation changed.')
        print('NahaN updater repair: existing core, config and key are preserved. Core is not restarted.')
        result = register_updater(binary)
        require(result.returncode == 0, 'Updater repair was rejected (exit ' + str(result.returncode) + '). Check the existing core service and updater profile locally; no core reinstall or restart was requested.')
        print('Updater registered. Existing core was not restarted.')
        return
    fresh_install()
    with open('/dev/tty', 'r', encoding='utf-8') as reader, open('/dev/tty', 'w', encoding='utf-8', buffering=1) as writer:
        tty = Terminal(reader, writer)
        with InstallerScreen(tty, plain='--plain' in sys.argv) as screen:
            registered = interactive_install(tty, screen, arch)
    print('NahaN INSTALLED | nahan.service active | /opt/nahan\nReturn to the panel and check the fresh core report. LAB is not production readiness.\nDiagnostics: systemctl status nahan.service\nPrivate local logs: journalctl -u nahan.service -n 40 --no-pager')
    if not registered:
        print('WARNING: core is running but updater registration failed. Repair as root without reinstalling:\n' + REPAIR_COMMAND)

def interactive_install(tty, screen, arch):
        screen.page(1, 'Connect this server to your panel', [
            'Linux ' + arch + ' / systemd / signed official release',
            'Keep the panel installation package open. No uploads are required.',
            'Paste only config.json at CONFIGURATION. /cancel or Ctrl+C stops safely.',
            'Your connection key will be requested separately and hidden while typing.'])
        config = read_config(tty)
        screen.page(2, 'Private connection key', [
            'Configuration accepted. Core: ' + config['ControlPlane']['CoreID'],
            'Copy core.key from the same panel package. Paste once, then press Enter.',
            'No characters appear during secret entry. This is intentional.',
            'Never paste the key into a shell command, chat or log.'])
        print('\n2/4 KEY: click Copy core.key in the panel, paste below, then press Enter. The key is hidden and never logged.', file=tty, flush=True)
        key = getpass.getpass('core.key: ', stream=tty).strip()
        require(bool(re.fullmatch(r'[A-Za-z0-9_+/=.-]{20,4096}', key)), 'Invalid key. Paste only core.key from the panel, not a command or config.json.')
        screen.page(3, 'Verify the official release', [
            'Downloading signed metadata over HTTPS from GitHub.',
            'Checking Ed25519 signature, expiry and architecture before installation.',
            'No local installation files have been created. This can take up to 60 seconds.'])
        with tempfile.TemporaryDirectory(prefix='nahan-install-') as temporary:
            work = Path(temporary)
            release = verify_catalog(fetch(CATALOG, 65536), work)
            asset = release['assets'].get('linux-' + arch)
            require(isinstance(asset, dict), 'The signed release does not include this architecture.')
            secure_url(asset.get('url'), asset=True)
            require(re.fullmatch(r'[a-f0-9]{64}', asset.get('sha256', '')) and type(asset.get('size')) is int
                    and 0 < asset['size'] <= 256 * 1024 * 1024, 'Invalid signed asset metadata.')
            require('/' + release['version'] + '/' in asset['url'], 'Release version and binary do not match.')
            screen.page(3, 'Review and approve installation', [
                'SIGNATURE VERIFIED / ' + release['version'] + ' / Linux ' + arch,
                'Service account: nahan (non-login, not root)',
                'Private runtime: /opt/nahan/runtime / permissions 0600',
                'Startup: systemd / automatic signed updater registration',
                'Firewall, tunnels and customer listeners will not be changed.'])
            print('Verified release: ' + release['version'] + '\nCore: ' + config['ControlPlane']['CoreID']
                  + '\nDestination: /opt/nahan\nService: nahan.service\nNo firewall or tunnel rules will be changed.\nType INSTALL to continue, or anything else to cancel:', file=tty, flush=True)
            require(tty.readline().strip() == 'INSTALL', 'Canceled. Nothing installed.')
            binary = work / 'NahaN'
            screen.page(4, 'Download and install verified core', ['Downloading release binary. No unverified binary will run.'])
            last_progress = [0.0]
            def progress(current, total):
                if time.monotonic() - last_progress[0] < 1 and current != total:
                    return
                last_progress[0] = time.monotonic()
                percent = min(100, current * 100 // total)
                bar = '#' * (percent // 5) + '.' * (20 - percent // 5)
                screen.page(4, 'Download verified core', [
                    '[' + bar + '] ' + str(percent) + '%',
                    str(current // 1024) + ' / ' + str(total // 1024) + ' KiB',
                    'Signed release: ' + release['version'],
                    'Next: SHA256 verification, private files and systemd startup.'])
                stage('binary-download')
            stage('binary-download')
            size = fetch(asset['url'], asset['size'], binary, progress=progress)
            stage('binary-verification')
            require(size == asset['size'] and hashlib.sha256(binary.read_bytes()).hexdigest() == asset['sha256'], 'Binary checksum mismatch. Nothing installed.')
            binary.chmod(0o700)
            screen.page(4, 'Start the permanent system service', [
                'Binary size and SHA256 verified.',
                'Creating private runtime and starting nahan.service.',
                'On startup failure, only this fresh installation is rolled back.'])
            stage('service-installation')
            registered = install(binary, config, key, tty)
            screen.page(5, 'INSTALLED / return to the panel', [
                'nahan.service is active and configured to start after reboot.',
                'Updater registered.' if registered else 'WARNING: updater registration failed. Core remains running. Use --repair-updater with the current installer; do not reinstall or restart the core.',
                'Click Check core report in the panel. Require a fresh heartbeat and matching revisions.',
                'This core remains LAB. Test a real listener before using customer traffic.',
                'systemctl status nahan.service',
                'journalctl -u nahan.service -n 40 --no-pager (private local logs)',
                'Press Enter to return to your shell.'])
            tty.readline()
            return registered

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nInstallation already complete. Service remains running; check the panel report.' if STAGE == 'complete' else '\nInstallation canceled.', file=sys.stderr)
        sys.exit(0 if STAGE == 'complete' else 1)
    except Exception as error:
        print('NahaN installation stopped [' + STAGE + ']: ' + explain_error(error), file=sys.stderr)
        sys.exit(1)
NAHAN_INSTALL_PY
