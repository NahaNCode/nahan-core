#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "${1:-}" = --help ]; then
  printf '%s\n' 'NahaN fresh native installer (Linux + systemd, amd64/arm64).' 'Run from a terminal as root. Paste panel config.json, then core.key when prompted.' 'Existing installations are never overwritten. No customer ports or tunnels are opened.'
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
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

PUBLIC_KEY = 'xiql0i80KrTc6ehKNhMQJuhnANSK7Q368RcCAoFO5Bc='
CATALOG = 'https://github.com/NahaNCode/nahan-core/releases/latest/download/updates.json'
ROOT = Path('/opt/nahan')
UNIT = Path('/etc/systemd/system/nahan.service')
REDIRECT_HOSTS = {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}

class InstallError(Exception):
    pass

def require(condition, message):
    if not condition:
        raise InstallError(message)

def run(args, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120)
    if check and result.returncode:
        raise InstallError('Command failed: ' + Path(args[0]).name + '. No credentials were logged.')
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

def fetch(value, maximum, output=None):
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

def fresh_install():
    require(not ROOT.exists() and not ROOT.is_symlink() and not UNIT.exists() and not UNIT.is_symlink(),
            'An installation already exists at /opt/nahan or nahan.service. Nothing overwritten. For an existing core use: sudo nahan-core update')
    require(run(['systemctl', 'show', 'nahan.service', '--property=LoadState', '--value'], check=False).stdout.strip() in (b'', b'not-found'), 'A nahan.service unit is already registered. Nothing overwritten.')

def write_private(path, value, uid, gid):
    with path.open('x') as target:
        target.write(value)
    path.chmod(0o600)
    os.chown(path, uid, gid)

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
    result = run([str(ROOT / 'NahaN'), 'update', 'register', '--service', 'nahan.service'], check=False)
    print('\n4/4 INSTALLED: nahan.service is active and starts after reboot.', file=tty)
    print('Updater registered.' if result.returncode == 0 else 'Core is running, but updater registration needs review: sudo /opt/nahan/NahaN update register --service nahan.service', file=tty)
    print('Return to the panel and click Check core report. Expect a fresh heartbeat and matching desired/applied revisions.\nNo customer listener or tunnel has been created. The core remains LAB until panel validation.\nDiagnostics: sudo systemctl status nahan.service\nLogs: sudo journalctl -u nahan.service -n 40 --no-pager\nNever share core.key or unredacted logs.', file=tty, flush=True)

def main():
    require(os.geteuid() == 0, 'Run as root.')
    lock = os.open('/run/lock/nahan-core-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise InstallError('Another NahaN installer is already running.') from None
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    require(arch is not None, 'Supported architectures: Linux x86_64 and arm64.')
    fresh_install()
    with open('/dev/tty', 'r', encoding='utf-8') as reader, open('/dev/tty', 'w', encoding='utf-8', buffering=1) as writer:
        tty = Terminal(reader, writer)
        print('NahaN fresh installation | Linux ' + arch + '\nNo uploads required. Settings and the secret are read only from this terminal.', file=tty)
        config = read_config(tty)
        print('\n2/4 KEY: click Copy core.key in the panel, paste below, then press Enter. The key is hidden and never logged.', file=tty, flush=True)
        key = getpass.getpass('core.key: ', stream=tty).strip()
        require(bool(re.fullmatch(r'[A-Za-z0-9_+/=.-]{20,4096}', key)), 'Invalid key. Paste only core.key from the panel, not a command or config.json.')
        print('\n3/4 VERIFY: downloading the signed official release catalog...', file=tty, flush=True)
        with tempfile.TemporaryDirectory(prefix='nahan-install-') as temporary:
            work = Path(temporary)
            release = verify_catalog(fetch(CATALOG, 65536), work)
            asset = release['assets'].get('linux-' + arch)
            require(isinstance(asset, dict), 'The signed release does not include this architecture.')
            secure_url(asset.get('url'), asset=True)
            require(re.fullmatch(r'[a-f0-9]{64}', asset.get('sha256', '')) and type(asset.get('size')) is int
                    and 0 < asset['size'] <= 256 * 1024 * 1024, 'Invalid signed asset metadata.')
            require('/' + release['version'] + '/' in asset['url'], 'Release version and binary do not match.')
            print('Verified release: ' + release['version'] + '\nCore: ' + config['ControlPlane']['CoreID']
                  + '\nDestination: /opt/nahan\nService: nahan.service\nNo firewall or tunnel rules will be changed.\nType INSTALL to continue, or anything else to cancel:', file=tty, flush=True)
            require(tty.readline().strip() == 'INSTALL', 'Canceled. Nothing installed.')
            binary = work / 'NahaN'
            size = fetch(asset['url'], asset['size'], binary)
            require(size == asset['size'] and hashlib.sha256(binary.read_bytes()).hexdigest() == asset['sha256'], 'Binary checksum mismatch. Nothing installed.')
            binary.chmod(0o700)
            install(binary, config, key, tty)

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nInstallation canceled.', file=sys.stderr)
        sys.exit(1)
    except InstallError as error:
        print('NahaN installation stopped: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('NahaN installation stopped: network, dependency or local service operation failed. Check HTTPS access to GitHub, system time and required packages, then retry. No credentials were logged.', file=sys.stderr)
        sys.exit(1)
NAHAN_INSTALL_PY
