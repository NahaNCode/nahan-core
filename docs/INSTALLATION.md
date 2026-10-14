# Installation

Use a separate staging installation. Do not overwrite existing core directories,
units, ports, firewall rules or tunnel interfaces. Build using the README's
patched-modfile commands; the Dockerfile uses the same pinned patching.

## Managed mode

This is the current NahaN panel contract. CoreID identifies the core (UUID);
per-entry numeric IDs are discovered from the panel manifest automatically.
Do not add legacy ApiConfig.NodeID entries. Keep the bootstrap Nodes list empty.
Both YAML and JSON are supported when selected with --config; the runtime path
in this guide is an installation convention, not a mandatory file location.

In the panel's core-management wizard, issue an installation package and download
both config.json and core.key. The current wizard registers a LAB core, not an
automatically provisioned production installation. Keep the issued ApiHost,
CoreID and ServerName values; do not substitute a legacy per-node sample.
Choose a dedicated non-login service user and owner-only runtime directory:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nahan
sudo install -d -m 755 /opt/nahan
sudo install -d -m 700 -o nahan -g nahan /opt/nahan/runtime
sudo install -m 755 NahaN /opt/nahan/NahaN
```

Install the panel-downloaded config.json and core.key together in
`/opt/nahan/runtime/`; never put the key in shell history. The issued key path
is ./core.key, so preserve the WorkingDirectory in the service below.
Both files must be owned by `nahan`, mode 0600. IP-based URLs require the correct
`ServerName`; private CAs require `CAFile`. Never disable TLS checks.

Save this unit as `/etc/systemd/system/nahan.service`:

```ini
[Unit]
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
[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now nahan.service
sudo systemctl status nahan.service
```

Verify fresh heartbeat, desired/applied revision equality and listener sockets.
Test actual client connections separately. No managed listener starts until the
panel publishes one. Temporary SS tests use free ports in 40000-49999 on the
original bind address; network reachability must be supplied by your topology.

## Docker

The image defaults to `/etc/NahaN/config.yml`. The command below explicitly
selects JSON instead. Put `config.json` and the private `core.key` in `runtime/`
and set ControlPlane.KeyFile to `/etc/NahaN/core.key` inside the container;
host paths such as `/opt/nahan/runtime/core.key` are not mounted there.

```sh
docker build -t nahan-core:local .
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v "$PWD/runtime:/etc/NahaN" nahan-core:local \
  --config /etc/NahaN/config.json
```

Grant NET_ADMIN, TUN access or low-port capabilities only when needed. Host
networking shares ports with existing services. Use the panel-issued package,
not the development or compatibility examples in this repository.

## Upgrade and recovery

Back up configuration and core-local secrets outside Git. Verify the candidate
checksum and compatibility, retain the previous binary, and restart only the
intended NahaN unit. Restart interrupts the engine and revokes temporary tests.
On failure, restore the old binary and verify both heartbeat and client traffic.
Native systemd installations can register the signed updater once using a
verified official release binary:

```sh
sudo ./NahaN update register --service nahan.service
sudo nahan-core update check
sudo nahan-core update
sudo nahan-core update status
sudo nahan-core update rollback
```

Registration discovers the existing core and does not create a panel record or
restart the core. `--core UUID` selects one of several registered services.
Only an explicitly confirmed upgrade restarts its selected unit. Preparation
checks the signed catalog, exact SHA256, source identity, configuration and
panel revision; activation retains a protected backup and restores it if health
verification fails. A repeated update of the exact current build is a no-op.
The panel checks new releases automatically and requires explicit activation.

If the existing core uses an unauthenticated loopback HTTPS proxy (HTTP CONNECT
or SOCKS5), registration preserves that route for authenticated updater reports
while retaining TLS identity verification. Remote or credentialed proxies are
not imported. Re-register after changing the service's route or installation.
Binary ancestors must be root-owned and non-writable by other users. Configuration
and credential files may belong to the registered service user. Shared binaries
must first be separated deliberately; the updater will not change a second unit.

Container upgrades and imported-certificate renewal are not automated here.
Do not paste credentials into command arguments or use unreviewed `curl | bash`.

## Automatic host identification

### Existing routing

Custom outbound inventories remain compatible with managed egress. Existing
routing rules require an explicit `ControlPlane.AllowManagedEgress: true`
acknowledgement on the host. A published managed binding takes precedence for
its selected inbound, including over existing routing rules; unselected inbounds
continue to use the existing router. Do not enable this option without reviewing
the rules that the selected inbounds previously relied on. Custom DNS and custom
inbound files remain excluded. No routing files are deleted or rewritten by this
option. Withdrawing the managed binding returns its inbound to the existing
router, not necessarily a direct Internet route.

With host agent 0.4 or newer, a native core requests a short-lived signed local
attestation. The panel verifies its registered agent key and automatically links
the existing core to that host. This does not create, install or move a core.
Non-root services use the restricted root helper after updater registration;
never make the agent socket world-accessible. A conflicting manual placement is
reported for review instead of silently overwritten. Socket access failure does
not stop regular core communication.
