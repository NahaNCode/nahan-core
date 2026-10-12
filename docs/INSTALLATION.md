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
Signed automatic upgrades and automatic imported-certificate renewal are not
provided by this release.
