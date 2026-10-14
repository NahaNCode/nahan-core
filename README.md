# NahaN Core

## Verified Native Updates

For an existing, dedicated systemd installation, register the updater once as
root using a verified release binary. Registration discovers the running binary
and configuration; it does not restart the core:

```sh
sudo ./NahaN update register --service YOUR-CORE.service
sudo nahan-core update check
sudo nahan-core update
sudo nahan-core update status
sudo nahan-core update rollback
```

Use `--core UUID` when several cores are registered. Updates require explicit
confirmation: restarting the selected core can interrupt its active connections.
The panel can prepare, upgrade and roll back a registered core after it reports
updater capability. Preparation downloads only Ed25519-signed official releases,
checks the exact binary digest, configuration, architecture, free disk space and
panel revision. Activation rechecks these conditions and retains a per-operation
backup. Failed activation restores the previous binary. The panel marks an
upgrade complete only after a fresh running-build receipt and heartbeat.

The privileged helper exposes only a per-core local Unix socket. It does not
accept shell commands, arbitrary download URLs or remote profile paths. Shared
binary installations and container registration are refused; container upgrades
must currently use the deployment operator's reviewed image replacement process.
Do not change a registered service's user or binary path without re-registration.

[راهنمای فارسی](README.fa.md)

An open-source Linux node runtime for the NahaN control plane, built on Xray.

### Automatic Host Placement

Updated native cores request a short-lived, core-specific signed attestation from
the local host agent at `/run/nahan-host-placement/placement.sock`. The panel
verifies it against the public key registered by that authenticated agent before
automatically assigning the core's host. Neither public IP nor hostname is used
as proof. Missing local access does not interrupt core heartbeat or routing.
Conflicting existing placements are reported rather than silently overwritten.

For containerized root-running cores, expose only the socket directory through
the read-only mount
`--mount type=bind,src=/run/nahan-host-placement,dst=/run/nahan-host-placement,readonly`.
Never mount the agent's credential or private state directory. Other socket paths
can be configured with `ControlPlane.HostSocket`. Non-root services need an
explicit permissioned local integration; do not make the socket world-accessible.

**Developer:** NahaN  
**Contact:** nahancode@gmail.com  
**License:** GPL-3.0. See [LICENSE](LICENSE).

## Status and capabilities

Experimental software: stage and verify before replacing a production core.
The separate NahaN panel is not included in this repository.

- Authenticated TLS control plane, managed manifests and apply receipts.
- Managed VLESS, VMess, Trojan and infrastructure Shadowsocks profiles.
- Core-local secret references, profile preflight and durable traffic reports.
- Live connection-policy updates for new connections while preserving existing
  sessions. Manifest changes can restart the engine.
- Temporary SS tests: independent key and port, one-hour expiry, active-session
  revocation, 10 Mbps/three-IP limits and encrypted browser delivery.

Not all engine protocols have managed adapters. General customer migration,
GRE management, container binary upgrades, imported-certificate renewal and
complete production provisioning remain incomplete. Engine restarts revoke
temporary tests. Example IPs/URLs are placeholders, not working demo servers.

## Build and documentation

Use the Go version in `go.mod` (Go 1.26 or newer) and the pinned patch tool:

```sh
git clone https://github.com/NahaNCode/nahan-core.git
cd nahan-core
MODFILE=$(go run ./tools/xray-patch)
go test -p 1 -modfile="$MODFILE" ./utility/entryprofile ./utility/controlplane ./api/nahan ./service/controller ./manager
CGO_ENABLED=0 go build -modfile="$MODFILE" -trimpath -ldflags="-s -w" -o NahaN .
```

Do not use raw `go install ...@latest`: builds require the repository's Xray
patches. The patch tool uses a temporary dependency copy, not the global cache.

- [Installation and managed configuration](docs/INSTALLATION.md)
- [Managed control-plane protocol](docs/MANAGED-LAB.md)
- [Advanced profiles](docs/advanced-entry-runtime.md)
- [Connection policies](docs/connection-policy.md)
- [Scoped routing consent and preserved DNS](docs/ROUTING-POLICY.md)
- [Traffic outbox](docs/TRAFFIC-OUTBOX.md)
- [Contributing](CONTRIBUTING.md) and [security reports](SECURITY.md)

## Connect using the NahaN panel package

1. In the NahaN panel's core-management page, add a core with a name and host.
2. Select **Issue installation package**. The current wizard registers a LAB
   core and displays the installation-package screen.
3. Download **config.json** and **core.key** from that screen. The key is
   presented at issuance: keep it private and do not commit either file.
4. Place both files together in a dedicated runtime directory on the core host.
   Preserve the panel-issued configuration; do not replace it with a legacy
   per-node configuration or guess the control-plane address.
5. Run the built NahaN binary from that directory:

```sh
cd /opt/nahan/runtime
chmod 600 config.json core.key
/opt/nahan/NahaN -c ./config.json
```

6. Use **Check core report** in the panel and verify a fresh heartbeat.
7. Create an inbound in NahaN, check its profile, publish it, and require the
   core's apply receipt. Client connectivity must then be tested separately.

The exported package already includes `ControlPlane.ApiHost`, `CoreID`,
`KeyFile` and, when used by the panel deployment, `ServerName`. Keep these
issued values together: an IP endpoint and its TLS server name are not
interchangeable. The default exported key path is `./core.key`, resolved from
the process working directory.

Inbound IDs are assigned by the panel and discovered by the runtime; no manual
`NodeID` or per-inbound API key is entered in this package. A connected core
alone does not imply that any inbound has been published.

The NahaN panel is a separate application, not included here. The current
wizard supplies connection files; it does not install the binary remotely.
See [installation](docs/INSTALLATION.md) for the service wrapper.
`examples/managed.json` explains the field shape for development only; it is
not a replacement for the package issued by your panel.

## Docker deployment

Follow [managed installation](docs/INSTALLATION.md#docker) for the same
CoreID/key-file configuration inside a container. This repository does not
provide deployment-topology or tunnel-configuration tutorials.
