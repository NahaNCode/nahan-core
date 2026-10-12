# Managed Advanced Entry Runtime

Only the isolated managed LAB uses this runtime. Existing standalone/production
installations are not migrated or modified. The core reports `entryRuntimeVersion=1`.
Supported managed account protocols are VLESS, VMess and Trojan, with registered
RAW/TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP and mKCP transports. Native WireGuard,
TUN, Hysteria and Shadowsocks account adapters are not advertised as operational.
Publication currently reserves one nonprivileged numeric port per entry.

## Panel To Core Jobs

The core polls `GET /api/core/v1/cores/{core}/jobs` over the existing verified
TLS/IP channel using its own Bearer key. Results go to the core-scoped
`POST .../jobs/{job}/result`. Jobs have a ten-minute expiry, bounded pending count,
immutable payload/revision, and idempotent completion. The OWNER session can issue
jobs and read their sanitized result; it cannot call completion as a core.

- `reality-key`: creates a persistent X25519 private key and random short ID locally.
- `tls-certificate`: creates a **self-signed LAB** certificate; this is not a public
  CA certificate and clients must explicitly trust its public certificate.
- `preflight`: resolves scoped secret references and calls the pinned Xray Build.

Secret files are owner-only under the directory beside `core.key` named
`entry-secrets`. The panel stores references and public metadata, never private
keys. A reference includes both core ID and generation-job UUID. Cross-core keys,
unmanaged certificate/key file paths, and master-key log paths are rejected.
Secret generation retries reuse the same job's key. Keep this directory in backups:
losing it breaks previously distributed REALITY links. Public CA issuance/import,
arbitrary secret types and automatic credential rotation are not implied by this
LAB certificate/key workflow.

## Apply And Rollback

Before closing the current engine, the managed loop fetches and builds all candidate
entries and their freedom outbounds, and fetches current eligible service accounts.
The original complete inbound profile is retained instead of projected through the
legacy server model. Generated controller tags and inline service credentials remain
managed, so arbitrary static account lists cannot bypass order/service assignment.

When a candidate fails to start (for example, a port is occupied), the partial engine
is closed and the preceding prepared node snapshot is started again. The failed
revision is not acknowledged and is not retried repeatedly without a new revision.
Service eligibility refresh remains active. Shutdown snapshots usage into the existing
durable traffic outbox before closing. This is a short engine-level restart, not
zero-downtime live replacement of an individual listener.

After a successful start, `last-good-entry-manifest.json` is atomically saved with
0600 permissions beside `core.key`; it includes sensitive resolved configuration.
Startup can restore that snapshot if the desired entries cannot be built or started.
It fetches current service eligibility again, never cached subscriber grants.
Core access revocation still stops the runtime. A failed rollback, unreachable
authorization service on cold startup, or occupied ports in the last-good snapshot
cannot be guaranteed away: those failures are explicit and fail closed.

Desired/applied revisions and error reporting remain distinct. The panel should
only deliver a test configuration once the core acknowledges the current manifest.
The OWNER-only test service is LAB-scoped, 32 MiB, 10 Mbps, one hour and three IPs.
The UI supplies a VLESS URI; a URI or a successful Build alone is not a transfer test.

## Verification

Unit coverage includes scoped/idempotent local keys, safe permissions, TLS Build,
unknown properties, duplicate JSON, unresolved references, bind failure and engine
restore. Operational tests must additionally exercise a panel-created REALITY entry
with an independent client, real HTTPS transfer, blocked candidate bind, in-process
rollback, cold-start snapshot restore, and unchanged production processes/tunnels.
# REALITY cover preflight

REALITY publication now tests a real engine handshake against the selected
cover through an ephemeral loopback socket. The entry port is not bound and
private keys are not returned to the panel. The first advertised SNI and Short
ID are checked with the installed Xray Chrome fingerprint. A successful build
alone is insufficient: an inaccessible or incompatible cover rejects the job.
This is not a guarantee for every client version or every client ISP.

Ports 1 through 65535 are accepted. Low ports still require OS bind permission;
the panel does not alter capabilities, firewalls, or another process's sockets.
