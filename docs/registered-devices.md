# Registered Device Runtime

The native `nahan-v1` heartbeat advertises `deviceRuntimeVersion: 1` with the
device gate wired through `Controller.AddInboundLimiter`. The backend must emit
device-mode subscription rows only after observing this capability. Older cores
(capability absent or zero) receive only the preserved legacy credential.
Non-native protocols and rows with `deviceId == 0` retain legacy IP limits.

## Identity and Migration

Each `/subscriptions` item supplies `id`, `serviceId`, `deviceId`, `deviceLimit`,
and the existing credential/speed fields. In device mode `id == deviceId > 0`,
`serviceId > 0`, `deviceLimit` is 1..100, and `iplimit` is zero. The legacy
device has `deviceId == serviceId` and keeps its credential. Additional device
IDs come from the backend's same service sequence, so auth IDs remain unique.
Core creates a unique internal email per device credential generation; UUID or
password rotation changes that email without changing the device ID. Unchanged
snapshots preserve it. Subscription removal revokes and deletes the old email;
traffic checks cannot revalidate old streams merely because the same device ID
has a valid lease for its replacement credential. No separate revocation feed is
required for credential changes reflected in subscription snapshots.
Auth UID and traffic report
`subscription_id` stay the device ID. The backend resolves device IDs to their
service for aggregate billing. Core rate buckets use `ServiceID`, shared across
devices and inbounds within the process; backend allocation remains responsible
for splitting an aggregate speed budget across cores.

Default migration preserves every legacy configuration through backend lazy
import as one registered identity. Core does not rotate or derive credentials,
delete registrations, restrict public IPs, or change ACLs.

Device identity is **credential enrollment, not hardware attestation**. Copying
one enrolled credential to another physical device cannot be detected as a new
device. Multiple connections, IP changes, inbounds, or cores using the same
identity count as one identity in the authoritative backend lease system.

## Lease Contract

Authenticated `POST /api/core/v1/nodes/{nodeId}/device-leases`:

```json
{"deviceIds":[101,102]}
```

```json
{"leaseSeconds":120,"grants":[{"deviceId":101,"expiresAt":1800000000}],"denied":[102]}
```

`expiresAt` is an absolute Unix timestamp in seconds, not `expiresAtUnix`.
Core requires a complete, non-duplicated partition of requested IDs into grants
and denials, no unsolicited IDs, and future expiries at most 120 seconds away.
A malformed response applies nothing. HTTP errors and timeouts do not extend
cached expiry. Explicit denials immediately invalidate the cached lease.

First-seen admission uses a local per-device singleflight cache and a two-second
HTTP deadline with no HTTP retry. Unknown/denied/expired identities fail closed;
later connection admissions may retry after a two-second backoff, sharing one
in-flight request per identity with renewal. There is no SQL, IP count, or network
request in the traffic path. Active identities renew in batches of at most 512
at the existing 60-second
`userInfoMonitor` cadence; inactive cache entries expire after 120 seconds.
Traffic wrappers check local cached validity on both native and pipe/Mux paths,
including after rate waits, and interrupt invalid streams. Existing authorization
snapshot revocation/expiry still interrupts streams independently. Idle device
streams are rejected when they next attempt traffic.

## Presence and Route Telemetry

`onlineip` retains its `{"data":[...]}` envelope. Rows contain
`subscription_id` (device auth UID), `ip`, `firstSeen`, `lastSeen` (Unix seconds),
and optional `routeTag` (string), `routeRevision` (int64). The backend maps the
device UID to its service. IP is presence context only, never a device-mode limit
or identity. Reporting remains 60 seconds and activity TTL remains 120 seconds;
traffic activity refreshes at most once every ten seconds per wrapper.

The dispatcher captures the actual selected handler tag and managed snapshot
revision at route selection, under the route registry lock. A flow keeps this
observation even when a later snapshot changes the route. Non-managed selections
have revision zero. Up to 64 IP/route/revision observations are retained per
device per inbound, evicting the oldest activity when full. Concurrent old and new
route versions can both appear until their activity expires. No credentials or
route secrets are added to logs.

Session client name is unknown. Registration metadata or subscription-fetch
metadata is backend-owned advisory information, not observed client identity.
Core does not fingerprint encrypted traffic or derive route metadata from a
client User-Agent. Automatic health failover is deferred.

## Validation and Release

Use the existing `tools/xray-patch` alternate module workflow for dispatcher
tests and release builds. Focused tests can run sequentially with
`GOMAXPROCS=2 go test -p 1 -race -modfile="$MODFILE"` for `./api/nahan`,
`./utility/limiter`, `./app/xdispatcher`, `./utility/egress`,
`./utility/exitroute`, and `./service/controller`. The signed release workflow is
unchanged; the parent deploys the reviewed release. This implementation does not
alter release version metadata.
