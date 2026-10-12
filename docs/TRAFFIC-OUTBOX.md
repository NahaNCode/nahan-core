# Durable traffic reporting (isolated phase)

Opt in using `TrafficOutboxDir` in each node's API configuration. The directory
must be writable by the service account and persistent across deployments.
Leave it unset for legacy compatibility. Enable only against a panel that
transactionally deduplicates `Idempotency-Key` (including across restarts).

The controller reads one snapshot per unique Xray counter tag. After a report
is written, fsynced, renamed atomically and its directory fsynced, it subtracts
only the recorded bytes from counters. Concurrent arrivals remain untouched.
Queued reports retain the same UUID and payload across failed requests and
core restarts. Acknowledged reports are deleted and the directory fsynced.
Replay happens on monitor ticks even when there is no new traffic. Corrupt
reports stop replay rather than silently discarding usage.

## Service identity

`SubscriptionTraffic.UID` is the subscription/service ID, not the owning account
or reseller ID. Each separately purchased service must receive a distinct ID
and credential from the panel; configurations belonging to that same service
use the same service ID. Shared credentials across different purchases cannot
be disambiguated on one inbound and must not be provisioned that way.
Counter tags include inbound tag, email and service ID. The queue namespace
includes API host and node ID; each report contains the unchanged service IDs.
The backend aggregates those services across nodes, not by password or owner.
Repeated identical counter tags in a subscription response are sampled once.

## Limits and deployment gate

- Traffic since the last snapshot is still volatile on process crash. This is
  durable delivery of captured reports, not zero-loss metering of every packet.
- Run one core process per queue namespace. This queue is not multi-process.
- Keep the API host stable while reports are pending; changing it changes the
  queue namespace. Drain or explicitly migrate before changing the host.
- Monitor disk usage: the queue is not auto-pruned. API rejection retains data.
  At 10,000 directory entries, new snapshots are refused and live counters
  remain intact until existing reports can be drained.
- The controller snapshot/consume sequence assumes one monitor per inbound.
- A panel ignoring idempotency headers will double-charge lost-ACK replays.

Validation includes replay after reopening the queue, simulated lost ACK,
unchanged service IDs/payload, acknowledgment removal, storage failure and
preserving bytes added after the snapshot. the isolated lab host crash-injection and full
backend integration remain separate deployment gates.

## the isolated lab host build environment

Archive the intended Git revision into `/opt/nahan-core-build/source` on the isolated lab host,
then run `sh deploy/test-isolated.sh` there. This uses an isolated Go container,
one CPU and 2 GiB RAM without swap allowance, with persistent module/build
caches. It neither binds service ports nor restarts deployed cores. The live
lab runtime remains under `/opt/nahan-direct-core-lab`, outside the build tree.

On 2026-10-10, revision `cd86b09` passed `go test -p 1` for
`./utility/outbox ./api/nahan ./service/controller` in this the isolated lab host environment
with the version-pinned Xray patch applied. This resolves the local dependency
download restriction; it does not replace deployment/crash-injection testing.
