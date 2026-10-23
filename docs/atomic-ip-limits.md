# Atomic IP Admission Candidate

Status: development candidate, not a signed production release. No protocol
engine change is included. Registered devices and distinct peer IPs remain
different policies; neither identifies physical hardware.

## Managed Runtime

The backend can opt specific native node IDs into `globalIpLimit` using the
operator-only `nahan.limits.atomic-ip-nodes` allowlist. The default is empty.
The flag applies only to eligible shared legacy credentials, retaining the same
UUID, password, subscription ID and public endpoint. It is not applied to
registered-device credentials. Enable it only after every participating core
has a verified compatible runtime: mixed local/global counting is not strict
global enforcement. This is an operator allowlist, not automatic negotiation.

An authenticated `POST /api/core/v1/nodes/{nodeId}/ip-leases` checks current
assignment, service status, quota, expiry, group publication and migration state
before coordinating one Redis sorted set per service. New IPs are admitted only
inside the configured cap. An existing IP on another core is one member.
Canonical IPv4-mapped addresses share the IPv4 identity. IPv6 spellings are
canonicalized; scoped addresses and hostnames are rejected.

The server returns grants lasting at most 120 seconds. The core uses per-IP
singleflight, at most eight concurrent HTTP requests, no blind POST retries,
512-entry renewal batches and a five-second whole-renewal budget. Rotating the
batch starting point prevents a failing batch from permanently starving later
entries. Renewal is driven by existing online-report scheduling and activity
touches. No Redis or HTTP request is made for every packet.

Stream validity is checked locally, including after rate waits. Once an IP
lease expires or is explicitly denied, subsequent traffic is rejected. A new
connection may reapply for a free slot; renewal alone cannot create an absent
member. Inactive entries are reclaimed after 120 seconds. A disconnect does not
delete presence that another core may still be using. Known limitations include
the existing approximately 60-second renewal cadence and the finite 120-second
lease: prolonged coordinator failure can stop traffic when its grant expires.
This is distinct from historical routing-authorization expiry and is not an
indefinite offline authorization guarantee.

## Outage Semantics

Unavailable Redis, exhausted work queues and malformed/partial replies return
HTTP 503 rather than a successful response denying every device/IP. A valid
old lease is neither extended nor revoked on infrastructure failure. Unknown
credentials never become authorized because Redis is down. Explicit denials
still revoke the local grant. Backend work shares a bounded worker pool with
registered-device coordination, so saturation is reported, not hidden.

The same separation fixes the existing registered-device response path. Local
atomic counters expose unavailable/denied/saturated cases without per-request
credential/IP logging. These getters are not yet surfaced in the admin UI or
persisted as a new heartbeat contract.

## Standalone Legacy Redis Adapter

The older `ControllerConfig.IPLimit` adapter no longer reads and asynchronously
rewrites a cached map. A one-key Lua script atomically prunes expired members,
checks the exact cap and inserts/refreshes membership using Redis time. Keys
hash the stable service identity plus an operator-defined shared `Scope`, not
the inbound tag or current limit. The old cache key space is not reused.

The adapter bounds sorted-set size to 4096, connections to eight and request
time to 1-5 seconds. Redis TLS supports normal certificate validation without
an insecure bypass. `OnError=allow` is the compatibility default: unavailable
coordination falls back to local admission limits for already authenticated
users and increments bypass counters. `OnError=deny` rejects new admissions.
Existing streams are not cut merely by the standalone adapter losing Redis;
its contract remains admission/presence, not hard fencing of every legacy flow.

Presence renewal uses bounded pipelines on the reporting cadence. A timeout
records unavailability/deferred work instead of spawning unbounded background
workers. No production Redis listener was exposed or configured for this work.

## Rate Scope

Local per-service buckets are shared across authorized inbounds and recomputed
on assignment/configuration changes, using the minimum nonzero applicable
ceiling. A faster inbound/update cannot increase a more restrictive assignment's
shared limit. Existing bucket references are preserved when removing a ceiling.
Upload and download consume the same per-process bucket, with a one-second
configured-rate burst, as in the existing implementation.

Unlimited streams also retain an attached bucket, so introducing a finite
ceiling affects already-established traffic without reconnecting. An actual
VLESS echo transfer tests this transition, not only bucket pointer equality.

This is not a new dynamic distributed speed allocator. The backend's existing
static per-core division remains unchanged and is not a partition-safe epoch/
fencing protocol. This remains work, not a claim of completed strict global
speed enforcement.

## Acceptance And Deployment

Tests use disposable local Redis/PostgreSQL, never production credentials/data.
Coverage includes independent limiter instances competing for one cap, actual
VLESS clients and two Xray runtimes, canonical addresses, expiry, explicit
denial, unknown-user rejection, current SQL entitlement and outage handling.
The release gates require Redis rather than silently skipping its test suite.

Before production: signed candidate build, real managed LAB endpoint testing,
distributed-speed allocation/fencing implementation and partition tests, admin
diagnostic plumbing, then one-host canary and serial rollout. The allowlist must
remain empty until compatible runtime coverage and acceptance are established.

References: [Redis Lua atomicity](https://redis.io/docs/latest/develop/programmability/eval-intro/),
[Redis TIME](https://redis.io/docs/latest/commands/time/),
[sorted-set expiry complexity](https://redis.io/docs/latest/commands/zremrangebyscore/).
