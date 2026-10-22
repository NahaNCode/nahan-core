# Managed Control Availability

## Execution Model

- Heartbeat and manifest retrieval have independent single-flight workers. Each
  attempt has a 27-second context budget, including verified fallback attempts.
- Successful polling waits ten seconds plus up to 20% jitter. Failures back off
  up to forty seconds plus jitter. There are no queued missed ticks or per-request
  goroutine fan-outs. Explicit core authentication revocation cancels the workers
  and stops the managed runtime; transport failure is not revocation.
- Engine changes remain serialized: jobs, egress, destination exit and connection
  policy run round-robin with a shared 27-second budget per complete operation.
  A pending manifest mailbox contains at most one immutable latest observation.
- Heartbeats send an immutable snapshot captured by the engine owner. They never
  invoke mutable routing callbacks from their sender goroutine. Configuration
  replacement reports an applying state before closing handlers. Applied revision
  changes only after successful startup, retaining existing rollback behavior.
- Temporary node/subscriber retrieval failures retry the same revision; permanent
  preflight rejection still requires a corrected revision. Old revisions are not
  reapplied. A stalled local engine startup/close is not forcibly aborted: unsafe
  concurrent rebuilds would be worse than a delayed apply acknowledgement.

## Transport And Accounting

The existing official-host HTTPS -> first direct IP+TLS -> second direct IP+TLS
policy, pinned private trust root, hostname validation, terminal authentication
errors and replay allowlist are retained. Native APIs no longer add a second
Resty transport retry layer around that policy. Unsafe job/device/policy writes
are not made replayable. Reports retain their original idempotency identity.

Durable traffic capture does not perform network delivery. One cancelable sender
per native client drains at most 64 reports per pass within a shared 27-second
budget. Closing a controller persists its final counter snapshot, cancels delivery
and leaves unacknowledged reports intact. Rollback can reopen the sender. The
queue keeps at most 10,000 entries, 64 MiB total and 4 MiB per newly enqueued
report. Existing reports are never silently evicted by age or disk pressure.
When persistence is refused, live counters are not consumed; a subsequent crash
can still lose counters not yet persisted. This is not a lossless-on-full-disk
claim. Operators must restore free capacity before that condition persists.

## Diagnostics And Security

Control diagnostics use eleven fixed labels: eight request categories and three
verified transport routes. Each stores counters, last success/failure, bounded
reason code and duration; no URL, service identity, payload or token is retained.
Request summaries emit at most once per category per minute, including flapping.
There is no append-only diagnostics file. The backend validates and replaces one
bounded document per core; a DB size check provides an additional 16 KiB ceiling.

The owner core list exposes `control_health` and `control_health_seen_at`.
When enabled, the existing owner-only Unix diagnostics socket exposes
`GET /debug/control-plane`. These are management observations, not proof of
customer connectivity. Public path health must continue using real probes.
`last_error` remains configuration-apply status, not a catch-all transport alarm.

No subscriber grants, device leases, revocation rules, quotas, IP limits or routing
consent were relaxed. A running engine retains its last applied state through
control transport failures under the existing authorization policy. Cold startup
does not manufacture fresh subscriber authorization from an old snapshot.

## Acceptance And Next Phase

Require race tests, blocked-job heartbeat/manifest isolation, authenticated
retained-stream transfer, unknown-credential rejection, terminal revocation,
cancelable traffic delivery, stable report replay, bounded storage, private-TLS
rejection and primary/direct-route failure/recovery tests. Validate backend
compatibility and bounded replacement using isolated PostgreSQL. Run the engine
fixture in a resource-limited LAB before any production core restart.

Next phase is global IP/device/speed enforcement and Redis atomicity/failure
policy. No new Xray protocol options or sing-box work belongs to this phase.
