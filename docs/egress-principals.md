# Route Infrastructure Principals

## Status

Implemented and tested locally; not a released production publication workflow.
Backend provisioning remains behind the default-disabled egress publication
flag. Do not enable it until the remaining release gates below are satisfied.

## Identity and Protocol

A route's infrastructure principal is independent of customer subscriptions.
The destination generates a fresh cryptographic UUID for VLESS/VMess or a
256-bit random password for Trojan. No customer's UUID or password is read,
copied, exported or placed in a source outbound. SS continues to use its
separate destination-owned credential adapter.

REALITY is VLESS security, not a protocol. Existing listener TLS/REALITY settings
are not replaced by principal provisioning. VLESS Vision flow is supported by
the runtime; advanced VLESS encryption provisioning is explicitly unsupported.

## Control Contract

- The owner requests a transfer for the exact persisted route revision.
- Both enabled cores must have fresh acknowledged manifests and pinned
  recipient identities. Non-SS provisioning requires principal runtime 1 or
  newer at the source and staged-principal runtime 3 at the destination. Pending
  staged jobs are withheld if the destination downgrades to a rotating runtime.
- `egress-principal` jobs contain the destination handler tag, protocol, flow,
  source public key and route/source/target/revision/expiry scope. They never
  contain customer clients or destination TLS/REALITY private keys.
- The destination verifies its actual handler protocol before adding a user.
  It does not rebuild the listener or restart the core.
- The result is RSA-OAEP/SHA-256 plus AES-256-GCM encrypted for the source and
  authenticated to the full scope. Principal envelopes use a separate domain
  from SS envelopes and cannot be substituted for them.
- Only the authenticated source receives the result while destination, recipient
  key, runtime and expiry still match. Draft edits invalidate candidate delivery,
  but not the identity authorized by an unchanged applied publication snapshot.
- Source files are AES-GCM encrypted under the local core credential, written
  atomically with owner-only permissions. Wire plans carry scoped local
  references, never inline credentials. Missing, mismatched or expired
  principal references fail closed.
- Authenticated renewal of the same transfer/binding/credential may atomically
  extend a still-live source file's authorization deadline. Equal deadlines are
  idempotent. Earlier deadlines, changed identities, tampered scope deadlines
  and attempts to revive an expired file are rejected. This is a storage-level
  primitive used by the development-gated backend renewal coordinator.
  Source imports are serialized within the process to prevent concurrent
  deliveries from regressing the persisted authorization deadline.

Managed core startup now configures an encrypted destination principal journal
under the owner-only key directory. Still-live identities are reinstalled on
compatible existing handlers without extending deadlines. Revoked/expired
records are not revived; wrong local keys, tampering and unsafe directory modes
fail closed. New authorization revisions generate independent credentials.
Runtime 3 staged requests use separate revision-scoped leases and encrypted
journal records. Preparing a candidate does not remove a still-live published
identity, stop its renewal or overwrite its journal. Revocation addresses the
exact revision. Legacy non-staged requests retain their explicit immediate
rotation semantics; the backend no longer issues new candidate jobs to those
old runtimes.

Principal runtime 2 advertises source monotonic renewal storage and destination
durability. The backend renewal coordinator only acts on applied, published
routes with fresh source/destination acknowledgements, exact published transfer
and node bindings, unchanged recipient identity and runtime 2 or newer on both
cores (runtime 3 required for staged destination identities). Renewals get independent
job IDs but deliver under the original transfer binding. Pending jobs are not
duplicated, expiry is not revived, and old initial envelopes are suppressed after
a completed renewal. Withdrawal stops renewal delivery. Published authorization
is read from the immutable applied plan and its transfer binding, not editable
draft kind/target/revision. Editing a draft cannot stop renewal of that plan.

## Lifetime and Revocation

Provisioning deadlines are short and explicit (current backend: five minutes).
An active same-revision renewal keeps the credential and existing stream; an
older timer cannot revoke a renewed lease. Changing the listener, recipient,
protocol or flow at the same revision is rejected. A revoked or expired
revision cannot be revived; explicit new authorization is required.

Revocation removes only the infrastructure user and interrupts only its
sessions. Customer users, limiter settings and customer sessions remain intact.
Infrastructure users retain node bandwidth limits but have no customer billing
ID and are excluded from customer online-device reports. Registry installation
count is bounded at 512 per engine lifetime, including rotations, to bound
retained revocation state. Renewal of existing identities still works at capacity.

## Verified

- Real VLESS, VMess and Trojan flows through newly generated principals,
  authenticated control job processing, encrypted source delivery/storage and
  reference-based outbounds; renewal, scoped revocation and customer isolation.
- Expiry, old-timer races, stale revisions, inline credential rejection, source/
  destination binding and cryptographic envelope domain separation.
- Actual VLESS/REALITY/Vision TCP handshake/echo with a synthetic local TLS
  camouflage target, wrong public key rejection and old stream retention:
  three consecutive runs of the complete principal group and five additional
  isolated repetitions pass under the race detector. The previous first-data
  stall was a cold target-profile readiness race, described below. This is a
  local acceptance result, not production-path acceptance.
- Actual Linux GRE traffic using a destination-provisioned, source-sealed and
  locally imported VLESS principal, alongside SS2022 regression checks. Tests
  run only in disposable namespaces, without production default routes.
- Explicit withdrawal with an empty newer snapshot: read-only preflight, atomic
  binding removal without engine restart, retained established TCP streams,
  restoration of normal routing for new flows and rejection of older snapshots.
- Durable destination restart tests for VLESS/VMess/Trojan preserve actual
  authentication and customer flows; revocation survives restart and tampered or
  expired journals are rejected.
- Candidate preparation preserves existing and new live-principal connections,
  customer authentication and old-revision renewal across VLESS/VMess/Trojan.
  Both candidate and live identities survive restart. Candidate-only revocation
  leaves the live principal usable. Tests include legacy-to-staged migration.
- A managed-path probe uses a separate engine in the real host namespace, with
  random authenticated loopback SOCKS credentials and no changes to the customer
  engine. It sends only an end-to-end verified HTTPS panel request through the
  selected outbound. Actual VLESS/HTTPS flow, untrusted TLS rejection, cancellation,
  closed probe listeners and customer-stream retention pass under race testing.
  This helper is not yet wired into asynchronous prepare receipts.

Use the existing version-pinned build module from `go run ./tools/xray-patch`
for release-equivalent tests. Vision in the unpatched pinned Xray source uses
intermediate uintptr arithmetic that fails Go's checkptr instrumentation. The
build correction retains unsafe.Pointer values, uses unsafe.Add and validates
TLS field layouts; it does not disable checkptr or modify the module cache.

The pinned REALITY server asynchronously detects target post-handshake record
profiles for each SNI/ALPN combination. After verifying a client handshake, it
polls an unfinished profile every five seconds before exposing the connection
to the inbound. The synthetic target being TLS-ready did not mean those profiles
were ready, so a five-second application deadline raced the polling interval.
The fixture now waits (bounded to ten seconds) until all three actual target
profiles have been detected before issuing acceptance traffic. It does not
mutate the profile cache, retry the application connection, skip failed cases,
disable certificate checks or weaken the wrong-key negative test. Production
path probes still need an explicit cold-start budget.

## Remaining Release Gates

- Wire the real authenticated path probe into asynchronous prepare receipts.
  Backend compilation now builds
  reviewed VLESS/VMess/Trojan/SS profiles from public metadata and scoped local
  credential references; compilation alone is not a network-path proof.
- Integrate and operationally accept continuous renewal with publication,
  withdrawal, restart, revision changes and bounded multi-revision draining.
- Backend withdrawal now has an explicit default-routing confirmation,
  operation-scoped prepare/commit, fresh exact receipts, monotonic candidate
  generations and retained-route dependency checks. It is development-gated;
  retaining managed routes requires the unfinished renewal/path acceptance.
  Remaining work includes rollback history, bounded stream draining,
  external outbound import/inventory and the complete publication UI.
- Production-path canary acceptance, reviewed public source synchronization,
  push/release and staged deployment. No production rollout is implied here.
