# Managed Routing Consent Runtime

Target core release: v1.6.6 (this change does not create or publish a release).

The core exposes routing-policy runtime version 1. This is permission to apply
panel-managed bindings to selected inbounds, not permission to delete or replace
server-local configuration. Other inbounds retain their existing routing.

Heartbeat field `routingPolicy` and job completion field `routingPolicy` contain:

```json
{"runtimeVersion":1,"digest":"64 lowercase hex characters","generation":1,"enabled":false,"hasRoute":true,"hasDNS":true,"hasInbound":false,"dnsCompatible":true,"blockers":[]}
```

The digest is a core-key-scoped HMAC of structured local path/content inputs,
including outbound configuration. Reports never include file paths, resolver
addresses, configuration contents or credentials. Generation changes when the
inputs change or consent changes. The report describes the running process's
configured paths, not a newly edited main configuration awaiting restart.

Jobs:

- `routing-policy-inspect`: read-only; payload is ignored. Completion is valid
  even if the report contains blockers.
- `routing-policy-apply`: requires a strict JSON payload with no extra fields:

```json
{"coreId":"core UUID","expectedDigest":"current report digest","expectedGeneration":1,"enabled":true,"acknowledged":true}
```

Every apply, including disable, requires explicit acknowledgment, matching core,
current digest/generation and a valid job UUID. Completion returns `valid`, `code`
and the current `routingPolicy`. Rejections use `routing_policy_rejected` without
disclosing configuration. Successful apply increments generation. Exact retries
of the most recent job are idempotent; stale approvals and old-job replay fail.
The panel must prohibit disabling consent while published bindings remain and
withdraw them first. The core callback independently rejects disable while live
or restored bindings remain (including expired bindings), without shortening
their leases. Configuration invalidation, unlike a rejected revoke request,
restricts existing managed leases immediately.

The owner-only `managed-egress-policy.json` journal alongside the core key is
HMAC authenticated, atomically replaced and fsynced. Invalid, foreign-core,
symlinked or permissive journals fail closed. Do not delete or edit this file to
bypass a failed approval. Inspect and repair it with server administrator access.

Existing supported DNS files remain untouched and are also loaded by the real
path probe. The conservative supported subset allows ordinary DNS servers and
query/cache/fallback options accepted by the engine. Custom hosts, FakeDNS,
unknown top-level DNS options and custom inbound files are blocked. Read errors
also block approval. Custom routing requires consent unless legacy
`AllowManagedEgress` was already explicitly enabled without custom DNS/inbounds.

Blocker codes: `configuration_unreadable`, `dns_unsupported`,
`custom_inbound_unsupported`, `policy_journal_invalid`,
`policy_persistence_failed`, `configuration_restart_required`.

Changing any inspected file invalidates consent. A running process also requires
restart before approving changed inputs, because its loaded DNS/routing may still
be the previous version. On startup and each control-plane cycle, invalid consent
expires restored/live managed bindings before any candidate can be activated.
Legacy configuration files are never rewritten. Permission alone does not
publish a route: the panel must complete identity transfer, probe and publication.
