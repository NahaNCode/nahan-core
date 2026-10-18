# Published Path Monitoring

This observational feature reuses the core's isolated managed-egress HTTPS probe.
It does not publish routes, renew financial entitlements, select DNS destinations,
or create customer credentials.

## Runtime

After renewing the active egress lease, a background worker checks only profiles
bound in the validated desired publication. It tests at most four profiles per
cycle, serially, with a 15-second per-profile timeout, a 90-second worker deadline,
and a 60-second minimum pause after completion. Larger plans rotate batches.
Only one worker runs per core. Publication withdrawal, replacement, shutdown, and
custom-routing rejection cancel obsolete work.

The existing `ProbeEgressProfile` uses a temporary loopback-authenticated SOCKS
inbound in an isolated Xray instance. `ProbeViaSOCKS` requests the panel manifest
through the selected outbound, with normal panel TLS verification. No customer
inbound, customer credential, or routing handler is changed. Latency measures
the HTTPS request, excluding temporary engine startup.

Results go to the authenticated core endpoint `POST /egress/health`, scoped by
publication revision, digest, and bound profile ID. No raw error text, address,
token, or credential is reported. Old publications are rejected server-side.

## Deployment Order

1. Deploy the panel migration and health endpoint first.
2. Test and build this core using the pinned Xray modfile used in CI.
3. Release through the existing signed core-update process; canary one source
   core, then verify health reports before rolling out the remaining source and
   transit cores. Destination-only cores do not originate profile checks.
4. Confirm that core and egress revisions remain acknowledged, leases continue
   renewing, and no live routing settings changed.

Old cores remain compatible but cannot provide periodic profile evidence. Their
paths are shown as unknown, not healthy. No separate probe host is required.

The panel follows acknowledged bindings recursively and combines source and
destination runtime freshness, authorization revisions, exact transferred
destination revisions, both managed-GRE sides, and every profile's fresh HTTPS
result. Unsupported routing, cycles, missing dependencies, and stale observations
remain unknown. A fresh explicit failure is an outage.

The panel stores one path-state sample per entry per 30-second bucket for 31 days.
Availability is operational / (operational + outage); coverage separately counts
known samples against the full requested window. Unknown samples and missing
time are never invented as successful. Historic ping-based SLA is not imported.

## Acceptance

- Successful first-hop checks must not mask a failed transit/downstream hop.
- Reports from old revision/digest or unknown profile must be rejected.
- GRE loss must affect dependent entries only.
- No report after expiry must display unknown, not a fabricated zero latency.
- Restarting the panel/core must preserve recorded SLA samples.
- Public output contains controlled reasons and opaque entry IDs, not topology
  identifiers, connection URLs, credentials, or internal addresses.
