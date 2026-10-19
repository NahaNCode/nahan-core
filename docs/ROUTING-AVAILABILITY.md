# Published Routing Availability

Starting with v1.6.12, an installed, validated source or destination routing
snapshot remains selected until explicitly replaced or restricted. Missing a
control-plane refresh does not automatically stop that route after 30 seconds.
The wire field `leaseSeconds` remains validated for protocol compatibility and
refresh scheduling, but is not a forwarding deadline for published routes.

This policy applies to the source egress registry, transit next-hop selection
and destination exit-IP selection. It does not enable direct fallback when a
managed handler is missing, a transit route is withdrawn, or a selector is
inactive. Revision/digest checks, locally owned exit-IP validation, routing
consent restrictions and explicit withdrawal are preserved.

## Persistence

Source publication writes an encrypted `prepared` journal before installation
and a `committed` journal only after success. Only committed publications can
be restored independently of the former refresh deadline. Interrupted,
uncommitted publications remain blocked. Destination publications are marked
committed only after successful installation and encrypted persistence.
Existing pre-v1.6.12 journals retain their previous bounded restore behavior
until a successful synchronization writes committed state.

User authorization, registered-device leases, service expiry, quotas, sealed
credential delivery expiry and destination-principal expiry are separate
controls and are not disabled by this change. Customer access can therefore
still be denied for those reasons; this is not an unlimited offline access
grant. Control-plane access may also still be required during core startup.

## Revocation Tradeoff

While the control plane is unreachable, a running core cannot learn a new
remote route withdrawal. The last installed route remains selected, rather
than treating silence as revocation. On reconnection, validated newer
snapshots and explicit restrictions continue to apply. Failed refreshes must
remain visible in management logs and telemetry, not be reported as success.

No GRE interface, key, MTU, TTL, firewall, NAT or default route is changed.
