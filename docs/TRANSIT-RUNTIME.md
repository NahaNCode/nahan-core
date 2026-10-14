# Managed Transit Runtime Contract

Status: runtime groundwork. End-to-end path orchestration and the panel editor
must be completed before enabling managed transit paths in production.

Native managed heartbeat advertises `transitRuntimeVersion: 1`. The panel must
require a fresh capability report before publishing any input with
`server.entryRole: "transit"`. A stable runtime without this capability must not
receive such a configuration: it could otherwise use ordinary routing.

Explicit `customer`, `transit`, and `exit` roles are distinct. Version 1 transit
and exit inputs require a managed infrastructure Shadowsocks listener. They cannot
be disguised as customer inputs, and unknown roles are rejected. Existing inputs
without explicit roles retain their legacy behavior.

The controller reserves each transit tag before starting the listener. A transit
tag requires an unexpired managed outbound binding with a scoped imported SS
credential. A direct, blackhole, or arbitrary external outbound cannot become its
next hop. Destination Internet exit-IP selection is forbidden on transit inputs.

Missing bindings, expired bindings, failed installation, and explicit withdrawal
reject new matching requests instead of falling back to normal Internet routing.
Reservations remain until engine shutdown so queued packets after input removal
cannot bypass the restriction. The reservation count is bounded. In-place role
downgrades are rejected; publish a separate input when changing purpose.

Existing streams retain their outbound references through expiry and withdrawal.
The backend's path compiler, ownership model and downstream-first publication
must preserve this runtime contract across the entire path, including rollback,
credential renewal and retirement. The runtime guard does not itself implement a
distributed transaction or prove end-to-end path readiness.

Local real-socket tests cover absent binding, a credentialed encrypted next hop,
rejection of direct transit, lease expiry, withdrawal, retained streams and normal
input isolation. API parsing tests cover explicit roles and invalid role claims.
