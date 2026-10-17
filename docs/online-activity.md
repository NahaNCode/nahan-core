# Online activity reporting

Online IP reporting previously reset the admission-time map after each report.
Long-lived streams were omitted until a new connection was dispatched.
Both dispatch entry points must be covered: `Dispatch` for pipe/Mux streams and
`DispatchLink` for native physical streams. The native path refreshes activity
on uplink reads and downlink writes; pipe streams refresh on both writers.

The dispatcher now refreshes authenticated user/IP activity on nonempty writes
in either direction, at most once per ten seconds per direction. Reports retain
recent activity and expire IPs after two minutes without activity. No per-stream
goroutine or timer is added for presence. Stale IPs stop consuming legacy IP
limits. Native registered-device mode uses backend identity leases instead of
IP counts; see [Registered Device Runtime](registered-devices.md) for migration,
lease enforcement, and route observations.

This measures recently active user/IP pairs, not humans or open TCP sockets.
Idle sessions expire, NAT can share an IP, and one subscription can use multiple
nodes. Panel totals must distinguish unique subscriptions from IP report rows.

Build and run regression tests using the modfile emitted by
`go run ./tools/xray-patch`, including limiter and dispatcher race tests.
Roll out on origin77 first; retain the previous binary before replacing the
diagnostics binary mount and restarting NahaN. Then apply on origin87 once SSH
access is available. Existing streams disconnect during the restart.
