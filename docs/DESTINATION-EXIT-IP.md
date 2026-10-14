# Destination Internet Exit IP

The managed destination can bind outbound Internet connections to an explicitly
selected local IPv4 address. This is separate from the tunnel endpoint, SS listen
address, and server default route. Existing routes without an explicit selection
continue using their previous routing behavior.

## Shared Listener

Multiple managed tunnels can use one destination listener and port. A rule matches
the listener tag and the validated source/local tunnel endpoint pair; each matched
connection uses its own `freedom` handler with `sendThrough` set to the selected
Internet IP and IPv4-only domain resolution. TCP uses the socket's local address.
For wildcard UDP listeners, the validated private /30 peer identifies the tunnel.

Two routes using the same destination listener and the same tunnel cannot select
different exit IPs. The destination cannot distinguish them. The panel rejects
this conflict rather than silently preferring one route. This is tunnel-based
selection, not a new per-user Shadowsocks identity or load-balancing algorithm.
Keep tunnel firewall anti-spoofing and peer restrictions in place.

## Independent Listener

A separate destination listener and port can select its own Internet IP without
a tunnel selector. All connections to that listener use the selection. It cannot
be mixed with shared selection or a conflicting automatic/default-IP route on the
same listener. Choose a genuinely separate listener when using this mode.

## Control and Safety

The core reports owned public IPv4 addresses, receives an authenticated complete
snapshot, installs its handlers atomically, persists the snapshot encrypted, and
acknowledges its exact revision and digest. The panel does not release the source
publication until the destination has acknowledged the required rule.

Rules have a short renewable lease. Expired, inactive, or restored-but-not-yet-
confirmed selections reject new matching connections instead of falling back to
the default IP. Established connections retain their handler during hot updates.
Withdrawal retains the old selector until the source acknowledges its replacement;
an offline or unauthorized source cannot keep renewing that selector.

The destination must have routing consent, a fresh report, an applied manifest,
and the selected IP on an active local interface. No public SS firewall exposure,
default route change, NAT rewrite, or automatic address installation is performed.
This feature selects IPv4 exits; it does not promise a separate IPv6 exit.

Use the normal signed updater (`nahan-core update check`, then
`nahan-core update --core CORE_UUID --yes`) or the panel upgrade workflow before
selecting an exit IP. A binary upgrade restarts that core; route selection itself
is a hot update. The panel and runtime must both support destination exit routing.
