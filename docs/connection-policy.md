# Managed Connection Policies

Connection policy v1 is a core-scoped domain access policy, not an outbound or a replacement for the Xray router. The first enabled matching rule decides `block` or `allow`. Allow only exempts the request from later managed connection-policy rules; existing node rules, authorization, quotas, and routing still apply.

## Runtime

- The authenticated managed core polls `GET connection-policy` independently from the node manifest revision. Policy changes never invoke `Manager.Close` or recreate handlers.
- A complete validated immutable snapshot is stored atomically in the dispatcher. Concurrent requests see the old or new complete snapshot, not a partially updated rule list.
- Existing TCP and UDP sessions keep their previous route. New dispatches use the new policy. Blocking already-open sessions is intentionally not part of v1.
- Domain matching includes subdomains with a label boundary. Domains obtained by Xray sniffing are checked through the routing context. IP-only connections without an observable domain, encrypted ClientHello names, and unknown speed-test providers are not covered. Do not describe a domain list as blocking every speed test.
- Only authenticated inbound user traffic is subject to this policy. Core management and other internal traffic are not intercepted.
- The last accepted snapshot is persisted with owner-only permissions and bound to the core identity. It is restored before listener startup, and survives temporary panel unavailability. Invalid local snapshots stop startup rather than silently disabling policy.
- A successful exact-revision receipt confirms application. Save/publication alone is not evidence of runtime application.

## Rollout

1. Deploy the backend schema and owner-only policy endpoints.
2. Upgrade a single isolated LAB core. Installing the first supporting binary may require a normal core restart; the no-restart guarantee applies to subsequent policy publications, not binary upgrades or other node configuration changes.
3. Verify the core advertises policy runtime version 2 by polling its authenticated policy endpoint. Version 1 recipients can accept domain-only rules; advanced rules reject unsupported recipients before publication.
4. Save a policy draft, then publish it. Unsupported or revoked recipients are rejected transactionally; other cores are not partially updated.
5. Verify all target revisions are acknowledged and validate traffic with the intended client/network.

Rollback is a new published policy revision containing the previous rule set. Removing a target or deleting a rule publishes a clearing snapshot to former recipients too. Source-core entitlement secrets are unrelated to policy configuration.

Limits: 200 rules per document, 100 domains per rule, 100 selected cores per rule; the panel proxy also limits request bodies to 64 KiB. Administrative edits use optimistic revision checks. The initial frontend upgrade preserves differing local prototypes as a recoverable draft; they are never automatically published.

## Checks

`go test -race ./utility/connectionpolicy` exercises immutable snapshot and concurrency behavior.

`go test ./manager -run TestConnectionPolicyHotReloadPreservesOpenConnection` uses real VLESS clients and a loopback echo endpoint to prove established connection preservation, denial of new requests, and removal of the policy. Loopback access is explicitly allowed only by the isolated test outbound.

Backend PostgreSQL integration tests cover target separation, clearing former recipients, stale receipts, revision conflicts, and transactional rejection of unsupported runtimes.

Run lifecycle regressions against the same patched dependency as the release binary:

```sh
MODFILE=$(go run ./tools/xray-patch)
go test -modfile="$MODFILE" ./internal/regression ./app/xdispatcher ./manager ./cmd ./utility/connectionpolicy
```

The unpatched upstream TCP bridge does not release its copy workers on downstream EOF. Docker and GitHub release builds both apply the pinned lifecycle fixes; do not build a production binary with plain `go build`.

## Advanced Conditions (Runtime 2)

Rules may combine exact or suffix domains, destination IPv4/IPv6 addresses and CIDRs, destination port lists/ranges, and TCP/UDP. Conditions in different categories are ANDed; alternatives within one category are ORed. At least one condition is required. IP matching uses observable target addresses and never performs extra DNS lookups. Existing sessions remain untouched by publication.
