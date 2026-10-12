# Session lifecycle investigation and rollout

## Verified defects in the pinned Xray dependency

The deployed Xray revision is `5ca6f4b7d4dc`, with sing v0.7.14.
The active outbound uses Shadowsocks-2022, not the older Shadowsocks client.

* `PacketConnWrapper.ReadPacket` discarded EOF/cancellation when no buffer
  was returned. The copy loop interpreted the result as a successful empty
  packet instead of ending the UDP session.
* `PipeConnWrapper.Close` did nothing. A failed download could leave the
  upload worker blocked until the idle timer fired; the copy group waits for
  both workers. Closing now finishes the timer, which interrupts the reader
  and server connection.
* TCP bridge timers were not finished when copying returned. A timer closure
  could retain ended-session references until the next inactivity checks.
* Shadowsocks-2022 did not defer closing the dialed connection before its
  early handshake/error returns. The patched version owns this cleanup.
* The outbound's UDP bridge timer is finished when copying returns.
* On the destination, SS2022 inbound UDP copy timers are also finished when
  copying returns; closing the generic packet bridge finishes its timer.
* NahaN wrapped physical inbound readers in `TimeoutWrapperReader`, which
  has no Interrupt/Close forwarding. A downstream failure could therefore
  leave the upload reader blocked even after the timer fired. DispatchLink
  now attaches an interruptible owner that closes only its physical inbound.
  Mux substreams still use Dispatch and independent pipes, not this owner.

These are reproducible lifecycle bugs, not proof that they explain all
historical RAM growth. RSS includes retained Go heap pages and stacks. Compare
live heap, goroutines, file descriptors and throughput across several idle
windows before calling the production incident resolved.

## Reproducible build

`tools/xray-patch` copies the exact pinned dependency into an isolated temporary
directory, applies checked single-occurrence edits, and produces an alternate
module file. The module cache and repository go.mod/go.sum stay unchanged.
It refuses an unreviewed Xray version or changed source anchors. Docker builds
run the regression tests against this patched module before compiling.

```sh
go run ./tools/xray-patch > /tmp/nahan-modfile
go test -race -modfile="$(cat /tmp/nahan-modfile)" ./internal/regression ./app/xdispatcher ./cmd
CGO_ENABLED=0 go build -modfile="$(cat /tmp/nahan-modfile)" -trimpath -o NahaN .
```

Running the regression package against the original dependency intentionally
fails: it demonstrates the bugs. No periodic forced GC, resource increase or
arbitrary connection cap is used to hide the problem.

## Private diagnostics

Disabled by default. Set `NAHAN_DIAGNOSTICS_SOCKET` to an absolute Unix socket
path to enable pprof. The socket is mode 0600; there is no TCP diagnostics
listener. Root can collect profiles through the container mount namespace:

```sh
pid=$(docker inspect -f '{{.State.Pid}}' nahan)
curl --unix-socket /proc/$pid/root/tmp/nahan-profile.sock \
  'http://localhost/debug/pprof/heap?gc=1' > heap.pb.gz
curl --unix-socket /proc/$pid/root/tmp/nahan-profile.sock \
  'http://localhost/debug/pprof/goroutine?debug=1' > goroutines.txt
```

Profiles may contain private operational data. Keep them root-only and never
commit them. `gc=1` is a diagnostic collection step, not a runtime policy.

## Canary and rollback

Start with origin77. Preserve the previous image, compose configuration and
binary. The optional `compose.diagnostics.yaml` binds a canary binary from
`/opt/nahan-docker/diagnostics/NahaN`. Recreate only the nahan container;
do not reboot the server or modify routing, credentials, GRE or node settings.

Validate both inbound listeners, fresh monitor evidence, successful outbound
HTTPS, TCP/UDP copy regression tests, and heap/socket trends under traffic.
Deploy origin87 only after the canary is healthy. A post-restart RAM drop alone
does not validate the fix. Long-term trend validation remains necessary.

To roll back the canary override, run the original compose file alone:

```sh
cd /opt/nahan-docker
docker compose -f compose.yaml up -d --no-build nahan
```

If using a patched image rather than the binary override, restore the saved
image reference first. Profile sockets disappear when the container is
recreated; do not reuse stale sockets in a persistent volume.

## Rollout checkpoint: 2026-10-02 UTC

* Origin77 started the patched binary at 17:35:16. At 17:46:34 it was still
  running with no automatic restart and no swap. Sampled live heap varied
  from 148 to 277 MB (unforced collection samples), ending at 145 MB.
  Goroutines varied from 2,114 to 2,797, ending at 2,005; file descriptors
  ended at 1,350. This demonstrates cleanup, not a multi-hour stability claim.
* Origin77's outbound HTTPS probe succeeded at approximately 288 ms.
* Origin87 started the same patched binary at 17:46:20. Its primary and backup
  outbound probes both succeeded after startup. The initial host memory drop
  is restart-related and must not be treated as proof of leak resolution.
* Both hosts use the binary bind-mount override, not a newly published image.
  The installed binary SHA-256 is
  `1480797abc7d397f43a8c4a76a6ff4d92ffc2593718707f44c3b957a52add482`.
  Use both compose files for subsequent recreations while this rollout is
  active; using the base compose alone intentionally rolls back.
* Targeted Go 1.26 race tests and vet passed. The repository-wide suite fails
  on pre-existing `utility/mylego` tests using obsolete certificate APIs.
* Continue evaluating the existing resource-history charts over several hours.
  Further heap/goroutine comparisons are needed if growth continues.

The first rollout's checkpoint above predates the physical-reader ownership
fix. A stricter downstream-EOF test exposed the additional blocked-reader
case; the integrated dispatcher test reproduces this through wrapLink and
passes with the owner. Do not confuse the first binary hash with this update.

The complete physical-reader fix was subsequently installed on origin77 and
then origin87 (17:55:43 UTC). Both listeners on origin77 and port 84 on origin87
were verified after recreation, with zero automatic restarts. The final binary
SHA-256 is `4dd50500034fe98c6158b2900818891f50b870de46c390f08a96485245f58c1b`.
The additional downstream-EOF and Mux-isolation tests passed with the race
detector. This rollout does not yet establish multi-hour memory stability.

## Destination122: 2026-10-02 UTC

The destination runs two standalone Xray 26.7.28 SS2022 inbound servers, not
NahaN. Before rollout their process RSS was approximately 1.9 GiB and
0.67 GiB; host memory use was approximately 84%. This establishes memory
pressure, not an independently proven leak in both processes.

Official tag v26.7.28 resolves to the same core revision 5ca6f4b7d4dc. Its
sing dependency is v0.5.1, unlike NahaN's override v0.7.14. The destination
binary was built inside the isolated patched Xray module with the official
module's dependency versions. The same regression suite passed with those
versions and the race detector. The verified shared defects are dropped UDP
EOF and incomplete bridge/timer cleanup; the NahaN physical-reader ownership
fix is not needed for the destination's independent pipe links.

The final destination binary SHA-256 is
`572dca9013e0e0aea0d8cc66a84ee6f66139648ec68878f52982a7a563d55be1`.
Both private SS configs passed `run -test` using the actual runtime UID 0.
The origin77 path was updated first at 18:07:22 UTC; a fresh authenticated
outbound HTTPS probe succeeded at 18:07:46 UTC (383 ms). Then the origin87
path was updated. Both TCP/UDP listeners remained bound to their private
GRE IPs, and both systemd units reported zero automatic restarts. Host RAM
after both restarts was approximately 23%, with no swap.

No GRE, routing, SS key or panel configuration was changed. Systemd drop-ins
mount `/opt/xray-session-fix/xray` over the original image binary; the original
image and `/opt/xray-session-fix/xray.before` are preserved. Removal of only
the lifecycle drop-in restores the original image binary. Regression tests
cover UDP cleanup, but a separate end-to-end user UDP test and multi-hour
memory-stability validation remain outside this rollout checkpoint.

See [managed installation](INSTALLATION.md) for runtime setup and recovery.
