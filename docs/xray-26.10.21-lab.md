# Xray 26.10.21 Upgrade Candidate

Status: isolated LAB candidate, not a production release.

## Runtime And Build

- Pin Xray commit `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74` and Go 1.27.3.
- The upstream release is marked pre-release and contains an emergency trust-store
  update. Do not substitute the withdrawn October 17 candidate.
- Native SS2022 replaces the removed singbridge implementation. The old bridge
  patch anchors and tests cannot be carried forward as if that code still existed.
- Retain native SS2022 cancellation, link interruption and timer cleanup through
  the reviewed alternate-module build. Its anchors and toolchain remain pinned.
- Replace bridge-specific regression fixtures with native packet-error and
  bidirectional disconnect tests; preserve physical-reader and Mux-isolation checks.
- Regenerate the entry catalog from the pinned engine's Go JSON contracts using
  `tools/entry-schema`. Generation does not advertise new publication adapters.
- Adapt removed error-severity builder calls without changing admission policy.

## Acceptance Evidence

The isolated host tests used a temporary systemd service with a private network,
an unprivileged user, a private temporary directory, read-only system paths, and
bounded CPU, memory and runtime. They did not reuse a live core identity.

Verified in that environment:

- VLESS RAW, WebSocket and XHTTP round trips.
- REALITY/Vision handshake and wrong-key rejection.
- Independent legacy SS2022 client to native server, TCP and UDP, with all three
  configured cipher methods.
- Native SS2022 candidate outbound to the previous binary's server, TCP, with
  all three cipher methods.
- Policy reload preserves an existing stream.
- Bind failure is reported and a subsequent clean start succeeds.
- Committed published source/destination routing survives a 31-second refresh gap.
- The candidate CLI serves 100 authenticated transfers, the previous CLI serves
  the same isolated configuration after replacement, and candidate reapplication
  succeeds. This is not a rollback of production runtime journals or financial data.

Local coverage additionally includes traffic-outbox replay/lost ACK and concurrent
counter snapshot behavior. These are not evidence of live production billing.

## Production Gates Still Required

1. Deploy and integration-test backend job receipt compatibility for both reviewed
   engine versions. The old backend accepts only 26.7.28 for most non-update jobs.
2. Verify real managed manifests, scoped jobs, receipts and authorization against
   an independent staging core, without copying a production core key.
3. Exercise a previous-engine client against the candidate's public-facing protocol
   profiles and test the reverse direction where the staged topology requires it.
4. Validate target-specific profiles and last-good/journal restoration across a
   real managed binary rollback, including usage queue preservation.
5. Complete representative soak/resource measurements and an immutable signed
   release before a single-host canary. Do not equate short loopback acceptance
   with ISP connectivity or long-term stability.

No routing authorization, device lease, financial quota, IP-limiter algorithm or
customer credential policy is changed by this upgrade candidate.
