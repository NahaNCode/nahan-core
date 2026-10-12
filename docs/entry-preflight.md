# Advanced Entry Preflight

`NahaN entry-preflight --file entry.json` validates a bare Xray inbound or the
version-2 NahaN entry envelope. `--file -` reads stdin. It never starts an engine,
opens a listener, reloads the manager, or changes existing nodes.

The embedded schema must match the compiled Xray version. Declared fields and
types are checked before calling the actual `conf.InboundDetourConfig.Build()`.
Opaque JSON extension values are preserved and validated by the engine where it
provides validation; this is not a universal semantic validator for custom JSON.
Xray Build can read certificate files or resolve target names. Run it with the
same restricted filesystem permissions intended for the managed core, not as a
public HTTP endpoint or with untrusted arbitrary paths as root.

Output is a structured result: `valid`, `engineVersion`, `digest`, `protocol`,
`stage`, and an optional stable `code`. Rejection exits nonzero. Detailed Xray
errors are deliberately not returned because they can contain credentials.
Digest is SHA-256 of canonical inbound JSON and excludes envelope metadata.

Secret references are rejected as `unresolved_secret`. They must eventually be
resolved through a separately authorized core-local secret store. This command
does not resolve them, receive secrets from management, or accept unknown engine
versions. Limit is 60,000 bytes and 24 nested objects/arrays.

## Deployment Boundary

This phase installs a separate preflight binary in the isolated LAB tools directory.
It does not replace or restart the running core. Successful Build does not prove
port availability, service/account binding, connectivity, protocol registration,
resource availability, or transactional apply/rollback. Do not enable unrestricted
advanced publication based solely on this result.

Next integration requires authenticated preflight jobs bound to core ID, draft
revision and digest; authorized secret/certificate resolution; service credential
binding; verification of actual registered engine capabilities; and a staged apply
mechanism that keeps or restores the last working configuration on failure.
Current manifest changes close the LAB engine before rebuilding, so they must not
be used to apply unchecked arbitrary profiles.
