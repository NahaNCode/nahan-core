# Managed Control-Plane Protocol

The panel issues a CoreID, HTTPS API address and private core.key. Keep the
issued values together; see [installation](INSTALLATION.md) for provisioning.
Configuration and credentials belong outside source control.

The client verifies TLS and server identity. An IP-based API URL requires the
issued ServerName. Private trust uses CAFile; disabling verification is not
supported. The credential file must be owner-readable only.

Manifest and heartbeat endpoints are scoped to `/api/core/v1/cores/{CoreID}`.
The credential authorizes only enabled nodes belonging to that core. A runtime
acknowledges the desired revision after starting its services. Manifest changes
can restart the engine. Authentication revocation stops the managed engine;
temporary connectivity failures retain the running configuration.

A heartbeat is not proof of end-to-end connectivity. Require a fresh apply
receipt and a real client request before accepting a deployment. Stage changes
with independent credentials and ports; never reuse a live identity in a second
instance. Server-specific units, incident reports and topology are private
operational records, not public product documentation.
