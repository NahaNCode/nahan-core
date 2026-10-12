# Security Policy

Report vulnerabilities privately to **nahancode@gmail.com** with the affected
commit and a minimal reproduction using synthetic credentials. No response-time
or long-term support guarantee is offered for this experimental release.

Do not post keys, bearer tokens, real subscription links, server inventories or
customer exports in public issues. Never commit `runtime/` or production secrets.
Use verified TLS and owner-only regular secret files. GRE is not encrypted.
Temporary SS tests use independent credentials, expire after one hour and are
revoked on engine restart. They do not open firewalls or create tunnels.
