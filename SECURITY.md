# Security policy

Alert Hub has not published its first supported release yet. Until a versioned release is
available, security fixes are made on `main` and no compatibility or response-time SLA is
promised.

Please do not disclose a suspected vulnerability in a public issue. Use GitHub's private
vulnerability reporting for this repository when it is enabled, or contact the repository owner
privately and include:

- the affected commit or version;
- the trust boundary and required attacker access;
- minimal reproduction steps without real credentials or infrastructure addresses;
- the expected impact and any safe workaround.

Never attach live source tokens, cookies, provider credentials, VAPID keys, cluster secrets,
database files, or unredacted incident payloads. The project threat model and operator response
procedure are documented in [docs/security.md](docs/security.md).
