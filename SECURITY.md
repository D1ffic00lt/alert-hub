# Security policy

Alert Hub publishes security fixes on `main` and, when applicable, in the latest
versioned release; `v0.1.0` is the first published release. No compatibility or
response-time SLA is promised during the `0.x` series.

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
