# Pull request

## What changed

<!-- Describe the operator- or user-visible outcome. -->

## Validation

- [ ] Backend format, lint, strict typing, tests, migrations, and OpenAPI contract pass.
- [ ] Frontend format, lint, typecheck, tests, and production build pass.
- [ ] Security/dependency/secret checks pass.
- [ ] Compose, backup/restore, and container smoke checks pass when applicable.
- [ ] New behavior has a regression test; distributed changes cover failure/retry behavior.

## Safety and operations

- [ ] No credentials, real infrastructure addresses, database files, or runtime artifacts are included.
- [ ] Schema changes are Alembic-managed, forward-only, and compatible with application version N-1.
- [ ] Public/peer/proxy boundaries remain explicit; no new service port is exposed.
- [ ] Documentation and runbooks reflect the implemented behavior and remaining acceptance work.

## External acceptance

<!-- Link evidence for any real multi-node, proxy, deployment rollback, or iPhone Web Push exercise. Automated substitutes must be labelled as such. -->
