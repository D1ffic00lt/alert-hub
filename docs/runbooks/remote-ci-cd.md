# Remote CI and production CD

Trusted same-repository checks, CodeQL, release builds and preview builds run on
the repository-scoped `ru3-ci-alert-hub` listener inside the existing isolated CI
VM. Its shared job hook serializes workloads with the other projects; no build
runs on the production host. The VM retains its existing CPU, memory, disk and
network ceilings. Fork PRs select `ubuntu-24.04` through the exact selector
validated by `check-ci-policy.py`. All external-contributor Actions runs require
operator approval; review workflow changes before approving a fork run.

The separate `ru3-cd-alert-hub` listener runs on the existing CD host, in the
aggregate CD resource slice. Its compatibility labels `alert-hub-ru`,
`alert-hub-nl` and `alert-hub-de` keep protected environments, ordered rollout,
manual release selection and independent component deployment unchanged. Old
node listeners must be idle and disabled before the compatibility labels are
activated on the new listener. Keep registrations repository-scoped.

The CD account has no Docker membership or general sudo. Four no-argument,
root-installed transport wrappers preserve only the existing deployment variable
allowlist. They hold the platform deployment lock, transmit bounded JSON through
SSH stdin, and execute the corresponding existing root-owned wrapper on the
selected node. Deployment secrets never appear in SSH arguments, source,
transport logs or saved requests. SSH identities stay root-only on the CD host.
The runner workspace is not a source for privileged code or configuration.

Every production node has a root-installed `alert-hub-remote-receiver` forced
command and `/etc/alert-hub/remote-control.json`. The receiver checks the exact
repository, node, operation and environment before invoking its fixed local
deploy, preview, rollback or status boundary. Existing backup, migration,
immutable-image, topology and rollback checks remain node-local. Preview is
enabled only on the configured preview node. No application deployment port is
opened, and the ordinary public proxies are unchanged.

Host addresses, pinned host keys and the SSH configuration live outside Git in
`/etc/ru3-cd/alert-hub`. Where direct management transport is unavailable, an
operator can configure a forced-command relay to fixed SSH destinations on a
reachable node. The relay accepts no arbitrary host, port or shell command.
Use separate restricted keys and source filtering; never copy an operator key.

The operator installs `deploy/scripts/ci-remote-node.py` from a reviewed revision
under the four existing wrapper names on the CD host and under
`alert-hub-remote-receiver` on production nodes. All files and parent directories
must be root-controlled. Validate the sudoers candidate with `visudo`, validate
Python syntax, check the systemd unit and verify pinned host keys before
enabling the listener. Snapshot the existing listener/service identities and
node wrapper hashes before installation. Keep the installation audit private.

The manual **Deployment runner status** workflow verifies all three protected
node boundaries without deploying an application release. Acceptance also
requires a real trusted CI run on the VM and checks that arbitrary sudo commands,
wrapper arguments, environment injection and arbitrary SSH commands are rejected.
Do not call a queued job successful or substitute a local unit test for the
actual runner/protected-environment checks.

CI browser system dependencies are provisioned by the operator in the VM;
workflow jobs download Chromium without package-manager privileges. The backup
and restore gate runs as root inside a disposable Docker container, preserving
its ownership checks without granting repository code general sudo in the VM.

To roll back runner placement, first wait for all active jobs to finish, disable
the new listeners, and restore the reviewed workflow revision and old listener
registrations/labels. Restore only transport configuration from its private
installation audit. Do not restore application databases or restart application
containers merely to move a runner.
