#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: install-proxy-config.sh nginx|caddy TEMPLATE DESTINATION \
  --server-name NAME --upstream HOST:PORT --trusted-proxy CIDR \
  [--validate-config CADDYFILE]

The destination must be absent or contain the marker "Managed by Alert Hub".
Unknown active configuration is never overwritten.
EOF
  exit 2
}

restore_destination() {
  local destination=$1
  local backup=$2

  if [[ -n ${backup} ]]; then
    cp -a -- "${backup}" "${destination}"
  else
    rm -f -- "${destination}"
  fi
}

[[ ${EUID} -eq 0 ]] || die "run as root"
[[ $# -ge 3 ]] || usage

proxy=$1
template=$2
destination=$3
shift 3
server_name=""
upstream=""
trusted_proxy=""
validate_config="/etc/caddy/Caddyfile"

while (($#)); do
  case "$1" in
    --server-name) [[ $# -ge 2 ]] || usage; server_name=$2; shift 2 ;;
    --upstream) [[ $# -ge 2 ]] || usage; upstream=$2; shift 2 ;;
    --trusted-proxy) [[ $# -ge 2 ]] || usage; trusted_proxy=$2; shift 2 ;;
    --validate-config) [[ $# -ge 2 ]] || usage; validate_config=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ ${proxy} == nginx || ${proxy} == caddy ]] || die "proxy must be nginx or caddy"
[[ -f ${template} && ! -L ${template} ]] || die "template is not a regular file"
[[ ${destination} == /* && ${destination} != / ]] || die "destination must be a specific absolute path"
[[ ${server_name} =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid server name"
[[ ${upstream} =~ ^(127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$ ]] || die "upstream must be loopback HOST:PORT"
[[ ${trusted_proxy} =~ ^[0-9A-Fa-f:.]+/[0-9]{1,3}$ ]] || die "invalid trusted proxy CIDR"

if [[ -e ${destination} ]] && ! grep -Fq 'Managed by Alert Hub' "${destination}"; then
  die "refusing to overwrite an unmanaged destination: ${destination}"
fi

validator_path=""
if ! validator_path=$(command -v "${proxy}"); then
  die "${proxy} is not installed"
fi
[[ ${validator_path} == /* && -x ${validator_path} ]] || die "${proxy} is not installed"

destination_dir=$(dirname -- "${destination}")
install -d -m 0755 "${destination_dir}"
candidate=$(mktemp "${destination_dir}/.alert-hub-proxy.XXXXXX")
backup=""

cleanup() {
  rm -f -- "${candidate}"
}
trap cleanup EXIT

{
  printf '# Managed by Alert Hub; generated from %s\n' "$(basename -- "${template}")"
  sed \
    -e "s|__SERVER_NAME__|${server_name}|g" \
    -e "s|__UPSTREAM__|${upstream}|g" \
    -e "s|__TRUSTED_PROXY_CIDR__|${trusted_proxy}|g" \
    "${template}"
} >"${candidate}"
chmod 0644 "${candidate}"

if grep -Eq '__[A-Z0-9_]+__' "${candidate}"; then
  die "unresolved placeholder remains in generated configuration"
fi

if [[ -e ${destination} ]]; then
  backup="${destination}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a -- "${destination}" "${backup}"
fi
install -o root -g root -m 0644 "${candidate}" "${destination}"

if [[ ${proxy} == nginx ]]; then
  validation_arguments=(-t)
else
  validation_arguments=(validate --config "${validate_config}")
fi

if ! "${validator_path}" "${validation_arguments[@]}"; then
  restore_destination "${destination}" "${backup}"
  die "proxy validation failed; original configuration restored"
fi

printf 'Installed and validated %s. Reload the proxy explicitly after review.\n' "${destination}"
