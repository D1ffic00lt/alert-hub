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
  --server-name NAME --upstream HOST:PORT \
  [--trusted-proxy CIDR] [--peer-cidr IPV4/32 ...] \
  [--tls-certificate FILE --tls-private-key FILE] \
  [--validate-config CADDYFILE] [--caddy-container NAME]

Options are required only when the selected template contains their matching
placeholder. --peer-cidr may be repeated and accepts exact IPv4 /32 entries.
An upstream is loopback, one literal RFC1918 address, or one DNS-safe container
service name. Public IP upstreams are rejected.

Use --caddy-container only when Caddy runs in Docker and DESTINATION is mounted
into that container's configuration. Validation then runs inside the named
running container; --validate-config is the path visible inside it.

The destination must be absent or contain the marker "Managed by Alert Hub".
Unknown active configuration is never overwritten.
EOF
  exit 2
}

valid_dns_name() {
  local name=$1
  local label
  local -a labels

  [[ ${#name} -le 253 && ${name} != .* && ${name} != *. && ${name} != *..* ]] || return 1
  IFS=. read -r -a labels <<<"${name}"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ ${label} =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}

valid_port() {
  local port=$1

  [[ ${port} =~ ^[0-9]{1,5}$ ]] || return 1
  ((10#${port} >= 1 && 10#${port} <= 65535))
}

valid_ipv4() {
  local value=$1
  local octet
  local -a octets

  IFS=. read -r -a octets <<<"${value}"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ ${octet} =~ ^[0-9]{1,3}$ ]] || return 1
    [[ ${octet} == 0 || ${octet} != 0* ]] || return 1
    ((10#${octet} <= 255)) || return 1
  done
}

valid_private_ipv4() {
  local value=$1
  local -a octets

  valid_ipv4 "${value}" || return 1
  IFS=. read -r -a octets <<<"${value}"
  ((
    10#${octets[0]} == 10 ||
      (10#${octets[0]} == 172 && 10#${octets[1]} >= 16 && 10#${octets[1]} <= 31) ||
      (10#${octets[0]} == 192 && 10#${octets[1]} == 168)
  ))
}

valid_upstream() {
  local value=$1
  local host=${value%:*}
  local port=${value##*:}

  [[ ${host} != "${value}" ]] || return 1
  valid_port "${port}" || return 1
  [[ ${host} == "127.0.0.1" || ${host} == "[::1]" ]] && return 0
  valid_private_ipv4 "${host}" && return 0

  # A named non-loopback upstream is intentionally limited to Docker DNS, not
  # an arbitrary Internet hostname.
  [[ ${host} != *.* ]] && valid_dns_name "${host}"
}

valid_ipv4_32() {
  local value=$1
  local address

  [[ ${value} == */32 ]] || return 1
  address=${value%/32}
  valid_ipv4 "${address}"
}

valid_absolute_path() {
  [[ $1 =~ ^/[A-Za-z0-9._/-]+$ && $1 != / ]]
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
peer_cidrs=()
tls_certificate=""
tls_private_key=""
validate_config="/etc/caddy/Caddyfile"
caddy_container=""

while (($#)); do
  case "$1" in
    --server-name) [[ $# -ge 2 ]] || usage; server_name=$2; shift 2 ;;
    --upstream) [[ $# -ge 2 ]] || usage; upstream=$2; shift 2 ;;
    --trusted-proxy) [[ $# -ge 2 ]] || usage; trusted_proxy=$2; shift 2 ;;
    --peer-cidr) [[ $# -ge 2 ]] || usage; peer_cidrs+=("$2"); shift 2 ;;
    --tls-certificate) [[ $# -ge 2 ]] || usage; tls_certificate=$2; shift 2 ;;
    --tls-private-key) [[ $# -ge 2 ]] || usage; tls_private_key=$2; shift 2 ;;
    --validate-config) [[ $# -ge 2 ]] || usage; validate_config=$2; shift 2 ;;
    --caddy-container) [[ $# -ge 2 ]] || usage; caddy_container=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ ${proxy} == nginx || ${proxy} == caddy ]] || die "proxy must be nginx or caddy"
[[ -f ${template} && ! -L ${template} ]] || die "template is not a regular file"
[[ ${destination} == /* && ${destination} != / ]] || die "destination must be a specific absolute path"
valid_dns_name "${server_name}" || die "invalid server name"
valid_upstream "${upstream}" ||
  die "upstream must be loopback, literal RFC1918, or a container service HOST:PORT"
valid_absolute_path "${validate_config}" || die "validate config must be a specific absolute path"

if grep -Fq '__TRUSTED_PROXY_CIDR__' "${template}"; then
  [[ ${trusted_proxy} =~ ^[0-9A-Fa-f:.]+/[0-9]{1,3}$ ]] || die "invalid trusted proxy CIDR"
elif [[ -n ${trusted_proxy} ]]; then
  die "template does not accept --trusted-proxy"
fi

peer_template=false
if grep -Eq '__PEER_(CIDRS|NGINX_ALLOW)__' "${template}"; then
  peer_template=true
  ((${#peer_cidrs[@]} > 0)) || die "peer template requires at least one --peer-cidr"
  for peer_cidr in "${peer_cidrs[@]}"; do
    valid_ipv4_32 "${peer_cidr}" || die "peer CIDR must be an exact IPv4 /32"
  done
else
  ((${#peer_cidrs[@]} == 0)) || die "template does not accept --peer-cidr"
fi

if grep -Eq '__TLS_(CERTIFICATE|PRIVATE_KEY)__' "${template}"; then
  valid_absolute_path "${tls_certificate}" || die "invalid TLS certificate path"
  valid_absolute_path "${tls_private_key}" || die "invalid TLS private-key path"
elif [[ -n ${tls_certificate} || -n ${tls_private_key} ]]; then
  die "template does not accept TLS certificate paths"
fi

if [[ -n ${caddy_container} ]]; then
  [[ ${proxy} == caddy ]] || die "--caddy-container requires the caddy proxy type"
  [[ ${caddy_container} =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "invalid Caddy container name"
fi

if [[ -e ${destination} ]] && ! grep -Fq 'Managed by Alert Hub' "${destination}"; then
  die "refusing to overwrite an unmanaged destination: ${destination}"
fi

validator_path=""
if [[ -n ${caddy_container} ]]; then
  if ! validator_path=$(command -v docker); then
    die "docker is not installed"
  fi
  [[ ${validator_path} == /* && -x ${validator_path} ]] || die "docker is not installed"
  [[ $("${validator_path}" inspect --format '{{.State.Running}}' "${caddy_container}" 2>/dev/null) == true ]] ||
    die "Caddy container is not running"
else
  if ! validator_path=$(command -v "${proxy}"); then
    die "${proxy} is not installed"
  fi
  [[ ${validator_path} == /* && -x ${validator_path} ]] || die "${proxy} is not installed"
fi

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
  peer_caddy_cidrs=""
  if [[ ${peer_template} == true ]]; then
    peer_caddy_cidrs=$(IFS=' '; printf '%s' "${peer_cidrs[*]}")
  fi
  while IFS= read -r line || [[ -n ${line} ]]; do
    if [[ ${line} =~ ^([[:space:]]*)__PEER_NGINX_ALLOW__[[:space:]]*$ ]]; then
      for peer_cidr in "${peer_cidrs[@]}"; do
        printf '%sallow %s;\n' "${BASH_REMATCH[1]}" "${peer_cidr}"
      done
    else
      printf '%s\n' "${line}"
    fi
  done < <(
    sed \
      -e "s|__SERVER_NAME__|${server_name}|g" \
      -e "s|__UPSTREAM__|${upstream}|g" \
      -e "s|__TRUSTED_PROXY_CIDR__|${trusted_proxy}|g" \
      -e "s|__PEER_CIDRS__|${peer_caddy_cidrs}|g" \
      -e "s|__TLS_CERTIFICATE__|${tls_certificate}|g" \
      -e "s|__TLS_PRIVATE_KEY__|${tls_private_key}|g" \
      "${template}"
  )
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

if [[ -n ${caddy_container} ]]; then
  validation_arguments=(exec "${caddy_container}" caddy validate --config "${validate_config}")
elif [[ ${proxy} == nginx ]]; then
  validation_arguments=(-t)
else
  validation_arguments=(validate --config "${validate_config}")
fi

if ! "${validator_path}" "${validation_arguments[@]}"; then
  restore_destination "${destination}" "${backup}"
  die "proxy validation failed; original configuration restored"
fi

printf 'Installed and validated %s. Reload the proxy explicitly after review.\n' "${destination}"
