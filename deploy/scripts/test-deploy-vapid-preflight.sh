#!/bin/bash
set -Eeuo pipefail

umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly SCRIPT_DIR
REPOSITORY_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)
readonly REPOSITORY_ROOT
readonly DEPLOY_SCRIPT=${REPOSITORY_ROOT}/.github/deploy/scripts/docker-deploy-node.sh

fail() {
  printf 'VAPID deploy preflight test failed: %s\n' "$1" >&2
  exit 1
}

for command_name in awk bash grep openssl sed tail tr; do
  command -v "${command_name}" >/dev/null || fail "required command is missing: ${command_name}"
done
[[ -f ${DEPLOY_SCRIPT} ]] || fail "deployment script is missing"

derive_expected_public_key() {
  printf '%s\n' "$1" |
    openssl pkey -passin pass: -pubout 2>/dev/null |
    openssl ec \
      -pubin \
      -conv_form uncompressed \
      -param_enc named_curve \
      -outform DER 2>/dev/null |
    tail -c 65 |
    openssl base64 -A 2>/dev/null |
    tr '+/' '-_' |
    tr -d '='
}

run_preflight() {
  local operation=$1
  local component=$2
  local private_key=$3
  local public_key=$4
  local -a bash_options=(-s)

  if [[ ${ALERT_HUB_TEST_XTRACE:-false} == true ]]; then
    bash_options=(-x -s)
  fi

  (
    export VAPID_PRIVATE_KEY=${private_key}
    export VAPID_PUBLIC_KEY=${public_key}
    {
      sed '/^\[\[ ${EUID} -eq 0 \]\]/,$d' "${DEPLOY_SCRIPT}"
      printf '%s\n' "preflight_vapid_material \"\$1\" \"\$2\""
    } | bash "${bash_options[@]}" -- "${operation}" "${component}"
  )
}

expect_success() {
  local description=$1
  local output
  shift

  if ! output=$(run_preflight "$@" 2>&1); then
    fail "${description} was rejected"
  fi
  [[ ${output} != *PRIVATE\ KEY* && ${output} != *EC\ PRIVATE* ]] ||
    fail "${description} exposed private material"
}

expect_failure() {
  local description=$1
  local expected_error=$2
  local private_key=$5
  local output
  shift 2

  if output=$(run_preflight "$@" 2>&1); then
    fail "${description} was accepted"
  fi
  [[ ${output} == *"${expected_error}"* ]] || fail "${description} returned an unexpected error"
  if [[ -n ${private_key} ]]; then
    [[ ${output} != *"${private_key}"* ]] || fail "${description} exposed private material"
  fi
}

p256_private=$(openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null)
p256_public=$(derive_expected_public_key "${p256_private}")
[[ ${p256_public} =~ ^B[A-Za-z0-9_-]{85}[AEIMQUYcgkosw048]$ ]] ||
  fail "test fixture public key is malformed"

second_p256_private=$(openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null)
second_p256_public=$(derive_expected_public_key "${second_p256_private}")
p384_private=$(openssl ecparam -name secp384r1 -genkey -noout 2>/dev/null)
rsa_private=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)
pkcs8_private=$(
  printf '%s\n' "${p256_private}" |
    openssl pkcs8 -topk8 -nocrypt 2>/dev/null
)
encrypted_private=$(
  printf '%s\n' "${p256_private}" |
    openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:test-only 2>/dev/null
)

expect_success "P-256 EC key without an explicit public key" deploy api "${p256_private}" ""
expect_success "matching canonical VAPID keypair" deploy all "${p256_private}" "${p256_public}"
expect_success "unencrypted PKCS#8 P-256 key" deploy api "${pkcs8_private}" ""
expect_success \
  "P-256 key with one trailing newline" \
  deploy api "${p256_private}"$'\n' "${p256_public}"
expect_success "web-only deploy without API secrets" deploy web "" ""
expect_success "rollback without workflow API secrets" rollback api "" ""

if ! xtrace_output=$(
  ALERT_HUB_TEST_XTRACE=true \
    run_preflight deploy api "${p256_private}" "${p256_public}" 2>&1
); then
  fail "xtrace-suppression preflight was rejected"
fi
[[ ${xtrace_output} != *PRIVATE\ KEY* && ${xtrace_output} != *"${p256_private}"* ]] ||
  fail "deployment script exposed private material when invoked with xtrace"

expect_failure \
  "missing private key" \
  "VAPID_PRIVATE_KEY is required for API deployment" \
  deploy api "" ""
expect_failure \
  "non-PEM private value" \
  "must be an unencrypted PEM EC private key on P-256" \
  deploy api "DO_NOT_LEAK_INVALID_VAPID_PRIVATE_KEY" ""
expect_failure \
  "encrypted P-256 private key" \
  "must be an unencrypted PEM EC private key on P-256" \
  deploy api "${encrypted_private}" ""
expect_failure \
  "RSA private key" \
  "must be an unencrypted PEM EC private key on P-256" \
  deploy api "${rsa_private}" ""
expect_failure \
  "P-384 private key" \
  "must be an unencrypted PEM EC private key on P-256" \
  deploy api "${p384_private}" ""
expect_failure \
  "mismatched public key" \
  "VAPID_PUBLIC_KEY does not match VAPID_PRIVATE_KEY" \
  deploy api "${p256_private}" "${second_p256_public}"
expect_failure \
  "padded public key" \
  "must be a canonical unpadded base64url P-256 public point" \
  deploy api "${p256_private}" "${p256_public}="
expect_failure \
  "malformed public key" \
  "must be a canonical unpadded base64url P-256 public point" \
  deploy api "${p256_private}" "not-a-p256-point"

preflight_line=$(
  grep -nF "preflight_vapid_material \"\${operation}\" \"\${COMPONENT}\"" "${DEPLOY_SCRIPT}" |
    tail -1 |
    awk -F: '{print $1}'
)
runtime_install_line=$(
  grep -nF "install -d -o root -g root -m 0700 \"\${CONFIG_DIR}\"" "${DEPLOY_SCRIPT}" |
    tail -1 |
    awk -F: '{print $1}'
)
[[ ${preflight_line} =~ ^[0-9]+$ && ${runtime_install_line} =~ ^[0-9]+$ ]] ||
  fail "could not locate deployment preflight ordering"
((preflight_line < runtime_install_line)) ||
  fail "VAPID validation must run before runtime directories are installed or changed"

printf 'VAPID deploy preflight tests passed.\n'
