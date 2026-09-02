#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "${repo_root}"

patterns='-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{20,}'

set +e
matches=$(git grep --untracked --exclude-standard -nI -E -e "${patterns}" -- \
  ':!package-lock.json' \
  ':!deploy/scripts/check-no-secrets.sh' \
  ':!docs/security.md')
grep_status=$?
set -e

if ((grep_status > 1)); then
  printf 'Secret scan failed before producing a trustworthy result (git grep exit %s).\n' "${grep_status}" >&2
  exit "${grep_status}"
fi

if [[ -n ${matches} ]]; then
  printf 'Potential committed secret material detected:\n%s\n' "${matches}" >&2
  exit 1
fi

if git ls-files | grep -E '(^|/)(\.env|secrets?|.*\.(pem|key|p12|pfx|sqlite|db))$' | grep -vE '\.example$'; then
  printf 'A secret- or data-shaped file is tracked. Use an .example file instead.\n' >&2
  exit 1
fi

printf 'No known secret patterns or secret-shaped tracked files found.\n'
