#!/bin/sh
set -eu

ui_runtime_dir=${1:-/run/alert-hub/ui}
runtime_tmp=""
manifest_tmp=""
guard_tmp=""

cleanup() {
  status=$?
  trap - 0 TERM INT
  [ -z "${runtime_tmp}" ] || rm -f -- "${runtime_tmp}"
  [ -z "${manifest_tmp}" ] || rm -f -- "${manifest_tmp}"
  [ -z "${guard_tmp}" ] || rm -f -- "${guard_tmp}"
  exit "${status}"
}
trap cleanup 0
trap 'exit 143' TERM
trap 'exit 130' INT

# Convert an arbitrary environment string to an ASCII-only JSON string. The
# decoder preserves valid UTF-8 as JSON Unicode escapes, replaces invalid UTF-8
# with U+FFFD, collapses Unicode whitespace, and limits by Unicode code points.
# NUL cannot occur in an environment value; every other control character is
# treated as whitespace. This keeps APP_NAME data out of shell/JavaScript syntax.
json_app_name() {
  limit=$1
  printf '%s' "${APP_NAME:-}" | od -An -tu1 -v | awk -v limit="${limit}" '
    function is_continuation(value) {
      return value >= 128 && value <= 191
    }

    function is_space(codepoint) {
      return codepoint <= 32 || codepoint == 127 || codepoint == 133 || \
        codepoint == 160 || codepoint == 5760 || \
        (codepoint >= 8192 && codepoint <= 8202) || \
        codepoint == 8232 || codepoint == 8233 || codepoint == 8239 || \
        codepoint == 8287 || codepoint == 12288
    }

    function append_codepoint(codepoint) {
      if (is_space(codepoint)) {
        if (count > 0) pending_space = 1
        return
      }
      if (pending_space && count < limit) {
        values[++count] = 32
        pending_space = 0
      }
      if (count < limit) values[++count] = codepoint
    }

    function append_default() {
      values[++count] = 65
      values[++count] = 108
      values[++count] = 101
      values[++count] = 114
      values[++count] = 116
      values[++count] = 32
      values[++count] = 72
      values[++count] = 117
      values[++count] = 98
    }

    function emit_json(codepoint, high, low) {
      if (codepoint == 34) return "\\\""
      if (codepoint == 92) return "\\\\"
      if (codepoint == 60) return "\\u003c"
      if (codepoint >= 32 && codepoint <= 126) return sprintf("%c", codepoint)
      if (codepoint <= 65535) return sprintf("\\u%04x", codepoint)
      codepoint -= 65536
      high = 55296 + int(codepoint / 1024)
      low = 56320 + (codepoint % 1024)
      return sprintf("\\u%04x\\u%04x", high, low)
    }

    {
      for (field = 1; field <= NF; field++) bytes[++byte_count] = $field + 0
    }

    END {
      cursor = 1
      while (cursor <= byte_count && count < limit) {
        first = bytes[cursor]
        consumed = 1
        codepoint = 65533

        if (first <= 127) {
          codepoint = first
        } else if (first >= 194 && first <= 223 && cursor + 1 <= byte_count && \
                   is_continuation(bytes[cursor + 1])) {
          codepoint = (first - 192) * 64 + (bytes[cursor + 1] - 128)
          consumed = 2
        } else if (first >= 224 && first <= 239 && cursor + 2 <= byte_count && \
                   is_continuation(bytes[cursor + 1]) && \
                   is_continuation(bytes[cursor + 2]) && \
                   !(first == 224 && bytes[cursor + 1] < 160) && \
                   !(first == 237 && bytes[cursor + 1] > 159)) {
          codepoint = (first - 224) * 4096 + \
            (bytes[cursor + 1] - 128) * 64 + (bytes[cursor + 2] - 128)
          consumed = 3
        } else if (first >= 240 && first <= 244 && cursor + 3 <= byte_count && \
                   is_continuation(bytes[cursor + 1]) && \
                   is_continuation(bytes[cursor + 2]) && \
                   is_continuation(bytes[cursor + 3]) && \
                   !(first == 240 && bytes[cursor + 1] < 144) && \
                   !(first == 244 && bytes[cursor + 1] > 143)) {
          codepoint = (first - 240) * 262144 + \
            (bytes[cursor + 1] - 128) * 4096 + \
            (bytes[cursor + 2] - 128) * 64 + (bytes[cursor + 3] - 128)
          consumed = 4
        }

        append_codepoint(codepoint)
        cursor += consumed
      }

      if (count == 0) append_default()
      printf "\""
      for (cursor = 1; cursor <= count; cursor++) printf "%s", emit_json(values[cursor])
      printf "\""
    }
  '
}

normalize_https_origin() {
  label=$1
  value=$2
  [ -n "${value}" ] || return 0
  printf '%s\n' "${value}" | awk -v label="${label}" '
    {
      candidate = $0
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
      if (candidate !~ /^https:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?\/?$/ || \
          candidate ~ /\.(:[0-9]+)?\/?$/ || candidate ~ /\.\./) {
        printf "%s must contain an exact public HTTPS origin\n", label > "/dev/stderr"
        exit 1
      }
      sub(/\/$/, "", candidate)
      port = candidate
      sub(/^.*:/, "", port)
      if (candidate ~ /:[0-9]+$/ && (port + 0 < 1 || port + 0 > 65535)) {
        printf "%s contains an invalid port\n", label > "/dev/stderr"
        exit 1
      }
      print candidate
    }
  '
}

json_https_origins() {
  printf '%s\n' "$1" | awk '
    BEGIN { printf "["; count = 0 }
    {
      total = split($0, values, ",")
      for (item_index = 1; item_index <= total; item_index++) {
        candidate = values[item_index]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
        if (!candidate) continue
        if (candidate !~ /^https:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?$/ || \
            candidate ~ /\.(:[0-9]+)?$/ || candidate ~ /\.\./) {
          print "PUBLIC_API_CANDIDATES must contain only exact public HTTPS origins" > "/dev/stderr"
          exit 1
        }
        port = candidate
        sub(/^.*:/, "", port)
        if (candidate ~ /:[0-9]+$/ && (port + 0 < 1 || port + 0 > 65535)) {
          print "PUBLIC_API_CANDIDATES contains an invalid port" > "/dev/stderr"
          exit 1
        }
        if (seen[candidate]++) {
          print "PUBLIC_API_CANDIDATES must contain unique origins" > "/dev/stderr"
          failed = 1
          exit 1
        }
        if (++count > 8) {
          print "PUBLIC_API_CANDIDATES must contain at most 8 origins" > "/dev/stderr"
          failed = 1
          exit 1
        }
        separator = count > 1 ? "," : ""
        printf "%s\"%s\"", separator, candidate
      }
    }
    END { if (!failed) printf "]" }
  '
}

umask 077
mkdir -p "${ui_runtime_dir}"
app_name_json=$(json_app_name 80)
short_name_json=$(json_app_name 24)
api_ha_mode=${API_HA_MODE:-single}
case "${api_ha_mode}" in
  single | client-failover | proxy-failover | external) ;;
  *)
    printf '%s\n' 'API_HA_MODE must be single, client-failover, proxy-failover, or external' >&2
    exit 1
    ;;
esac
node_public_api_url=$(normalize_https_origin NODE_PUBLIC_API_URL "${NODE_PUBLIC_API_URL:-}")
candidate_input=${PUBLIC_API_CANDIDATES:-}
public_api_candidates_json=$(json_https_origins "${candidate_input}")
if [ "${api_ha_mode}" = client-failover ] && [ -z "${node_public_api_url}" ] && [ "${public_api_candidates_json}" = '[]' ]; then
  printf '%s\n' 'client-failover requires NODE_PUBLIC_API_URL or PUBLIC_API_CANDIDATES' >&2
  exit 1
fi
if [ -n "${node_public_api_url}" ]; then
  node_public_api_json=\"${node_public_api_url}\"
else
  node_public_api_json=null
fi
runtime_tmp=$(mktemp "${ui_runtime_dir}/.runtime-config.js.XXXXXX")
manifest_tmp=$(mktemp "${ui_runtime_dir}/.manifest.webmanifest.XXXXXX")
guard_tmp=$(mktemp "${ui_runtime_dir}/.shell-guard.conf.XXXXXX")

printf '%s%s%s%s%s%s%s%s%s%s\n' \
  'Object.defineProperty(globalThis,"__ALERT_HUB_CONFIG__",{value:Object.freeze({"appName":' \
  "${app_name_json}" \
  ',"apiHaMode":"' "${api_ha_mode}" \
  '","nodePublicApiUrl":' "${node_public_api_json}" \
  ',"publicApiCandidates":Object.freeze(' "${public_api_candidates_json}" ')' \
  '}),writable:false,configurable:false});' \
  >"${runtime_tmp}"

case "${api_ha_mode}" in
  client-failover | proxy-failover)
    printf '%s\n' '# API-independent shell enabled by API_HA_MODE.' >"${guard_tmp}"
    ;;
  *)
    printf '%s\n' \
      'auth_request /_api_ready;' \
      'error_page 500 502 503 504 =503 /service-unavailable.html;' \
      >"${guard_tmp}"
    ;;
esac

printf '%s%s%s%s%s\n' \
  '{"id":"/","name":' "${app_name_json}" ',"short_name":' "${short_name_json}" \
  ',"description":"Распределённый мониторинг инцидентов и отказоустойчивая доставка оповещений.","start_url":"/","scope":"/","display":"standalone","display_override":["window-controls-overlay","standalone","minimal-ui"],"orientation":"any","background_color":"#0A0A0B","theme_color":"#0A0A0B","categories":["productivity","utilities"],"icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png","purpose":"any"},{"src":"/icon-512.png","sizes":"512x512","type":"image/png","purpose":"maskable"}],"shortcuts":[{"name":"Активные инциденты","short_name":"Инциденты","description":"Открыть список активных инцидентов","url":"/incidents"},{"name":"Состояние кластера","short_name":"Кластер","description":"Проверить синхронизацию узлов","url":"/cluster"}]}' \
  >"${manifest_tmp}"

chmod 0444 "${runtime_tmp}" "${manifest_tmp}" "${guard_tmp}"
mv -f "${runtime_tmp}" "${ui_runtime_dir}/runtime-config.js"
runtime_tmp=""
mv -f "${manifest_tmp}" "${ui_runtime_dir}/manifest.webmanifest"
manifest_tmp=""
mv -f "${guard_tmp}" "${ui_runtime_dir}/shell-guard.conf"
guard_tmp=""
