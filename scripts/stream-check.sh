#!/bin/zsh

set -euo pipefail

DATA_DIR="${1:-.supply-stream-data}"
LOG_DIR="${DATA_DIR}/logs"
OUTPUT_FILE="${LOG_DIR}/manual-stream-checks.ndjson"
CHECK_HOURS_VALUE="${CHECK_HOURS:-1 6 24}"
HOURS=(${=CHECK_HOURS_VALUE})

mkdir -p "${LOG_DIR}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

WINDOW_FILES=()

for hours in "${HOURS[@]}"; do
  window_file="${TMP_DIR}/${hours}.json"
  target/debug/supply-stream history --data-dir "${DATA_DIR}" report --since-hours "${hours}" --json \
    | jq --argjson window_hours "${hours}" '
        {
          window_hours: $window_hours,
          generated_at,
          since,
          until,
          events_scanned,
          unique_packages,
          capture_states,
          diff_states,
          assessments,
          active_assessments,
          suspicious_examples: (
            (.suspicious_examples // [])
            | map({
                event_id,
                ecosystem,
                package,
                version,
                severity,
                reason,
                bundle_path
              })
            | .[:10]
          ),
          cleaned_examples: (
            (.cleaned_examples // [])
            | map({
                event_id,
                ecosystem,
                package,
                version,
                severity,
                reason,
                cleaned_at,
                cleaned_by_event_id,
                cleaned_by_version
              })
            | .[:5]
          )
        }' > "${window_file}"
  WINDOW_FILES+=("${window_file}")
done

jq -s '.' "${WINDOW_FILES[@]}" > "${TMP_DIR}/windows.json"

if [[ -f "${LOG_DIR}/5min-summary.ndjson" ]]; then
  latest_summary="$(tail -n 1 "${LOG_DIR}/5min-summary.ndjson" 2>/dev/null || print -- 'null')"
else
  latest_summary='null'
fi

record="$(
  jq -n \
    --arg checked_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg data_dir "${DATA_DIR}" \
    --arg check_hours "${CHECK_HOURS_VALUE}" \
    --argjson latest_summary "${latest_summary}" \
    --slurpfile windows "${TMP_DIR}/windows.json" '
      {
        checked_at: $checked_at,
        data_dir: $data_dir,
        check_hours: $check_hours,
        latest_summary: $latest_summary,
        windows: (
          ($windows[0] // [])
          | map({
              key: ((.window_hours | tostring) + "h"),
              value: (del(.window_hours))
            })
          | from_entries
        )
      }'
)"

print -- "${record}" >> "${OUTPUT_FILE}"
print -- "${record}"
