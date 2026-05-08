#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <log-dir> <cargo-output-log> [<cargo-output-log>...]" >&2
  exit 1
fi

log_dir="$1"
shift
output_dir="${log_dir}/failed-test-logs"
logs=()

for log in "$@"; do
  if [[ -f "${log}" ]]; then
    logs+=("${log}")
  else
    echo "Log file not found, skipping: ${log}"
  fi
done

rm -rf "${output_dir}"
mkdir -p "${output_dir}"
printf "test\tstatus\tpath\n" > "${output_dir}/manifest.tsv"

if [[ ${#logs[@]} -eq 0 ]]; then
  echo "No cargo output logs found."
  exit 0
fi

failed_tests="$(
  awk '
    /^test .* \.\.\. FAILED$/ {
      sub(/^test /, "")
      sub(/ \.\.\. FAILED$/, "")
      print
    }
    /^---- .* stdout ----$/ {
      sub(/^---- /, "")
      sub(/ stdout ----$/, "")
      print
    }
  ' "${logs[@]}" | sort -u
)"

if [[ -z "${failed_tests}" ]]; then
  echo "No failed tests found in cargo output."
  exit 0
fi

find_log_file() {
  local safe_name="$1"
  find "${log_dir}" -maxdepth 2 -path "*/${safe_name}.log" -print -quit
}

while IFS= read -r test_name; do
  safe_name="$(printf "%s" "${test_name}" | sed -E 's/[^A-Za-z0-9_-]/_/g' | cut -c1-180)"
  source_file="$(find_log_file "${safe_name}")"

  if [[ -z "${source_file}" ]]; then
    printf "%s\tmissing\t%s.log\n" "${test_name}" "${safe_name}" >> "${output_dir}/manifest.tsv"
    continue
  fi

  cp "${source_file}" "${output_dir}/${safe_name}.log"
  printf "%s\tcopied\t%s.log\n" "${test_name}" "${safe_name}" >> "${output_dir}/manifest.tsv"
done <<< "${failed_tests}"
