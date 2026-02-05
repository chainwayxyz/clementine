#!/usr/bin/env bash
set -euo pipefail

# Dumps the dbs that failed test into the specified output directory.
# Locally, use a command like this to import the db (it will overwrite your own dbs with same name):
# PGPASSWORD=clementine psql -h localhost -p 5432 -U clementine -f db_dump_operator_transfer_to_btc_wallet.sql 


if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <output-dir> <log-file> [<log-file>...]" >&2
  exit 1
fi

output_dir="$1"
shift

mkdir -p "${output_dir}"

failed_tests=$(cat "$@" 2>/dev/null \
  | grep -E "^test .* \.\.\. FAILED" \
  | sed -E 's/^test (.*) \.\.\. FAILED/\1/' \
  | awk -F'::' '{print $NF}' \
  | sort -u)

if [[ -z "${failed_tests}" ]]; then
  echo "No failed tests found in logs."
  exit 0
fi

for test_name in ${failed_tests}; do
  echo "Collecting DBs for test: ${test_name}"
  dbs=$(docker run --rm --network host -e PGPASSWORD=clementine postgres:latest \
    psql -h localhost -p 5432 -U clementine -d postgres -At \
    -c "select datname from pg_database where datname like '%${test_name}%';" || true)

  if [[ -z "${dbs}" ]]; then
    echo "No DBs found for test: ${test_name}"
    continue
  fi

  for db in ${dbs}; do
    echo "Dumping DB: ${db}"
    docker run --rm --network host -e PGPASSWORD=clementine postgres:latest \
      pg_dump -h localhost -p 5432 -U clementine -d "${db}" --clean --if-exists -C \
      >> "${output_dir}/db_dump_${test_name}.sql"
  done
done
