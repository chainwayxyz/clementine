#!/usr/bin/env bash
set -euo pipefail

# Keep the paired node in this private repository so CI's own GITHUB_TOKEN can
# fetch it. Verify the pinned archive on cache hits as well as fresh downloads.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lock="$script_dir/citrea-e2e.json"
destination=${1:?Usage: install-citrea-e2e.sh DESTINATION}
mkdir -p "$destination"
destination=$(cd -- "$destination" && pwd)
repository=$(jq -er '.repository' "$lock")
tag=$(jq -er '.release_tag' "$lock")
asset=$(jq -er '.asset' "$lock")
checksum=$(jq -er '.sha256' "$lock")
source_commit=$(jq -er '.source_commit' "$lock")
[[ "$asset" == citrea-sp1-linux-amd64.tar.gz ]]
[[ "$checksum" =~ ^[0-9a-f]{64}$ ]]
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]]

if [[ ! -f "$destination/$asset" ]]; then
  gh release download "$tag" --repo "$repository" --pattern "$asset" --dir "$destination"
fi
(
  cd -- "$destination"
  printf '%s  %s\n' "$checksum" "$asset" | sha256sum --check --strict
  tar -xzf "$asset" ./citrea ./SOURCE_COMMIT ./RUST_VERSION
  test "$(cat SOURCE_COMMIT)" = "$source_commit"
  chmod +x citrea
  ./citrea --version
)
echo "Installed SP1 Citrea from $source_commit in $destination"
