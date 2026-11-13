#!/usr/bin/env bash
set -euo pipefail

# Promote a successful Citrea CI build into a private release asset readable by
# Clementine's repository-scoped GITHUB_TOKEN, then update the dependency lock.
# Run with a maintainer's gh login that can read Citrea and write Clementine.
run_id=${1:?Usage: pin-citrea-e2e.sh CITREA_WORKFLOW_RUN_ID [DOWNLOADED_ARTIFACT_DIR]}
[[ "$run_id" =~ ^[0-9]+$ ]]
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_repository=chainwayxyz/prv-citrea
repository=chainwayxyz/clementine-private
asset=citrea-sp1-linux-amd64.tar.gz
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

# These paired repositories are private; the promoted artifact stays private.
gh api "repos/$repository" --jq .private | grep -qx true
gh run view "$run_id" --repo "$source_repository" --json jobs,headSha > "$temporary/run.json"
jq -e '.jobs | any(.name == "build" and .conclusion == "success")' "$temporary/run.json" > /dev/null
if [[ -n "${2:-}" ]]; then
  cp -- "$2/$asset" "$2/$asset.sha256" "$temporary/"
else
  gh run download "$run_id" --repo "$source_repository" --name citrea-sp1-linux-amd64 --dir "$temporary"
fi
(
  cd -- "$temporary"
  sha256sum --check --strict "$asset.sha256"
)
source_commit=$(tar -xOzf "$temporary/$asset" ./SOURCE_COMMIT)
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]]
checksum=$(sha256sum "$temporary/$asset" | cut -d ' ' -f 1)
tag="citrea-e2e-$source_commit"
if gh release view "$tag" --repo "$repository" > /dev/null 2>&1; then
  mkdir "$temporary/existing"
  gh release download "$tag" --repo "$repository" --pattern "$asset" --dir "$temporary/existing"
  cmp "$temporary/$asset" "$temporary/existing/$asset"
else
  cat > "$temporary/notes.md" <<EOF
Native SP1 Citrea test dependency, built with \`--features testing\`.

Source: $source_repository at $source_commit
Build: https://github.com/$source_repository/actions/runs/$run_id
SHA-256: $checksum

Pinned by \`scripts/citrea-e2e.json\` for Clementine's paired e2e tests.
EOF
  gh release create "$tag" "$temporary/$asset" "$temporary/$asset.sha256" \
    --repo "$repository" --target "$(git -C "$script_dir" rev-parse HEAD)" \
    --prerelease --title "SP1 Citrea e2e dependency ($source_commit)" \
    --notes-file "$temporary/notes.md"
fi
jq -n --arg repository "$repository" --arg release_tag "$tag" \
  --arg asset "$asset" --arg sha256 "$checksum" \
  --arg source_repository "$source_repository" --arg source_commit "$source_commit" \
  --arg source_head "$(jq -r .headSha "$temporary/run.json")" \
  --argjson source_run_id "$run_id" \
  '{repository: $repository, release_tag: $release_tag, asset: $asset, sha256: $sha256,
    source_repository: $source_repository, source_commit: $source_commit,
    source_head: $source_head, source_run_id: $source_run_id}' > "$script_dir/citrea-e2e.json"
