#!/usr/bin/env bash
# check-release-assets verifies dist/artifacts.json, the list GoReleaser itself writes of
# what it will upload (https://goreleaser.com/customization/general/artifacts/), against
# the exact asset names the README and docs/setup.md tell users to download, then runs
# `sha256sum -c` on each checksum file against the real published artifact, the same
# command a user runs. Earlier this checked dist/wgft-<os>-<arch> and dist/*.sha256
# directly, but those are copies scripts/goreleaser-checksum.sh writes itself; a rename of
# archives.name_template in .goreleaser.yaml would leave those copies (and this check)
# green while the names GoReleaser actually publishes, and the README download URLs,
# broke. Reading artifacts.json checks what GoReleaser publishes, not the hook's copies.
# This is also what would have caught #22's mismatch: scripts/goreleaser-checksum.sh wrote
# wgft-windows-amd64.sha256 for an asset actually published as wgft-windows-amd64.exe.
#
#   scripts/check-release-assets.sh [dist-dir]
#
# Must run from the repository root: the "path" fields in artifacts.json are relative to
# it (this is how CI invokes it, and how a local `goreleaser release --snapshot` leaves
# them too).
#
# The expected_names list below is the single place to add a new OS/arch: keep it in sync
# with builds.goos/goarch/ignore and archives.name_template in .goreleaser.yaml. macOS
# (darwin) is published for arm64 only (darwin/amd64 is in builds.ignore), as
# wgft-darwin-arm64 with no extension.
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to read dist/artifacts.json (preinstalled on ubuntu-latest runners)" >&2
  exit 1
fi

dist=${1:-dist}
artifacts_json="$dist/artifacts.json"

if [ ! -f "$artifacts_json" ]; then
  echo "missing $artifacts_json (did goreleaser run?)" >&2
  exit 1
fi

expected_names=(
  "wgft-linux-amd64"
  "wgft-linux-arm64"
  "wgft-darwin-arm64"
  "wgft-windows-amd64.exe"
)

# The archives pipe's `formats: [binary]` entries are what GoReleaser uploads as release
# binaries (see internal/pipe/archive/archive.go: these get Type: artifact.UploadableBinary,
# which artifacts.json renders as the string "Binary", plus extra.Format: "binary"). The
# raw per-target build output is also typed "Binary" in artifacts.json but has no "Format"
# key in extra, so that field is what tells the two apart.
actual_names=$(jq -r '
  [.[] | select(.type == "Binary" and .extra.Format == "binary")] | sort_by(.name) | .[].name
' "$artifacts_json")
expected_sorted=$(printf '%s\n' "${expected_names[@]}" | sort)

if [ "$actual_names" != "$expected_sorted" ]; then
  {
    echo "release binary artifacts in $artifacts_json do not match the expected names"
    echo "--- expected ---"
    echo "$expected_sorted"
    echo "--- actual ---"
    echo "$actual_names"
  } >&2
  exit 1
fi

status=0
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

for name in "${expected_names[@]}"; do
  sum="$dist/$name.sha256"
  if [ ! -f "$sum" ]; then
    echo "missing checksum file: $sum (release.extra_files uploads this alongside $name)" >&2
    status=1
    continue
  fi

  path=$(jq -r --arg name "$name" '
    [.[] | select(.type == "Binary" and .extra.Format == "binary" and .name == $name)] | .[0].path // empty
  ' "$artifacts_json")
  if [ -z "$path" ] || [ ! -f "$path" ]; then
    echo "artifact path for $name not found in $artifacts_json (path=$path)" >&2
    status=1
    continue
  fi

  # Verify the checksum against the real published artifact (from its artifacts.json
  # path), not scripts/goreleaser-checksum.sh's dist/ copy, in its own directory named
  # after the published asset; this also catches the .sha256 naming the wrong file, since
  # sha256sum -c looks the name up relative to its own directory.
  verify_dir="$tmpdir/$name"
  mkdir -p "$verify_dir"
  cp "$path" "$verify_dir/$name"
  cp "$sum" "$verify_dir/$name.sha256"
  if ! ( cd "$verify_dir" && sha256sum -c "$name.sha256" ); then
    echo "checksum verification failed for $name (artifact at $path)" >&2
    status=1
    continue
  fi
  echo "OK: $name matches $sum ($path)"
done

exit "$status"
