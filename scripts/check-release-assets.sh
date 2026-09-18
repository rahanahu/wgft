#!/usr/bin/env bash
# check-release-assets verifies a GoReleaser dist/ directory against the exact set of
# binaries and checksum files the README and docs/setup.md tell users to download, and
# then runs `sha256sum -c` on each checksum file, the same command a user runs. This is
# what would have caught #22's mismatch: scripts/goreleaser-checksum.sh wrote
# wgft-windows-amd64.sha256 for an asset actually published as wgft-windows-amd64.exe.
#
#   scripts/check-release-assets.sh [dist-dir]
#
# The targets list below is the single place to add a new OS/arch: keep it in sync with
# builds.goos/goarch/ignore in .goreleaser.yaml. macOS (darwin) support is planned; add its
# "os arch" line here (with an empty ext, same as linux) once .goreleaser.yaml builds it.
set -euo pipefail

dist=${1:-dist}

# "<os> <arch> [ext]", one line per released target. ext is empty except on Windows,
# where GoReleaser keeps the .exe suffix on the published binary name.
targets=(
  "linux amd64"
  "linux arm64"
  "windows amd64 .exe"
)

status=0
for t in "${targets[@]}"; do
  read -r os arch ext <<<"$t"
  name="wgft-$os-$arch${ext:-}"
  bin="$dist/$name"
  sum="$dist/$name.sha256"

  if [ ! -f "$bin" ]; then
    echo "missing release asset: $bin" >&2
    status=1
    continue
  fi
  if [ ! -f "$sum" ]; then
    echo "missing checksum file: $sum" >&2
    status=1
    continue
  fi
  if ! ( cd "$dist" && sha256sum -c "$name.sha256" ); then
    echo "checksum verification failed for $name" >&2
    status=1
  fi
done

exit "$status"
