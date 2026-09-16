#!/usr/bin/env bash
# third-party-licenses.sh writes THIRD_PARTY_LICENSES.txt: the license text of every Go module
# compiled into the wgft binary. GoReleaser attaches it to each release (before hook in
# .goreleaser.yaml) and deploy/Dockerfile.agent puts it into the image under /usr/share/doc/wgft/.
#
#   scripts/third-party-licenses.sh [build/THIRD_PARTY_LICENSES.txt]
#
# The default lives outside dist/ because GoReleaser runs before hooks and only then refuses a
# non-empty dist/ (even with --clean).
#
# The module list comes from `go list -deps ./cmd/wgft` (only what is linked, so test-only and
# tool-only dependencies are left out). A module that ships no license file in its module zip is
# taken from scripts/licenses/<module path with / replaced by _>.LICENSE; a module with neither
# fails the run, so a new dependency cannot slip in without its license text.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-build/THIRD_PARTY_LICENSES.txt}
mkdir -p "$(dirname "$out")"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
  echo "wgft is licensed under the MIT License (see LICENSE)."
  echo "The binary also contains the following Go modules, under the licenses reproduced below."
  echo
  go list -deps -f '{{if and .Module (not .Module.Main)}}{{.Module.Path}} {{.Module.Dir}}{{end}}' ./cmd/wgft | sort -u | while read -r mod dir; do
    [ -n "$mod" ] || continue
    files=$(find "$dir" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | sort)
    if [ -z "$files" ]; then
      fallback="scripts/licenses/${mod//\//_}.LICENSE"
      if [ ! -f "$fallback" ]; then
        echo "no license file for module $mod in $dir and no $fallback" >&2
        exit 1
      fi
      files=$fallback
    fi
    echo "================================================================================"
    echo "$mod"
    echo "================================================================================"
    for f in $files; do
      echo
      echo "--- $(basename "$f") ---"
      echo
      cat "$f"
    done
    echo
  done
} > "$tmp"
mv "$tmp" "$out"
chmod 0644 "$out"
echo "wrote $out ($(grep -c '^====' "$out") separator lines, $(wc -l < "$out") lines)"
