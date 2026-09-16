#!/usr/bin/env bash
# check-ascii-punct rejects non-ASCII punctuation in public files:
# full-width ASCII-equivalents (U+FF01-FF5E), dashes (U+2010-2015, U+2212),
# the wave dash (U+301C), and the ideographic space (U+3000). Japanese letters
# themselves and the marks . , / (U+3002 U+3001 U+30FB) and the long vowel mark
# (U+30FC) are kept. Prints offending lines and exits non-zero if any remain.
#
# Paths listed in scripts/check-ascii-punct.exclude (one grep -E pattern per line, matched
# against ./path) are skipped; the file is optional.
set -u
cd "$(dirname "$0")/.."

pattern='[\x{FF01}-\x{FF5E}\x{2010}-\x{2015}\x{2212}\x{301C}\x{3000}]'

mapfile -t files < <(
  find . \
    -type d \( -name .git -o -name .claude -o -name experiments -o -name notes -o -name node_modules -o -name dist -o -name bin \) -prune -o \
    -type f \( -name '*.go' -o -name '*.md' -o -name '*.yaml' -o -name '*.yml' -o -name '*.sh' -o -name '*.gohtml' -o -name '*.service' -o -name '*.example' -o -path ./lab/lab \) -print \
  | { if [ -s scripts/check-ascii-punct.exclude ]; then grep -vEf scripts/check-ascii-punct.exclude; else cat; fi; }
)

hits=0
for f in "${files[@]}"; do
  if grep -nP "$pattern" "$f" >/dev/null 2>&1; then
    grep -nHP "$pattern" "$f"
    hits=$((hits + $(grep -cP "$pattern" "$f")))
  fi
done

if [ "$hits" -gt 0 ]; then
  echo "non-ASCII punctuation found: $hits line(s) (see above)" >&2
  exit 1
fi
echo "OK: no non-ASCII punctuation in public files"
