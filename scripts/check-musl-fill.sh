#!/usr/bin/env bash
# check-musl-fill.sh checks that wgstack's chunk fill does not call memset in the shipping musl build.
#
#   scripts/check-musl-fill.sh [TARGET]
#
# TARGET defaults to x86_64-unknown-linux-musl. The shipping Linux agent is built for musl with zigbuild,
# whose memset is a byte-store loop, so the chunk fill (`fill_chunk` in wgft-wgstack) writes wide stores
# itself. The script builds `wgft` the way lab/lab does (cargo zigbuild --release --locked -p wgft) but
# keeps the symbols, disassembles `fill_chunk` and fails if it is missing, calls or jumps to memset or
# memcpy, or has no vector store. It needs cargo-zigbuild, zig, objdump and the target installed. Set
# CARGO_TARGET_DIR to reuse a build directory; it is a temporary one otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."
target=${1:-x86_64-unknown-linux-musl}
if [[ -z ${CARGO_TARGET_DIR:-} ]]; then
  CARGO_TARGET_DIR=$(mktemp -d "${TMPDIR:-/tmp}/check-musl-fill.XXXXXX")
  trap 'rm -rf "$CARGO_TARGET_DIR"' EXIT
fi
export CARGO_TARGET_DIR
CARGO_PROFILE_RELEASE_STRIP=none cargo zigbuild --release --locked -q --target "$target" -p wgft
bin=$CARGO_TARGET_DIR/$target/release/wgft
[[ -x $bin ]] || { echo "check-musl-fill: $bin was not built" >&2; exit 1; }
# fill_chunk is #[inline(never)], so it stays a symbol of its own. objdump -d prints "<symbol>:" labels.
body=$(objdump -d --no-show-raw-insn "$bin" | awk '
  /^[0-9a-f]+ <.*>:$/ { on = ($0 ~ /wgft_wgstack3buf5chunk10fill_chunk(\.llvm\.[0-9]+)?>:$/) }
  on { print }
')
[[ -n $body ]] || { echo "check-musl-fill: fill_chunk is not in $bin" >&2; exit 1; }
if grep -Eq '\b(call|callq|jmp|jmpq)\b.*memset|\b(call|callq|jmp|jmpq)\b.*memcpy' <<<"$body"; then
  echo "check-musl-fill: fill_chunk calls memset or memcpy:" >&2
  grep -E 'memset|memcpy' <<<"$body" >&2
  exit 1
fi
grep -Eq 'movdq[au]|movups|movaps|\bstp\b +q[0-9]' <<<"$body" || { echo "check-musl-fill: fill_chunk has no vector store" >&2; exit 1; }
echo "check-musl-fill: ok; fill_chunk in the $target build has no memset or memcpy call ($(wc -l <<<"$body") lines)"
