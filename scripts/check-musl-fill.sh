#!/usr/bin/env bash
# check-musl-fill.sh checks that wgstack's chunk fill does not call memset in the shipping musl build.
#
#   scripts/check-musl-fill.sh [--asm] [TARGET]
#
# TARGET defaults to x86_64-unknown-linux-musl. The shipping Linux agent is built for musl with zigbuild,
# whose memset is a byte-store loop, so the chunk fill (`fill_chunk` in wgft-wgstack) writes wide stores
# itself. The script isolates the body of that one symbol and fails if it is missing or ambiguous, mentions
# memset, memcpy or memmove, or has no vector store.
#
# Two modes share the same body checks:
#   default  builds `wgft` the way lab/lab does (cargo zigbuild --release --locked -p wgft) with the symbols
#            kept and disassembles the linked binary. It needs cargo-zigbuild, zig, objdump and the target.
#   --asm    needs only the pinned toolchain and the target (rust-toolchain.toml installs it). It emits the
#            assembly of the wgft-wgstack library with `cargo rustc --emit asm`. CI uses this mode. The
#            library is compiled by rustc itself, so it checks what LLVM makes of the loop, not zig's
#            linker or its compiler_rt.
# Set CARGO_TARGET_DIR to reuse a build directory; it is a temporary one otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=zig
if [[ ${1:-} == --asm ]]; then
  mode=asm
  shift
fi
target=${1:-x86_64-unknown-linux-musl}
if [[ -z ${CARGO_TARGET_DIR:-} ]]; then
  CARGO_TARGET_DIR=$(mktemp -d "${TMPDIR:-/tmp}/check-musl-fill.XXXXXX")
  trap 'rm -rf "$CARGO_TARGET_DIR"' EXIT
fi
export CARGO_TARGET_DIR
fail() {
  echo "check-musl-fill: $*" >&2
  exit 1
}

# The symbol is matched whole, not as a substring: v0 mangling `_RNvNtNtC<id>_12wgft_wgstack3buf5chunk10fill_chunk`
# or legacy `_ZN12wgft_wgstack3buf5chunk10fill_chunk17h<16 hex>E`, optionally with LLVM's `.llvm.N` suffix.
sym='(_RNvNtNtC[A-Za-z0-9]+_12wgft_wgstack3buf5chunk10fill_chunk|_ZN12wgft_wgstack3buf5chunk10fill_chunk17h[0-9a-f]{16}E)(\.llvm\.[0-9]+)?'
if [[ $mode == zig ]]; then
  CARGO_PROFILE_RELEASE_STRIP=none cargo zigbuild --release --locked -q --target "$target" -p wgft
  bin=$CARGO_TARGET_DIR/$target/release/wgft
  [[ -x $bin ]] || fail "$bin was not built"
  # fill_chunk is #[inline(never)], so it stays a symbol of its own. objdump -d prints "<symbol>:" labels.
  listing=$(objdump -d --no-show-raw-insn "$bin")
  labels='^[0-9a-f]+ <.*>:$'
  want="^[0-9a-f]+ <${sym}>:\$"
  endfn=
  where=$bin
  asm=0
else
  # A cached library build would emit no assembly, and an old .s must not be read, so rebuild the library.
  cargo clean -q -p wgft-wgstack --release --target "$target"
  rm -f "$CARGO_TARGET_DIR/$target"/release/deps/wgft_wgstack-*.s
  cargo rustc --release --locked -q --target "$target" -p wgft-wgstack --lib -- --emit asm
  shopt -s nullglob
  files=("$CARGO_TARGET_DIR/$target"/release/deps/wgft_wgstack-*.s)
  ((${#files[@]})) || fail "no assembly was emitted for $target"
  listing=$(cat "${files[@]}")
  labels=
  want="^${sym}:\$"
  endfn='^\.Lfunc_end[0-9]+:$'
  where="the assembly of $target"
  asm=1
fi
# Print the lines of the function whose label matches $want; the count of such labels goes to a side file.
awk_out=$(mktemp "$CARGO_TARGET_DIR/.count.XXXXXX")
# The patterns go through the environment, because awk -v would process the backslashes in them.
body=$(want=$want labels=$labels endfn=$endfn awk -v asm="$asm" -v cnt="$awk_out" '
  BEGIN { want = ENVIRON["want"]; labels = ENVIRON["labels"]; endfn = ENVIRON["endfn"] }
  $0 ~ want { on = 1; n++; next }
  on && asm && $0 ~ endfn { on = 0; next }
  on && !asm && $0 ~ labels { on = 0 }
  on { print }
  END { print n + 0 > cnt }
' <<<"$listing")
count=$(<"$awk_out")
[[ $count == 1 ]] || fail "expected exactly one fill_chunk in $where, found $count"
[[ -n $body ]] || fail "fill_chunk has an empty body in $where"
# Any mention counts: x86 call/jmp, arm64 bl/b, PLT and GOT forms, address loads.
if grep -Eq 'mem(set|cpy|move)' <<<"$body"; then
  echo "check-musl-fill: fill_chunk refers to memset, memcpy or memmove:" >&2
  grep -E 'mem(set|cpy|move)' <<<"$body" >&2
  exit 1
fi
# A vector store: SSE/AVX moves on x86_64, a 128-bit q register stored by stp, str or st1 on aarch64. The
# prologue's `stp x29, x30` is not one, because it needs a q register as the first operand.
grep -Eq '^[[:space:]]*(movdq[au]|movups|movaps|vmovdq[au]|vmovups|vmovaps)[[:space:]]+%[xyz]mm[0-9]+,|^[[:space:]]*(stp|str)[[:space:]]+q[0-9]+,|^[[:space:]]*st1[[:space:]]+\{ *v[0-9]+' <<<"$body" ||
  fail "fill_chunk has no vector store in $where"
echo "check-musl-fill: ok; fill_chunk in $where has no memset, memcpy or memmove and has a vector store ($(wc -l <<<"$body") lines)"
