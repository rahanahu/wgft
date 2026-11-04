#!/usr/bin/env bash
# wgstack-record.sh makes the frozen Go wgstack's recordings, the request and response frames the
# Rust wgstack's replay compares with (docs/design/v2/test-tooling.md section 4).
#
#   scripts/wgstack-record.sh [--set git|full] [--out DIR] [--keep DIR] [--check]
#
#   --set git   the set kept in git (default), installed into testdata/wgstack-rec/; the set must
#               fit in the budget that TestRecordingsBudget checks. divergences.json stays.
#   --set full  the larger set for a local cache, such as every stream seed; --out names where.
#   --out DIR   where the full set goes (required with --set full).
#   --keep DIR  make the sets in DIR, which must be absent or empty, and keep them.
#   --check     make the git set once and require it to be the same as testdata/wgstack-rec/,
#               without writing there: the gate's check that the recordings in git are fresh.
#
# Without --check it makes the set twice from scratch and requires both makings to be the same.
# Two recordings are the same when their frames, and their metas apart from go_version, are; for a
# scenario that reads or writes from a goroutine of its own, whose frames may come in another
# order, only the metas are compared (scripts/wgstack-reccmp). Installing keeps a recording in git
# that is the same as the new one, so such a scenario's file changes only when its meta does, such
# as when the Go wgstack's commit changes; the replay test then runs over the installed set.
#
# It runs only on Linux on x86-64 and builds with GOAMD64=v1: the last digits of CUBIC's floating
# point can depend on whether the compiler fuses multiply and add. The meta names the last commit
# that changed the Go wgstack's product code or internal/ipv4frag, which it builds on. The exit
# status is 1 when making or checking fails, and 2 for a usage error or another platform.
set -euo pipefail

set_name=git out="" keep="" check=0
while (($#)); do
  case $1 in
    --set) set_name=${2:-}; shift 2 || { echo "wgstack-record: --set needs git or full" >&2; exit 2; } ;;
    --out) out=${2:-}; shift 2 || { echo "wgstack-record: --out needs a directory" >&2; exit 2; } ;;
    --keep) keep=${2:-}; shift 2 || { echo "wgstack-record: --keep needs a directory" >&2; exit 2; } ;;
    --check) check=1; shift ;;
    -h | --help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "wgstack-record: unknown argument: $1" >&2; exit 2 ;;
  esac
done
case $set_name in
  git) ;;
  full)
    [[ -n $out ]] || { echo "wgstack-record: --set full needs --out DIR" >&2; exit 2; }
    ((!check)) || { echo "wgstack-record: --check checks the git set only" >&2; exit 2; }
    ;;
  *) echo "wgstack-record: --set must be git or full; got $set_name" >&2; exit 2 ;;
esac
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "wgstack-record: recordings are made on Linux on x86-64 only; this is $(uname -s) $(uname -m)" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
# The git set's budget, 5 MiB (test-tooling.md section 4), is checked on the installed set by
# TestRecordingsBudget: a concurrent scenario's recording varies in size from one making to the
# next, and the one in git is kept while its meta stays the same.
dest=testdata/wgstack-rec

export GOAMD64=v1 GOOS=linux GOARCH=amd64
export WGFT_WGSTACK_RECORD_SET=$set_name
WGFT_WGSTACK_RECORD_COMMIT=$(git log -1 --format=%H -- internal/wgstack internal/ipv4frag \
  ':(exclude)internal/wgstack/*_test.go' ':(exclude)internal/wgstack/testdata' ':(exclude)internal/ipv4frag/*_test.go')
export WGFT_WGSTACK_RECORD_COMMIT
[[ -n $WGFT_WGSTACK_RECORD_COMMIT ]] || { echo "wgstack-record: no commit of internal/wgstack found" >&2; exit 1; }

if [[ -n $keep ]]; then
  if [[ -e $keep ]] && [[ -n $(ls -A "$keep") ]]; then
    echo "wgstack-record: --keep $keep is not empty; give an absent or empty directory" >&2
    exit 2
  fi
  work=$keep
  mkdir -p "$work"
else
  work=$(mktemp -d "${TMPDIR:-/tmp}/wgstack-record.XXXXXX")
  trap 'rm -rf "$work"' EXIT
fi

make_set() {
  local dir=$1
  mkdir -p "$dir"
  go test -c -o "$work/wgstack-dutserve.test" ./internal/wgstack
  WGFT_WGSTACK_RECORD=$dir go test -count=1 -timeout 60m -run '^TestWriteRecordings$' ./internal/wgstack
  WGFT_WGSTACK_RECORD=$dir WGFT_TEST_WGSTACK_DUT="$work/wgstack-dutserve.test" \
    go test -count=1 -timeout 60m -run '^TestWriteScenarioRecordings$' ./internal/tcpharness/rustdut
}

if ((check)); then
  echo "wgstack-record: making the git set once in $work to compare with $dest; Go wgstack commit $WGFT_WGSTACK_RECORD_COMMIT"
  make_set "$work/a"
  go run ./scripts/wgstack-reccmp "$work/a" "$dest" || {
    echo "wgstack-record: the recordings in $dest are not what the code makes now; run scripts/wgstack-record.sh and commit them" >&2
    exit 1
  }
  exit 0
fi

echo "wgstack-record: making the $set_name set twice in $work; Go wgstack commit $WGFT_WGSTACK_RECORD_COMMIT"
make_set "$work/a"
make_set "$work/b"
go run ./scripts/wgstack-reccmp "$work/a" "$work/b"

if [[ $set_name == git ]]; then
  mkdir -p "$dest"
  go run ./scripts/wgstack-reccmp -install "$work/a" "$dest"
  [[ -f $dest/divergences.json ]] || echo '[]' >"$dest/divergences.json"
  go test -count=1 -run 'TestRecordingsReplay|TestRecordingsBudget|TestDivergencesList' ./internal/wgstack
  echo "wgstack-record: installed into $dest"
else
  mkdir -p "$out"
  cp -r "$work/a/." "$out/"
  echo "wgstack-record: wrote $out; replay it with WGFT_WGSTACK_REPLAY_DIR=$out go test -run TestRecordingsReplay ./internal/wgstack"
fi
