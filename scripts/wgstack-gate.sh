#!/usr/bin/env bash
# wgstack-gate.sh runs the host gate a wgstack change passes before review, as concurrent steps
# with a bound on how many run at once, and prints one table: step, PASS or FAIL, duration. Each
# step's full output stays in a log directory.
#
#   scripts/wgstack-gate.sh [-j N] [--timeout DURATION] [--lab] [--log DIR] [--only REGEX]
#
#   -j N        at most N steps at once (default 4). Each step's go command uses the machine's
#               CPUs as usual, so N bounds the steps, not the processes.
#   --timeout D a step running longer than D, a duration timeout(1) takes, fails and is killed
#               (default 45m; the lab suite gets three times as long).
#   --lab       also run the lab suite beside the host steps: `lab/lab suite --vms 2` when lab/lab
#               has that command, else `lab/lab build` and `lab/lab exec vm labhost run -parallel
#               8 all`. WGFT_LAB_VM and the other WGFT_LAB_* variables pass through.
#   --log DIR   where the logs go (default a new directory under ${TMPDIR:-/tmp}).
#   --only RE   run only the steps whose name matches the extended regular expression RE.
#
# A step that needs something absent, such as a fuzz target or a test this tree does not have
# yet, reports SKIP with the reason; one that cannot tell, because the package does not compile,
# fails. The exit status is 1 if any step failed, and 2 for a usage error. It needs bash 5.1 or
# newer and timeout(1).
set -u

if ((BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 1))); then
  echo "wgstack-gate: needs bash 5.1 or newer for wait -n -p; this is $BASH_VERSION" >&2
  exit 2
fi
command -v timeout >/dev/null || { echo "wgstack-gate: needs timeout(1)" >&2; exit 2; }

jobs=4 lab=0 logdir="" only="" step_timeout=45m
while (($#)); do
  case $1 in
    -j) jobs=${2:-}; shift 2 || { echo "wgstack-gate: -j needs a number" >&2; exit 2; } ;;
    --timeout) step_timeout=${2:-}; shift 2 || { echo "wgstack-gate: --timeout needs a duration" >&2; exit 2; } ;;
    --lab) lab=1; shift ;;
    --log) logdir=${2:-}; shift 2 || { echo "wgstack-gate: --log needs a directory" >&2; exit 2; } ;;
    --only) only=${2:-}; shift 2 || { echo "wgstack-gate: --only needs a pattern" >&2; exit 2; } ;;
    -h | --help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "wgstack-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ $jobs =~ ^[0-9]+$ ]] && ((jobs >= 1)) || { echo "wgstack-gate: -j must be a whole number of at least 1; got $jobs" >&2; exit 2; }
[[ $step_timeout =~ ^[0-9]+(\.[0-9]+)?[smhd]?$ ]] || { echo "wgstack-gate: --timeout must be a duration such as 45m; got $step_timeout" >&2; exit 2; }

cd "$(dirname "$0")/.." || exit 2
[[ -n $logdir ]] || logdir=$(mktemp -d "${TMPDIR:-/tmp}/wgstack-gate.XXXXXX")
mkdir -p "$logdir" && logdir=$(cd "$logdir" && pwd) || exit 2

# has_test reports whether package $1 has a test or fuzz target named $2: 0 if it has, 1 if it
# has not, and 2, with the reason, when go test -list fails, such as when the package does not
# compile; a step then fails instead of skipping.
has_test() {
  local out
  if ! out=$(go test -list "^$2\$" "$1" 2>&1); then
    echo "go test -list $1 failed:"
    echo "$out"
    return 2
  fi
  grep -qx "$2" <<<"$out"
}

# need_test is has_test for a step: it exits the step with SKIP when the target is absent and
# with a failure when the package cannot tell.
need_test() {
  has_test "$1" "$2"
  case $? in
    0) return 0 ;;
    1) echo "SKIP: no $2 in this tree"; exit 0 ;;
    *) exit 1 ;;
  esac
}

# copy_tree copies the tracked and untracked, not ignored, files into a new directory $tmp, removed
# when the step ends: a step that edits go.mod works there, out of reach of the steps beside it.
# With an argument, the copy goes there and stays.
copy_tree() {
  if [[ -n ${1:-} ]]; then
    tmp=$1
    rm -rf "$tmp" && mkdir -p "$tmp" || return 1
  else
    tmp=$(mktemp -d) || return 1
    trap 'rm -rf "$tmp"' EXIT
  fi
  { git ls-files -z; git ls-files -z -o --exclude-standard; } | xargs -0 cp --parents -t "$tmp"
}

# fuzz runs a fuzz target, $3 workers at once, on its own copy of the tree, kept in the log
# directory: a failing input is written to the copy's testdata, where the steps beside it would
# otherwise run it as a seed. It ends with a NOTE line of the executions per second, which the
# table shows.
fuzz() {
  local target=$1 times=$2 workers=$3 rc
  need_test ./internal/wgstack "$target"
  copy_tree "$logdir/$target-tree" && cd "$tmp" || return 1
  go test ./internal/wgstack -run '^$' -fuzz "^$target\$" -fuzztime "$times" -parallel "$workers"
  rc=$?
  fuzz_rate
  ((rc == 0)) && return 0
  echo "the failing input is under $tmp/internal/wgstack/testdata/fuzz/$target"
  return 1
}

# fuzz_shards runs a fuzz target for $2 executions in all as $3 processes of one worker each, and
# runs fuzz with $3 workers instead on a machine with fewer than $3 CPUs. One process with $3
# workers is slower: under -fuzztime Nx the coordinator reserves the executions left for the calls
# it has sent, the reservations drift apart and are not split again, so the end of the run goes on
# fewer and fewer workers. Each shard has one reservation, so nothing drifts.
#
# The shards run with GOMAXPROCS=1 and are not pinned to CPUs: the gain comes from the split, and
# fixed CPUs would collide with other gates and pinned VMs on the same host, while a job runner
# that re-pins the step's processes would undo them anyway.
#
# Each shard starts from a copy of the fuzz cache go test uses, so that it does not rediscover
# the inputs earlier runs kept; the shards do not share what they find while they run. When the
# shards have exited, and when the step is stopped by its timeout or an interrupt, each shard's new
# cache entries are copied into that cache. An entry is named after its content, so the union does
# not depend on the order. When a shard fails, the others are interrupted, as one process stops at
# its first failure. A failing input goes to the testdata of the tree copy, as with fuzz.
#
# When the step is stopped, the process group usually gets TERM, which ends the shards at once;
# their cache entries are on disk already, as Go writes each one when found, and this function
# merges them if its own shell survives the signal. If only this shell gets the signal, it
# interrupts the shards first.
#
# Every shard minimizes the new inputs it finds, so the minimization is bounded by executions:
# by default it may take 60 seconds, the shard makes no progress meanwhile, and a minimization that
# runs out of time can be killed with its executions left uncounted. The bound covers a failing
# input's minimization too.
fuzz_shards() {
  local target=$1 total=$2 k=$3 step=${FUZZ_STEP:-fuzz} i n rc=0 bin shared cache log t0 secs
  local execs found sum=0 done_pid status first="" f src
  local pids=() running=() failed=()
  local -A shard_of=()
  need_test ./internal/wgstack "$target"
  if (($(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1) < k)); then
    echo "fewer than $k CPUs; running one process with $k workers"
    fuzz "$target" "${total}x" "$k"
    return
  fi
  src=$PWD
  copy_tree "$logdir/$target-tree" && cd "$tmp" || return 1
  bin=$tmp/$target.test
  go test -c -fuzz "^$target\$" -o "$bin" ./internal/wgstack || return 1
  shared=$(go env GOCACHE)/fuzz/$(go list -f '{{.ImportPath}}' ./internal/wgstack)/$target
  mkdir -p "$shared" || return 1
  # Temporary files that a merge killed in the middle left beside the target's directory. Only old
  # ones go, so that a gate merging at the same time keeps its own.
  find "${shared%/*}" -maxdepth 1 -name ".$target.*.tmp" -mmin +60 -delete 2>/dev/null
  echo "$k shards of one worker and GOMAXPROCS=1, $total execs in all, starting from the $(find "$shared" -type f | wc -l) inputs in $shared"
  for ((i = 0; i < k; i++)); do
    cache=$logdir/$step.shard$i.cache
    rm -rf "$cache" && mkdir -p "$cache/$target" && cp -R "$shared/." "$cache/$target/" || return 1
  done
  # merge_shards copies the shards' new cache entries into the shared cache, each through a
  # unique temporary name beside the target's directory, so that no partial entry is ever in it
  # and gates merging the same entry at the same time do not share a file.
  merge_shards() {
    local i f name merged=0 t
    for ((i = 0; i < k; i++)); do
      for f in "$logdir/$step.shard$i.cache/$target"/*; do
        name=${f##*/}
        [[ -f $f && ! -e $shared/$name ]] || continue
        t=$(mktemp "${shared%/*}/.$target.XXXXXX.tmp") || continue
        if cp "$f" "$t" && chmod 644 "$t" && mv -f "$t" "$shared/$name"; then merged=$((merged + 1)); else rm -f "$t"; fi
      done
      rm -rf "$logdir/$step.shard$i.cache"
    done
    echo "copied $merged new inputs from the shards into $shared"
  }
  # On a timeout, timeout(1) and stop send TERM to the whole process group; Go does not handle
  # TERM, so the shards die at once, and the entries they found are already on disk, as Go writes
  # each one when it finds it. When only this shell gets the signal, the shards are interrupted.
  trap 'echo "stopped; interrupting the shards if they still run, and keeping what they found"; kill -INT "${pids[@]}" 2>/dev/null; wait; merge_shards; exit 1' TERM INT
  t0=$(date +%s)
  for ((i = 0; i < k; i++)); do
    n=$((total / k + (i < total % k ? 1 : 0)))
    cache=$logdir/$step.shard$i.cache
    # fuzzseed=N would give every shard the same mutator seed, so most executions would repeat.
    (cd internal/wgstack && GODEBUG=$(sed -E 's/(^|,)fuzzseed=[^,]*//g; s/^,//' <<<"${GODEBUG:-}") GOMAXPROCS=1 exec "$bin" -test.run '^$' -test.fuzz "^$target\$" \
      -test.fuzztime "${n}x" -test.fuzzminimizetime 5000x -test.parallel 1 -test.fuzzcachedir "$cache") >"$logdir/$step.shard$i.log" 2>&1 &
    pids+=($!)
    shard_of[$!]=$i
  done
  running=("${pids[@]}")
  while ((${#running[@]})); do
    done_pid=""
    wait -n -p done_pid "${running[@]}"
    status=$?
    [[ -n $done_pid ]] || { rc=1; break; }
    for i in "${!running[@]}"; do [[ ${running[$i]} == "$done_pid" ]] && unset 'running[i]'; done
    running=("${running[@]}")
    ((status == 0)) && continue
    if [[ -n $first ]]; then
      echo "shard ${shard_of[$done_pid]} was interrupted after shard $first failed; exit status $status"
      continue
    fi
    rc=1 first=${shard_of[$done_pid]}
    failed+=("$first")
    echo "shard $first failed; interrupting the other shards"
    kill -INT "${pids[@]}" 2>/dev/null
  done
  wait
  trap - TERM INT
  secs=$(($(date +%s) - t0))
  for ((i = 0; i < k; i++)); do
    log=$logdir/$step.shard$i.log
    execs=$(grep -o 'execs: [0-9]*' "$log" | tail -1 | awk '{ print $2 + 0 }')
    sum=$((sum + ${execs:-0}))
    found=$(grep -o 'new interesting: [0-9]*' "$log" | tail -1 | awk '{ print $3 + 0 }')
    echo "shard $i: ${execs:-0} execs, ${found:-0} new inputs; log $log"
  done
  merge_shards
  for i in "${failed[@]}"; do
    log=$logdir/$step.shard$i.log
    echo "shard $i failed; the end of $log:"
    tail -n 40 "$log"
    f=$(sed -n 's/.*Failing input written to \(testdata\/fuzz\/[^ ]*\).*/\1/p' "$log" | tail -1)
    [[ -z $f ]] || echo "the failing input of shard $i is $tmp/internal/wgstack/$f"
  done
  if ((${#failed[@]})); then
    # Another shard may have found a crasher before the interrupt reached it.
    echo "all inputs under $tmp/internal/wgstack/testdata/fuzz/$target that the source tree does not have:"
    for f in "$tmp/internal/wgstack/testdata/fuzz/$target"/*; do
      [[ -f $f && ! -e $src/internal/wgstack/testdata/fuzz/$target/${f##*/} ]] && echo "  $f"
    done
  fi
  ((secs > 0)) && echo "NOTE: $sum execs in ${secs}s, $((sum / secs))/s, $k shards"
  return $rc
}

# replay_full makes the full set of Go recordings, unless the cache has the set for the tree's recording
# sources, and replays shard $1 of it (i/n) on the Rust wgstack. The cache key is the git trees of the
# packages the set is made from; a tree with changes there makes the set in the log directory instead. The
# set takes the inputs of the Go fuzz cache as they are when it is made. One shard makes the set under an
# exclusive lock, into a temporary directory renamed into place, and evicts the other keys; the replays
# hold the lock shared, so no set is removed under a replay. The step runs only when the tree changes the
# Rust wgstack, the test tooling or the recordings against the merge base with WGFT_GATE_BASE (default
# origin/feat/v2-rust if it exists, else origin/main), or when WGFT_GATE_REPLAY_FULL=1; the stage gates
# replay the full set as a whole.
replay_full() {
  local shard=$1 paths=(internal/wgstack internal/ipv4frag internal/dutproto internal/tcpharness scripts/wgstack-record.sh scripts/wgstack-reccmp)
  local root=${XDG_CACHE_HOME:-$HOME/.cache}/wgft/wgstack-rec-full key d base tmp fz
  command -v cargo >/dev/null || { echo "SKIP: no cargo"; exit 0; }
  command -v flock >/dev/null || { echo "SKIP: no flock(1)"; exit 0; }
  [[ -f crates/wgft-wgstack-dut/tests/replay.rs && -x scripts/wgstack-record.sh ]] || { echo "SKIP: no Rust replay in this tree"; exit 0; }
  [[ "$(uname -s) $(uname -m)" == "Linux x86_64" ]] || { echo "SKIP: recordings are made on Linux on x86-64 only"; exit 0; }
  if [[ ${WGFT_GATE_REPLAY_FULL:-} != 1 ]]; then
    local gbase=${WGFT_GATE_BASE:-} mb rust=(crates/wgft-wgstack crates/wgft-wgstack-dut crates/wgft-tcpharness testdata/wgstack-rec Cargo.lock "${paths[@]}")
    if [[ -z $gbase ]]; then
      git rev-parse -q --verify origin/feat/v2-rust >/dev/null && gbase=origin/feat/v2-rust || gbase=origin/main
    fi
    mb=$(git merge-base HEAD "$gbase" 2>/dev/null) || { echo "SKIP: no merge base with $gbase; set WGFT_GATE_REPLAY_FULL=1 to run"; exit 0; }
    if git diff --quiet "$mb" -- "${rust[@]}" && [[ -z $(git status --porcelain -- "${rust[@]}") ]]; then
      echo "SKIP: no change to the Rust wgstack, its test tooling or the recordings since $gbase; set WGFT_GATE_REPLAY_FULL=1 to run"
      exit 0
    fi
  fi
  if [[ -z $(git status --porcelain -- "${paths[@]}") ]]; then
    key=$(for p in "${paths[@]}"; do git rev-parse "HEAD:$p"; done | sha256sum | cut -c1-16)
    base=$root
  else
    echo "the recording sources have changes; making the full set in the log directory"
    key=set base=$logdir/wgstack-rec-full
  fi
  d=$base/$key
  mkdir -p "$base" || return 1
  (
    flock -x 9 || exit 1
    [[ -f $d/.done ]] && exit 0
    tmp=$base/.making.$$ fz=$logdir/fuzz-cache.$$
    rm -rf "$tmp" "$fz"
    # a snapshot, since the Go fuzz steps beside this one add to the cache while the set is made twice
    if [[ -d $(go env GOCACHE)/fuzz/github.com/rahanahu/wgft/internal/wgstack ]]; then
      cp -r "$(go env GOCACHE)/fuzz/github.com/rahanahu/wgft/internal/wgstack" "$fz" || exit 1
    fi
    WGFT_WGSTACK_RECORD_FUZZ_DIR=$([[ -d $fz ]] && echo "$fz") TMPDIR=$logdir scripts/wgstack-record.sh --set full --out "$tmp" || exit 1
    rm -rf "$fz"
    touch "$tmp/.done"
    find "$base" -mindepth 1 -maxdepth 1 ! -name "$key" ! -name ".making.$$" ! -name .lock -exec rm -rf {} + || exit 1
    rm -rf "$d" && mv -T "$tmp" "$d"
  ) 9>"$base/.lock" || return 1
  echo "replaying shard $shard of the full set in $d"
  flock -s "$base/.lock" env WGFT_WGSTACK_REPLAY_DIR="$d" WGFT_WGSTACK_REPLAY_SHARD="$shard" \
    cargo test --release -p wgft-wgstack-dut --locked --test replay
}

# fuzz_rs runs the Rust wgstack's cargo-fuzz target $1 for $2 executions, without AddressSanitizer and
# without tracing comparisons, which make a run about twice as slow and safe Rust gains little from. The new
# inputs go to a corpus in the log directory and a failing input to an artifact beside it.
fuzz_rs() {
  local target=$1 runs=$2 fz=crates/wgft-wgstack/fuzz work
  command -v cargo >/dev/null && cargo +nightly fuzz --version >/dev/null 2>&1 || { echo "SKIP: no nightly cargo with cargo-fuzz"; exit 0; }
  grep -q "^name = \"$target\"" "$fz/Cargo.toml" 2>/dev/null || { echo "SKIP: no fuzz target $target in this tree"; exit 0; }
  work=$logdir/fuzz-rs-$target
  rm -rf "$work" && mkdir -p "$work/corpus" || return 1
  if [[ $target == replay ]]; then
    cargo run -q -p wgft-wgstack-dut --locked --example replay_seeds -- "$work/corpus" || return 1
  fi
  # raw_adversary needs long inputs to fill the half-open table and reach the SYN cookie check, so it
  # starts from the stable test's seeds
  if [[ $target == raw_adversary ]]; then
    cargo run -q -p wgft-wgstack-dut --locked --example raw_seeds -- "$work/corpus" || return 1
  fi
  # core reads two bytes a step for up to 500 steps; libFuzzer's length control would keep its inputs to
  # a few steps, so core runs at the full length from the start, and so does raw_adversary
  local extra=()
  [[ $target == core ]] && extra=(-len_control=0 -max_len=1024)
  [[ $target == raw_adversary ]] && extra=(-len_control=0 -max_len=16000)
  # the corpus in git, when the target has one; raw_adversary has none and starts from raw_seeds
  local corpora=("$work/corpus")
  [[ -d $fz/corpus/$target ]] && corpora+=("fuzz/corpus/$target")
  (cd crates/wgft-wgstack && cargo +nightly fuzz run -s none --no-trace-compares "$target" "${corpora[@]}" -- \
    -runs="$runs" -artifact_prefix="$work/" "${extra[@]}") || { echo "the failing input is under $work"; return 1; }
}

# fuzz_rate reads the last progress line of the fuzzing output above it in the step's log, such
# as "fuzz: elapsed: 1m6s, execs: 205209 (3498/sec)", and prints the run's executions per second.
fuzz_rate() {
  awk '/^fuzz: elapsed: / { el = $3; ex = $5 } END {
    sub(/,$/, "", el); sub(/,$/, "", ex); t = 0; n = ""
    for (i = 1; i <= length(el); i++) {
      c = substr(el, i, 1)
      if (c ~ /[0-9.]/) { n = n c; continue }
      t += n * (c == "h" ? 3600 : c == "m" ? 60 : 1); n = ""
    }
    if (t > 0) printf "NOTE: %d execs in %ds, %.0f/s\n", ex, t, ex / t
  }' "$logdir/${FUZZ_STEP:-fuzz}.log"
}

# The steps, as name and command. A command that prints "SKIP: reason" and exits 0 counts as
# skipped.
names=() cmds=()
step() { names+=("$1"); cmds+=("$2"); }

step gofmt 'out=$(gofmt -l .); [[ -z $out ]] || { echo "not gofmt-clean:"; echo "$out"; exit 1; }'
step build 'go build ./...'
step vet-linux 'GOOS=linux go vet ./...'
step vet-windows 'GOOS=windows go vet ./...'
step vet-darwin 'GOOS=darwin go vet ./...'
# the qbench package builds only with its tag, so the vet steps above leave it out
step vet-qbench 'for os in linux darwin windows; do GOOS=$os go vet -tags qbench ./internal/tcpharness/qbench || exit 1; done'
step qbench-rules 'go test -count=1 -tags qbench -run "^(TestJudgeRules|TestContentLoss.*|TestArrivalLossUnchanged)\$" ./internal/tcpharness/qbench'
step test 'go test -count=1 ./...'
step race-wgstack 'go test -count=1 -race ./internal/wgstack'
step race-relay 'go test -count=1 -race ./internal/dataplane/userspace/relay'
step cpu1-wgstack 'go test -count=1 -cpu 1 ./internal/wgstack'
# staticcheck needs the go1.27.1 toolchain and a go.mod that says so, as CI's step explains; it
# runs on a copy of the tree, so the go.mod edit cannot reach the steps running beside it.
step staticcheck 'copy_tree && cd "$tmp" && go mod edit -go=1.27.1 && GOTOOLCHAIN=go1.27.1 go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...'
step conformance-seeds 'for s in 1 2 3 4 5; do WGFT_TEST_WGSTACK_CONFORMANCE=1 WGFT_TEST_TCPHARNESS_SEED=$s go test -count=1 ./internal/tcpharness/wgstackdut || exit 1; done'
# rustdut drives the Go wgstack's dutserve, a mode of its test binary, over the DUT frames and must
# give wgstackdut's results on every scenario (docs/design/v2/test-tooling.md section 3).
step rustdut-dutserve 'need_test ./internal/tcpharness/rustdut TestSameAsWgstackdut; go test -c -o "$logdir/wgstack-dutserve.test" ./internal/wgstack || exit 1; for s in 1 2 3 4 5; do WGFT_TEST_WGSTACK_DUT="$logdir/wgstack-dutserve.test" WGFT_TEST_TCPHARNESS_SEED=$s go test -count=1 ./internal/tcpharness/rustdut || exit 1; WGFT_TEST_WGSTACK_DUT="$logdir/wgstack-dutserve.test" WGFT_TEST_TCPHARNESS_SEED=$s go test -count=1 -run TestRustdut ./internal/tcpharness/wgstackdut || exit 1; done'
# the recordings in testdata/wgstack-rec must be what the code makes now (test-tooling.md section 4)
step recordings-fresh '[[ "$(uname -s) $(uname -m)" == "Linux x86_64" ]] || { echo "SKIP: recordings are made on Linux on x86-64 only"; exit 0; }; [[ -x scripts/wgstack-record.sh ]] || { echo "SKIP: no scripts/wgstack-record.sh in this tree"; exit 0; }; scripts/wgstack-record.sh --check'
# The Rust runner must send the Go runner's requests: both run every scenario script against
# dutserve, run seeds 1 to 5, and their transcripts and check traces must be equal byte for byte
# (docs/design/v2/test-tooling.md section 2). SKIP where there is no cargo or no Rust runner.
step harness-rust-go 'command -v cargo >/dev/null || { echo "SKIP: no cargo"; exit 0; }; [[ -f crates/wgft-tcpharness/tests/scripts.rs ]] || { echo "SKIP: no Rust runner in this tree"; exit 0; }; need_test ./internal/tcpharness/rustdut TestWriteTranscripts; go test -c -o "$logdir/harness-dutserve.test" ./internal/wgstack || exit 1; rm -rf "$logdir/transcripts"; export WGFT_TEST_WGSTACK_DUT="$logdir/harness-dutserve.test" WGFT_TEST_TCPHARNESS_TRANSCRIPTS="$logdir/transcripts"; go test -count=1 -run "TestWriteTranscripts|TestRustVectors" ./internal/tcpharness/rustdut && cargo test -p wgft-tcpharness --locked'
# The Rust wgstack behind wgstack-dut (docs/design/v2/test-tooling.md sections 2 to 4): the replay of the
# Go recordings whose tags the landed stages cover, the scenario scripts in process on run seeds 1 to 5,
# and the adapter and binary tests. SKIP where there is no cargo or no wgstack-dut crate.
step wgstack-rs 'command -v cargo >/dev/null || { echo "SKIP: no cargo"; exit 0; }; [[ -d crates/wgft-wgstack-dut ]] || { echo "SKIP: no wgstack-dut in this tree"; exit 0; }; cargo test -p wgft-wgstack-dut --locked || exit 1; for s in 1 2 3 4 5; do WGFT_TEST_TCPHARNESS_SEED=$s cargo test -p wgft-wgstack-dut --locked --test scenarios || exit 1; done'
# The Rust replay of the full set of Go recordings, the set too large for git (test-tooling.md section 4):
# every stream and FuzzCore seed of the recording tests, the adversarial seeds of the Go step below, and
# the inputs of the Go fuzz cache. The set changes only with its sources, which the migration freezes, so it
# is made once into the user cache and kept; the replay runs in a release build, split into three steps
# that the scheduler runs beside each other.
for i in 0 1 2; do
  step "wgstack-rs-replay-full-$((i + 1))of3" "replay_full $i/3"
done
# The Rust adversarial sender (crates/wgft-wgstack-dut/tests/fuzz_corpus.rs) on as many seeds as the Go step
# below, in a release build: a seed takes about 3 s in a debug build and about 0.1 s in a release one.
step wgstack-rs-adversarial 'command -v cargo >/dev/null || { echo "SKIP: no cargo"; exit 0; }; [[ -f crates/wgft-wgstack-dut/tests/fuzz_corpus.rs ]] || { echo "SKIP: no Rust adversarial sender in this tree"; exit 0; }; WGFT_WGSTACK_AUDIT_SEEDS=3000 cargo test --release -p wgft-wgstack-dut --locked --test fuzz_corpus'
# The Rust wgstack's cargo-fuzz targets (docs/design/v2/test-tooling.md section 6) for a fixed number of
# executions each, sized to stay within about two minutes beside the other steps. replay starts from the requests of
# every Go recording in git besides its own seeds. SKIP where there is no nightly toolchain or cargo-fuzz.
for t in parse:2000000 core:2500 replay:20000 adversarial_sender:200 raw_adversary:2000; do
  step "fuzz-rs-${t%%:*}" "fuzz_rs ${t%%:*} ${t#*:}"
done
step stream-seeds-full 'WGFT_WGSTACK_STREAM_SEEDS=full go test -count=1 ./internal/wgstack -run "Stream|Scoreboard|RecvBuf"'
step adversarial-seeds 'need_test ./internal/wgstack TestAdversarialSender; WGFT_WGSTACK_AUDIT_SEEDS=3000 go test -count=1 ./internal/wgstack -run TestAdversarialSender'
# FuzzCore runs as 4 single-worker shards, which finish the same executions sooner than one process with
# 4 workers; FuzzAdversarialSender stays one process of 8 workers for a smoke amount, since every
# shard would first rerun the whole cached corpus, and the long fuzzing runs on a separate machine.
step fuzz-core 'FUZZ_STEP=fuzz-core fuzz_shards FuzzCore 5000000 4'
step fuzz-adversarial 'FUZZ_STEP=fuzz-adversarial fuzz FuzzAdversarialSender 30000x 8'
step docs 'go run ./scripts/check-japanese/ && bash scripts/check-ascii-punct.sh && python3 scripts/check-docs.py && python3 scripts/check-docs-test.py && bash scripts/check-log-tokens.sh'
step mod-tidy 'copy_tree && mkdir -p "$tmp/.orig" && cp go.mod go.sum "$tmp/.orig/" && cd "$tmp" && go mod tidy && cmp go.mod .orig/go.mod && cmp go.sum .orig/go.sum || { echo "go mod tidy changes go.mod or go.sum"; exit 1; }'
if ((lab)); then
  step lab 'if grep -q "^  suite)" lab/lab; then lab/lab suite --vms 2; else lab/lab build && lab/lab exec vm labhost run -parallel 8 all; fi'
fi

export logdir
export -f has_test need_test copy_tree fuzz fuzz_rate fuzz_shards fuzz_rs replay_full

declare -A start dur result note
running=()

# launch starts step $1 in the background, its output in its log, in a session of its own so
# that a timeout or an interrupt can kill all of it, under timeout(1) and with pipefail.
launch() {
  local i=$1 log="$logdir/${names[$1]}.log" limit=$step_timeout
  if [[ ${names[$i]} == lab ]]; then
    limit=$(awk -v t="$step_timeout" 'BEGIN { n = t + 0; u = substr(t, length(t)); if (u !~ /[smhd]/) u = "s"; print 3 * n u }')
  fi
  start[$i]=$(date +%s)
  setsid timeout --kill-after=30s "$limit" bash -o pipefail -c "${cmds[$i]}" >"$log" 2>&1 &
  running+=("$!:$i")
}

# finish records step $1's end with exit status $2.
finish() {
  local i=$1 rc=$2
  dur[$i]=$(($(date +%s) - start[$i]))
  if ((rc == 124 || rc == 137)) && ! grep -q '^SKIP: ' "$logdir/${names[$i]}.log"; then
    echo "wgstack-gate: the step was killed or ran past --timeout $step_timeout; exit status $rc" >>"$logdir/${names[$i]}.log"
  fi
  if ((rc != 0)); then result[$i]=FAIL
  elif grep -q '^SKIP: ' "$logdir/${names[$i]}.log"; then result[$i]=SKIP
  else result[$i]=PASS; fi
  note[$i]=$(sed -n 's/^NOTE: //p' "$logdir/${names[$i]}.log" | tail -1)
  printf '%-20s %-4s %5ds %s\n' "${names[$i]}" "${result[$i]}" "${dur[$i]}" "${note[$i]}"
}

# reap waits for one running step to end and records it. When wait reports no pid, as after a
# signal, every step that is no longer running is recorded as failed, so the table survives.
reap() {
  local done_pid=""
  wait -n -p done_pid 2>/dev/null
  local rc=$? keep=() e pid i
  for e in "${running[@]}"; do
    pid=${e%%:*} i=${e##*:}
    if [[ -n $done_pid && $pid == "$done_pid" ]]; then
      finish "$i" "$rc"
    elif [[ -z $done_pid ]] && ! kill -0 "$pid" 2>/dev/null; then
      echo "wgstack-gate: the step ended and its exit status was lost" >>"$logdir/${names[$i]}.log"
      finish "$i" 1
    else
      keep+=("$e")
    fi
  done
  running=("${keep[@]}")
}

# stop kills every running step, each a session of its own, and exits.
stop() {
  local e
  for e in "${running[@]}"; do kill -TERM -- "-${e%%:*}" 2>/dev/null; done
  echo "wgstack-gate: interrupted; the running steps were killed" >&2
  exit 130
}
trap stop INT TERM

t0=$(date +%s)
echo "wgstack-gate: logs in $logdir; at most $jobs steps at once"
# The lab suite mostly waits on its VM, so it starts first and does not count against -j.
order=() selected=0
for i in "${!names[@]}"; do
  [[ -z $only || ${names[$i]} =~ $only ]] || continue
  selected=$((selected + 1))
  if [[ ${names[$i]} == lab ]]; then launch "$i"; else order+=("$i"); fi
done
if ((selected == 0)); then
  echo "wgstack-gate: --only $only selects no step; the steps are: ${names[*]}" >&2
  exit 2
fi
# host counts the running steps other than the lab suite.
host() {
  local n=0 e
  for e in "${running[@]}"; do [[ ${names[${e##*:}]} == lab ]] || n=$((n + 1)); done
  echo $n
}
for i in "${order[@]}"; do
  while (($(host) >= jobs)); do reap; done
  launch "$i"
done
while ((${#running[@]})); do reap; done

echo
printf '%-20s %-4s %8s  %-30s %s\n' step result seconds note log
failed=0
for i in "${!names[@]}"; do
  [[ -n ${result[$i]:-} ]] || continue
  printf '%-20s %-4s %8d  %-30s %s\n' "${names[$i]}" "${result[$i]}" "${dur[$i]}" "${note[$i]:-}" "$logdir/${names[$i]}.log"
  [[ ${result[$i]} == FAIL ]] && failed=1
done
echo "wall time $(($(date +%s) - t0))s"
exit $failed
