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
step test 'go test -count=1 ./...'
step race-wgstack 'go test -count=1 -race ./internal/wgstack'
step race-relay 'go test -count=1 -race ./internal/dataplane/userspace/relay'
step cpu1-wgstack 'go test -count=1 -cpu 1 ./internal/wgstack'
# staticcheck needs the go1.27.1 toolchain and a go.mod that says so, as CI's step explains; it
# runs on a copy of the tree, so the go.mod edit cannot reach the steps running beside it.
step staticcheck 'copy_tree && cd "$tmp" && go mod edit -go=1.27.1 && GOTOOLCHAIN=go1.27.1 go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...'
step conformance-seeds 'for s in 1 2 3 4 5; do WGFT_TEST_WGSTACK_CONFORMANCE=1 WGFT_TEST_TCPHARNESS_SEED=$s go test -count=1 ./internal/tcpharness/wgstackdut || exit 1; done'
step stream-seeds-full 'WGFT_WGSTACK_STREAM_SEEDS=full go test -count=1 ./internal/wgstack -run "Stream|Scoreboard|RecvBuf"'
step adversarial-seeds 'need_test ./internal/wgstack TestAdversarialSender; WGFT_WGSTACK_AUDIT_SEEDS=3000 go test -count=1 ./internal/wgstack -run TestAdversarialSender'
# FuzzCore barely speeds up past 8 workers and runs at 4; FuzzAdversarialSender scales with them
# and runs at 8 for a smoke amount, since the long fuzzing runs on a separate machine.
step fuzz-core 'FUZZ_STEP=fuzz-core fuzz FuzzCore 5000000x 4'
step fuzz-adversarial 'FUZZ_STEP=fuzz-adversarial fuzz FuzzAdversarialSender 30000x 8'
step docs 'go run ./scripts/check-japanese/ && bash scripts/check-ascii-punct.sh && python3 scripts/check-docs.py && python3 scripts/check-docs-test.py && bash scripts/check-log-tokens.sh'
step mod-tidy 'copy_tree && mkdir -p "$tmp/.orig" && cp go.mod go.sum "$tmp/.orig/" && cd "$tmp" && go mod tidy && cmp go.mod .orig/go.mod && cmp go.sum .orig/go.sum || { echo "go mod tidy changes go.mod or go.sum"; exit 1; }'
if ((lab)); then
  step lab 'if grep -q "^  suite)" lab/lab; then lab/lab suite --vms 2; else lab/lab build && lab/lab exec vm labhost run -parallel 8 all; fi'
fi

export logdir
export -f has_test need_test copy_tree fuzz fuzz_rate

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
