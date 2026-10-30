#!/usr/bin/env bash
# wgstack-gate.sh runs the host gate a wgstack change passes before review, as concurrent steps
# with a bound on how many run at once, and prints one table: step, PASS or FAIL, duration. Each
# step's full output stays in a log directory.
#
#   scripts/wgstack-gate.sh [-j N] [--lab] [--log DIR] [--only REGEX]
#
#   -j N        at most N steps at once (default 4). Each step's go command uses the machine's
#               CPUs as usual, so N bounds the steps, not the processes.
#   --lab       also run the lab suite beside the host steps: `lab/lab suite --vms 2` when lab/lab
#               has that command, else `lab/lab build` and `lab/lab exec vm labhost run -parallel
#               8 all`. WGFT_LAB_VM and the other WGFT_LAB_* variables pass through.
#   --log DIR   where the logs go (default a new directory under ${TMPDIR:-/tmp}).
#   --only RE   run only the steps whose name matches the extended regular expression RE.
#
# A step that needs something absent, such as a fuzz target or a test this tree does not have
# yet, reports SKIP with the reason. The exit status is 1 if any step failed.
set -u

jobs=4 lab=0 logdir="" only=""
while (($#)); do
  case $1 in
    -j) jobs=$2; shift 2 ;;
    --lab) lab=1; shift ;;
    --log) logdir=$2; shift 2 ;;
    --only) only=$2; shift 2 ;;
    -h | --help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "wgstack-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.." || exit 2
[[ -n $logdir ]] || logdir=$(mktemp -d "${TMPDIR:-/tmp}/wgstack-gate.XXXXXX")
mkdir -p "$logdir" || exit 2

# has_test reports whether package $1 has a test or fuzz target named $2.
has_test() { go test -list "^$2\$" "$1" 2>/dev/null | grep -qx "$2"; }

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

# fuzz runs a fuzz target on its own copy of the tree, kept in the log directory: a failing input
# is written to the copy's testdata, where the steps beside it would otherwise run it as a seed.
fuzz() {
  local target=$1 times=$2
  has_test ./internal/wgstack "$target" || { echo "SKIP: no $target in this tree"; return 0; }
  copy_tree "$logdir/$target-tree" && cd "$tmp" || return 1
  go test ./internal/wgstack -run '^$' -fuzz "^$target\$" -fuzztime "$times" -parallel 4 && return 0
  echo "the failing input is under $tmp/internal/wgstack/testdata/fuzz/$target"
  return 1
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
step adversarial-seeds 'has_test ./internal/wgstack TestAdversarialSender || { echo "SKIP: no TestAdversarialSender in this tree"; exit 0; }; WGFT_WGSTACK_AUDIT_SEEDS=3000 go test -count=1 ./internal/wgstack -run TestAdversarialSender'
step fuzz-core 'fuzz FuzzCore 5000000x'
step fuzz-adversarial 'fuzz FuzzAdversarialSender 150000x'
step docs 'go run ./scripts/check-japanese/ && bash scripts/check-ascii-punct.sh && python3 scripts/check-docs.py && python3 scripts/check-docs-test.py && bash scripts/check-log-tokens.sh'
step mod-tidy 'copy_tree && mkdir -p "$tmp/.orig" && cp go.mod go.sum "$tmp/.orig/" && cd "$tmp" && go mod tidy && cmp go.mod .orig/go.mod && cmp go.sum .orig/go.sum || { echo "go mod tidy changes go.mod or go.sum"; exit 1; }'
if ((lab)); then
  step lab 'if grep -q "^  suite)" lab/lab; then lab/lab suite --vms 2; else lab/lab build && lab/lab exec vm labhost run -parallel 8 all; fi'
fi

export logdir
export -f has_test copy_tree fuzz

declare -A start dur result
running=()

# launch starts step $1 in the background, its output in its log.
launch() {
  local i=$1 log="$logdir/${names[$1]}.log"
  start[$i]=$(date +%s)
  bash -c "${cmds[$i]}" >"$log" 2>&1 &
  running+=("$!:$i")
}

# reap waits for one running step to end and records it.
reap() {
  wait -n -p done_pid 2>/dev/null
  local rc=$? keep=() e pid i
  for e in "${running[@]}"; do
    pid=${e%%:*} i=${e##*:}
    if [[ $pid == "$done_pid" ]]; then
      dur[$i]=$(($(date +%s) - start[$i]))
      if ((rc != 0)); then result[$i]=FAIL
      elif grep -q '^SKIP: ' "$logdir/${names[$i]}.log"; then result[$i]=SKIP
      else result[$i]=PASS; fi
      printf '%-20s %-4s %5ds\n' "${names[$i]}" "${result[$i]}" "${dur[$i]}"
    else
      keep+=("$e")
    fi
  done
  running=("${keep[@]}")
}

t0=$(date +%s)
echo "wgstack-gate: logs in $logdir; at most $jobs steps at once"
# The lab suite mostly waits on its VM, so it starts first and does not count against -j.
order=()
for i in "${!names[@]}"; do
  [[ -z $only || ${names[$i]} =~ $only ]] || continue
  if [[ ${names[$i]} == lab ]]; then launch "$i"; else order+=("$i"); fi
done
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
printf '%-20s %-4s %8s  %s\n' step result seconds log
failed=0
for i in "${!names[@]}"; do
  [[ -n ${result[$i]:-} ]] || continue
  printf '%-20s %-4s %8d  %s\n' "${names[$i]}" "${result[$i]}" "${dur[$i]}" "$logdir/${names[$i]}.log"
  [[ ${result[$i]} == FAIL ]] && failed=1
done
echo "wall time $(($(date +%s) - t0))s"
exit $failed
