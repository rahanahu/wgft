#!/usr/bin/env bash
# agent-perf-stat.sh runs the host-side tunnel socket measurement (crates/wgft-agent-perf) under
# perf stat and prints one comparable line per metric. The lab VMs have no PMU, so the cache and
# instruction counts of the batching work come from here.
#
#   scripts/agent-perf-stat.sh [--base REF] [--rounds N] [--packets N] [--burst N]
#                              [--modes "send recv"] [--sizes "1408 64"]
#                              [--head-bin PATH] [--base-bin PATH] [--no-netns]
#
#   --base REF     also build REF in a temporary worktree and alternate base and head runs
#                  (base, head, base, head, ...) per mode and size, so both see the same
#                  conditions; each line then has base, head and head/base. REF's own copy of the
#                  tool is used if it has one, else the head's copy is laid over it.
#   --rounds N     runs per arm and cell (default 7); the lines show the median and the range.
#   --packets N    packets per run (default 200000), --burst N packets per burst (default 64).
#   --head-bin P   use the prebuilt binary P instead of building (likewise --base-bin).
#   --no-netns     measure on the host loopback instead of an unprivileged network namespace.
#
# Run it on a timing lane, where the CPUs are quiet and fixed:
#   notes/scripts/wgft-heavy --timing --vm-mem 0 -- scripts/agent-perf-stat.sh [--base REF]
# The measured thread and the second thread take the first two CPUs of WGFT_HEAVY_CPUS, or of the
# CPUs this shell may run on. The build runs before the measurement and may use the whole set.
#
# The measurement runs inside `unshare -rn` (an unprivileged user and network namespace with its
# own loopback), so it needs no root. perf_event_paranoid level 2 lets perf count user space
# only: instructions and cache misses leave out the kernel's UDP and loopback work, while the
# system calls per packet and the CPU time per byte include it.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cache=${XDG_CACHE_HOME:-$HOME/.cache}/wgft-agent-perf

base="" rounds=7 packets=200000 burst=64 modes="send recv" sizes="1408 64"
head_bin="" base_bin="" netns=1 measure=0
while (($#)); do
  case $1 in
    --base) base=$2; shift 2 ;;
    --rounds) rounds=$2; shift 2 ;;
    --packets) packets=$2; shift 2 ;;
    --burst) burst=$2; shift 2 ;;
    --modes) modes=$2; shift 2 ;;
    --sizes) sizes=$2; shift 2 ;;
    --head-bin) head_bin=$2; shift 2 ;;
    --base-bin) base_bin=$2; shift 2 ;;
    --no-netns) netns=0; shift ;;
    --measure) measure=1; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "agent-perf-stat: unknown option $1" >&2; exit 2 ;;
  esac
done

if ((!measure)); then
  # Phase 1: build, outside the namespace because the namespace has no network for the crate registry.
  if [[ -z $head_bin ]]; then
    (cd "$root" && cargo build --release -p wgft-agent-perf >&2)
    head_bin=$(cd "$root" && cargo metadata --format-version 1 --no-deps | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')/release/wgft-agent-perf
  fi
  if [[ -n $base && -z $base_bin ]]; then
    mkdir -p "$cache"
    tmp=$(mktemp -d "$cache/run.XXXXXX")
    wt=$tmp/wt
    git -C "$root" worktree add --detach "$wt" "$base" >&2
    trap 'git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true' EXIT
    if git -C "$root" cat-file -e "$base:crates/wgft-agent-perf/Cargo.toml" 2>/dev/null; then
      echo "agent-perf-stat: base uses its own copy of the tool" >&2
    else
      echo "agent-perf-stat: base has no tool; laying the head's copy over it" >&2
      rm -rf "$wt/crates/wgft-agent-perf"
      cp -r "$root/crates/wgft-agent-perf" "$wt/crates/wgft-agent-perf"
    fi
    (cd "$wt" && CARGO_TARGET_DIR=$cache/base-target cargo build --release -p wgft-agent-perf >&2)
    # Copy the binary out, so that a concurrent run sharing the target directory cannot replace it,
    # and drop the worktree now: phase 2 replaces this shell with exec, so no EXIT trap would run.
    cp "$cache/base-target/release/wgft-agent-perf" "$tmp/base-bin"
    base_bin=$tmp/base-bin
    git -C "$root" worktree remove --force "$wt" >&2
    trap - EXIT
    export WGFT_PERF_TMP=$tmp
  fi
  args=(--measure --rounds "$rounds" --packets "$packets" --burst "$burst" --modes "$modes" --sizes "$sizes" --head-bin "$head_bin")
  [[ -n $base_bin ]] && args+=(--base "${base:-base}" --base-bin "$base_bin")
  if ((netns)); then
    exec unshare -rn bash -c 'ip link set lo up && exec "$0" "$@"' "$0" "${args[@]}"
  fi
  exec "$0" "${args[@]}" --no-netns
fi

# Phase 2: measure.
allowed=$(taskset -pc $$ | sed 's/.*: //')
cpus_expand() { local p; IFS=, read -ra parts <<<"$1"; for p in "${parts[@]}"; do if [[ $p == *-* ]]; then seq "${p%-*}" "${p#*-}"; else echo "$p"; fi; done; }
read -ra cpus <<<"$(cpus_expand "${WGFT_HEAVY_CPUS:-$allowed}" | tr '\n' ' ')"
((${#cpus[@]} >= 2)) || { echo "agent-perf-stat: needs two CPUs, have: ${cpus[*]}" >&2; exit 2; }
cpu_main=${cpus[0]} cpu_peer=${cpus[1]}

# The PMU of the measured CPU: a hybrid machine names them cpu_core and cpu_atom.
if [[ -r /sys/devices/cpu_atom/cpus ]] && cpus_expand "$(cat /sys/devices/cpu_atom/cpus)" | grep -qx "$cpu_main"; then
  pmu=cpu_atom
  events="cpu_atom/cycles/,cpu_atom/instructions/,cpu_atom/cache-misses/,cpu_atom/mem_load_uops_retired.l1_miss/"
elif [[ -r /sys/devices/cpu_core/cpus ]]; then
  pmu=cpu_core
  events="cpu_core/cycles/,cpu_core/instructions/,cpu_core/cache-misses/,cpu_core/L1-dcache-load-misses/"
else
  pmu=cpu
  events="cycles,instructions,cache-misses,L1-dcache-load-misses"
fi
work=$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/wgft-agent-perf-run.XXXXXX")
trap 'rm -rf "$work" ${WGFT_PERF_TMP:+"$WGFT_PERF_TMP"}' EXIT

# Preflight on the measured CPU: all four events must count.
need_events="cache-misses L1-dcache-load-misses instructions cycles"
check_events() {
  local file=$1 ev
  for ev in $need_events; do
    awk -F, -v want="$ev" '
      /^#/ || NF < 3 { next }
      { e = $3; sub(/^cpu_[a-z]+\//, "", e); sub(/\/u*$/, "", e); sub(/:[a-zA-Z]+$/, "", e)
        if (e == "mem_load_uops_retired.l1_miss") e = "L1-dcache-load-misses"
        if (e == want && $1 ~ /^[0-9]+$/) found = 1 }
      END { exit !found }' "$file" || { echo "agent-perf-stat: event $ev is missing, not counted or not supported on CPU $cpu_main (events: $events)" >&2; return 1; }
  done
}
taskset -c "$cpu_main" perf stat -x, --no-inherit -e "$events" -o "$work/pre.csv" -- true >/dev/null 2>&1 || true
check_events "$work/pre.csv" || exit 1
rows=$work/rows.tsv

# run_one ARM BIN MODE SIZE: one perf stat run; appends "arm mode size metric value" rows.
run_one() {
  local arm=$1 bin=$2 mode=$3 size=$4
  perf stat -x, --no-inherit -e "$events" -o "$work/perf.csv" -- \
    "$bin" --mode "$mode" --size "$size" --packets "$packets" --burst "$burst" \
    --cpu-main "$cpu_main" --cpu-peer "$cpu_peer" >"$work/tool.out" 2>"$work/tool.err" \
    || { echo "agent-perf-stat: $arm $mode $size failed: $(cat "$work/tool.err")" >&2; exit 1; }
  check_events "$work/perf.csv" || exit 1
  awk -F, -v arm="$arm" -v mode="$mode" -v size="$size" '
    FNR == NR {
      n = split($0, words, " ")
      if (words[1] == "RESULT") for (i = 2; i <= n; i++) { split(words[i], kv, "="); r[kv[1]] = kv[2] }
      next
    }
    /^#/ || NF < 3 { next }
    {
      ev = $3; sub(/^cpu_[a-z]+\//, "", ev); sub(/\/u*$/, "", ev); sub(/:[a-zA-Z]+$/, "", ev)
      if (ev == "mem_load_uops_retired.l1_miss") ev = "L1-dcache-load-misses"
      v[ev] = $1
    }
    END {
      if (r["packets"] == "") exit 1
      p = r["packets"]; b = r["bytes"]
      if (v["cache-misses"] ~ /^[0-9]+$/) printf "%s\t%s\t%s\tcache-misses/packet\t%.4f\n", arm, mode, size, v["cache-misses"] / p
      if (v["L1-dcache-load-misses"] ~ /^[0-9]+$/) printf "%s\t%s\t%s\tL1-dcache-load-misses/packet\t%.4f\n", arm, mode, size, v["L1-dcache-load-misses"] / p
      if (v["instructions"] ~ /^[0-9]+$/) printf "%s\t%s\t%s\tinstructions/byte\t%.6f\n", arm, mode, size, v["instructions"] / b
      printf "%s\t%s\t%s\tsyscalls/packet\t%.6f\n", arm, mode, size, (r["data_syscalls"] + r["wake_syscalls"]) / p
      printf "%s\t%s\t%s\tcpu-ns/byte\t%.6f\n", arm, mode, size, r["cpu_ns"] / b
    }' "$work/tool.out" "$work/perf.csv" >>"$rows"
}

echo "agent-perf-stat: pmu=$pmu cpus=$cpu_main,$cpu_peer packets=$packets burst=$burst rounds=$rounds netns=$netns head=$head_bin${base_bin:+ base=$base_bin}"
echo "agent-perf-stat: kernel=$(uname -r) cpu=$(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //') paranoid=$(cat /proc/sys/kernel/perf_event_paranoid) (counts are user space only above 1)"
for ((r = 1; r <= rounds; r++)); do
  for mode in $modes; do
    for size in $sizes; do
      [[ -n $base_bin ]] && run_one base "$base_bin" "$mode" "$size"
      run_one head "$head_bin" "$mode" "$size"
    done
  done
done

# One line per mode, size and metric: the median of the rounds with the range, and the ratio.
awk -F'\t' '
  function med(key, n,   i, j, t, a) {
    n = cnt[key]
    for (i = 1; i <= n; i++) a[i] = val[key, i]
    for (i = 2; i <= n; i++) { t = a[i]; for (j = i - 1; j >= 1 && a[j] > t; j--) a[j + 1] = a[j]; a[j + 1] = t }
    lo[key] = a[1]; hi[key] = a[n]
    return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
  }
  {
    cell = $2 SUBSEP $3 SUBSEP $4
    if (!(cell in seen)) { seen[cell] = 1; order[++cells] = cell }
    key = $1 SUBSEP cell
    val[key, ++cnt[key]] = $5
    arms[$1] = 1
  }
  END {
    for (c = 1; c <= cells; c++) {
      split(order[c], p, SUBSEP)
      line = sprintf("%-4s %-5s %-30s", p[1], p[2], p[3])
      h = med("head" SUBSEP order[c]); hk = "head" SUBSEP order[c]
      if ("base" in arms) {
        bk = "base" SUBSEP order[c]
        b = med(bk)
        line = line sprintf(" base=%.4f [%.4f..%.4f] head=%.4f [%.4f..%.4f] ratio=%.3f", b, lo[bk], hi[bk], h, lo[hk], hi[hk], b > 0 ? h / b : 0)
      } else {
        line = line sprintf(" head=%.4f [%.4f..%.4f]", h, lo[hk], hi[hk])
      }
      print "METRIC " line
    }
  }' "$rows"
