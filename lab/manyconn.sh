#!/usr/bin/env bash
# manyconn.sh measures the userspace agent under many connections, in the split lab of `lab/lab paired
# --split`: the agent in a VM of its own, compared with a reference arm (the kernel-mode agent by
# default) in the same pair of VMs. It is a measurement for a person to read, not a check: nothing in
# it is asserted on beyond what `lab/lab paired` itself fails on, and it is not in lab/suite.txt.
#
#   lab/manyconn.sh cases concurrent|fixed|churn         print that set's case file
#   lab/manyconn.sh run concurrent|fixed|churn [lab paired options...]
#   lab/manyconn.sh summary <out dir>...                 the table of finished runs
#
# The sets, each one `lab/lab paired --split --cases` run (one pair of VMs, under its 3300-second
# --max-wall):
#   concurrent  N concurrent iperf3 streams at full speed, N = 16, 256, 1024 and 2000, each way
#               (down: the agent sends into the tunnel; up: it receives), with UDP round trips
#               (--udp-ping). 2000 streams and the iperf3 clients' 16 control connections stay
#               under the agent's default flow budget, WGFT_MAX_TCP_FLOWS = 2048 less the 4 spare
#               flows one rule may not take (docs/design/v2/agent-bound.md, design 7a.10).
#   fixed       the same N with every stream capped so that the streams add up to about
#               MANYCONN_FIXED_MBIT (2048 by default, whole Mbit/s per stream), with UDP round trips:
#               the same offered load for both arms, below the Rust agent's one-thread limit.
#   churn       short connections (200 bytes each way, the target closing first) at 500 to 16000
#               a second for 10 s, with UDP round trips, and 2000 a second for 60 s, past what
#               the wgstack TIME_WAIT table holds (65536 rows held for 60 s, about 1092 closes a
#               second). From the client's one address the table does not fill: the client's
#               ephemeral ports come round within the 60 s, and a new SYN on a TIME_WAIT row
#               takes that row over, so the rows stay under the port range (28232 by default);
#               the 2026-11-07 run evicted none. Filling it needs more client addresses.
# Every case runs 2 rounds of 2 runs per arm, with --vcpus 4 and --placement apart unless the
# options say otherwise; the options go to `lab/lab paired` before --cases (for example --vcpus 1,
# --out DIR, --base REF). MANYCONN_ARMS names the two arms, "rust kernel" by default. The CPU
# decision value is AGENTVMGUESTRATIO in each case's result.txt (lab/README.md), with the guest's
# /proc/stat (AGENTVMRATIO) for reference. The kernel arm has no RATIO of the agent process.
#
# summary prints `tcpquality.py manyconn` for every case under the out directories: per case and arm
# the medians of the rate (iperf3's own, and window_mbit, the bytes over the whole CPU window, a lower
# bound when hundreds of streams make iperf3 spend seconds connecting and closing; window_s shows how
# far the run stretched), the agent VM's CPU per GB (host guest time), the fairness, the UDP round
# trips, the agent's RSS against its logged memory bound, its refusal lines and the drop counters,
# or, for churn, the connections a second, the setup times and the agent VM's CPU per connection.
#
# Requirements are those of `lab/lab paired --split` (WGFT_LAB_PAIR_CPUS for the pinning; the Rust
# agent is built since an arm is rust), plus tools/churn, which `lab/lab paired` builds and installs
# with the other tools.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ARMS=${MANYCONN_ARMS:-rust kernel}
FIXED_MBIT=${MANYCONN_FIXED_MBIT:-2048}

cases() {
  local n
  case $1 in
    concurrent)
      for n in 16 256 1024 2000; do
        echo "s$n-down fast --tool iperf3 --streams $n --direction down --udp-ping"
        echo "s$n-up fast --tool iperf3 --streams $n --direction up --udp-ping"
      done ;;
    fixed)
      for n in 16 256 1024 2000; do
        local per=$((FIXED_MBIT / n))
        ((per >= 1)) || per=1
        echo "f$n-down fast --tool iperf3 --streams $n --direction down --bulk-mbit $per --udp-ping"
        echo "f$n-up fast --tool iperf3 --streams $n --direction up --bulk-mbit $per --udp-ping"
      done ;;
    churn)
      for n in 500 1000 2000 4000 8000 16000; do
        echo "churn-$n fast --tool churn --churn-rate $n --udp-ping"
      done
      echo "churn-2000-60s fast --tool churn --churn-rate 2000 --churn-seconds 60" ;;
    *) echo "manyconn.sh: the sets are concurrent, fixed and churn" >&2; exit 2 ;;
  esac
}

summary() {
  local d logs=()
  for d in "$@"; do
    mapfile -t -O "${#logs[@]}" logs < <(find "$d" -mindepth 2 -maxdepth 2 -name paired.log | sort -V)
  done
  ((${#logs[@]})) || { echo "manyconn.sh: no paired.log under $*" >&2; exit 1; }
  python3 "$HERE/tcpquality.py" manyconn "${logs[@]}"
}

case ${1:-} in
  cases) cases "${2:?cases concurrent|fixed|churn}" ;;
  summary) shift; summary "${@:?summary <out dir>...}" ;;
  run)
    set_name=${2:?run concurrent|fixed|churn [lab paired options...]}
    shift 2
    out="" args=()
    while (($#)); do
      case $1 in
        --out) out=${2:?--out DIR}; shift 2 ;;
        *) args+=("$1"); shift ;;
      esac
    done
    out=${out:-$HOME/.cache/wgft-lab/manyconn-$set_name-$(date +%Y%m%d-%H%M%S)}
    mkdir -p "$out"
    cases "$set_name" > "$out/cases.txt"
    # the defaults come first, so that the options given override them
    # shellcheck disable=SC2086 # the arms are two words on purpose
    rc=0
    "$HERE/lab" paired --split --vcpus 4 --placement apart --rounds 2 --runs 2 ${args[@]+"${args[@]}"} \
      --cases "$out/cases.txt" --out "$out" $ARMS || rc=$?
    summary "$out" | tee "$out/manyconn.txt" || true
    exit "$rc" ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
