#!/usr/bin/env bash
# tcpquality-cpu.sh compares the userspace agent's CPU per transferred byte between gVisor and
# wgstack on one path of lab/tcpquality.sh, the measurement the CPU target of
# docs/design/userspace/wgstack-performance.md is judged by:
#
#   lab/lab exec vm bash /wgft/lab/tcpquality-cpu.sh fast
#   lab/lab exec vm env DIRECTION=up bash /wgft/lab/tcpquality-cpu.sh rate
#
# fast is the path without netem and a 1 GiB transfer; rate is 25 ms each way at 20 Mbit/s with a
# 200-packet queue, no loss and a 32 MiB transfer. BYTES overrides the size. DIRECTION=up makes the
# agent's netstack the receiver, as in tcpquality.sh. Neither path has an outage.
#
# It runs tcpquality.sh with CPU=1 ROUNDS times, RUNS runs of each netstack a round, and swaps which
# netstack goes first every round, so both netstacks see the same periods of the VM. It then prints
# tcpquality.py cpuratio's lines: per netstack the median, quartiles and range of the agent's CPU
# seconds per GB, and the ratio of the wgstack and gVisor medians with a bootstrap 95% interval.
# The defaults, 3 rounds of 3 runs, give the 9 runs per case of the design's gate. Run it alone in
# the VM. Requires `lab/lab build` and the netns topology (`lab/lab net up`).
#
# With a mode of tcpquality.sh after the path, it runs only that mode, RUNS runs on the path, and
# prints tcpquality.sh's lines without the ratio; `lab/lab paired` runs it so in two VMs at once:
#
#   lab/lab exec vm env SYNC=1 bash /wgft/lab/tcpquality-cpu.sh fast wgstack
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
case "${1:-}" in
  fast) export DELAY_MS=0 LOSS_PCT=0 BYTES=${BYTES:-1073741824}; unset RATE_MBIT ;;
  rate) export DELAY_MS=25 LOSS_PCT=0 RATE_MBIT=20 QUEUE_PKTS=200 BYTES=${BYTES:-33554432} ;;
  *) echo "usage: tcpquality-cpu.sh fast|rate [mode]" >&2; exit 2 ;;
esac
export CPU=1 OUTAGE_S=0 RUNS=${RUNS:-3} DIRECTION=${DIRECTION:-down}
ROUNDS=${ROUNDS:-3}
if [ -n "${2:-}" ]; then
  exec bash "$HERE/tcpquality.sh" "$2"
fi

. "$HERE/sandbox.sh"
log=$W/wgft-tqcpu.log
: > "$log"
fail=0
for round in $(seq 1 "$ROUNDS"); do
  if [ $((round % 2)) = 1 ]; then order="gvisor wgstack"; else order="wgstack gvisor"; fi
  echo "== round $round of $ROUNDS: $order"
  # shellcheck disable=SC2086 # the order is two words on purpose
  bash "$HERE/tcpquality.sh" $order | tee -a "$log"
  [ "${PIPESTATUS[0]}" = 0 ] || fail=1
done
python3 "$HERE/tcpquality.py" cpuratio "$log" || fail=1
exit "$fail"
