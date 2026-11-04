#!/usr/bin/env python3
# Golden test of the paired estimators of tcpquality.py (the cpupaired subcommand and its
# MBITRATIO) on two tiny synthetic logs, and tests of the host and guest counters that
# `lab/lab paired --split` records: python3 lab/tcpquality_test.py
import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
import unittest

TQ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tcpquality.py")

PAIRED = ("PAIRED round=%d run=1 arm=%s vm=%s name=%s pass=1 sync=ok agent_cpu_s_per_gb=%.3f overall_mbit=%d "
          "agent_cpu_share=0.5 sender_cpu_share=0.1 t_start=0 t_end=10")


def synthetic_log():
    lines = ["PLAN rounds=4 runs=1 vcpus=4"]
    for rnd in range(1, 5):
        for arm, name, cpu in (("x", "new", 1.0), ("y", "old", 1.25)):
            vm = "a" if (rnd % 2 == 1) == (arm == "x") else "b"
            lines.append(PAIRED % (rnd, arm, vm, name, cpu * (1 + 0.01 * rnd), 1000 + 10 * rnd))
    return lines


def analyse(lines):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "paired.log")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        p = subprocess.run([sys.executable, TQ, "cpupaired", path], capture_output=True, text=True)
    return p.returncode, p.stdout


EXPECTED_PLAIN = """CPU arm=x name=new runs=4 cpu_s_per_gb=1.025 q1=1.018 q3=1.032 min=1.010 max=1.040 mbit=1025.0 agent_cpu_share=0.50 sender_cpu_share=0.10 vm_cpu_share=nan
CPU arm=y name=old runs=4 cpu_s_per_gb=1.281 q1=1.272 q3=1.291 min=1.262 max=1.300 mbit=1025.0 agent_cpu_share=0.50 sender_cpu_share=0.10 vm_cpu_share=nan
ROUND round=1 x_in_vm=a pairs=1 ratio_median=0.800
ROUND round=2 x_in_vm=b pairs=1 ratio_median=0.800
ROUND round=3 x_in_vm=a pairs=1 ratio_median=0.800
ROUND round=4 x_in_vm=b pairs=1 ratio_median=0.800
LEFT_OUT planned=4 used=4 missing=0 failed=0 sync_timeout=0 sender_bound=0
PAIRS x_in_vm=a pairs=2 ratio_median=0.800 min=0.800 max=0.800
PAIRS x_in_vm=b pairs=2 ratio_median=0.800 min=0.800 max=0.800
RATIO x_over_y=0.800 ci95_low=0.800 ci95_high=0.800 pairs=4 left_out=0 vm_a_over_b=1.000 overlap=1.00 x=new y=old
MBITRATIO key=overall_mbit x_over_y=1.000 ci95_low=1.000 ci95_high=1.000 pairs=4 planned=4 missing=0 failed=0 sync_timeout=0 sender_bound=0 x=new y=old
"""

EXPECTED_LEFT_OUT = """CPU arm=x name=new runs=2 cpu_s_per_gb=1.025 q1=1.018 q3=1.032 min=1.010 max=1.040 mbit=1025.0 agent_cpu_share=0.50 sender_cpu_share=0.10 vm_cpu_share=nan
CPU arm=y name=old runs=2 cpu_s_per_gb=1.281 q1=1.272 q3=1.291 min=1.262 max=1.300 mbit=1025.0 agent_cpu_share=0.50 sender_cpu_share=0.10 vm_cpu_share=nan
ROUND round=1 x_in_vm=a pairs=1 ratio_median=0.800
ROUND round=4 x_in_vm=b pairs=1 ratio_median=0.800
LEFT_OUT planned=4 used=2 missing=1 failed=1 sync_timeout=0 sender_bound=0
WARN x_in_vm=a: no pair is left from round(s) 3, so this side rests on 1 agent start(s)
WARN x_in_vm=b: no pair is left from round(s) 2, so this side rests on 1 agent start(s)
TOO FEW x_in_vm=a pairs=1 of 2 planned; fewer than half remain, so no ratio is given
TOO FEW x_in_vm=b pairs=1 of 2 planned; fewer than half remain, so no ratio is given
MBITRATIO key=overall_mbit TOO FEW x_in_vm=a pairs=1 of 2 planned; no ratio missing=1 failed=1 sync_timeout=0 sender_bound=0
"""


class CpuPaired(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(analyse(synthetic_log()), (0, EXPECTED_PLAIN))

    def test_failed_and_missing_pairs_are_counted(self):
        lines = [l for l in synthetic_log() if not l.startswith("PAIRED round=3 run=1 arm=x")]
        lines = [l.replace("pass=1", "pass=0") if l.startswith("PAIRED round=2 run=1 arm=y") else l for l in lines]
        self.assertEqual(analyse(lines), (1, EXPECTED_LEFT_OUT))

    @staticmethod
    def split_log(peer):
        # a --split log of 4 rounds x 2 runs; peer(rnd, run, arm) gives the run's peer VM fields
        lines = ["PLAN rounds=4 runs=2 vcpus=4 split=1 peer_vcpus=8"]
        for rnd in range(1, 5):
            for run in (1, 2):
                for arm, name, cpu in (("x", "new", 1.0), ("y", "old", 1.25)):
                    vm = "a" if (rnd % 2 == 1) == (arm == "x") else "b"
                    lines.append(PAIRED.replace("run=1", "run=%d" % run) % (rnd, arm, vm, name, cpu * (1 + 0.01 * rnd), 1000 + 10 * rnd)
                                 + " agentvm_cpu_s_per_gb=%.3f " % cpu + peer(rnd, run, arm))
        return lines

    @staticmethod
    def peer_fields(cpus):
        # peer VM fields from [(busy, kw), ...] per vCPU
        return "peervm_maxcpu=%.2f " % max(b for b, _ in cpus) + " ".join(
            "peervm_cpu%d_busy=%.2f peervm_cpu%d_kw=%.2f" % (i, b, i, k) for i, (b, k) in enumerate(cpus))

    def test_peer_bound_needs_a_busy_vcpu_and_its_own_kernel_worker(self):
        special = {
            # 0.96 busy with little worker time: kept
            (2, 2, "y"): [(0.30, 0.95), (0.96, 0.30)],
            # saturated: left out
            (3, 1, "x"): [(0.30, 0.20), (0.99, 0.99)],
            # two vCPUs tie at 0.99 and only the second has its worker at 0.95: left out
            (4, 2, "y"): [(0.99, 0.20), (0.99, 0.95)],
        }
        lines = self.split_log(lambda rnd, run, arm: self.peer_fields(special.get((rnd, run, arm), [(0.30, 0.95), (0.80, 0.20)])))
        rc, out = analyse(lines)
        self.assertEqual(rc, 0, out)
        self.assertIn("RATIO x_over_y=0.800 ci95_low=0.800 ci95_high=0.800 pairs=6 left_out=2 ", out)
        self.assertIn("LEFT_OUT planned=8 used=6 missing=0 failed=0 sync_timeout=0 sender_bound=0 peer_bound=2 "
                      "peer_bound_x=1 peer_bound_y=1\n", out)
        self.assertIn("AGENTVMLEFT_OUT planned=8 used=6 missing=0 failed=0 sync_timeout=0 sender_bound=0 peer_bound=2 "
                      "peer_bound_x=1 peer_bound_y=1\n", out)
        self.assertRegex(out, r"MBITRATIO key=overall_mbit .* pairs=6 planned=8 missing=0 failed=0 sync_timeout=0 "
                              r"sender_bound=0 peer_bound=2 peer_bound_x=1 peer_bound_y=1 ")
        self.assertNotIn("WARN peer_bound", out)

    def test_peer_bound_warns_when_one_arm_has_most(self):
        bound = {(1, 1, "x"), (2, 1, "x")}
        lines = self.split_log(lambda rnd, run, arm: self.peer_fields(
            [(0.99, 0.99)] if (rnd, run, arm) in bound else [(0.80, 0.20)]))
        rc, out = analyse(lines)
        self.assertEqual(rc, 0, out)
        self.assertIn("peer_bound=2 peer_bound_x=2 peer_bound_y=0\n", out)
        self.assertEqual(out.count("WARN peer_bound"), 1, out)
        self.assertIn("\nWARN peer_bound x=2 y=0: ", out)

    def test_split_log_without_kernel_worker_time_is_unchanged(self):
        # logs of older lab heads: no peer-bound check, whatever peervm_maxcpu says
        busy = self.split_log(lambda rnd, run, arm: "peervm_maxcpu=%.2f" % (0.99 if (rnd, run) == (2, 2) else 0.80))
        calm = self.split_log(lambda rnd, run, arm: "peervm_maxcpu=0.80")
        rc, out = analyse(busy)
        self.assertEqual((rc, out), analyse(calm))
        self.assertNotIn("peer_bound", out)
        self.assertIn("LEFT_OUT planned=8 used=8 ", out)

    def test_placement_rejects_userspace_arms_with_more_threads(self):
        # --placement apart pins the agent to one CPU: only the rust and kernel arms. --rounds 3 is
        # invalid too, so the command stops in validation even if the placement check were gone
        lab = os.path.join(os.path.dirname(TQ), "lab")
        for arms in (("gvisor", "rust"), ("rust", "base:wgstack")):
            p = subprocess.run(["bash", lab, "paired", "--split", "--placement", "apart", "--tool", "iperf3", "--rounds", "3",
                                "--base", "HEAD", "fast", *arms], capture_output=True, text=True,
                               env={k: v for k, v in os.environ.items() if not k.startswith("WGFT_LAB")})
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertIn("--placement apart", p.stderr)
            self.assertIn("one CPU", p.stderr)

    def lab_paired(self, args, cases=None):
        # lab/lab paired with arguments that must stop before provisioning. --out lies under /proc, so even
        # a command line that passed every check would stop at creating it, before any build or VM
        lab = os.path.join(os.path.dirname(TQ), "lab")
        with tempfile.TemporaryDirectory() as d:
            if cases is not None:
                path = os.path.join(d, "cases.txt")
                with open(path, "w") as f:
                    f.write(cases)
                args = [a.replace("CASES", path) for a in args]
            p = subprocess.run(["bash", lab, "paired", "--out", "/proc/wgft-no-such-dir/out", *args], capture_output=True, text=True,
                               env={k: v for k, v in os.environ.items() if not k.startswith("WGFT_LAB")}, timeout=60)
        self.assertNotIn("built", p.stdout + p.stderr)
        self.assertNotIn("deleting", p.stdout + p.stderr)
        return p.returncode, p.stderr

    def test_cases_are_checked_before_provisioning(self):
        good = "# comment\nupload fast --direction up --tool iperf3\n\nlocal-down fast --target local --tool iperf3 --streams 4\n"
        base = ["--split", "--placement", "apart", "--cases", "CASES"]
        for args, cases, want in (
                (["--cases", "CASES", "rust", "kernel"], good, "--cases goes with --split"),
                (base + ["fast", "rust", "kernel"], good, "give the two arms only"),
                (base + ["rust", "kernel"], "a fast\na fast --direction up\n", "the name a is used twice"),
                (base + ["rust", "kernel"], "a fast --vcpus 2\n", "--vcpus is not a per-case flag"),
                (base + ["rust", "kernel"], "a fast --direction\n", "--direction wants a value"),
                (base + ["rust", "kernel"], "# nothing\n", "has no case"),
                (base + ["rust", "kernel"], "a fast --tool iperf3\nb slow\n", "the path is fast, rate or delay"),
                (base + ["rust", "kernel"], "a fast --tool iperf3\nb fast --target local\n", "--target local wants --tool iperf3"),
                (base + ["gvisor", "rust"], good, "--placement apart pins"),
        ):
            rc, err = self.lab_paired(args, cases)
            self.assertEqual(rc, 1, err)
            self.assertIn(want, err)
        # the case that is wrong is named
        rc, err = self.lab_paired(base + ["rust", "kernel"], "a fast --tool iperf3\nb fast --target local\n")
        self.assertIn("case b: see the message above", err)
        rc, err = self.lab_paired(base + ["rust", "kernel"], None)
        self.assertEqual(rc, 1, err)
        self.assertIn("is not a readable file", err)
        # a file that passes every check gets as far as the output directory, which cannot be made
        rc, err = self.lab_paired(base + ["--tool", "iperf3", "rust", "kernel"], good)
        self.assertNotEqual(rc, 0, err)
        self.assertIn("/proc/wgft-no-such-dir", err)

    def test_peer_value_does_not_change_a_single_vm_log(self):
        lines = [l + " peervm_maxcpu=0.99" if l.startswith("PAIRED") else l for l in synthetic_log()]
        self.assertEqual(analyse(lines), (0, EXPECTED_PLAIN))

    def test_non_numeric_and_nan_values_are_failed_pairs(self):
        # a value that is not a number, or is nan, fails its pair instead of raising or passing
        lines = synthetic_log()
        lines = [l.replace("agent_cpu_s_per_gb=1.020", "agent_cpu_s_per_gb=abc") if l.startswith("PAIRED round=2 run=1 arm=x") else l
                 for l in lines]
        lines = [l.replace("agent_cpu_s_per_gb=1.040", "agent_cpu_s_per_gb=nan") if l.startswith("PAIRED round=4 run=1 arm=x") else l
                 for l in lines]
        rc, out = analyse(lines)
        self.assertEqual(rc, 1, out)
        self.assertIn("failed=2", out)
        self.assertNotIn("Traceback", out)


def load_tq():
    spec = importlib.util.spec_from_file_location("tcpquality", TQ)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tq = load_tq()

INTERRUPTS = """            CPU0       CPU1
  24:          5          7  PCI-MSIX-0000:01:00.0   0-edge      virtio1-config
  25:        100        200  PCI-MSIX-0000:01:00.0   1-edge      virtio1-input.0
  26:         10         20  PCI-MSIX-0000:01:00.0   2-edge      virtio1-output.0
  27:          1          2  PCI-MSIX-0000:01:00.0   3-edge      virtio1-input.1
  28:          3          4  IO-APIC   1-edge      i8042
 LOC:       1000       2000   Local timer interrupts
 RES:         30         40   Rescheduling interrupts
 CAL:          5          6   Function call interrupts
 ERR:          0
"""

SOFTIRQS = """                    CPU0       CPU1
          HI:          0          0
       TIMER:         10         20
      NET_TX:          1          2
      NET_RX:        300        400
"""


def thread(comm, allowed, proc=0, **vals):
    base = {k: 0 for k in tq.THREAD_KEYS}
    base.update(vals)
    return (comm, proc, allowed, base)


class GuestCounters(unittest.TestCase):
    def test_interrupts(self):
        self.assertEqual(tq.parse_interrupts(INTERRUPTS), {
            "irq_virtio1_config": 12, "irq_virtio1_input": 303, "irq_virtio1_output": 30,
            "irq_LOC": 3000, "irq_RES": 70, "irq_CAL": 11})

    def test_softirqs(self):
        self.assertEqual(tq.parse_softirqs(SOFTIRQS), {"sirq_HI": 0, "sirq_TIMER": 30, "sirq_NET_TX": 3, "sirq_NET_RX": 700})

    def test_cpuidle(self):
        with tempfile.TemporaryDirectory() as d:
            for cpu in (0, 1):
                for st, name, usage, us in ((0, "POLL", 5, 50), (1, "C1", 10, 1000)):
                    sd = os.path.join(d, "cpu%d" % cpu, "cpuidle", "state%d" % st)
                    os.makedirs(sd)
                    for f, v in (("name", name), ("usage", usage), ("time", us)):
                        with open(os.path.join(sd, f), "w") as g:
                            g.write("%s\n" % v)
            os.makedirs(os.path.join(d, "cpufreq"))
            self.assertEqual(tq.cpuidle_counters(d), {"idle_POLL_usage": 10, "idle_POLL_us": 100,
                                                      "idle_C1_usage": 20, "idle_C1_us": 2000})
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "cpu0"))
            self.assertEqual(tq.cpuidle_counters(d), {})

    def test_ethstats_keep(self):
        got = tq.ethstats_keep({"rx_queue_0_packets": 1, "rx_queue_0_bytes": 2, "rx_queue_0_kicks": 3,
                                "tx_queue_0_kicks": 4, "tx-queue-0-drops": 5, "tx_queue_0_xdp_tx": 6})
        self.assertEqual(got, {"rx_queue_0_packets": 1, "rx_queue_0_kicks": 3, "tx_queue_0_kicks": 4, "tx_queue_0_drops": 5})

    def test_snapdiff_rates(self):
        before = "peervm_t=0 peervm_busy_us=0 peervm_user_us=0 peervm_sys_us=0 peervm_soft_us=0 peervm_irq_us=0 peervm_steal_us=0 " \
                 "peervm_irq_virtio1_input=100 peervm_irq_RES=0 peervm_sirq_NET_RX=0 peervm_idle_C1_usage=0 peervm_idle_C1_us=0 " \
                 "eth_homerouter_lan0_tx_queue_0_kicks=0"
        after = "peervm_t=10 peervm_busy_us=5000000 peervm_user_us=0 peervm_sys_us=0 peervm_soft_us=0 peervm_irq_us=0 peervm_steal_us=0 " \
                "peervm_irq_virtio1_input=2100 peervm_irq_RES=500 peervm_sirq_NET_RX=0 peervm_idle_C1_usage=1000 peervm_idle_C1_us=4000000 " \
                "eth_homerouter_lan0_tx_queue_0_kicks=3000"
        p = subprocess.run([sys.executable, TQ, "snapdiff", "2000000000", "10", "down", before, after],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = dict(kv.split("=") for kv in p.stdout.split())
        self.assertEqual(got["peervm_irq_virtio1_input_per_s"], "200")
        self.assertEqual(got["peervm_irq_virtio1_input_per_gb"], "1000")
        self.assertEqual(got["peervm_irq_RES_per_s"], "50")
        self.assertNotIn("peervm_sirq_NET_RX_per_s", got)
        self.assertEqual(got["peervm_idle_C1_per_s"], "100")
        self.assertEqual(got["peervm_idle_C1_share"], "0.400")
        self.assertEqual(got["homerouter_lan0_tx_queue_0_kicks_per_gb"], "1500")
        self.assertEqual(got["homerouter_lan0_tx_queue_0_kicks_per_s"], "300")


class HostCounters(unittest.TestCase):
    def test_sampler_keeps_exited_threads_and_counts_new_ones(self):
        s = tq.HostSampler(pcores={0})
        busy, irq = {16: 100, 17: 50}, {16: 4, 17: 1}
        parts = s.vm("agent", 7, {"1": thread("qemu-system-x86", "0-23", run=1000),
                                  "2": thread("qemu-system-x86", "16", run=5000, guest=3, stime=1, vcs=2),
                                  "3": thread("vhost-7", "0-23", proc=0, run=100)}, busy, irq)
        got = dict(p.split("=") for p in parts)
        self.assertEqual((got["agent_vcpu_ns"], got["agent_vhost_ns"], got["agent_other_ns"]), ("5000", "100", "1000"))
        self.assertEqual((got["agent_vcpucpu_busy"], got["agent_vcpucpu_irq"], got["agent_vcpucpu_n"]), ("100", "4", "1"))
        # thread 1 exits, thread 4 is born, the vhost worker moves to an E-core
        parts = s.vm("agent", 7, {"2": thread("qemu-system-x86", "16", run=6000, guest=5, stime=2, vcs=3),
                                  "3": thread("vhost-7", "0-23", proc=9, run=150),
                                  "4": thread("qemu-system-x86", "0-23", run=40)}, busy, irq)
        got = dict(p.split("=") for p in parts)
        self.assertEqual((got["agent_vcpu_ns"], got["agent_vhost_ns"], got["agent_other_ns"]), ("6000", "150", "1040"))
        self.assertEqual((got["agent_vcpu_guest"], got["agent_vcpu_stime"], got["agent_vcpu_vcs"]), ("5", "2", "3"))
        self.assertEqual((got["agent_vhostp_ns"], got["agent_vhoste_ns"]), ("0", "50"))

    def test_hostsample_stops_when_its_lab_is_gone(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "123"))
            self.assertTrue(tq.lab_alive(123, d))
            self.assertFalse(tq.lab_alive(124, d))
            lab = subprocess.Popen(["sleep", "0.6"])
            out = os.path.join(d, "samples.txt")
            sampler = subprocess.Popen([sys.executable, TQ, "hostsample", out, "0.1", "--lab-pid=%d" % lab.pid])
            lab.wait()
            try:
                self.assertEqual(sampler.wait(timeout=10), 0)
            finally:
                sampler.kill()
            with open(out) as f:
                rows = f.read().splitlines()
            self.assertGreater(len(rows), 0)
            self.assertNotIn("lab-pid", rows[0])

    def test_hostwin_line_splits_the_vcpu_time(self):
        hz = os.sysconf("SC_CLK_TCK")
        rows = []
        for t, k in ((0.0, 0), (10.0, 1)):
            rows.append({"t": t, "hcpu0": 1000 * hz / 100 * k, "hirq0": 10 * hz / 100 * k,
                         "peer_pid": 42.0, "peer_vcpu_ns": 8e9 * k, "peer_vhost_ns": 1e9 * k, "peer_other_ns": 0.0,
                         "peer_vhostp_ns": 0.0, "peer_vhoste_ns": 1e9 * k,
                         "peer_vcpu_guest": 3 * hz * k, "peer_vcpu_utime": 3.5 * hz * k, "peer_vcpu_stime": 4.5 * hz * k,
                         "peer_vcpu_wait": 0.2e9 * k, "peer_vcpu_vcs": 1000.0 * k, "peer_vcpu_nvcs": 10.0 * k,
                         "peer_vhost_vcs": 500.0 * k,
                         "peer_vcpucpu_busy": 8.5 * hz * k, "peer_vcpucpu_irq": 0.25 * hz * k})
        kvm = [{"t": 0.0, "kvm_42_halt_poll_success_ns": 0.0, "kvm_42_exits": 0.0},
               {"t": 10.0, "kvm_42_halt_poll_success_ns": 4e9, "kvm_42_exits": 1e6}]
        r = {"t_start": "0", "t_end": "10", "window_s": "10", "bytes": "2000000000", "peervm_cpu_share": "0.3"}
        got = dict(x.split("=") for x in tq.hostwin_line(r, rows, hz, set(), kvm))
        want = {"host_peer_vcpu_s": "8.000", "host_peer_s": "9.000", "host_peer_s_per_gb": "4.500",
                "host_peer_vcpu_guest_s": "3.000", "host_peer_vcpu_kvm_s": "4.500", "host_peer_vcpu_qemu_s": "0.500",
                "host_peer_vcpu_wait_s": "0.200", "host_peer_vcpu_blocks_per_s": "100", "host_peer_vcpu_preempt_per_s": "1",
                "host_peer_vhost_blocks_per_s": "50", "host_peer_vcpucpu_irq_s": "0.250", "host_peer_vcpucpu_not_vcpu_s": "0.500",
                "host_peer_vcpu_beyond_guest_s": "5.000", "host_peer_vcpu_beyond_guest_s_per_gb": "2.500",
                "host_peer_kvm_halt_poll_success_s": "4.000", "host_peer_kvm_exits_per_s": "100000",
                "host_qemu_s_per_gb": "4.500", "host_vhost_pcore_frac": "0.00", "host_irq_s": "0.100"}
        for k, v in want.items():
            self.assertEqual(got.get(k), v, k)

    def test_kvmsample_reads_debugfs(self):
        with tempfile.TemporaryDirectory() as d:
            vm = os.path.join(d, "1234-11")
            os.makedirs(os.path.join(vm, "vcpu0"))
            for name, v in (("halt_poll_success_ns", 7), ("exits", 9), ("pages_4k", 3)):
                with open(os.path.join(vm, name), "w") as f:
                    f.write("%d\n" % v)
            out = os.path.join(d, "kvm.txt")
            self.assertEqual(tq.kvmsample(out, "0", d), 0)
            with open(out) as f:
                line = f.read().split()
            self.assertEqual(line[1:], ["kvm_1234_exits=9", "kvm_1234_halt_poll_success_ns=7"])

    def test_pollctl_writes_every_cpu(self):
        with tempfile.TemporaryDirectory() as d:
            for c in (0, 1):
                os.makedirs(os.path.join(d, str(c)))
                with open(os.path.join(d, str(c), "msr"), "wb") as f:
                    f.truncate(tq.MSR_KVM_POLL_CONTROL + 8)
                with open(os.path.join(d, str(c), "cpuid"), "wb") as f:
                    f.seek(tq.KVM_CPUID_FEATURES)
                    f.write(struct.pack("4I", 1 << tq.KVM_FEATURE_POLL_CONTROL, 0, 0, 0))
            self.assertEqual(tq.pollctl("on", d), 0)
            for c in (0, 1):
                with open(os.path.join(d, str(c), "msr"), "rb") as f:
                    f.seek(tq.MSR_KVM_POLL_CONTROL)
                    self.assertEqual(struct.unpack("<Q", f.read(8))[0], 1)
            self.assertEqual(tq.pollctl("off", d), 0)
            with open(os.path.join(d, "1", "msr"), "rb") as f:
                f.seek(tq.MSR_KVM_POLL_CONTROL)
                self.assertEqual(struct.unpack("<Q", f.read(8))[0], 0)
            with open(os.path.join(d, "0", "cpuid"), "r+b") as f:
                f.seek(tq.KVM_CPUID_FEATURES)
                f.write(struct.pack("4I", 0, 0, 0, 0))
            self.assertEqual(tq.pollctl("on", d), 1)



class Placement(unittest.TestCase):
    def test_parse_irq_cpus_sums_one_device_per_cpu(self):
        text = INTERRUPTS + "  30:        900        800  PCI-MSIX-0000:06:00.0   1-edge      virtio12-input.0\n"
        self.assertEqual(tq.parse_irq_cpus(text, "virtio1"), ([116, 229], [25, 27, 24, 26]))
        self.assertEqual(tq.parse_irq_cpus(text, "virtio12"), ([900, 800], [30]))
        self.assertEqual(tq.parse_irq_cpus(text, ""), ([], []))

    def test_irq_affinity_sets_and_reads_back(self):
        with tempfile.TemporaryDirectory() as d:
            for n, eff in ((25, "3"), (26, None)):
                os.makedirs(os.path.join(d, str(n)))
                with open(os.path.join(d, str(n), "smp_affinity_list"), "w") as f:
                    f.write("0-3\n")
                if eff:
                    with open(os.path.join(d, str(n), "effective_affinity_list"), "w") as f:
                        f.write(eff + "\n")
            self.assertEqual(tq.irq_affinity([25, 26], base=d), "3+0-3")
            self.assertEqual(tq.irq_affinity([26], "1", base=d), "1")

    def test_parse_thread_sched(self):
        self.assertEqual(tq.parse_thread_sched("wgft-dataplane (812, #threads: 5)\n---\n"
                                               "se.exec_start                                :     123.4\n"
                                               "se.nr_migrations                             :                   17\n"), 17)
        self.assertIsNone(tq.parse_thread_sched("se.exec_start : 1\n"))

    def test_thread_sampler_counts_cpus_and_follows_the_thread(self):
        with tempfile.TemporaryDirectory() as d:
            def task(tid, comm, state, cpu):
                td = os.path.join(d, "812", "task", str(tid))
                os.makedirs(td, exist_ok=True)
                fields = [state] + ["0"] * 35 + [str(cpu)] + ["0"] * 10
                for name, body in (("comm", comm), ("stat", "%d (%s) %s" % (tid, comm, " ".join(fields))),
                                   ("schedstat", "5000000 2000000 40"), ("sched", "se.nr_migrations : 3")):
                    with open(os.path.join(td, name), "w") as f:
                        f.write(body + "\n")
            task(812, "wgft", "S", 0)
            s = tq.ThreadSampler(812, "wgft-dataplane", 4, proc=d)
            s.sample()
            self.assertEqual((s.samples, s.counters("dp")), (0, []))
            task(813, "wgft-dataplane", "R", 2)
            s.sample()
            s.sample()
            task(813, "wgft-dataplane", "S", 1)
            s.sample()
            got = dict(s.counters("dp"))
            self.assertEqual((got["thr_dp_samples"], got["thr_dp_running"]), (3, 2))
            self.assertEqual([got["thr_dp_oncpu%d" % i] for i in range(4)], [0, 1, 2, 0])
            self.assertEqual((got["thr_dp_run_us"], got["thr_dp_wait_us"], got["thr_dp_mig"], got["thr_dp_now"]),
                             (5000, 2000, 3, 1))
            # the thread goes, then the process
            import shutil
            shutil.rmtree(os.path.join(d, "812", "task", "813"))
            s.sample()
            self.assertTrue(s.alive)
            shutil.rmtree(os.path.join(d, "812"))
            s.sample()
            self.assertFalse(s.alive)

    def test_kthreads_per_cpu(self):
        self.assertEqual(tq.parse_kthread("kworker/3:1-events"), ("kw", 3))
        self.assertEqual(tq.parse_kthread("kworker/12:0H"), ("kw", 12))
        self.assertEqual(tq.parse_kthread("ksoftirqd/1"), ("ksi", 1))
        self.assertEqual(tq.parse_kthread("kworker/u16:2-wg-crypt-wgft0"), ("kwu", -1))
        self.assertIsNone(tq.parse_kthread("iperf3"))
        hz = os.sysconf("SC_CLK_TCK")
        with tempfile.TemporaryDirectory() as d:
            for pid, comm, ut, st in ((10, "kworker/1:0-wg", 1, 2), (11, "kworker/1:1", 3, 4), (12, "ksoftirqd/0", 5, 0),
                                      (13, "kworker/u4:0", 0, 7), (14, "iperf3", 50, 50)):
                os.makedirs(os.path.join(d, str(pid)))
                with open(os.path.join(d, str(pid), "comm"), "w") as f:
                    f.write(comm + "\n")
                with open(os.path.join(d, str(pid), "stat"), "w") as f:
                    f.write("%d (%s) S %s %d %d %s\n" % (pid, comm, " ".join(["0"] * 10), ut, st, " ".join(["0"] * 30)))
            os.makedirs(os.path.join(d, "self"))
            got = dict(tq.kthread_counters(d, ncpu=2))
        tick = 1000000 // hz
        self.assertEqual(got, {"kw_cpu0_us": 0, "kw_cpu1_us": 10 * tick, "ksi_cpu0_us": 5 * tick, "ksi_cpu1_us": 0,
                               "kwu_us": 7 * tick})

    def test_snapdiff_placement(self):
        common = "agentvm_busy_us=%d agentvm_user_us=0 agentvm_sys_us=0 agentvm_soft_us=0 agentvm_irq_us=0 agentvm_steal_us=0 " \
                 "agentvm_cpu0_us=%d agentvm_cpu1_us=%d agentvm_cpu0_soft_us=%d agentvm_cpu1_soft_us=0 agentvm_kw_cpu0_us=%d agentvm_kwu_us=0 agentvm_nicirq_cpu0=%d agentvm_nicirq_cpu1=%d agentvm_nicirq_eff=1 " \
                 "agentvm_thr_dp_samples=%d agentvm_thr_dp_running=%d agentvm_thr_dp_oncpu0=%d agentvm_thr_dp_oncpu1=%d " \
                 "agentvm_thr_dp_wait_us=%d agentvm_thr_dp_mig=%d"
        before = common % (0, 0, 0, 0, 0, 100, 100, 10, 10, 5, 5, 0, 4)
        after = common % (15000000, 5000000, 10000000, 3000000, 2000000, 400, 1000, 210, 200, 55, 155, 500000, 6)
        p = subprocess.run([sys.executable, TQ, "snapdiff", "2000000000", "10", "up", before, after],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = dict(kv.split("=") for kv in p.stdout.split())
        self.assertEqual((got["agentvm_cpu0_busy"], got["agentvm_cpu1_busy"]), ("0.50", "1.00"))
        self.assertEqual((got["agentvm_cpu0_soft"], got["agentvm_cpu1_soft"]), ("0.30", "0.00"))
        self.assertEqual((got["agentvm_cpu0_kw"], got["agentvm_kwu"]), ("0.20", "0.00"))
        self.assertEqual((got["agentvm_nicirq_cpu0_frac"], got["agentvm_nicirq_cpu1_frac"], got["agentvm_nicirq_top_cpu"]),
                         ("0.25", "0.75", "1"))
        self.assertEqual(got["agentvm_nicirq_eff"], "1")
        self.assertEqual((got["agentvm_thr_dp_cpu0_frac"], got["agentvm_thr_dp_cpu1_frac"]), ("0.25", "0.75"))
        self.assertEqual((got["agentvm_thr_dp_running_frac"], got["agentvm_thr_dp_mig"], got["agentvm_thr_dp_wait_share"]),
                         ("0.95", "2", "0.050"))
        # 0.25 * 0.25 + 0.75 * 0.75
        self.assertEqual(got["agentvm_thr_dp_on_nicirq_frac"], "0.62")
        # the existing values stay as they were
        self.assertEqual((got["agentvm_cpu_share"], got["agentvm_maxcpu"]), ("1.500", "1.00"))


if __name__ == "__main__":
    unittest.main()
