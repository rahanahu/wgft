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

    def test_split_log_gets_the_guest_mode_ratio(self):
        # host_agent_vcpu_guest_s over the bytes: x 1.2 s and y 1.0 s for 1 GB each give 1.2
        def host(rnd, run, arm):
            return "bytes=1000000000 window_s=10 host_agent_vcpu_guest_s=%s host_peer_vcpu_guest_s=2" % (
                "1.2" if arm == "x" else "1.0")
        rc, out = analyse(self.split_log(host))
        self.assertEqual(rc, 0, out)
        self.assertIn("AGENTVMGUESTRATIO x_over_y=1.200 ci95_low=1.200 ci95_high=1.200 pairs=8 ", out)
        self.assertIn("AGENTVMGUESTCPU arm=x name=new runs=8 cpu_s_per_gb=1.200 ", out)
        self.assertRegex(out, r"AGENTVMGUESTCPU arm=y .* agentvm_guest_share=0.10\n")
        self.assertIn("PEERVMGUESTRATIO x_over_y=1.000 ", out)
        # the decision lines come before the /proc/stat ones
        self.assertLess(out.index("AGENTVMGUESTRATIO"), out.index("AGENTVMRATIO"))
        # without the host's samples there is no guest ratio, and the log says the VM ratio is reference only
        rc, out = analyse(self.split_log(lambda rnd, run, arm: ""))
        self.assertNotIn("AGENTVMGUESTRATIO", out)
        self.assertIn("AGENTVMGUEST unavailable: ", out)
        self.assertIn("AGENTVMRATIO x_over_y=0.800 ", out)

    def test_run_without_guest_time_is_left_out_of_the_guest_ratio_only(self):
        def host(rnd, run, arm):
            if (rnd, run, arm) == (2, 1, "x"):
                return "bytes=1000000000 window_s=10"
            return "bytes=1000000000 window_s=10 host_agent_vcpu_guest_s=%s" % ("1.2" if arm == "x" else "1.0")
        rc, out = analyse(self.split_log(host))
        self.assertEqual(rc, 0, out)
        self.assertIn("AGENTVMGUESTRATIO x_over_y=1.200 ci95_low=1.200 ci95_high=1.200 pairs=7 left_out=1 ", out)
        self.assertIn("AGENTVMGUESTLEFT_OUT planned=8 used=7 missing=0 failed=1 ", out)
        self.assertIn("AGENTVMRATIO x_over_y=0.800 ci95_low=0.800 ci95_high=0.800 pairs=8 left_out=0 ", out)
        self.assertNotIn("AGENTVMGUEST unavailable", out)

    @staticmethod
    def consistency_host(bad=(), kvm_bad="4.8", tick=None, extra=None):
        # vCPU run time 10 s, KVM 4 s, qemu 0 s, so the guest estimate (run - KVM - qemu) is 6 s. The tick guest
        # time is 6 s unless tick(arm) says else; a run in `bad` has KVM kvm_bad (4.8 s: tick consistency 1.08,
        # estimate 5.2 s). y moves 1.2 GB, so the ratio x/y of the 6 s guest time is 1.2
        def host(rnd, run, arm):
            return ("bytes=%d window_s=10 host_agent_vcpu_s=10 host_agent_vcpu_guest_s=%s host_agent_vcpu_kvm_s=%s "
                    "host_agent_vcpu_qemu_s=0 %s"
                    % (1000000000 if arm == "x" else 1200000000, tick(arm) if tick else "6",
                       kvm_bad if (rnd, run, arm) in bad else "4.0", extra(rnd, run, arm) if extra else ""))
        return host

    @staticmethod
    def guest_ratio(out):
        return out.split("AGENTVMGUESTRATIO ")[1].split("\n")[0]

    def test_consistent_run_keeps_its_value(self):
        rc, out = analyse(self.split_log(self.consistency_host()))
        self.assertEqual(rc, 0, out)
        self.assertIn("AGENTVMGUESTCONSISTENCY arm=x name=new flagged=0 of 8 checked runs worst=1.000 guest=run-kvm-qemu in 8 runs;", out)
        self.assertIn("AGENTVMGUESTCONSISTENCY arm=y name=old flagged=0 of 8 checked runs worst=1.000 guest=run-kvm-qemu in 8 runs;", out)
        self.assertIn("x_over_y=1.200 ci95_low=1.200 ci95_high=1.200 pairs=8 left_out=0 ", self.guest_ratio(out))

    def test_every_run_uses_run_less_kvm_and_qemu_not_the_tick_value(self):
        # tick guest 9 s in x and 6 s in y would give 1.8; run - KVM = 6 s in both gives 1.2
        rc, out = analyse(self.split_log(self.consistency_host(tick=lambda arm: "9" if arm == "x" else "6")))
        self.assertEqual(rc, 0, out)
        self.assertIn("x_over_y=1.200 ci95_low=1.200 ci95_high=1.200 pairs=8 ", self.guest_ratio(out))
        self.assertIn("flagged=8 of 8 checked runs worst=1.300", out)
        self.assertNotIn("NOT DECIDABLE", out)

    def test_flagged_run_is_a_diagnostic_only(self):
        # y round 2 run 1: KVM 4.8 s, so the tick consistency is 1.08 and the estimate 5.2 s instead of 6 s
        rc, out = analyse(self.split_log(self.consistency_host({(2, 1, "y")})))
        self.assertEqual(rc, 0, out)
        self.assertIn("AGENTVMGUESTCONSISTENCY arm=y name=old flagged=1 of 8 checked runs worst=1.080 guest=run-kvm-qemu in 8 runs;", out)
        self.assertIn("AGENTVMGUESTCONSISTENCY arm=x name=new flagged=0 of 8 checked runs worst=1.000 ", out)
        self.assertRegex(out, r"AGENTVMGUESTLEFT_OUT planned=8 used=8 missing=0 failed=0 sync_timeout=0 sender_bound=0\n")
        self.assertIn("pairs=8 left_out=0 ", self.guest_ratio(out))
        self.assertNotIn("ci95_high=1.200", self.guest_ratio(out))

    def test_low_side_is_flagged_too(self):
        rc, out = analyse(self.split_log(self.consistency_host({(1, 1, "x")}, kvm_bad="3.0")))
        self.assertIn("AGENTVMGUESTCONSISTENCY arm=x name=new flagged=1 of 8 checked runs worst=0.900 ", out)

    def test_qemu_user_time_counts_in_the_diagnostic_and_the_estimate(self):
        # tick 6 + KVM 4 + qemu 0.5 = 1.05 of the run time; the estimate is 10 - 4 - 0.5 = 5.5 s
        rc, out = analyse(self.split_log(self.consistency_host(
            extra=lambda r, n, a: "host_agent_vcpu_qemu_s=0.5")))
        self.assertIn("flagged=8 of 8 checked runs worst=1.050 ", out)
        self.assertIn("agentvm_guest_share=0.55\n", out)

    def test_half_the_runs_flagged_still_gives_a_ratio(self):
        bad = {(1, 1, "x"), (2, 1, "y"), (3, 1, "x"), (4, 1, "y")}
        rc, out = analyse(self.split_log(self.consistency_host(bad)))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("NOT DECIDABLE", out)
        self.assertIn("pairs=8 left_out=0 ", self.guest_ratio(out))

    def test_arm_asymmetric_flags_warn(self):
        bad = {(1, 1, "x"), (2, 1, "x"), (3, 1, "x")}
        rc, out = analyse(self.split_log(self.consistency_host(bad)))
        self.assertIn("AGENTVMGUESTWARN guest_inconsistent x=3 y=0: ", out)

    def test_mixed_log_checks_and_estimates_only_runs_with_the_fields(self):
        def host(rnd, run, arm):
            if (rnd, run) == (1, 1):
                return "bytes=1000000000 window_s=10 host_agent_vcpu_guest_s=6"
            return self.consistency_host()(rnd, run, arm)
        rc, out = analyse(self.split_log(host))
        self.assertEqual(rc, 0, out)
        self.assertIn("flagged=0 of 7 checked runs worst=1.000 unchecked=1 guest=run-kvm-qemu in 7 runs;", out)
        self.assertNotIn("CONSISTENCY unavailable", out)

    def test_peer_bound_and_flagged_pair_counts_once_as_peer_bound(self):
        bound = {(1, 1, "x")}
        host = self.consistency_host({(1, 1, "x")}, extra=lambda r, n, a: self.peer_fields(
            [(0.99, 0.99)] if (r, n, a) in bound else [(0.80, 0.20)]))
        rc, out = analyse(self.split_log(host))
        self.assertRegex(out, r"AGENTVMGUESTLEFT_OUT planned=8 used=7 missing=0 failed=0 sync_timeout=0 sender_bound=0 peer_bound=1 ")
        self.assertIn("flagged=0 of 7 checked runs", out)

    def test_peer_vm_uses_the_same_basis(self):
        # peer tick guest 9 s in x and 6 s in y would give 1.8; run - KVM = 6 s in both gives 1.2
        def extra(rnd, run, arm):
            return "host_peer_vcpu_s=10 host_peer_vcpu_guest_s=%s host_peer_vcpu_kvm_s=%s host_peer_vcpu_qemu_s=0" % (
                "9" if arm == "x" else "6", "4.8" if (rnd, run, arm) == (1, 1, "x") else "4.0")
        rc, out = analyse(self.split_log(self.consistency_host(extra=extra)))
        self.assertIn("PEERVMGUESTCONSISTENCY arm=x name=new flagged=8 of 8 checked runs worst=1.380 guest=run-kvm-qemu in 8 runs;", out)
        self.assertIn("PEERVMGUESTCONSISTENCY arm=y name=old flagged=0 of 8 checked runs worst=1.000 guest=run-kvm-qemu in 8 runs;", out)
        self.assertRegex(out, r"PEERVMGUESTRATIO x_over_y=1\.[12]\d\d ")
        self.assertNotIn("PEERVMGUESTRATIO x_over_y=1.800", out)

    def test_log_without_consistency_fields_keeps_the_tick_value(self):
        def host(rnd, run, arm):
            return "bytes=1000000000 window_s=10 host_agent_vcpu_guest_s=%s" % ("1.2" if arm == "x" else "1.0")
        rc, out = analyse(self.split_log(host))
        self.assertEqual(rc, 0, out)
        self.assertIn("AGENTVMGUESTCONSISTENCY unavailable: ", out)
        self.assertIn("AGENTVMGUESTRATIO x_over_y=1.200 ci95_low=1.200 ci95_high=1.200 pairs=8 ", out)

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
                (base + ["rust", "kernel"], "setup.txt fast --tool iperf3\n", "dash or underscore only"),
                (base + ["--max-wall", "1h", "rust", "kernel"], good, "--max-wall wants a whole number of seconds"),
        ):
            rc, err = self.lab_paired(args, cases)
            self.assertEqual(rc, 1, err)
            self.assertIn(want, err)
        # --placement apart-mt: 3 vCPUs at least, and rust or kernel arms only
        for args, want in ((["--split", "--placement", "apart-mt", "--vcpus", "3", "--tool", "iperf3", "fast", "rust", "kernel"],
                            "wants --vcpus 4 or more"),
                           (["--split", "--placement", "apart-mt", "--vcpus", "4", "--tool", "iperf3", "fast", "gvisor", "rust"],
                            "--placement apart-mt places the Rust agent's data-plane thread and crypto workers"),
                           (["--split", "--placement", "apart-st", "fast", "rust", "kernel"], "--placement wants apart or apart-mt")):
            rc, err = self.lab_paired(args)
            self.assertEqual(rc, 1, err)
            self.assertIn(want, err)
        rc, err = self.lab_paired(["--split", "--placement", "apart-mt", "--vcpus", "4", "--tool", "iperf3", "fast", "rust", "kernel"])
        self.assertIn("/proc/wgft-no-such-dir", err)
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

    def test_peer_series_marks_runs_saturated_for_part_of_the_window(self):
        # vCPU 1 saturated, with its workers, in 3 of 20 intervals of (2, 2, y): whole-window averages
        # stay low, the series rule marks it; (3, 1, x) is saturated in 1 interval only and kept
        def peer(rnd, run, arm):
            # (4, 1, y): 2 of 21 intervals, 0.095, prints as 0.10 but stays below the threshold
            sat, n = {(2, 2, "y"): (3, 20), (3, 1, "x"): (1, 20), (4, 1, "y"): (2, 21)}.get((rnd, run, arm), (0, 20))
            return self.peer_fields([(0.30, 0.10), (0.80, 0.25)]) + \
                " peervm_series_intervals=%d peervm_sat_intervals=%d peervm_sat_frac=%.2f" % (n, sat, sat / n)
        rc, out = analyse(self.split_log(peer))
        self.assertEqual(rc, 0, out)
        self.assertIn("LEFT_OUT planned=8 used=7 missing=0 failed=0 sync_timeout=0 sender_bound=0 peer_bound=1 "
                      "peer_bound_x=0 peer_bound_y=1\n", out)
        # the whole-window rule alone, for comparison
        self.assertIn("\nWHOLEWINDOW LEFT_OUT planned=8 used=8 ", out)
        self.assertIn("\nWHOLEWINDOW MBITRATIO key=overall_mbit ", out)
        # per arm: x has 1 saturated interval in 8 runs, y 5
        self.assertIn("\nPEERSERIES threshold=0.10 x_sat_frac_mean=0.006 y_sat_frac_mean=0.031 x_sat_intervals=1 y_sat_intervals=5 ", out)
        self.assertIn("\nWARN peer series x=1 y=5: ", out)
        # the threshold re-picked when the log is analysed again
        os.environ["WGFT_LAB_PEER_SAT_FRAC"] = "0.05"
        try:
            rc, out = analyse(self.split_log(peer))
        finally:
            del os.environ["WGFT_LAB_PEER_SAT_FRAC"]
        self.assertIn("peer_bound=3 peer_bound_x=1 peer_bound_y=2\n", out)
        self.assertIn("PEERSERIES threshold=0.05 ", out)
        # no difference between the rules: no comparison lines
        rc, out = analyse(self.split_log(lambda rnd, run, arm: self.peer_fields([(0.80, 0.25)]) +
                                         " peervm_series_intervals=20 peervm_sat_intervals=0 peervm_sat_frac=0.00"))
        self.assertNotIn("WHOLEWINDOW", out)
        self.assertNotIn("WARN peer series", out)

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


class PeerSeries(unittest.TestCase):
    def test_sum_counts_saturated_intervals_in_the_window(self):
        rows, busy, kw = [], [0, 0], [0, 0]
        for i in range(12):
            # vCPU 1: busy 1.0 with workers 0.95 in intervals 3 and 4, busy 1.0 without workers in 6
            db = [0.3, 1.0 if i in (3, 4, 6) else 0.5]
            dk = [0.0, 0.95 if i in (3, 4) else 0.1]
            rows.append(tq.peerseries_row({0: busy[0], 1: busy[1]}, {0: kw[0], 1: kw[1]}, 100 + 0.5 * i) + " tcpmem=%d" % (1000 * i))
            busy = [b + int(d * 500000) for b, d in zip(busy, db)]
            kw = [k + int(d * 500000) for k, d in zip(kw, dk)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "series")
            with open(path, "w") as f:
                f.write("\n".join(rows) + "\n")
            got = dict(kv.split("=") for kv in tq.peerseries_sum(path, "100", "105.5").split())
            self.assertEqual((got["peervm_series_intervals"], got["peervm_sat_intervals"], got["peervm_sat_frac"]), ("11", "2", "0.18"))
            self.assertEqual(got["peervm_maxcpu_peak"], "1.00")
            self.assertEqual(got["peervm_tcpmem_peak_mb"], "%.1f" % (11000 * os.sysconf("SC_PAGE_SIZE") / 1048576))
            # a window holding only intervals 0 to 2
            got = dict(kv.split("=") for kv in tq.peerseries_sum(path, "100", "101.5").split())
            self.assertEqual((got["peervm_sat_intervals"], got["peervm_sat_frac"]), ("0", "0.00"))
            self.assertEqual(tq.peerseries_sum(path, "200", "201"), "")

    def test_peerseries_runs_and_stops(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "series")
            self.assertEqual(tq.peerseries(path, "0.1", "0.45"), 0)
            with open(path) as f:
                rows = [dict(kv.split("=") for kv in l.split()) for l in f]
        self.assertGreaterEqual(len(rows), 3)
        self.assertIn("cpu0", rows[0])
        self.assertIn("kw0", rows[0])
        self.assertIn("tcpmem", rows[0])
        # the bound workers' time is counted from the first sample on, so it does not jump
        for a, b in zip(rows, rows[1:]):
            dt = (float(b["t"]) - float(a["t"])) * 1e6
            for k in a:
                if k.startswith("kw"):
                    self.assertLessEqual(int(b[k]) - int(a[k]), dt * 1.5 + 20000)


class TcpMemory(unittest.TestCase):
    def test_parse_tcpmem(self):
        sockstat = "sockets: used 120\nTCP: inuse 9 orphan 0 tw 3 alloc 12 mem 20480\nUDP: inuse 2 mem 4\n"
        self.assertEqual(tq.parse_tcpmem(sockstat, "45984\t61312\t91968\n"),
                         [("tcpmem_pages", 20480), ("tcp_mem_pressure_pages", 61312), ("tcp_mem_max_pages", 91968)])
        self.assertEqual(tq.parse_tcpmem("TCP: inuse 0\n", "1 2\n"), [])

    def test_snapdiff_tcpmem(self):
        common = "peervm_busy_us=%d peervm_user_us=0 peervm_sys_us=0 peervm_soft_us=0 peervm_irq_us=0 peervm_steal_us=0 " \
                 "peervm_tcpmem_pages=%d peervm_tcp_mem_pressure_pages=163840 peervm_tcp_mem_max_pages=163840 " \
                 "snmp_client_tcp_ofodrop=%d snmp_client_tcp_mempressures=%d snmp_client_tcp_rcvpruned=0"
        p = subprocess.run([sys.executable, TQ, "snapdiff", "2000000000", "10", "up", common % (0, 256, 5, 0),
                            common % (1000000, 131072, 105, 2)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = dict(kv.split("=") for kv in p.stdout.split())
        pg = os.sysconf("SC_PAGE_SIZE")
        self.assertEqual(got["peervm_tcpmem_start_mb"], "%.1f" % (256 * pg / 1048576))
        self.assertEqual(got["peervm_tcpmem_end_mb"], "%.1f" % (131072 * pg / 1048576))
        self.assertEqual(got["peervm_tcp_mem_max_mb"], "%.0f" % (163840 * pg / 1048576))
        self.assertEqual((got["client_tcp_ofodrop"], got["client_tcp_mempressures"]), ("100", "2"))
        self.assertNotIn("client_tcp_rcvpruned", got)

    def test_snmp_keys_cover_memory_pressure(self):
        for name in ("PruneCalled", "RcvPruned", "OfoPruned", "TCPOFODrop", "TCPMemoryPressures", "TCPAbortOnMemory"):
            self.assertIn(("TcpExt", name), tq.SNMP_KEYS)


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
        # the pinned vCPU thread on its own, by its host CPU, cumulative
        self.assertEqual((got["agent_pv16_run_ns"], got["agent_pv16_guest"], got["agent_pv16_stime"]), ("6000", "5", "2"))
        self.assertNotIn("agent_pv0-23_run_ns", got)

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
                         "peer_vcpucpu_busy": 8.5 * hz * k, "peer_vcpucpu_irq": 0.25 * hz * k,
                         "peer_pv9_run_ns": 6e9 * k, "peer_pv9_guest": 1 * hz * k, "peer_pv9_stime": 4.5 * hz * k,
                         "peer_pv8_run_ns": 2e9 * k, "peer_pv8_guest": 2 * hz * k, "peer_pv8_stime": 0.0})
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
                "host_qemu_s_per_gb": "4.500", "host_vhost_pcore_frac": "0.00", "host_irq_s": "0.100",
                # vCPUs in the order of their host CPUs: 8 is vCPU 0, 9 is vCPU 1
                "host_peer_vcpu0_run_share": "0.200", "host_peer_vcpu0_guest_share": "0.200",
                "host_peer_vcpu0_kvm_share": "0.000", "host_peer_vcpu1_run_share": "0.600",
                "host_peer_vcpu1_guest_share": "0.100", "host_peer_vcpu1_kvm_share": "0.450"}
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

    def test_threads_sampler_groups_every_thread(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            def task(tid, comm, state, cpu, run, wait, mig):
                td = os.path.join(d, "812", "task", str(tid))
                os.makedirs(td, exist_ok=True)
                fields = [state] + ["0"] * 35 + [str(cpu)] + ["0"] * 10
                for name, body in (("comm", comm), ("stat", "%d (%s) %s" % (tid, comm, " ".join(fields))),
                                   ("schedstat", "%d %d 1" % (run * 1000, wait * 1000)), ("sched", "se.nr_migrations : %d" % mig)):
                    with open(os.path.join(td, name), "w") as f:
                        f.write(body + "\n")
            task(812, "wgft", "S", 0, 10, 0, 0)
            task(813, "wgft-dataplane", "R", 1, 100, 5, 1)
            task(814, "wgft-crypto", "R", 2, 50, 1, 0)
            task(815, "wgft-crypto", "S", 3, 40, 2, 0)
            s = tq.ThreadsSampler(812, 4, proc=d)
            first = dict(s.counters())
            s.sample()
            s.sample()
            # a worker goes, another one comes
            shutil.rmtree(os.path.join(d, "812", "task", "815"))
            task(816, "wgft-crypto", "R", 2, 7, 0, 3)
            task(813, "wgft-dataplane", "R", 1, 160, 9, 1)
            s.sample()
            got = dict(s.counters())
        self.assertEqual([got["thr_dp_oncpu%d" % i] for i in range(4)], [0, 3, 0, 0])
        self.assertEqual([got["thr_crypto_oncpu%d" % i] for i in range(4)], [0, 0, 4, 2])
        self.assertEqual((got["thr_crypto_samples"], got["thr_crypto_running"]), (6, 4))
        self.assertEqual((got["thr_other_samples"], got["thr_other_oncpu0"]), (3, 3))
        # the run time grows by the increments only; the worker that went keeps what it had
        self.assertEqual(got["thr_dp_run_us"] - first["thr_dp_run_us"], 60)
        self.assertEqual(got["thr_crypto_run_us"] - first["thr_crypto_run_us"], 7)
        self.assertEqual(got["thr_crypto_mig"] - first["thr_crypto_mig"], 3)

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


class ManyConnections(unittest.TestCase):
    @staticmethod
    def iperf_json(d, name, streams, seconds=10.0):
        import json
        path = os.path.join(d, name)
        with open(path, "w") as f:
            json.dump({"end": {"sum_received": {"bytes": sum(streams), "seconds": seconds,
                                                "bits_per_second": sum(streams) * 8 / seconds},
                               "sum_sent": {"bytes": sum(streams), "retransmits": 3},
                               "streams": [{"receiver": {"bytes": b, "seconds": seconds}} for b in streams]}}, f)
        return path

    def test_iperf_adds_up_several_clients(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.iperf_json(d, "a.json", [1000000, 1000000])
            b = self.iperf_json(d, "b.json", [1000000, 0], seconds=9.5)
            p = subprocess.run([sys.executable, TQ, "iperf", a, b], capture_output=True, text=True)
        got = dict(kv.split("=") for kv in p.stdout.split())
        self.assertEqual((got["received"], got["duration_s"], got["retransmits"]), ("3000000", "10.000", "6"))
        # Jain over the four streams: 3^2 / (4 * 3) in units of 1 MB
        self.assertEqual((got["stream_jain"], got["stream_min_over_max"], got["stream_zero"]), ("0.7500", "0.000", "1"))
        self.assertEqual((got["stream_min_mbit"], got["stream_max_mbit"]), ("0.000", "0.842"))

    def test_iperf_fails_the_run_when_one_client_failed(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.iperf_json(d, "a.json", [1000000, 1000000])
            b = os.path.join(d, "b.json")
            with open(b, "w") as f:
                f.write('{"error": "unable to connect stream"}')
            p = subprocess.run([sys.executable, TQ, "iperf", a, b], capture_output=True, text=True)
        self.assertTrue(p.stdout.startswith("received=0 "), p.stdout)

    def test_agent_log_counts_keeps_the_latest_count_of_each_kind(self):
        log = "\n".join([
            "2026/11/07 memory bound: 1981 MiB, derived from the flow caps",
            "2026/11/07 wgstack: evicted the oldest TIME_WAIT rows because the table was full; 10 since the tunnel was built",
            "2026/11/07 wgstack: evicted the oldest TIME_WAIT rows because the table was full; 250 since the tunnel was built",
            "2026/11/07 wgstack: dropped control packets because the control output ring was full; 3 since the tunnel was built",
            "2026/11/07 wgstack: dropped TCP handshakes that advertise an MSS below 64; 2 dropped since the tunnel was built; peers",
            "2026/11/07 wgstack: dropped UDP datagrams because receiving sockets are not read fast enough; 4 over the per-socket "
            "limit of 1 bytes and 2 datagrams, 5 over the tunnel budget of 3 bytes and 4 datagrams, since the tunnel was built",
            "2026/11/07 tcp/41800: rule cap reached; refusing new connections",
            "2026/11/07 wgstack: SomethingNew; 7 since the tunnel was built",
        ])
        self.assertEqual(tq.agent_log_counts(log), {
            "agent_bound_mib": 1981, "wg_tw_evicted": 250, "wg_ctl_dropped": 3, "wg_mss_floor": 2,
            "wg_udp_endpoint_full": 4, "wg_udp_tunnel_full": 5, "relay_tcp_refusing_lines": 1, "wg_other_lines": 1})

    def test_manyconn_reads_a_churn_case(self):
        line = ("PAIRED round=%d run=1 arm=%s vm=%s name=%s pass=1 sync=go bytes=4000000 window_s=10 "
                "churn_rate=1000 churn_ok=10000 churn_planned=10000 churn_refused=0 churn_ok_per_s=1000.0 "
                "churn_connect_p50_ms=0.5 churn_connect_p99_ms=%s host_agent_vcpu_guest_s=%s agent_rss_mib=40.0 "
                "wg_tw_evicted=%d client_tcp_synretrans=4")
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "churn-1000"))
            path = os.path.join(d, "churn-1000", "paired.log")
            with open(path, "w") as f:
                f.write("PLAN rounds=2 runs=1\n")
                for rnd, arm, vm, name, p99, g, ev in ((1, "x", "a", "rust", "2.0", "1.0", 0), (1, "y", "b", "kernel", "1.0", "0.5", 0),
                                                       (2, "x", "b", "rust", "4.0", "3.0", 9), (2, "y", "a", "kernel", "1.0", "0.5", 0)):
                    f.write(line % (rnd, arm, vm, name, p99, g, ev) + "\n")
            p = subprocess.run([sys.executable, TQ, "manyconn", path], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        x = dict(kv.split("=") for kv in p.stdout.splitlines()[0].split()[1:])
        self.assertEqual((x["case"], x["name"], x["runs"], x["churn_ok"], x["churn_connect_p99_ms"]),
                         ("churn-1000", "rust", "2", "20000", "3"))
        # median of 100 and 300 us per connection; the eviction count is the largest; SYN retransmits add up
        self.assertEqual((x["agentvm_guest_us_per_conn"], x["wg_tw_evicted"], x["client_tcp_synretrans"]), ("200.0", "9", "8"))


class RxQueueTools(unittest.TestCase):
    """The measurement tools for the receive-path benchmark: one-way UDP delays, a series by time, the heavy UDP
    sender and its sink, the extra iperf3 flows and the parsed ss samples."""

    def run_tq(self, *args):
        p = subprocess.run([sys.executable, TQ, *args], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    @staticmethod
    def free_port():
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_uping_one_way_delays_against_a_stamping_echo(self):
        port = self.free_port()
        echo = subprocess.Popen([sys.executable, TQ, "uecho", "127.0.0.1", str(port), "stamp"])
        try:
            import time
            time.sleep(0.5)
            with tempfile.TemporaryDirectory() as d:
                samples = os.path.join(d, "s.txt")
                out = self.run_tq("uping", "127.0.0.1", str(port), "0.5", "10", "u", samples)
                got = dict(kv.split("=") for kv in out.split())
                for k in ("u_p95_ms", "u_fwd_p50_ms", "u_fwd_p99_ms", "u_ret_p95_ms", "u_ret_max_ms"):
                    self.assertIn(k, got)
                self.assertEqual(got["u_lost"], "0")
                start, rows = tq.read_usamples(samples)
                self.assertGreater(start, 1e9)
                self.assertEqual(len(rows), int(got["u_sent"]))
                self.assertTrue(all(r[3] is not None and r[4] is not None for r in rows))
                # the two halves of a ping are differences on the one clock, so they add up to its round trip
                self.assertTrue(all(abs(r[3] + r[4] - r[2]) < 0.01 for r in rows))
                series = self.run_tq("useries", samples, "0.25").splitlines()
                self.assertTrue(series[0].startswith("USERIES start_epoch="))
                self.assertGreaterEqual(len(series), 3)
                self.assertIn("rtt_p95_ms=", series[1])
        finally:
            echo.kill()
            echo.wait()

    def test_uping_without_a_stamp_has_no_one_way_delays(self):
        port = self.free_port()
        echo = subprocess.Popen([sys.executable, TQ, "uecho", "127.0.0.1", str(port)])
        try:
            import time
            time.sleep(0.5)
            out = self.run_tq("uping", "127.0.0.1", str(port), "0.3", "10", "u")
            self.assertIn("u_p95_ms=", out)
            self.assertNotIn("_fwd_", out)
        finally:
            echo.kill()
            echo.wait()

    def test_ubuckets_split_by_send_time_and_count_losses(self):
        rows = [(0, 0.1, 1.0, 0.4, 0.6), (1, 0.6, 3.0, 1.0, 2.0), (2, 1.2, None, None, None), (3, 1.4, 2.0, None, None),
                (4, 2.5, 5.0, 2.0, 3.0)]
        b = tq.ubuckets(rows, 1.0)
        self.assertEqual([(d["t"], d["sent"], d["lost"]) for d in b], [(0, 2, 0), (1, 2, 1), (2, 1, 0)])
        self.assertEqual(b[0]["rtt"], [1.0, 3.0, 3.0, 3.0])
        self.assertEqual(b[0]["fwd"], [0.4, 1.0, 1.0, 1.0])
        # the bucket with one echoed ping and no stamp has no one-way values
        self.assertEqual(b[1]["rtt"], [2.0, 2.0, 2.0, 2.0])
        self.assertIsNone(b[1]["fwd"])

    def test_ublast_reaches_the_rate_and_the_sink_counts(self):
        import time
        port = self.free_port()
        with tempfile.TemporaryDirectory() as d:
            stats = os.path.join(d, "stats")
            sink = subprocess.Popen([sys.executable, TQ, "usink", "127.0.0.1", str(port), stats])
            try:
                for _ in range(50):
                    if os.path.exists(stats):
                        break
                    time.sleep(0.1)
                out = dict(kv.split("=") for kv in self.run_tq("ublast", "127.0.0.1", str(port), "40", "1", "1000").split())
                time.sleep(1.2)
                with open(stats) as fh:
                    got = dict(kv.split("=") for kv in fh.read().split())
            finally:
                sink.kill()
                sink.wait()
        # 40 Mbit/s of 1000-byte datagrams is 5000 a second
        self.assertAlmostEqual(int(out["udp_blast_sent"]), 5000, delta=300)
        self.assertAlmostEqual(float(out["udp_blast_mbit"]), 40, delta=3)
        self.assertEqual(int(out["udp_blast_bytes"]), int(out["udp_blast_sent"]) * 1000)
        self.assertGreater(int(got["recv"]), 0.9 * int(out["udp_blast_sent"]))
        self.assertEqual(int(got["bytes"]), int(got["recv"]) * 1000)

    def test_ublast_counts_a_refused_send_as_an_error_not_as_sent(self):
        # nothing listens on the port, so the ICMP port unreachable makes later sends fail with ECONNREFUSED
        port = self.free_port()
        out = dict(kv.split("=") for kv in self.run_tq("ublast", "127.0.0.1", str(port), "40", "1", "1000").split())
        sent, err = int(out["udp_blast_sent"]), int(out["udp_blast_send_err"])
        self.assertGreater(err, 0)
        self.assertAlmostEqual(sent + err, 5000, delta=300)
        self.assertEqual(int(out["udp_blast_bytes"]), sent * 1000)

    IPERF = {"end": {"sum_received": {"bytes": 1000000, "seconds": 2.0, "bits_per_second": 4000000.0},
                     "sum_sent": {"bytes": 1000500, "retransmits": 3},
                     "streams": [{"receiver": {"bytes": 600000}}, {"receiver": {"bytes": 400000}}]},
             "intervals": [{"sum": {"start": 0, "end": 1, "bits_per_second": 3e6, "retransmits": 1}},
                           {"sum": {"start": 1, "end": 2, "bits_per_second": 5e6, "retransmits": 2}}]}
    LATE = {"end": {"sum_received": {"bytes": 500000, "seconds": 1.0, "bits_per_second": 4000000.0},
                    "sum_sent": {"bytes": 500100, "retransmits": 2}}}

    @staticmethod
    def write_json(d, name, obj):
        import json
        path = os.path.join(d, name)
        with open(path, "w") as f:
            json.dump(obj, f)
        return path

    def test_iperf_adds_the_late_flow_and_keeps_the_main_duration(self):
        with tempfile.TemporaryDirectory() as d:
            main = self.write_json(d, "m.json", self.IPERF)
            late = self.write_json(d, "l.json", self.LATE)
            alone = dict(kv.split("=") for kv in self.run_tq("iperf", main).split())
            both = dict(kv.split("=") for kv in self.run_tq("iperf", "--late", late, main).split())
            x = self.run_tq("iperfx", late, "late").split()
            series = self.run_tq("iperfseries", main).splitlines()
            missing = self.run_tq("iperfx", os.path.join(d, "none.json"), "cross")
        self.assertEqual((alone["received"], alone["mbit"], alone["retransmits"]), ("1000000", "4.00", "3"))
        self.assertEqual((both["received"], both["sent"], both["retransmits"], both["duration_s"]),
                         ("1500000", "1500600", "5", "2.000"))
        self.assertEqual(both["mbit"], "6.00")
        # fairness is the main streams' alone
        self.assertEqual(alone["stream_jain"], both["stream_jain"])
        self.assertEqual(x, ["late_mbit=4.00", "late_bytes=500000", "late_retransmits=2"])
        self.assertEqual(series, ["IPERFSERIES start_s=0.0 end_s=1.0 mbit=3.00 retransmits=1",
                                  "IPERFSERIES start_s=1.0 end_s=2.0 mbit=5.00 retransmits=2"])
        self.assertEqual(missing.split(), ["cross_mbit=0", "cross_bytes=0", "cross_retransmits=-", "cross_error=1"])

    def test_iperf_merges_parallel_clients_and_a_late_flow(self):
        # two parallel clients of the main streams, and a late flow: the semantics of #902 and #903 together
        with tempfile.TemporaryDirectory() as d:
            a = ManyConnections.iperf_json(d, "a.json", [1000000, 1000000])
            b = ManyConnections.iperf_json(d, "b.json", [1000000, 0], seconds=9.5)
            late = self.write_json(d, "l.json", self.LATE)
            main_only = dict(kv.split("=") for kv in self.run_tq("iperf", a, b).split())
            got = dict(kv.split("=") for kv in self.run_tq("iperf", "--late", late, a, b).split())
            # the late file is left out when it is missing or unreadable, and a failed main client still fails the run
            gone = dict(kv.split("=") for kv in self.run_tq("iperf", "--late", os.path.join(d, "none.json"), a, b).split())
            failed = self.run_tq("iperf", "--late", late, a, os.path.join(d, "none.json"))
            errfile = self.write_json(d, "e.json", {"error": "unable to connect stream"})
            noresult = self.write_json(d, "n.json", {"end": {}})
            reasons = [dict(kv.split("=") for kv in self.run_tq("iperf", "--late", f, a, b).split())
                       for f in (errfile, noresult, "")]
        # bytes and retransmits add up over the clients and the late flow; the duration is the longest main one
        self.assertEqual((got["received"], got["sent"], got["retransmits"], got["duration_s"]),
                         ("3500000", "3500100", "8", "10.000"))
        # the clients' rates add up; the late flow's bytes are over the main duration: 2.442 + 0.4 Mbit/s
        self.assertEqual((main_only["mbit"], got["mbit"]), ("2.44", "2.84"))
        # the fairness is over the four main streams alone
        for k in ("stream_jain", "stream_min_over_max", "stream_zero", "stream_min_mbit", "stream_max_mbit"):
            self.assertEqual(got[k], main_only[k], k)
        # a missing late file is marked, and the other values are the main ones
        self.assertIn("late_error", gone)
        del gone["late_error"]
        self.assertEqual(gone, main_only)
        self.assertEqual([r["late_error"] for r in reasons], ["unable_to_connect_stream", "no_result", "empty_late_path"])
        for r in reasons:
            self.assertEqual(r["received"], main_only["received"])
        self.assertTrue(failed.startswith("received=0 "), failed)

    def test_ssparse_reads_samples_and_sums_connections(self):
        text = (
            "T 100.000000000\n"
            "0 0 10.0.0.1:5001 10.0.0.2:40000\n"
            "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 mss:1448 cwnd:10 snd_wnd:65536 retrans:0/0 rwnd_limited:5ms(1.0%)\n"
            "0 0 10.0.0.1:5001 10.0.0.2:40002\n"
            "\t cubic rtt:1.5/0.5 cwnd:20 retrans:0/1\n"
            "T 100.200000000\n"
            "0 0 10.0.0.1:5001 10.0.0.2:40000\n"
            "\t cubic rtt:0.7/0.25 cwnd:40 retrans:1/4 rwnd_limited:15ms(3.0%)\n"
            "0 0 10.0.0.1:5001 10.0.0.2:40002\n"
            "\t cubic rtt:1.0/0.5 cwnd:30 retrans:0/2\n")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ss.txt")
            with open(path, "w") as f:
                f.write(text)
            out = self.run_tq("ssparse", path).splitlines()
        self.assertEqual(len(out), 5)
        self.assertIn("conn=10.0.0.1:5001>10.0.0.2:40000 cwnd=10 retrans=0 rtt=0.5 rwnd_limited=5 snd_wnd=65536", out[0])
        # the last values per connection: cwnd 40 and 30 (the largest seen is 40), retransmits 4 + 2, rwnd_limited 15 + 0
        self.assertEqual(out[-1], "SSSUM ss_samples=4 ss_conns=2 ss_cwnd_max=40 ss_retrans=6 ss_rwnd_limited_ms=15")


if __name__ == "__main__":
    unittest.main()
