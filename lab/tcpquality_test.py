#!/usr/bin/env python3
# Golden test of the paired estimators of tcpquality.py (the cpupaired subcommand and its
# MBITRATIO) on two tiny synthetic logs: python3 lab/tcpquality_test.py
import os
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


if __name__ == "__main__":
    unittest.main()
