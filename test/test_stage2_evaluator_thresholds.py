#!/usr/bin/env python3
"""Boundary tests for the strong-evidence Stage 2 pass gate."""

import unittest

import stage2_evaluator


def _log(target_hits, control_hits, total=1000):
    return [
        "STAGE2_PMU_STATUS=OK",
        "STAGE2_ROUND0_TARGET_HITS={}".format(target_hits),
        "STAGE2_ROUND0_TARGET_TOTAL={}".format(total),
        "STAGE2_ROUND0_CONTROL_HITS={}".format(control_hits),
        "STAGE2_ROUND0_CONTROL_TOTAL={}".format(total),
    ]


class Stage2EvaluatorThresholdTests(unittest.TestCase):

    def test_exact_signal_and_target_boundaries_pass(self):
        result = stage2_evaluator.stage2_evaluate(_log(700, 200))
        self.assertTrue(result["passed"])
        self.assertAlmostEqual(result["mean_signal"], 0.50)
        self.assertAlmostEqual(result["mean_target_rate"], 0.70)

    def test_signal_just_below_boundary_fails(self):
        result = stage2_evaluator.stage2_evaluate(_log(700, 201))
        self.assertFalse(result["passed"])
        self.assertAlmostEqual(result["mean_signal"], 0.499)

    def test_target_just_below_boundary_fails(self):
        result = stage2_evaluator.stage2_evaluate(_log(699, 0))
        self.assertFalse(result["passed"])
        self.assertAlmostEqual(result["mean_target_rate"], 0.699)

    def test_old_weak_gate_no_longer_passes(self):
        result = stage2_evaluator.stage2_evaluate(_log(100, 20))
        self.assertFalse(result["passed"])
        self.assertAlmostEqual(result["mean_signal"], 0.08)


if __name__ == "__main__":
    unittest.main()
