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


class Stage2RoundValidationTests(unittest.TestCase):

    def _assert_invalid(self, log, expected_error):
        result = stage2_evaluator.stage2_evaluate(log)
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["detail"], "invalid_stage2_data")
        self.assertIn(expected_error, result["round_validation_error"])

    def test_missing_required_counter_field_is_rejected(self):
        log = _log(700, 200)
        log = [line for line in log if "CONTROL_HITS" not in line]
        self._assert_invalid(log, "missing_fields: control_hits")

    def test_zero_total_is_rejected(self):
        self._assert_invalid(_log(0, 0, total=0),
                             "target_total_must_be_positive")

    def test_hits_greater_than_total_is_rejected(self):
        self._assert_invalid(_log(1001, 0),
                             "target_hits_out_of_range")

    def test_negative_hits_is_rejected(self):
        self._assert_invalid(_log(-1, 0),
                             "target_hits_out_of_range")

    def test_non_contiguous_rounds_are_rejected(self):
        log = _log(700, 200)
        log.extend([
            "STAGE2_ROUND2_TARGET_HITS=700",
            "STAGE2_ROUND2_TARGET_TOTAL=1000",
            "STAGE2_ROUND2_CONTROL_HITS=200",
            "STAGE2_ROUND2_CONTROL_TOTAL=1000",
        ])
        self._assert_invalid(log, "non_contiguous_round_indices")


if __name__ == "__main__":
    unittest.main()
