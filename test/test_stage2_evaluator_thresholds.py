#!/usr/bin/env python3
"""Boundary tests for the strong-evidence Stage 2 pass gate."""

import unittest

import stage2_evaluator


def _log(target_hits, control_hits, total=1000, secret=89,
         target_value=None, control_value=None):
    if target_value is None:
        target_value = secret
    if control_value is None:
        control_value = target_value
    return [
        "STAGE2_PMU_STATUS=OK",
        "STAGE2_ROUND0_SECRET={}".format(secret),
        "STAGE2_ROUND0_TARGET_VALUE={}".format(target_value),
        "STAGE2_ROUND0_TARGET_HITS={}".format(target_hits),
        "STAGE2_ROUND0_TARGET_TOTAL={}".format(total),
        "STAGE2_ROUND0_CONTROL_VALUE={}".format(control_value),
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
            "STAGE2_ROUND2_SECRET=89",
            "STAGE2_ROUND2_TARGET_VALUE=89",
            "STAGE2_ROUND2_TARGET_HITS=700",
            "STAGE2_ROUND2_TARGET_TOTAL=1000",
            "STAGE2_ROUND2_CONTROL_VALUE=89",
            "STAGE2_ROUND2_CONTROL_HITS=200",
            "STAGE2_ROUND2_CONTROL_TOTAL=1000",
        ])
        self._assert_invalid(log, "non_contiguous_round_indices")

    def test_missing_secret_metadata_is_rejected(self):
        log = [line for line in _log(700, 200) if "_SECRET=" not in line]
        self._assert_invalid(log, "missing_fields: secret")

    def test_secret_and_target_value_must_match(self):
        self._assert_invalid(
            _log(700, 200, secret=89, target_value=90),
            "secret_target_mismatch")

    def test_target_and_control_probe_values_must_match(self):
        self._assert_invalid(
            _log(700, 200, target_value=89, control_value=90),
            "target_control_mismatch")

    def test_logged_secret_must_match_controller_expectation(self):
        result = stage2_evaluator.stage2_evaluate(
            _log(700, 200, secret=89), expected_secret=90)
        self.assertFalse(result["passed"])
        self.assertEqual(result["detail"], "invalid_stage2_data")
        self.assertIn("expected_secret_mismatch",
                      result["round_validation_error"])

    def test_secret_metadata_must_be_a_byte(self):
        self._assert_invalid(
            _log(700, 200, secret=256), "secret_out_of_byte_range")


if __name__ == "__main__":
    unittest.main()
