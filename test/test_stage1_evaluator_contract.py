#!/usr/bin/env python3
"""Regression tests for the Stage 1 joint gate and score weights."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stage1_evaluator as evaluator


def _metric(score, passed, detail="ok"):
    return {"score": score, "passed": passed, "detail": detail}


class Stage1EvaluatorContractTests(unittest.TestCase):
    def _evaluate(self, brmisp, uops, **weights):
        with mock.patch.object(evaluator, "parse_brmisp_deltas",
                               return_value=[]), \
                mock.patch.object(evaluator, "parse_uops_transient",
                                  return_value=[]), \
                mock.patch.object(evaluator, "brmisp_pattern_score",
                                  return_value=brmisp), \
                mock.patch.object(evaluator, "uops_transient_score",
                                  return_value=uops):
            return evaluator.stage1_evaluate([], period=6, **weights)

    def test_both_metrics_must_pass(self):
        cases = [
            (True, True, True),
            (True, False, False),
            (False, True, False),
            (False, False, False),
        ]
        for brmisp_passed, uops_passed, expected in cases:
            result = self._evaluate(
                _metric(1.0, brmisp_passed),
                _metric(1.0, uops_passed))
            self.assertEqual(result["passed"], expected)

    def test_default_score_uses_eighty_twenty_weights(self):
        result = self._evaluate(
            _metric(0.75, True), _metric(0.25, True))

        self.assertAlmostEqual(result["score"], 0.65)
        self.assertEqual(result["score_weights"], {
            "brmisp": 0.8,
            "uops": 0.2,
        })

    def test_invalid_metric_contributes_zero_without_reweighting(self):
        result = self._evaluate(
            _metric(1.0, False, detail="insufficient_data"),
            _metric(1.0, True))

        self.assertAlmostEqual(result["score"], 0.2)
        self.assertFalse(result["passed"])

    def test_zero_total_weight_is_rejected(self):
        with self.assertRaises(ValueError):
            self._evaluate(
                _metric(1.0, True), _metric(1.0, True),
                brmisp_weight=0.0, uops_weight=0.0)


if __name__ == "__main__":
    unittest.main()
