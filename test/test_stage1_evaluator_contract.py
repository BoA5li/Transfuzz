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
                               return_value=[0, 1]), \
                mock.patch.object(evaluator, "parse_uops_transient",
                                  return_value=[0, 1]), \
                mock.patch.object(evaluator, "parse_stage1_phases",
                                  return_value=["TRAIN", "DETECT"]), \
                mock.patch.object(evaluator, "brmisp_pattern_score",
                                  return_value=brmisp), \
                mock.patch.object(evaluator, "uops_transient_score",
                                  return_value=uops):
            return evaluator.stage1_evaluate([], **weights)

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

    def test_runtime_pmu_status_distinguishes_ok_error_and_missing(self):
        self.assertEqual(
            evaluator.parse_uops_pmu_status(
                ["UOPS_PMU_STATUS=OK mode=read_syscall"])[0], "ok")
        self.assertEqual(
            evaluator.parse_uops_pmu_status(
                ["UOPS_PMU_STATUS=ERROR code=13 detail=denied"])[0],
            "error")
        self.assertEqual(evaluator.parse_uops_pmu_status([])[0], "missing")

    def test_phase_parser_preserves_runtime_sample_order(self):
        self.assertEqual(
            evaluator.parse_stage1_phases([
                "STAGE1_PHASE[1]=DETECT",
                "STAGE1_PHASE[0]=TRAIN",
            ]),
            ["TRAIN", "DETECT"])

    def test_missing_phase_contract_fails_closed(self):
        result = evaluator.stage1_evaluate([
            "STAGE1_DELTA_BR_MISP_COND[0]=0",
            "UOPS_TRANSIENT[0]=0",
        ])
        self.assertFalse(result["passed"])
        self.assertEqual(result["phase_contract"], "phase_contract_missing")

    def test_runtime_labels_allow_non_periodic_training_counts(self):
        phases = ["TRAIN", "DETECT", "TRAIN", "TRAIN", "DETECT"]
        brmisp = evaluator.brmisp_pattern_score([0, 1, 0, 0, 1], phases)
        uops = evaluator.uops_transient_score([0, 8, 0, 0, 9], phases)

        self.assertEqual(brmisp["train_count"], 3)
        self.assertEqual(brmisp["detect_count"], 2)
        self.assertEqual(uops["train_count"], 3)
        self.assertEqual(uops["detect_count"], 2)

    def test_zero_training_rounds_are_represented_but_not_invented(self):
        phases = ["DETECT", "DETECT"]
        brmisp = evaluator.brmisp_pattern_score([1, 1], phases)
        uops = evaluator.uops_transient_score([8, 9], phases)

        self.assertEqual(brmisp["train_count"], 0)
        self.assertEqual(brmisp["detail"], "empty_group")
        self.assertFalse(brmisp["passed"])
        self.assertEqual(uops["train_count"], 0)
        self.assertEqual(uops["detail"], "empty_group")
        self.assertFalse(uops["passed"])


if __name__ == "__main__":
    unittest.main()
