#!/usr/bin/env python3
import os
import tempfile
import unittest

from seed_pool import Seed
from stage3_controller import Stage3Controller
from stage3_evaluator import stage3_evaluate


def _valid_log(secret=89, rounds=20, candidates=256):
    lines = [
        "STAGE3_ROUND0_EXPECTED={}".format(secret),
        "STAGE3_ROUND0_TOP1=1",
        "STAGE3_ROUND0_TOP2=2",
        "STAGE3_ROUND0_TOP1_SCORE=0",
        "STAGE3_ROUND0_TOP2_SCORE=0",
        "STAGE3_ROUND0_MATCH=0",
    ]
    for round_idx in range(rounds):
        lines.append(
            "STAGE3_DEBUG_ROUND[{}]_TIMES_BEGIN".format(round_idx))
        for candidate_idx in range(candidates):
            lines.append(
                "STAGE3_DEBUG_ROUND[{}]_TIME[{}]={} "
                "EXPECTED={} NOISE=0 SCORE=0 MEASURED={}".format(
                    round_idx, candidate_idx, 40 + round_idx,
                    1 if candidate_idx == secret else 0, round_idx + 1))
        lines.append(
            "STAGE3_DEBUG_ROUND[{}]_TIMES_END".format(round_idx))
    return lines


class Stage3LatencyContractTests(unittest.TestCase):
    def test_complete_dump_produces_latency_score(self):
        result = stage3_evaluate(_valid_log(), expected_secret=89)
        self.assertFalse(result["framework_error"])
        self.assertEqual(49.5, result["mean_expected_latency"])
        self.assertGreater(result["score"], 0.0)

    def test_missing_timing_line_fails_closed(self):
        lines = _valid_log()
        lines.remove(next(
            line for line in lines
            if "ROUND[7]_TIME[89]" in line))
        result = stage3_evaluate(lines, expected_secret=89)
        self.assertTrue(result["framework_error"])
        self.assertEqual(0.0, result["score"])
        self.assertIn("incomplete_latency_candidates", result["detail"])

    def test_missing_dump_fails_closed_even_when_match_is_present(self):
        lines = [
            "STAGE3_ROUND0_EXPECTED=89",
            "STAGE3_ROUND0_TOP1=89",
            "STAGE3_ROUND0_TOP2=2",
            "STAGE3_ROUND0_TOP1_SCORE=20",
            "STAGE3_ROUND0_TOP2_SCORE=0",
            "STAGE3_ROUND0_MATCH=1",
        ]
        result = stage3_evaluate(lines, expected_secret=89)
        self.assertTrue(result["framework_error"])
        self.assertFalse(result["passed"])

    def test_wrong_expected_marker_fails_closed(self):
        lines = _valid_log()
        index = next(
            i for i, line in enumerate(lines)
            if "ROUND[3]_TIME[89]" in line)
        lines[index] = lines[index].replace("EXPECTED=1", "EXPECTED=0")
        result = stage3_evaluate(lines, expected_secret=89)
        self.assertTrue(result["framework_error"])
        self.assertIn("invalid_expected_latency_marker", result["detail"])

    def test_disabled_dump_is_rejected_before_sanity_check(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            controller = Stage3Controller({
                "dump_times": 0,
                "work_dir": temp_dir,
            })
            controller._sanity_check = lambda: self.fail(
                "sanity check must not run when timing dump is disabled")
            result = controller.run([Seed("unused.s")])
        self.assertIsNone(result)
        self.assertEqual(
            "stage3 latency dump is disabled", controller.framework_error)

    def test_invalid_latency_data_stops_baseline_and_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            controller = Stage3Controller({
                "dump_times": 1,
                "work_dir": temp_dir,
            })
            controller._sanity_check = lambda: True
            controller._precompile_stage3_obj = lambda: None
            controller._evaluate_seed = lambda seed, tag: {
                "score": 0.0,
                "passed": False,
                "detail": "invalid_latency_data:missing",
                "framework_error": True,
            }
            result = controller.run([Seed("unused.s")])
        self.assertIsNone(result)
        self.assertEqual(
            "invalid_latency_data:missing", controller.framework_error)
        self.assertEqual([], controller.seed_pool.seeds)

    def test_controller_and_backend_wire_dump_flag(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "stage3_controller.py")) as stream:
            controller_source = stream.read()
        with open(os.path.join(base, "stage3_driver_safe.c")) as stream:
            backend_source = stream.read()
        self.assertIn('env["STAGE3_DUMP_TIMES"] = "1"', controller_source)
        self.assertIn('getenv("STAGE3_DUMP_TIMES")', backend_source)


if __name__ == "__main__":
    unittest.main()
