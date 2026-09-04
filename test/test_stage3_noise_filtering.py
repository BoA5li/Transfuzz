#!/usr/bin/env python3
import os
import unittest

from stage3_config import (
    STAGE3_PARAM_SPECS,
    generate_stage3_env,
    get_stage3_defaults,
)
from stage3_evaluator import stage3_evaluate


def _log_for_secret(secret, noise_candidate=None):
    lines = [
        "STAGE3_ROUND0_EXPECTED={}".format(secret),
        "STAGE3_ROUND0_TOP1={}".format(secret),
        "STAGE3_ROUND0_TOP2=255",
        "STAGE3_ROUND0_TOP1_SCORE=20",
        "STAGE3_ROUND0_TOP2_SCORE=0",
        "STAGE3_ROUND0_MATCH=1",
    ]
    for round_idx in range(20):
        lines.append("STAGE3_DEBUG_ROUND[{}]_TIMES_BEGIN".format(round_idx))
        for candidate_idx in range(256):
            lines.append(
                "STAGE3_DEBUG_ROUND[{}]_TIME[{}]={} EXPECTED={} "
                "NOISE={} SCORE={} MEASURED={}".format(
                    round_idx,
                    candidate_idx,
                    20 if candidate_idx == secret else 200,
                    1 if candidate_idx == secret else 0,
                    1 if candidate_idx == noise_candidate else 0,
                    round_idx + 1 if candidate_idx == secret else 0,
                    round_idx + 1))
        lines.append("STAGE3_DEBUG_ROUND[{}]_TIMES_END".format(round_idx))
    return lines


class Stage3NoiseFilteringTests(unittest.TestCase):
    def test_candidate_value_range_is_not_a_mutation_axis(self):
        self.assertNotIn("noise_range_start", STAGE3_PARAM_SPECS)
        self.assertNotIn("noise_range_end", STAGE3_PARAM_SPECS)
        env = generate_stage3_env(get_stage3_defaults())
        self.assertNotIn("STAGE3_NOISE_START", env)
        self.assertNotIn("STAGE3_NOISE_END", env)

    def test_low_byte_secret_remains_eligible(self):
        result = stage3_evaluate(_log_for_secret(1), expected_secret=1)
        self.assertFalse(result["framework_error"])
        self.assertTrue(result["passed"])

    def test_noise_marker_for_any_byte_fails_closed(self):
        result = stage3_evaluate(
            _log_for_secret(89, noise_candidate=7), expected_secret=89)
        self.assertTrue(result["framework_error"])
        self.assertIn("invalid_candidate_noise_marker", result["detail"])

    def test_backend_does_not_exclude_candidate_indices(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "stage3_driver_safe.c")) as stream:
            source = stream.read()
        self.assertNotIn("stage3_is_noise_candidate", source)
        self.assertIn("int is_noise = 0;", source)


if __name__ == "__main__":
    unittest.main()
