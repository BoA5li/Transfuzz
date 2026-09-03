#!/usr/bin/env python3
"""Regression tests for the fixed Stage 3 observation budget."""

import json
import os
import tempfile
import unittest

from stage3_config import (
    STAGE3_DETECTION_ROUNDS,
    STAGE3_PARAM_SPECS,
    generate_stage3_env,
    get_stage3_defaults,
    load_stage3_config,
    mutate_stage3_config,
)


class Stage3FixedRoundsTests(unittest.TestCase):
    def test_rounds_is_not_a_mutable_parameter(self):
        self.assertEqual(20, STAGE3_DETECTION_ROUNDS)
        self.assertNotIn("rounds", STAGE3_PARAM_SPECS)
        self.assertNotIn("rounds", get_stage3_defaults())

    def test_runtime_environment_always_uses_twenty_rounds(self):
        config = get_stage3_defaults()
        config["rounds"] = 500
        self.assertEqual(
            "20", generate_stage3_env(config)["STAGE3_ROUNDS"])

    def test_mutation_cannot_change_observation_rounds(self):
        config = get_stage3_defaults()
        for _ in range(100):
            mutated = mutate_stage3_config(config, per_param_prob=1.0)
            self.assertNotIn("rounds", mutated)
            self.assertEqual(
                "20", generate_stage3_env(mutated)["STAGE3_ROUNDS"])

    def test_legacy_rounds_field_is_discarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stage3_config.json")
            with open(path, "w") as stream:
                json.dump({"rounds": 500, "cache_hit_threshold": 90}, stream)
            loaded = load_stage3_config(path)
        self.assertNotIn("rounds", loaded)
        self.assertEqual(90, loaded["cache_hit_threshold"])


class Stage3NativeFixedRoundsTests(unittest.TestCase):
    def test_driver_and_backend_use_shared_fixed_constant(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "auto_stage1_2_3_driver.c")) as stream:
            driver = stream.read()
        with open(os.path.join(base, "stage3_driver_safe.c")) as stream:
            backend = stream.read()

        self.assertNotIn('GET_ENV_INT("STAGE3_ROUNDS"', driver)
        self.assertIn(
            "g_stage3_cfg.rounds              = STAGE3_DETECTION_ROUNDS;",
            driver)
        self.assertNotIn("rounds = cfg->rounds", backend)
        self.assertIn("rounds = STAGE3_DETECTION_ROUNDS;", backend)


if __name__ == "__main__":
    unittest.main()
