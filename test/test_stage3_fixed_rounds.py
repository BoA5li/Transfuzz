#!/usr/bin/env python3
import json
import os
import tempfile
import unittest

from stage3_config import (
    STAGE3_DETECTION_ROUNDS,
    generate_stage3_env,
    get_stage3_defaults,
    load_stage3_config,
    mutate_stage3_config,
    save_stage3_config,
)


class Stage3FixedRoundsContractTest(unittest.TestCase):
    def test_driver_default_matches_fixed_round_count(self):
        driver_path = os.path.join(
            os.path.dirname(__file__), "auto_stage1_2_3_driver.c")
        with open(driver_path, "r") as driver_file:
            source = driver_file.read()
        self.assertNotIn('GET_ENV_INT("STAGE3_ROUNDS"', source)
        self.assertIn(
            "g_stage3_cfg.rounds              = STAGE3_DETECTION_ROUNDS;",
            source)

    def test_rounds_is_not_a_mutation_parameter(self):
        defaults = get_stage3_defaults()
        self.assertNotIn("rounds", defaults)
        for _ in range(25):
            self.assertNotIn(
                "rounds", mutate_stage3_config(defaults, per_param_prob=1.0))

    def test_runtime_rounds_is_fixed_and_cannot_be_overridden(self):
        self.assertEqual(20, STAGE3_DETECTION_ROUNDS)
        self.assertEqual(
            "20", generate_stage3_env({"rounds": 500})["STAGE3_ROUNDS"])

    def test_legacy_rounds_key_is_removed_from_persistence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "stage3_config.json")
            save_stage3_config({"rounds": 500, "cache_hit_threshold": 90}, path)
            with open(path, "r") as config_file:
                self.assertNotIn("rounds", json.load(config_file))

            with open(path, "w") as config_file:
                json.dump({"rounds": 500, "cache_hit_threshold": 90}, config_file)
            loaded = load_stage3_config(path)
            self.assertNotIn("rounds", loaded)
            self.assertEqual(90, loaded["cache_hit_threshold"])


if __name__ == "__main__":
    unittest.main()
