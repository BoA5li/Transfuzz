#!/usr/bin/env python3
import json
import os
import tempfile
import unittest

from stage3_config import (
    STAGE3_DETECTION_CANDIDATES,
    generate_stage3_env,
    get_stage3_defaults,
    load_stage3_config,
    mutate_stage3_config,
    save_stage3_config,
)


class Stage3FixedCandidateContractTest(unittest.TestCase):
    def test_complete_byte_domain_is_fixed(self):
        self.assertEqual(256, STAGE3_DETECTION_CANDIDATES)
        self.assertEqual(list(range(256)), list(range(STAGE3_DETECTION_CANDIDATES)))

    def test_candidate_count_is_not_mutable_or_overridable(self):
        defaults = get_stage3_defaults()
        self.assertNotIn("candidate_count", defaults)
        for _ in range(25):
            mutated = mutate_stage3_config(defaults, per_param_prob=1.0)
            self.assertNotIn("candidate_count", mutated)
            env = generate_stage3_env(dict(mutated, candidate_count=64))
            self.assertEqual("256", env["STAGE3_CANDIDATE_COUNT"])

    def test_legacy_candidate_count_is_removed_from_persistence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "stage3_config.json")
            save_stage3_config(
                {"candidate_count": 64, "cache_hit_threshold": 90}, path)
            with open(path, "r") as config_file:
                self.assertNotIn("candidate_count", json.load(config_file))

            with open(path, "w") as config_file:
                json.dump(
                    {"candidate_count": 64, "cache_hit_threshold": 90},
                    config_file)
            loaded = load_stage3_config(path)
            self.assertNotIn("candidate_count", loaded)
            self.assertEqual(90, loaded["cache_hit_threshold"])

    def test_native_backend_ignores_legacy_candidate_field(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "auto_stage1_2_3_driver.c")) as stream:
            driver = stream.read()
        with open(os.path.join(base, "stage3_driver_safe.c")) as stream:
            backend = stream.read()

        self.assertNotIn('GET_ENV_INT("STAGE3_CANDIDATE_COUNT"', driver)
        self.assertIn(
            "g_stage3_cfg.candidate_count     = STAGE3_DETECTION_CANDIDATES;",
            driver)
        self.assertNotIn("candidate_count = cfg->candidate_count", backend)
        self.assertIn(
            "candidate_count = STAGE3_DETECTION_CANDIDATES;", backend)


if __name__ == "__main__":
    unittest.main()
