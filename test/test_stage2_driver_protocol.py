#!/usr/bin/env python3
"""Static regression checks for the Stage 2 sampling protocol."""

import os
import unittest


class Stage2DriverProtocolTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        source_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "auto_stage1_2_3_driver.c")
        with open(source_path, "r") as source:
            cls.source = source.read()

    def test_target_and_control_are_paired_with_alternating_order(self):
        self.assertIn("for (int i = 0; i < trials; i++)", self.source)
        self.assertIn("if ((i & 1) == 0)", self.source)
        self.assertIn("stage2_target_trial(probe_target)", self.source)
        self.assertIn("stage2_control_trial(probe_target)", self.source)
        self.assertIn("STAGE2_TRIAL_SCHEDULE=PAIRED_ALTERNATING",
                      self.source)

    def test_each_trial_flushes_the_probe_line(self):
        target_start = self.source.index("static int stage2_target_trial")
        control_start = self.source.index("static int stage2_control_trial")
        round_start = self.source.index("static int stage2_round_dual")
        target_body = self.source[target_start:control_start]
        control_body = self.source[control_start:round_start]
        self.assertIn("flush_line(probe_target);", target_body)
        self.assertIn("flush_line(probe_target);", control_body)

    def test_trial_count_remains_fixed_at_1000_per_group(self):
        self.assertIn("int trials = 1000;", self.source)
        self.assertIn("total_t++;", self.source)
        self.assertIn("total_c++;", self.source)

    def test_probe_region_is_prepared_once_before_measurement(self):
        main_start = self.source.index("int main(int argc, char **argv)")
        main_body = self.source[main_start:]
        prepare = main_body.index("vf_prepare_probe_region(256);")
        measure = main_body.index("stage2_round_dual(s0, trials")
        self.assertLess(prepare, measure)
        self.assertEqual(main_body.count("vf_prepare_probe_region(256);"), 1)

    def test_round_has_no_dead_secret_parameter(self):
        round_start = self.source.index("static int stage2_round_dual")
        round_end = self.source.index("int main(int argc, char **argv)")
        round_body = self.source[round_start:round_end]
        self.assertNotIn("uint8_t secret", round_body)
        self.assertNotIn("(void)secret", round_body)

    def test_null_probe_address_is_rejected(self):
        self.assertIn("if (probe_target == NULL) return -2;", self.source)
        self.assertIn("detail=null_target_probe", self.source)


if __name__ == "__main__":
    unittest.main()
