#!/usr/bin/env python3
"""Regression tests for preprocessing-time Stage 1 PMU selection."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from run_stage_pipeline_stage1_2_3 import process_asm


SOURCE = ["STAGE1_BEGIN:\n", "\tnop\n", "STAGE1_END:\n"]


class Stage1PmuEventSelectionTests(unittest.TestCase):
    def test_conditional_remains_backward_compatible(self):
        output = "".join(process_asm(SOURCE, stage1_pmu_event="conditional"))
        self.assertIn("call pmu_stage1_before", output)
        self.assertIn("call pmu_stage1_after", output)
        self.assertNotIn("pmu_stage1_indirect", output)

    def test_indirect_uses_direct_event_specific_calls(self):
        output = "".join(process_asm(SOURCE, stage1_pmu_event="indirect"))
        self.assertIn("call pmu_stage1_indirect_before", output)
        self.assertIn("call pmu_stage1_indirect_after", output)
        self.assertIn("pmu_stage1_event_indirect_selected:", output)
        self.assertNotIn("call pmu_stage1_before", output)

    def test_documented_full_event_names_are_accepted(self):
        output = "".join(process_asm(
            SOURCE, stage1_pmu_event="BR_MISP_EXEC.INDIRECT"))
        self.assertIn("call pmu_stage1_indirect_before", output)

    def test_disambiguation_uses_direct_event_specific_calls(self):
        output = "".join(process_asm(
            SOURCE, stage1_pmu_event="disambiguation"))
        self.assertIn("call pmu_stage1_disambiguation_before", output)
        self.assertIn("call pmu_stage1_disambiguation_after", output)
        self.assertIn("pmu_stage1_event_disambiguation_selected:", output)
        self.assertNotIn("call pmu_stage1_before", output)

    def test_machine_clears_full_event_name_is_accepted(self):
        output = "".join(process_asm(
            SOURCE, stage1_pmu_event="MACHINE_CLEARS.DISAMBIGUATION"))
        self.assertIn("call pmu_stage1_disambiguation_before", output)

    def test_return_uses_direct_event_specific_calls(self):
        output = "".join(process_asm(SOURCE, stage1_pmu_event="return"))
        self.assertIn("call pmu_stage1_return_before", output)
        self.assertIn("call pmu_stage1_return_after", output)
        self.assertIn("pmu_stage1_event_return_selected:", output)
        self.assertNotIn("call pmu_stage1_before", output)

    def test_return_full_event_name_is_accepted(self):
        output = "".join(process_asm(
            SOURCE, stage1_pmu_event="BR_MISP_RETIRED.RETURN"))
        self.assertIn("call pmu_stage1_return_before", output)

    def test_unknown_event_fails_closed(self):
        with self.assertRaises(ValueError):
            process_asm(SOURCE, stage1_pmu_event="unknown-event")

    def test_lfence_baseline_places_fence_first_in_measured_window(self):
        output = process_asm(
            SOURCE, stage1_pmu_event="conditional",
            stage1_begin_lfence=True)
        begin = output.index("STAGE1_BEGIN:\n")
        self.assertEqual(output[begin + 1], "\tcall pmu_stage1_before\n")
        self.assertEqual(
            output[begin + 2],
            "\tlfence # [stage1-lfence-baseline]\n")

    def test_normal_instrumentation_does_not_add_lfence(self):
        output = "".join(process_asm(SOURCE))
        self.assertNotIn("lfence", output)


if __name__ == "__main__":
    unittest.main()
