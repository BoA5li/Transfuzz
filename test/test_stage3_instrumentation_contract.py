#!/usr/bin/env python3
"""Stage 3 preprocessing and driver isolation regression tests."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from run_stage_pipeline_stage1_2_3 import (
    STAGE1_PMU_EVENTS, STAGE1_PMU_EVENT_MARKERS)
from stage3_controller import Stage3Controller


class Stage3InstrumentationContractTests(unittest.TestCase):
    def setUp(self):
        self.controller = Stage3Controller.__new__(Stage3Controller)

    def test_all_stage1_event_and_uops_calls_are_removed(self):
        symbols = [
            symbol
            for pair in STAGE1_PMU_EVENTS.values()
            for symbol in pair
        ] + [
            "pmu_stage1_set_phase",
            "pmu_uops_snap_before",
            "pmu_uops_snap_after",
            "pmu_uops_print_results",
            "pmu_stage1_get_count",
            "pmu_stage1_get_delta",
            "pmu_uops_get_count",
            "pmu_uops_get_transient",
            "pmu_uops_get_issued_delta",
            "pmu_uops_get_retired_delta",
            "pmu_uops_get_status_code",
            "pmu_uops_get_status_message",
            "pmu_uops_get_mode",
        ]
        source = ["\tcall {}@PLT\n".format(symbol) for symbol in symbols]
        cleaned = self.controller._remove_stage1_instrumentation(source)

        self.assertEqual(len(source), len(cleaned))
        self.assertTrue(all(line.startswith("# [s3-removed]")
                            for line in cleaned))

    def test_every_event_selection_section_is_removed_as_a_unit(self):
        for marker in STAGE1_PMU_EVENT_MARKERS.values():
            source = [
                "\t.pushsection .rodata\n",
                "\t.globl {}\n".format(marker),
                "{}:\n".format(marker),
                "\t.byte 1\n",
                "\t.popsection\n",
                "\tmovq %rax, %rbx\n",
            ]
            cleaned = self.controller._remove_stage1_instrumentation(source)
            self.assertTrue(all(line.startswith("# [s3-removed]")
                                for line in cleaned[:5]), marker)
            self.assertEqual(source[5], cleaned[5])

    def test_similarly_named_victim_function_is_not_removed(self):
        source = [
            "\tcall pmu_stage1_return_before_extra@PLT\n",
            "\tcall victim_pmu_uops_get_count@PLT\n",
            "\tlfence\n",
        ]
        self.assertEqual(
            source, self.controller._remove_stage1_instrumentation(source))

    def test_stage3_driver_bypasses_stage2_pmu_sampling(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "auto_stage1_2_3_driver.c")) as stream:
            driver = stream.read()
        main_start = driver.index("int main(int argc, char **argv)")
        stage3_gate = driver.index("if (stage3_enabled)", main_start)
        prepare = driver.index("vf_prepare_probe_region(256);", main_start)
        stage2_sample = driver.index("stage2_round_dual(s0, trials", prepare)
        self.assertLess(stage3_gate, prepare)
        self.assertLess(stage3_gate, stage2_sample)
        gate_body = driver[stage3_gate:prepare]
        self.assertIn("return run_stage3_only", gate_body)

    def test_pmu_constructor_skips_opening_events_in_stage3_mode(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "pmu_helper_auto.c")) as stream:
            helper = stream.read()
        init_start = helper.index("static void pmu_init(void)")
        init_body = helper[init_start:]
        stage3_check = init_body.index('getenv("ENABLE_STAGE3")')
        first_open = init_body.index("setup_stage1_event(")
        self.assertLess(stage3_check, first_open)


if __name__ == "__main__":
    unittest.main()
