#!/usr/bin/env python3
"""Regression tests for the Stage 1 to Stage 2 assembly contract."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stage1_controller import Stage1Controller
from stage2_controller import Stage2Controller


class Stage2Stage1CleanupTests(unittest.TestCase):
    def setUp(self):
        self.controller = Stage2Controller.__new__(Stage2Controller)

    def test_all_stage1_event_and_uops_calls_are_removed(self):
        symbols = [
            "pmu_stage1_before",
            "pmu_stage1_after",
            "pmu_stage1_indirect_before",
            "pmu_stage1_indirect_after",
            "pmu_stage1_disambiguation_before",
            "pmu_stage1_disambiguation_after",
            "pmu_stage1_return_before",
            "pmu_stage1_return_after",
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

        self.assertEqual(len(cleaned), len(source))
        self.assertTrue(all(line.startswith("# [s2-removed]")
                            for line in cleaned))

    def test_event_selection_section_is_removed_as_one_unit(self):
        source = [
            "\t.pushsection .rodata\n",
            "\t.globl pmu_stage1_event_indirect_selected\n",
            "pmu_stage1_event_indirect_selected:\n",
            "\t.byte 1\n",
            "\t.popsection\n",
            "\tmovq %rax, %rbx\n",
        ]
        cleaned = self.controller._remove_stage1_instrumentation(source)

        self.assertTrue(all(line.startswith("# [s2-removed]")
                            for line in cleaned[:5]))
        self.assertEqual(cleaned[5], source[5])

    def test_victim_boundaries_nop_region_and_user_lfence_are_retained(self):
        source = [
            "STAGE1_BEGIN:\n",
            "# NOP_REGION_BEGIN\n",
            "\tmovq %rax, %rbx\n",
            "\tlfence\n",
            "# NOP_REGION_END\n",
            "STAGE1_END:\n",
            "\tcall pmu_stage1_before_extra@PLT\n",
            "\tlfence # [stage1-lfence-baseline]\n",
        ]
        cleaned = self.controller._remove_stage1_instrumentation(source)

        self.assertEqual(cleaned[:7], source[:7])
        self.assertTrue(cleaned[7].startswith("# [s2-removed]"))

    def test_stage1_processing_is_side_file_and_preserves_raw_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_path = os.path.join(directory, "seed.s")
            raw_lines = [
                "STAGE1_BEGIN:\n",
                "# NOP_REGION_BEGIN\n",
                "\tmovq %rax, %rbx\n",
                "\taddq $1, %rax\n",
                "# NOP_REGION_END\n",
                "STAGE1_END:\n",
            ]
            with open(raw_path, "w") as source:
                source.writelines(raw_lines)

            stage1 = Stage1Controller.__new__(Stage1Controller)
            stage1.stage1_pmu_event = "conditional"
            stage1.framework_error = None
            processed_path = stage1._process_asm(raw_path, "baseline")

            with open(raw_path, "r") as source:
                self.assertEqual(source.readlines(), raw_lines)
            self.assertNotEqual(processed_path, raw_path)
            with open(processed_path, "r") as source:
                processed = source.read()
            self.assertIn("\tnop\n", processed)
            self.assertNotIn("\tmovq %rax, %rbx\n", processed)
            self.assertNotIn("\taddq $1, %rax\n", processed)


if __name__ == "__main__":
    unittest.main()
