#!/usr/bin/env python3
"""Regression tests for the Stage 1 failure-directory contract."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stage1_controller


class Stage1FailureDirectoryTests(unittest.TestCase):
    def test_failure_artifacts_use_stage_work_dir_without_nested_stage1(self):
        controller = stage1_controller.Stage1Controller.__new__(
            stage1_controller.Stage1Controller)

        with tempfile.TemporaryDirectory() as pipeline_work_dir:
            controller.work_dir = os.path.join(pipeline_work_dir, "stage1")
            os.makedirs(controller.work_dir)

            source = os.path.join(controller.work_dir, "mutant.s")
            with open(source, "w") as output:
                output.write("nop\n")

            controller._save_failure_artifact(
                source, "r1", "asm_fail", "assembler failed")

            failure_root = os.path.join(
                pipeline_work_dir, "stage1", "_failures")
            self.assertEqual(controller._failure_root(), failure_root)
            self.assertTrue(os.path.isfile(os.path.join(
                failure_root, "asm_fail", "r1_asm_fail.s")))
            self.assertTrue(os.path.isfile(os.path.join(
                failure_root, "asm_fail", "r1_asm_fail.err")))
            self.assertFalse(os.path.exists(os.path.join(
                pipeline_work_dir, "stage1", "stage1")))


if __name__ == "__main__":
    unittest.main()
