#!/usr/bin/env python3
"""Regression tests for the top-level pipeline contract."""

import io
import os
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_full_pipeline as pipeline
from seed_pool import Seed


def _args(work_dir):
    return Namespace(
        input="victim.c", work_dir=work_dir, expected_secret="Y",
        period=6, s1_budget=0, s1_pool_size=2, s2_budget=0,
        s2_pool_size=2, s3_budget=0, s3_pool_size=2,
        anchors_json=None, strong_objects_json=None, gcc="gcc",
        pmu_helper_obj="pmu.o", pmu_uops_obj="uops.o",
        stage1_pmu_event="indirect",
        driver_c="driver.c", stage3_driver_c="stage3.c", dump_times=1)


class _Stage1WithOnePass(object):
    def __init__(self, config):
        self.framework_error = None

    def run(self):
        seed = Seed("stage1.s")
        seed.current_stage_mutated_pcs.add("0x10")
        return [seed]


class PipelineContractTests(unittest.TestCase):
    def setUp(self):
        Seed._next_id = 0

    def test_lock_export_does_not_allocate_seed_id(self):
        seed = Seed("seed.s", cross_stage_locked_pcs={"0x10"})
        seed.current_stage_mutated_pcs.add("0x20")
        next_id = Seed._next_id

        self.assertEqual(seed.get_next_stage_locked_pcs(), {"0x10", "0x20"})
        self.assertEqual(Seed._next_id, next_id)

    def test_stage2_no_finding_preserves_stage1_count(self):
        class Stage2NoFinding(object):
            def __init__(self, config):
                self.framework_error = None

            def run(self, seeds):
                return []

        with tempfile.TemporaryDirectory() as work_dir, \
                mock.patch.object(pipeline, "Stage1Controller",
                                  _Stage1WithOnePass), \
                mock.patch.object(pipeline, "Stage2Controller",
                                  Stage2NoFinding):
            output = io.StringIO()
            with redirect_stdout(output):
                result = pipeline.run_pipeline(_args(work_dir))

        self.assertEqual(result.exit_code, pipeline.EXIT_NOT_FOUND)
        self.assertIn("Stage 1 (Branch Misprediction): 1 passed seeds",
                      output.getvalue())

    def test_stage2_framework_failure_has_distinct_exit_code(self):
        class Stage2Failure(object):
            def __init__(self, config):
                self.framework_error = "baseline infrastructure failed"

            def run(self, seeds):
                return []

        with tempfile.TemporaryDirectory() as work_dir, \
                mock.patch.object(pipeline, "Stage1Controller",
                                  _Stage1WithOnePass), \
                mock.patch.object(pipeline, "Stage2Controller", Stage2Failure):
            result = pipeline.run_pipeline(_args(work_dir))

        self.assertEqual(result.exit_code, pipeline.EXIT_FRAMEWORK_ERROR)


if __name__ == "__main__":
    unittest.main()
