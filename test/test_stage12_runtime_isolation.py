#!/usr/bin/env python3
"""Regression tests for phase-pure Stage 1 and Stage 2 runtimes."""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from stage1_pmu_preflight import run_stage1_pmu_preflight
from stage2_controller import Stage2Controller
from stage2_pmu_preflight import run_stage2_pmu_preflight


def _completed(stdout=b""):
    return subprocess.CompletedProcess([], 0, stdout, b"")


class Stage12RuntimeIsolationTests(unittest.TestCase):
    def test_stage2_controller_has_no_stage3_build_dependency(self):
        controller = Stage2Controller({"work_dir": tempfile.mkdtemp()})
        self.assertFalse(hasattr(controller, "stage3_driver_c"))
        self.assertFalse(hasattr(controller, "stage3_obj"))
        self.assertFalse(hasattr(controller, "_precompile_stage3_obj"))

    def test_stage2_driver_is_compiled_in_stage2_only_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            victim = os.path.join(directory, "victim.s")
            driver = os.path.join(directory, "driver.c")
            helper = os.path.join(directory, "helper.o")
            for path in (victim, driver, helper):
                open(path, "w").close()
            controller = Stage2Controller({
                "work_dir": directory,
                "driver_c": driver,
                "pmu_helper_obj": helper,
            })
            with mock.patch("stage2_controller.subprocess.run",
                            return_value=_completed()) as run:
                controller._compile_stage2(victim, directory, "test")
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn("-DSTAGE2_ONLY", commands[1])
            self.assertEqual(
                [controller.cc, commands[0][-1], commands[1][-1], helper,
                 "-o", os.path.join(directory, "stage2_exe")],
                commands[2])

    def test_preflights_select_only_their_own_pmu_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = os.path.join(directory, "helper.o")
            probe = os.path.join(directory, "probe.c")
            open(helper, "w").close()
            open(probe, "w").close()

            stage1_responses = [
                _completed(),
                _completed(b"STAGE1_PMU_PREFLIGHT_STATUS=OK value=0\n"),
            ]
            with mock.patch("stage1_pmu_preflight.subprocess.run",
                            side_effect=stage1_responses) as run:
                result = run_stage1_pmu_preflight(
                    "cc", helper, "conditional", directory,
                    probe_source=probe)
            self.assertTrue(result["ok"])
            self.assertEqual(
                "1", run.call_args_list[1].kwargs["env"]["TRANSFUZZ_PMU_STAGE"])

            stage2_responses = [
                _completed(),
                _completed(b"L1D_PMU_PREFLIGHT_STATUS=OK value=0\n"),
            ]
            with mock.patch("stage2_pmu_preflight.subprocess.run",
                            side_effect=stage2_responses) as run:
                result = run_stage2_pmu_preflight(
                    "cc", helper, directory, probe_source=probe)
            self.assertTrue(result["ok"])
            self.assertEqual(
                "2", run.call_args_list[1].kwargs["env"]["TRANSFUZZ_PMU_STAGE"])


if __name__ == "__main__":
    unittest.main()
