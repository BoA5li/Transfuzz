#!/usr/bin/env python3
"""Tests for the fail-closed selected Stage 1 PMU preflight."""

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stage1_controller
import stage1_pmu_preflight as preflight


def _completed(returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class Stage1PmuPreflightTests(unittest.TestCase):
    def _files(self, directory):
        obj = os.path.join(directory, "pmu_helper_auto.o")
        source = os.path.join(directory, "probe.c")
        open(obj, "wb").close()
        open(source, "w").close()
        return obj, source

    def test_successful_zero_read_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [
                _completed(),
                _completed(stdout=(
                    b"STAGE1_PMU_PREFLIGHT_STATUS=OK value=0\n")),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_stage1_pmu_preflight(
                    "cc", obj, "return", directory, probe_source=source)

        self.assertTrue(result["ok"])
        self.assertEqual(result["value"], 0)
        self.assertEqual(result["raw_event"], "0xf7c5")

    def test_permission_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [
                _completed(),
                _completed(
                    returncode=2,
                    stderr=(b"STAGE1_PMU_PREFLIGHT_STATUS=ERROR code=13 "
                            b"detail=Permission denied\n")),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_stage1_pmu_preflight(
                    "cc", obj, "indirect", directory, probe_source=source)

        self.assertFalse(result["ok"])
        self.assertIn("Permission denied", result["reason"])

    def test_event_specific_compile_define_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [
                _completed(),
                _completed(stdout=(
                    b"STAGE1_PMU_PREFLIGHT_STATUS=OK value=1\n")),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses) as run:
                result = preflight.run_stage1_pmu_preflight(
                    "cc", obj, "MACHINE_CLEARS.DISAMBIGUATION", directory,
                    probe_source=source)

        self.assertTrue(result["ok"])
        self.assertIn("-DSTAGE1_PMU_EVENT_DISAMBIGUATION",
                      run.call_args_list[0].args[0])

    def test_missing_object_stops_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(preflight.subprocess, "run") as run:
            result = preflight.run_stage1_pmu_preflight(
                "cc", os.path.join(directory, "missing.o"), "return",
                directory)

        self.assertFalse(result["ok"])
        self.assertIn("not found", result["reason"])
        run.assert_not_called()

    def test_stage1_stops_before_target_preprocessing_on_failure(self):
        controller = stage1_controller.Stage1Controller.__new__(
            stage1_controller.Stage1Controller)
        controller.cc = "cc"
        controller.pmu_helper_obj = "pmu.o"
        controller.pmu_uops_obj = "uops.o"
        controller.stage1_pmu_event = "return"
        controller.compile_timeout = 20
        controller.run_timeout = 20
        controller.framework_error = None
        controller.failure_stats = {
            "stage1_pmu_unavailable": 0, "uops_pmu_unavailable": 0}

        failure = {
            "ok": False, "reason": "perf_event permission denied",
            "event": "BR_MISP_RETIRED.RETURN", "raw_event": "0xf7c5",
            "value": None,
        }
        with tempfile.TemporaryDirectory() as work_dir, \
                mock.patch.object(
                    stage1_controller, "run_stage1_pmu_preflight",
                    return_value=failure), \
                mock.patch.object(
                    stage1_controller, "run_uops_pmu_preflight") as uops, \
                mock.patch.object(controller, "_preprocess") as preprocess:
            controller.work_dir = work_dir
            passed = controller.run()

        self.assertEqual(passed, [])
        self.assertEqual(controller.framework_error,
                         "perf_event permission denied")
        self.assertEqual(
            controller.failure_stats["stage1_pmu_unavailable"], 1)
        uops.assert_not_called()
        preprocess.assert_not_called()


if __name__ == "__main__":
    unittest.main()
