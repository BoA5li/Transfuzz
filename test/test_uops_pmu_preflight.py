#!/usr/bin/env python3
"""Tests for the fail-closed UOPS PMU preflight runner."""

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uops_pmu_preflight as preflight
import stage1_controller


def _completed(returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class UopsPmuPreflightTests(unittest.TestCase):
    def _files(self, directory):
        obj = os.path.join(directory, "pmu_uops_rdpmc.o")
        source = os.path.join(directory, "probe.c")
        open(obj, "wb").close()
        open(source, "w").close()
        return obj, source

    def test_successful_zero_reads_are_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [
                _completed(),
                _completed(stdout=(
                    b"UOPS_PREFLIGHT_STATUS=OK mode=read_syscall "
                    b"profile=intel_family6_model85 issued=0 retired=0\n")),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_uops_pmu_preflight(
                    "cc", obj, directory, probe_source=source)

        self.assertTrue(result["ok"])
        self.assertEqual(result["issued"], 0)
        self.assertEqual(result["retired"], 0)

    def test_permission_failure_is_reported_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [
                _completed(),
                _completed(
                    returncode=2,
                    stderr=(b"UOPS_PREFLIGHT_STATUS=ERROR code=13 "
                            b"detail=Permission denied\n")),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_uops_pmu_preflight(
                    "cc", obj, directory, probe_source=source)

        self.assertFalse(result["ok"])
        self.assertIn("Permission denied", result["reason"])

    def test_missing_object_stops_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(preflight.subprocess, "run") as run:
            result = preflight.run_uops_pmu_preflight(
                "cc", os.path.join(directory, "missing.o"), directory)

        self.assertFalse(result["ok"])
        self.assertIn("not found", result["reason"])
        run.assert_not_called()

    def test_missing_ok_marker_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [_completed(), _completed(stdout=b"issued=0 retired=0\n")]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_uops_pmu_preflight(
                    "cc", obj, directory, probe_source=source)

        self.assertFalse(result["ok"])
        self.assertIn("without an OK marker", result["reason"])

    def test_wrong_cpu_profile_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [
                _completed(),
                _completed(
                    returncode=2,
                    stderr=(b"UOPS_PREFLIGHT_STATUS=ERROR code=95 "
                            b"detail=raw UOPS profile is Cascade Lake only\n")),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_uops_pmu_preflight(
                    "cc", obj, directory, probe_source=source)

        self.assertFalse(result["ok"])
        self.assertIn("Cascade Lake", result["reason"])

    def test_stage1_stops_before_preprocessing_when_preflight_fails(self):
        controller = stage1_controller.Stage1Controller.__new__(
            stage1_controller.Stage1Controller)
        controller.cc = "cc"
        controller.pmu_uops_obj = "pmu.o"
        controller.pmu_helper_obj = "stage1-pmu.o"
        controller.stage1_pmu_event = "conditional"
        controller.work_dir = "/unused"
        controller.compile_timeout = 20
        controller.run_timeout = 20
        controller.framework_error = None
        controller.failure_stats = {
            "uops_pmu_unavailable": 0, "stage1_pmu_unavailable": 0}

        failure = {
            "ok": False,
            "reason": "perf_event permission denied",
            "mode": None,
            "profile": "intel_family6_model85",
            "raw_events": {},
            "issued": None,
            "retired": None,
        }
        with mock.patch.object(
                stage1_controller, "run_stage1_pmu_preflight",
                return_value={
                    "ok": True, "reason": "ok", "event":
                    "BR_MISP_RETIRED.CONDITIONAL", "raw_event": "0x01c5",
                    "value": 0}), \
                mock.patch.object(
                stage1_controller, "run_uops_pmu_preflight",
                return_value=failure), \
                mock.patch.object(controller, "_preprocess") as preprocess, \
                tempfile.TemporaryDirectory() as work_dir:
            controller.work_dir = work_dir
            passed = controller.run()

        self.assertEqual(passed, [])
        self.assertEqual(controller.framework_error,
                         "perf_event permission denied")
        self.assertEqual(controller.failure_stats["uops_pmu_unavailable"], 1)
        preprocess.assert_not_called()


if __name__ == "__main__":
    unittest.main()
