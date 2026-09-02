#!/usr/bin/env python3
"""Tests for fail-closed Stage 2 L1D PMU validation."""

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stage2_controller
import stage2_evaluator
import stage2_pmu_preflight as preflight
from seed_pool import Seed


def _completed(returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class Stage2PmuPreflightTests(unittest.TestCase):
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
                _completed(stdout=b"L1D_PMU_PREFLIGHT_STATUS=OK value=0\n"),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_stage2_pmu_preflight(
                    "cc", obj, directory, probe_source=source)

        self.assertTrue(result["ok"])
        self.assertEqual(result["value"], 0)
        self.assertEqual(result["raw_event"], "0x08d1")

    def test_permission_failure_is_not_converted_to_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, source = self._files(directory)
            responses = [
                _completed(),
                _completed(
                    returncode=2,
                    stderr=(b"L1D_PMU_PREFLIGHT_STATUS=ERROR code=13 "
                            b"detail=Permission denied\n")),
            ]
            with mock.patch.object(
                    preflight.subprocess, "run", side_effect=responses):
                result = preflight.run_stage2_pmu_preflight(
                    "cc", obj, directory, probe_source=source)

        self.assertFalse(result["ok"])
        self.assertIn("Permission denied", result["reason"])

    def test_runtime_status_is_required_by_evaluator(self):
        log = [
            "STAGE2_ROUND0_SECRET=89",
            "STAGE2_ROUND0_TARGET_VALUE=89",
            "STAGE2_ROUND0_TARGET_HITS=10",
            "STAGE2_ROUND0_TARGET_TOTAL=10",
            "STAGE2_ROUND0_CONTROL_VALUE=89",
            "STAGE2_ROUND0_CONTROL_HITS=0",
            "STAGE2_ROUND0_CONTROL_TOTAL=10",
        ]
        missing = stage2_evaluator.stage2_evaluate(log)
        healthy = stage2_evaluator.stage2_evaluate(
            ["STAGE2_PMU_STATUS=OK event=MEM_LOAD_RETIRED.L1_MISS"] + log)

        self.assertEqual(missing["detail"], "pmu_missing")
        self.assertFalse(missing["passed"])
        self.assertEqual(healthy["pmu_status"], "ok")
        self.assertTrue(healthy["passed"])

    def test_controller_stops_before_seed_processing_on_failure(self):
        controller = stage2_controller.Stage2Controller.__new__(
            stage2_controller.Stage2Controller)
        controller.cc = "cc"
        controller.pmu_helper_obj = "pmu.o"
        controller.compile_timeout = 20
        controller.run_timeout = 20
        controller.pmu_preflight_results = None
        controller.framework_error = None
        controller.failure_stats = {"l1d_pmu_unavailable": 0}
        failure = {
            "ok": False,
            "reason": "perf_event permission denied",
            "event": "MEM_LOAD_RETIRED.L1_MISS",
            "raw_event": "0x08d1",
            "value": None,
        }
        with tempfile.TemporaryDirectory() as work_dir, \
                mock.patch.object(
                    stage2_controller, "run_stage2_pmu_preflight",
                    return_value=failure), \
                mock.patch.object(controller, "_precompile_stage3_obj") as precompile:
            controller.work_dir = work_dir
            passed = controller.run([])

        self.assertEqual(passed, [])
        self.assertEqual(controller.framework_error,
                         "perf_event permission denied")
        self.assertEqual(controller.failure_stats["l1d_pmu_unavailable"], 1)
        precompile.assert_not_called()

    @staticmethod
    def _healthy_preflight():
        return {
            "ok": True,
            "reason": "ok",
            "event": "MEM_LOAD_RETIRED.L1_MISS",
            "raw_event": "0x08d1",
            "value": 0,
        }

    @staticmethod
    def _valid_evaluation():
        return {
            "score": 1.0,
            "passed": True,
            "mean_signal": 1.0,
            "mean_target_rate": 1.0,
            "mean_control_rate": 0.0,
        }

    def _controller(self, work_dir, budget=3):
        return stage2_controller.Stage2Controller({
            "work_dir": work_dir,
            "budget": budget,
            "report_interval": 100,
            "pmu_preflight_results": {"l1d": self._healthy_preflight()},
        })

    def test_framework_error_stops_remaining_baseline_evaluations(self):
        with tempfile.TemporaryDirectory() as work_dir:
            controller = self._controller(work_dir)
            seeds = [Seed("seed_a.s"), Seed("seed_b.s")]

            def fail_framework(*args, **kwargs):
                controller.framework_error = "L1D PMU runtime read failed"
                return None

            with mock.patch.object(controller, "_precompile_stage3_obj"), \
                    mock.patch.object(
                        controller, "_evaluate_seed",
                        side_effect=fail_framework) as evaluate:
                passed = controller.run(seeds)

        self.assertEqual(passed, [])
        self.assertEqual(evaluate.call_count, 1)
        self.assertEqual(controller.framework_error,
                         "L1D PMU runtime read failed")

    def test_framework_error_stops_remaining_mutation_rounds(self):
        with tempfile.TemporaryDirectory() as work_dir:
            controller = self._controller(work_dir)
            seed = Seed("seed.s")

            def fail_first_round(round_idx):
                controller.framework_error = "L1D PMU runtime read failed"

            with mock.patch.object(controller, "_precompile_stage3_obj"), \
                    mock.patch.object(
                        controller, "_evaluate_seed",
                        return_value=self._valid_evaluation()), \
                    mock.patch.object(
                        controller, "_mutation_round",
                        side_effect=fail_first_round) as mutate:
                passed = controller.run([seed])

        self.assertEqual(passed, [])
        self.assertEqual(mutate.call_count, 1)
        self.assertEqual(controller.framework_error,
                         "L1D PMU runtime read failed")


if __name__ == "__main__":
    unittest.main()
