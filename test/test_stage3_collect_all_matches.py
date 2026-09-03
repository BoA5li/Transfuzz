#!/usr/bin/env python3
"""Regression tests for full-budget Stage 3 match collection."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seed_pool import Seed
from stage3_controller import Stage3Controller


class Stage3CollectAllMatchesTests(unittest.TestCase):
    def setUp(self):
        Seed._next_id = 0
        self.tmp = tempfile.TemporaryDirectory()
        self.asm_path = os.path.join(self.tmp.name, "seed.s")
        with open(self.asm_path, "w") as stream:
            stream.write("ret\n")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _passed_result():
        return {
            "score": 1.0,
            "passed": True,
            "match_rate": 1.0,
            "match_count": 2,
            "mean_expected_latency": 20.0,
            "num_rounds": 2,
        }

    def _controller(self, budget):
        controller = Stage3Controller({
            "budget": budget,
            "pool_size": 20,
            "work_dir": self.tmp.name,
            "driver_c": self.asm_path,
            "pmu_helper_obj": self.asm_path,
            "report_interval": 100,
        })
        controller._sanity_check = lambda: True
        controller._precompile_stage3_obj = lambda: None
        controller._archive_success = lambda *args, **kwargs: os.path.join(
            self.tmp.name, kwargs.get("tag", "match"))
        return controller

    def test_baseline_match_does_not_skip_later_baselines_or_budget(self):
        controller = self._controller(budget=3)
        evaluated = []

        def evaluate(seed, tag):
            evaluated.append(tag)
            return self._passed_result()

        mutation_rounds = []

        def mutation(round_index):
            mutation_rounds.append(round_index)
            seed = Seed(self.asm_path, score=1.0)
            seed.eval_detail = self._passed_result()
            return {"passed": True, "seed": seed}

        controller._evaluate_seed = evaluate
        controller._mutation_round = mutation

        first = controller.run([
            Seed(self.asm_path, score=1.0),
            Seed(self.asm_path, score=1.0),
        ])

        self.assertEqual(2, len(evaluated))
        self.assertEqual([0, 1, 2], mutation_rounds)
        self.assertIs(first, controller.success_seeds[0])
        self.assertEqual(5, len(controller.success_seeds))
        self.assertEqual(3, controller.run_summary["mutation_rounds_attempted"])
        self.assertEqual(5, controller.run_summary["completed_evaluations"])
        self.assertEqual(5, controller.run_summary["match_seed_count"])
        self.assertEqual(
            100.0,
            controller.run_summary[
                "matches_per_100_completed_evaluations"])

        summary_path = os.path.join(
            self.tmp.name, "stage3_match_summary.json")
        with open(summary_path) as stream:
            persisted = json.load(stream)
        self.assertEqual(5, len(persisted["matches"]))
        self.assertEqual("baseline", persisted["first_match"]["stage"])
        self.assertEqual(2, persisted["last_match"]["round_index"])

    def test_no_match_still_runs_full_budget_and_writes_summary(self):
        controller = self._controller(budget=2)
        no_match = dict(self._passed_result(), passed=False, score=0.2,
                        match_rate=0.0, match_count=0)
        controller._evaluate_seed = lambda seed, tag: no_match
        rounds = []

        def mutation(round_index):
            rounds.append(round_index)
            return None

        controller._mutation_round = mutation
        result = controller.run([Seed(self.asm_path, score=1.0)])

        self.assertIsNone(result)
        self.assertEqual([0, 1], rounds)
        self.assertEqual("no_match", controller.run_summary["status"])
        self.assertEqual(2, controller.run_summary["mutation_rounds_attempted"])


if __name__ == "__main__":
    unittest.main()
