#!/usr/bin/env python3
"""
run_stage1_mutation.py

Stage 1 变异循环入口（优化版）。
- TRAIN/DETECT membership is supplied by runtime sample labels
Compatible with Python 3.6+.
"""

import argparse
import logging
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stage1_controller import Stage1Controller
from stage1_evaluator import DEFAULT_BRMISP_WEIGHT, DEFAULT_UOPS_WEIGHT
from run_stage_pipeline_stage1_2_3 import (
    STAGE1_PMU_EVENTS, normalize_stage1_pmu_event)


def main():
    ap = argparse.ArgumentParser(
        description="Stage 1 mutation loop with seed pool and "
                    "feedback-guided scheduling."
    )

    ap.add_argument("victim_c",
                    help="Path to victim C source file")
    ap.add_argument("--budget", type=int, default=1000,
                    help="Mutation budget (default: 1000)")
    ap.add_argument("--pool-size", type=int, default=200,
                    help="Seed pool max size (default: 200)")
    ap.add_argument("--anchors-json", default=None,
                    help="Path to assembly_anchor_candidates.json")
    ap.add_argument("--strong-objects-json", default=None,
                    help="Path to strong_causal_objects.json")
    ap.add_argument("--work-dir", default="./stage1_work",
                    help="Working directory (default: ./stage1_work)")
    ap.add_argument("--gcc", default="gcc",
                    help="GCC executable (default: gcc)")
    ap.add_argument("--pmu-helper-obj", default="pmu_helper_auto.o",
                    help="Path to pmu_helper_auto.o")
    ap.add_argument("--pmu-uops-obj", default="pmu_uops_rdpmc.o",
                    help="Path to pmu_uops_rdpmc.o")
    ap.add_argument("--stage1-pmu-event", default="conditional",
                    type=normalize_stage1_pmu_event,
                    choices=sorted(STAGE1_PMU_EVENTS),
                    help="Stage 1 PMU event selected during instrumentation "
                         "(default: conditional)")
    ap.add_argument("--brmisp-weight", type=float,
                    default=DEFAULT_BRMISP_WEIGHT,
                    help="BR_MISP score weight (default: 0.8)")
    ap.add_argument("--uops-weight", type=float,
                    default=DEFAULT_UOPS_WEIGHT,
                    help="UOPS score weight (default: 0.2)")
    ap.add_argument("--run-timeout", type=int, default=60,
                    help="Execution timeout seconds (default: 60)")
    ap.add_argument("--early-stop", type=int, default=10,
                    help="Stop after N passed seeds (default: 10)")
    ap.add_argument("--report-interval", type=int, default=50,
                    help="Report stats every N rounds (default: 50)")
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                    help="Logging level (default: INFO)")

    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if not os.path.exists(args.victim_c):
        sys.stderr.write("Error: victim C file not found: {}\n".format(
            args.victim_c))
        sys.exit(1)

    if not os.path.exists(args.pmu_helper_obj):
        sys.stderr.write("Error: pmu_helper_auto.o not found: {}\n".format(
            args.pmu_helper_obj))
        sys.stderr.write(
            "Build: gcc -c pmu_helper_auto.c -o pmu_helper_auto.o\n")
        sys.exit(1)

    if not os.path.exists(args.pmu_uops_obj):
        sys.stderr.write("Error: {} not found.\n".format(args.pmu_uops_obj))
        sys.stderr.write(
            "Build: gcc -c pmu_uops_rdpmc.c -o pmu_uops_rdpmc.o\n")
        sys.stderr.write(
            "Stage 1 requires readable UOPS PMU measurements and will stop.\n")
        return 2

    config = {
        "victim_c": args.victim_c,
        "budget": args.budget,
        "pool_size": args.pool_size,
        "anchors_json": args.anchors_json,
        "strong_objects_json": args.strong_objects_json,
        "work_dir": args.work_dir,
        "cc": args.gcc,
        "pmu_helper_obj": args.pmu_helper_obj,
        "pmu_uops_obj": args.pmu_uops_obj,
        "stage1_pmu_event": args.stage1_pmu_event,
        "brmisp_weight": args.brmisp_weight,
        "uops_weight": args.uops_weight,
        "run_timeout": args.run_timeout,
        "early_stop_passed": args.early_stop,
        "report_interval": args.report_interval,
    }

    controller = Stage1Controller(config)
    passed_seeds = controller.run()

    print("")
    print("=" * 60)
    print("Stage 1 Results: {} passed seeds".format(len(passed_seeds)))
    print("=" * 60)

    for i, seed in enumerate(passed_seeds):
        print("")
        print("  Seed {}:".format(i + 1))
        print("    ID: {}".format(seed.id))
        print("    Score: {:.4f}".format(seed.score))
        print("    ASM: {}".format(seed.asm_path))
        print("    Cross-stage locked PCs: {}".format(
            seed.cross_stage_locked_pcs))
        print("    Stage mutated PCs: {}".format(
            seed.current_stage_mutated_pcs))
        print("    Mutations: {}".format(len(seed.mutation_history)))
        if seed.eval_detail:
            print("    Runtime phases: train={}, detect={}, contract={}".format(
                seed.eval_detail.get("train_count", 0),
                seed.eval_detail.get("detect_count", 0),
                seed.eval_detail.get("phase_contract", "unknown")))
            br = seed.eval_detail.get("brmisp", {})
            uops = seed.eval_detail.get("uops", {})
            print("    BR_MISP: elevation_rate={:.3f}, "
                "stability={:.3f}, pattern_quality={:.3f}, "
                "baseline_mean={}".format(
                    br.get("elevation_rate", 0),
                    br.get("train_stability", 0),
                    br.get("pattern_quality", 0),
                    br.get("baseline_mean")))
            print("    UOPS: speculative_uops={}, "
                  "stability={:.3f}, saturation={}".format(
                      uops.get("speculative_uops", 0),
                      uops.get("stability", 0),
                      uops.get("saturation_threshold", 0)))

    if passed_seeds:
        print("\nPassed seed ASM files can be used as input for Stage 2.")
        print("To prepare for Stage 2, use create_child_for_next_stage().")
    else:
        print("\nNo seeds passed Stage 1 within the budget.")
        best = controller.seed_pool.get_best_seed()
        if best:
            print("Best seed: id={}, score={:.4f}".format(
                best.id, best.score))
            
    # 导出 locked PCs 和 passed seeds 信息
    if passed_seeds:
        locked_pcs_export = {}
        passed_asm_paths = []
        for seed in passed_seeds:
            child = seed.create_child_for_next_stage()
            locked_pcs_export[seed.asm_path] = \
                sorted(list(child.cross_stage_locked_pcs))
            passed_asm_paths.append(seed.asm_path)

        export_path = os.path.join(args.work_dir, "stage1_locked_pcs.json")
        with open(export_path, "w") as f:
            json.dump(locked_pcs_export, f, indent=2)
        print("\nLocked PCs exported to: {}".format(export_path))
        print("Use with Stage 2: --locked-pcs {}".format(export_path))

    return 0 if passed_seeds else 1


if __name__ == "__main__":
    sys.exit(main())
