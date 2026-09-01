#!/usr/bin/env python3
"""
run_stage2_mutation.py

Stage 2 变异循环入口。

用法:
  python3 run_stage2_mutation.py \
      --seed-asm ./stage1_work/seed_0.s \
      --driver-c auto_stage1_2_3_driver.c \
      --stage3-driver-c stage3_driver_safe.c \
      --budget 100
"""

import argparse
import logging
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seed_pool import Seed
from stage2_controller import Stage2Controller


def main():
    ap = argparse.ArgumentParser(
        description="Stage 2: cache side-channel signal optimization.")

    ap.add_argument("--seed-asm", nargs="+", required=True,
                    help="Stage 1 passed seed .s files")
    ap.add_argument("--locked-pcs", default=None,
                    help="JSON: asm_path -> list of locked PCs from Stage 1")

    ap.add_argument("--driver-c",
                    default="auto_stage1_2_3_driver.c")
    ap.add_argument("--stage3-driver-c",
                    default="stage3_driver_safe.c",
                    help="Stage 3 driver C source (provides stage3_parse_mode etc.)")
    ap.add_argument("--pmu-helper-obj",
                    default="pmu_helper_auto.o")

    ap.add_argument("--budget", type=int, default=1000)
    ap.add_argument("--pool-size", type=int, default=200)
    ap.add_argument("--anchors-json", default=None)
    ap.add_argument("--strong-objects-json", default=None)
    ap.add_argument("--work-dir", default="./stage2_work")
    ap.add_argument("--gcc", default="gcc")
    ap.add_argument("--run-timeout", type=int, default=120)
    ap.add_argument("--early-stop", type=int, default=10)
    ap.add_argument("--report-interval", type=int, default=50)
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    # 验证输入
    for p in args.seed_asm:
        if not os.path.exists(p):
            sys.stderr.write("seed asm not found: {}\n".format(p))
            sys.exit(1)
    for p in [args.driver_c, args.pmu_helper_obj]:
        if not os.path.exists(p):
            sys.stderr.write("required file not found: {}\n".format(p))
            sys.exit(1)

    # 解析 locked PCs
    locked_pcs_map = {}
    if args.locked_pcs:
        if os.path.exists(args.locked_pcs):
            with open(args.locked_pcs) as f:
                locked_pcs_map = json.load(f)
        else:
            try:
                locked_pcs_map = json.loads(args.locked_pcs)
            except json.JSONDecodeError:
                sys.stderr.write("Cannot parse --locked-pcs\n")
                sys.exit(1)

    # 构造 Stage 1 passed 种子
    stage1_passed = []
    for asm_path in args.seed_asm:
        locked = locked_pcs_map.get(asm_path, [])
        seed = Seed(asm_path=asm_path, score=1.0,
                    cross_stage_locked_pcs=set(locked))
        stage1_passed.append(seed)

    config = {
        "driver_c": args.driver_c,
        "stage3_driver_c": args.stage3_driver_c,
        "budget": args.budget,
        "pool_size": args.pool_size,
        "anchors_json": args.anchors_json,
        "strong_objects_json": args.strong_objects_json,
        "work_dir": args.work_dir,
        "cc": args.gcc,
        "pmu_helper_obj": args.pmu_helper_obj,
        "run_timeout": args.run_timeout,
        "early_stop_passed": args.early_stop,
        "report_interval": args.report_interval,
    }

    controller = Stage2Controller(config)
    passed_seeds = controller.run(stage1_passed)

    # 输出结果
    print("")
    print("=" * 60)
    print("Stage 2 Results: {} passed seeds".format(len(passed_seeds)))
    print("=" * 60)

    for i, seed in enumerate(passed_seeds):
        print("")
        print("  Seed {}:".format(i + 1))
        print("    ID: {}".format(seed.id))
        print("    Score: {:.4f}".format(seed.score))
        print("    ASM: {}".format(seed.asm_path))
        print("    Cross-stage locked PCs: {}".format(
            seed.cross_stage_locked_pcs))
        print("    Stage 2 mutated PCs: {}".format(
            seed.current_stage_mutated_pcs))
        if seed.eval_detail:
            ed = seed.eval_detail
            print("    Signal: {:.4f} (target={:.4f}, control={:.4f})".format(
                ed.get("mean_signal", 0),
                ed.get("mean_target_rate", 0),
                ed.get("mean_control_rate", 0)))

    return 0 if passed_seeds else 1


if __name__ == "__main__":
    sys.exit(main())
