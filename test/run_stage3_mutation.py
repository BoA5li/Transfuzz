#!/usr/bin/env python3
"""
run_stage3_mutation.py - 添加配置变异开关

新增参数：
  --enable-config-mutation: 启用配置参数变异
  --config-mutation-prob: 配置变异概率（默认 0.3）
  --enable-asm-mutation: 启用汇编变异（默认 True）
  --asm-mutation-prob: 汇编变异概率（默认 0.7）
  --stage3-config: 初始配置文件路径
"""

import argparse
import logging
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seed_pool import Seed
from stage3_controller import Stage3Controller


def main():
    ap = argparse.ArgumentParser(
        description="Stage 3: secret recovery via flush-reload")

    ap.add_argument("--seed-asm", nargs="+", required=True,
                    help="Stage 2 passed seed .s files")
    ap.add_argument("--locked-pcs", default=None,
                    help="JSON: asm_path -> list of locked PCs "
                         "from Stage 1+2")

    ap.add_argument("--driver-c",
                    default="auto_stage1_2_3_driver.c")
    ap.add_argument("--stage3-driver-c",
                    default="stage3_driver_safe.c")
    ap.add_argument("--pmu-helper-obj",
                    default="pmu_helper_auto.o")
    ap.add_argument("--pmu-uops-obj",
                    default="pmu_uops_rdpmc.o")

    ap.add_argument("--budget", type=int, default=1000)
    ap.add_argument("--pool-size", type=int, default=200)
    ap.add_argument("--anchors-json", default=None)
    ap.add_argument("--strong-objects-json", default=None)
    ap.add_argument("--work-dir", default="./stage3_work")
    ap.add_argument("--gcc", default="gcc")
    ap.add_argument("--run-timeout", type=int, default=180)
    ap.add_argument("--report-interval", type=int, default=50)
    ap.add_argument("--dump-times", type=int, default=1,
                    help="Enable debug time dump (default: 1)")
    
    # ============================================================
    # 新增：Stage 3 配置变异参数
    # ============================================================
    ap.add_argument("--enable-config-mutation", action="store_true",
                    help="Enable Stage 3 config parameter mutation "
                         "(default: disabled)")
    ap.add_argument("--config-mutation-prob", type=float, default=0.3,
                    help="Probability of config mutation per round "
                         "(default: 0.3)")
    ap.add_argument("--enable-asm-mutation", action="store_true", default=False,
                    help="Enable assembly mutation (default: enabled)")
    ap.add_argument("--asm-mutation-prob", type=float, default=0.7,
                    help="Probability of assembly mutation per round "
                         "(default: 0.7)")
    ap.add_argument("--stage3-config", default=None,
                    help="Path to initial Stage 3 config JSON "
                         "(default: auto-generated)")
    ap.add_argument("--verbose", action="store_true",
                    help="Print detailed config and mutation info")
    
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
            sys.stderr.write(
                "Seed asm not found: {}\n".format(p))
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

    # 构造 Stage 2 passed 种子
    stage2_passed = []
    for asm_path in args.seed_asm:
        locked = locked_pcs_map.get(asm_path, [])
        seed = Seed(asm_path=asm_path, score=1.0,
                    cross_stage_locked_pcs=set(locked))
        stage2_passed.append(seed)

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
        "pmu_uops_obj": args.pmu_uops_obj,
        "run_timeout": args.run_timeout,
        "report_interval": args.report_interval,
        "dump_times": args.dump_times,
        
        # ============================================================
        # 新增：Stage 3 配置变异参数
        # ============================================================
        "enable_config_mutation": args.enable_config_mutation,
        "config_mutation_probability": args.config_mutation_prob,
        "enable_asm_mutation": args.enable_asm_mutation,
        "asm_mutation_probability": args.asm_mutation_prob,
        "stage3_config_path": args.stage3_config,
        "verbose": args.verbose,
    }

    controller = Stage3Controller(config)
    success_seed, all_evaluated = controller.run(stage2_passed)

    # 输出结果
    print("")
    print("=" * 60)
    if success_seed:
        print("Stage 3 Result: SECRET RECOVERED!")
        print("=" * 60)
        print("  ID: {}".format(success_seed.id))
        print("  Score: {:.4f}".format(success_seed.score))
        print("  ASM: {}".format(success_seed.asm_path))
        print("  Cross-stage locked PCs: {}".format(
            success_seed.cross_stage_locked_pcs))
        print("  Stage 3 mutated PCs: {}".format(
            success_seed.current_stage_mutated_pcs))
        if success_seed.eval_detail:
            ed = success_seed.eval_detail
            print("  Match rate: {:.3f}".format(
                ed.get("match_rate", 0)))
            print("  Mean latency: {:.1f}".format(
                ed.get("mean_expected_latency", 0)))
        
        # 打印最终配置
        if args.enable_config_mutation:
            print("")
            print("  Final Stage 3 config:")
            for key, value in controller.current_stage3_config.items():
                print("    {}: {}".format(key, value))
    else:
        print("Stage 3 Result: FAILED - Secret not recovered")
        print("=" * 60)
        best = controller.seed_pool.get_best_seed()
        if best and best.eval_detail:
            ed = best.eval_detail
            print("  Best seed: id={}, score={:.4f}".format(
                best.id, best.score))
            print("  Mean latency: {:.1f}".format(
                ed.get("mean_expected_latency", 0)))
        print("")
        print("  Suggestions:")
        print("  - Increase --budget")
        print("  - Try --enable-config-mutation to adapt flush-reload params")
        print("  - Try different Stage 2 passed seeds")
        print("  - Check if Stage 2 signal is strong enough")
        print("  - Adjust cache_hit_threshold for your CPU architecture")

    return 0 if success_seed else 1


if __name__ == "__main__":
    sys.exit(main())