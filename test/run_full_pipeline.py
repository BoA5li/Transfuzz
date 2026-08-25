#!/usr/bin/env python3
"""
run_full_pipeline.py

三阶段自动化检测流水线。

流程:
  输入待测程序 (.c / .s)
    → 预处理(编译/插桩)
    → Stage 1: 分支误预测检测 + 变异循环
      → passed seeds → 锁定变异点
    → Stage 2: Cache 加载检测 + 变异循环
      → passed seeds → 继续锁定
    → Stage 3: Flush-Reload 数据恢复 + 变异循环
      → match=1 → 检测成功
      → 全部失败 → 检测未通过

每个阶段:
  - 只有前阶段 passed 的种子才能进入下一阶段
  - 跑完迭代次数后检查是否有 passed 种子
  - 无 passed 种子 → 流水线终止
  - 变异点跨阶段锁定，保护前阶段的有效变异

Compatible with Python 3.6+.
"""

import sys
import os
import argparse
import json
import re
import subprocess
import logging
import time
from pathlib import Path

# 确保能导入项目模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from seed_pool import Seed
from stage1_controller import Stage1Controller
from stage2_controller import Stage2Controller
from stage3_controller import Stage3Controller


logger = logging.getLogger("pipeline")


# ================================================================
# 预处理: C → .s → 插桩
# ================================================================

def is_lineno_comment(stripped):
    return bool(re.match(r"^#\s+\d+", stripped))


def process_asm(lines,
                begin_label="STAGE1_BEGIN",
                end_label="STAGE1_END",
                nop_region_begin="# NOP_REGION_BEGIN",
                nop_region_end="# NOP_REGION_END"):
    """
    汇编预处理:
    1) 在 STAGE1_BEGIN/END 处插入 PMU 调用
    2) 对 NOP_REGION 区域压缩为 nop
    3) 过滤 #APP / #NO_APP / 行号注释
    """
    out = []
    in_nop_region = False
    nop_emitted = False

    for line in lines:
        stripped = line.strip()

        if (stripped == "#APP" or stripped == "#NO_APP"
                or is_lineno_comment(stripped)):
            continue

        if stripped.startswith(nop_region_begin):
            in_nop_region = True
            nop_emitted = False
            continue

        if stripped.startswith(nop_region_end):
            in_nop_region = False
            nop_emitted = False
            continue

        if stripped == "{}:".format(begin_label):
            out.append(line)
            out.append("\tcall pmu_stage1_before\n")
            continue

        if stripped == "{}:".format(end_label):
            out.append(line)
            out.append("\tcall pmu_stage1_after\n")
            continue

        if in_nop_region:
            if (stripped == "" or stripped.startswith(".")
                    or stripped.startswith("#")
                    or stripped.endswith(":")):
                continue
            if not nop_emitted:
                out.append("\tnop\n")
                nop_emitted = True
            continue

        out.append(line)

    return out


def preprocess_input(input_path, work_dir, gcc="gcc"):
    """
    将输入 .c / .s 预处理为插桩后的 .s 文件。

    返回: 插桩后的 .s 文件路径
    """
    input_path = Path(input_path)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    if input_path.suffix == ".c":
        # C → .s
        s_file = work_dir / (input_path.stem + ".s")
        logger.info("Compiling {} -> {}".format(input_path, s_file))
        r = subprocess.run(
            [gcc, "-S", str(input_path), "-o", str(s_file)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            logger.error("Compilation failed: {}".format(
                r.stderr.decode("utf-8", errors="ignore")[:500]))
            return None
    elif input_path.suffix == ".s":
        # 复制 .s 到 work_dir
        s_file = work_dir / input_path.name
        if str(input_path.resolve()) != str(s_file.resolve()):
            import shutil
            shutil.copy2(str(input_path), str(s_file))
    else:
        logger.error(
            "Input must be .c or .s file, got: {}".format(
                input_path.suffix))
        return None

    # 插桩
    with s_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    out_lines = process_asm(lines)

    instrumented_s = work_dir / (input_path.stem + "_instrumented.s")
    with instrumented_s.open("w", encoding="utf-8") as f:
        f.writelines(out_lines)

    logger.info("Instrumented assembly: {}".format(instrumented_s))
    return str(instrumented_s)


# ================================================================
# 主流水线
# ================================================================

def run_pipeline(args):
    """三阶段自动化流水线主函数"""
    start_time = time.time()

    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    expected_secret_char = args.expected_secret[0]
    expected_secret_byte = ord(expected_secret_char)
    os.environ['VF_EXPECTED_SECRET'] = str(expected_secret_byte)
    logger.info(f"Expected secret: '{expected_secret_char}' (0x{expected_secret_byte:02x})")

    # ============================================================
    # 预处理
    # ============================================================
    logger.info("=" * 70)
    logger.info("PIPELINE: Preprocessing")
    logger.info("=" * 70)

    seed_s = preprocess_input(
        args.input, work_dir / "preprocess", gcc=args.gcc)
    if seed_s is None:
        logger.error("Preprocessing failed. Pipeline aborted.")
        return None

    # ============================================================
    # Stage 1: 分支误预测检测
    # ============================================================
    logger.info("")
    logger.info("=" * 70)
    logger.info("PIPELINE: Stage 1 - Branch Misprediction Detection")
    logger.info("=" * 70)

    s1_config = {
        "victim_c": args.input,           # Stage1Controller 使用 victim_c
        "period": args.period,
        "budget": args.s1_budget,
        "pool_size": args.s1_pool_size,
        "anchors_json": args.anchors_json,
        "strong_objects_json": args.strong_objects_json,
        "work_dir": str(work_dir / "stage1"),
        "cc": args.gcc,
        "pmu_helper_obj": args.pmu_helper_obj,
        "pmu_uops_obj": args.pmu_uops_obj,
    }

    s1_ctrl = Stage1Controller(s1_config)
    s1_passed = s1_ctrl.run()

    # 导出 locked PCs
    s1_locked_pcs = {}
    if s1_passed:
        for seed in s1_passed:
            child = seed.create_child_for_next_stage()
            locked_pcs = [pc for pc in child.cross_stage_locked_pcs if pc is not None]
            s1_locked_pcs[seed.asm_path] = sorted(locked_pcs)

        locked_path = work_dir / "stage1" / "stage1_locked_pcs.json"
        with open(str(locked_path), "w") as f:
            json.dump(s1_locked_pcs, f, indent=2)
        logger.info("Stage 1 locked PCs exported: {}".format(
            locked_path))

    logger.info("")
    logger.info("-" * 70)
    logger.info("PIPELINE: Stage 1 Result: {} passed seeds".format(
        len(s1_passed) if s1_passed else 0))
    logger.info("-" * 70)

    if not s1_passed:
        logger.error(
            "PIPELINE: No seeds passed Stage 1. "
            "Pipeline TERMINATED.")
        _print_final_result(False, "stage1", start_time)
        return None

    # ============================================================
    # Stage 2: Cache 加载检测
    # ============================================================
    logger.info("")
    logger.info("=" * 70)
    logger.info("PIPELINE: Stage 2 - Cache Loading Detection")
    logger.info("=" * 70)

    s2_config = {
        "driver_c": args.driver_c,         # Stage2Controller 使用 driver_c
        "stage3_driver_c": args.stage3_driver_c,
        "budget": args.s2_budget,
        "pool_size": args.s2_pool_size,
        "anchors_json": args.anchors_json,
        "strong_objects_json": args.strong_objects_json,
        "work_dir": str(work_dir / "stage2"),
        "cc": args.gcc,
        "pmu_helper_obj": args.pmu_helper_obj,
        "pmu_uops_obj": args.pmu_uops_obj,
        "expected_secret": expected_secret_byte,
    }

    s2_ctrl = Stage2Controller(s2_config)
    s2_passed = s2_ctrl.run(s1_passed)

    # 导出 locked PCs（Stage 1 + Stage 2）
    s2_locked_pcs = {}
    if s2_passed:
        for seed in s2_passed:
            child = seed.create_child_for_next_stage()
            locked_pcs = [pc for pc in child.cross_stage_locked_pcs if pc is not None]
            s2_locked_pcs[seed.asm_path] = sorted(locked_pcs)

        locked_path = work_dir / "stage2" / "stage2_locked_pcs.json"
        with open(str(locked_path), "w") as f:
            json.dump(s2_locked_pcs, f, indent=2)
        logger.info("Stage 2 locked PCs exported: {}".format(
            locked_path))

    logger.info("")
    logger.info("-" * 70)
    logger.info("PIPELINE: Stage 2 Result: {} passed seeds".format(
        len(s2_passed) if s2_passed else 0))
    logger.info("-" * 70)

    if not s2_passed:
        logger.error(
            "PIPELINE: No seeds passed Stage 2. "
            "Pipeline TERMINATED.")
        _print_final_result(False, "stage2", start_time)
        return None

    # ============================================================
    # Stage 3: Flush-Reload 数据恢复
    # ============================================================
    logger.info("")
    logger.info("=" * 70)
    logger.info("PIPELINE: Stage 3 - Secret Recovery (Flush-Reload)")
    logger.info("=" * 70)

    s3_config = {
        "driver_c": args.driver_c,         # Stage3Controller 使用 driver_c
        "stage3_driver_c": args.stage3_driver_c,
        "budget": args.s3_budget,
        "pool_size": args.s3_pool_size,
        "anchors_json": args.anchors_json,
        "strong_objects_json": args.strong_objects_json,
        "work_dir": str(work_dir / "stage3"),
        "cc": args.gcc,
        "pmu_helper_obj": args.pmu_helper_obj,
        "pmu_uops_obj": args.pmu_uops_obj,
        "dump_times": args.dump_times,
        "expected_secret": expected_secret_byte,
    }

    s3_ctrl = Stage3Controller(s3_config)
    success_seed, all_evaluated = s3_ctrl.run(s2_passed)

    # 导出结果
    if success_seed:
        success_info = {
            "seed_id": success_seed.id,
            "asm_path": success_seed.asm_path,
            "score": success_seed.score,
            "cross_stage_locked_pcs": sorted(
                list(success_seed.cross_stage_locked_pcs)),
            "stage3_mutated_pcs": sorted(
                list(success_seed.current_stage_mutated_pcs)),
        }
        if success_seed.eval_detail:
            success_info["match_rate"] = \
                success_seed.eval_detail.get("match_rate", 0)
            success_info["mean_expected_latency"] = \
                success_seed.eval_detail.get(
                    "mean_expected_latency", 0)

        export_path = work_dir / "stage3" / "stage3_success.json"
        with open(str(export_path), "w") as f:
            json.dump(success_info, f, indent=2)

    logger.info("")
    logger.info("-" * 70)
    if success_seed:
        logger.info(
            "PIPELINE: Stage 3 Result: SECRET RECOVERED!")
    else:
        logger.info(
            "PIPELINE: Stage 3 Result: FAILED - "
            "Secret not recovered")
    logger.info("-" * 70)

    _print_final_result(
        success_seed is not None, "complete", start_time,
        success_seed=success_seed,
        s1_passed_count=len(s1_passed),
        s2_passed_count=len(s2_passed),
        s3_ctrl=s3_ctrl)

    return success_seed


def _print_final_result(success, stopped_at, start_time,
                        success_seed=None,
                        s1_passed_count=0,
                        s2_passed_count=0,
                        s3_ctrl=None):
    """打印最终结果摘要"""
    elapsed = time.time() - start_time

    print("")
    print("=" * 70)
    print("PIPELINE FINAL RESULT")
    print("=" * 70)
    print("")

    if success:
        print("  Status: VULNERABLE - Secret successfully recovered")
    else:
        print("  Status: NOT CONFIRMED - Detection stopped at {}".format(
            stopped_at))

    print("")
    print("  Stage 1 (Branch Misprediction): {} passed seeds".format(
        s1_passed_count))
    print("  Stage 2 (Cache Loading):        {} passed seeds".format(
        s2_passed_count))

    if stopped_at == "complete":
        if success and success_seed:
            ed = success_seed.eval_detail or {}
            print("  Stage 3 (Secret Recovery):      MATCH FOUND")
            print("")
            print("  Success Seed:")
            print("    ID: {}".format(success_seed.id))
            print("    ASM: {}".format(success_seed.asm_path))
            print("    Match rate: {:.3f}".format(
                ed.get("match_rate", 0)))
            print("    Mean latency: {:.1f} cycles".format(
                ed.get("mean_expected_latency", 0)))
            print("    Locked PCs: {}".format(
                success_seed.cross_stage_locked_pcs))
            print("    Stage 3 mutated PCs: {}".format(
                success_seed.current_stage_mutated_pcs))
        else:
            print("  Stage 3 (Secret Recovery):      NO MATCH")
            if s3_ctrl:
                best = s3_ctrl.seed_pool.get_best_seed()
                if best and best.eval_detail:
                    ed = best.eval_detail
                    print("")
                    print("  Best Stage 3 seed:")
                    print("    Score: {:.4f}".format(best.score))
                    print("    Mean latency: {:.1f}".format(
                        ed.get("mean_expected_latency", 0)))

    print("")
    print("  Total time: {:.1f}s".format(elapsed))
    print("=" * 70)


# ================================================================
# 入口
# ================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Three-stage transient execution detection "
                    "pipeline with mutation-guided fuzzing.")

    # 输入
    ap.add_argument("input",
                    help="Input C (.c) or assembly (.s) file "
                         "(the program under test)")

    # 通用参数
    ap.add_argument("--gcc", default="gcc",
                    help="GCC compiler (default: gcc)")
    ap.add_argument("-p", "--period", type=int, default=6,
                    help="Train/attack period for Stage 1 "
                         "(default: 6)")
    ap.add_argument("--driver-c",
                    default="auto_stage1_2_3_driver.c",
                    help="Stage 2/3 driver C file")
    ap.add_argument("--stage3-driver-c",
                    default="stage3_driver_safe.c",
                    help="Stage 3 flush-reload driver C file")
    ap.add_argument("--pmu-helper-obj",
                    default="pmu_helper_auto.o",
                    help="PMU helper object file")
    ap.add_argument("--pmu-uops-obj",
                    default="pmu_uops_rdpmc.o",
                    help="UOPS measurement object file")

    # 分析器输出
    ap.add_argument("--anchors-json",
                    default="assembly_anchor_candidates.json",
                    help="Anchor candidates from analyzer")
    ap.add_argument("--strong-objects-json",
                    default="strong_causal_objects.json",
                    help="Strong causal objects from analyzer")

    # Stage 1 参数
    ap.add_argument("--s1-budget", type=int, default=1000,
                    help="Stage 1 mutation budget (default: 100)")
    ap.add_argument("--s1-pool-size", type=int, default=100,
                    help="Stage 1 seed pool size (default: 50)")

    # Stage 2 参数
    ap.add_argument("--s2-budget", type=int, default=1000,
                    help="Stage 2 mutation budget (default: 200)")
    ap.add_argument("--s2-pool-size", type=int, default=100,
                    help="Stage 2 seed pool size (default: 100)")

    # Stage 3 参数
    ap.add_argument("--s3-budget", type=int, default=1000,
                    help="Stage 3 mutation budget (default: 1000)")
    ap.add_argument("--s3-pool-size", type=int, default=200,
                    help="Stage 3 seed pool size (default: 200)")
    ap.add_argument("--dump-times", type=int, default=1,
                    help="Stage 3 dump access latencies "
                         "(default: 1)")
    ap.add_argument('--expected-secret', type=str, default='Y',
                    help='Expected secret value for Stage 3 verification')
    ap.add_argument("--enable-stage3", action="store_true", default=True)
    ap.add_argument("--stage3-mode",   default="flush-reload",
                    choices=["flush-reload", "prime-probe", "custom"])

    # 工作目录和日志
    ap.add_argument("--work-dir", default="./pipeline_work",
                    help="Working directory (default: "
                         "./pipeline_work)")
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = ap.parse_args()

    # 配置日志
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    # 验证输入
    if not os.path.exists(args.input):
        sys.stderr.write(
            "Input file not found: {}\n".format(args.input))
        sys.exit(1)

    logger.info("=" * 70)
    logger.info("THREE-STAGE TRANSIENT EXECUTION DETECTION PIPELINE")
    logger.info("=" * 70)
    logger.info("Input: {}".format(args.input))
    logger.info("Work dir: {}".format(args.work_dir))
    logger.info("Stage 1: budget={}, pool={}".format(
        args.s1_budget, args.s1_pool_size))
    logger.info("Stage 2: budget={}, pool={}".format(
        args.s2_budget, args.s2_pool_size))
    logger.info("Stage 3: budget={}, pool={}".format(
        args.s3_budget, args.s3_pool_size))
    logger.info("")

    result = run_pipeline(args)

    return 0 if result is not None else 1


if __name__ == "__main__":
    sys.exit(main())