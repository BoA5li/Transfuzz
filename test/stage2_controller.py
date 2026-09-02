#!/usr/bin/env python3
"""
stage2_controller.py

Stage 2 变异循环主控（优化版 v2）。
输入: Stage 1 passed 种子（汇编文件 + 跨阶段锁定的变异点）
度量: target_rate - control_rate (cache side-channel signal)
目标: 通过变异增大 signal，使瞬态指令成功加载目标数据到缓存

优化点:
- 入库判定统一由 seed_pool.add() 处理（移除外层 should_admit 重复检查）
- 全局超时保护：编译 30s，运行 5min，超时强制杀死进程
- 失败统计：编译/运行/超时分类统计
"""

import os
import sys
import re
import json
import subprocess
import shutil
import logging
import time

from seed_pool import Seed, SeedPool
from mutation_scheduler import MutationScheduler
from stage2_evaluator import stage2_evaluate, parse_stage2_pmu_status
from stage2_pmu_preflight import run_stage2_pmu_preflight

logger = logging.getLogger("stage2")


class Stage2Controller(object):
    """Stage 2 主控器（优化版）"""

    def __init__(self, config):
        self.config = config

        # 所有路径转为绝对路径
        def _abs(p):
            if p and not os.path.isabs(p):
                return os.path.abspath(p)
            return p

        self.driver_c = _abs(config.get("driver_c", "auto_stage1_2_3_driver.c"))
        self.stage3_driver_c = _abs(config.get("stage3_driver_c", "stage3_driver_safe.c"))

        self.budget = config.get("budget", 1000)
        self.work_dir = _abs(config.get("work_dir", "./stage2_work"))
        self.cc = config.get("cc", "gcc")
        self.pmu_helper_obj = _abs(config.get("pmu_helper_obj", "pmu_helper_auto.o"))
        self.expected_secret = int(config.get("expected_secret", ord('Y')))

        # ============================================================
        # ✅ 新增：超时配置
        # ============================================================
        # 运行超时：默认 20 ），超时强制杀死进程
        self.run_timeout = config.get("run_timeout", 20)
        # 编译超时：默认 30 秒
        self.compile_timeout = config.get("compile_timeout", 20)

        self.report_interval = config.get("report_interval", 30)
        self.trials_per_round = config.get("trials_per_round", 1000)

        # ============================================================
        # ✅ 新增：失败统计
        # ============================================================
        self.failure_stats = {
            "process_failed": 0,      # 汇编预处理失败
            "compile_failed": 0,      # 编译/链接失败
            "compile_timeout": 0,     # 编译超时
            "run_failed": 0,          # 运行失败（非超时）
            "run_timeout": 0,         # 运行超时
            "eval_exception": 0,      # 评估流程异常
            "no_op_mutation": 0,      # 无效变异（NO-OP）
            "l1d_pmu_unavailable": 0,
            "invalid_round_data": 0,  # 缺失或越界的 Stage 2 计数
        }

        self.pmu_preflight_results = config.get("pmu_preflight_results")

        # Precompile only after PMU preflight, so initialization work cannot
        # precede the measurement-validity gate in standalone Stage 2 runs.
        self.stage3_obj = os.path.join(self.work_dir, "stage3_driver_safe.o")

        # anchors
        self.anchors = []
        self.strong_objects = []
        anchors_path = _abs(config.get("anchors_json"))
        if anchors_path and os.path.exists(anchors_path):
            with open(anchors_path) as f:
                self.anchors = json.load(f)
            logger.info("Loaded {} anchors from {}".format(
                len(self.anchors), anchors_path))

        strong_obj_path = _abs(config.get("strong_objects_json"))
        if strong_obj_path and os.path.exists(strong_obj_path):
            with open(strong_obj_path) as f:
                self.strong_objects = json.load(f)
            logger.info("Loaded {} strong objects".format(
                len(self.strong_objects)))

        self.scheduler = MutationScheduler(
            self.anchors, self.strong_objects, stage=2
        )
        self.seed_pool = SeedPool(
            max_size=config.get("pool_size", 200),
            stage_name="stage2"
        )

        os.makedirs(self.work_dir, exist_ok=True)
        self.passed_seeds = []
        self.framework_error = None

        logger.info("Stage 2 Controller initialized:")
        logger.info("  budget={}, run_timeout={}s, compile_timeout={}s".format(
            self.budget, self.run_timeout, self.compile_timeout))

    def _precompile_stage3_obj(self):
        """预编译 stage3_driver_safe.c → .o"""
        os.makedirs(self.work_dir, exist_ok=True)

        if not os.path.exists(self.stage3_driver_c):
            logger.warning("stage3_driver_safe.c not found: {}".format(
                self.stage3_driver_c))
            self.stage3_obj = None
            return

        try:
            r = subprocess.run(
                [self.cc, "-c", "-O0", self.stage3_driver_c, "-o", self.stage3_obj],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout
            )
            if r.returncode != 0:
                logger.warning("stage3_driver_safe.c compile failed: {}".format(
                    r.stderr.decode("utf-8", errors="ignore")[:300]))
                self.stage3_obj = None
            else:
                logger.info("Pre-compiled stage3_driver_safe.o: {}".format(
                    self.stage3_obj))
        except subprocess.TimeoutExpired:
            logger.warning("stage3_driver_safe.c compile timeout")
            self.stage3_obj = None

    # =========================================================
    # 主流程
    # =========================================================
    def run(self, stage1_passed_seeds):
        """
        执行 Stage 2 完整流程。

        关键语义：
        - 每个 Stage1 passed 种子都必须无条件评测 baseline
        - Baseline 评测失败的种子被跳过（与 Stage 1 区别：Stage 2 是多 baseline）
        - 至少一个 baseline 成功才能继续；全失败则硬错误终止
        - Baseline 无条件加入种子库（不经过 score 比较）
        - Baseline 即使已 passed，也继续进入变异循环（探索更多解空间）
        """
        logger.info("=" * 60)
        logger.info("Stage 2: Initialization")
        logger.info("=" * 60)

        preflight = None
        if isinstance(self.pmu_preflight_results, dict):
            preflight = self.pmu_preflight_results.get("l1d")
        if preflight is None:
            preflight = run_stage2_pmu_preflight(
                self.cc, self.pmu_helper_obj, self.work_dir,
                compile_timeout=self.compile_timeout,
                run_timeout=min(self.run_timeout, 10))
        preflight_report = os.path.join(
            self.work_dir, "stage2_l1d_pmu_preflight.json")
        try:
            with open(preflight_report, "w") as report_file:
                json.dump(preflight, report_file, indent=2, sort_keys=True)
        except (OSError, TypeError) as exc:
            self.framework_error = (
                "cannot persist Stage 2 PMU preflight report: {}".format(exc))
            return []
        if not preflight.get("ok", False):
            self.failure_stats["l1d_pmu_unavailable"] += 1
            self.framework_error = preflight.get(
                "reason", "Stage 2 L1D PMU preflight failed")
            logger.error("Stage 2 L1D PMU preflight FAILED: {}".format(
                self.framework_error))
            return []
        logger.info(
            "Stage 2 L1D PMU preflight PASSED: event={}, raw={}, value={} "
            "(zero is a valid successful read)".format(
                preflight.get("event"), preflight.get("raw_event"),
                preflight.get("value")))

        self._precompile_stage3_obj()

        # Stage 1 passed → Stage 2 种子
        stage2_seeds = []
        for s1_seed in stage1_passed_seeds:
            s2_seed = s1_seed.create_child_for_next_stage()
            stage2_seeds.append(s2_seed)
            locked = s1_seed.cross_stage_locked_pcs | s1_seed.current_stage_mutated_pcs
            logger.info("Stage1 seed id={}, score={:.4f}, locked_pcs={} "
                        "-> Stage2 seed id={}".format(
                            s1_seed.id, s1_seed.score, locked, s2_seed.id))

        if not stage2_seeds:
            logger.error("No Stage 1 passed seeds to process")
            self.framework_error = "stage2 received no input seeds"
            return []

        # ============================================================
        # 基线评估（UNCONDITIONAL：无条件评测所有 baseline）
        # ============================================================
        logger.info("=" * 60)
        logger.info("Stage 2: Collecting baselines for {} seeds "
                    "(UNCONDITIONAL evaluation)".format(len(stage2_seeds)))
        logger.info("=" * 60)

        baseline_success_count = 0
        for seed in stage2_seeds:
            # ✅ Baseline 必须无条件评测
            eval_result = self._evaluate_seed(
                seed,
                tag="s2_base_{}".format(seed.id),
                is_baseline=True
            )

            if eval_result is None:
                # ✅ 与 Stage 1 不同：Stage 2 是多 baseline 场景，
                #   单个 baseline 失败不应导致整个流程终止，仅跳过
                logger.warning(
                    "Baseline eval failed for seed {} - skipped".format(seed.id))
                continue

            seed.score = eval_result["score"]
            seed.eval_detail = eval_result

            # ✅ Baseline 无条件加入种子库（作为初始种子）
            admitted = self.seed_pool.add(seed)
            baseline_success_count += 1
            logger.info(
                "  Seed {}: score={:.4f}, signal={:.4f}, "
                "target_rate={:.4f}, control_rate={:.4f}, "
                "passed={}, admitted={}"
                .format(seed.id, eval_result["score"],
                        eval_result["mean_signal"],
                        eval_result["mean_target_rate"],
                        eval_result["mean_control_rate"],
                        eval_result["passed"],
                        admitted))

            # ✅ Baseline passed 加入 passed_seeds，但不阻止后续变异循环
            if eval_result["passed"]:
                self.passed_seeds.append(seed)
                logger.info("  >>> Baseline already passes Stage 2! <<<")

        # ============================================================
        # 至少一个 baseline 必须成功
        # ============================================================
        if baseline_success_count == 0:
            logger.error("All baseline evaluations failed - HARD ERROR")
            logger.error("Cannot proceed without any valid baseline measurement")
            self.framework_error = "all stage2 baseline evaluations failed"
            return []

        if not self.seed_pool.seeds:
            logger.error("No seeds survived baseline evaluation")
            self.framework_error = "stage2 seed pool rejected every baseline"
            return []

        logger.info("Stage 2: {}/{} baselines succeeded, entering mutation loop"
                    .format(baseline_success_count, len(stage2_seeds)))

        # ============================================================
        # 变异循环（✅ 即使有 baseline 已 passed，也进入循环探索更多解）
        # ============================================================
        logger.info("=" * 60)
        logger.info("Stage 2: Mutation loop (budget={})".format(self.budget))
        logger.info("=" * 60)

        for round_idx in range(self.budget):
            self._mutation_round(round_idx)

            if (round_idx + 1) % self.report_interval == 0:
                self._report_stats(round_idx + 1)

        logger.info("=" * 60)
        logger.info("Stage 2 complete: {} passed seeds".format(
            len(self.passed_seeds)))
        self._report_stats(self.budget)
        self._report_failure_stats()

        if not self.passed_seeds:
            logger.info("No passed seeds. Pipeline terminates.")

        return self.passed_seeds
    

    # =========================================================
    # 变异轮（精简版：入库判定统一由 seed_pool.add() 处理）
    # =========================================================
    def _mutation_round(self, round_idx):
        """
        单轮变异（带完整异常保护和超时保护）。

        超时层级：
        - 单轮总超时: ROUND_TIMEOUT 秒（防止任何环节卡死）
        - _evaluate_seed 内部各步骤独立超时（编译/运行）

        异常处理：
        - KeyboardInterrupt: 向上传播（用户中断）
        - TimeoutError: 记录后继续下一轮
        - 其他异常: 记录后继续下一轮（保证框架不退出）

        关键语义：
        - 若调度器实际未应用任何变异算子（line=0 ∧ combo=0 ∧ pcs=[]），
          视为 "无效复测"，直接丢弃本轮，不评分、不入库。
        - 评估失败（包括超时）的种子绝不进入种子库。
        - passed 种子的文件即使被 pool 拒绝也保留，供下一阶段使用。
        """
        logger.debug("=== ROUND {} ENTER ===".format(round_idx))
        import signal

        # ============================================================
        # 单轮总超时保护
        # Stage 2 比 Stage 1 运行更慢（cache 测量需要更长），
        # 超时设定为 compile_timeout + run_timeout + 余量
        # ============================================================
        ROUND_TIMEOUT = max(
            120,
            self.compile_timeout * 3 + self.run_timeout + 30
        )

        def _round_timeout_handler(signum, frame):
            raise TimeoutError(
                "Round {} timeout after {}s".format(round_idx, ROUND_TIMEOUT))

        # 保存原有 SIGALRM 处理器
        old_handler = signal.getsignal(signal.SIGALRM)

        logger.info("Round {}: Starting (pool_size={})".format(
            round_idx, len(self.seed_pool.seeds)))

        mutant_path = None  # 用于异常分支清理

        try:
            # ========================================================
            # 注册单轮超时
            # ========================================================
            signal.signal(signal.SIGALRM, _round_timeout_handler)
            signal.alarm(ROUND_TIMEOUT)

            # ========================================================
            # Step 1: 选择种子
            # ========================================================
            seed = self.seed_pool.select()
            if seed is None:
                logger.warning("Round {}: empty seed pool".format(round_idx))
                signal.alarm(0)
                return

            # ========================================================
            # Step 2: 选择锚点
            # ========================================================
            excluded = seed.get_excluded_pcs()
            anchor = self.scheduler.select_anchor(
                cross_stage_locked_pcs=excluded
            )
            if anchor is None:
                logger.debug("Round {}: no available anchors".format(round_idx))
                signal.alarm(0)
                return

            # ========================================================
            # Step 3: 应用变异
            # ========================================================
            result = self.scheduler.apply_mutation(
                seed.asm_path, anchor, self.work_dir, cross_stage_locked_pcs=excluded
            )
            if result is None:
                logger.info("Round {}: mutation apply failed".format(round_idx))
                signal.alarm(0)
                return
            mutant_path, mutation_info = result

            # ========================================================
            # ✅ Step 3.5: 无效变异检测（NO-OP 丢弃）
            # --------------------------------------------------------
            # 根据 mutation_scheduler.apply_mutation 的契约：
            #   - total_line_mutations: 逐行变异成功次数
            #   - total_combo_mutations: 组合变异成功次数
            #   - mutated_pcs: 实际被变异的 PC 列表
            # 若三者全为空 → 调度器实际未改变汇编 → 视为无效复测 → 丢弃
            # ========================================================
            total_line = mutation_info.get("total_line_mutations", 0)
            total_combo = mutation_info.get("total_combo_mutations", 0)
            mutated_pcs = mutation_info.get("mutated_pcs", []) or []

            if total_line == 0 and total_combo == 0 and len(mutated_pcs) == 0:
                logger.info(
                    "Round {}: NO-OP mutation detected "
                    "(line=0, combo=0, pcs=[]), discarding without evaluation"
                    .format(round_idx))
                self.failure_stats["no_op_mutation"] += 1
                self._cleanup_mutant(mutant_path)
                signal.alarm(0)
                return

            # ========================================================
            # Step 3.6: 构建 mutant_seed（仅在确认有真实变异后）
            # ========================================================
            anchor_pc = mutation_info["anchor_pc"]
            new_history = seed.mutation_history + [mutation_info]

            mutant_seed = Seed(
                asm_path=mutant_path,
                cross_stage_locked_pcs=seed.cross_stage_locked_pcs,
                mutation_history=new_history,
                parent_id=seed.id,
            )
            mutant_seed.current_stage_mutated_pcs = set(
                seed.current_stage_mutated_pcs)

            # ✅ 记录所有真实变异的 PC（而不仅是 anchor_pc）
            for pc in mutated_pcs:
                mutant_seed.record_mutation(pc)
            # 兼容旧逻辑：anchor_pc 也单独记录一次
            if anchor_pc:
                mutant_seed.record_mutation(anchor_pc)

            # ========================================================
            # Step 4: 评估种子（带内部超时）
            # ========================================================
            tag = "s2_r{}".format(round_idx)
            eval_result = self._evaluate_seed(
                mutant_seed, tag=tag, is_baseline=False)

            # ========================================================
            # 评估失败（包括超时）的种子绝不进入种子库
            # ========================================================
            if eval_result is None:
                logger.info(
                    "Round {}: evaluation failed for anchor {}".format(
                        round_idx, anchor_pc))
                self._cleanup_mutant(mutant_path)
                signal.alarm(0)
                return

            mutant_seed.score = eval_result["score"]
            mutant_seed.eval_detail = eval_result

            # passed 种子: 加入 passed_seeds（独立的成功种子集合）
            if eval_result["passed"]:
                self.passed_seeds.append(mutant_seed)
                logger.info(
                    "Round {}: >>> PASSED <<< score={:.4f}, signal={:.4f}, "
                    "target={:.4f}, control={:.4f}, anchor={}, "
                    "mutations={} line + {} combo"
                    .format(round_idx, eval_result["score"],
                            eval_result["mean_signal"],
                            eval_result["mean_target_rate"],
                            eval_result["mean_control_rate"],
                            anchor_pc, total_line, total_combo))

            # ========================================================
            # 入库判定统一由 seed_pool.add() 处理
            # ========================================================
            worst_before = self.seed_pool.get_worst_score()
            admitted = self.seed_pool.add(mutant_seed)

            if admitted:
                seed.children_produced += 1
                logger.debug(
                    "Round {}: admitted, score={:.4f}, pool_size={}, "
                    "prev_worst={:.4f}, passed={}, mutations={}+{}"
                    .format(round_idx, eval_result["score"],
                            len(self.seed_pool.seeds), worst_before,
                            eval_result["passed"], total_line, total_combo))
            else:
                # ✅ passed 种子绝不清理文件（供下一阶段使用）
                if eval_result["passed"]:
                    logger.debug(
                        "Round {}: rejected by pool but PASSED, "
                        "file kept for next stage".format(round_idx))
                else:
                    logger.debug(
                        "Round {}: rejected, score={:.4f} <= worst={:.4f}"
                        .format(round_idx, eval_result["score"], worst_before))
                    self._cleanup_mutant(mutant_path)

            signal.alarm(0)

        except KeyboardInterrupt:
            # 用户中断，向上传播
            signal.alarm(0)
            logger.warning("User interrupted at round {}".format(round_idx))
            if mutant_path is not None:
                try:
                    self._cleanup_mutant(mutant_path)
                except Exception:
                    pass
            raise

        except TimeoutError as te:
            # ========================================================
            # 单轮超时：记录后继续下一轮
            # ========================================================
            signal.alarm(0)
            logger.error("Round {}: ROUND TIMEOUT - {}".format(round_idx, te))
            self.failure_stats["eval_exception"] += 1
            if mutant_path is not None:
                try:
                    self._cleanup_mutant(mutant_path)
                except Exception as cleanup_err:
                    logger.debug("Cleanup error: {}".format(cleanup_err))
            return

        except Exception as e:
            # ========================================================
            # 其他异常：记录后继续下一轮（保证框架不退出）
            # ✅ 强制打印完整 traceback 到 ERROR 级别
            # ========================================================
            signal.alarm(0)
            import traceback
            tb_str = traceback.format_exc()
            logger.error("Round {}: Unexpected exception: {}".format(
                round_idx, e))
            logger.error("Round {}: FULL TRACEBACK:\n{}".format(
                round_idx, tb_str))
            self.failure_stats["eval_exception"] += 1
            if mutant_path is not None:
                try:
                    self._cleanup_mutant(mutant_path)
                except Exception as cleanup_err:
                    logger.debug("Cleanup error: {}".format(cleanup_err))
            return

        finally:
            # ========================================================
            # 确保 SIGALRM 处理器被恢复
            # ========================================================
            try:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            except Exception:
                pass
    
        

    # =========================================================
    # 评估：编译 → 运行 → 解析（带超时保护）
    # =========================================================

    def _evaluate_seed(self, seed, tag="eval", is_baseline=False):
        """
        编译、运行、评估 Stage 2（带超时保护）。
        
        超时策略：
          - 编译超时：30 秒
          - 运行超时：5 分钟（默认，可配置）
          - 任何超时都视为失败，不加入种子池
        """
        try:
            with open(seed.asm_path, "r") as f:
                asm_lines = f.readlines()

            # Stage 2 不做 Stage 1 插桩，反而要移除已有插桩
            cleaned_lines = self._remove_stage1_instrumentation(asm_lines)

            # 剥离 main
            stripped_lines = self._strip_main_function(cleaned_lines)

            # 写出
            out_dir = os.path.join(self.work_dir, tag)
            os.makedirs(out_dir, exist_ok=True)
            processed_s = os.path.join(out_dir, "victim_processed.s")
            try:
                with open(processed_s, "w") as f:
                    f.writelines(stripped_lines)
            except Exception as e:
                self.failure_stats["process_failed"] += 1
                logger.debug("[{}] Cannot write processed asm: {}".format(tag, e))
                return None

            # 编译（带超时）
            exe_path = self._compile_stage2(processed_s, out_dir, tag)
            if exe_path is None:
                return None

            # 运行（带超时 + 强制杀死）
            log_lines = self._run_executable(exe_path, tag)
            if log_lines is None:
                return None

            pmu_status, pmu_detail = parse_stage2_pmu_status(log_lines)
            if pmu_status != "ok":
                self.failure_stats["l1d_pmu_unavailable"] += 1
                self.framework_error = (
                    "Stage 2 L1D PMU runtime health check failed: {}".format(
                        pmu_detail))
                logger.error("[{}] {}".format(tag, self.framework_error))
                return None

            # 评估。无效 ROUND 数据属于测量失败，不能作为零分种子入池。
            eval_result = stage2_evaluate(log_lines)
            if eval_result.get("detail") == "invalid_stage2_data":
                self.failure_stats["invalid_round_data"] += 1
                logger.error(
                    "[{}] Invalid Stage 2 round data: {}".format(
                        tag, eval_result.get("round_validation_error")))
                return None
            return eval_result

        except subprocess.TimeoutExpired:
            # 兜底：理论上不会到达这里
            self.failure_stats["run_timeout"] += 1
            logger.debug("[{}] Timeout (uncaught)".format(tag))
            return None
        except Exception as e:
            import traceback
            self.failure_stats["eval_exception"] += 1
            logger.debug("[{}] Evaluation error: {}".format(tag, e))
            logger.debug("[{}] FULL TRACEBACK:\n{}".format(tag, traceback.format_exc()))
            return None

    def _remove_stage1_instrumentation(self, asm_lines):
        """Remove Stage 1 measurement code without changing victim logic.

        Stage 1 normally hands Stage 2 the unprocessed ``Seed.asm_path``;
        therefore its lossy NOP-region compression and LFENCE reference exist
        only in evaluation side files.  This cleanup still accepts instrumented
        assembly defensively.  It removes every supported Stage 1 PMU/UOPS
        call and complete event-selection marker sections, while retaining
        STAGE1_BEGIN/END, NOP_REGION_BEGIN/END, and unmarked LFENCE instructions
        because those may be part of the victim's control-flow contract.
        """
        result = []
        stage1_calls = {
            "pmu_stage1_before",
            "pmu_stage1_after",
            "pmu_stage1_indirect_before",
            "pmu_stage1_indirect_after",
            "pmu_stage1_disambiguation_before",
            "pmu_stage1_disambiguation_after",
            "pmu_stage1_return_before",
            "pmu_stage1_return_after",
            "pmu_stage1_set_phase",
            "pmu_uops_snap_before",
            "pmu_uops_snap_after",
            "pmu_uops_print_results",
            "pmu_stage1_get_count",
            "pmu_stage1_get_delta",
            "pmu_uops_get_count",
            "pmu_uops_get_transient",
            "pmu_uops_get_issued_delta",
            "pmu_uops_get_retired_delta",
            "pmu_uops_get_status_code",
            "pmu_uops_get_status_message",
            "pmu_uops_get_mode",
        }

        event_markers = {
            "pmu_stage1_event_indirect_selected",
            "pmu_stage1_event_disambiguation_selected",
            "pmu_stage1_event_return_selected",
        }

        stage1_markers = [
            "STAGE1_PMU_BEGIN",
            "STAGE1_PMU_END",
            "STAGE1_UOPS_BEGIN",
            "STAGE1_UOPS_END",
            "# [stage1",
            "# --- PMU",
            "# --- UOPS",
        ]

        # The Stage 1 rewriter emits a complete .pushsection/.popsection block
        # for a non-default event.  Removing only the marker label would leave
        # a global symbol and one data byte behind, so remove the whole block.
        marker_section_lines = set()
        section_start = None
        for index, line in enumerate(asm_lines):
            stripped = line.strip()
            if stripped.startswith(".pushsection"):
                section_start = index
            if section_start is not None and any(
                    marker in stripped for marker in event_markers):
                end = section_start
                while end < len(asm_lines):
                    marker_section_lines.add(end)
                    if asm_lines[end].strip().startswith(".popsection"):
                        break
                    end += 1
                section_start = None
            elif section_start is not None and stripped.startswith(
                    ".popsection"):
                section_start = None

        call_pattern = re.compile(
            r"^callq?\s+([A-Za-z_.$][A-Za-z0-9_.$]*)"
            r"(?:@(?:PLT|GOTPCREL))?(?:\s|$)")

        for index, line in enumerate(asm_lines):
            stripped = line.strip()

            if index in marker_section_lines:
                result.append("# [s2-removed] {}\n".format(stripped))
                continue

            call_match = call_pattern.match(stripped)
            if call_match and call_match.group(1) in stage1_calls:
                result.append("# [s2-removed] {}\n".format(stripped))
                continue

            is_stage1_marker = False
            for marker in stage1_markers:
                if marker in stripped:
                    is_stage1_marker = True
                    break

            if is_stage1_marker:
                result.append("# [s2-removed] {}\n".format(stripped))
                continue

            result.append(line)

        removed = sum(1 for l in result if l.startswith("# [s2-removed]"))
        if removed > 0:
            logger.debug("Removed {} Stage 1 instrumentation lines".format(removed))

        return result

    def _strip_main_function(self, asm_lines):
        """
        从汇编中剥离 main 函数体，保留 vf_* 等其他函数。

        GCC -S 输出的典型结构:
            .globl  main
            .type   main, @function
          main:
          .LFB...:
              pushq %rbp
              ...
              ret
          .LFE...:
              .size  main, .-main

        剥离策略:
          - 注释掉 .globl main / .type main / main: / .size main
          - 注释掉 main 函数体内的所有行
          - 遇到 .size main 或下一个非 main 的 .globl 时停止
        """
        result = []
        in_main = False

        for line in asm_lines:
            stripped = line.strip()

            # .globl main
            if re.match(r'^\s*\.glob[al]+\s+main\s*$', stripped):
                result.append("# [s2-strip] " + line)
                continue

            # .type main, @function
            if re.match(r'^\s*\.type\s+main\s*,\s*@function', stripped):
                result.append("# [s2-strip] " + line)
                continue

            # main: 标签
            if re.match(r'^main\s*:', stripped):
                in_main = True
                result.append("# [s2-strip] " + line)
                continue

            # .size main, .-main（main 结束标记）
            if in_main and re.match(r'^\s*\.size\s+main\s*,', stripped):
                result.append("# [s2-strip] " + line)
                in_main = False
                continue

            # 在 main 内部
            if in_main:
                # 遇到新函数开始 → main 结束
                if (re.match(r'^\s*\.glob[al]+\s+\w', stripped) and
                        'main' not in stripped):
                    in_main = False
                    result.append(line)
                    continue
                if (re.match(r'^\s*\.type\s+\w+\s*,\s*@function', stripped) and
                        'main' not in stripped):
                    in_main = False
                    result.append(line)
                    continue

                # 注释掉 main 内部代码
                result.append("# [s2-strip] " + line)
                continue

            # 不在 main 内部，保留
            result.append(line)

        return result

    def _compile_stage2(self, victim_s, out_dir, tag):
        """
        Stage 2 编译链（带超时保护）:
          gcc -c victim_processed.s         → victim.o
          gcc -c auto_stage1_2_3_driver.c   → driver.o
          gcc victim.o driver.o pmu_helper_auto.o stage3_driver_safe.o → exe
        
        超时时间：self.compile_timeout（默认 30 秒）
        """
        victim_o = os.path.join(out_dir, "victim.o")
        driver_o = os.path.join(out_dir, "driver.o")
        exe_path = os.path.join(out_dir, "stage2_exe")

        # ============================================================
        # Step 1: 编译 victim（带超时）
        # ============================================================
        try:
            r1 = subprocess.run(
                [self.cc, "-c", victim_s, "-o", victim_o],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout)
        except subprocess.TimeoutExpired:
            self.failure_stats["compile_timeout"] += 1
            logger.info("[{}] Victim asm timeout ({}s)".format(
                tag, self.compile_timeout))
            return None
        except Exception as e:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Victim asm error: {}".format(tag, e))
            return None

        if r1.returncode != 0:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Victim asm failed: {}".format(
                tag, r1.stderr.decode("utf-8", errors="ignore")[:300]))
            return None

        # ============================================================
        # Step 2: 编译 driver（带超时）
        # ============================================================
        try:
            r2 = subprocess.run(
                [self.cc, "-c", "-O0", self.driver_c, "-o", driver_o],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout)
        except subprocess.TimeoutExpired:
            self.failure_stats["compile_timeout"] += 1
            logger.info("[{}] Driver compile timeout ({}s)".format(
                tag, self.compile_timeout))
            return None
        except Exception as e:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Driver compile error: {}".format(tag, e))
            return None

        if r2.returncode != 0:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Driver compile failed: {}".format(
                tag, r2.stderr.decode("utf-8", errors="ignore")[:300]))
            return None

        # ============================================================
        # Step 3: 链接（带超时）
        # ============================================================
        link_cmd = [self.cc, victim_o, driver_o, self.pmu_helper_obj]

        # stage3_driver_safe.o
        if self.stage3_obj and os.path.exists(self.stage3_obj):
            link_cmd.append(self.stage3_obj)

        link_cmd += ["-o", exe_path]

        logger.debug("[{}] Link: {}".format(tag, " ".join(link_cmd)))

        try:
            r3 = subprocess.run(
                link_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout)
        except subprocess.TimeoutExpired:
            self.failure_stats["compile_timeout"] += 1
            logger.info("[{}] Link timeout ({}s)".format(
                tag, self.compile_timeout))
            return None
        except Exception as e:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Link error: {}".format(tag, e))
            return None

        if r3.returncode != 0:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Link failed: {}".format(
                tag, r3.stderr.decode("utf-8", errors="ignore")[:500]))
            return None

        return exe_path

    def _run_executable(self, exe_path, tag):
        """
        运行可执行文件（带超时保护 + 强制杀死）。
        
        超时策略：
        1. 使用 Popen 启动进程
        2. 每秒检查进程状态
        3. 超时后先发送 SIGTERM（优雅终止）
        4. 1 秒后仍未退出，发送 SIGKILL（强制杀死）
        5. 清理僵尸进程
        """
        import signal
        
        start_time = time.time()
        
        try:
            env = os.environ.copy()
            env.pop("ENABLE_STAGE3", None)
            env.pop("STAGE3_MODE", None)
            env["VF_EXPECTED_SECRET"] = str(self.expected_secret)
            # 启动进程
            proc = subprocess.Popen(
                [exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                #timeout=self.compile_timeout,
                env=env,                     # 必须显式 env
                preexec_fn=os.setsid  # ← 创建新进程组，便于批量杀死
            )
            
            # 轮询进程状态
            while True:
                elapsed = time.time() - start_time
                
                # 检查是否超时
                if elapsed > self.run_timeout:
                    logger.info(
                        "[{}] Execution timeout after {:.1f}s (limit: {}s), killing process"
                        .format(tag, elapsed, self.run_timeout))
                    
                    # ============================================================
                    # ✅ 强制杀死进程（分两步）
                    # ============================================================
                    
                    # Step 1: 尝试优雅终止（SIGTERM）
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        logger.debug("[{}] Sent SIGTERM to process group".format(tag))
                    except ProcessLookupError:
                        pass  # 进程已退出
                    
                    # 等待 1 秒
                    try:
                        proc.wait(timeout=1.0)
                        logger.debug("[{}] Process terminated gracefully".format(tag))
                    except subprocess.TimeoutExpired:
                        # Step 2: 强制杀死（SIGKILL）
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                            logger.debug("[{}] Sent SIGKILL to process group".format(tag))
                            proc.wait(timeout=1.0)  # 再等 1 秒
                        except (ProcessLookupError, subprocess.TimeoutExpired):
                            pass
                    
                    # 清理僵尸进程
                    try:
                        proc.communicate(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
                    
                    logger.info("[{}] Kill completed in {:.1f}s".format(
                        tag, time.time() - start_time))
                    
                    self.failure_stats["run_timeout"] += 1
                    return None
                
                # 检查进程是否已退出
                rc = proc.poll()
                if rc is not None:
                    # 进程已退出
                    stdout, stderr = proc.communicate()
                    output = stdout.decode("utf-8", errors="ignore")
                    lines = output.splitlines()
                    
                    if rc != 0:
                        self.failure_stats["run_failed"] += 1
                        pmu_status, pmu_detail = parse_stage2_pmu_status(lines)
                        if pmu_status == "error":
                            self.failure_stats["l1d_pmu_unavailable"] += 1
                            self.framework_error = (
                                "Stage 2 L1D PMU runtime health check failed: "
                                "{}".format(pmu_detail))
                        logger.debug("[{}] Execution failed: rc={}, time={:.1f}s".format(
                            tag, rc, elapsed))
                        return None
                    
                    if not lines:
                        self.failure_stats["run_failed"] += 1
                        logger.debug("[{}] Empty output (time={:.1f}s)".format(tag, elapsed))
                        return None
                    
                    logger.debug("[{}] Execution succeeded in {:.1f}s".format(tag, elapsed))
                    return lines
                
                # 等待 0.1 秒后再检查
                time.sleep(0.1)
        
        except Exception as e:
            self.failure_stats["run_failed"] += 1
            logger.debug("[{}] Execution exception: {}".format(tag, e))
            
            # 确保进程被杀死
            try:
                if proc.poll() is None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    proc.wait(timeout=1.0)
            except:
                pass
            
            return None

    def _kill_process(self, exe_path):
        """
        强制杀死超时的进程及其子进程。
        
        策略：
          1. 通过进程名 pkill -9 -f
          2. 通过基础名 killall -9
        """
        try:
            exe_name = os.path.basename(exe_path)
            
            # 方法 1: pkill -f 匹配完整命令行
            try:
                subprocess.run(
                    ["pkill", "-9", "-f", exe_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
            except Exception:
                pass
            
            # 方法 2: killall 兜底
            try:
                subprocess.run(
                    ["killall", "-9", exe_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
            except Exception:
                pass
            
            logger.debug("Killed process: {}".format(exe_name))
            
        except Exception as e:
            logger.debug("Failed to kill process {}: {}".format(exe_path, e))

    def _cleanup_mutant(self, mutant_path):
        """清理被拒绝的变异体目录"""
        try:
            d = os.path.dirname(mutant_path)
            if "mutant_" in os.path.basename(d):
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

    def _report_stats(self, round_num):
        """报告种子池统计信息（增强版：含失败统计）"""
        stats = self.seed_pool.stats()
        logger.info(
            "Round {}/{}: pool={}, passed={}, added={}, evicted={}, "
            "rejected={}, avg={:.4f}, max={:.4f}, min={:.4f}"
            .format(round_num, self.budget,
                    stats["size"], len(self.passed_seeds),
                    stats["total_added"], stats["total_evicted"],
                    stats["total_rejected"],
                    stats["avg_score"], stats["max_score"],
                    stats["min_score"]))

        # ✅ 失败统计（仅在有失败时打印）
        total_failures = sum(self.failure_stats.values())
        if total_failures > 0:
            logger.info(
                "  Failures: process={}, compile={} (timeout={}), "
                "run={} (timeout={}), eval_exc={}, l1d_pmu_unavailable={}, "
                "invalid_round_data={}"
                .format(
                    self.failure_stats["process_failed"],
                    self.failure_stats["compile_failed"],
                    self.failure_stats["compile_timeout"],
                    self.failure_stats["run_failed"],
                    self.failure_stats["run_timeout"],
                    self.failure_stats["eval_exception"],
                    self.failure_stats["l1d_pmu_unavailable"],
                    self.failure_stats["invalid_round_data"]))

        best = self.seed_pool.get_best_seed()
        if best and best.eval_detail:
            ed = best.eval_detail
            logger.info(
                "  Best: id={}, score={:.4f}, signal={:.4f}, "
                "target={:.4f}, control={:.4f}".format(
                    best.id, best.score,
                    ed.get("mean_signal", 0),
                    ed.get("mean_target_rate", 0),
                    ed.get("mean_control_rate", 0)))

    def _report_failure_stats(self):
        """完整的失败统计报告（在 run() 结束时调用）"""
        total_failures = sum(self.failure_stats.values())
        if total_failures == 0:
            logger.info("No failures recorded.")
            return
        
        logger.info("=" * 60)
        logger.info("Failure Statistics Summary:")
        logger.info("=" * 60)
        logger.info("Total failures: {}".format(total_failures))
        logger.info("  process_failed:   {}".format(self.failure_stats["process_failed"]))
        logger.info("  compile_failed:   {}".format(self.failure_stats["compile_failed"]))
        logger.info("  compile_timeout:  {}".format(self.failure_stats["compile_timeout"]))
        logger.info("  run_failed:       {}".format(self.failure_stats["run_failed"]))
        logger.info("  run_timeout:      {}".format(self.failure_stats["run_timeout"]))
        logger.info("  eval_exception:   {}".format(self.failure_stats["eval_exception"]))
        logger.info("  l1d_pmu_unavailable: {}".format(
            self.failure_stats["l1d_pmu_unavailable"]))
        logger.info("  invalid_round_data: {}".format(
            self.failure_stats["invalid_round_data"]))
        logger.info("  no_op_mutation:   {}".format(self.failure_stats["no_op_mutation"]))  
        
        # 计算失败率
        total_attempts = total_failures + self.seed_pool.total_added
        if total_attempts > 0:
            failure_rate = total_failures / float(total_attempts) * 100
            logger.info("Failure rate: {:.1f}% ({}/{})".format(
                failure_rate, total_failures, total_attempts))
