#!/usr/bin/env python3
"""
stage1_controller.py

Stage 1 变异循环主控（优化版 v2）。
- period 自动检测
- passed 种子同时加入 passed_seeds 和种子库
- 同阶段可重复变异同一位置
- 入库判定: score > 库中最差（严格判定，无论池是否已满）
- 全局超时保护：编译 30s，运行 5min，超时强制杀死进程
- 失败统计：编译/运行/超时分类统计
Compatible with Python 3.6+.
"""

import os
import sys
import json
import subprocess
import shutil
import logging
import tempfile
import time

from seed_pool import Seed, SeedPool
from mutation_scheduler import MutationScheduler
from stage1_evaluator import stage1_evaluate, detect_period, \
    parse_brmisp_deltas, parse_uops_transient, parse_uops_pmu_status, \
    DEFAULT_BRMISP_WEIGHT, DEFAULT_UOPS_WEIGHT
from uops_pmu_preflight import run_uops_pmu_preflight

logger = logging.getLogger("stage1")


class Stage1Controller(object):
    """Stage 1 主控器（优化版）"""

    def __init__(self, config):
        self.config = config

        self.victim_c = config["victim_c"]
        # period=None 表示自动检测
        self.period = config.get("period", None)

        self.budget = config.get("budget", 1000)
        self.work_dir = config.get("work_dir", "./stage1_work")
        self.cc = config.get("cc", "gcc")
        self.pmu_helper_obj = config.get("pmu_helper_obj", "pmu_helper_auto.o")
        self.pmu_uops_obj = config.get("pmu_uops_obj", "pmu_uops_rdpmc.o")
        self.brmisp_weight = config.get(
            "brmisp_weight", DEFAULT_BRMISP_WEIGHT)
        self.uops_weight = config.get("uops_weight", DEFAULT_UOPS_WEIGHT)

        # ============================================================
        # ✅ 新增：超时配置
        # ============================================================
        # 运行超时：默认（20 秒），超时强制杀死进程
        self.run_timeout = config.get("run_timeout", 20)
        # 编译超时：默认 30 秒
        self.compile_timeout = config.get("compile_timeout", 20)

        self.report_interval = config.get("report_interval", 30)

        # ============================================================
        # ✅ 新增：失败统计
        # ============================================================
        self.failure_stats = {
            "process_failed": 0,      # 汇编预处理失败
            "sanity_failed": 0,       # 健全性检查失败
            "compile_failed": 0,      # 编译/链接失败
            "compile_timeout": 0,     # 编译超时
            "run_failed": 0,          # 运行失败（非超时）
            "run_timeout": 0,         # 运行超时
            "eval_exception": 0,      # 评估流程异常
            "no_op_mutation": 0,
            "uops_pmu_unavailable": 0,
        }

        # 加载分析器输出
        self.anchors = []
        self.strong_objects = []
        anchors_path = config.get("anchors_json")
        if anchors_path:
            if os.path.exists(anchors_path):
                with open(anchors_path) as f:
                    self.anchors = json.load(f)
                logger.info("Loaded {} anchors from {}".format(
                    len(self.anchors), anchors_path))
            else:
                logger.warning("Anchors JSON not found: {}".format(anchors_path))

        strong_obj_path = config.get("strong_objects_json")
        if strong_obj_path:
            if os.path.exists(strong_obj_path):
                with open(strong_obj_path) as f:
                    self.strong_objects = json.load(f)
                logger.info("Loaded {} strong objects from {}".format(
                    len(self.strong_objects), strong_obj_path))
            else:
                logger.warning("Strong objects JSON not found: {}".format(
                    strong_obj_path))

        if not self.anchors:
            logger.warning("No anchors loaded. Mutation loop will be ineffective.")

        self.scheduler = MutationScheduler(
            self.anchors, self.strong_objects, stage=1
        )
        self.seed_pool = SeedPool(
            max_size=config.get("pool_size", 200),
            stage_name="stage1"
        )

        os.makedirs(self.work_dir, exist_ok=True)
        self.passed_seeds = []
        self.framework_error = None

        # 检测到的 period（基线阶段确定后固定使用）
        self.detected_period = self.period

        logger.info("Stage 1 Controller initialized:")
        logger.info("  budget={}, run_timeout={}s, compile_timeout={}s".format(
            self.budget, self.run_timeout, self.compile_timeout))
        logger.info(
            "  pass_gate=BR_MISP_AND_UOPS, score_weights="
            "BR_MISP:{:.3f}/UOPS:{:.3f}".format(
                self.brmisp_weight, self.uops_weight))
        
        #注册退出清理钩子
        import atexit
        atexit.register(self._cleanup_all_processes)

    def _cleanup_all_processes(self):
        """清理所有残留进程（退出时调用）"""
        logger.info("Cleaning up residual processes...")
        
        try:
            import psutil
            current_pid = os.getpid()
            current_process = psutil.Process(current_pid)
            
            # 终止所有子进程
            children = current_process.children(recursive=True)
            for child in children:
                try:
                    logger.debug(f"Killing child process: {child.pid}")
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            
            # 等待子进程退出
            gone, alive = psutil.wait_procs(children, timeout=3)
            for p in alive:
                logger.warning(f"Process {p.pid} did not terminate, force killing")
                try:
                    p.kill()
                except:
                    pass
        
        except ImportError:
            # psutil 未安装，使用 pkill 兜底
            logger.warning("psutil not installed, using pkill")
            os.system("pkill -9 -f 'mutant_.*_processed' 2>/dev/null")
            os.system("pkill -9 -f 'stage[123]_exe' 2>/dev/null")

    def run(self):
        """
        执行 Stage 1 完整流程。

        关键语义：
        - Baseline 必须无条件评测（避免高质量 baseline 被错过）
        - Baseline 评测失败视为硬错误，直接终止
        - Baseline 无条件加入种子库作为初始种子
        """

        logger.info("=" * 60)
        logger.info("Stage 1: UOPS PMU preflight")
        logger.info("=" * 60)

        preflight = run_uops_pmu_preflight(
            self.cc, self.pmu_uops_obj, self.work_dir,
            compile_timeout=self.compile_timeout,
            run_timeout=min(self.run_timeout, 10))
        preflight_report = os.path.join(
            self.work_dir, "uops_pmu_preflight.json")
        try:
            with open(preflight_report, "w") as report_file:
                json.dump(preflight, report_file, indent=2, sort_keys=True)
        except (OSError, TypeError) as exc:
            self.framework_error = (
                "cannot persist UOPS PMU preflight report: {}".format(exc))
            logger.error(self.framework_error)
            return []
        if not preflight["ok"]:
            self.failure_stats["uops_pmu_unavailable"] += 1
            self.framework_error = preflight["reason"]
            logger.error("UOPS PMU preflight FAILED: {}".format(
                preflight["reason"]))
            logger.error(
                "Stage 1 stopped before baseline collection; verify raw-event "
                "support, perf_event permissions and PMU availability.")
            return []
        logger.info(
            "UOPS PMU preflight PASSED: profile={}, mode={}, issued={}, "
            "retired={} "
            "(zero values are valid successful reads)".format(
                preflight["profile"], preflight["mode"], preflight["issued"],
                preflight["retired"]))
        logger.info("UOPS PMU preflight report: {}".format(preflight_report))

        logger.info("=" * 60)
        logger.info("Stage 1: Preprocessing")
        logger.info("=" * 60)

        seed_0 = self._preprocess()
        if seed_0 is None:
            logger.error("Preprocessing failed")
            self.framework_error = "stage1 preprocessing failed"
            return []

        logger.info("=" * 60)
        logger.info("Stage 1: Collecting baseline (UNCONDITIONAL evaluation)")
        logger.info("=" * 60)

        # ✅ Baseline 必须无条件评测：即使评测失败也明确报错，
        #    避免高质量 baseline 被错过
        baseline_eval = self._evaluate_seed(seed_0, tag="baseline", is_baseline=True)
        if baseline_eval is None:
            logger.error("Baseline evaluation failed - this is a HARD ERROR")
            logger.error("Cannot proceed without a valid baseline measurement")
            if self.framework_error is None:
                self.framework_error = "stage1 baseline evaluation failed"
            return []

        # 从基线评估中获取 period
        self.detected_period = baseline_eval.get("period", self.period)
        if self.detected_period is None:
            self.detected_period = 6
            logger.warning("Period detection failed, using default 6")

        seed_0.score = baseline_eval["score"]
        seed_0.eval_detail = baseline_eval

        # ✅ Baseline 无条件加入种子库（作为初始种子，不经过 score 比较）
        admitted_baseline = self.seed_pool.add(seed_0)
        logger.info("Baseline admitted to pool: {}".format(admitted_baseline))

        br = baseline_eval["brmisp"]
        uops = baseline_eval["uops"]
        logger.info("Baseline score: {:.4f}".format(baseline_eval["score"]))
        logger.info("  Detected period: {} (confidence: {:.3f}, method: {})".format(
            self.detected_period,
            baseline_eval.get("period_confidence", 0),
            baseline_eval.get("period_detail", "unknown")))
        logger.info("  BR_MISP: passed={}, score={:.4f}, "
                    "baseline_mean={}, baseline_range={}, "
                    "stability={:.3f}, elevation_rate={:.3f}, "
                    "pattern_quality={:.3f}"
                    .format(br["passed"], br["score"],
                            br.get("baseline_mean"),
                            br.get("baseline_range"),
                            br.get("train_stability", 0),
                            br.get("elevation_rate", 0),
                            br.get("pattern_quality", 0)))
        logger.info("  UOPS: passed={}, score={:.4f}, "
                    "speculative_uops={}, stability={:.3f}, "
                    "saturation_threshold={}"
                    .format(uops["passed"], uops["score"],
                            uops.get("speculative_uops", 0),
                            uops.get("stability", 0),
                            uops.get("saturation_threshold", 0)))

        # ✅ 即使 baseline 已经 passed，也要进入变异循环（探索更多解空间）
        if baseline_eval["passed"]:
            logger.info(">>> Baseline already passes Stage 1! <<<")
            self.passed_seeds.append(seed_0)

        logger.info("=" * 60)
        logger.info("Stage 1: Mutation loop (budget={})".format(self.budget))
        logger.info("=" * 60)

        for round_idx in range(self.budget):
            self._mutation_round(round_idx)

            if self.framework_error is not None:
                logger.error(
                    "Stage 1 aborted during mutation because measurement "
                    "validity was lost: {}".format(self.framework_error))
                return []

            if (round_idx + 1) % self.report_interval == 0:
                self._report_stats(round_idx + 1)

        logger.info("=" * 60)
        logger.info("Stage 1 complete: {} passed seeds".format(
            len(self.passed_seeds)))
        self._report_stats(self.budget)
        self._report_failure_stats()

        if not self.passed_seeds:
            logger.info("No passed seeds. Pipeline terminates.")

        return self.passed_seeds

    def _preprocess(self):
        """预处理: C → .s"""
        if not os.path.exists(self.victim_c):
            logger.error("Victim C file not found: {}".format(self.victim_c))
            return None

        seed_s = os.path.join(self.work_dir, "seed_0.s")

        try:
            result = subprocess.run(
                [self.cc, "-S", "-O0", self.victim_c, "-o", seed_s],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout
            )
            if result.returncode != 0:
                logger.error("Compilation failed: {}".format(
                    result.stderr.decode("utf-8", errors="ignore")))
                return None
        except subprocess.TimeoutExpired:
            logger.error("Preprocessing compilation timeout")
            return None

        logger.info("Initial seed generated: {}".format(seed_s))
        return Seed(asm_path=seed_s, score=0.0)

    def _mutation_round(self, round_idx):
        """
        单轮变异（带完整异常保护和超时保护）。

        超时层级：
        - 单轮总超时: ROUND_TIMEOUT 秒（防止任何环节卡死）
        - _evaluate_seed 内部各步骤独立超时

        异常处理：
        - KeyboardInterrupt: 向上传播（用户中断）
        - TimeoutError: 记录后继续下一轮
        - 其他异常: 记录后继续下一轮（保证框架不退出）

        关键语义：
        - 若调度器实际未应用任何变异算子（line=0 ∧ combo=0 ∧ pcs=[]），
        视为 "无效复测"，直接丢弃本轮，不评分、不入库。
        """
        logger.error("=== ROUND {} ENTER ===".format(round_idx))
        import signal

        # ============================================================
        # 单轮总超时保护
        # ============================================================
        ROUND_TIMEOUT = 80  # 单轮最多 80 秒（包含编译、运行、评分）

        def _round_timeout_handler(signum, frame):
            raise TimeoutError(
                "Round {} timeout after {}s".format(round_idx, ROUND_TIMEOUT))

        # 保存原有处理器
        old_handler = signal.getsignal(signal.SIGALRM)

        # 心跳日志：标记本轮开始
        logger.info("Round {}: Starting (pool_size={})".format(
            round_idx, len(self.seed_pool.seeds)))

        mutant_path = None  # 用于异常分支清理

        try:
            # ============================================================
            # 注册单轮超时
            # ============================================================
            signal.signal(signal.SIGALRM, _round_timeout_handler)
            signal.alarm(ROUND_TIMEOUT)

            # ============================================================
            # Step 1: 选择种子
            # ============================================================
            seed = self.seed_pool.select()
            if seed is None:
                logger.warning("Round {}: empty seed pool".format(round_idx))
                signal.alarm(0)
                return

            # ============================================================
            # Step 2: 选择锚点
            # ============================================================
            # 只排除跨阶段锁定的 PC，同阶段变异过的不排除
            excluded = seed.get_excluded_pcs()

            anchor = self.scheduler.select_anchor(
                cross_stage_locked_pcs=excluded
            )
            if anchor is None:
                logger.debug("Round {}: no available anchors".format(round_idx))
                signal.alarm(0)
                #return

            # ============================================================
            # Step 3: 应用变异
            # ============================================================
            result = self.scheduler.apply_mutation(
                seed.asm_path, anchor, self.work_dir
            )
            if result is None:
                logger.info("Round {}: mutation apply failed".format(round_idx))
                signal.alarm(0)
                return
            mutant_path, mutation_info = result

            # ============================================================
            # ✅ Step 3.5: 无效变异检测（新增）
            # ------------------------------------------------------------
            # 根据 mutation_scheduler.apply_mutation 的契约：
            #   - total_line_mutations: 逐行变异成功次数
            #   - total_combo_mutations: 组合变异成功次数
            #   - mutated_pcs: 实际被变异的 PC 列表
            # 若三者全为空 → 调度器实际未改变汇编 → 视为无效复测 → 丢弃
            # ============================================================
            total_line = mutation_info.get("total_line_mutations", 0)
            total_combo = mutation_info.get("total_combo_mutations", 0)
            mutated_pcs = mutation_info.get("mutated_pcs", []) or []

            if total_line == 0 and total_combo == 0 and len(mutated_pcs) == 0:
                logger.info(
                    "Round {}: NO-OP mutation detected (line=0, combo=0, pcs=[]), "
                    "discarding without evaluation".format(round_idx))
                self.failure_stats["no_op_mutation"] += 1
                self._cleanup_mutant(mutant_path)
                signal.alarm(0)
                return

            # ============================================================
            # Step 3.6: 构建 mutant_seed（仅在确认有真实变异后）
            # ============================================================
            anchor_pc = mutation_info["anchor_pc"]
            new_history = seed.mutation_history + [mutation_info]

            mutant_seed = Seed(
                asm_path=mutant_path,
                cross_stage_locked_pcs=seed.cross_stage_locked_pcs,
                mutation_history=new_history,
                parent_id=seed.id,
            )
            mutant_seed.current_stage_mutated_pcs = \
                set(seed.current_stage_mutated_pcs)

            # ✅ 记录所有真实变异的 PC（而不仅是 anchor_pc）
            for pc in mutated_pcs:
                mutant_seed.record_mutation(pc)
            # 兼容旧逻辑：anchor_pc 也单独记录一次（即使已在 mutated_pcs 中也无副作用）
            if anchor_pc:
                mutant_seed.record_mutation(anchor_pc)

            # ============================================================
            # Step 4: 评估种子（带内部超时）
            # ============================================================
            tag = "r{}".format(round_idx)
            eval_result = self._evaluate_seed(mutant_seed, tag=tag, is_baseline=False)

            # ============================================================
            # 评估失败（包括超时）的种子绝不进入种子库
            # ============================================================
            if eval_result is None:
                logger.info("Round {}: evaluation failed for anchor {}".format(
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
                    "Round {}: >>> PASSED <<< score={:.4f}, anchor_pc={}, "
                    "mutations={} line + {} combo"
                    .format(round_idx, eval_result["score"], anchor_pc,
                            total_line, total_combo))

            # 入库判定（passed 种子由 add() 内部无条件接受）
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
                # ✅ 关键修订：passed 种子绝不清理文件
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
            # 清理本轮的变异产物
            if mutant_path is not None:
                try:
                    self._cleanup_mutant(mutant_path)
                except Exception:
                    pass
            raise

        except TimeoutError as te:
            # ============================================================
            # 单轮超时：记录后继续下一轮
            # ============================================================
            signal.alarm(0)
            logger.error("Round {}: ROUND TIMEOUT - {}".format(round_idx, te))
            self.failure_stats["eval_exception"] += 1
            # 清理本轮的变异产物
            if mutant_path is not None:
                try:
                    self._cleanup_mutant(mutant_path)
                except Exception as cleanup_err:
                    logger.debug("Cleanup error: {}".format(cleanup_err))
            return

        except Exception as e:
            # ============================================================
            # 其他异常：记录后继续下一轮（保证框架不退出）
            # ✅ 强制打印完整 traceback 到 ERROR 级别
            # ============================================================
            signal.alarm(0)
            import traceback
            tb_str = traceback.format_exc()
            logger.error("Round {}: Unexpected exception: {}".format(round_idx, e))
            logger.error("Round {}: FULL TRACEBACK:\n{}".format(round_idx, tb_str))
            self.failure_stats["eval_exception"] += 1
            if mutant_path is not None:
                try:
                    self._cleanup_mutant(mutant_path)
                except Exception as cleanup_err:
                    logger.debug("Cleanup error: {}".format(cleanup_err))
            return

        finally:
            # ============================================================
            # 确保 SIGALRM 处理器被恢复
            # ============================================================
            try:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            except Exception:
                pass
        
        

    def _evaluate_seed(self, seed, tag="eval", is_baseline=False):
        """
        编译、运行、评估（带多层超时保护 + 健全性检查）。

        新增参数:
            is_baseline: 若为 True，则跳过 "无效变异" 检测（baseline 必须被评测）。

        超时策略：
        - 编译超时：compile_timeout 秒
        - 运行超时：run_timeout 秒
        - 评分超时：10 秒
        - 任何超时都视为失败，不加入种子池
        """
        import signal

        SCORE_TIMEOUT = 10

        def _score_timeout_handler(signum, frame):
            raise TimeoutError("Score computation timeout after {}s".format(SCORE_TIMEOUT))

        old_handler = signal.getsignal(signal.SIGALRM)

        try:
            # Step 1: process_asm
            logger.debug("[{}] ❤️ Step 1: process_asm start".format(tag))
            processed_path = self._process_asm(seed.asm_path, tag)
            if processed_path is None:
                self.failure_stats["process_failed"] += 1
                logger.info("[{}] process_asm returned None".format(tag))
                return None
            logger.debug("[{}] ❤️ Step 1: process_asm done".format(tag))

            # Step 1.5: sanity check
            logger.debug("[{}] ❤️ Step 1.5: sanity check start".format(tag))
            try:
                from asm_sanity_check import sanity_check_file
                ok, reason = sanity_check_file(processed_path, strict=False)
                if not ok:
                    self.failure_stats["sanity_failed"] += 1
                    logger.info("[{}] Sanity check FAILED: {}".format(tag, reason))
                    try:
                        self._save_failure_artifact(
                            processed_path, tag, "sanity_fail", reason)
                    except Exception:
                        pass
                    return None
                logger.debug("[{}] ❤️ Step 1.5: sanity check done ({})".format(tag, reason))
            except ImportError:
                logger.warning("asm_sanity_check module not found, skipping check")
            except Exception as e:
                logger.warning("[{}] Sanity check error: {} (continuing)".format(tag, e))

            # Step 2: compile
            logger.debug("[{}] ❤️ Step 2: compile start".format(tag))
            exe_path = self._compile(processed_path, tag)
            if exe_path is None:
                logger.info("[{}] compile returned None".format(tag))
                try:
                    mutant_dir = os.path.dirname(processed_path)
                    if "mutant_" in mutant_dir:
                        fail_root = os.path.join(self.work_dir, "stage1", "_failures")
                        os.makedirs(fail_root, exist_ok=True)
                        dst = os.path.join(fail_root, os.path.basename(mutant_dir))
                        if not os.path.exists(dst):
                            shutil.move(mutant_dir, dst)
                            logger.debug("Moved failed mutant to: {}".format(dst))
                except Exception as e:
                    logger.debug("Failed to preserve mutant: {}".format(e))
                return None
            logger.debug("[{}] ❤️ Step 2: compile done".format(tag))

            # Step 3: run
            logger.debug("[{}] ❤️ Step 3: run start".format(tag))
            log_lines = self._run_executable(exe_path, tag)
            if log_lines is None:
                logger.info("[{}] run returned None".format(tag))
                return None
            logger.debug("[{}] ❤️ Step 3: run done ({} lines)".format(tag, len(log_lines)))

            # Step 4 & 5: score
            logger.debug("[{}] ❤️ Step 4-5: compute score start (limit={}s)".format(
                tag, SCORE_TIMEOUT))

            signal.signal(signal.SIGALRM, _score_timeout_handler)
            signal.alarm(SCORE_TIMEOUT)

            try:
                uops_status, uops_status_detail = parse_uops_pmu_status(
                    log_lines)
                if uops_status != "ok":
                    self.failure_stats["uops_pmu_unavailable"] += 1
                    self.framework_error = (
                        "UOPS PMU runtime health check failed: {}".format(
                            uops_status_detail))
                    logger.error(
                        "[{}] UOPS PMU runtime health check failed: {}"
                        .format(tag, uops_status_detail))
                    return None
                result = stage1_evaluate(
                    log_lines,
                    period=self.detected_period,
                    brmisp_weight=self.brmisp_weight,
                    uops_weight=self.uops_weight,
                )
                signal.alarm(0)
                logger.debug("[{}] ❤️ Step 4-5: compute score done".format(tag))
                return result

            except TimeoutError as te:
                signal.alarm(0)
                self.failure_stats["eval_exception"] += 1
                logger.error("[{}] Score computation timeout: {}".format(tag, te))
                return None

            finally:
                signal.alarm(0)

        except subprocess.TimeoutExpired:
            self.failure_stats["run_timeout"] += 1
            logger.info("[{}] Timeout (uncaught)".format(tag))
            return None

        except Exception as e:
            self.failure_stats["eval_exception"] += 1
            logger.info("[{}] Evaluation error: {}".format(tag, e))
            import traceback
            logger.debug("[{}] Traceback:\n{}".format(tag, traceback.format_exc()))
            return None

        finally:
            try:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            except Exception:
                pass

    def _process_asm(self, asm_path, tag):
        """对 .s 做插桩"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        from run_stage_pipeline_stage1_2_3 import process_asm

        try:
            with open(asm_path, "r") as f:
                lines = f.readlines()
        except Exception as e:
            logger.debug("[{}] Cannot read asm: {}".format(tag, e))
            return None

        processed_lines = process_asm(lines)

        base_dir = os.path.dirname(asm_path)
        base_name = os.path.basename(asm_path).replace(".s", "")
        processed_path = os.path.join(
            base_dir, "{}_{}_processed.s".format(base_name, tag))

        try:
            with open(processed_path, "w") as f:
                f.writelines(processed_lines)
        except Exception as e:
            logger.debug("[{}] Cannot write processed asm: {}".format(tag, e))
            return None

        return processed_path

    def _compile(self, processed_asm_path, tag):
        """
        编译 .s → 可执行文件（带超时保护）。
        
        超时时间：self.compile_timeout（默认 30 秒）
        超时或失败均返回 None。
        """
        obj_path = processed_asm_path.replace(".s", ".o")
        exe_path = processed_asm_path.replace(".s", "")

        # ============================================================
        # Step 1: 编译汇编 → .o（带超时）
        # ============================================================]
        try:
            r1 = subprocess.run(
                [self.cc, "-c", processed_asm_path, "-o", obj_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout
            )
        except subprocess.TimeoutExpired:
            self.failure_stats["compile_timeout"] += 1
            logger.info("[{}] Assembly timeout ({}s)".format(
                tag, self.compile_timeout))
            return None
        except Exception as e:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Assembly error: {}".format(tag, e))
            return None

        if r1.returncode != 0:
            self.failure_stats["compile_failed"] += 1
            err = r1.stderr.decode("utf-8", errors="ignore")
            err_short = err[:500] if len(err) <= 500 else err[:500] + "...[truncated]"
            logger.debug("[{}] Assembly failed (rc={}):\n{}".format(
            tag, r1.returncode, err_short))
            self._save_failure_artifact(processed_asm_path, tag, "asm_fail", err)
            return None

        # ============================================================
        # Step 2: 链接 → 可执行文件（带超时）
        # ============================================================
        link_cmd = [self.cc, obj_path, self.pmu_helper_obj]
        if os.path.exists(self.pmu_uops_obj):
            link_cmd.append(self.pmu_uops_obj)
        link_cmd += ["-o", exe_path]

        try:
            r2 = subprocess.run(
                link_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout
            )
        except subprocess.TimeoutExpired:
            self.failure_stats["compile_timeout"] += 1
            logger.info("[{}] Link timeout ({}s)".format(
                tag, self.compile_timeout))
            return None
        except Exception as e:
            self.failure_stats["compile_failed"] += 1
            logger.debug("[{}] Link error: {}".format(tag, e))
            return None

        if r2.returncode != 0:
            self.failure_stats["compile_failed"] += 1
            err = r2.stderr.decode("utf-8", errors="ignore")
            err_short = err[:500] if len(err) <= 500 else err[:500] + "...[truncated]"
            logger.debug("[{}] Link failed (rc={}):\n{}".format(
                tag, r2.returncode, err_short))
            self._save_failure_artifact(processed_asm_path, tag, "Link_fail", err)
            return None

        return exe_path
    
    def _save_failure_artifact(self, src_path, tag, fail_type, err_msg):
        """保留失败现场用于事后分析"""
        fail_dir = os.path.join(self.work_dir, "stage1", "_failures", fail_type)
        os.makedirs(fail_dir, exist_ok=True)
        
        # 复制源文件
        dst = os.path.join(fail_dir, "{}_{}.s".format(tag, fail_type))
        try:
            shutil.copy(src_path, dst)
        except Exception:
            pass
        
        # 保存错误信息
        err_file = os.path.join(fail_dir, "{}_{}.err".format(tag, fail_type))
        try:
            with open(err_file, "w") as f:
                f.write(err_msg)
        except Exception:
            pass

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
            #env["VF_EXPECTED_SECRET"] = str(self.expected_secret)
            # 启动进程
            proc = subprocess.Popen(
                [exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
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
                    
                    if rc != 0:
                        self.failure_stats["run_failed"] += 1
                        logger.debug("[{}] Execution failed: rc={}, time={:.1f}s".format(
                            tag, rc, elapsed))
                        return None
                    
                    output = stdout.decode("utf-8", errors="ignore")
                    lines = output.splitlines()
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
            mutant_dir = os.path.dirname(mutant_path)
            if "mutant_" in os.path.basename(mutant_dir):
                shutil.rmtree(mutant_dir, ignore_errors=True)
        except Exception:
            pass

    def _report_stats(self, round_num):
        """报告种子池统计信息（增强版：含失败统计）"""
        stats = self.seed_pool.stats()
        logger.info(
            "Round {}/{}: pool_size={}, passed={}, "
            "added={}, evicted={}, rejected={}, "
            "avg_score={:.4f}, max_score={:.4f}, min_score={:.4f}, "
            "avg_age={:.1f}"
            .format(round_num, self.budget,
                    stats["size"], stats["passed_count"],
                    stats["total_added"], stats["total_evicted"],
                    stats["total_rejected"],
                    stats["avg_score"], stats["max_score"],
                    stats["min_score"], stats["avg_age"]))

        total_failures = sum(self.failure_stats.values())
        if total_failures > 0:
            logger.info(
                "  Failures: process={}, sanity={}, compile={} (timeout={}), "
                "run={} (timeout={}), eval_exc={}, no_op={}"
                .format(
                    self.failure_stats["process_failed"],
                    self.failure_stats["sanity_failed"],
                    self.failure_stats["compile_failed"],
                    self.failure_stats["compile_timeout"],
                    self.failure_stats["run_failed"],
                    self.failure_stats["run_timeout"],
                    self.failure_stats["eval_exception"],
                    self.failure_stats["no_op_mutation"]))

        best = self.seed_pool.get_best_seed()
        if best and best.eval_detail:
            br = best.eval_detail.get("brmisp", {})
            uops = best.eval_detail.get("uops", {})
            logger.info(
                "  Best: id={}, score={:.4f}, "
                "br_elev={:.3f}, spec_uops={}"
                .format(best.id, best.score,
                        br.get("elevation_rate", 0),
                        uops.get("speculative_uops", 0)))

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
        logger.info("  sanity_failed:    {}".format(self.failure_stats["sanity_failed"]))
        logger.info("  compile_failed:   {}".format(self.failure_stats["compile_failed"]))
        logger.info("  compile_timeout:  {}".format(self.failure_stats["compile_timeout"]))
        logger.info("  run_failed:       {}".format(self.failure_stats["run_failed"]))
        logger.info("  run_timeout:      {}".format(self.failure_stats["run_timeout"]))
        logger.info("  eval_exception:   {}".format(self.failure_stats["eval_exception"]))
        logger.info("  no_op_mutation:   {}".format(self.failure_stats["no_op_mutation"]))
        
        total_attempts = total_failures + self.seed_pool.total_added
        if total_attempts > 0:
            failure_rate = total_failures / float(total_attempts) * 100
            logger.info("Failure rate: {:.1f}% ({}/{})".format(
                failure_rate, total_failures, total_attempts))
