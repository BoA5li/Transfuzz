#!/usr/bin/env python3
"""
stage3_controller.py - 配置变异版（优化版 v3 - 防御加固版）

本版本相对 v2 的修正:
1. 单轮总超时 (SIGALRM, 嵌套安全)              - 默认 90s
2. atexit 清理钩子, 进程退出强杀残留子进程
3. 失败现场归档 _failures/  + 成功现场归档 _success/
4. 无效变异检测 (配置 + 汇编两个维度, 任一发生即视为有效)
5. Sanity check (run() 开头验证工具链)
6. Passed seed 文件保护 (不被清理误删)
7. 关键异常使用 ERROR + traceback
8. Baseline 评测失败也走失败归档

保持不变:
- 配置变异 / 汇编变异的 30/70 调度策略
- _select_safe_anchor / _is_flush_reload_critical
- 三步编译链与环境变量注入
- seed_pool.add() 入库判定
- stage3_evaluator.py / stage3_config.py 完全不动
"""

import os
import sys
import re
import json
import signal
import atexit
import subprocess
import shutil
import logging
import random
import time
import traceback

from seed_pool import Seed, SeedPool
from mutation_scheduler import MutationScheduler
from stage3_evaluator import stage3_evaluate
from stage3_config import (
    mutate_stage3_config,
    save_stage3_config,
    load_stage3_config,
    get_stage3_defaults,
    generate_stage3_env,
    print_stage3_config,
)

logger = logging.getLogger("stage3")


# =====================================================================
# 模块级: 残留子进程清理
# =====================================================================

_ACTIVE_CHILD_PIDS = set()


def _atexit_kill_children():
    """进程退出时, 强杀所有还在跑的子进程组"""
    for pid in list(_ACTIVE_CHILD_PIDS):
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            pass
    _ACTIVE_CHILD_PIDS.clear()


atexit.register(_atexit_kill_children)


# =====================================================================
# 单轮总超时 (嵌套安全)
# =====================================================================

class _RoundTimeout(Exception):
    """单轮总超时"""
    pass


class _round_deadline(object):
    """
    上下文管理器: 在进入时设定 SIGALRM, 在退出时恢复外层 alarm.

    嵌套安全:
      - 进入时记录当前 signal.alarm(0) 返回的剩余时间 (外层剩余)
      - 退出时:
          * 如果外层有剩余, 用 max(1, 外层剩余 - 已耗时) 恢复 alarm
          * 否则 alarm(0) 清除
      - 永远 restore 原 handler

    只在主线程有效 (SIGALRM 限制).
    """

    def __init__(self, seconds):
        self.seconds = int(seconds)
        self._prev_handler = None
        self._prev_remaining = 0
        self._t_enter = 0.0
        self._enabled = False

    def __enter__(self):
        if self.seconds <= 0:
            return self
        try:
            def _handler(signum, frame):
                raise _RoundTimeout(
                    "round deadline ({}s) exceeded".format(self.seconds))

            self._prev_handler = signal.signal(signal.SIGALRM, _handler)
            # 取消外层 alarm, 拿到外层剩余秒数
            self._prev_remaining = signal.alarm(0)
            self._t_enter = time.time()
            signal.alarm(self.seconds)
            self._enabled = True
        except (ValueError, AttributeError):
            # 非主线程, 或平台不支持 SIGALRM
            self._enabled = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._enabled:
            return False
        try:
            signal.alarm(0)
            if self._prev_handler is not None:
                signal.signal(signal.SIGALRM, self._prev_handler)
            # 恢复外层 alarm
            if self._prev_remaining > 0:
                elapsed = int(time.time() - self._t_enter)
                remain = self._prev_remaining - elapsed
                if remain < 1:
                    remain = 1
                try:
                    signal.alarm(remain)
                except Exception:
                    pass
        except Exception:
            pass
        return False


# =====================================================================
# Stage 3 主控
# =====================================================================

class Stage3Controller(object):
    """Stage 3 主控器 (配置变异版 + 防御加固版)"""

    def __init__(self, config):
        self.config = config

        def _abs(p):
            if p and not os.path.isabs(p):
                return os.path.abspath(p)
            return p

        # 复用 auto_stage1_2_3_driver.c
        self.driver_c = _abs(config.get(
            "driver_c", "auto_stage1_2_3_driver.c"))
        self.stage3_driver_c = _abs(config.get(
            "stage3_driver_c", "stage3_driver_safe.c"))

        self.budget = config.get("budget", 1000)
        self.work_dir = _abs(config.get("work_dir", "./stage3_work"))
        self.cc = config.get("cc", "gcc")
        self.pmu_helper_obj = _abs(config.get(
            "pmu_helper_obj", "pmu_helper_auto.o"))
        self.pmu_uops_obj = _abs(config.get(
            "pmu_uops_obj", "pmu_uops_rdpmc.o"))

        # 超时配置
        self.run_timeout = config.get("run_timeout", 20)
        self.compile_timeout = config.get("compile_timeout", 20)
        # 新增: 单轮总超时 (默认 90s, 按用户要求)
        self.per_round_timeout = config.get("per_round_timeout", 90)

        self.report_interval = config.get("report_interval", 30)
        self.dump_times = config.get("dump_times", 1)

        self.expected_secret = int(
            config.get("expected_secret", ord('Y')))
        logger.info("Expected secret: {} (0x{:02x})".format(
            chr(self.expected_secret), self.expected_secret))

        # 失败统计 (8 类, 对齐 Stage 1 风格)
        self.failure_stats = {
            "process_failed":   0,  # 汇编预处理失败
            "compile_failed":   0,  # 编译/链接失败 (非超时)
            "compile_timeout":  0,  # 编译超时
            "run_failed":       0,  # 运行失败 (非超时)
            "run_timeout":      0,  # 运行超时
            "eval_exception":   0,  # 评估流程异常
            "round_timeout":    0,  # 单轮总超时
            "invalid_mutation": 0,  # 无效变异 (配置 + 汇编都未变)
        }

        # 配置变异 / 汇编变异 开关
        self.enable_config_mutation = config.get(
            "enable_config_mutation", False)
        self.config_mutation_probability = config.get(
            "config_mutation_probability", 0.3)
        self.enable_asm_mutation = config.get(
            "enable_asm_mutation", True)
        self.asm_mutation_probability = config.get(
            "asm_mutation_probability", 1)

        # 加载初始配置
        stage3_config_path = config.get(
            "stage3_config_path",
            os.path.join(self.work_dir, "stage3_config.json"))
        os.makedirs(self.work_dir, exist_ok=True)
        if os.path.exists(stage3_config_path):
            self.current_stage3_config = load_stage3_config(
                stage3_config_path)
            logger.info("Loaded Stage 3 config from {}".format(
                stage3_config_path))
        else:
            self.current_stage3_config = get_stage3_defaults()
            save_stage3_config(
                self.current_stage3_config, stage3_config_path)
            logger.info("Created default Stage 3 config at {}".format(
                stage3_config_path))
        self.stage3_config_path = stage3_config_path

        if config.get("verbose", False):
            print_stage3_config(self.current_stage3_config)

        # 预编译 stage3_driver_safe.o
        self.stage3_obj = os.path.join(
            self.work_dir, "stage3_driver_safe.o")

        # anchors
        self.anchors = []
        self.strong_objects = []
        anchors_path = _abs(config.get("anchors_json"))
        if anchors_path and os.path.exists(anchors_path):
            with open(anchors_path) as f:
                self.anchors = json.load(f)
            logger.info("Loaded {} anchors".format(len(self.anchors)))

        strong_obj_path = _abs(config.get("strong_objects_json"))
        if strong_obj_path and os.path.exists(strong_obj_path):
            with open(strong_obj_path) as f:
                self.strong_objects = json.load(f)
            logger.info("Loaded {} strong objects".format(
                len(self.strong_objects)))

        self.scheduler = MutationScheduler(
            self.anchors, self.strong_objects, stage=3
        )
        self.seed_pool = SeedPool(
            max_size=config.get("pool_size", 200),
            stage_name="stage3"
        )

        self.seed_pool.set_evict_callback(self._unbind_seed_config)

        # 失败 / 成功 归档目录
        self.failures_dir = os.path.join(self.work_dir, "_failures")
        self.success_dir = os.path.join(self.work_dir, "_success")
        os.makedirs(self.failures_dir, exist_ok=True)
        os.makedirs(self.success_dir, exist_ok=True)

        # passed seed 文件保护 (不被清理误删)
        self._protected_paths = set()
        self.seed_stage3_configs = {}

        self.success_seed = None

        logger.info("Stage 3 Controller initialized:")
        logger.info(
            "  budget={}, run_timeout={}s, compile_timeout={}s, "
            "per_round_timeout={}s".format(
                self.budget, self.run_timeout,
                self.compile_timeout, self.per_round_timeout))

    # =================================================================
    # Sanity check
    # =================================================================

    def _sanity_check(self):
        """run() 开头验证工具链与关键文件"""
        ok = True

        # 1. 编译器
        try:
            r = subprocess.run(
                [self.cc, "--version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5)
            if r.returncode != 0:
                logger.error("Sanity: cc '{}' returned {}".format(
                    self.cc, r.returncode))
                ok = False
        except Exception as e:
            logger.error("Sanity: cc '{}' unusable: {}".format(
                self.cc, e))
            ok = False

        # 2. driver_c
        if not os.path.exists(self.driver_c):
            logger.error("Sanity: driver_c not found: {}".format(
                self.driver_c))
            ok = False

        # 3. pmu_helper_obj
        if not os.path.exists(self.pmu_helper_obj):
            logger.error("Sanity: pmu_helper_obj not found: {}".format(
                self.pmu_helper_obj))
            ok = False

        # 4. stage3_driver_c (warning, 不致命)
        if not os.path.exists(self.stage3_driver_c):
            logger.warning("Sanity: stage3_driver_c not found: {}".format(
                self.stage3_driver_c))

        # 5. work_dir 可写
        try:
            probe = os.path.join(self.work_dir, ".sanity_probe")
            with open(probe, "w") as f:
                f.write("ok")
            os.remove(probe)
        except Exception as e:
            logger.error("Sanity: work_dir not writable: {}".format(e))
            ok = False

        return ok

    # =================================================================
    # Per-seed stage3 配置管理 (核心: 让变异参数真正参与执行)
    # =================================================================

    def _get_seed_config(self, seed):
        """
        获取 seed 绑定的 stage3 配置.

        返回值始终是深拷贝 (enable 模式下) 或 current 引用 (disable 模式下),
        调用方可以自由修改返回值而不影响档案.
        """
        import copy

        # 关闭配置变异: 共享只读引用即可, 不深拷贝以避免无谓开销
        if not self.enable_config_mutation:
            return self.current_stage3_config

        # 开启配置变异: 必须返回独立副本
        cfg = self.seed_stage3_configs.get(seed.id)
        if cfg is not None:
            return copy.deepcopy(cfg)

        # [FIX-B7] 自愈式 fallback:
        # 该 seed 没有档案 (典型场景: baseline seed 首次评测前没绑定).
        # 此时为它落一份 current 的快照作为正式档案, 避免后续每次都走 fallback,
        # 也保证它被选作父本时, parent_cfg 取得的是它当时评测使用的精确配置.
        snapshot = copy.deepcopy(self.current_stage3_config)
        self.seed_stage3_configs[seed.id] = snapshot
        try:
            cfg_path = os.path.join(
                self.work_dir,
                "stage3_cfg_seed{}.json".format(seed.id))
            save_stage3_config(snapshot, cfg_path)
        except Exception as e:
            logger.debug(
                "auto-bind fallback stage3_config failed "
                "(seed={}): {}".format(seed.id, e))
        logger.debug(
            "seed id={} had no bound stage3 config, "
            "auto-bound a snapshot of current_stage3_config".format(seed.id))

        return copy.deepcopy(snapshot)

    def _set_seed_config(self, seed, cfg, persist=True):
        """
        绑定 seed 与 stage3 配置, 并落盘到 work_dir 便于复现.

        关键契约 (与用户分析逻辑一致):
        - enable_config_mutation=False (Case A):
            配置永不漂移, 所有 seed 共享 current, 落档无意义 -> no-op
        - enable_config_mutation=True 且本轮发生配置变异 (Case B):
            mutant_cfg 是新 cfg, 必须落档以便后续作为父本时精确复现
        - enable_config_mutation=True 且本轮未发生配置变异 (Case C, 关键!):
            mutant_cfg 等于 parent_cfg, 仍必须为 mutant.id 落一份独立档案;
            否则 mutant 将来作为父本时 _get_seed_config 走 fallback,
            会误用 self.current_stage3_config 的快照而非它真实评测用的 cfg,
            形成"延迟漂移".
        调用方在 _mutation_round 中无条件调用本函数, 已天然覆盖三种 case.

        实现细节:
        - [FIX-B5] enable_config_mutation=False 时直接返回, 不做任何事
        - [FIX-B2] 写入档案前深拷贝, 隔离调用方后续对 cfg 的修改
        """
        if not self.enable_config_mutation:
            return  # [FIX-B5] Case A: 关闭模式, no-op

        import copy
        cfg_snapshot = copy.deepcopy(cfg)  # [FIX-B2] 深拷贝写入
        self.seed_stage3_configs[seed.id] = cfg_snapshot

        if persist:
            try:
                cfg_path = os.path.join(
                    self.work_dir,
                    "stage3_cfg_seed{}.json".format(seed.id))
                save_stage3_config(cfg_snapshot, cfg_path)
            except Exception as e:
                logger.debug(
                    "save per-seed stage3_config failed "
                    "(seed={}): {}".format(seed.id, e))

    def _unbind_seed_config(self, seed):
        """
        [FIX-B6] 清理指定 seed 的 stage3 配置档案 (内存 + 磁盘).

        调用时机:
        - mutant 评测返回 None (eval failed)
        - mutant 被 seed_pool 拒绝 (admitted=False)
        - [新增] mutant 入池后又被驱逐 (由 SeedPool 通过 evict_callback 触发)

        seed 参数也可以是裸 id (int), 用于 SeedPool 驱逐回调场景
        (SeedPool 不持有 controller, 通过 lambda 间接调用).
        """
        if not self.enable_config_mutation:
            return

        # 兼容 Seed 对象与裸 id
        seed_id = seed.id if hasattr(seed, "id") else seed

        self.seed_stage3_configs.pop(seed_id, None)
        try:
            cfg_path = os.path.join(
                self.work_dir,
                "stage3_cfg_seed{}.json".format(seed_id))
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except Exception as e:
            logger.debug(
                "remove per-seed stage3_config failed "
                "(seed={}): {}".format(seed_id, e))

    @staticmethod
    def _config_diff(old_cfg, new_cfg):
        """计算两份 stage3 config 的差异; 用于精确判定 config 是否真的变了."""
        diff = {}
        old_cfg = old_cfg or {}
        new_cfg = new_cfg or {}
        for k in set(old_cfg.keys()) | set(new_cfg.keys()):
            if old_cfg.get(k) != new_cfg.get(k):
                diff[k] = {"old": old_cfg.get(k), "new": new_cfg.get(k)}
        return diff
    
    
    
    # =================================================================
    # 主流程
    # =================================================================

    def run(self, stage2_passed_seeds):
        """
        执行 Stage 3 完整流程.

        终止条件:
          1. 任一种子 (baseline 或 mutant) match=1 -> 保存成功归档, 立即返回
          2. budget 用完 -> 返回 None
        """
        logger.info("=" * 60)
        logger.info("Stage 3: Initialization")
        logger.info("=" * 60)
        logger.info("Config mutation: {}".format(
            "ENABLED" if self.enable_config_mutation else "DISABLED"))
        logger.info("ASM mutation: {}".format(
            "ENABLED" if self.enable_asm_mutation else "DISABLED"))

        # Sanity check
        if not self._sanity_check():
            logger.error("Sanity check FAILED, aborting Stage 3")
            return None, []

        # 预编译
        self._precompile_stage3_obj()

        # Stage 2 passed -> Stage 3 种子
        stage3_seeds = []
        for s2_seed in stage2_passed_seeds:
            s3_seed = s2_seed.create_child_for_next_stage()
            stage3_seeds.append(s3_seed)
            locked = (s2_seed.cross_stage_locked_pcs |
                      s2_seed.current_stage_mutated_pcs)
            logger.info(
                "Stage2 seed id={}, score={:.4f}, locked={} "
                "-> Stage3 seed id={}".format(
                    s2_seed.id, s2_seed.score, locked, s3_seed.id))

        if not stage3_seeds:
            logger.error("No Stage 2 passed seeds to process")
            return None, []

        # ============================================================
        # Baseline 评估 (D4: 不做无效变异检测, 直接评测直接入库)
        # ============================================================
        logger.info("=" * 60)
        logger.info("Stage 3: Baseline evaluation for {} seeds".format(
            len(stage3_seeds)))
        logger.info("=" * 60)

        all_evaluated = []

        for seed in stage3_seeds:
            tag = "s3_base_{}".format(seed.id)
            self._set_seed_config(seed, self.current_stage3_config)
            try:
                eval_result = self._evaluate_seed(seed, tag=tag)
            except _RoundTimeout as e:
                # baseline 阶段没有外层 alarm, 这里基本不会触发,
                # 但为完备性保留
                logger.warning("[{}] baseline round timeout: {}".format(
                    tag, e))
                self.failure_stats["round_timeout"] += 1
                eval_result = None
            except Exception as e:
                logger.error("[{}] baseline exception: {}".format(tag, e))
                logger.error("Traceback:\n{}".format(traceback.format_exc()))
                self.failure_stats["eval_exception"] += 1
                eval_result = None

            if eval_result is None:
                logger.warning(
                    "Baseline eval failed for seed {}".format(seed.id))
                continue

            seed.score = eval_result["score"]
            seed.eval_detail = eval_result
            # D4: baseline 无条件入库
            self.seed_pool.add(seed)
            all_evaluated.append(seed)

            logger.info(
                "  Seed {}: score={:.4f}, match_rate={:.3f}, "
                "mean_latency={:.1f}, passed={}".format(
                    seed.id, eval_result["score"],
                    eval_result["match_rate"],
                    eval_result["mean_expected_latency"],
                    eval_result["passed"]))

            # D5: baseline passed 也走完整成功归档
            if eval_result["passed"]:
                logger.info(
                    "  >>> SECRET RECOVERED at baseline! <<<")
                self.success_seed = seed
                self._archive_success(
                    seed, tag=tag,
                    eval_result=eval_result,
                    stage="baseline")
                self._report_failure_stats()
                return seed, all_evaluated

        if not self.seed_pool.seeds:
            logger.error("No seeds survived baseline evaluation")
            self._report_failure_stats()
            return None, all_evaluated

        # ============================================================
        # 变异循环
        # ============================================================
        logger.info("=" * 60)
        logger.info("Stage 3: Mutation loop (budget={})".format(
            self.budget))
        logger.info("=" * 60)

        for round_idx in range(self.budget):
            # 单轮总超时 90s (嵌套安全)
            try:
                with _round_deadline(self.per_round_timeout):
                    round_result = self._mutation_round(round_idx)
            except _RoundTimeout as e:
                logger.warning(
                    "Round {}: round deadline exceeded ({}), skip".format(
                        round_idx, e))
                self.failure_stats["round_timeout"] += 1
                round_result = None
            except KeyboardInterrupt:
                logger.warning(
                    "User interrupted at round {}".format(round_idx))
                self._report_failure_stats()
                raise
            except Exception as e:
                logger.error("Round {}: top-level exception: {}".format(
                    round_idx, e))
                logger.error("Traceback:\n{}".format(traceback.format_exc()))
                self.failure_stats["eval_exception"] += 1
                round_result = None

            if round_result is not None:
                all_evaluated.append(round_result["seed"])
                if round_result.get("passed"):
                    logger.info(
                        ">>> SECRET RECOVERED at round {}! <<<".format(
                            round_idx))
                    self.success_seed = round_result["seed"]
                    self._archive_success(
                        round_result["seed"],
                        tag="s3_r{}".format(round_idx),
                        eval_result=round_result["seed"].eval_detail,
                        stage="mutation_round_{}".format(round_idx))
                    self._report_failure_stats()
                    return round_result["seed"], all_evaluated

            if (round_idx + 1) % self.report_interval == 0:
                self._report_stats(round_idx + 1)

        # budget 用完
        logger.info("=" * 60)
        logger.info(
            "Stage 3 complete: secret NOT recovered "
            "within budget ({})".format(self.budget))
        self._report_stats(self.budget)
        self._report_failure_stats()

        return None, all_evaluated

    # =================================================================
    # 变异轮
    # =================================================================

    def _mutation_round(self, round_idx):
        """
        单轮变异 (配置变异 + 保护性汇编变异).

        无效变异规则 (Q2):
        - 配置变异是否发生: 是否进入配置变异分支并产生真实 diff
        - 汇编变异是否发生: scheduler 返回的 line/combo/pcs 是否 > 0
        - 二者皆未发生 -> 视为无效复测 -> 直接丢弃, 不评测不入库

        本次修订核心:
        [FIX-B1~B4] 严格隔离父/子 seed 的 stage3 配置档案:
            1) parent_cfg 通过 _get_seed_config 取出 (已深拷贝)
            2) mutant_cfg 用 deepcopy 而非 dict() 浅拷贝
            3) mutate_stage3_config 传入参数也深拷贝
            4) 不再写 self.current_stage3_config = new_cfg
            (该全局赋值会让"种子 A 的变异结果漂移到种子 B")
        [FIX-B6] mutant 评测失败 / 拒绝入池时, 清理它的 cfg 档案
        [契约-CaseC] 即便本轮未发生配置变异, 也无条件为 mutant 落一份独立档案,
                    防止"延迟漂移".

        返回:
        dict {"seed": ..., "passed": bool}  或 None
        """
        import copy  # 局部 import, 不污染模块顶层

        seed = self.seed_pool.select()
        if seed is None:
            logger.warning("Round {}: empty seed pool".format(round_idx))
            return None

        mutation_info = {}
        mutant_path = seed.asm_path  # 默认: 不变异汇编

        # ============================================================
        # 第一步: 配置变异
        # ------------------------------------------------------------
        # parent_cfg: 从父 seed 的绑定档案取出 (深拷贝, 改它不污染档案)
        # mutant_cfg: 默认完整继承父配置 (再做一次深拷贝, 与 parent 隔离)
        # ============================================================
        parent_cfg = self._get_seed_config(seed)
        mutant_cfg = copy.deepcopy(parent_cfg)  # [FIX-B2] 深拷贝替代 dict()
        config_mutated_flag = False

        if (self.enable_config_mutation and
                random.random() < self.config_mutation_probability):
            try:
                # [FIX-B4] 给 mutate_stage3_config 一份独立副本, 防止它就地改入参
                cfg_for_mutation = copy.deepcopy(parent_cfg)
                new_cfg = mutate_stage3_config(cfg_for_mutation)
                diff = self._config_diff(parent_cfg, new_cfg)
                if diff:
                    mutant_cfg = new_cfg
                    config_mutated_flag = True
                    mutation_info["config_mutated"] = True
                    mutation_info["config_diff"] = diff
                    # [FIX-B3] 删除原来的 self.current_stage3_config = new_cfg
                    #   该全局赋值是导致"配置漂移"的根因.
                    #   mutant 的新配置仅绑定在它自己的 seed.id 上,
                    #   通过下方 _set_seed_config(mutant_seed, mutant_cfg) 落档.
                    logger.debug(
                        "Round {}: Config mutated from parent seed id={}, "
                        "diff_keys={}".format(
                            round_idx, seed.id, list(diff.keys())))
                else:
                    mutation_info["config_mutated"] = False
                    logger.debug(
                        "Round {}: mutate_stage3_config returned "
                        "identical config (no diff)".format(round_idx))
            except Exception as e:
                logger.error(
                    "Round {}: config mutation exception: {}".format(
                        round_idx, e))
                logger.error("Traceback:\n{}".format(
                    traceback.format_exc()))
                mutation_info["config_mutated"] = False
                # 异常时确保 mutant_cfg 回到 parent 的副本
                mutant_cfg = copy.deepcopy(parent_cfg)
        else:
            mutation_info["config_mutated"] = False

        # ============================================================
        # 第二步: 汇编变异 (D3: line/combo/pcs == 0 视为空)
        # ============================================================
        asm_mutated_flag = False
        anchor_pc = None
        if (self.enable_asm_mutation and
                random.random() < self.asm_mutation_probability):
            excluded = seed.get_excluded_pcs()
            anchor = self._select_safe_anchor(excluded)
            if anchor is None:
                logger.debug(
                    "Round {}: No safe anchors available".format(round_idx))
            else:
                try:
                    result = self.scheduler.apply_mutation(
                        seed.asm_path, anchor, self.work_dir,
                        cross_stage_locked_pcs=excluded
                    )
                except Exception as e:
                    logger.error(
                        "Round {}: scheduler.apply_mutation exception: {}"
                        .format(round_idx, e))
                    logger.error("Traceback:\n{}".format(
                        traceback.format_exc()))
                    result = None

                if result is None:
                    logger.info(
                        "Round {}: Mutation apply failed".format(round_idx))
                else:
                    new_mutant_path, asm_mutation_info = result
                    mutation_info.update(asm_mutation_info)

                    # D3: 空变异判定
                    line_cnt = int(asm_mutation_info.get(
                        "total_line_mutations", 0))
                    combo_cnt = int(asm_mutation_info.get(
                        "total_combo_mutations", 0))
                    pcs_cnt = len(asm_mutation_info.get(
                        "mutated_pcs", []))

                    if (line_cnt + combo_cnt + pcs_cnt) > 0:
                        mutation_info["asm_mutated"] = True
                        asm_mutated_flag = True
                        anchor_pc = mutation_info.get(
                            "anchor_pc", anchor.get("pc"))
                        mutant_path = new_mutant_path
                        logger.debug(
                            "Round {}: ASM mutated, anchor={}, "
                            "line={}, combo={}, pcs={}".format(
                                round_idx, anchor_pc,
                                line_cnt, combo_cnt, pcs_cnt))
                    else:
                        mutation_info["asm_mutated"] = False
                        logger.debug(
                            "Round {}: scheduler returned empty mutation "
                            "(line=0, combo=0, pcs=0)".format(round_idx))
                        # 清理生成但未使用的 mutant 目录
                        if new_mutant_path and new_mutant_path != seed.asm_path:
                            self._cleanup_mutant(new_mutant_path)
        else:
            mutation_info["asm_mutated"] = False

        # ============================================================
        # 无效变异检测 (Q2 核心)
        # ============================================================
        if not config_mutated_flag and not asm_mutated_flag:
            self.failure_stats["invalid_mutation"] += 1
            logger.debug(
                "Round {}: invalid mutation (no config change, "
                "no asm change), discard".format(round_idx))
            return None

        # ============================================================
        # 第三步: 构建变异种子, 并绑定它自己的 cfg 档案
        # ------------------------------------------------------------
        # 注意: 即使本轮没有发生配置变异 (mutant_cfg == parent_cfg),
        #   mutant_seed 也必须绑定一份独立档案 (深拷贝).
        #   这样 mutant 后续被选作父本时, _get_seed_config 能直接命中它的档案,
        #   不会走 fallback, 也不会与 parent 共享引用.
        #   这正是用户分析的 Case C: enable=True 但本轮 70% 未命中变异时,
        #   仍需为 mutant 落档以防"延迟漂移".
        # ============================================================
        new_history = seed.mutation_history + [mutation_info]
        anchor_pc_for_record = anchor_pc if anchor_pc else "config_only"

        mutant_seed = Seed(
            asm_path=mutant_path,
            cross_stage_locked_pcs=seed.cross_stage_locked_pcs,
            mutation_history=new_history,
            parent_id=seed.id,
        )
        mutant_seed.current_stage_mutated_pcs = set(
            seed.current_stage_mutated_pcs)
        if asm_mutated_flag:
            mutant_seed.record_mutation(anchor_pc_for_record)

        # _set_seed_config 内部已做 deepcopy, 外部传 mutant_cfg 即可
        # enable_config_mutation=False 时函数内 no-op, 满足 Case A
        self._set_seed_config(mutant_seed, mutant_cfg)

        # ============================================================
        # 第四步: 评估
        # ============================================================
        tag = "s3_r{}".format(round_idx)
        eval_result = self._evaluate_seed(mutant_seed, tag=tag)

        if eval_result is None:
            logger.info(
                "Round {}: evaluation failed (anchor={})".format(
                    round_idx, anchor_pc_for_record))
            if mutant_path != seed.asm_path:
                self._cleanup_mutant(mutant_path)
            # [FIX-B6] 评测失败: 清理它已经绑定的 cfg 档案
            self._unbind_seed_config(mutant_seed)
            return None

        mutant_seed.score = eval_result["score"]
        mutant_seed.eval_detail = eval_result

        # passed: 立即返回
        if eval_result["passed"]:
            logger.info(
                "Round {}: >>> MATCH <<< score={:.4f}, "
                "match_rate={:.3f}, latency={:.1f}, "
                "config_mutated={}, asm_mutated={}".format(
                    round_idx, eval_result["score"],
                    eval_result["match_rate"],
                    eval_result["mean_expected_latency"],
                    config_mutated_flag, asm_mutated_flag))
            # 保护 passed seed 的 .s 文件不被后续清理
            self._protected_paths.add(mutant_seed.asm_path)
            return {"passed": True, "seed": mutant_seed}

        # 入库 (由 seed_pool.add 决策)
        worst_before = self.seed_pool.get_worst_score()
        admitted = self.seed_pool.add(mutant_seed)
        if admitted:
            seed.children_produced += 1
            logger.debug(
                "Round {}: admitted, score={:.4f}, latency={:.1f}, "
                "pool_size={}, prev_worst={:.4f}".format(
                    round_idx, eval_result["score"],
                    eval_result["mean_expected_latency"],
                    len(self.seed_pool.seeds), worst_before))
        else:
            logger.debug(
                "Round {}: rejected, score={:.4f} <= worst={:.4f}".format(
                    round_idx, eval_result["score"], worst_before))
            if mutant_path != seed.asm_path:
                self._cleanup_mutant(mutant_path)
            # [FIX-B6] 被池拒绝: 清理它的 cfg 档案
            self._unbind_seed_config(mutant_seed)

        return {"passed": False, "seed": mutant_seed}

    # =================================================================
    # 评估 (带超时保护)
    # =================================================================

    def _evaluate_seed(self, seed, tag="eval"):
        """
        编译, 运行 (ENABLE_STAGE3=1 + 该 seed 绑定的 stage3 配置), 评估.

        关键点: stage3 配置从 self.seed_stage3_configs[seed.id] 取出,
        然后透传到 _run_executable, 由 generate_stage3_env 注入子进程 env.
        """
        try:
            with open(seed.asm_path, "r") as f:
                asm_lines = f.readlines()

            cleaned_lines = self._remove_stage1_instrumentation(asm_lines)
            stripped_lines = self._strip_main_function(cleaned_lines)

            out_dir = os.path.join(self.work_dir, tag)
            os.makedirs(out_dir, exist_ok=True)
            processed_s = os.path.join(out_dir, "victim_processed.s")

            try:
                with open(processed_s, "w") as f:
                    f.writelines(stripped_lines)
            except Exception as e:
                self.failure_stats["process_failed"] += 1
                logger.debug(
                    "[{}] Cannot write processed asm: {}".format(tag, e))
                return None

            exe_path = self._compile_stage3(processed_s, out_dir, tag)
            if exe_path is None:
                return None

            # 取出该 seed 绑定的 stage3 配置 (缺省回退到 current)
            stage3_cfg = self._get_seed_config(seed)

            logger.debug(
                "[{}] Compiled OK, running with ENABLE_STAGE3=1, "
                "secret={}, seed_id={}".format(
                    tag, self.expected_secret, seed.id))

            log_lines = self._run_executable(
                exe_path, tag, stage3_cfg=stage3_cfg)
            if log_lines is None:
                return None

            result = stage3_evaluate(log_lines)
            # 把实际生效的配置挂到评测结果上, 后续 archive / metadata 复用
            if isinstance(result, dict):
                result["stage3_config_used"] = stage3_cfg
            return result

        except _RoundTimeout:
            raise
        except subprocess.TimeoutExpired:
            self.failure_stats["run_timeout"] += 1
            logger.debug("[{}] Timeout (uncaught)".format(tag))
            return None
        except Exception as e:
            self.failure_stats["eval_exception"] += 1
            logger.error("[{}] Evaluation error: {}".format(tag, e))
            logger.error("Traceback:\n{}".format(traceback.format_exc()))
            return None

    def _precompile_stage3_obj(self):
        """预编译 stage3_driver_safe.c -> .o"""
        os.makedirs(self.work_dir, exist_ok=True)

        if not os.path.exists(self.stage3_driver_c):
            logger.warning(
                "stage3_driver_safe.c not found: {}".format(
                    self.stage3_driver_c))
            self.stage3_obj = None
            return

        compile_cmd = [
            self.cc, "-c", "-O0",
            self.stage3_driver_c,
            "-o", self.stage3_obj
        ]
        try:
            r = subprocess.run(
                compile_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.compile_timeout)
            if r.returncode != 0:
                logger.warning("stage3 compile failed: {}".format(
                    r.stderr.decode("utf-8", errors="ignore")[:300]))
                self.stage3_obj = None
            else:
                logger.info("Pre-compiled stage3_driver_safe.o")
        except subprocess.TimeoutExpired:
            logger.warning("stage3_driver_safe.c compile timeout")
            self.stage3_obj = None

    def _remove_stage1_instrumentation(self, asm_lines):
        """移除 Stage 1 PMU 插桩代码"""
        result = []
        stage1_calls = [
            "pmu_stage1_before", "pmu_stage1_after",
            "pmu_uops_snap_before", "pmu_uops_snap_after",
            "pmu_stage1_get_count", "pmu_stage1_get_delta",
        ]
        stage1_markers = [
            "STAGE1_PMU_BEGIN", "STAGE1_PMU_END",
            "STAGE1_UOPS_BEGIN", "STAGE1_UOPS_END",
            "# [stage1", "# --- PMU", "# --- UOPS",
        ]

        for line in asm_lines:
            stripped = line.strip()
            is_call = any(
                "call" in stripped and func in stripped
                for func in stage1_calls)
            is_marker = any(m in stripped for m in stage1_markers)
            if is_call or is_marker:
                result.append("# [s3-removed] {}\n".format(stripped))
            else:
                result.append(line)

        removed = sum(
            1 for l in result if l.startswith("# [s3-removed]"))
        if removed > 0:
            logger.debug(
                "Removed {} Stage 1 instrumentation lines".format(removed))
        return result

    def _strip_main_function(self, asm_lines):
        """从汇编中剥离 main 函数体"""
        result = []
        in_main = False

        for line in asm_lines:
            stripped = line.strip()

            if re.match(r'^\s*\.glob[al]+\s+main\s*$', stripped):
                result.append("# [s3-strip] " + line)
                continue
            if re.match(
                    r'^\s*\.type\s+main\s*,\s*@function', stripped):
                result.append("# [s3-strip] " + line)
                continue
            if re.match(r'^main\s*:', stripped):
                in_main = True
                result.append("# [s3-strip] " + line)
                continue
            if in_main and re.match(
                    r'^\s*\.size\s+main\s*,', stripped):
                result.append("# [s3-strip] " + line)
                in_main = False
                continue
            if in_main:
                if (re.match(r'^\s*\.glob[al]+\s+\w', stripped)
                        and 'main' not in stripped):
                    in_main = False
                    result.append(line)
                    continue
                if (re.match(
                        r'^\s*\.type\s+\w+\s*,\s*@function',
                        stripped) and 'main' not in stripped):
                    in_main = False
                    result.append(line)
                    continue
                result.append("# [s3-strip] " + line)
                continue
            result.append(line)
        return result

    def _compile_stage3(self, victim_s, out_dir, tag):
        """Stage 3 编译链 (三步, 各自带超时)"""
        victim_o = os.path.join(out_dir, "victim.o")
        driver_o = os.path.join(out_dir, "driver.o")
        exe_path = os.path.join(out_dir, "stage3_exe")

        # Step 1: 编译 victim
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
            err_text = r1.stderr.decode("utf-8", errors="ignore")[:300]
            logger.debug("[{}] Victim asm failed: {}".format(tag, err_text))
            self._archive_failure(
                tag, "compile_victim_failed",
                victim_s=victim_s, stderr=err_text)
            return None

        # Step 2: 编译 driver
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
            logger.debug("[{}] Driver compile failed".format(tag))
            return None

        # Step 3: 链接
        link_cmd = [self.cc, victim_o, driver_o, self.pmu_helper_obj]
        if self.stage3_obj and os.path.exists(self.stage3_obj):
            link_cmd.append(self.stage3_obj)
        if (self.pmu_uops_obj and os.path.exists(self.pmu_uops_obj)):
            link_cmd.append(self.pmu_uops_obj)
        link_cmd += ["-o", exe_path]

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
            err_text = r3.stderr.decode("utf-8", errors="ignore")[:500]
            logger.debug("[{}] Link failed: {}".format(tag, err_text))
            self._archive_failure(
                tag, "link_failed",
                victim_s=victim_s, stderr=err_text)
            return None

        return exe_path

    def _run_executable(self, exe_path, tag, stage3_cfg=None):
        """
        运行可执行文件 (带超时保护 + 强杀 + 环境变量注入).

        stage3_cfg: 本次运行使用的 stage3 配置 dict.
                    缺省 None 时回退到 self.current_stage3_config.
                    由调用方 (_evaluate_seed) 从 seed_stage3_configs 取出.
        """
        if stage3_cfg is None:
            stage3_cfg = self.current_stage3_config

        env = os.environ.copy()
        env["ENABLE_STAGE3"] = "1"
        env["STAGE3_MODE"] = "flush-reload"
        env["VF_EXPECTED_SECRET"] = str(self.expected_secret)

        # ---- 关键: 把变异后的 stage3 配置注入子进程 env ----
        cfg_env = {}
        try:
            extra = generate_stage3_env(stage3_cfg)
            if isinstance(extra, dict):
                cfg_env = {str(k): str(v) for k, v in extra.items()}
                env.update(cfg_env)
            else:
                logger.warning(
                    "[{}] generate_stage3_env returned non-dict ({}), "
                    "no stage3 env injected".format(
                        tag, type(extra).__name__))
        except Exception as e:
            # 升级为 ERROR + traceback: 静默吞错会掩盖"配置变异空转"
            logger.error(
                "[{}] generate_stage3_env failed: {}".format(tag, e))
            logger.error("Traceback:\n{}".format(traceback.format_exc()))

        # INFO 级曝光实际注入的变异参数, 直接证明配置变异有效
        logger.info(
            "[{}] inject stage3 env (count={}): {}".format(
                tag, len(cfg_env), cfg_env))
        logger.debug(
            "[{}] launch env: ENABLE_STAGE3={} STAGE3_MODE={} "
            "VF_EXPECTED_SECRET={}".format(
                tag, env.get("ENABLE_STAGE3"),
                env.get("STAGE3_MODE"),
                env.get("VF_EXPECTED_SECRET")))

        start_time = time.time()
        proc = None
        try:
            proc = subprocess.Popen(
                [exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=os.setsid,
            )
            _ACTIVE_CHILD_PIDS.add(proc.pid)

            while True:
                elapsed = time.time() - start_time

                # 运行超时
                if elapsed > self.run_timeout:
                    logger.info(
                        "[{}] Execution timeout after {:.1f}s "
                        "(limit: {}s), killing".format(
                            tag, elapsed, self.run_timeout))
                    self._kill_proc_group(proc, tag)
                    self.failure_stats["run_timeout"] += 1
                    # 抢救一份 stderr
                    try:
                        _, stderr_tail = proc.communicate(timeout=0.5)
                        err_tail = stderr_tail.decode(
                            "utf-8", errors="ignore")[:500]
                    except Exception:
                        err_tail = ""
                    self._archive_failure(
                        tag, "run_timeout",
                        exe_path=exe_path,
                        stderr=err_tail,
                        note="elapsed={:.1f}s".format(elapsed))
                    return None

                rc = proc.poll()
                if rc is not None:
                    try:
                        stdout, stderr = proc.communicate()
                    except Exception as e:
                        logger.debug(
                            "[{}] communicate() error: {}".format(tag, e))
                        stdout, stderr = b"", b""

                    output = stdout.decode("utf-8", errors="ignore")
                    err = stderr.decode("utf-8", errors="ignore")
                    lines = output.splitlines()

                    # rc != 0 时不直接丢弃 (SIGSEGV 时 stdout 也可能有有效输出)
                    if rc != 0:
                        logger.debug(
                            "[{}] rc={}, time={:.1f}s, "
                            "stderr={}".format(
                                tag, rc, elapsed, err[:200]))

                    if not lines:
                        self.failure_stats["run_failed"] += 1
                        logger.debug(
                            "[{}] Empty stdout (rc={}, time={:.1f}s)"
                            .format(tag, rc, elapsed))
                        self._archive_failure(
                            tag, "run_empty_stdout",
                            exe_path=exe_path,
                            stdout=output[:2000],
                            stderr=err[:1000],
                            note="rc={}".format(rc))
                        return None

                    if not any(
                            "STAGE3_ROUND" in ln or
                            "STAGE3_DEBUG_ROUND" in ln
                            for ln in lines):
                        logger.warning(
                            "[{}] Driver produced NO STAGE3_ROUND* "
                            "output. (rc={}, stderr_head={})".format(
                                tag, rc, err[:120]))
                        self._archive_failure(
                            tag, "no_stage3_output",
                            exe_path=exe_path,
                            stdout=output[:2000],
                            stderr=err[:1000],
                            note="rc={}".format(rc))

                    logger.debug(
                        "[{}] Execution finished in {:.1f}s, "
                        "rc={}".format(tag, elapsed, rc))
                    return lines

                time.sleep(0.1)

        except _RoundTimeout:
            # 上层 alarm 触发, 杀掉子进程后传播
            if proc is not None:
                self._kill_proc_group(proc, tag)
            raise
        except Exception as e:
            self.failure_stats["run_failed"] += 1
            logger.error("[{}] Execution exception: {}".format(tag, e))
            logger.error("Traceback:\n{}".format(traceback.format_exc()))
            if proc is not None and proc.poll() is None:
                self._kill_proc_group(proc, tag)
            return None
        finally:
            if proc is not None:
                _ACTIVE_CHILD_PIDS.discard(proc.pid)

    def _kill_proc_group(self, proc, tag):
        """SIGTERM -> wait 1s -> SIGKILL 双阶段终止"""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            logger.debug("[{}] Sent SIGTERM to process group".format(tag))
        except ProcessLookupError:
            return
        except Exception as e:
            logger.debug("[{}] SIGTERM error: {}".format(tag, e))

        try:
            proc.wait(timeout=1.0)
            logger.debug("[{}] Process terminated gracefully".format(tag))
            return
        except subprocess.TimeoutExpired:
            pass

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            logger.debug("[{}] Sent SIGKILL to process group".format(tag))
            proc.wait(timeout=1.0)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logger.debug("[{}] SIGKILL error: {}".format(tag, e))

    def _kill_process(self, exe_path):
        """兜底: 通过进程名清理同名残留 (仅在异常路径使用)"""
        try:
            exe_name = os.path.basename(exe_path)
            for cmd in (["pkill", "-9", "-f", exe_name],
                        ["killall", "-9", exe_name]):
                try:
                    subprocess.run(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2)
                except Exception:
                    pass
            logger.debug("Killed process: {}".format(exe_name))
        except Exception as e:
            logger.debug(
                "Failed to kill process {}: {}".format(exe_path, e))

    def _cleanup_mutant(self, mutant_path):
        """清理被拒绝的变异体目录 (受 _protected_paths 保护)"""
        try:
            if mutant_path in self._protected_paths:
                return
            d = os.path.dirname(mutant_path)
            for prot in self._protected_paths:
                if os.path.dirname(prot) == d:
                    return
            if "mutant_" in os.path.basename(d):
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

    # =================================================================
    # 归档: 失败 / 成功
    # =================================================================

    def _archive_failure(self, tag, reason,
                         victim_s=None, exe_path=None,
                         stdout=None, stderr=None, note=None):
        """将失败现场归档到 _failures/{tag}__{reason}/"""
        try:
            ts = time.strftime("%Y%m%d_%H%M%S")
            dest_name = "{}__{}__{}".format(tag, reason, ts)
            dest = os.path.join(self.failures_dir, dest_name)
            os.makedirs(dest, exist_ok=True)

            if victim_s and os.path.exists(victim_s):
                try:
                    shutil.copy2(
                        victim_s,
                        os.path.join(dest, "victim_processed.s"))
                except Exception:
                    pass
            if exe_path and os.path.exists(exe_path):
                try:
                    shutil.copy2(
                        exe_path, os.path.join(dest, "stage3_exe"))
                except Exception:
                    pass
            if stdout:
                with open(os.path.join(dest, "stdout.log"), "w") as f:
                    f.write(stdout)
            if stderr:
                with open(os.path.join(dest, "stderr.log"), "w") as f:
                    f.write(stderr)

            meta = {
                "tag": tag,
                "reason": reason,
                "timestamp": ts,
                "note": note or "",
                "stage3_config": self.current_stage3_config,
            }
            with open(os.path.join(dest, "metadata.json"), "w") as f:
                json.dump(meta, f, indent=2)
            logger.debug("Archived failure to {}".format(dest))
        except Exception as e:
            logger.debug("Archive failure error: {}".format(e))

    def _archive_success(self, seed, tag, eval_result, stage):
        """
        保存成功现场到 _success/{tag}__{ts}/
        用于后续手工复现.
        """
        try:
            ts = time.strftime("%Y%m%d_%H%M%S")
            dest_name = "{}__{}".format(tag, ts)
            dest = os.path.join(self.success_dir, dest_name)
            os.makedirs(dest, exist_ok=True)

            # 1. 原始 .s
            if seed.asm_path and os.path.exists(seed.asm_path):
                try:
                    shutil.copy2(
                        seed.asm_path,
                        os.path.join(dest, "victim.s"))
                except Exception as e:
                    logger.debug(
                        "copy victim.s failed: {}".format(e))

            # 2. 实际编译用的 victim_processed.s (在 work_dir/{tag}/ 下)
            processed_s = os.path.join(
                self.work_dir, tag, "victim_processed.s")
            if os.path.exists(processed_s):
                try:
                    shutil.copy2(
                        processed_s,
                        os.path.join(dest, "victim_processed.s"))
                except Exception:
                    pass

            # 3. 当时该 seed 实际生效的 stage3 配置 (per-seed)
            try:
                save_stage3_config(
                    self._get_seed_config(seed),
                    os.path.join(dest, "stage3_config.json"))
            except Exception as e:
                logger.debug(
                    "save stage3_config failed: {}".format(e))

            # 4. metadata
            try:
                meta = {
                    "stage": stage,
                    "tag": tag,
                    "timestamp": ts,
                    "expected_secret": self.expected_secret,
                    "expected_secret_char": chr(self.expected_secret),
                    "seed_id": getattr(seed, "id", None),
                    "parent_id": getattr(seed, "parent_id", None),
                    "score": getattr(seed, "score", None),
                    "match_rate": (eval_result or {}).get("match_rate"),
                    "match_count": (eval_result or {}).get("match_count"),
                    "mean_expected_latency":
                        (eval_result or {}).get("mean_expected_latency"),
                    "num_rounds": (eval_result or {}).get("num_rounds"),
                    "mutation_history": getattr(
                        seed, "mutation_history", []),
                    "cross_stage_locked_pcs": sorted(list(
                        getattr(seed, "cross_stage_locked_pcs", set()))),
                    "current_stage_mutated_pcs": sorted(list(
                        getattr(seed, "current_stage_mutated_pcs", set()))),
                    "stage3_config_used": self._get_seed_config(seed),
                    "run_timeout": self.run_timeout,
                    "compile_timeout": self.compile_timeout,
                    "per_round_timeout": self.per_round_timeout,
                }
                with open(os.path.join(dest, "metadata.json"), "w") as f:
                    json.dump(meta, f, indent=2, default=str)
            except Exception as e:
                logger.debug("save metadata failed: {}".format(e))

            # 5. 复现说明
            try:
                with open(os.path.join(dest, "REPRODUCE.txt"), "w") as f:
                    f.write(
                        "Stage 3 SUCCESS reproduction package\n"
                        "=====================================\n\n"
                        "Stage           : {stage}\n"
                        "Timestamp       : {ts}\n"
                        "Expected secret : {sec} (0x{sec_x:02x})\n"
                        "Seed id         : {sid}\n"
                        "Score           : {score}\n"
                        "Match rate      : {mr}\n\n"
                        "Files:\n"
                        "  victim.s             : original asm seed\n"
                        "  victim_processed.s   : asm actually compiled\n"
                        "  stage3_config.json   : runtime config used\n"
                        "  metadata.json        : full provenance\n\n"
                        "Reproduce (rough):\n"
                        "  gcc -c victim_processed.s -o victim.o\n"
                        "  gcc -c -O0 <driver_c> -o driver.o\n"
                        "  gcc victim.o driver.o <pmu_helper_obj> "
                        "[<stage3_obj>] [<pmu_uops_obj>] -o stage3_exe\n"
                        "  ENABLE_STAGE3=1 STAGE3_MODE=flush-reload "
                        "VF_EXPECTED_SECRET={sec_x} "
                        "<+ env from stage3_config.json> ./stage3_exe\n"
                        .format(
                            stage=stage, ts=ts,
                            sec=chr(self.expected_secret),
                            sec_x=self.expected_secret,
                            sid=getattr(seed, "id", None),
                            score=getattr(seed, "score", None),
                            mr=(eval_result or {}).get("match_rate")))
            except Exception:
                pass

            # 保护 success 目录下文件不被清理
            for fn in os.listdir(dest):
                self._protected_paths.add(os.path.join(dest, fn))
            # 同时保护原 seed.asm_path
            if seed.asm_path:
                self._protected_paths.add(seed.asm_path)

            logger.info("Archived SUCCESS to {}".format(dest))
        except Exception as e:
            logger.error("Archive success error: {}".format(e))
            logger.error("Traceback:\n{}".format(traceback.format_exc()))

    # =================================================================
    # 报告
    # =================================================================

    def _report_stats(self, round_num):
        """报告种子池统计 + 失败统计"""
        stats = self.seed_pool.stats()
        logger.info(
            "Round {}/{}: pool={}, added={}, evicted={}, "
            "rejected={}, avg={:.4f}, max={:.4f}".format(
                round_num, self.budget,
                stats["size"],
                stats["total_added"], stats["total_evicted"],
                stats["total_rejected"],
                stats["avg_score"], stats["max_score"]))

        total_failures = sum(self.failure_stats.values())
        if total_failures > 0:
            logger.info(
                "  Failures: process={}, compile={} (timeout={}), "
                "run={} (timeout={}), eval_exc={}, "
                "round_timeout={}, invalid_mutation={}".format(
                    self.failure_stats["process_failed"],
                    self.failure_stats["compile_failed"],
                    self.failure_stats["compile_timeout"],
                    self.failure_stats["run_failed"],
                    self.failure_stats["run_timeout"],
                    self.failure_stats["eval_exception"],
                    self.failure_stats["round_timeout"],
                    self.failure_stats["invalid_mutation"]))

        best = self.seed_pool.get_best_seed()
        if best and best.eval_detail:
            ed = best.eval_detail
            logger.info(
                "  Best: id={}, score={:.4f}, "
                "match_rate={:.3f}, latency={:.1f}".format(
                    best.id, best.score,
                    ed.get("match_rate", 0),
                    ed.get("mean_expected_latency", 0)))

    def _report_failure_stats(self):
        """完整失败统计 (run() 结束时调用)"""
        total_failures = sum(self.failure_stats.values())
        if total_failures == 0:
            logger.info("No failures recorded.")
            return

        logger.info("=" * 60)
        logger.info("Failure Statistics Summary:")
        logger.info("=" * 60)
        logger.info("Total failures: {}".format(total_failures))
        for k in ("process_failed", "compile_failed", "compile_timeout",
                  "run_failed", "run_timeout", "eval_exception",
                  "round_timeout", "invalid_mutation"):
            logger.info("  {:<18s}: {}".format(k, self.failure_stats[k]))

        total_attempts = total_failures + self.seed_pool.total_added
        if total_attempts > 0:
            failure_rate = total_failures / float(total_attempts) * 100
            logger.info("Failure rate: {:.1f}% ({}/{})".format(
                failure_rate, total_failures, total_attempts))

    # =================================================================
    # 保护性锚点选择 (保留不动)
    # =================================================================

    def _select_safe_anchor(self, excluded_pcs):
        """选择安全锚点 (排除跨阶段锁定 + flush-reload 核心区域)"""
        safe_anchors = []
        for anchor in self.anchors:
            pc = anchor.get("pc", "")
            if pc in excluded_pcs:
                continue
            if self._is_flush_reload_critical(anchor):
                continue
            safe_anchors.append(anchor)
        if not safe_anchors:
            return None
        return random.choice(safe_anchors)

    def _is_flush_reload_critical(self, anchor):
        """判断锚点是否在 flush-reload 核心区域"""
        disasm = anchor.get("disasm", "").lower()
        mnemonic = anchor.get("mnemonic", "").lower()

        critical_functions = [
            "vf_run_attack_once",
            "vf_get_probe_addr_for_secret",
            "vf_prepare_probe_region",
            "stage3_flush_line",
            "stage3_reload_timed",
            "_mm_clflush",
            "__rdtscp",
            "_mm_mfence",
            "_mm_lfence",
        ]
        if mnemonic == "call":
            for func in critical_functions:
                if func in disasm:
                    return True

        causal_objs = anchor.get("causal_objects_full_mutation", [])
        for obj_id in causal_objs:
            obj = self.scheduler.strong_object_by_id.get(obj_id, {})
            obj_name = obj.get("name", "").lower()
            if "probe" in obj_name or "array" in obj_name:
                return True

        tags = set(anchor.get("semantic_tags", []))
        critical_tags = {
            "flush_reload_core",
            "cache_timing_measurement",
            "probe_array_access",
        }
        if tags & critical_tags:
            return True

        return False