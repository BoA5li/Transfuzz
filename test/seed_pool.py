#!/usr/bin/env python3
"""
seed_pool.py

种子库管理模块（优化版）。
- 入库判定统一为 score > 库中最差
- locked_pcs 区分同阶段/跨阶段语义
Compatible with Python 3.6+.
"""

import random
import os
import shutil
import logging

logger = logging.getLogger("seed_pool")


class Seed(object):
    """单个种子"""

    _next_id = 0

    def __init__(self, asm_path, score=0.0,
                 cross_stage_locked_pcs=None,
                 mutation_history=None, parent_id=None):
        """
        参数:
          asm_path:                 .s 汇编文件路径
          score:                    综合评分
          cross_stage_locked_pcs:   跨阶段锁定的 PC 集合
                                    （前一阶段的变异点，本阶段不可触碰）
          mutation_history:         变异历史
          parent_id:                父种子 ID
        """
        self.id = Seed._next_id
        Seed._next_id += 1

        self.asm_path = asm_path
        self.score = score

        # 跨阶段锁定: 前一阶段确定的变异点，本阶段不可再变异
        self.cross_stage_locked_pcs = set(cross_stage_locked_pcs) \
            if cross_stage_locked_pcs else set()

        # 同阶段变异历史: 仅记录，不锁定（同阶段可重复变异同一位置）
        self.current_stage_mutated_pcs = set()

        self.mutation_history = list(mutation_history) if mutation_history else []
        self.parent_id = parent_id

        self.age = 0
        self.children_produced = 0
        self.eval_detail = None

    def record_mutation(self, anchor_pc):
        """记录本阶段的一次变异（不锁定）"""
        # ✅ 新增：过滤 None
        if anchor_pc is None:
            return
        self.current_stage_mutated_pcs.add(anchor_pc)

    def get_excluded_pcs(self):
        """
        获取本次变异应排除的 PC 集合。
        只排除跨阶段锁定的 PC（前阶段变异点）。
        同阶段变异过的 PC 不排除（可重复变异）。
        """
        return set(self.cross_stage_locked_pcs)

    def create_child_for_next_stage(self):
        """
        为下一阶段创建子种子。
        本阶段的所有变异点（cross_stage + current_stage）
        都变成下一阶段的 cross_stage_locked_pcs。
        """
        all_locked = self.cross_stage_locked_pcs | self.current_stage_mutated_pcs
        child = Seed(
            asm_path=self.asm_path,
            score=self.score,
            cross_stage_locked_pcs=all_locked,
            mutation_history=list(self.mutation_history),
            parent_id=self.id,
        )
        child.eval_detail = self.eval_detail
        return child

    def __repr__(self):
        return (
            "Seed(id={}, score={:.4f}, age={}, "
            "cross_locked={}, stage_mutated={}, children={})"
            .format(self.id, self.score, self.age,
                    len(self.cross_stage_locked_pcs),
                    len(self.current_stage_mutated_pcs),
                    self.children_produced)
        )


class SeedPool:
    """种子池（优化版：严格入库判定）"""
    
    def __init__(self, max_size=200, stage_name="unknown"):
        if max_size <= 0:
            raise ValueError(
                "SeedPool max_size must be >= 1, got {}. "
                "Hint: --{}-pool-size should be positive even "
                "when budget=0 (for baseline seeds).".format(max_size, stage_name))
        self.max_size = max_size
        self.stage_name = stage_name
        self.seeds = []
        
        # 统计信息
        self.total_added = 0
        self.total_evicted = 0
        self.total_rejected = 0  # 未达标被拒绝的种子数
        self.total_passed_admitted = 0   # 新增：passed 种子入库统计
        
        # ✅ 新增：最低分数阈值（动态调整）
        self.min_score_threshold = 0.0  # 初始阈值为 0

        # [新增] 驱逐回调: 由 controller 注入, 用于清理 per-seed 外部资源
        # (例如 stage3 per-seed cfg 档案).
        # 签名: callback(victim_seed) -> None
        self._evict_callback = None
    
    @staticmethod
    def _is_passed(seed):
        """判断种子是否通过本阶段检测"""
        ed = getattr(seed, "eval_detail", None)
        return bool(ed and ed.get("passed", False))

    def _passed_seeds_in_pool(self):
        return [s for s in self.seeds if self._is_passed(s)]

    def _non_passed_seeds_in_pool(self):
        return [s for s in self.seeds if not self._is_passed(s)]

    def should_admit(self, seed):
        """
        修订版判定：
          - passed 种子：无条件接受（即使分数低）
          - 非 passed 种子：必须超过当前最差非 passed 种子的分数
          - 若池中全为 passed 且非 passed 候选要入库 → 拒绝
        """
        # ✅ 池为空：直接接受
        if len(self.seeds) == 0:
            return True

        # ✅ passed 种子：无条件接受
        if self._is_passed(seed):
            return True

        # 非 passed 种子：与非 passed 种子的最差分数比较
        non_passed = self._non_passed_seeds_in_pool()
        if not non_passed:
            # 池中全是 passed → 非 passed 候选无资格挤入
            return False

        worst_non_passed_score = min(s.score for s in non_passed)
        return seed.score > worst_non_passed_score

    def add(self, seed):
        """
        修订版 add：
          1. 池未满 → 直接入库
          2. 池已满 + 候选是 passed → 优先驱逐非 passed worst；
             若全 passed 则驱逐最低 passed
          3. 池已满 + 候选非 passed → 驱逐非 passed worst（若分数更低）
        """
        is_passed = self._is_passed(seed)

        # 接受性检查（passed 种子总是通过）
        if not self.should_admit(seed):
            self.total_rejected += 1
            return False

        # ---- 池未满 ----
        if len(self.seeds) < self.max_size:
            self.seeds.append(seed)
            self.total_added += 1
            if is_passed:
                self.total_passed_admitted += 1
            self._update_threshold()
            return True

        # ---- 池已满 ----
        if is_passed:
            # 优先淘汰非 passed
            non_passed = self._non_passed_seeds_in_pool()
            if non_passed:
                victim = min(non_passed, key=lambda s: s.score)
                victim_idx = self.seeds.index(victim)
                self._evict_file(victim)
                self.seeds[victim_idx] = seed
            else:
                # 全 passed：找最低分 passed
                victim_idx = self._find_worst_seed_index()
                victim = self.seeds[victim_idx]
                if seed.score >= victim.score:
                    self._evict_file(victim)
                    self.seeds[victim_idx] = seed
                else:
                    # 拒绝（不删除候选文件，调用方通常会保留 passed）
                    self.total_rejected += 1
                    return False
            self.total_added += 1
            self.total_evicted += 1
            self.total_passed_admitted += 1
            self._update_threshold()
            return True

        # 候选非 passed
        non_passed = self._non_passed_seeds_in_pool()
        if not non_passed:
            self.total_rejected += 1
            return False
        victim = min(non_passed, key=lambda s: s.score)
        if seed.score > victim.score:
            victim_idx = self.seeds.index(victim)
            self._evict_file(victim)
            self.seeds[victim_idx] = seed
            self.total_added += 1
            self.total_evicted += 1
            self._update_threshold()
            return True

        self.total_rejected += 1
        return False
    
    # ----------------------------------------------------------------
    # ✅ 新增：被驱逐种子的文件清理（仅清理非 passed）
    # ----------------------------------------------------------------
    def _evict_file(self, victim):
        """
        驱逐种子时尝试清理其 .s 文件目录, 并调用外部驱逐回调.
        ⚠️ 仅清理非 passed 种子的 .s 目录;
        passed 种子的文件由 controller 统一管理.
        但外部回调对 passed/非 passed 都触发, 由 controller 自行决定逻辑.
        """
        # 先调用外部回调 (例如清理 per-seed cfg 档案)
        # 不论 victim 是否 passed 都通知, 让 controller 拥有完整决定权.
        if self._evict_callback is not None:
            try:
                self._evict_callback(victim)
            except Exception as e:
                logger.debug(
                    "evict callback failed for seed id={}: {}".format(
                        getattr(victim, "id", "?"), e))

        # 再清理 .s 目录 (仅非 passed)
        if self._is_passed(victim):
            return
        try:
            import os, shutil
            asm_dir = os.path.dirname(victim.asm_path)
            # 只清理 mutant_xxx 目录，避免误删 baseline
            if asm_dir and "mutant_" in asm_dir and os.path.isdir(asm_dir):
                shutil.rmtree(asm_dir, ignore_errors=True)
                logger.debug("Evicted mutant dir: {}".format(asm_dir))
        except Exception as e:
            logger.debug("Evict file cleanup failed: {}".format(e))

    def set_evict_callback(self, callback):
        """
        注册驱逐回调.

        当 pool 决定驱逐一个 seed 时, 会在 _evict_file 中调用该回调,
        传入被驱逐的 Seed 对象, 让外部 (如 controller) 清理与之关联的资源
        (例如 per-seed 配置档案、外部索引等).

        callback(victim_seed) -> None
        """
        self._evict_callback = callback

    def _find_worst_seed_index(self):
        """找到分数最低的种子索引"""
        if not self.seeds:
            return -1
        return min(range(len(self.seeds)), 
                   key=lambda i: self.seeds[i].score)

    def get_worst_score(self):
        """获取池中最差种子的分数"""
        if not self.seeds:
            return 0.0
        return min(s.score for s in self.seeds)

    def get_best_seed(self):
        """获取池中最好的种子"""
        if not self.seeds:
            return None
        return max(self.seeds, key=lambda s: s.score)

    def _update_threshold(self):
        """更新最低分数阈值（用于统计）"""
        if self.seeds:
            self.min_score_threshold = self.get_worst_score()

    def select(self):
        """加权随机（保持原逻辑）"""
        if not self.seeds:
            return None

        weights = []
        for seed in self.seeds:
            w = seed.score
            age_penalty = 1.0 / (1.0 + seed.age * 0.1)
            w *= age_penalty
            fertility_penalty = 1.0 / (1.0 + seed.children_produced * 0.05)
            w *= fertility_penalty
            # passed 种子给予轻微选择优势（×1.2）
            if self._is_passed(seed):
                w *= 1.2
            weights.append(max(w, 0.01))

        total = sum(weights)
        if total <= 0:
            self.seeds[0].age += 1
            return self.seeds[0]

        r = random.random() * total
        cumsum = 0
        for i, w in enumerate(weights):
            cumsum += w
            if r <= cumsum:
                self.seeds[i].age += 1
                return self.seeds[i]
        self.seeds[-1].age += 1
        return self.seeds[-1]

    def stats(self):
        if not self.seeds:
            return {
                "size": 0, "avg_score": 0.0, "max_score": 0.0,
                "min_score": 0.0, "avg_age": 0.0,
                "total_added": self.total_added,
                "total_evicted": self.total_evicted,
                "total_rejected": self.total_rejected,
                "total_passed_admitted": self.total_passed_admitted,
                "passed_count": 0,
            }
        scores = [s.score for s in self.seeds]
        ages = [s.age for s in self.seeds]
        passed_count = sum(1 for s in self.seeds if self._is_passed(s))
        return {
            "size": len(self.seeds),
            "avg_score": sum(scores) / len(scores),
            "max_score": max(scores),
            "min_score": min(scores),
            "avg_age": sum(ages) / len(ages),
            "total_added": self.total_added,
            "total_evicted": self.total_evicted,
            "total_rejected": self.total_rejected,
            "total_passed_admitted": self.total_passed_admitted,
            "passed_count": passed_count,
        }