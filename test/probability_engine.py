#!/usr/bin/env python3
"""
probability_engine.py

变异概率计算引擎。
"""

from typing import Dict, Set, List


# Tier 基础概率
TIER_BASE_PROBABILITY = {
    "tier_1_critical": 0.70,
    "tier_2_high": 0.55,
    "tier_3_medium": 0.40,
    "tier_4_low": 0.25,
    "tier_5_prologue_epilogue": 0.15,
    "tier_6_structural": 0.10,
}

# 强因果对象加成
STRONG_CAUSAL_BOOST = 1.3

# 非强因果对象衰减
WEAK_CAUSAL_DECAY = 0.7


class ProbabilityEngine:
    """概率计算引擎"""
    
    def __init__(self, strong_objects: Set[str], locked_pcs: Set[str]):
        self.strong_objects = strong_objects
        self.locked_pcs = locked_pcs
    
    def compute_mutation_probability(self, anchor: Dict, 
                                     protection_modifier: float = 1.0,
                                     loop_modifier: float = 1.0) -> float:
        """计算变异概率"""
        
        pc = anchor.get("pc")
        
        # 1. 锁定 PC 概率为 0
        if pc in self.locked_pcs:
            return 0.0
        
        # 2. 基础概率（基于 tier）
        tier = anchor.get("tier", "tier_6_structural")
        base_prob = TIER_BASE_PROBABILITY.get(tier, 0.1)
        
        # 3. 强因果对象加成
        causal_objs = set(anchor.get("causal_objects", []))
        if causal_objs & self.strong_objects:
            base_prob *= STRONG_CAUSAL_BOOST
        else:
            base_prob *= WEAK_CAUSAL_DECAY
        
        # 4. 保护策略调整
        base_prob *= protection_modifier
        
        # 5. 循环摘要调整
        base_prob *= loop_modifier
        
        # 6. 限制在 [0, 1]
        return min(max(base_prob, 0.0), 1.0)
    
    def select_mutator_probabilities(self, anchor: Dict, 
                                     available_mutators: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
        """调整变异算子概率，确保多样性"""
        
        # 归一化概率，避免差距过大
        total_prob = sum(p for _, p in available_mutators)
        
        if total_prob == 0:
            return available_mutators
        
        # 计算归一化后的概率
        normalized = []
        for mutator, prob in available_mutators:
            norm_prob = prob / total_prob
            
            # 限制最大概率差距（最高不超过最低的 5 倍）
            normalized.append((mutator, norm_prob))
        
        # 重新归一化
        min_prob = min(p for _, p in normalized)
        max_prob = max(p for _, p in normalized)
        
        if max_prob > min_prob * 5:
            # 压缩概率范围
            adjusted = []
            for mutator, prob in normalized:
                # 线性压缩到 [min_prob, min_prob * 5]
                new_prob = min_prob + (prob - min_prob) / (max_prob - min_prob) * (min_prob * 4)
                adjusted.append((mutator, new_prob))
            
            normalized = adjusted
        
        # 最终归一化
        total = sum(p for _, p in normalized)
        return [(m, p / total) for m, p in normalized]