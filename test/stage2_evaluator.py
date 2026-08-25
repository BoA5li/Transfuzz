#!/usr/bin/env python3
"""
stage2_evaluator.py

Stage 2 种子评分模块。
核心指标: target_rate - control_rate (cache line 命中差值)
差值越大，说明瞬态指令越成功地将目标数据加载到缓存中。

Compatible with Python 3.6+.
"""

import re
import math


# ============================================================
# 日志解析
# ============================================================

def parse_stage2_rounds(log_lines, max_rounds=100):
    """
    从日志行解析所有 STAGE2_ROUND{i}_... 数据。

    返回:
      list of dict, 每个 dict 包含一轮的数据:
        {
          "round": int,
          "secret": int,
          "target_value": int,
          "target_hits": int,
          "target_total": int,
          "control_value": int,
          "control_hits": int,
          "control_total": int,
        }
    """
    rounds = []

    for round_idx in range(max_rounds):
        prefix = "STAGE2_ROUND{}".format(round_idx)

        data = {}
        patterns = {
            "secret":        re.compile(prefix + r"_SECRET\s*=\s*(\d+)"),
            "target_value":  re.compile(prefix + r"_TARGET_VALUE\s*=\s*(\d+)"),
            "target_hits":   re.compile(prefix + r"_TARGET_HITS\s*=\s*(\d+)"),
            "target_total":  re.compile(prefix + r"_TARGET_TOTAL\s*=\s*(\d+)"),
            "control_value": re.compile(prefix + r"_CONTROL_VALUE\s*=\s*(\d+)"),
            "control_hits":  re.compile(prefix + r"_CONTROL_HITS\s*=\s*(\d+)"),
            "control_total": re.compile(prefix + r"_CONTROL_TOTAL\s*=\s*(\d+)"),
        }

        for line in log_lines:
            for key, pat in patterns.items():
                m = pat.search(line)
                if m:
                    data[key] = int(m.group(1))

        # 至少需要 target_total 才算有效轮
        if "target_total" not in data:
            break

        data["round"] = round_idx
        rounds.append(data)

    return rounds


# ============================================================
# 单轮评分
# ============================================================

def _compute_round_signal(round_data):
    """
    计算单轮的 signal = target_rate - control_rate。

    返回:
      {
        "target_rate": float,
        "control_rate": float,
        "signal": float,          # target_rate - control_rate
        "target_hits": int,
        "target_total": int,
        "control_hits": int,
        "control_total": int,
        "secret": int or None,
      }
    """
    t_hits = round_data.get("target_hits", 0)
    t_total = round_data.get("target_total", 0)
    c_hits = round_data.get("control_hits", 0)
    c_total = round_data.get("control_total", 0)

    t_rate = t_hits / float(t_total) if t_total > 0 else 0.0
    c_rate = c_hits / float(c_total) if c_total > 0 else 0.0

    signal = t_rate - c_rate

    return {
        "target_rate": t_rate,
        "control_rate": c_rate,
        "signal": signal,
        "target_hits": t_hits,
        "target_total": t_total,
        "control_hits": c_hits,
        "control_total": c_total,
        "secret": round_data.get("secret"),
    }


# ============================================================
# 综合评分
# ============================================================

def _mean(data):
    if not data:
        return 0.0
    return sum(data) / float(len(data))


def _median(data):
    if not data:
        return 0.0
    s = sorted(data)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def _std(data):
    if len(data) < 2:
        return 0.0
    m = _mean(data)
    return math.sqrt(sum((x - m) ** 2 for x in data) / float(len(data)))


def stage2_evaluate(log_lines):
    """
    Stage 2 种子评分（优化版）。

    核心指标: mean_signal = mean(target_rate) - mean(control_rate)

    评分维度:
    1. signal_strength: mean_signal 的大小（主导）
    2. target_quality:  mean(target_rate) 本身
    3. control_quality: mean(control_rate) 越低越好

    评分公式:
      score = signal_score * 0.55 +
              target_score * 0.25 +
              control_score * 0.20

    通过判定:
      passed = (mean_signal >= 0.05) AND (mean_target_rate >= 0.02)

    注: consistency 维度已移除。当前 driver 只运行单轮（ROUND0），
        多轮一致性没有区分度。如果后续 driver 支持多轮，
        可以重新加入。
    """
    rounds = parse_stage2_rounds(log_lines)

    result = {
        "score": 0.0,
        "passed": False,
        "detail": "ok",
        "num_rounds": 0,
        "mean_signal": 0.0,
        "mean_target_rate": 0.0,
        "mean_control_rate": 0.0,
        "round_details": [],
    }

    if not rounds:
        result["detail"] = "no_stage2_data"
        return result

    # 计算每轮信号
    round_details = []
    signals = []
    target_rates = []
    control_rates = []

    for rd in rounds:
        detail = _compute_round_signal(rd)
        round_details.append(detail)
        signals.append(detail["signal"])
        target_rates.append(detail["target_rate"])
        control_rates.append(detail["control_rate"])

    result["round_details"] = round_details
    result["num_rounds"] = len(rounds)

    # ============================================================
    # 所有维度统一使用 mean
    # ============================================================
    mean_signal = _mean(signals)
    mean_target = _mean(target_rates)
    mean_control = _mean(control_rates)

    # === 维度 1: Signal Strength ===
    # 非线性映射，弱信号也能获得分数以指导变异方向
    if mean_signal <= 0:
        signal_score = 0.0
    elif mean_signal <= 0.1:
        # 微弱信号: 0-0.1 → 0-0.3
        signal_score = mean_signal / 0.1 * 0.3
    elif mean_signal <= 0.3:
        # 中等信号: 0.1-0.3 → 0.3-0.7
        signal_score = 0.3 + (mean_signal - 0.1) / 0.2 * 0.4
    elif mean_signal <= 0.6:
        # 强信号: 0.3-0.6 → 0.7-0.9
        signal_score = 0.7 + (mean_signal - 0.3) / 0.3 * 0.2
    else:
        # 极强信号: >0.6 → 0.9-1.0
        signal_score = min(0.9 + (mean_signal - 0.6) / 0.4 * 0.1, 1.0)

    # === 维度 2: Target Quality ===
    target_score = min(mean_target, 1.0)

    # === 维度 3: Control Quality ===
    # control_rate 越低越好: 0 → 1.0, 0.5 → 0.0
    control_score = max(0.0, 1.0 - mean_control * 2.0)

    # === 综合评分 ===
    score = (
        signal_score * 0.55 +
        target_score * 0.25 +
        control_score * 0.20
    )

    # === 通过判定（统一使用 mean） ===
    passed = (mean_signal >= 0.05) and (mean_target >= 0.02)

    result.update({
        "score": score,
        "passed": passed,
        "mean_signal": mean_signal,
        "mean_target_rate": mean_target,
        "mean_control_rate": mean_control,
        "signal_score": signal_score,
        "target_score": target_score,
        "control_score": control_score,
    })

    return result