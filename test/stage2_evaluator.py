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


# Stage 2 accepts only a strong target-vs-control cache signal.  With the
# default 1000 trials, these thresholds require a target-control gap equivalent
# to at least 500/1000 trials and a target hit rate of at least 700/1000.
STAGE2_MIN_MEAN_SIGNAL = 0.50
STAGE2_MIN_MEAN_TARGET_RATE = 0.70
_THRESHOLD_EPSILON = 1e-12


# ============================================================
# 日志解析
# ============================================================

def parse_stage2_pmu_status(log_lines):
    """Return the explicit runtime health marker for the L1D PMU path."""
    for line in log_lines:
        if "STAGE2_PMU_STATUS=OK" in line:
            return "ok", line.strip()
        if "STAGE2_PMU_STATUS=ERROR" in line:
            return "error", line.strip()
    return "missing", "STAGE2_PMU_STATUS marker missing"

_ROUND_FIELD_RE = re.compile(
    r"STAGE2_ROUND(\d+)_(SECRET|TARGET_VALUE|TARGET_HITS|TARGET_TOTAL|"
    r"CONTROL_VALUE|CONTROL_HITS|CONTROL_TOTAL)\s*=\s*(-?\d+)")
_REQUIRED_COUNTER_FIELDS = (
    "target_hits", "target_total", "control_hits", "control_total")


def parse_stage2_rounds_checked(log_lines, max_rounds=100):
    """
    Parse and validate all Stage 2 rounds.

    Returns ``(rounds, validation_error)``.  A present round is accepted only
    when both target/control hit and total fields are present, totals are
    positive, and each hit count is in ``[0, total]``.  Round numbering must be
    contiguous from ROUND0 so a truncated middle round cannot be overlooked.
    """
    by_round = {}
    for line in log_lines:
        for match in _ROUND_FIELD_RE.finditer(line):
            round_idx = int(match.group(1))
            if round_idx >= max_rounds:
                return [], "round_{}_exceeds_max_rounds_{}".format(
                    round_idx, max_rounds)
            field = match.group(2).lower()
            by_round.setdefault(round_idx, {})[field] = int(match.group(3))

    if not by_round:
        return [], None

    round_indices = sorted(by_round)
    expected_indices = list(range(round_indices[-1] + 1))
    if round_indices != expected_indices:
        return [], "non_contiguous_round_indices: {}".format(round_indices)

    rounds = []
    for round_idx in round_indices:
        data = by_round[round_idx]
        missing = [
            field for field in _REQUIRED_COUNTER_FIELDS if field not in data]
        if missing:
            return [], "round_{}_missing_fields: {}".format(
                round_idx, ",".join(missing))

        for group in ("target", "control"):
            hits = data["{}_hits".format(group)]
            total = data["{}_total".format(group)]
            if total <= 0:
                return [], "round_{}_{}_total_must_be_positive: {}".format(
                    round_idx, group, total)
            if hits < 0 or hits > total:
                return [], "round_{}_{}_hits_out_of_range: {}/{}".format(
                    round_idx, group, hits, total)

        data["round"] = round_idx
        rounds.append(data)

    return rounds, None


def parse_stage2_rounds(log_lines, max_rounds=100):
    """Backward-compatible parser; invalid input returns no usable rounds."""
    rounds, _ = parse_stage2_rounds_checked(log_lines, max_rounds=max_rounds)

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
      passed = (mean_signal >= 0.50) AND (mean_target_rate >= 0.70)

    注: consistency 维度已移除。当前 driver 只运行单轮（ROUND0），
        多轮一致性没有区分度。如果后续 driver 支持多轮，
        可以重新加入。
    """
    pmu_status, pmu_status_detail = parse_stage2_pmu_status(log_lines)
    rounds, round_validation_error = parse_stage2_rounds_checked(log_lines)

    result = {
        "score": 0.0,
        "passed": False,
        "detail": "ok",
        "num_rounds": 0,
        "mean_signal": 0.0,
        "mean_target_rate": 0.0,
        "mean_control_rate": 0.0,
        "round_details": [],
        "pmu_status": pmu_status,
        "pmu_status_detail": pmu_status_detail,
        "round_validation_error": round_validation_error,
    }

    if pmu_status != "ok":
        result["detail"] = "pmu_{}".format(pmu_status)
        return result

    if round_validation_error is not None:
        result["detail"] = "invalid_stage2_data"
        return result

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
    passed = (
        mean_signal + _THRESHOLD_EPSILON >= STAGE2_MIN_MEAN_SIGNAL and
        mean_target + _THRESHOLD_EPSILON >= STAGE2_MIN_MEAN_TARGET_RATE
    )

    result.update({
        "score": score,
        "passed": passed,
        "mean_signal": mean_signal,
        "mean_target_rate": mean_target,
        "mean_control_rate": mean_control,
        "signal_score": signal_score,
        "target_score": target_score,
        "control_score": control_score,
        "min_mean_signal": STAGE2_MIN_MEAN_SIGNAL,
        "min_mean_target_rate": STAGE2_MIN_MEAN_TARGET_RATE,
    })

    return result
