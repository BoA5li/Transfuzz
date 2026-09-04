#!/usr/bin/env python3
"""
stage3_evaluator.py

Stage 3 种子评分模块。

核心观测:
  flush-reload 解析的 top1/top2 是否与 expected secret match
  (任一匹配即认为解析成功)

辅助信号 (match=0 时用于指导变异):
  expected secret 对应候选值的平均访问延迟
  延迟越短 → 越接近 cache hit → 种子越有潜力 → 变异优先级越高

Compatible with Python 3.6+.
"""

import re
import math


STAGE3_EXPECTED_LATENCY_ROUNDS = 20
STAGE3_EXPECTED_CANDIDATES = 256


# ============================================================
# 基础工具
# ============================================================

def _mean(data):
    if not data:
        return 0.0
    return sum(data) / float(len(data))


# ============================================================
# 日志解析
# ============================================================

def parse_stage3_rounds(log_lines, max_rounds=100):
    """
    解析 STAGE3_ROUND{i}_... 输出行。

    返回:
      list of dict:
        {
          "round": int,
          "expected_secret": int,
          "top1_value": int,
          "top2_value": int,
          "top1_score": int,
          "top2_score": int,
          "match": int (0 or 1),
        }
    """
    rounds = []

    for round_idx in range(max_rounds):
        prefix = "STAGE3_ROUND{}".format(round_idx)

        data = {}
        patterns = {
            "expected_secret": re.compile(
                prefix + r"_EXPECTED\s*=\s*(\d+)"),
            "top1_value": re.compile(
                prefix + r"_TOP1\s*=\s*(\d+)"),
            "top2_value": re.compile(
                prefix + r"_TOP2\s*=\s*(\d+)"),
            "top1_score": re.compile(
                prefix + r"_TOP1_SCORE\s*=\s*(-?\d+)"),
            "top2_score": re.compile(
                prefix + r"_TOP2_SCORE\s*=\s*(-?\d+)"),
            "match": re.compile(
                prefix + r"_MATCH\s*=\s*(\d+)"),
        }

        for line in log_lines:
            for key, pat in patterns.items():
                m = pat.search(line)
                if m:
                    data[key] = int(m.group(1))

        if "match" not in data and "top1_value" not in data:
            break

        data["round"] = round_idx
        rounds.append(data)

    return rounds


def extract_expected_latencies(log_lines):
    """
    从 STAGE3_DEBUG_ROUND[r]_TIME[idx] 行中提取
    expected secret 对应候选值的访问延迟。

    匹配格式:
      STAGE3_DEBUG_ROUND[0]_TIME[42]=15 EXPECTED=1 ...

    只提取 EXPECTED=1 的行（即 expected secret 对应的候选值）。

    返回:
      list of int: 每条 EXPECTED=1 记录的访问延迟
    """
    pattern = re.compile(
        r"STAGE3_DEBUG_ROUND\[\d+\]_TIME\[\d+\]=(\d+)"
        r"\s+EXPECTED=1")

    latencies = []
    for line in log_lines:
        m = pattern.search(line)
        if m:
            latencies.append(int(m.group(1)))

    return latencies


def validate_stage3_latency_dump(
        log_lines,
        expected_secret,
        expected_rounds=STAGE3_EXPECTED_LATENCY_ROUNDS,
        expected_candidates=STAGE3_EXPECTED_CANDIDATES):
    """Strictly validate the per-round timing dump used by scoring."""
    begin_pattern = re.compile(
        r"^STAGE3_DEBUG_ROUND\[(\d+)\]_TIMES_BEGIN$")
    end_pattern = re.compile(
        r"^STAGE3_DEBUG_ROUND\[(\d+)\]_TIMES_END$")
    time_pattern = re.compile(
        r"^STAGE3_DEBUG_ROUND\[(\d+)\]_TIME\[(\d+)\]=(\d+)"
        r"\s+EXPECTED=(\d+)\s+NOISE=(\d+)\s+SCORE=(-?\d+)"
        r"\s+MEASURED=(\d+)$")

    begins = []
    ends = []
    records = {}
    for line in log_lines:
        match = begin_pattern.match(line)
        if match:
            begins.append(int(match.group(1)))
            continue
        match = end_pattern.match(line)
        if match:
            ends.append(int(match.group(1)))
            continue
        match = time_pattern.match(line)
        if match:
            round_idx = int(match.group(1))
            candidate_idx = int(match.group(2))
            record = {
                "latency": int(match.group(3)),
                "expected": int(match.group(4)),
                "noise": int(match.group(5)),
                "score": int(match.group(6)),
                "measured": int(match.group(7)),
            }
            round_records = records.setdefault(round_idx, {})
            if candidate_idx in round_records:
                return [], "duplicate_latency_candidate:round={}:candidate={}".format(
                    round_idx, candidate_idx)
            round_records[candidate_idx] = record

    expected_round_indices = list(range(expected_rounds))
    if begins != expected_round_indices:
        return [], "invalid_latency_begin_rounds:{}".format(begins)
    if ends != expected_round_indices:
        return [], "invalid_latency_end_rounds:{}".format(ends)
    if sorted(records) != expected_round_indices:
        return [], "invalid_latency_record_rounds:{}".format(
            sorted(records))

    expected_candidate_indices = set(range(expected_candidates))
    expected_latencies = []
    for round_idx in expected_round_indices:
        round_records = records[round_idx]
        actual_indices = set(round_records)
        if actual_indices != expected_candidate_indices:
            missing = sorted(expected_candidate_indices - actual_indices)
            extra = sorted(actual_indices - expected_candidate_indices)
            return [], (
                "incomplete_latency_candidates:round={}:missing={}:extra={}"
                .format(round_idx, missing, extra))

        expected_flags = [
            candidate_idx for candidate_idx, record in round_records.items()
            if record["expected"] == 1
        ]
        if expected_flags != [expected_secret]:
            return [], (
                "invalid_expected_latency_marker:round={}:expected={}:marked={}"
                .format(round_idx, expected_secret, expected_flags))
        if any(record["expected"] not in (0, 1)
               for record in round_records.values()):
            return [], "invalid_expected_flag:round={}".format(round_idx)

        expected_latencies.append(
            round_records[expected_secret]["latency"])

    return expected_latencies, None


# ============================================================
# 综合评分
# ============================================================

def stage3_evaluate(log_lines, expected_secret=None,
                    expected_latency_rounds=STAGE3_EXPECTED_LATENCY_ROUNDS,
                    expected_candidate_count=STAGE3_EXPECTED_CANDIDATES):
    """
    Stage 3 综合评分。

    通过判定:
      passed = 任何一轮 match=1
      (top1 或 top2 与 expected secret 匹配即为成功)
      通过即终止检测流程

    评分 (match=0 时, 指导变异方向):
      唯一因素: expected secret 对应候选值的平均访问延迟
      延迟越短 → score 越高 → 变异优先级越高

      score = 1.0 / (1.0 + mean_latency / 100.0)

      示例:
        mean_latency =   0 → score = 1.000
        mean_latency =  50 → score = 0.667
        mean_latency = 100 → score = 0.500
        mean_latency = 200 → score = 0.333
        mean_latency = 500 → score = 0.167

      这是一个平滑的反比映射, 没有硬阈值,
      延迟越小分数越高, 自然地指导变异器优先选择
      能让 expected secret 访问延迟更低的变异方向。
    """
    rounds = parse_stage3_rounds(log_lines)

    result = {
        "score": 0.0,
        "passed": False,
        "detail": "ok",
        "num_rounds": 0,
        "match_rate": 0.0,
        "match_count": 0,
        "mean_expected_latency": 0.0,
        "round_details": [],
        "framework_error": False,
    }

    if not rounds:
        result["detail"] = "no_stage3_data"
        return result

    result["num_rounds"] = len(rounds)
    result["round_details"] = rounds

    required_round_fields = {
        "expected_secret", "top1_value", "top2_value",
        "top1_score", "top2_score", "match",
    }
    for round_data in rounds:
        missing = sorted(required_round_fields - set(round_data))
        if missing:
            result["detail"] = (
                "invalid_stage3_round_data:round={}:missing={}"
                .format(round_data["round"], missing))
            result["framework_error"] = True
            return result
        if round_data["match"] not in (0, 1):
            result["detail"] = "invalid_stage3_match_value:round={}".format(
                round_data["round"])
            result["framework_error"] = True
            return result

    if expected_secret is None:
        expected_values = set(
            r.get("expected_secret") for r in rounds
            if "expected_secret" in r)
        if len(expected_values) != 1:
            result["detail"] = "invalid_expected_secret_metadata"
            result["framework_error"] = True
            return result
        expected_secret = expected_values.pop()

    if any(r["expected_secret"] != expected_secret for r in rounds):
        result["detail"] = "stage3_expected_secret_mismatch"
        result["framework_error"] = True
        return result

    expected_latencies, latency_error = validate_stage3_latency_dump(
        log_lines,
        expected_secret=expected_secret,
        expected_rounds=expected_latency_rounds,
        expected_candidates=expected_candidate_count)
    if latency_error is not None:
        result["detail"] = "invalid_latency_data:{}".format(latency_error)
        result["framework_error"] = True
        return result

    # ============================================================
    # 检查 match
    # ============================================================
    match_count = sum(1 for r in rounds if r.get("match", 0) == 1)
    match_rate = match_count / float(len(rounds))

    result["match_count"] = match_count
    result["match_rate"] = match_rate

    # 计算 latency 信号 (两段都要用)
    mean_latency = _mean(expected_latencies)
    latency_score = 1.0 / (1.0 + mean_latency / 100.0)
    result["mean_expected_latency"] = mean_latency

    PASS_THRESHOLD = 0.5

    # 核心判定: 只要有一轮 match_rate>PASS_THRESHOLD, 直接通过
    if match_rate > PASS_THRESHOLD:
        result["score"] = 1.0
        result["passed"] = True
        result["detail"] = "match_found (rate={:.2f} > {})".format(
            match_rate, PASS_THRESHOLD)
        return result

    # ============================================================
    # 未通过: 用 match_rate + latency 共同构造连续评分
    # ------------------------------------------------------------
    # 设计目标:
    #   1) 任何"有命中"的种子分数 > 任何"零命中"的种子
    #   2) match_rate 越高分数越高 (单调引导变异向稳定命中收敛)
    #   3) 同一 match_rate 下 latency 越短分数越高 (保留原信号)
    #   4) score < 1.0, 与 passed 段严格分离
    # ------------------------------------------------------------
    # 分段:
    #   段 A: match_rate == 0       → score ∈ [0.0, 0.4)
    #         由 latency 单独引导
    #   段 B: 0 < match_rate ≤ 0.5  → score ∈ [0.4, 0.95]
    #         以 match_rate 为主, latency 做次级排序
    # ============================================================
    if match_rate == 0.0:
        # 段 A: 纯 latency 引导, 上限压到 0.4
        result["score"] = 0.4 * latency_score
    else:
        # 段 B: match_rate 主导 (0.4 ~ 0.9), latency 微调 (0 ~ 0.05)
        # match_rate=0.01 → 0.40 + ε
        # match_rate=0.50 → 0.90 + ε  (ε ≤ 0.05)
        rate_component = 0.4 + (match_rate / 0.5) * 0.5
        latency_component = 0.05 * latency_score
        result["score"] = rate_component + latency_component
        result["detail"] = "partial_match (rate={:.2f})".format(match_rate)
        
    result["passed"] = False

    return result
