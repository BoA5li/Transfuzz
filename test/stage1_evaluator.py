#!/usr/bin/env python3
"""
stage1_evaluator.py

Stage 1 种子评分模块。
- 使用目标程序提供的逐样本 TRAIN/DETECT 运行时标签
- BR_MISP baseline 使用阈值范围去噪
- UOPS 阈值自适应
Compatible with Python 3.6+.
"""

import re
import math


# ============================================================
# 基础工具
# ============================================================

def _mean(data):
    if not data:
        return 0.0
    return sum(data) / float(len(data))


def _median(data):
    if not data:
        return 0
    s = sorted(data)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    else:
        return (s[n // 2 - 1] + s[n // 2]) / 2.0


def _std(data):
    """标准差"""
    if len(data) < 2:
        return 0.0
    m = _mean(data)
    variance = sum((x - m) ** 2 for x in data) / float(len(data))
    return math.sqrt(variance)


def _mad(data):
    """Median Absolute Deviation"""
    if not data:
        return 0
    med = _median(data)
    deviations = sorted([abs(d - med) for d in data])
    return deviations[len(deviations) // 2]


def _remove_outliers_mad(data, factor=5):
    """基于 MAD 去除异常值"""
    if len(data) < 3:
        return list(data)
    med = _median(data)
    mad_val = _mad(data)
    threshold = factor * max(mad_val, 1)
    return [d for d in data if abs(d - med) <= threshold]


def _counter_most_common(data):
    """众数计算"""
    counts = {}
    for d in data:
        counts[d] = counts.get(d, 0) + 1
    if not counts:
        return 0, 0
    most = max(counts.items(), key=lambda x: x[1])
    return most[0], most[1]


# ============================================================
# 日志解析
# ============================================================

def parse_brmisp_deltas(log_lines):
    """从日志行解析 BR_MISP delta 数组"""
    pattern = re.compile(r"STAGE1_DELTA_BR_MISP_COND\[(\d+)\]\s*=\s*(\d+)")
    vals = {}
    for line in log_lines:
        m = pattern.search(line)
        if m:
            vals[int(m.group(1))] = int(m.group(2))
    if not vals:
        return []
    return [vals.get(i, 0) for i in range(max(vals.keys()) + 1)]


def parse_uops_transient(log_lines):
    """从日志行解析 UOPS transient 数组"""
    pattern = re.compile(r"UOPS_TRANSIENT\[(\d+)\]\s*=\s*(-?\d+)")
    vals = {}
    for line in log_lines:
        m = pattern.search(line)
        if m:
            vals[int(m.group(1))] = int(m.group(2))
    if not vals:
        return []
    return [vals.get(i, 0) for i in range(max(vals.keys()) + 1)]


def parse_uops_pmu_status(log_lines):
    """Return the explicit UOPS PMU runtime status marker, if present."""
    for line in log_lines:
        if "UOPS_PMU_STATUS=OK" in line:
            return "ok", line.strip()
        if "UOPS_PMU_STATUS=ERROR" in line:
            return "error", line.strip()
    return "missing", "UOPS_PMU_STATUS marker missing"


def parse_stage1_phases(log_lines):
    """Parse the explicit runtime phase associated with every PMU sample."""
    pattern = re.compile(r"STAGE1_PHASE\[(\d+)\]\s*=\s*(\S+)")
    vals = {}
    for line in log_lines:
        match = pattern.search(line)
        if match:
            vals[int(match.group(1))] = match.group(2).upper()
    if not vals:
        return []
    return [vals.get(i, "MISSING") for i in range(max(vals.keys()) + 1)]


# ============================================================
# BR_MISP 评分 (优化: 阈值范围 baseline)
# ============================================================

def _compute_baseline_range(train_data, tolerance_factor=1.5):
    """
    计算训练轮的 baseline 范围。

    不是简单取众数，而是:
    1. 取众数 mode
    2. 计算 MAD
    3. baseline 范围 = [mode - tolerance, mode + tolerance]
       其中 tolerance = tolerance_factor * max(MAD, 0.5)
    4. 落在范围内的数据都被视为「正常 baseline」
    5. 范围外的数据被视为噪声，不参与 baseline 计算

    返回:
      (baseline_value, baseline_low, baseline_high, clean_train, noise_count)
    """
    if not train_data:
        return 0, 0, 0, [], 0

    mode, mode_count = _counter_most_common(train_data)
    mad_val = _mad(train_data)

    tolerance = tolerance_factor * max(mad_val, 0.5)
    baseline_low = mode - tolerance
    baseline_high = mode + tolerance

    clean = [d for d in train_data if baseline_low <= d <= baseline_high]
    noise_count = len(train_data) - len(clean)

    # baseline_value 取 clean 数据的中位数（比众数更稳定）
    if clean:
        baseline_value = _median(clean)
    else:
        baseline_value = mode

    return baseline_value, baseline_low, baseline_high, clean, noise_count


def brmisp_pattern_score(deltas, phases):
    """
    BR_MISP 模式匹配评分（优化版）。

    逻辑：
    1. 按逐样本运行时标签分组为 train/detect
    2. 对 train 数据做阈值范围去噪，计算 baseline_mean
    3. 每轮攻击的抬升幅度 = attack_delta - baseline_mean
    4. 抬升幅度落在 [elev_low, elev_high] 范围内才算"有效抬升"
       （理论上多一次误预测 → 抬升≈1，考虑噪声给 [0.85, 1.15]）
    5. elevation_rate = 有效抬升轮数 / 总攻击轮数
    6. 评分以 elevation_rate 为主导

    评分公式:
      score = elevation_rate * 0.60 +
              train_stability * 0.25 +
              pattern_quality * 0.15

    通过条件:
      elevation_rate >= 0.70 AND train_stability >= 0.50
    """
    result = {
        "score": 0.0, "passed": False, "detail": "ok",
        "phase_source": "runtime_labels",
        "train_count": 0, "detect_count": 0,
        "train_mode": None, "train_stability": 0.0,
        "baseline_value": None, "baseline_mean": None,
        "baseline_range": None,
        "noise_count": 0,
        "elevation_rate": 0.0,
        "pattern_quality": 0.0,
        "elevations": [],
    }

    if not deltas or not phases or len(deltas) != len(phases):
        result["detail"] = "insufficient_data"
        return result

    # ============================================================
    # Step 1: 按目标程序在运行时提供的真实相位标签分组
    # ============================================================
    train = [d for d, phase in zip(deltas, phases) if phase == "TRAIN"]
    attack = [d for d, phase in zip(deltas, phases) if phase == "DETECT"]

    result["train_count"] = len(train)
    result["detect_count"] = len(attack)

    if not train or not attack:
        result["detail"] = "empty_group"
        return result

    # ============================================================
    # Step 2: Train baseline 去噪
    # ============================================================
    # 取众数作为参考点，用 MAD 确定正常范围
    baseline_value, bl_low, bl_high, clean_train, noise_count = \
        _compute_baseline_range(train, tolerance_factor=1.5)

    # baseline_mean: 去噪后训练数据的平均值
    if clean_train:
        baseline_mean = _mean(clean_train)
    else:
        baseline_mean = float(baseline_value)

    train_mode, train_mode_count = _counter_most_common(train)

    # stability: 去噪后数据占总训练数据的比例
    train_stability = len(clean_train) / float(len(train)) if clean_train else 0.0

    # ============================================================
    # Step 3: 逐轮抬升检测
    # ============================================================
    # 理论上攻击比训练多一次误预测 → 抬升幅度 ≈ 1
    # 考虑噪声和平均数偏差，合理范围 [0.85, 1.15]
    ELEV_LOW = 0.85
    ELEV_HIGH = 1.15
    # 最低抬升阈值：attack_delta - baseline_mean > ELEV_LOW 才算有抬升
    ELEV_MIN_THRESHOLD = ELEV_LOW

    elevations = []        # 每轮攻击的抬升幅度
    valid_elevations = []  # 落在合理范围内的抬升

    for a_val in attack:
        elev = a_val - baseline_mean
        elevations.append(elev)

        if elev >= ELEV_MIN_THRESHOLD:
            valid_elevations.append(elev)

    # elevation_rate: 有效抬升（>= 0.85）的比例
    elevation_rate = len(valid_elevations) / float(len(attack))

    # ============================================================
    # Step 4: 模式质量 (pattern_quality)
    # ============================================================
    # 衡量有效抬升中，落在理想范围 [0.85, 1.15] 内的比例
    # 这个比例越高，说明抬升模式越接近理论预期（恰好多一次误预测）
    # 过大的抬升（> 1.15）可能是噪声引入的多次误预测
    if valid_elevations:
        ideal_count = sum(1 for e in valid_elevations
                          if ELEV_LOW <= e <= ELEV_HIGH)
        pattern_quality = ideal_count / float(len(valid_elevations))
    else:
        pattern_quality = 0.0

    # ============================================================
    # Step 5: 评分
    # ============================================================
    score = (
        elevation_rate * 0.60 +
        train_stability * 0.25 +
        pattern_quality * 0.15
    )

    # ============================================================
    # Step 6: 通过判定
    # ============================================================
    passed = (
        elevation_rate >= 0.70 and
        train_stability >= 0.50
    )

    result.update({
        "score": score,
        "passed": passed,
        "train_mode": train_mode,
        "train_stability": train_stability,
        "baseline_value": baseline_value,
        "baseline_mean": baseline_mean,
        "baseline_range": (bl_low, bl_high),
        "noise_count": noise_count,
        "elevation_rate": elevation_rate,
        "pattern_quality": pattern_quality,
        "elevations": elevations,
    })
    return result


# ============================================================
# UOPS 评分 (优化: 阈值自适应)
# ============================================================

def _estimate_uops_saturation(train_transients):
    """
    估计 UOPS transient 的饱和阈值。

    原理:
      正常的推测窗口 uops 取决于:
      - gadget 代码量（通常 5-30 条指令 → 10-80 uops）
      - 推测窗口长度（与缓存 miss 延迟相关，通常 100-200 cycles）
      - 流水线宽度（Cascade Lake 4-wide → 每 cycle 可发射 4 uops）

      合理的 speculative_uops 上限 ≈ 窗口长度 × 发射宽度 ÷ 2
      ≈ 150 × 4 ÷ 2 = 300（极端情况）

      但实际中，由于 gadget 有数据依赖，实际执行 uops 通常远低于此。
      用 train_transients 的统计特征来估计合理范围:
        saturation = train_median + 6 × train_MAD
      如果 train 本身波动大，saturation 相应提高。
    """
    if not train_transients:
        return 100  # 默认值

    med = _median(train_transients)
    mad_val = _mad(train_transients)

    # 饱和点: train 中位数的 3 倍，或 train + 6*MAD，取较大值
    # 但不低于 80，不高于 500
    saturation = max(
        med * 3,
        med + 6 * max(mad_val, 5),
        80
    )
    return min(saturation, 500)


def uops_transient_score(transients, phases):
    """
    UOPS 瞬态窗口评分（优化版）。

    改进:
    - 饱和阈值自适应（基于 train 统计）
    - 通过阈值改为 speculative_uops >= 3 或 > train_MAD*3
    """
    result = {
        "score": 0.0, "passed": False, "detail": "ok",
        "phase_source": "runtime_labels",
        "train_count": 0, "detect_count": 0,
        "speculative_uops": 0, "train_median": 0, "attack_median": 0,
        "stability": 0.0, "saturation_threshold": 100,
    }

    if not transients or not phases or len(transients) != len(phases):
        result["detail"] = "insufficient_data"
        return result

    train_t = [t for t, phase in zip(transients, phases)
               if phase == "TRAIN"]
    attack_t = [t for t, phase in zip(transients, phases)
                if phase == "DETECT"]
    result["train_count"] = len(train_t)
    result["detect_count"] = len(attack_t)

    if not train_t or not attack_t:
        result["detail"] = "empty_group"
        return result

    train_clean = _remove_outliers_mad(train_t, factor=4)
    attack_clean = _remove_outliers_mad(attack_t, factor=4)
    if not train_clean:
        train_clean = train_t
    if not attack_clean:
        attack_clean = attack_t

    train_med = _median(train_clean)
    attack_med = _median(attack_clean)
    speculative_uops = attack_med - train_med

    # 自适应饱和阈值
    saturation = _estimate_uops_saturation(train_clean)

    # 评分
    if speculative_uops <= 0:
        uops_score = 0.0
    elif speculative_uops <= saturation:
        uops_score = speculative_uops / float(saturation)
    else:
        # 超过饱和点缓慢衰减
        uops_score = max(0.0, 1.0 - (speculative_uops - saturation) / (saturation * 3.0))

    # 稳定性
    if len(attack_clean) > 1:
        attack_mean = _mean(attack_clean)
        attack_std_val = _std(attack_clean)
        stability = max(0.0, 1.0 - attack_std_val / max(abs(attack_mean), 1))
    else:
        stability = 0.5

    score = uops_score * 0.7 + stability * 0.3

    # 通过判定: speculative_uops 超过噪声水平
    train_mad = _mad(train_clean)
    noise_threshold = max(3, train_mad * 3)
    passed = speculative_uops >= noise_threshold

    result.update({
        "score": score,
        "passed": passed,
        "speculative_uops": speculative_uops,
        "train_median": train_med,
        "attack_median": attack_med,
        "stability": stability,
        "saturation_threshold": saturation,
    })
    return result


# ============================================================
# 综合评分
# ============================================================

DEFAULT_BRMISP_WEIGHT = 0.8
DEFAULT_UOPS_WEIGHT = 0.2


def stage1_evaluate(log_lines,
                    brmisp_weight=DEFAULT_BRMISP_WEIGHT,
                    uops_weight=DEFAULT_UOPS_WEIGHT):
    """
    Stage 1 综合评分。

    TRAIN/DETECT membership comes exclusively from explicit runtime labels.
    No manual period or PMU-signal heuristic is used.
    """
    brmisp_deltas = parse_brmisp_deltas(log_lines)
    uops_transients = parse_uops_transient(log_lines)
    phases = parse_stage1_phases(log_lines)

    phase_detail = "ok"
    valid_phases = {"TRAIN", "DETECT"}
    if not phases:
        phase_detail = "phase_contract_missing"
    elif any(phase not in valid_phases for phase in phases):
        phase_detail = "phase_contract_invalid"
    elif len(phases) != len(brmisp_deltas):
        phase_detail = "brmisp_phase_count_mismatch"
    elif len(phases) != len(uops_transients):
        phase_detail = "uops_phase_count_mismatch"

    if brmisp_weight < 0 or uops_weight < 0:
        raise ValueError("Stage 1 score weights must be non-negative")
    total_w = brmisp_weight + uops_weight
    if total_w <= 0:
        raise ValueError("At least one Stage 1 score weight must be positive")

    # 评分
    scoring_phases = phases if phase_detail == "ok" else []
    br_eval = brmisp_pattern_score(brmisp_deltas, scoring_phases)
    uops_eval = uops_transient_score(uops_transients, scoring_phases)

    # 无效指标不贡献分数，但仍保留其权重，避免缺失指标导致剩余指标
    # 被重新归一化并获得不合理的满权重。
    brmisp_score = br_eval["score"] if br_eval["detail"] == "ok" else 0.0
    uops_score = uops_eval["score"] if uops_eval["detail"] == "ok" else 0.0
    combined_score = (brmisp_score * brmisp_weight +
                      uops_score * uops_weight) / total_w

    combined_passed = (
        phase_detail == "ok" and
        (br_eval["detail"] == "ok" and br_eval["passed"]) and
        (uops_eval["detail"] == "ok" and uops_eval["passed"])
    )

    return {
        "score": combined_score,
        "passed": combined_passed,
        "phase_contract": phase_detail,
        "phase_source": "runtime_labels",
        "train_count": phases.count("TRAIN"),
        "detect_count": phases.count("DETECT"),
        "brmisp": br_eval,
        "uops": uops_eval,
        "score_weights": {
            "brmisp": brmisp_weight / total_w,
            "uops": uops_weight / total_w,
        },
    }
