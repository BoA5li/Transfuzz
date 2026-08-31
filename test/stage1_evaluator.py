#!/usr/bin/env python3
"""
stage1_evaluator.py

Stage 1 种子评分模块。
- 支持自动 period 检测（无需手动指定）
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


# ============================================================
# Period 自动检测
# ============================================================

def _autocorrelation(data, lag):
    """
    计算归一化自相关系数。
    对数据减去均值后，计算 lag 处的自相关。
    返回值范围 [-1, 1]，1 表示完美正相关。
    """
    n = len(data)
    if lag >= n or lag <= 0:
        return 0.0
    m = _mean(data)
    centered = [x - m for x in data]

    numerator = 0.0
    for i in range(n - lag):
        numerator += centered[i] * centered[i + lag]

    denominator = sum(c * c for c in centered)
    if denominator < 1e-12:
        return 0.0
    return numerator / denominator


def _detect_period_autocorrelation(data, min_period=3, max_period=None):
    """
    通过自相关分析检测周期。

    原理:
      如果数据有周期 P，那么自相关函数在 lag=P, 2P, 3P... 处会有峰值。
      扫描所有候选 lag，找到自相关系数最高的 lag 作为 period。

    参数:
      data:       一维数值序列
      min_period: 最小候选周期（默认 3，因为 period<3 无意义）
      max_period: 最大候选周期（默认 len(data)//3，确保至少 3 个完整周期）

    返回:
      (best_period, confidence)
      confidence 是最佳 period 的自相关系数，[0, 1]。
      > 0.3 通常认为有可靠周期。
    """
    n = len(data)
    if n < 6:
        return None, 0.0

    if max_period is None:
        max_period = n // 3

    max_period = min(max_period, n // 2)
    if max_period < min_period:
        return None, 0.0

    best_lag = None
    best_corr = -1.0

    for lag in range(min_period, max_period + 1):
        corr = _autocorrelation(data, lag)
        if corr > best_corr:
            best_corr = corr
            best_lag = lag

    if best_lag is None or best_corr < 0.1:
        return None, 0.0

    return best_lag, best_corr


def _detect_period_peak_spacing(data, min_period=3, max_period=None):
    """
    通过峰值间距检测周期。

    原理:
      攻击轮的 delta 通常高于训练轮。
      找出所有「高于中位数 + 阈值」的峰值位置，
      计算相邻峰值的间距，取间距的众数作为 period。

    这个方法与自相关互补——自相关对正弦型周期更敏感，
    峰值间距对脉冲型周期（训练-训练-训练-攻击-训练-训练...）更敏感。
    """
    n = len(data)
    if n < 6:
        return None, 0.0

    if max_period is None:
        max_period = n // 3

    med = _median(data)
    mad_val = _mad(data)
    # 峰值阈值: 中位数 + 1.5 * MAD（自适应）
    threshold = med + max(mad_val * 1.5, 0.5)

    peak_indices = [i for i, v in enumerate(data) if v > threshold]

    if len(peak_indices) < 2:
        return None, 0.0

    # 计算相邻峰值的间距
    spacings = []
    for i in range(1, len(peak_indices)):
        s = peak_indices[i] - peak_indices[i - 1]
        if min_period <= s <= max_period:
            spacings.append(s)

    if not spacings:
        return None, 0.0

    spacing_mode, spacing_count = _counter_most_common(spacings)
    consistency = spacing_count / float(len(spacings))

    return spacing_mode, consistency


def detect_period(brmisp_deltas, uops_transients, min_period=3, max_period=None):
    """
    综合两个数据源自动检测 period。

    策略:
      1. 分别对 BR_MISP 和 UOPS 做自相关检测
      2. 分别做峰值间距检测
      3. 如果多个方法同意某个 period，confidence 叠加
      4. 返回 confidence 最高的 period

    返回:
      (period, confidence, method_detail)
    """
    candidates = {}  # period → [(confidence, method_name)]

    # 方法 1: BR_MISP 自相关
    if brmisp_deltas and len(brmisp_deltas) >= 6:
        p, c = _detect_period_autocorrelation(brmisp_deltas, min_period, max_period)
        if p is not None and c > 0.1:
            candidates.setdefault(p, []).append((c, "brmisp_autocorr"))

    # 方法 2: UOPS 自相关
    if uops_transients and len(uops_transients) >= 6:
        p, c = _detect_period_autocorrelation(uops_transients, min_period, max_period)
        if p is not None and c > 0.1:
            candidates.setdefault(p, []).append((c, "uops_autocorr"))

    # 方法 3: BR_MISP 峰值间距
    if brmisp_deltas and len(brmisp_deltas) >= 6:
        p, c = _detect_period_peak_spacing(brmisp_deltas, min_period, max_period)
        if p is not None and c > 0.3:
            candidates.setdefault(p, []).append((c, "brmisp_peak"))

    # 方法 4: UOPS 峰值间距
    if uops_transients and len(uops_transients) >= 6:
        p, c = _detect_period_peak_spacing(uops_transients, min_period, max_period)
        if p is not None and c > 0.3:
            candidates.setdefault(p, []).append((c, "uops_peak"))

    if not candidates:
        return None, 0.0, "no_period_detected"

    # 每个候选 period 的综合 confidence:
    #   多方法一致 → 加分
    #   单方法高 confidence → 也可以
    best_period = None
    best_score = -1.0
    best_detail = ""

    for period, entries in candidates.items():
        # 基础分: 各方法 confidence 之和
        total_conf = sum(c for c, _ in entries)
        # 一致性加分: 多个方法同意同一个 period
        agreement_bonus = len(entries) * 0.15
        combined = total_conf + agreement_bonus

        methods_str = "+".join(m for _, m in entries)

        if combined > best_score:
            best_score = combined
            best_period = period
            best_detail = "period={}, methods=[{}], conf={:.3f}".format(
                period, methods_str, combined)

    # 归一化 confidence 到 [0, 1]
    # 最高可能: 4 方法 × 1.0 + 4 × 0.15 = 4.6
    normalized_conf = min(best_score / 2.0, 1.0)

    return best_period, normalized_conf, best_detail


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


def brmisp_pattern_score(deltas, period):
    """
    BR_MISP 模式匹配评分（优化版）。

    逻辑：
    1. 按 period 分组为 train/attack
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
        "period": period,
        "train_mode": None, "train_stability": 0.0,
        "baseline_value": None, "baseline_mean": None,
        "baseline_range": None,
        "noise_count": 0,
        "elevation_rate": 0.0,
        "pattern_quality": 0.0,
        "elevations": [],
    }

    if not deltas or period is None or period < 2:
        result["detail"] = "insufficient_data"
        return result

    if len(deltas) < period:
        result["detail"] = "insufficient_data"
        return result

    # ============================================================
    # Step 1: 按 period 分组
    # ============================================================
    # 约定: 每个周期的最后一轮(index % period == period-1)是 attack
    # 注意: 使用 (i+1) % period == 0 等价于 i % period == period-1
    train = [d for i, d in enumerate(deltas) if (i + 1) % period != 0]
    attack = [d for i, d in enumerate(deltas) if (i + 1) % period == 0]

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


def uops_transient_score(transients, period):
    """
    UOPS 瞬态窗口评分（优化版）。

    改进:
    - 饱和阈值自适应（基于 train 统计）
    - 通过阈值改为 speculative_uops >= 3 或 > train_MAD*3
    """
    result = {
        "score": 0.0, "passed": False, "detail": "ok",
        "period": period,
        "speculative_uops": 0, "train_median": 0, "attack_median": 0,
        "stability": 0.0, "saturation_threshold": 100,
    }

    if not transients or period is None or period < 2:
        result["detail"] = "insufficient_data"
        return result

    if len(transients) < period:
        result["detail"] = "insufficient_data"
        return result

    train_t = [t for i, t in enumerate(transients) if (i + 1) % period != 0]
    attack_t = [t for i, t in enumerate(transients) if (i + 1) % period == 0]

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


def stage1_evaluate(log_lines, period=None,
                    brmisp_weight=DEFAULT_BRMISP_WEIGHT,
                    uops_weight=DEFAULT_UOPS_WEIGHT):
    """
    Stage 1 综合评分。

    改进:
    - period=None 时自动检测
    - 返回检测到的 period 供后续使用
    """
    brmisp_deltas = parse_brmisp_deltas(log_lines)
    uops_transients = parse_uops_transient(log_lines)

    # Period 检测
    detected_period = period
    period_confidence = 1.0
    period_detail = "user_specified"

    if period is None:
        detected_period, period_confidence, period_detail = \
            detect_period(brmisp_deltas, uops_transients)

        if detected_period is None:
            # 无法检测 period，尝试常见值
            # 扫描 [3..15]，取评分最高的
            best_p = None
            best_s = -1.0
            for try_p in range(3, min(16, len(brmisp_deltas) // 2 + 1)):
                br_eval = brmisp_pattern_score(brmisp_deltas, try_p)
                if br_eval["score"] > best_s:
                    best_s = br_eval["score"]
                    best_p = try_p
            if best_p is not None:
                detected_period = best_p
                period_confidence = 0.3  # 低置信度
                period_detail = "brute_force_scan"
            else:
                detected_period = 6  # 最后兜底
                period_confidence = 0.1
                period_detail = "fallback_default"

    if brmisp_weight < 0 or uops_weight < 0:
        raise ValueError("Stage 1 score weights must be non-negative")
    total_w = brmisp_weight + uops_weight
    if total_w <= 0:
        raise ValueError("At least one Stage 1 score weight must be positive")

    # 评分
    br_eval = brmisp_pattern_score(brmisp_deltas, detected_period)
    uops_eval = uops_transient_score(uops_transients, detected_period)

    # 无效指标不贡献分数，但仍保留其权重，避免缺失指标导致剩余指标
    # 被重新归一化并获得不合理的满权重。
    brmisp_score = br_eval["score"] if br_eval["detail"] == "ok" else 0.0
    uops_score = uops_eval["score"] if uops_eval["detail"] == "ok" else 0.0
    combined_score = (brmisp_score * brmisp_weight +
                      uops_score * uops_weight) / total_w

    if period_confidence < 0.5:
        combined_score *= (0.5 + period_confidence)

    combined_passed = (
        (br_eval["detail"] == "ok" and br_eval["passed"]) and
        (uops_eval["detail"] == "ok" and uops_eval["passed"])
    )

    return {
        "score": combined_score,
        "passed": combined_passed,
        "period": detected_period,
        "period_confidence": period_confidence,
        "period_detail": period_detail,
        "brmisp": br_eval,
        "uops": uops_eval,
        "score_weights": {
            "brmisp": brmisp_weight / total_w,
            "uops": uops_weight / total_w,
        },
    }
