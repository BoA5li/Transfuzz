#!/usr/bin/env python3
"""
post_test_stage_auto.py

Post-process Stage1 output: BR_MISP + UOPS analysis.
支持自动 period 检测。
Compatible with Python 3.6+.
"""

import sys
import os

# 确保能导入 stage1_evaluator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stage1_evaluator import (
    parse_brmisp_deltas, parse_uops_transient,
    detect_period, brmisp_pattern_score, uops_transient_score,
    _mean, _median
)


def main():
    import argparse

    ap = argparse.ArgumentParser(
        description="Post-process Stage1 output: BR_MISP + UOPS analysis."
    )
    ap.add_argument("-p", "--period", type=int, default=None,
                    help="Train/attack period. "
                         "If not specified, auto-detected.")
    ap.add_argument("input", nargs="?", default="-",
                    help="Input file (default: stdin)")
    args = ap.parse_args()

    if args.input == "-" or args.input == "/dev/stdin":
        lines = sys.stdin.readlines()
    else:
        with open(args.input, "r") as f:
            lines = f.readlines()

    # 解析数据
    brmisp_deltas = parse_brmisp_deltas(lines)
    uops_transients = parse_uops_transient(lines)

    # Period 检测
    period = args.period
    if period is None:
        detected, confidence, detail = detect_period(
            brmisp_deltas, uops_transients)
        if detected is not None:
            period = detected
            print("=" * 50)
            print("Period Auto-Detection")
            print("=" * 50)
            print("Detected period: {}".format(period))
            print("Confidence: {:.3f}".format(confidence))
            print("Method: {}".format(detail))
            print("")
        else:
            # 暴力扫描
            best_p = None
            best_s = -1.0
            for try_p in range(3, min(16, len(brmisp_deltas) // 2 + 1)):
                br_eval = brmisp_pattern_score(brmisp_deltas, try_p)
                if br_eval["score"] > best_s:
                    best_s = br_eval["score"]
                    best_p = try_p
            if best_p is not None:
                period = best_p
                print("=" * 50)
                print("Period Auto-Detection (brute-force scan)")
                print("=" * 50)
                print("Best period: {} (score={:.4f})".format(period, best_s))
                print("")
            else:
                period = 6
                print("Period detection failed, using default: {}".format(
                    period))
    else:
        print("Using user-specified period: {}".format(period))
        print("")

    # === BR_MISP 分析 ===
    if brmisp_deltas:
        br_result = brmisp_pattern_score(brmisp_deltas, period)

        train = [d for i, d in enumerate(brmisp_deltas)
                 if (i + 1) % period != 0]
        attack = [d for i, d in enumerate(brmisp_deltas)
                  if (i + 1) % period == 0]

        print("=" * 50)
        print("BR_MISP_RETIRED.CONDITIONAL Analysis")
        print("=" * 50)
        print("Period: {}".format(period))
        print("Total samples: {}".format(len(brmisp_deltas)))
        print("Train samples: {}".format(len(train)))
        if train:
            print("Train mean: {:.3f}".format(_mean(train)))
        print("Attack samples: {}".format(len(attack)))
        if attack:
            print("Attack mean: {:.3f}".format(_mean(attack)))

        print("")
        print("Pattern Analysis:")
        print("  Baseline value: {}".format(br_result.get("baseline_value")))
        print("  Baseline range: {}".format(br_result.get("baseline_range")))
        print("  Noise samples removed: {}".format(
            br_result.get("noise_count", 0)))
        print("  Train stability: {:.3f}".format(
            br_result.get("train_stability", 0)))
        print("  Attack elevation rate: {:.3f}".format(
            br_result.get("elevation_rate", 0)))
        print("  Elevation mode: +{}".format(
            br_result.get("elev_mode", 0)))
        print("  Elevation consistency: {:.3f}".format(
            br_result.get("elev_consistency", 0)))
        print("  Score: {:.4f}".format(br_result.get("score", 0)))
        print("  Passed: {}".format(br_result.get("passed", False)))
    else:
        print("No BR_MISP data found.")

    # === UOPS 分析 ===
    if uops_transients:
        uops_result = uops_transient_score(uops_transients, period)

        train_u = [t for i, t in enumerate(uops_transients)
                   if (i + 1) % period != 0]
        attack_u = [t for i, t in enumerate(uops_transients)
                    if (i + 1) % period == 0]

        print("")
        print("=" * 50)
        print("UOPS Transient Window Analysis")
        print("=" * 50)
        print("Period: {}".format(period))
        print("Total samples: {}".format(len(uops_transients)))
        print("Train samples: {}".format(len(train_u)))
        if train_u:
            print("Train mean transient: {:.3f}".format(_mean(train_u)))
        print("Attack samples: {}".format(len(attack_u)))
        if attack_u:
            print("Attack mean transient: {:.3f}".format(_mean(attack_u)))

        print("")
        print("Transient Window Analysis:")
        print("  Train median: {}".format(uops_result.get("train_median")))
        print("  Attack median: {}".format(uops_result.get("attack_median")))
        print("  Speculative uops: {}".format(
            uops_result.get("speculative_uops")))
        print("  Saturation threshold: {}".format(
            uops_result.get("saturation_threshold")))
        print("  Stability: {:.3f}".format(
            uops_result.get("stability", 0)))
        print("  Score: {:.4f}".format(uops_result.get("score", 0)))
        print("  Passed: {}".format(uops_result.get("passed", False)))

        if uops_result.get("speculative_uops", 0) > 0:
            print("  -> Speculative execution detected")
        else:
            print("  -> No speculative execution signal")
    else:
        print("")
        print("No UOPS_TRANSIENT data found.")


if __name__ == "__main__":
    main()