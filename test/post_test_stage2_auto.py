#!/usr/bin/env python3
"""
post_test_stage2_auto.py

Post-process Stage 2 output: cache hit rate analysis.
支持多轮结果和详细信号分析。

Compatible with Python 3.6+.
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stage2_evaluator import parse_stage2_rounds_checked, stage2_evaluate, \
    _compute_round_signal


def main():
    ap = argparse.ArgumentParser(
        description="Post-process Stage 2 output: cache side-channel analysis."
    )
    ap.add_argument("input", help="Input log file (Stage 2 run output)")
    ap.add_argument("--high-threshold", type=float, default=0.7,
                    help="Target hit rate threshold for PASS (default: 0.7)")
    ap.add_argument("--low-threshold", type=float, default=0.2,
                    help="Max control hit rate for PASS (default: 0.2)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Show per-round details")

    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # 解析数据
    rounds, validation_error = parse_stage2_rounds_checked(lines)

    if validation_error is not None:
        print("Invalid STAGE2_ROUND data: {}".format(validation_error))
        sys.exit(1)

    if not rounds:
        print("No STAGE2_ROUND* data found in {}".format(args.input))
        sys.exit(1)

    print("=" * 60)
    print("Stage 2 Cache Side-Channel Analysis")
    print("=" * 60)
    print("Rounds found: {}".format(len(rounds)))
    print("")

    # 逐轮分析
    all_signals = []
    for rd in rounds:
        detail = _compute_round_signal(rd)
        all_signals.append(detail)

        if args.verbose or len(rounds) <= 5:
            print("Round {}:".format(rd["round"]))
            print("  Secret: {}".format(detail["secret"]))
            print("  Target: value={}, hits={}/{}, rate={:.4f}".format(
                rd.get("target_value"),
                detail["target_hits"], detail["target_total"],
                detail["target_rate"]))
            print("  Control: value={}, hits={}/{}, rate={:.4f}".format(
                rd.get("control_value"),
                detail["control_hits"], detail["control_total"],
                detail["control_rate"]))
            print("  Signal (target-control): {:.4f}".format(detail["signal"]))
            print("")

    # 综合评估
    eval_result = stage2_evaluate(lines)

    print("-" * 40)
    print("Summary:")
    print("-" * 40)
    print("  Mean target rate:  {:.4f}".format(eval_result["mean_target_rate"]))
    print("  Mean control rate: {:.4f}".format(eval_result["mean_control_rate"]))
    print("  Mean signal:       {:.4f}".format(eval_result["mean_signal"]))
    if "median_signal" in eval_result:
        print("  Median signal:     {:.4f}".format(eval_result["median_signal"]))
    if eval_result.get("signal_std", 0) > 0:
        print("  Signal std:        {:.4f}".format(eval_result["signal_std"]))
    print("")
    print("  Score breakdown:")
    print("    Signal score:    {:.4f} (weight: 0.55)".format(
        eval_result.get("signal_score", 0)))
    print("    Target score:    {:.4f} (weight: 0.25)".format(
        eval_result.get("target_score", 0)))
    print("    Control score:   {:.4f} (weight: 0.20)".format(
        eval_result.get("control_score", 0)))
    print("  Combined score:    {:.4f}".format(eval_result["score"]))
    print("")

    # 传统阈值判定（兼容旧版）
    mean_t = eval_result["mean_target_rate"]
    mean_c = eval_result["mean_control_rate"]

    if mean_t >= args.high_threshold and mean_c <= args.low_threshold:
        print("Stage 2 (threshold): PASS "
              "(target>={:.2f} AND control<={:.2f})".format(
                  args.high_threshold, args.low_threshold))
    else:
        print("Stage 2 (threshold): FAIL "
              "(target={:.4f} vs {:.2f}, control={:.4f} vs {:.2f})".format(
                  mean_t, args.high_threshold, mean_c, args.low_threshold))

    # 信号判定
    signal_threshold = eval_result.get("min_mean_signal", 0.50)
    target_threshold = eval_result.get("min_mean_target_rate", 0.70)
    if eval_result["passed"]:
        print("Stage 2 (signal): PASS (signal={:.4f} >= {:.2f} AND "
              "target={:.4f} >= {:.2f})".format(
                  eval_result["mean_signal"], signal_threshold,
                  eval_result["mean_target_rate"], target_threshold))
    else:
        print("Stage 2 (signal): FAIL (signal={:.4f} vs {:.2f}, "
              "target={:.4f} vs {:.2f})".format(
                  eval_result["mean_signal"], signal_threshold,
                  eval_result["mean_target_rate"], target_threshold))

    sys.exit(0 if eval_result["passed"] else 2)


if __name__ == "__main__":
    main()
