#!/usr/bin/env python3
"""Post-process Stage 1 output using explicit runtime phase labels."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stage1_evaluator import stage1_evaluate


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Post-process Stage 1 output using STAGE1_PHASE labels; no "
            "manual or inferred period is accepted."))
    parser.add_argument("input", nargs="?", default="-",
                        help="Input file (default: stdin)")
    args = parser.parse_args()

    if args.input in ("-", "/dev/stdin"):
        lines = sys.stdin.readlines()
    else:
        with open(args.input, "r") as source:
            lines = source.readlines()

    result = stage1_evaluate(lines)
    brmisp = result["brmisp"]
    uops = result["uops"]

    print("=" * 50)
    print("Stage 1 Runtime-Phase Analysis")
    print("=" * 50)
    print("Phase source: {}".format(result["phase_source"]))
    print("Phase contract: {}".format(result["phase_contract"]))
    print("Training samples: {}".format(result["train_count"]))
    print("Detection samples: {}".format(result["detect_count"]))
    print("")
    print("Selected PMU metric:")
    print("  Detail: {}".format(brmisp.get("detail")))
    print("  Train stability: {:.3f}".format(
        brmisp.get("train_stability", 0)))
    print("  Detection elevation rate: {:.3f}".format(
        brmisp.get("elevation_rate", 0)))
    print("  Score: {:.4f}".format(brmisp.get("score", 0)))
    print("  Passed: {}".format(brmisp.get("passed", False)))
    print("")
    print("UOPS metric:")
    print("  Detail: {}".format(uops.get("detail")))
    print("  Speculative uops: {}".format(uops.get("speculative_uops", 0)))
    print("  Stability: {:.3f}".format(uops.get("stability", 0)))
    print("  Score: {:.4f}".format(uops.get("score", 0)))
    print("  Passed: {}".format(uops.get("passed", False)))
    print("")
    print("Combined score: {:.4f}".format(result["score"]))
    print("Combined passed: {}".format(result["passed"]))

    return 0 if result["phase_contract"] == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
