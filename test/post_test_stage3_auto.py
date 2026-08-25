#!/usr/bin/env python3
import sys
import re
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        print("usage: post_test_stage3_auto.py <run_stage2.log>", file=sys.stderr)
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print("log file not found: {}".format(log_path), file=sys.stderr)
        sys.exit(1)

    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    round_expected = {}
    round_top1 = {}
    round_top2 = {}
    round_top1_score = {}
    round_top2_score = {}
    round_match = {}

    for line in lines:
        m = re.match(r"^STAGE3_ROUND(\d+)_EXPECTED=(\d+)$", line)
        if m:
            round_expected[int(m.group(1))] = int(m.group(2))
            continue

        m = re.match(r"^STAGE3_ROUND(\d+)_TOP1=(\d+)$", line)
        if m:
            round_top1[int(m.group(1))] = int(m.group(2))
            continue

        m = re.match(r"^STAGE3_ROUND(\d+)_TOP2=(\d+)$", line)
        if m:
            round_top2[int(m.group(1))] = int(m.group(2))
            continue

        m = re.match(r"^STAGE3_ROUND(\d+)_TOP1_SCORE=(-?\d+)$", line)
        if m:
            round_top1_score[int(m.group(1))] = int(m.group(2))
            continue

        m = re.match(r"^STAGE3_ROUND(\d+)_TOP2_SCORE=(-?\d+)$", line)
        if m:
            round_top2_score[int(m.group(1))] = int(m.group(2))
            continue

        m = re.match(r"^STAGE3_ROUND(\d+)_MATCH=(\d+)$", line)
        if m:
            round_match[int(m.group(1))] = int(m.group(2))
            continue

    round_ids = sorted(set(round_expected.keys()) |
                       set(round_top1.keys()) |
                       set(round_top2.keys()) |
                       set(round_top1_score.keys()) |
                       set(round_top2_score.keys()) |
                       set(round_match.keys()))

    print("=== STAGE3 EMBEDDED SUMMARY ===")

    if not round_ids:
        print("No embedded Stage3 round data found.")
        sys.exit(0)

    total_rounds = 0
    total_match = 0
    total_top1_hit = 0
    total_top2_hit = 0

    for i in round_ids:
        expected = round_expected.get(i, -1)
        top1 = round_top1.get(i, -1)
        top2 = round_top2.get(i, -1)
        top1_score = round_top1_score.get(i, 0)
        top2_score = round_top2_score.get(i, 0)
        match = round_match.get(i, -1)

        top1_hit = 1 if (expected != -1 and top1 == expected) else 0
        top2_hit = 1 if (expected != -1 and top2 == expected) else 0

        if match == 1:
            total_match += 1
        if top1_hit:
            total_top1_hit += 1
        if top2_hit:
            total_top2_hit += 1
        if match != -1:
            total_rounds += 1

        print(
            "round {}: expected={}, top1={}, top2={}, top1_score={}, top2_score={}, top1_hit={}, top2_hit={}, match={}".format(
                i, expected, top1, top2, top1_score, top2_score, top1_hit, top2_hit, match
            )
        )

    if total_rounds > 0:
        match_acc = float(total_match) / float(total_rounds)
        top1_acc = float(total_top1_hit) / float(total_rounds)
        top2_acc = float(total_top2_hit) / float(total_rounds)

        print("total_match={}".format(total_match))
        print("total_top1_hit={}".format(total_top1_hit))
        print("total_top2_hit={}".format(total_top2_hit))
        print("total_rounds={}".format(total_rounds))
        print("top1_accuracy={:.4f}".format(top1_acc))
        print("top2_accuracy={:.4f}".format(top2_acc))
        print("top1_or_top2_accuracy={:.4f}".format(match_acc))
    else:
        print("No valid match fields found.")

if __name__ == "__main__":
    main()