# -*- coding: utf-8 -*-
import subprocess
import statistics
from typing import List, Dict, Tuple

# 核心 PMU 事件集
PMU_EVENTS = [
    "branches",
    "branch-misses",
    "br_inst_retired.all_branches",
    "br_misp_retired.all_branches",
    "machine_clears.count",
    "mem_inst_retired.all_loads",
    "mem_inst_retired.all_stores",
]

# 单一测试程序：通过参数选择阶段
BINARY = "./spectre_stage"

# 定义三个阶段及其命令行参数
STAGES = {
    "stage1": "1",   # mis-train + trigger
    "stage2": "2",   # gadget
    "stage3": "3",   # probe only
    "full":   "4",   # 原来的完整攻击
}


def run_perf(binary: str, args: List[str], events: List[str]) -> Dict[str, int]:
    """
    对指定二进制执行一次 perf stat，返回 {event_name: count}
    args: 传给 binary 的额外参数，比如 ["1"] 表示 stage1
    """
    events_str = ",".join(events)
    cmd = [
        "perf", "stat",
        "-x", ",",           # CSV 输出
        "-e", events_str,
        binary,
    ] + args

    print("Running:", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    out, err = proc.communicate()

    if proc.returncode != 0:
        print("Program output:", out)
        print("perf error output:", err)
        raise RuntimeError(f"perf stat failed with code {proc.returncode}")

    results: Dict[str, int] = {}
    for line in err.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        count_str, _unit, event_name = parts[:3]
        event_name = event_name.strip()

        if event_name not in events:
            continue

        try:
            count = int(count_str)
        except ValueError:
            count = 0
        results[event_name] = count

    return results


def run_experiments_stage(
    stage_name: str,
    events: List[str],
    repeats: int = 5
) -> List[Dict[str, int]]:
    """
    对指定 stage（例如 "stage1"）重复跑 repeats 次 perf stat。
    """
    if stage_name not in STAGES:
        raise ValueError(f"Unknown stage {stage_name}")

    stage_arg = STAGES[stage_name]
    results = []
    for i in range(repeats):
        print(f"Run {i+1}/{repeats} for {BINARY} stage={stage_name} (arg={stage_arg})")
        res = run_perf(BINARY, [stage_arg], events)
        results.append(res)
    return results


def summarize(results: List[Dict[str, int]], events: List[str]) -> Dict[str, Dict[str, float]]:
    """
    { event_name: { 'mean': x, 'stdev': y } }
    """
    summary: Dict[str, Dict[str, float]] = {}
    for ev in events:
        values = [r.get(ev, 0) for r in results]
        mean = statistics.mean(values) if values else 0.0
        stdev = statistics.pstdev(values) if len(values) > 1 else 0.0
        summary[ev] = {"mean": mean, "stdev": stdev}
    return summary


def print_summary_table_multi(
    summaries: Dict[str, Dict[str, Dict[str, float]]],
    events: List[str]
):
    """
    summaries: { stage_name: { event_name: { mean, stdev } } }
    打印一个多列表，比较不同 stage。
    """
    stage_names = list(summaries.keys())

    print("\n=== Summary (mean ± stdev) for each stage ===")
    header = f"{'Event':35s}"
    for st in stage_names:
        header += f" {st:25s}"
    print(header)
    print("-" * len(header))

    for ev in events:
        line = f"{ev:35s}"
        for st in stage_names:
            s = summaries[st][ev]
            cell = f"{s['mean']:.2f} ± {s['stdev']:.2f}"
            line += " " + cell.ljust(25)
        print(line)


def print_mispredict_rate_multi(
    summaries: Dict[str, Dict[str, Dict[str, float]]]
):
    """
    打印每个 stage 的 mispredict 率 (mispredicts / branches)
    """
    print("\n=== Branch mispredict rate (mispredicts / branches) per stage ===")
    for st, summary in summaries.items():
        br  = summary.get("br_inst_retired.all_branches", {}).get("mean", 0.0)
        mis = summary.get("br_misp_retired.all_branches", {}).get("mean", 0.0)
        if br <= 0:
            print(f"{st}: no branches observed")
            continue
        rate = mis / br
        print(f"{st}: {rate:.6f} (~{rate*100:.4f}% of branches mispredicted)")


if __name__ == "__main__":
    # 针对每个 stage 跑若干次
    repeats = 20
    summaries: Dict[str, Dict[str, Dict[str, float]]] = {}

    for st in ["stage1", "stage3", "full"]:
        print(f"\n=== Running experiments for {st} ===")
        results = run_experiments_stage(st, PMU_EVENTS, repeats=repeats)
        summaries[st] = summarize(results, PMU_EVENTS)

    # 打印多列对比表
    print_summary_table_multi(summaries, PMU_EVENTS)

    # 打印每个 stage 的 branch mispredict rate
    print_mispredict_rate_multi(summaries)