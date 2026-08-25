# -*- coding: utf-8 -*-
import subprocess
import statistics
from typing import List, Dict, Tuple

# 要测的事件
PMU_EVENTS = [
    "branches",
    "branch-misses",
    "br_inst_retired.all_branches",
    "br_misp_retired.all_branches",
    "machine_clears.count",
    "machine_clears.memory_ordering",
    "machine_clears.smc",
]

# 两个测试程序
BINARY_BASELINE = "./spectre1_baseline"
BINARY_ATTACK   = "./spectre1"


def run_perf(binary: str, events: List[str]) -> Dict[str, int]:
    """
    对指定二进制执行一次 perf stat，返回 {event_name: count}
    """
    events_str = ",".join(events)
    cmd = [
        "perf", "stat",
        "-x", ",",           # CSV 输出
        "-e", events_str,
        binary
    ]

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


def run_experiments(
    binary: str,
    events: List[str],
    repeats: int = 5
) -> List[Dict[str, int]]:
    """
    对同一个 binary 重复跑 repeats 次 perf stat。
    """
    results = []
    for i in range(repeats):
        print(f"Run {i+1}/{repeats} for {binary}")
        res = run_perf(binary, events)
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


def print_summary_table(
    baseline_summary: Dict[str, Dict[str, float]],
    attack_summary: Dict[str, Dict[str, float]],
    events: List[str]
):
    print("\n=== Summary (mean ± stdev) ===")
    header = f"{'Event':35s} {'Baseline':25s} {'Attack':25s} {'Attack/Baseline':>15s}"
    print(header)
    print("-" * len(header))
    for ev in events:
        b = baseline_summary[ev]
        a = attack_summary[ev]
        ratio = (a["mean"] / b["mean"]) if b["mean"] > 0 else float('inf')
        print(
            f"{ev:35s} "
            f"{b['mean']:.2f} ± {b['stdev']:.2f}".ljust(25),
            f"{a['mean']:.2f} ± {a['stdev']:.2f}".ljust(25),
            f"{ratio:15.2f}"
        )


def infer_branch_mispredict_pair(
    baseline_summary: Dict[str, Dict[str, float]],
    attack_summary: Dict[str, Dict[str, float]]
) -> str:
    """
    基于 baseline vs attack 的对比，给出关于分支误预测的“相对变化”描述。
    不使用固定阈值，只报告倍率和与噪声的相对关系。
    """
    def get(ev, summary, key):
        return summary.get(ev, {}).get(key, 0.0)

    br_b   = get("br_inst_retired.all_branches", baseline_summary, "mean")
    br_a   = get("br_inst_retired.all_branches", attack_summary,   "mean")
    mis_b  = get("br_misp_retired.all_branches", baseline_summary, "mean")
    mis_a  = get("br_misp_retired.all_branches", attack_summary,   "mean")
    mis_b_sd = get("br_misp_retired.all_branches", baseline_summary, "stdev")
    mis_a_sd = get("br_misp_retired.all_branches", attack_summary,   "stdev")

    if br_b <= 0 or br_a <= 0:
        return "无法比较分支误预测（baseline 或 attack 未观测到分支）"

    rate_b = mis_b / br_b if br_b > 0 else 0.0
    rate_a = mis_a / br_a if br_a > 0 else 0.0

    # 倍数
    br_ratio   = br_a / br_b
    mis_ratio  = mis_a / mis_b if mis_b > 0 else float('inf')
    rate_ratio = rate_a / rate_b if rate_b > 0 else float('inf')

    # 简单噪声评估：差值相对于标准差之和
    diff_mis = abs(mis_a - mis_b)
    noise_mis = mis_b_sd + mis_a_sd
    if noise_mis > 0:
        snr_mis = diff_mis / noise_mis
    else:
        snr_mis = float('inf') if diff_mis > 0 else 0.0

    lines = []
    lines.append(
        f"baseline: branches={br_b:.3g}, mispredicts={mis_b:.3g}, rate={rate_b:.3g}"
    )
    lines.append(
        f"attack:   branches={br_a:.3g}, mispredicts={mis_a:.3g}, rate={rate_a:.3g}"
    )
    lines.append(
        f"attack vs baseline: "
        f"branches×{br_ratio:.2f}, mispredicts×{mis_ratio:.2f}, rate×{rate_ratio:.2f}"
    )
    lines.append(
        f"误预测次数差值与噪声比: Δmis / (σ_b+σ_a) ≈ {snr_mis:.2f}"
    )

    # 可选：只在“变化远大于噪声”时给一句轻度结论
    if snr_mis > 3 and mis_ratio > 1.0:
        lines.append("结论：attack 场景下分支误预测次数相对 baseline 有显著增加（变化大于测量噪声）。")
    elif snr_mis < 1:
        lines.append("结论：attack 与 baseline 的分支误预测差异与噪声同量级，难以下结论。")
    else:
        lines.append("结论：attack 与 baseline 的分支误预测有一定差异，但幅度相对于噪声不算特别大。")

    return "\n".join(lines)


def infer_machine_clears_pair(
    baseline_summary: Dict[str, Dict[str, float]],
    attack_summary: Dict[str, Dict[str, float]]
) -> str:
    def get(ev, summary, key):
        return summary.get(ev, {}).get(key, 0.0)

    mc_b   = get("machine_clears.count", baseline_summary, "mean")
    mc_a   = get("machine_clears.count", attack_summary,   "mean")
    mc_b_sd = get("machine_clears.count", baseline_summary, "stdev")
    mc_a_sd = get("machine_clears.count", attack_summary,   "stdev")

    lines = []
    lines.append(
        f"baseline: machine_clears.count={mc_b:.3g} (σ≈{mc_b_sd:.3g})"
    )
    lines.append(
        f"attack:   machine_clears.count={mc_a:.3g} (σ≈{mc_a_sd:.3g})"
    )

    if mc_b == 0 and mc_a == 0:
        lines.append("两种场景下 machine_clears.count 都接近 0，未观察到可区分的 machine clear 信号。")
        return "\n".join(lines)

    ratio = (mc_a / mc_b) if mc_b > 0 else float('inf')
    lines.append(f"attack vs baseline: machine_clears.count×{ratio:.2f}")

    diff_mc = abs(mc_a - mc_b)
    noise_mc = mc_b_sd + mc_a_sd
    if noise_mc > 0:
        snr_mc = diff_mc / noise_mc
    else:
        snr_mc = float('inf') if diff_mc > 0 else 0.0
    lines.append(
        f"machine_clears 差值与噪声比: Δmc / (σ_b+σ_a) ≈ {snr_mc:.2f}"
    )

    if snr_mc > 3 and ratio != 1.0:
        lines.append("结论：attack 与 baseline 的 machine_clears.count 差异超过测量噪声，可认为有显著差别。")
    elif snr_mc < 1:
        lines.append("结论：attack 与 baseline 的 machine_clears.count 差异与噪声同级，难以下结论。")
    else:
        lines.append("结论：attack 与 baseline 的 machine_clears.count 存在一定差异，但未明显超过噪声。")

    return "\n".join(lines)

def print_mispredict_rate(
    baseline_summary: Dict[str, Dict[str, float]],
    attack_summary: Dict[str, Dict[str, float]]
):
    br_b   = baseline_summary.get("br_inst_retired.all_branches", {}).get("mean", 0.0)
    br_a   = attack_summary.get("br_inst_retired.all_branches", {}).get("mean", 0.0)
    mis_b  = baseline_summary.get("br_misp_retired.all_branches", {}).get("mean", 0.0)
    mis_a  = attack_summary.get("br_misp_retired.all_branches", {}).get("mean", 0.0)

    if br_b <= 0 or br_a <= 0:
        print("\n=== Branch mispredict rate (mispredicts / branches) ===")
        print("baseline 或 attack 未观测到分支，无法计算占比。")
        return

    rate_b = mis_b / br_b
    rate_a = mis_a / br_a
    rate_ratio = rate_a / rate_b if rate_b > 0 else float('inf')

    print("\n=== Branch mispredict rate (mispredicts / branches) ===")
    print(f"baseline: {rate_b:.6f}  (~{rate_b*100:.4f}% of branches are mispredicted)")
    print(f"attack:   {rate_a:.6f}  (~{rate_a*100:.4f}% of branches are mispredicted)")
    print(f"attack / baseline rate: ×{rate_ratio:.2f}")




if __name__ == "__main__":
    # 1. baseline / attack 各跑若干次
    print("=== Baseline binary ===")
    baseline_results = run_experiments(BINARY_BASELINE, PMU_EVENTS, repeats=20)

    print("\n=== Attack binary ===")
    attack_results = run_experiments(BINARY_ATTACK, PMU_EVENTS, repeats=20)

    # 2. 统计
    baseline_summary = summarize(baseline_results, PMU_EVENTS)
    attack_summary   = summarize(attack_results, PMU_EVENTS)

    # 3. 打印表格
    print_summary_table(baseline_summary, attack_summary, PMU_EVENTS)

    print_mispredict_rate(baseline_summary, attack_summary)

    print("\n--- Branch mispredict comparison ---")
    print(infer_branch_mispredict_pair(baseline_summary, attack_summary))

    print("\n--- Machine clears comparison ---")
    print(infer_machine_clears_pair(baseline_summary, attack_summary))