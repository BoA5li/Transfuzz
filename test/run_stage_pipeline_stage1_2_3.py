#!/usr/bin/env python3
"""
run_stage_pipeline_stage1_2_3.py

Stage1+Stage2+Stage3 PMU pipeline: instrument, build, run, and compare.

Modified: added --pmu-uops-obj for UOPS measurement linking.
"""
import sys
import argparse
import re
import subprocess
import os
from pathlib import Path


STAGE1_PMU_EVENTS = {
    "conditional": ("pmu_stage1_before", "pmu_stage1_after"),
    "indirect": ("pmu_stage1_indirect_before", "pmu_stage1_indirect_after"),
    "disambiguation": (
        "pmu_stage1_disambiguation_before",
        "pmu_stage1_disambiguation_after"),
    "return": ("pmu_stage1_return_before", "pmu_stage1_return_after"),
}

STAGE1_PMU_EVENT_MARKERS = {
    "indirect": "pmu_stage1_event_indirect_selected",
    "disambiguation": "pmu_stage1_event_disambiguation_selected",
    "return": "pmu_stage1_event_return_selected",
}


def normalize_stage1_pmu_event(event_name):
    """Return a canonical event key, rejecting unknown configurations."""
    normalized = str(event_name or "conditional").strip().lower()
    aliases = {
        "br_misp_retired.conditional": "conditional",
        "br_misp_exec.indirect": "indirect",
        "machine_clears.disambiguation": "disambiguation",
        "br_misp_retired.return": "return",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in STAGE1_PMU_EVENTS:
        raise ValueError(
            "unsupported Stage 1 PMU event {!r}; expected one of: {}".format(
                event_name, ", ".join(sorted(STAGE1_PMU_EVENTS))))
    return normalized


def is_lineno_comment(stripped):
    """判断是否是 gcc 生成的行号注释"""
    return bool(re.match(r"^#\s+\d+", stripped))


def process_asm(lines,
                begin_label="STAGE1_BEGIN",
                end_label="STAGE1_END",
                nop_region_begin="# NOP_REGION_BEGIN",
                nop_region_end="# NOP_REGION_END",
                stage1_pmu_event="conditional"):
    """
    第一轮用的汇编处理：
    1) 在 begin_label/end_label 处插入 PMU 调用
    2) 对 NOP_REGION 区域压缩为 nop
    3) 去掉 #APP / #NO_APP / 行号注释
    """
    event_key = normalize_stage1_pmu_event(stage1_pmu_event)
    before_symbol, after_symbol = STAGE1_PMU_EVENTS[event_key]
    out = []
    event_marker = STAGE1_PMU_EVENT_MARKERS.get(event_key)
    if event_marker:
        # Link-time marker: the helper constructor opens only the selected raw
        # event.  This is emitted during preprocessing, not tested in-window.
        out.extend([
            "\t.pushsection .rodata\n",
            "\t.globl {}\n".format(event_marker),
            "{}:\n".format(event_marker),
            "\t.byte 1\n",
            "\t.popsection\n",
        ])
    in_nop_region = False
    nop_emitted = False

    for line in lines:
        stripped = line.strip()

        # 全局过滤
        if stripped == "#APP" or stripped == "#NO_APP" or is_lineno_comment(stripped):
            continue

        # NOP 区域
        if stripped.startswith(nop_region_begin):
            in_nop_region = True
            nop_emitted = False
            continue

        if stripped.startswith(nop_region_end):
            in_nop_region = False
            nop_emitted = False
            continue

        # STAGE1_BEGIN/END 插桩
        if stripped == "{0}:".format(begin_label):
            out.append(line)
            out.append("\tcall {}\n".format(before_symbol))
            continue

        if stripped == "{0}:".format(end_label):
            out.append(line)
            out.append("\tcall {}\n".format(after_symbol))
            continue

        # NOP 区域内部压缩
        if in_nop_region:
            if stripped == "" or stripped.startswith(".") or stripped.startswith("#") or stripped.endswith(":"):
                continue
            if not nop_emitted:
                out.append("\tnop\n")
                nop_emitted = True
            continue

        out.append(line)

    return out


def process_asm_all_nop(lines,
                        begin_label="STAGE1_BEGIN",
                        end_label="STAGE1_END"):
    """
    第二轮对照实验：STAGE1 窗口内指令全替换为 nop。
    """
    out = []
    in_window = False
    seen_before_call = False
    seen_after_call = False
    nop_emitted = False

    for line in lines:
        stripped = line.strip()

        if stripped == "{0}:".format(begin_label):
            in_window = True
            seen_before_call = False
            nop_emitted = False
            out.append(line)
            continue

        if stripped == "{0}:".format(end_label):
            in_window = False
            seen_after_call = False
            nop_emitted = False
            out.append(line)
            continue

        if in_window:
            if (not seen_before_call and
                stripped.startswith("call") and
                "pmu_stage1_before" in stripped):
                out.append(line)
                seen_before_call = True
                continue

            if stripped == "":
                continue
            if stripped.startswith(".") or stripped.startswith("#") or stripped.endswith(":"):
                out.append(line)
                continue

            if not nop_emitted:
                out.append("\tnop\n")
                nop_emitted = True
            continue
        else:
            if (not seen_after_call and
                stripped.startswith("call") and
                "pmu_stage1_after" in stripped):
                out.append(line)
                seen_after_call = True
                continue
            out.append(line)

    return out


def run_cmd(cmd, cwd=None):
    """简单封装 subprocess.run，兼容 Python 3.6"""
    print("[RUN]", " ".join(cmd))
    res = subprocess.run(cmd, cwd=cwd)
    if res.returncode != 0:
        sys.stderr.write("Command failed: {}\n".format(" ".join(cmd)))
        sys.exit(res.returncode)
    return res


def build_and_run_from_s(s_file, pmu_helper_obj, pmu_uops_obj,
                         post_script, period, tag):
    """
    从 .s 出发构建并运行。
    """
    gcc = "gcc"
    s_file = Path(s_file)
    pmu_helper_obj = Path(pmu_helper_obj)
    pmu_uops_obj = Path(pmu_uops_obj) if pmu_uops_obj else None

    if not s_file.exists():
        sys.stderr.write("Assembly file not found: {}\n".format(s_file))
        sys.exit(1)

    o_file = s_file.with_suffix("")
    o_file = o_file.with_name(o_file.name + "_" + tag + ".o")
    run_cmd([gcc, "-c", str(s_file), "-o", str(o_file)])

    exe_file = s_file.with_suffix("")
    exe_file = exe_file.with_name(exe_file.name + "_" + tag)

    link_objs = [str(o_file), str(pmu_helper_obj)]
    if pmu_uops_obj is not None and pmu_uops_obj.exists():
        link_objs.append(str(pmu_uops_obj))
    link_objs += ["-o", str(exe_file)]
    run_cmd([gcc] + link_objs)

    exe_path = exe_file.resolve()
    if not exe_path.exists():
        sys.stderr.write("Executable not found after link: {}\n".format(exe_path))
        sys.exit(1)
    print("[INFO] Executable ({}): {}".format(tag, exe_path))

    log_file = s_file.with_name("run_{}.log".format(tag))
    print("[RUN] {} > {}".format(exe_path, log_file))
    with log_file.open("w", encoding="utf-8") as f:
        res = subprocess.run([str(exe_path)], stdout=f, stderr=subprocess.PIPE)
    if res.returncode != 0:
        sys.stderr.write("Executable failed ({}): {}\n".format(tag, exe_path))
        if res.stderr:
            sys.stderr.write(res.stderr.decode("utf-8", errors="ignore"))
        sys.exit(res.returncode)

    run_cmd(["python3", str(post_script), "-p", str(period), str(log_file)])


def pipeline_two_rounds_from_c(c_file, pmu_helper_obj, pmu_uops_obj,
                               post_script, period, gcc="gcc",
                               stage1_pmu_event="conditional"):
    """从 .c 起跑两轮实验。"""
    c_file = Path(c_file)
    pmu_helper_obj = Path(pmu_helper_obj)
    post_script = Path(post_script)

    if not c_file.exists():
        sys.stderr.write("C file not found: {}\n".format(c_file))
        sys.exit(1)

    s_file = c_file.with_suffix(".s")
    run_cmd([gcc, "-S", str(c_file), "-o", str(s_file)])

    with s_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    out_lines = process_asm(lines, stage1_pmu_event=stage1_pmu_event)
    with s_file.open("w", encoding="utf-8") as f:
        f.writelines(out_lines)
    print("[INFO] Instrumented assembly written back to {}".format(s_file))

    build_and_run_from_s(s_file, pmu_helper_obj, pmu_uops_obj,
                         post_script, period, tag="stage1")

    # 第二轮: all-nop 对照
    s_nop_file = s_file.with_name(s_file.stem + "_stage1_nop.s")
    with s_file.open("r", encoding="utf-8") as f:
        lines2 = f.readlines()
    out_lines2 = process_asm_all_nop(lines2)
    with s_nop_file.open("w", encoding="utf-8") as f:
        f.writelines(out_lines2)
    print("[INFO] All-nop STAGE1 assembly written to {}".format(s_nop_file))

    build_and_run_from_s(s_nop_file, pmu_helper_obj, pmu_uops_obj,
                         post_script, period, tag="stage1_nop")
    return s_file


def process_asm_only(asm_file, stage1_pmu_event="conditional"):
    """仅对 .s 做插桩处理"""
    asm_file = Path(asm_file)
    if not asm_file.exists():
        sys.stderr.write("Assembly file not found: {}\n".format(asm_file))
        sys.exit(1)
    with asm_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    out_lines = process_asm(lines, stage1_pmu_event=stage1_pmu_event)
    with asm_file.open("w", encoding="utf-8") as f:
        f.writelines(out_lines)
    print("[INFO] Instrumented assembly written back to {}".format(asm_file))


def pipeline_stage2_from_c(c_file, pmu_helper_obj, pmu_uops_obj,
                           stage2_driver_obj, stage2_post_script,
                           gcc="gcc",
                           enable_stage3=False,
                           stage3_driver_obj=None,
                           stage3_post_script=None,
                           stage3_mode="flush-reload"):
    """Stage2（可选 Stage3）。"""
    c_file = Path(c_file)
    pmu_helper_obj = Path(pmu_helper_obj)
    stage2_driver_obj = Path(stage2_driver_obj)
    stage2_post_script = Path(stage2_post_script)

    if not c_file.exists():
        sys.stderr.write("C file not found: {}\n".format(c_file))
        sys.exit(1)
    if not stage2_driver_obj.exists():
        sys.stderr.write("stage2 driver object not found: {}\n".format(stage2_driver_obj))
        sys.exit(1)

    victim_o = c_file.with_suffix("")
    victim_o = victim_o.with_name(victim_o.name + "_stage2.o")
    run_cmd([gcc, "-c", "-DSTAGE2_TEST_MAIN", str(c_file), "-o", str(victim_o)])

    exe_file = c_file.with_suffix("")
    exe_file = exe_file.with_name(exe_file.name + "_stage2")

    pmu_uops_path = Path(pmu_uops_obj) if pmu_uops_obj else None

    link_cmd = [gcc, str(victim_o), str(stage2_driver_obj), str(pmu_helper_obj)]
    if pmu_uops_path is not None and pmu_uops_path.exists():
        link_cmd.append(str(pmu_uops_path))
    if enable_stage3:
        stage3_driver_obj = Path(stage3_driver_obj)
        link_cmd.append(str(stage3_driver_obj))
    link_cmd += ["-o", str(exe_file)]
    run_cmd(link_cmd)

    exe_path = exe_file.resolve()
    if not exe_path.exists():
        sys.stderr.write("Stage2 executable not found: {}\n".format(exe_path))
        sys.exit(1)
    print("[INFO] Stage2 Executable: {}".format(exe_path))

    log_file = c_file.with_name("run_stage2.log")
    print("[RUN] {} > {}".format(exe_path, log_file))

    run_env = os.environ.copy()
    if enable_stage3:
        run_env["ENABLE_STAGE3"] = "1"
        run_env["STAGE3_MODE"] = stage3_mode

    with log_file.open("w", encoding="utf-8") as f:
        res = subprocess.run([str(exe_path)], stdout=f, stderr=subprocess.PIPE,
                             env=run_env)
    if res.returncode != 0:
        sys.stderr.write("Stage2 executable failed: {}\n".format(exe_path))
        if res.stderr:
            sys.stderr.write(res.stderr.decode("utf-8", errors="ignore"))
        sys.exit(res.returncode)

    run_cmd(["python3", str(stage2_post_script), str(log_file)])
    if enable_stage3:
        stage3_post_script = Path(stage3_post_script)
        run_cmd(["python3", str(stage3_post_script), str(log_file)])


def pipeline_stage3_from_c(c_file, stage3_driver_obj, stage3_observer_obj,
                           stage3_post_script, stage3_mode, gcc="gcc"):
    """Stage3 pipeline."""
    c_file = Path(c_file)
    stage3_driver_obj = Path(stage3_driver_obj)
    stage3_observer_obj = Path(stage3_observer_obj)
    stage3_post_script = Path(stage3_post_script)

    victim_o = c_file.with_suffix("")
    victim_o = victim_o.with_name(victim_o.name + "_stage3.o")
    run_cmd([gcc, "-c", "-DSTAGE2_TEST_MAIN", str(c_file), "-o", str(victim_o)])

    exe_file = c_file.with_suffix("")
    exe_file = exe_file.with_name(exe_file.name + "_stage3")
    run_cmd([
        gcc,
        "-DSTAGE3_MODE_STR=\"{}\"".format(stage3_mode),
        str(victim_o),
        str(stage3_driver_obj),
        str(stage3_observer_obj),
        "-o", str(exe_file)
    ])

    exe_path = exe_file.resolve()
    log_file = c_file.with_name("run_stage3.log")
    print("[RUN] {} > {}".format(exe_path, log_file))
    with log_file.open("w", encoding="utf-8") as f:
        res = subprocess.run([str(exe_path)], stdout=f, stderr=subprocess.PIPE)
    if res.returncode != 0:
        sys.stderr.write("Stage3 executable failed: {}\n".format(exe_path))
        if res.stderr:
            sys.stderr.write(res.stderr.decode("utf-8", errors="ignore"))
        sys.exit(res.returncode)

    run_cmd(["python3", str(stage3_post_script), str(log_file)])


def main():
    ap = argparse.ArgumentParser(
        description="Stage1+Stage2+Stage3 PMU pipeline."
    )
    ap.add_argument("input",
                    help="Input C or assembly file.")
    ap.add_argument("--pmu-helper-obj", default="pmu_helper_auto.o",
                    help="Path to pmu_helper object file (default: pmu_helper_auto.o)")
    ap.add_argument("--pmu-uops-obj", default="pmu_uops_rdpmc.o",
                    help="Path to pmu_uops_rdpmc object file (default: pmu_uops_rdpmc.o)")
    ap.add_argument("--stage1-pmu-event", default="conditional",
                    type=normalize_stage1_pmu_event,
                    choices=sorted(STAGE1_PMU_EVENTS),
                    help="Stage 1 branch event selected during instrumentation "
                         "(default: conditional)")
    ap.add_argument("--post-script", default="post_test_stage_auto.py",
                    help="Post-process script (default: post_test_stage_auto.py)")
    ap.add_argument("-p", "--period", type=int, default=10,
                    help="Train/attack period (default: 10)")
    ap.add_argument("--gcc", default="gcc", help="gcc executable (default: gcc)")

    ap.add_argument("--enable-stage2", action="store_true")
    ap.add_argument("--stage2-driver-obj", default="stage2_driver.o")
    ap.add_argument("--stage2-post-script", default="post_test_stage2_auto.py")

    ap.add_argument("--enable-stage3", action="store_true")
    ap.add_argument("--stage3-driver-obj", default="stage3_driver_safe.o")
    ap.add_argument("--stage3-post-script", default="post_test_stage3_auto.py")
    ap.add_argument("--stage3-mode", default="flush-reload")

    args = ap.parse_args()
    inp = Path(args.input)
    pmu_uops = args.pmu_uops_obj

    if inp.suffix == ".c":
        s_file = pipeline_two_rounds_from_c(
            c_file=inp,
            pmu_helper_obj=args.pmu_helper_obj,
            pmu_uops_obj=pmu_uops,
            post_script=args.post_script,
            period=args.period,
            gcc=args.gcc,
            stage1_pmu_event=args.stage1_pmu_event,
        )
        if args.enable_stage2 or args.enable_stage3:
            pipeline_stage2_from_c(
                c_file=inp,
                pmu_helper_obj=args.pmu_helper_obj,
                pmu_uops_obj=pmu_uops,
                stage2_driver_obj=args.stage2_driver_obj,
                stage2_post_script=args.stage2_post_script,
                gcc=args.gcc,
                enable_stage3=args.enable_stage3,
                stage3_driver_obj=args.stage3_driver_obj,
                stage3_post_script=args.stage3_post_script,
                stage3_mode=args.stage3_mode,
            )
    elif inp.suffix == ".s":
        process_asm_only(inp, stage1_pmu_event=args.stage1_pmu_event)
    else:
        sys.stderr.write("Input must be a .c or .s file\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
