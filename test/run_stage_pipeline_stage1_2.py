#!/usr/bin/env python3
import sys
import argparse
import re
import subprocess
from pathlib import Path

def is_lineno_comment(stripped: str) -> bool:
    """判断是否是 gcc 生成的行号注释，例如: '# 48 \"file.c\" 1'"""
    return bool(re.match(r"^#\s+\d+", stripped))

def process_asm(lines,
                begin_label="STAGE1_BEGIN",
                end_label="STAGE1_END",
                nop_region_begin="# NOP_REGION_BEGIN",
                nop_region_end="# NOP_REGION_END"):
    """
    第一轮用的汇编处理：
    1) 在 begin_label/end_label 处插入 PMU 调用：
       - begin_label: 插入 call pmu_stage1_before
       - end_label:   插入 call pmu_stage1_after
    2) 对 NOP_REGION_BEGIN / NOP_REGION_END 包围的区域，将中间的整个指令序列
       压缩为一条 'nop'：
       - 不输出 NOP_REGION_BEGIN/END 标记本身
       - 不输出该区域内的行号注释、#APP/#NO_APP 等
       - 仅在区域内第一次遇到“指令行”时输出一条 nop
    3) 全局：去掉所有 '#APP'、'#NO_APP' 和 gcc 的行号注释行。
    """
    out = []
    in_stage1_window = False
    in_nop_region = False
    nop_emitted = False

    for line in lines:
        stripped = line.strip()

        # 全局过滤：#APP / #NO_APP / 行号注释
        if stripped == "#APP" or stripped == "#NO_APP" or is_lineno_comment(stripped):
            continue

        # NOP 区域标记本身也不输出，只用于状态切换
        if stripped.startswith(nop_region_begin):
            in_nop_region = True
            nop_emitted = False
            continue

        if stripped.startswith(nop_region_end):
            in_nop_region = False
            nop_emitted = False
            continue

        # 处理 STAGE1_BEGIN/END 标签：插桩 PMU
        if stripped == f"{begin_label}:":
            out.append(line)
            out.append("\tcall pmu_stage1_before\n")
            in_stage1_window = True
            continue

        if stripped == f"{end_label}:":
            out.append(line)
            out.append("\tcall pmu_stage1_after\n")
            in_stage1_window = False
            continue

        # 在 NOP 区域内部：压缩成一条 nop
        if in_nop_region:
            # 判断是否为“指令行”：
            if stripped == "":
                continue
            if stripped.startswith("."):
                continue
            if stripped.startswith("#"):
                continue
            if stripped.endswith(":"):
                continue

            # 走到这里说明是指令行
            if not nop_emitted:
                out.append("\tnop\n")
                nop_emitted = True
            # 原指令不输出
            continue

        # 默认原样输出
        out.append(line)

    return out

def process_asm_all_nop(lines,
                        begin_label="STAGE1_BEGIN",
                        end_label="STAGE1_END"):
    """
    第二轮对照实验用的汇编处理：
    在 STAGE1_BEGIN 和 STAGE1_END 标签之间，将“除了 pmu_stage1_before/after 和标签外的指令”
    压缩为一条 nop。

    具体约定：
    - 保留：
      * STAGE1_BEGIN: 这一行
      * 紧跟在 STAGE1_BEGIN: 后的 'call pmu_stage1_before'
      * STAGE1_END: 这一行
      * 紧跟在 STAGE1_END: 后的 'call pmu_stage1_after'
      * 任何标签行（以 ':' 结尾，例如 .L2:）
      * 伪指令（以 '.' 开头）
      * 注释行（以 '#' 开头）
    - 在 BEGIN 与 END 之间，除了上述行以外的所有“指令行”被整体压缩为单条 'nop'。
    - BEGIN/END 外部的内容完全不改。
    """
    out = []
    in_window = False
    seen_before_call = False    # 是否已遇到 begin 后的 pmu_stage1_before
    seen_after_call = False     # 是否已遇到 end 后的 pmu_stage1_after
    nop_emitted = False

    for line in lines:
        stripped = line.strip()

        # 检测 STAGE1_BEGIN
        if stripped == f"{begin_label}:":
            in_window = True
            seen_before_call = False
            nop_emitted = False
            out.append(line)
            continue

        # 检测 STAGE1_END
        if stripped == f"{end_label}:":
            # 先结束窗口，再输出 END 标签
            in_window = False
            seen_after_call = False
            nop_emitted = False
            out.append(line)
            continue

        if in_window:
            # BEGIN 后第一个 pmu_stage1_before 必须保留
            if (not seen_before_call and
                stripped.startswith("call") and
                "pmu_stage1_before" in stripped):
                out.append(line)
                seen_before_call = True
                continue

            # END 之后的 pmu_stage1_after 不在 in_window 里处理
            # 所以这里不处理 after

            # 伪指令、注释、标签都原样保留
            if stripped == "":
                continue  # 空行可以直接丢，也可以 out.append(line)
            if stripped.startswith("."):
                out.append(line)
                continue
            if stripped.startswith("#"):
                out.append(line)
                continue
            if stripped.endswith(":"):
                out.append(line)
                continue

            # 剩余的是窗口内的“普通指令”
            if not nop_emitted:
                out.append("\tnop\n")
                nop_emitted = True
            # 后续普通指令全部丢弃
            continue

        else:
            # 在窗口外：要特别识别 END 后的 pmu_stage1_after 并保留
            if (not seen_after_call and
                stripped.startswith("call") and
                "pmu_stage1_after" in stripped):
                out.append(line)
                seen_after_call = True
                continue

            # 其它行一律原样输出
            out.append(line)

    return out

def run_cmd(cmd, cwd=None):
    """
    简单封装 subprocess.run，兼容 Python 3.6：
    - 不使用 capture_output
    - 标准输出/错误继承当前终端
    """
    print("[RUN]", " ".join(cmd))
    res = subprocess.run(cmd, cwd=cwd)
    if res.returncode != 0:
        sys.stderr.write("Command failed: {}\n".format(" ".join(cmd)))
        sys.exit(res.returncode)
    return res

def build_and_run_from_s(s_file: Path,
                         pmu_helper_obj: Path,
                         post_script: Path,
                         tag: str):
    """
    从一个已存在的 .s 出发：
    1) gcc -c -> .o
    2) 链接 pmu_helper_obj -> 可执行文件
    3) 运行可执行，输出到 run_<tag>.log
    4) 调用 post_script 做统计
    """
    gcc = "gcc"
    if not s_file.exists():
        sys.stderr.write("Assembly file not found: {}\n".format(s_file))
        sys.exit(1)
    if not pmu_helper_obj.exists():
        sys.stderr.write("pmu_helper object not found: {}\n".format(pmu_helper_obj))
        sys.exit(1)
    if not post_script.exists():
        sys.stderr.write("post-process script not found: {}\n".format(post_script))
        sys.exit(1)

    # .o 文件名加上 tag
    o_file = s_file.with_suffix("")  # 去掉 .s
    o_file = o_file.with_name(o_file.name + "_" + tag + ".o")

    run_cmd([gcc, "-c", str(s_file), "-o", str(o_file)])

    exe_file = s_file.with_suffix("")
    exe_file = exe_file.with_name(exe_file.name + "_" + tag)
    run_cmd([gcc, str(o_file), str(pmu_helper_obj), "-o", str(exe_file)])

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

    # 后处理
    run_cmd(["python3", str(post_script), str(log_file)])

def pipeline_two_rounds_from_c(c_file: Path,
                               pmu_helper_obj: Path,
                               post_script: Path,
                               gcc="gcc"):
    """
    从 .c 起跑两轮实验：
    第一轮（tag='stage1'):
      - gcc -S -> c.stem.s
      - process_asm() 插桩 + NOP_REGION 压缩（覆盖 .s）
      - 从 .s 构建并运行，post-process，日志 run_stage1.log
    第二轮（tag='stage1_nop'):
      - 基于第一轮的 .s，生成一个新的 .s_nop（不覆盖原 .s）
      - 对新 .s 在 STAGE1_BEGIN/END 间做 all-nop
      - 从新 .s 构建并运行，post-process，日志 run_stage1_nop.log
    """
    if not c_file.exists():
        sys.stderr.write("C file not found: {}\n".format(c_file))
        sys.exit(1)
    if not pmu_helper_obj.exists():
        sys.stderr.write("pmu_helper object not found: {}\n".format(pmu_helper_obj))
        sys.exit(1)
    if not post_script.exists():
        sys.stderr.write("post-process script not found: {}\n".format(post_script))
        sys.exit(1)

    # === 第一轮：正常 STAGE1 窗口 ===
    s_file = c_file.with_suffix(".s")
    run_cmd([gcc, "-S", str(c_file), "-o", str(s_file)])

    with s_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    out_lines = process_asm(lines)
    with s_file.open("w", encoding="utf-8") as f:
        f.writelines(out_lines)
    print("[INFO] Instrumented assembly written back to {}".format(s_file))

    # 从 s_file 构建并运行（tag='stage1'）
    build_and_run_from_s(s_file, pmu_helper_obj, post_script, tag="stage1")

    # === 第二轮：STAGE1 窗口 all-nop 对照 ===
    # 新的 .s 文件，不覆盖原 s_file
    s_nop_file = s_file.with_name(s_file.stem + "_stage1_nop.s")
    with s_file.open("r", encoding="utf-8") as f:
        lines2 = f.readlines()
    out_lines2 = process_asm_all_nop(lines2)
    with s_nop_file.open("w", encoding="utf-8") as f:
        f.writelines(out_lines2)
    print("[INFO] All-nop STAGE1 assembly written to {}".format(s_nop_file))

    # 从 s_nop_file 构建并运行（tag='stage1_nop'）
    build_and_run_from_s(s_nop_file, pmu_helper_obj, post_script,
                         tag="stage1_nop")
    return s_file

def process_asm_only(asm_file: Path):
    """仅对已有的 .s 做插桩 + NOP_REGION 处理（就地覆盖原文件）。"""
    if not asm_file.exists():
        sys.stderr.write("Assembly file not found: {}\n".format(asm_file))
        sys.exit(1)
    with asm_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    out_lines = process_asm(lines)
    with asm_file.open("w", encoding="utf-8") as f:
        f.writelines(out_lines)
    print("[INFO] Instrumented assembly written back to {}".format(asm_file))

def pipeline_stage2_from_c(c_file: Path,
                           pmu_helper_obj: Path,
                           stage2_driver_obj: Path,
                           stage2_post_script: Path,
                           gcc="gcc"):
    """
    Stage2: 基于 PoC C 源：
      1) gcc -c -DSTAGE2_TEST_MAIN c_file -> victim_stage2.o（无 PoC main，只剩 vf_* 等）
      2) 链接 victim_stage2.o + stage2_driver_obj + pmu_helper_obj -> exe_stage2
      3) 运行 exe_stage2，输出到 run_stage2.log
      4) 调用 stage2_post_script 解析 STAGE2_* 输出
    """
    if not c_file.exists():
        sys.stderr.write("C file not found: {}\n".format(c_file))
        sys.exit(1)
    if not pmu_helper_obj.exists():
        sys.stderr.write("pmu_helper object not found: {}\n".format(pmu_helper_obj))
        sys.exit(1)
    if not stage2_driver_obj.exists():
        sys.stderr.write("stage2 driver object not found: {}\n".format(stage2_driver_obj))
        sys.exit(1)
    if not stage2_post_script.exists():
        sys.stderr.write("stage2 post-process script not found: {}\n".format(stage2_post_script))
        sys.exit(1)

    victim_o = c_file.with_suffix("")
    victim_o = victim_o.with_name(victim_o.name + "_stage2.o")

    # 注意这里从 .c 编译，并定义 STAGE2_TEST_MAIN，以屏蔽 PoC main
    run_cmd([gcc, "-c", "-DSTAGE2_TEST_MAIN", str(c_file), "-o", str(victim_o)])

    exe_file = c_file.with_suffix("")
    exe_file = exe_file.with_name(exe_file.name + "_stage2")
    run_cmd([gcc,
             str(victim_o),
             str(stage2_driver_obj),
             str(pmu_helper_obj),
             "-o", str(exe_file)])

    exe_path = exe_file.resolve()
    if not exe_path.exists():
        sys.stderr.write("Stage2 executable not found: {}\n".format(exe_path))
        sys.exit(1)
    print("[INFO] Stage2 Executable: {}".format(exe_path))

    log_file = c_file.with_name("run_stage2.log")
    print("[RUN] {} > {}".format(exe_path, log_file))
    with log_file.open("w", encoding="utf-8") as f:
        res = subprocess.run([str(exe_path)], stdout=f, stderr=subprocess.PIPE)
    if res.returncode != 0:
        sys.stderr.write("Stage2 executable failed: {}\n".format(exe_path))
        if res.stderr:
            sys.stderr.write(res.stderr.decode("utf-8", errors="ignore"))
        sys.exit(res.returncode)

    run_cmd(["python3", str(stage2_post_script), str(log_file)])


def main():
    ap = argparse.ArgumentParser(
        description="Stage1+Stage2 PMU pipeline: instrument, build, run, and compare."
    )
    ap.add_argument("input",
                    help="Input C or assembly file. "
                         "If ends with .c, run two-round pipeline from C; "
                         "if ends with .s, only instrument assembly in-place (first-round style).")
    ap.add_argument("--pmu-helper-obj", default="pmu_helper_auto.o",
                    help="Path to pmu_helper object file (default: pmu_helper_auto.o)")
    ap.add_argument("--post-script", default="post_test_stage_auto.py",
                    help="Post-process script (default: post_test_stage_auto.py)")
    ap.add_argument("--gcc", default="gcc", help="gcc executable (default: gcc)")

    ap.add_argument("--enable-stage2", action="store_true",
                    help="Enable Stage2 L1D-miss based cache-hit validation.")
    ap.add_argument("--stage2-driver-obj", default="stage2_driver.o",
                    help="Pre-built Stage2 driver object file (default: stage2_driver.o)")
    ap.add_argument("--stage2-post-script", default="post_test_stage2_auto.py",
                    help="Stage2 post-process script (default: post_test_stage2_auto.py)")

    args = ap.parse_args()

    inp = Path(args.input)

    if inp.suffix == ".c":
        # 从 C 起跑 Stage1，返回生成的 s_file 供 Stage2 复用
        s_file = pipeline_two_rounds_from_c(
            c_file=inp,
            pmu_helper_obj=Path(args.pmu_helper_obj),
            post_script=Path(args.post_script),
            gcc=args.gcc,
        )
        if args.enable_stage2:
            pipeline_stage2_from_c(
                c_file=inp,
                pmu_helper_obj=Path(args.pmu_helper_obj),
                stage2_driver_obj=Path(args.stage2_driver_obj),
                stage2_post_script=Path(args.stage2_post_script),
                gcc=args.gcc,
            )

    elif inp.suffix == ".s":
        # 仅汇编输入的情况：可选 Stage1 插桩 + Stage2 验证
        process_asm_only(inp)
        if args.enable_stage2:
            pipeline_stage2_from_c(
                c_file=inp,
                pmu_helper_obj=Path(args.pmu_helper_obj),
                stage2_driver_obj=Path(args.stage2_driver_obj),
                stage2_post_script=Path(args.stage2_post_script),
                gcc=args.gcc,
            )
    else:
        sys.stderr.write("Input must be a .c or .s file\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
