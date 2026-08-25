#!/usr/bin/env python3
import sys
import argparse
import re

def is_lineno_comment(stripped: str) -> bool:
    """
    判断是否是 gcc 生成的行号注释，例如:
      # 48 "spectre_stage_auto.c" 1
    """
    return bool(re.match(r"^#\s+\d+", stripped))

def process_asm(lines,
                begin_label="STAGE1_BEGIN",
                end_label="STAGE1_END",
                nop_region_begin="# NOP_REGION_BEGIN",
                nop_region_end="# NOP_REGION_END"):
    """
    处理汇编：
    1) 在 begin_label/end_label 处插入 PMU 调用：
       - begin_label: 插入 call pmu_stage1_before
       - end_label:   插入 call pmu_stage1_after
    2) 对 NOP_REGION_BEGIN / NOP_REGION_END 包围的区域，将中间的整个指令序列
       压缩为一条 'nop'：
       - 不再输出 NOP_REGION_BEGIN/END 标记本身
       - 不输出该区域内的行号注释、#APP/#NO_APP 等
       - 仅在区域内第一次遇到“指令行”时输出一条 nop
    3) 全局：去掉所有 '#APP'、'#NO_APP' 和 gcc 的行号注释行。
    """
    out = []
    in_stage1_window = False      # 目前只用来标记 begin/end，可扩展
    in_nop_region = False
    nop_emitted = False           # 当前 nop 区域内是否已经输出过一条 nop

    for line in lines:
        stripped = line.strip()

        # 全局过滤：#APP / #NO_APP / 行号注释
        if stripped == "#APP" or stripped == "#NO_APP" or is_lineno_comment(stripped):
            # 直接丢弃，不输出
            continue

        # NOP 区域标记本身也不输出，只用于状态切换
        if stripped.startswith(nop_region_begin):
            in_nop_region = True
            nop_emitted = False
            # 不输出标记行本身
            continue

        if stripped.startswith(nop_region_end):
            in_nop_region = False
            nop_emitted = False
            # 不输出标记行本身
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
            # - 空行：忽略
            # - '.' 开头：伪指令，忽略
            # - '#' 开头：注释（行号/其它），忽略
            # - 以 ':' 结尾：标签，忽略
            # 其它非空行视作指令
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
            # 无论如何，不输出原指令行
            continue

        # 默认原样输出
        out.append(line)

    return out

def main():
    ap = argparse.ArgumentParser(
        description="Instrument STAGE1_BEGIN/END and compress NOP_REGION to a single nop (in-place)."
    )
    ap.add_argument("asm_file", help="Assembly file to process (will be overwritten)")
    ap.add_argument("--begin", default="STAGE1_BEGIN",
                    help="Begin label name (default: STAGE1_BEGIN)")
    ap.add_argument("--end", default="STAGE1_END",
                    help="End label name (default: STAGE1_END)")
    ap.add_argument("--nop-region-begin", default="# NOP_REGION_BEGIN",
                    help="Marker line indicating start of NOP region (default: '# NOP_REGION_BEGIN')")
    ap.add_argument("--nop-region-end", default="# NOP_REGION_END",
                    help="Marker line indicating end of NOP region (default: '# NOP_REGION_END')")

    args = ap.parse_args()

    asm_path = args.asm_file

    with open(asm_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    out_lines = process_asm(
        lines,
        begin_label=args.begin,
        end_label=args.end,
        nop_region_begin=args.nop_region_begin,
        nop_region_end=args.nop_region_end,
    )

    # 覆盖原文件
    with open(asm_path, "w", encoding="utf-8") as f:
        f.writelines(out_lines)

if __name__ == "__main__":
    main()