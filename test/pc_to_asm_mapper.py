#!/usr/bin/env python3
"""
pc_to_asm_mapper.py

将 anchors.json 中的 PC 地址映射到 .s 汇编文件中的行号。

映射原理:
  1. 将 victim .c 编译为 .o（带调试信息 -g）
  2. 用 objdump -d 反汇编 .o，得到 offset → 指令 的映射
  3. 用 objdump -d 同时可以得到 .text section 的起始偏移
  4. anchors.json 中的 PC 是链接后的虚拟地址，需要减去 .text base
     或直接用 objdump 的 offset 匹配
  5. 将 .o 的反汇编指令与 .s 中的指令做模式匹配

更稳健的方案:
  gcc -S -g 生成的 .s 文件包含 .loc 指令（源文件行号），
  但不包含地址信息。所以我们用 mnemonic + operands 做模糊匹配。

  具体做法:
  - 从 anchors.json 取 pc + disasm（反汇编文本）
  - 在 .s 文件中搜索匹配的指令行
  - 返回 {pc: line_number} 映射

用法:
  mapper = PcToAsmMapper("seed_0.s", anchors)
  line_no = mapper.get_line(pc="0x7da")
"""

import re
import os
import subprocess
import json
import sys


class PcToAsmMapper:
    """PC 地址到 .s 行号的映射器"""

    def __init__(self, asm_path, anchors=None):
        """
        参数:
          asm_path: .s 汇编文件路径
          anchors: anchor 列表（从 anchors.json 加载）
        """
        self.asm_path = asm_path
        self.anchors = anchors or []
        self.asm_lines = []
        self.pc_to_line = {}  # pc -> line_number (0-based)
        self.line_to_pc = {}  # line_number -> pc

        self._load_asm()
        if self.anchors:
            self._build_mapping()

    def _load_asm(self):
        """加载 .s 文件"""
        with open(self.asm_path, "r") as f:
            self.asm_lines = f.readlines()

    def _normalize_asm_operand(self, operand):
        """
        标准化汇编操作数，使 AT&T 和 Intel 语法可以匹配。

        Intel: mov qword ptr [rbp - 8], rdi
        AT&T:  movq %rdi, -8(%rbp)

        返回标准化后的 token 集合（用于模糊匹配）。
        """
        s = operand.lower().strip()
        # 去除大小修饰
        for prefix in ["byte ptr ", "word ptr ", "dword ptr ", "qword ptr ",
                        "xmmword ptr ", "ymmword ptr "]:
            s = s.replace(prefix, "")
        # 去除 % 前缀 (AT&T) 和 $ 前缀
        s = s.replace("%", "").replace("$", "")
        # 统一空格
        s = re.sub(r"\s+", " ", s).strip()
        # 提取所有标识符和数字
        tokens = set(re.findall(r"[a-z0-9_]+", s))
        return tokens

    def _match_instruction(self, anchor_disasm, asm_line):
        """
        检查 anchor 的反汇编文本是否与 .s 文件中的某行匹配。

        使用宽松匹配: mnemonic 相同且操作数 token 有足够重叠。
        """
        asm_stripped = asm_line.strip()

        # 跳过非指令行
        if not asm_stripped:
            return False
        if asm_stripped.startswith(".") or asm_stripped.startswith("#"):
            return False
        if asm_stripped.endswith(":"):
            return False

        # 从 anchor_disasm 提取 mnemonic
        # 格式: "mov qword ptr [rbp - 8], rdi" 或 "cmp qword ptr [rbp - 8], rax"
        anchor_parts = anchor_disasm.strip().split(None, 1)
        if not anchor_parts:
            return False
        anchor_mnemonic = anchor_parts[0].lower()

        # 从 .s 行提取 mnemonic
        # AT&T 格式: "movq %rdi, -8(%rbp)" or "cmpq -8(%rbp), %rax"
        asm_parts = asm_stripped.split(None, 1)
        if not asm_parts:
            return False
        asm_mnemonic = asm_parts[0].lower()

        # mnemonic 匹配（考虑 AT&T 后缀: movq vs mov, cmpq vs cmp）
        base_anchor = re.sub(r"[bwlq]$", "", anchor_mnemonic)
        base_asm = re.sub(r"[bwlq]$", "", asm_mnemonic)
        if base_anchor != base_asm:
            return False

        # 操作数 token 匹配
        if len(anchor_parts) > 1 and len(asm_parts) > 1:
            anchor_tokens = self._normalize_asm_operand(anchor_parts[1])
            asm_tokens = self._normalize_asm_operand(asm_parts[1])

            # 要求至少有一半的 token 重叠
            if not anchor_tokens or not asm_tokens:
                return True  # 无操作数，mnemonic 匹配即可

            overlap = anchor_tokens & asm_tokens
            min_size = min(len(anchor_tokens), len(asm_tokens))
            if min_size > 0 and len(overlap) >= max(1, min_size // 2):
                return True
            return False
        else:
            # 无操作数的指令（如 nop, ret）
            return True

    def _build_mapping(self):
        """构建 PC → 行号映射"""
        # 为每个 anchor，在 .s 文件中搜索匹配的行
        for anchor in self.anchors:
            pc = anchor.get("pc", "")
            disasm = anchor.get("disasm", "")
            mnemonic = anchor.get("mnemonic", "")

            if not pc or not disasm:
                continue

            # 搜索匹配行（可能有多个匹配，取第一个）
            matches = []
            for line_no, line in enumerate(self.asm_lines):
                if self._match_instruction(disasm, line):
                    matches.append(line_no)

            if matches:
                # 如果有多个匹配，优先选 STAGE1_BEGIN/END 区域内的
                best = self._select_best_match(matches)
                self.pc_to_line[pc] = best
                self.line_to_pc[best] = pc

    def _select_best_match(self, line_numbers):
        """
        如果有多个匹配行，选择最可能的那个。
        优先选 STAGE1_BEGIN 和 STAGE1_END 之间的行。
        """
        stage1_begin = None
        stage1_end = None

        for i, line in enumerate(self.asm_lines):
            stripped = line.strip()
            if stripped == "STAGE1_BEGIN:" or "STAGE1_BEGIN" in stripped:
                stage1_begin = i
            if stripped == "STAGE1_END:" or "STAGE1_END" in stripped:
                stage1_end = i

        if stage1_begin is not None and stage1_end is not None:
            in_window = [ln for ln in line_numbers
                         if stage1_begin <= ln <= stage1_end]
            if in_window:
                return in_window[0]

        return line_numbers[0]

    def get_line(self, pc):
        """获取 PC 对应的行号（0-based），未找到返回 -1"""
        return self.pc_to_line.get(pc, -1)

    def get_line_content(self, pc):
        """获取 PC 对应的行内容"""
        line_no = self.get_line(pc)
        if line_no < 0 or line_no >= len(self.asm_lines):
            return None
        return self.asm_lines[line_no]

    def get_all_mappings(self):
        """返回所有映射"""
        return dict(self.pc_to_line)

    def get_mapped_anchor_count(self):
        """返回成功映射的 anchor 数量"""
        return len(self.pc_to_line)

    def print_mappings(self):
        """打印所有映射"""
        print("PC -> Line mappings ({} anchors mapped):".format(
            len(self.pc_to_line)))
        for pc, line_no in sorted(self.pc_to_line.items()):
            content = self.asm_lines[line_no].rstrip() if line_no < len(self.asm_lines) else "?"
            print("  {} -> L{}: {}".format(pc, line_no + 1, content))


def build_mapping_via_objdump(c_file, anchors, gcc="gcc"):
    """
    更精确的映射方案: 通过 objdump 反汇编对齐。

    1. gcc -c -g c_file → .o
    2. objdump -d .o → 得到 offset:instruction 列表
    3. 同时 gcc -S c_file → .s
    4. 将 objdump 的指令序列与 .s 的指令序列对齐
    5. anchors 中的 PC 通过 objdump offset 映射到 .s 行号
    """
    import tempfile

    obj_file = tempfile.mktemp(suffix=".o")
    try:
        # 编译为 .o
        res = subprocess.run(
            [gcc, "-c", "-g", "-O0", c_file, "-o", obj_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res.returncode != 0:
            sys.stderr.write("objdump mapping: compile failed\n")
            return {}

        # 反汇编
        res = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", obj_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res.returncode != 0:
            sys.stderr.write("objdump mapping: objdump failed\n")
            return {}

        objdump_lines = res.stdout.decode("utf-8", errors="ignore").splitlines()

        # 解析 objdump 输出: offset → (mnemonic, operands)
        # 格式: "  7da:	cmp    -0x8(%rbp),%rax"
        offset_map = {}  # offset_hex → (mnemonic, full_line)
        pattern = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)")
        for line in objdump_lines:
            m = pattern.match(line)
            if m:
                offset_hex = m.group(1)
                mnem = m.group(2)
                ops = m.group(3).strip()
                offset_map[offset_hex] = (mnem, ops, line.strip())

        # 为每个 anchor，在 offset_map 中查找
        # anchor 的 pc 是链接后的地址，.o 中的 offset 从 0 开始
        # 需要找到 base offset
        # 尝试: 如果 anchor pc 能直接在 offset_map 中找到（可能是相对地址）
        anchor_offsets = {}
        for anchor in anchors:
            pc = anchor.get("pc", "")
            if not pc:
                continue
            # 去掉 0x 前缀
            pc_hex = pc.lower().replace("0x", "")
            if pc_hex in offset_map:
                anchor_offsets[pc] = pc_hex

        # 如果直接匹配没找到，尝试减去一个 base
        if not anchor_offsets and anchors and offset_map:
            # 找 anchors 中最小的 PC
            anchor_pcs = []
            for a in anchors:
                try:
                    anchor_pcs.append(int(a["pc"], 16))
                except (KeyError, ValueError):
                    pass
            if anchor_pcs:
                min_anchor_pc = min(anchor_pcs)
                # 找 objdump 中最小的 offset
                obj_offsets = [int(k, 16) for k in offset_map.keys()]
                min_obj_offset = min(obj_offsets) if obj_offsets else 0
                # base = min_anchor_pc - min_obj_offset（近似）
                # 更好的方法：找到 spectre_function 的起始
                for offset_hex, (mnem, ops, _) in offset_map.items():
                    # 不可靠，跳过
                    pass

        return anchor_offsets

    finally:
        if os.path.exists(obj_file):
            os.remove(obj_file)


# CLI 入口
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Map PC addresses from anchors.json to .s line numbers."
    )
    ap.add_argument("asm_file", help="Assembly (.s) file")
    ap.add_argument("--anchors-json", required=True, help="anchors.json path")
    args = ap.parse_args()

    with open(args.anchors_json) as f:
        anchors = json.load(f)

    mapper = PcToAsmMapper(args.asm_file, anchors)
    mapper.print_mappings()
    print("\nTotal anchors: {}".format(len(anchors)))
    print("Mapped: {}".format(mapper.get_mapped_anchor_count()))