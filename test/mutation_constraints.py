# -*- coding: utf-8 -*-
"""
mutation_constraints.py

跨阶段变异约束与控制流敏感性闸门。

本模块提供：
  1. CFG 敏感指令集合（含 AT&T 所有大小后缀变体）
  2. PC 字符串归一化（解决 "0xb86" / "0x0000000000000b86" / "b86" 等多格式）
  3. 助记符归一化（AT&T q/l/w/b 后缀剥离，用于双向匹配）
  4. is_cfg_sensitive_instruction：判定一条解析后的指令是否为 CFG 敏感
  5. is_result_cfg_safe：判定变异结果（list of str）是否未引入 CFG 敏感
  6. DataDependencyAnalyzer：基于行索引的数据依赖前驱分析（用于软锁集）
  7. compute_soft_locked_line_indices：计算软锁集（行索引集合）

设计原则（选项 A）：
  Stage 2/3 中：
    - 不变异任何 CFG 敏感指令（含 call/ret/jmp/jcc/loop/int/syscall/ud2 等）
    - 不在任何位置插入 CFG 敏感指令
    - 不删除 CFG 敏感指令
    - 前阶段 locked_pcs 对应行 + 其数据依赖前驱 → 软锁集，仅允许等价变异
"""

import re
import logging

logger = logging.getLogger(__name__)


# ====================================================================
# 一、CFG 敏感指令集合（x86 AT&T，含所有大小后缀变体）
# ====================================================================

# 直接分支（无条件 + 条件）
# 注意：Jcc 类在 AT&T 中本身不带操作数大小后缀，jmp 有 jmpq/jmpl/jmpw 变体
CFG_SENSITIVE_DIRECT_BRANCH = frozenset({
    # 无条件跳转
    "jmp", "jmpq", "jmpl", "jmpw",
    # 条件跳转（Jcc）
    "je", "jz", "jne", "jnz",
    "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe",
    "js", "jns", "jo", "jno",
    "jp", "jpe", "jnp", "jpo",
    "jc", "jnc",
    "jcxz", "jecxz", "jrcxz",
})

# 调用与返回
CFG_SENSITIVE_CALL_RET = frozenset({
    "call", "callq", "calll",
    "ret", "retq", "retl", "retn",
    "retf", "lret", "lretq",
    "iret", "iretq", "iretd", "iretl",
})

# 异常/系统调用/陷阱
CFG_SENSITIVE_EXCEPTION = frozenset({
    "int", "int3", "into",
    "syscall", "sysenter", "sysexit", "sysret",
    "ud2", "ud0", "ud1",
    "hlt",
})

# 循环指令
CFG_SENSITIVE_LOOP = frozenset({
    "loop", "loopq", "loope", "loopne",
    "loopz", "loopnz",
})

# 所有 CFG 敏感助记符合集
CFG_SENSITIVE_ALL = (
    CFG_SENSITIVE_DIRECT_BRANCH
    | CFG_SENSITIVE_CALL_RET
    | CFG_SENSITIVE_EXCEPTION
    | CFG_SENSITIVE_LOOP
)


# ====================================================================
# 二、PC 字符串归一化
# ====================================================================

def normalize_pc(pc):
    """
    将 PC 归一化为小写、带 0x 前缀、无前导零的标准形式。

    输入支持：
      - "0xb86"      → "0xb86"
      - "0xB86"      → "0xb86"
      - "0x0000b86"  → "0xb86"
      - "b86"        → "0xb86"
      - 2950 (int)   → "0xb86"
      - "0x0"        → "0x0"
      - None / ""    → ""

    返回：归一化字符串，或空串（无法解析时）
    """
    if pc is None:
        return ""
    if isinstance(pc, int):
        return "0x{:x}".format(pc)
    if not isinstance(pc, str):
        return ""
    s = pc.strip().lower()
    if not s:
        return ""
    # 去掉 0x 前缀
    if s.startswith("0x"):
        s = s[2:]
    # 去掉前导零（但保留至少一位）
    s = s.lstrip("0") or "0"
    # 校验是否为合法十六进制
    if not re.match(r'^[0-9a-f]+$', s):
        return ""
    return "0x" + s


def normalize_pc_set(pc_iterable):
    """将 PC 集合/列表归一化为统一格式的 set"""
    if not pc_iterable:
        return set()
    result = set()
    for pc in pc_iterable:
        npc = normalize_pc(pc)
        if npc:
            result.add(npc)
    return result


# ====================================================================
# 三、助记符归一化（AT&T 后缀剥离）
# ====================================================================

# AT&T 操作数大小后缀
_ATT_SIZE_SUFFIXES = ('q', 'l', 'w', 'b')

# 不可剥离后缀的助记符前缀（这些天然以 q/l/w/b 结尾，剥离会误伤）
# 例如：cmp 不能剥成 cm，je 不能剥成 j
_NO_STRIP_FULL = frozenset({
    # Jcc 系列（天然不带大小后缀）
    "je", "jz", "jne", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno",
    "jp", "jpe", "jnp", "jpo", "jc", "jnc",
    "jcxz", "jecxz", "jrcxz",
    # Setcc 系列
    "sete", "setne", "setg", "setge", "setl", "setle",
    "seta", "setae", "setb", "setbe", "sets", "setns",
    "seto", "setno", "setp", "setnp", "setc", "setnc",
    "setz", "setnz",
    # Cmovcc 系列
    "cmove", "cmovne", "cmovg", "cmovge", "cmovl", "cmovle",
    "cmova", "cmovae", "cmovb", "cmovbe", "cmovs", "cmovns",
    "cmovo", "cmovno", "cmovp", "cmovnp", "cmovc", "cmovnc",
    "cmovz", "cmovnz",
    # 其他不可剥离
    "nop", "int", "int3", "ud2", "hlt",
    "syscall", "sysenter", "sysexit", "sysret",
})


def normalize_mnemonic(mn):
    """
    将助记符归一化。返回 (full_lower, stripped) 二元组。

    full_lower:  仅做小写处理的原始助记符
    stripped:    若末尾为 q/l/w/b 且不在不可剥离白名单中，则剥离；否则同 full_lower

    用于双向匹配：anchor 的 Intel 风格 "call" 与 seed 的 AT&T "callq" 互相匹配
    """
    if not mn:
        return "", ""
    full = mn.strip().lower()
    if not full:
        return "", ""
    if full in _NO_STRIP_FULL:
        return full, full
    # 仅当长度 >= 3 且末尾是 q/l/w/b 时考虑剥离
    if len(full) >= 3 and full[-1] in _ATT_SIZE_SUFFIXES:
        return full, full[:-1]
    return full, full


def mnemonics_match(mn1, mn2):
    """
    双向归一化匹配两个助记符。
    
    例子：
      mnemonics_match("call", "callq") → True
      mnemonics_match("movq", "mov")   → True
      mnemonics_match("je", "jne")     → False
      mnemonics_match("cmp", "cmpq")   → True
    """
    if not mn1 or not mn2:
        return False
    f1, s1 = normalize_mnemonic(mn1)
    f2, s2 = normalize_mnemonic(mn2)
    return f1 == f2 or s1 == s2 or f1 == s2 or s1 == f2


# ====================================================================
# 四、CFG 敏感判定
# ====================================================================

def is_cfg_sensitive_mnemonic(mn):
    """判定一个助记符（字符串）是否为 CFG 敏感"""
    if not mn:
        return False
    full, stripped = normalize_mnemonic(mn)
    return full in CFG_SENSITIVE_ALL or stripped in CFG_SENSITIVE_ALL


def is_cfg_sensitive_instruction(parsed):
    """
    判定一条 parse_asm_line 解析结果是否为 CFG 敏感指令。

    参数:
      parsed: parse_asm_line 的返回 dict

    返回:
      True / False
    """
    if not isinstance(parsed, dict):
        return False
    if parsed.get("kind") != "instruction":
        return False
    return is_cfg_sensitive_mnemonic(parsed.get("mnemonic") or "")


def is_cfg_sensitive_anchor(anchor):
    """判定一个 anchor JSON 是否为 CFG 敏感"""
    if not isinstance(anchor, dict):
        return False
    # 优先按 anchor_kinds 判定
    kinds = set(anchor.get("anchor_kinds", []) or [])
    if {"call_anchor", "branch_anchor", "ret_anchor",
        "indirect_jump_anchor", "syscall_anchor"} & kinds:
        return True
    # 回退按 mnemonic
    return is_cfg_sensitive_mnemonic(anchor.get("mnemonic") or "")


# ====================================================================
# 五、变异结果后置过滤
# ====================================================================

# 用于扫描变异结果文本中的助记符
_MNEMONIC_EXTRACT_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_\.]*)')


def _extract_mnemonic_from_text(line_text):
    """从一行汇编文本中提取助记符（小写）。返回 "" 表示无指令。"""
    if not line_text:
        return ""
    s = line_text.strip()
    # 跳过空行、注释、标签
    if not s or s.startswith('#') or s.startswith('//'):
        return ""
    if s.endswith(':'):
        return ""
    # 跳过 directive
    if s.startswith('.'):
        return ""
    m = _MNEMONIC_EXTRACT_RE.match(s)
    if not m:
        return ""
    return m.group(1).lower()


def is_result_cfg_safe(result):
    """
    判定变异算子的结果（list of str 或 单个 str）是否不含 CFG 敏感指令。

    返回 True 表示安全（可使用）；False 表示包含 CFG 敏感，应拒绝。

    注意：
      - 不解析整行结构，只提取首 token 作为助记符
      - 对每一行都检查，任何一行 CFG 敏感即拒绝整体
    """
    if result is None:
        return True
    if isinstance(result, str):
        lines = [result]
    elif isinstance(result, list):
        lines = result
    else:
        return True

    for line in lines:
        if not isinstance(line, str):
            continue
        # 多行字符串拆开
        for sub in line.split('\n'):
            mn = _extract_mnemonic_from_text(sub)
            if mn and is_cfg_sensitive_mnemonic(mn):
                return False
    return True


# ====================================================================
# 六、寄存器读写提取（用于 DDG）
# ====================================================================

# 寄存器别名 → 规范名（64 位）
_REG_CANONICAL = {
    # rax 族
    "rax": "rax", "eax": "rax", "ax": "rax", "ah": "rax", "al": "rax",
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bh": "rbx", "bl": "rbx",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "ch": "rcx", "cl": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dh": "rdx", "dl": "rdx",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    "r8":  "r8",  "r8d":  "r8",  "r8w":  "r8",  "r8b":  "r8",
    "r9":  "r9",  "r9d":  "r9",  "r9w":  "r9",  "r9b":  "r9",
    "r10": "r10", "r10d": "r10", "r10w": "r10", "r10b": "r10",
    "r11": "r11", "r11d": "r11", "r11w": "r11", "r11b": "r11",
    "r12": "r12", "r12d": "r12", "r12w": "r12", "r12b": "r12",
    "r13": "r13", "r13d": "r13", "r13w": "r13", "r13b": "r13",
    "r14": "r14", "r14d": "r14", "r14w": "r14", "r14b": "r14",
    "r15": "r15", "r15d": "r15", "r15w": "r15", "r15b": "r15",
    # rip
    "rip": "rip", "eip": "rip", "ip": "rip",
    # flags
    "rflags": "rflags", "eflags": "rflags", "flags": "rflags",
}

_REG_TOKEN_RE = re.compile(r'%([A-Za-z][A-Za-z0-9]*)')


def _canonicalize_reg(reg_name):
    """规范化寄存器名（去 % 前缀，转小写，归并到 64 位族名）"""
    if not reg_name:
        return None
    r = reg_name.lstrip('%').lower()
    return _REG_CANONICAL.get(r)


def _extract_regs_from_operand(operand_str):
    """从一个操作数字符串中提取所有寄存器（规范名 set）"""
    if not operand_str:
        return set()
    regs = set()
    for m in _REG_TOKEN_RE.finditer(operand_str):
        canon = _canonicalize_reg(m.group(1))
        if canon:
            regs.add(canon)
    return regs


# 改写所有操作数的指令（dst 不含读语义，仅写）
# 在 AT&T 中，目标是最后一个操作数
_WRITE_ONLY_DST_MNEMONICS = frozenset({
    "mov", "movq", "movl", "movw", "movb",
    "movabs", "movabsq",
    "movzx", "movzbl", "movzwl", "movzbq", "movzwq",
    "movsx", "movsbl", "movswl", "movsbq", "movswq", "movslq", "movsxd",
    "lea", "leaq", "leal", "leaw",
})

# 读写都做的算术/逻辑指令（dst 既读又写）
_READ_MODIFY_WRITE_MNEMONICS = frozenset({
    "add", "addq", "addl", "addw", "addb",
    "sub", "subq", "subl", "subw", "subb",
    "and", "andq", "andl", "andw", "andb",
    "or",  "orq",  "orl",  "orw",  "orb",
    "xor", "xorq", "xorl", "xorw", "xorb",
    "shl", "shlq", "shll", "shlw", "shlb",
    "shr", "shrq", "shrl", "shrw", "shrb",
    "sal", "salq", "sall", "salw", "salb",
    "sar", "sarq", "sarl", "sarw", "sarb",
    "rol", "rolq", "roll",
    "ror", "rorq", "rorl",
    "adc", "adcq", "adcl",
    "sbb", "sbbq", "sbbl",
    "inc", "incq", "incl", "incw", "incb",
    "dec", "decq", "decl", "decw", "decb",
    "neg", "negq", "negl",
    "not", "notq", "notl",
    "imul", "imulq", "imull",
})

# 仅读，不写任何寄存器（仅影响 flags）
_READ_ONLY_MNEMONICS = frozenset({
    "cmp", "cmpq", "cmpl", "cmpw", "cmpb",
    "test", "testq", "testl", "testw", "testb",
})

# 栈操作（隐式读写 rsp）
_STACK_PUSH = frozenset({"push", "pushq", "pushl", "pushw"})
_STACK_POP = frozenset({"pop", "popq", "popl", "popw"})


def extract_reg_read_write(parsed):
    """
    从一条解析指令中提取读寄存器集合与写寄存器集合（规范名）。

    返回 (reads_set, writes_set)

    设计：保守策略 — 不确定时归入读集合（防止漏锁）
    """
    reads = set()
    writes = set()

    if not isinstance(parsed, dict) or parsed.get("kind") != "instruction":
        return reads, writes

    mn = (parsed.get("mnemonic") or "").lower()
    operands = parsed.get("operands") or []

    if not mn:
        return reads, writes

    # 栈操作：隐式读写 rsp
    if mn in _STACK_PUSH:
        # push src: 读 src, 读写 rsp
        if operands:
            reads |= _extract_regs_from_operand(operands[0])
        reads.add("rsp")
        writes.add("rsp")
        return reads, writes

    if mn in _STACK_POP:
        # pop dst: 写 dst, 读写 rsp
        if operands:
            # 在 AT&T 中 pop 的操作数本身就是目标
            writes |= _extract_regs_from_operand(operands[0])
        reads.add("rsp")
        writes.add("rsp")
        return reads, writes

    # leave: 等价于 mov rbp,rsp; pop rbp
    if mn in ("leave", "leaveq"):
        reads.add("rbp")
        writes.add("rbp")
        writes.add("rsp")
        return reads, writes

    # 所有源操作数中的寄存器都算读
    # AT&T 中：最后一个操作数是 dst，前面是 src
    if not operands:
        return reads, writes

    # 单操作数指令（inc/dec/neg/not/idiv/mul 等）
    if len(operands) == 1:
        op_regs = _extract_regs_from_operand(operands[0])
        if mn in _WRITE_ONLY_DST_MNEMONICS:
            writes |= op_regs
        elif mn in _READ_ONLY_MNEMONICS:
            reads |= op_regs
        elif mn in _READ_MODIFY_WRITE_MNEMONICS:
            reads |= op_regs
            writes |= op_regs
        else:
            # 保守：归入读
            reads |= op_regs
        return reads, writes

    # 多操作数：最后一个是 dst（AT&T 顺序）
    src_operands = operands[:-1]
    dst_operand = operands[-1]

    # 收集所有源操作数寄存器（都是读）
    for src in src_operands:
        reads |= _extract_regs_from_operand(src)

    # 目标操作数寄存器
    dst_regs = _extract_regs_from_operand(dst_operand)

    # 如果目标是内存形式（包含 ( 或 [ ），则其内部寄存器是读，不是写
    if '(' in dst_operand or '[' in dst_operand:
        reads |= dst_regs
    else:
        # 纯寄存器目标
        if mn in _WRITE_ONLY_DST_MNEMONICS:
            writes |= dst_regs
        elif mn in _READ_ONLY_MNEMONICS:
            reads |= dst_regs
        elif mn in _READ_MODIFY_WRITE_MNEMONICS:
            reads |= dst_regs
            writes |= dst_regs
        else:
            # 保守：归入读
            reads |= dst_regs

    return reads, writes


# ====================================================================
# 七、数据依赖前驱分析（基于行索引）
# ====================================================================

class DataDependencyAnalyzer(object):
    """
    基于行索引的数据依赖前驱分析器。

    对于给定的一组锚定行索引，向上回溯找出其数据依赖前驱（写入了被这些行读取的寄存器的指令）。

    设计要点：
      - 仅在基本块内回溯，遇到 label / CFG 敏感指令即停止（控制流边界）
      - 仅追踪寄存器依赖（栈/内存依赖暂不追踪，保守归入读但不向前传播）
      - 最大回溯深度可配置，避免过度扩散
    """

    def __init__(self, asm_lines, max_lookback=20, max_depth=3):
        """
        参数:
          asm_lines:    种子汇编行列表
          max_lookback: 单条锚定指令向上回溯的最大行数
          max_depth:    依赖链最大深度
        """
        self.asm_lines = asm_lines
        self.max_lookback = max_lookback
        self.max_depth = max_depth

        # 预解析所有行
        from mutation_scheduler import parse_asm_line  # 按你的实际模块路径调整
        self._parsed_cache = [parse_asm_line(l) for l in asm_lines]

    def _is_boundary(self, parsed):
        """判定是否为基本块边界（停止回溯）"""
        if not isinstance(parsed, dict):
            return True
        kind = parsed.get("kind")
        if kind == "label":
            return True
        # directive 中的 .L 局部标签也是边界
        if kind == "directive":
            mn = (parsed.get("mnemonic") or "")
            if re.match(r'^\.[Ll][A-Za-z0-9_]+$', mn):
                return True
        if kind == "instruction" and is_cfg_sensitive_instruction(parsed):
            return True
        return False

    def find_predecessors(self, anchor_line_indices):
        """
        计算给定锚定行集合的数据依赖前驱行集合。

        参数:
          anchor_line_indices: set[int]，初始锚定的行索引

        返回:
          set[int]：前驱行索引集合（不包含输入的锚定行本身）
        """
        if not anchor_line_indices:
            return set()

        predecessors = set()
        # BFS 按依赖层级
        # 每个待处理项：(line_idx, depth, regs_needed)
        worklist = []
        for idx in anchor_line_indices:
            if 0 <= idx < len(self._parsed_cache):
                parsed = self._parsed_cache[idx]
                if parsed.get("kind") == "instruction":
                    reads, _ = extract_reg_read_write(parsed)
                    if reads:
                        worklist.append((idx, 0, reads))

        # 防止重复访问
        visited = set()

        while worklist:
            cur_idx, depth, needed_regs = worklist.pop(0)

            if depth >= self.max_depth:
                continue
            if not needed_regs:
                continue

            # 向上回溯
            remaining = set(needed_regs)
            steps = 0
            j = cur_idx - 1
            while j >= 0 and steps < self.max_lookback and remaining:
                steps += 1
                parsed_j = self._parsed_cache[j]

                # 边界：停止
                if self._is_boundary(parsed_j):
                    break

                if parsed_j.get("kind") != "instruction":
                    j -= 1
                    continue

                reads_j, writes_j = extract_reg_read_write(parsed_j)
                # 若该指令写入了我们需要的寄存器之一 → 是前驱
                killed = remaining & writes_j
                if killed:
                    if j not in predecessors and j not in anchor_line_indices:
                        predecessors.add(j)
                        # 该前驱自身的读 → 下一层依赖
                        if (j, depth + 1) not in visited:
                            visited.add((j, depth + 1))
                            if reads_j and depth + 1 < self.max_depth:
                                worklist.append((j, depth + 1, set(reads_j)))
                    # 该寄存器已被定义，不再向更上层追溯
                    remaining -= killed

                j -= 1

        return predecessors


# ====================================================================
# 八、软锁集计算（行索引）
# ====================================================================

def compute_soft_locked_line_indices(asm_lines, hard_locked_pcs, pc_to_line_map,
                                     max_lookback=20, max_depth=3):
    """
    基于硬锁定 PC 集合，计算软锁定行索引集合。

    流程：
      1. 将 hard_locked_pcs 通过 pc_to_line_map 映射为锚定行索引集合
      2. 使用 DataDependencyAnalyzer 计算数据依赖前驱行索引
      3. 返回软锁集（不包含硬锁定行本身，由调用方分别处理）

    参数:
      asm_lines:        种子汇编行列表
      hard_locked_pcs:  跨阶段硬锁定 PC 集合（任意格式）
      pc_to_line_map:   {normalized_pc: line_idx}

    返回:
      dict:
        "hard_locked_lines": set[int]    硬锁定行（前阶段已变异，本阶段不可触碰）
        "soft_locked_lines": set[int]    软锁定行（前驱，仅允许等价变异）
    """
    hard_pcs_norm = normalize_pc_set(hard_locked_pcs)

    # 映射 PC → 行索引
    hard_lines = set()
    for pc in hard_pcs_norm:
        idx = pc_to_line_map.get(pc)
        if idx is not None:
            hard_lines.add(idx)

    if not hard_lines:
        return {
            "hard_locked_lines": set(),
            "soft_locked_lines": set(),
        }

    # 计算前驱
    analyzer = DataDependencyAnalyzer(
        asm_lines, max_lookback=max_lookback, max_depth=max_depth)
    soft_lines = analyzer.find_predecessors(hard_lines)
    # 去掉与硬锁定重叠的部分（硬锁定优先）
    soft_lines -= hard_lines

    return {
        "hard_locked_lines": hard_lines,
        "soft_locked_lines": soft_lines,
    }


# ====================================================================
# 九、等价变异判定（用于软锁定行）
# ====================================================================

# 已知的"等价"变异算子白名单（不改变寄存器读写关系，不改变值）
# 这些算子可应用于软锁定行
EQUIVALENT_MUTATORS = frozenset({
    "swap_independent_instructions",   # 调换相邻独立指令顺序
    "insert_nop_before",                # 在前面插入 nop
    "insert_nop_after",                 # 在后面插入 nop
    "insert_fence_before",              # 在前面插入 lfence/mfence（不改语义）
    "rename_to_equivalent_register",    # 等价寄存器重命名（需要全局重命名）
})


def is_equivalent_mutator(mutator_name):
    """判定一个变异算子名是否为等价变异"""
    if not mutator_name:
        return False
    return mutator_name in EQUIVALENT_MUTATORS