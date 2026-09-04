#!/usr/bin/env python3
"""
mutation_scheduler.py

变异调度器（完整实现）。

核心设计：
  1. 概率驱动多点变异：每轮遍历所有指令行，每条指令以不同概率决定是否变异
  2. 基于 anchor 的 causal_objects 选择变异算子
  3. 组合变异策略（Spectre v1/v2/v4/RSB/Meltdown 模式）
  4. 保护机制：插桩标签、驱动函数调用不可删除（但函数实现可变异）
  5. 崩溃保留（不做语义引导规避）
  6. Stage 3 通过配置文件变异 flush-reload 参数
  7. 循环摘要感知：循环体内指令降低概率，循环边界指令提升概率
  8. Spectre RSB 栈帧分析：允许对非 ABI 必须的栈帧指令变异

Compatible with Python 3.6+.
"""

import random
import re
import os
import copy
import shutil
import tempfile
import logging
import json

from mutation_constraints import (
    # 常量
    CFG_SENSITIVE_ALL,
    # PC / 助记符
    normalize_pc,
    normalize_pc_set,
    mnemonics_match,
    # CFG 判定
    is_cfg_sensitive_mnemonic,
    is_cfg_sensitive_instruction,
    is_cfg_sensitive_anchor,
    # 结果过滤
    is_result_cfg_safe,
    # 软锁集
    compute_soft_locked_line_indices,
    # 等价变异
    is_equivalent_mutator,
    EQUIVALENT_MUTATORS,
)

logger = logging.getLogger("mutation_scheduler")


# ====================================================================
# 第一部分：常量与配置
# ====================================================================

# Tier -> 基础变异概率（差距适中保证多样性）
TIER_BASE_PROBABILITY = {
    "primary":     0.55,
    "secondary":   0.40,
    "contextual":  0.35,
}

# 非 anchor 指令的基础变异概率
NON_ANCHOR_BASE_PROBABILITY = 0.10

# 强因果对象加成
STRONG_CAUSAL_BOOST = 1.3

# 非强相关 Anchor 衰减
WEAK_CAUSAL_DECAY = 0.7

# 序言/尾声指令概率衰减
PROLOGUE_EPILOGUE_DECAY = 0.4

# 循环体内指令衰减
LOOP_BODY_DECAY = 0.5

# 循环边界指令加成
LOOP_BOUND_BOOST = 1.4

# 条件分支助记符
BRANCH_MNEMONICS = frozenset({
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno",
    "jp", "jnp", "jcxz", "jecxz", "jrcxz",
    "loop", "loope", "loopne",
})

# 无条件跳转
UNCONDITIONAL_JUMP_MNEMONICS = frozenset({"jmp", "jmpq"})

# 比较助记符
COMPARE_MNEMONICS = frozenset({"cmp", "test"})

# 算术助记符
ARITHMETIC_MNEMONICS = frozenset({
    "add", "sub", "imul", "mul", "idiv", "div",
    "inc", "dec", "neg", "not",
    "and", "or", "xor",
    "shl", "shr", "sal", "sar", "rol", "ror",
    "adc", "sbb",
})

# 移动类助记符
MOVE_MNEMONICS = frozenset({
    "mov", "movl", "movq", "movw", "movb",
    "movzx", "movsx", "movsxd",
    "lea",
    "cmovl", "cmovle", "cmovg", "cmovge",
    "cmove", "cmovne", "cmovs", "cmovns",
    "cmova", "cmovae", "cmovb", "cmovbe",
})

# 不可变异的伪指令/指令
IMMUTABLE_MNEMONICS = frozenset({
    ".cfi_startproc", ".cfi_endproc", ".cfi_def_cfa_offset",
    ".cfi_offset", ".cfi_def_cfa_register", ".cfi_restore",
    ".cfi_def_cfa", ".cfi_remember_state", ".cfi_restore_state",
    ".type", ".size", ".globl", ".global", ".section",
    ".text", ".data", ".bss", ".rodata",
    ".align", ".p2align", ".balign",
    ".file", ".ident", ".comm", ".local",
    ".byte", ".word", ".long", ".quad", ".ascii", ".asciz", ".string",
    ".zero", ".space", ".set", ".equ",
    ".weak", ".hidden", ".protected", ".internal",
    ".loc", ".loc_is_stmt",
})

# 条件分支反转映射
BRANCH_INVERSION = {
    "je": "jne", "jne": "je",
    "jz": "jnz", "jnz": "jz",
    "jg": "jle", "jle": "jg",
    "jge": "jl", "jl": "jge",
    "ja": "jbe", "jbe": "ja",
    "jae": "jb", "jb": "jae",
    "js": "jns", "jns": "js",
    "jo": "jno", "jno": "jo",
    "jp": "jnp", "jnp": "jp",
}

# 条件分支替换候选
BRANCH_ALTERNATIVES = {
    "je":  ["jne", "jl", "jg", "jle", "jge"],
    "jne": ["je",  "jl", "jg", "jle", "jge"],
    "jl":  ["jg",  "jle", "jge", "je", "jne"],
    "jg":  ["jl",  "jle", "jge", "je", "jne"],
    "jle": ["jge", "jl", "jg", "je", "jne"],
    "jge": ["jle", "jl", "jg", "je", "jne"],
    "ja":  ["jb",  "jae", "jbe"],
    "jb":  ["ja",  "jae", "jbe"],
    "jae": ["jbe", "ja", "jb"],
    "jbe": ["jae", "ja", "jb"],
}

# 算术操作码互换组
ARITHMETIC_SWAP_GROUPS = [
    ["add", "sub"],
    ["inc", "dec"],
    ["and", "or", "xor"],
    ["shl", "shr"],
    ["sal", "sar"],
    ["rol", "ror"],
]

# 通用寄存器池（按 size 分组）
GENERAL_REGS_64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                   "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
GENERAL_REGS_32 = ["eax", "ebx", "ecx", "edx", "esi", "edi",
                   "r8d", "r9d", "r10d", "r11d", "r12d", "r13d",
                   "r14d", "r15d"]
GENERAL_REGS_16 = ["ax", "bx", "cx", "dx", "si", "di"]
GENERAL_REGS_8  = ["al", "bl", "cl", "dl", "sil", "dil"]

# 保护标签
PROTECTED_LABELS = frozenset({
    "STAGE1_BEGIN", "STAGE1_END",
    "STAGE2_BEGIN", "STAGE2_END",
    "STAGE3_BEGIN", "STAGE3_END",
})

# 保护函数调用目标（call 指令不可删除）
PROTECTED_CALL_TARGETS = frozenset({
    # PMU
    "pmu_stage1_before", "pmu_stage1_after",
    "pmu_stage1_indirect_before", "pmu_stage1_indirect_after",
    "pmu_stage1_disambiguation_before", "pmu_stage1_disambiguation_after",
    "pmu_stage1_return_before", "pmu_stage1_return_after",
    "pmu_stage1_set_phase",
    "pmu_read_l1d_miss", "pmu_read_uops",
    # Victim Framework API
    "vf_run_attack_once",
    "vf_get_probe_addr_for_secret", "vf_prepare_probe_region",
    # Stage 3
    "stage3_run_single_reuse_secret",
    "stage3_flush_line", "stage3_reload_timed",
    # 系统
    "printf", "fprintf", "puts", "putchar",
    "malloc", "free", "calloc", "realloc",
    "memset", "memcpy", "mmap", "munmap",
    "clock_gettime", "rand_r", "srand",
    "__stack_chk_fail",
})

# 函数定义标签保护（标签本身不可删除，但函数实现内的指令可变异）
PROTECTED_FUNCTION_LABELS = frozenset({
    "vf_run_attack_once",
    "vf_get_probe_addr_for_secret", "vf_prepare_probe_region",
    "victim_function", "victim_function_v1",
    "main",
})

# Spectre RSB 相关：栈帧操作指令模式
RSB_STACK_PATTERNS = [
    # push rbp; mov rbp, rsp 标准序言
    (r"push\s+%?rbp", r"mov\s+%?rsp\s*,\s*%?rbp|mov\s+%?rbp\s*,\s*%?rsp"),
    # pop rbp; ret 标准尾声
    (r"pop\s+%?rbp", r"ret"),
    # sub rsp, XX 栈分配
    (r"sub\s+.*%?rsp", None),
    # add rsp, XX 栈回收
    (r"add\s+.*%?rsp", None),
]


# ====================================================================
# 第二部分：Stage 3 配置变异
# ====================================================================

STAGE3_DETECTION_ROUNDS = 20
STAGE3_DETECTION_CANDIDATES = 256

STAGE3_DEFAULT_CONFIG = {
    "cache_hit_threshold": {
        "default": 80,
        "range": [40, 200],
        "step_choices": [-20, -10, -5, 5, 10, 20, 40],
        "description": "cache hit 判定阈值 (CPU cycles)",
    },
    "probe_stride": {
        "default": 512,
        "choices": [64, 128, 256, 512, 1024, 2048, 4096],
        "description": "probe array 访问步长 (bytes)",
    },
    "attack_repetitions": {
        "default": 1,
        "choices": [1, 2, 3, 5, 10],
        "description": "每轮攻击重复次数",
    },
    "noise_range_start": {
        "default": 1,
        "choices": [0, 1, 2],
        "description": "噪声过滤起始候选值",
    },
    "noise_range_end": {
        "default": 16,
        "choices": [8, 16, 32, 48],
        "description": "噪声过滤结束候选值",
    },
    "use_poc_permutation": {
        "default": 1,
        "choices": [0, 1],
        "description": "是否使用 PoC 风格排列扫描",
    },
    "flush_wait_cycles": {
        "default": 100,
        "choices": [0, 50, 100, 200, 500],
        "description": "flush 后等待空转次数",
    },
    "reload_wait_cycles": {
        "default": 100,
        "choices": [0, 50, 100, 200, 500],
        "description": "attack 后到 reload 前的等待空转次数",
    },
}


def generate_stage3_config_variant(base_config=None):
    """
    生成一个 Stage 3 配置变异体。

    参数:
      base_config: 基础配置（为 None 时使用默认值）

    返回:
      dict: 变异后的配置
    """
    config = {}
    for key, spec in STAGE3_DEFAULT_CONFIG.items():
        base_val = spec["default"]
        if base_config and key in base_config:
            base_val = base_config[key]

        if "choices" in spec:
            config[key] = random.choice(spec["choices"])
        elif "range" in spec:
            delta = random.choice(spec["step_choices"])
            val = base_val + delta
            val = max(spec["range"][0], min(spec["range"][1], val))
            config[key] = val
        else:
            config[key] = base_val
    return config


def write_stage3_config(config, output_path):
    """将 Stage 3 配置写入 JSON 文件"""
    persisted_config = {
        key: value for key, value in config.items()
        if key in STAGE3_DEFAULT_CONFIG
    }
    with open(output_path, 'w') as f:
        json.dump(persisted_config, f, indent=2)
    return output_path


def generate_stage3_env(config):
    """将 Stage 3 配置转换为环境变量字典"""
    env_map = {
        "cache_hit_threshold": "STAGE3_CACHE_HIT_THRESHOLD",
        "probe_stride": "STAGE3_PROBE_STRIDE",
        "attack_repetitions": "STAGE3_ATTACK_REPS",
        "noise_range_start": "STAGE3_NOISE_START",
        "noise_range_end": "STAGE3_NOISE_END",
        "use_poc_permutation": "STAGE3_USE_PERMUTATION",
        "flush_wait_cycles": "STAGE3_FLUSH_WAIT",
        "reload_wait_cycles": "STAGE3_RELOAD_WAIT",
    }
    env = {
        "STAGE3_ROUNDS": str(STAGE3_DETECTION_ROUNDS),
        "STAGE3_CANDIDATE_COUNT": str(STAGE3_DETECTION_CANDIDATES),
    }
    for key, env_var in env_map.items():
        if key in config:
            env[env_var] = str(config[key])
    return env


# ====================================================================
# 第三部分：汇编行解析辅助
# ====================================================================

def parse_asm_line(line):
    """
    解析一行汇编，返回结构化信息。

    返回 dict:
      kind:       'label' | 'directive' | 'instruction' | 'empty'
      mnemonic:   助记符 (小写) 或 None
      operands:   操作数列表 (字符串)
      raw:        原始行（含换行符）
      indent:     缩进
      comment:    行尾注释
      label:      标签名（如果是标签行）
    """
    raw = line.rstrip('\n')
    stripped = raw.strip()

    if not stripped or stripped.startswith('#') or stripped.startswith('//'):
        return {"kind": "empty", "mnemonic": None, "operands": [],
                "raw": line, "indent": "", "comment": stripped,
                "label": None}

    # 提取行尾注释
    comment_part = ""
    code_part = stripped
    hash_idx = _find_comment_hash(stripped)
    if hash_idx >= 0:
        comment_part = stripped[hash_idx:].strip()
        code_part = stripped[:hash_idx].strip()

    if not code_part:
        return {"kind": "empty", "mnemonic": None, "operands": [],
                "raw": line, "indent": "", "comment": comment_part,
                "label": None}

    indent = raw[:len(raw) - len(raw.lstrip())]

    # 标签
    if code_part.endswith(':') and not code_part.startswith('.'):
        return {"kind": "label", "mnemonic": None, "operands": [],
                "raw": line, "indent": indent, "comment": comment_part,
                "label": code_part[:-1].strip()}

    # 标签 + 指令
    if ':' in code_part and not code_part.startswith('.'):
        colon_pos = code_part.index(':')
        maybe_label = code_part[:colon_pos].strip()
        # 排除内存操作数中的冒号（如 QWORD PTR [xxx]）
        if ' ' not in maybe_label and '[' not in maybe_label:
            rest = code_part[colon_pos+1:].strip()
            if rest:
                parsed = _parse_instruction_part(rest)
                parsed["raw"] = line
                parsed["indent"] = indent
                parsed["comment"] = comment_part
                parsed["label"] = maybe_label
                return parsed
            return {"kind": "label", "mnemonic": None, "operands": [],
                    "raw": line, "indent": indent, "comment": comment_part,
                    "label": maybe_label}

    # 汇编指令 (directive)
    if code_part.startswith('.'):
        mn = code_part.split()[0].lower()
        return {"kind": "directive", "mnemonic": mn, "operands": [],
                "raw": line, "indent": indent, "comment": comment_part,
                "label": None}

    # 指令
    parsed = _parse_instruction_part(code_part)
    parsed["raw"] = line
    parsed["indent"] = indent
    parsed["comment"] = comment_part
    parsed["label"] = None
    return parsed


def _find_comment_hash(s):
    """查找注释 # 的位置（跳过括号和引号内的 #）"""
    depth = 0
    in_quote = False
    for i, ch in enumerate(s):
        if ch == '"' or ch == "'":
            in_quote = not in_quote
        elif not in_quote:
            if ch in ('(', '['):
                depth += 1
            elif ch in (')', ']'):
                depth = max(0, depth - 1)
            elif ch == '#' and depth == 0:
                return i
    return -1


def _parse_instruction_part(code):
    """解析纯指令部分（无标签、无注释）"""
    parts = code.split(None, 1)
    mnemonic = parts[0].lower()
    operands = []
    if len(parts) > 1:
        operands = _split_operands(parts[1])
    return {"kind": "instruction", "mnemonic": mnemonic,
            "operands": operands}


def _split_operands(s):
    """按逗号分隔操作数（跳过括号/方括号内的逗号）"""
    result = []
    current = []
    depth = 0
    for ch in s:
        if ch in ('(', '['):
            depth += 1
            current.append(ch)
        elif ch in (')', ']'):
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == ',' and depth == 0:
            result.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        result.append(''.join(current).strip())
    return result


def reconstruct_line(mnemonic, operands, indent="\t", comment="",
                     label=None):
    """重建汇编行"""
    parts = []
    if label:
        parts.append("{}:".format(label))

    if operands:
        instr = "{}{} {}".format(indent, mnemonic, ", ".join(operands))
    else:
        instr = "{}{}".format(indent, mnemonic)
    parts.append(instr)

    line = " ".join(parts) if label else instr
    if comment:
        line += "  " + comment
    return line


def extract_registers(operand):
    """从操作数中提取所有寄存器名"""
    regs = set()
    pattern = (r'\b(r[a-z]{2}|e[a-z]{2}|[a-z]{2}l|[a-z]{2}h|'
               r'r\d+[dwb]?|rip|rsp|rbp|esp|ebp|[a-z]l|[a-z]h)\b')
    for m in re.finditer(pattern, operand, re.IGNORECASE):
        regs.add(m.group(0).lower())
    return regs


def extract_all_registers(parsed):
    """从已解析指令中提取所有寄存器"""
    regs = set()
    for op in parsed.get("operands", []):
        regs |= extract_registers(op)
    return regs


def extract_immediate(operand):
    """从操作数中提取立即数（返回 (match_str, int_value) 或 None）"""
    # $0x1234 形式 (AT&T) 或直接数字 (Intel)
    m = re.search(r'\$?(0x[0-9a-fA-F]+|\-?[0-9]+)', operand)
    if m:
        s = m.group(1)
        try:
            val = int(s, 16) if s.lower().startswith('0x') else int(s)
            return (m.group(0), val)
        except ValueError:
            pass
    return None


def has_memory_operand(parsed):
    """检查指令是否包含内存操作数"""
    for op in parsed.get("operands", []):
        if '[' in op or '(' in op:
            return True
    return False


def get_register_pool(reg_name):
    """获取同 size 的替换寄存器池（排除保护寄存器）"""
    rn = reg_name.lower()
    # 不替换保护寄存器
    if rn in ("rsp", "rbp", "rip", "esp", "ebp", "eip"):
        return []
    if rn in GENERAL_REGS_64:
        return [r for r in GENERAL_REGS_64 if r != rn]
    if rn in GENERAL_REGS_32:
        return [r for r in GENERAL_REGS_32 if r != rn]
    if rn in GENERAL_REGS_16:
        return [r for r in GENERAL_REGS_16 if r != rn]
    if rn in GENERAL_REGS_8:
        return [r for r in GENERAL_REGS_8 if r != rn]
    return []

def extract_memory_operand(parsed):
    """
    从解析后的指令中提取 AT&T 语法的内存操作数文本。
    
    AT&T 语法特征：
      - 内存操作数用圆括号：(%rax), 0x20(%rbp), array(%rip)
      - 复杂形式：disp(base, index, scale)
    
    参数:
        parsed: parse_asm_line() 返回的字典
    
    返回:
        str | None: 内存操作数文本，如 "(%rax)", "0x20(%rbp,%rcx,4)", "array(%rip)"
                    如果没有则返回 None
    """
    if not parsed.get("has_memory_operand"):
        return None
    
    operands = parsed.get("operands", [])
    
    # AT&T 语法：内存操作数必然包含括号
    for op in operands:
        op = op.strip()
        if '(' in op and ')' in op:
            return op
    
    # 备用：从原始文本正则提取
    import re
    raw = parsed.get("raw", "")
    # 匹配 disp(base), disp(base,index), disp(base,index,scale), (base), 等
    pattern = r'(?:[\w\.\+\-]+)?\([^)]+\)'
    match = re.search(pattern, raw)
    if match:
        return match.group(0)
    
    return None

def extract_registers_from_memory_operand(mem_op):
    """
    从 AT&T 语法的内存操作数中提取所有涉及的寄存器。
    
    AT&T 语法示例：
      - (%rax)           → {"rax"}
      - 0x20(%rbp)       → {"rbp"}
      - (%rax,%rcx,4)    → {"rax", "rcx"}
      - array(%rip)      → {"rip"}
    
    参数:
        mem_op: 内存操作数文本
    
    返回:
        set: 寄存器集合（小写，不含 % 前缀）
    """
    import re
    
    # AT&T 语法寄存器前缀是 %
    # 匹配 %rax, %rbp, %r8, %rip 等
    reg_pattern = r'%([re]?[abcd]x|[re]?[sb]p|[re]?[sd]i|r(?:[89]|1[0-5])|[re]?ip)'
    matches = re.findall(reg_pattern, mem_op, re.IGNORECASE)
    
    return set(r.lower() for r in matches)

def get_written_registers(parsed):
    """
    获取 AT&T 语法指令写入的寄存器集合（保守估计）。
    
    AT&T 语法特征：
      - 双操作数指令：目标在最后（mov %rax, %rbx → 写 rbx）
      - 单操作数指令：该操作数既读又写
    
    参数:
        parsed: parse_asm_line() 返回的字典
    
    返回:
        set: 被写入的寄存器集合（小写，不含 % 前缀）
    """
    import re
    
    mnemonic = parsed.get("mnemonic", "").lower()
    operands = parsed.get("operands", [])
    
    written = set()
    
    # ============================================================
    # 1. 隐式写 %rsp 的指令
    # ============================================================
    if mnemonic in ["call", "callq", "push", "pushq", "pop", "popq", "ret", "retq"]:
        written.add("rsp")
    
    # ============================================================
    # 2. pop 同时写目标寄存器
    # ============================================================
    if mnemonic in ["pop", "popq"] and operands:
        written |= _extract_regs_from_operand(operands[0])
    
    # ============================================================
    # 3. 单操作数读写指令（inc, dec, neg, not, setcc）
    # ============================================================
    if mnemonic in ["inc", "incq", "dec", "decq", "neg", "negq", "not", "notq"]:
        if operands:
            written |= _extract_regs_from_operand(operands[0])
    
    if mnemonic.startswith("set"):  # setb, sete, setne 等
        if operands:
            written |= _extract_regs_from_operand(operands[0])
    
    # ============================================================
    # 4. 双操作数指令（AT&T：目标在最后）
    # ============================================================
    if len(operands) >= 2:
        # mov %rax, %rbx → 写 %rbx
        # add %rax, %rbx → 写 %rbx
        written |= _extract_regs_from_operand(operands[-1])
    
    # ============================================================
    # 5. 乘除法指令隐式写 %rax/%rdx
    # ============================================================
    if mnemonic in ["imul", "imulq", "mul", "mulq"]:
        # 单操作数形式隐式写 %rax/%rdx
        if len(operands) == 1:
            written.add("rax")
            written.add("rdx")
        # 多操作数形式写目标（已在步骤 4 处理）
    
    if mnemonic in ["div", "divq", "idiv", "idivq"]:
        written.add("rax")
        written.add("rdx")
    
    # ============================================================
    # 6. xchg 写两个操作数（特殊情况）
    # ============================================================
    if mnemonic in ["xchg", "xchgq"]:
        for op in operands:
            written |= _extract_regs_from_operand(op)
    
    # ============================================================
    # 7. lea 只写目标，不影响 flags（已在步骤 4 处理）
    # ============================================================
    
    return written


def _extract_regs_from_operand(operand):
    """
    从单个操作数中提取所有寄存器（AT&T 语法）。
    
    示例:
      - "%rax"         → {"rax"}
      - "0x20(%rbp)"   → {"rbp"}
      - "(%rax,%rcx,4)" → {"rax", "rcx"}
    """
    import re
    reg_pattern = r'%([re]?[abcd]x|[re]?[sb]p|[re]?[sd]i|r(?:[89]|1[0-5])|[re]?ip)'
    matches = re.findall(reg_pattern, operand, re.IGNORECASE)
    return set(r.lower() for r in matches)

def is_memory_operand_stable(mem_op, src_idx, cur_idx, asm_lines):
    """
    检查内存操作数从来源位置到当前插入点之间是否稳定。
    
    稳定条件：
      - 该内存操作数依赖的所有寄存器，在区间 (src_idx, cur_idx) 内未被改写
    
    参数:
        mem_op: 内存操作数文本（AT&T 语法）
        src_idx: 候选来源指令的索引
        cur_idx: 当前插入点的索引
        asm_lines: 汇编代码行列表
    
    返回:
        bool: True 表示稳定，False 表示不稳定
    """
    # 提取该内存操作数依赖的寄存器
    dep_regs = extract_registers_from_memory_operand(mem_op)
    
    if not dep_regs:
        # 如果是纯 label/symbol（如 array(%rip) 但 %rip 不算依赖），直接稳定
        # 实际上 %rip 会被提取出来，但 %rip 在用户代码中不会被显式改写
        # 为了简化，认为 %rip 是稳定的
        if dep_regs == {"rip"}:
            return True
        if not dep_regs:
            return True
    
    # 扫描区间 (src_idx, cur_idx) 内的所有指令
    for idx in range(src_idx + 1, cur_idx):
        if idx >= len(asm_lines):
            break
        
        line = asm_lines[idx]
        parsed = parse_asm_line(line)
        
        if parsed["kind"] != "instruction":
            continue
        
        # 获取该指令写的寄存器
        written_regs = get_written_registers(parsed)
        
        # 如果写集合与依赖寄存器有交集，则不稳定
        if dep_regs & written_regs:
            return False
    
    return True



# ====================================================================
# 第四部分：保护判定
# ====================================================================

class ProtectionChecker(object):
    """保护判定器"""

    def __init__(self):
        # 保护区域：(start_label, end_offset)
        # 在插桩标签后 5 行内的指令受保护
        self.label_protection_radius = 5

    def is_protected(self, parsed, context):
        """
        判断一行是否受保护。

        context dict:
          recent_labels:  最近 N 个标签名列表
          line_idx:       行索引
          label_line_map: {label_name: line_idx}
        """
        kind = parsed["kind"]

        # 空行/注释/伪指令 不变异
        if kind in ("empty", "directive"):
            return True

        # 标签本身不变异
        if kind == "label":
            return True

        # 非指令直接保护
        if kind != "instruction":
            return True
        

        # 新增：保护栈相关关键指令
        if kind == "instruction":
            mn = parsed["mnemonic"].lower()
            operands_str = " ".join(parsed.get("operands", [])).lower()

            _STACK_FRAME_PUSH_POP = ("push", "pushq", "pushl", "pushw",
                         "pop", "popq", "popl", "popw",
                         "leave", "leaveq",
                         "ret", "retq", "retl", "retn")
            _STACK_FRAME_ARITH = ("sub", "subq", "subl", "subw",
                                "add", "addq", "addl", "addw")
            _STACK_FRAME_MOV = ("mov", "movq", "movl", "movw")
            
            # 1. 栈帧建立/销毁指令绝不变异
            if mn in _STACK_FRAME_PUSH_POP:
                if any(reg in operands_str for reg in ("%rbp", "%rsp", "%ebp", "%esp", "%bp", "%sp")):
                    return True
            
            # 2. subq/addq 操作 %rsp（栈空间分配）
            if mn in _STACK_FRAME_ARITH:
                if "%rsp" in operands_str:
                    return True
            
            # 3. movq %rsp, %rbp（栈帧基址保存）
            if mn in _STACK_FRAME_MOV and "%rsp" in operands_str and "%rbp" in operands_str:
                return True

        mn = parsed["mnemonic"]

        # 不可变异伪指令
        if mn in IMMUTABLE_MNEMONICS:
            return True
        
        # ---- 新增: 局部标签作为 directive 时也要保护 ----
        # GCC 生成的局部标签如 .L6:, .L115: 会被解析为 directive
        # 必须保护其行不被删除
        if mn and re.match(r'^\.[Ll][A-Za-z0-9_]+$', mn):
            return True

        # ret/retq 保护（不删除，但 RSB 组合变异可在其前插入指令）
        if mn in ("ret", "retq"):
            return True

        # call 指令：检查目标是否是保护函数
        if mn == "call" or mn == "callq":
            for op in parsed["operands"]:
                op_clean = op.strip().lstrip('*')
                for target in PROTECTED_CALL_TARGETS:
                    if target in op_clean:
                        return True

        # 检查是否在保护标签附近
        recent_labels = context.get("recent_labels", [])
        label_line_map = context.get("label_line_map", {})
        line_idx = context.get("line_idx", -1)

        for lbl in recent_labels:
            if lbl in PROTECTED_LABELS:
                lbl_idx = label_line_map.get(lbl, -999)
                if 0 <= (line_idx - lbl_idx) <= self.label_protection_radius:
                    return True

        return False

    def is_stack_frame_instruction(self, parsed):
        """
        判断是否是栈帧操作指令。

        Spectre RSB 分析：
          - 标准 ABI 栈帧（push rbp; mov rbp,rsp; pop rbp）
            → 默认受保护，但允许在前面插入指令
          - 栈分配/回收（sub rsp,XX; add rsp,XX）
            → 可以变异分配大小
          - push/pop 其他寄存器
            → 可以变异
        """
        if parsed["kind"] != "instruction":
            return False, "none"

        mn = parsed["mnemonic"]
        operands_str = " ".join(parsed.get("operands", [])).lower()

        # push rbp / pop rbp — ABI 标准栈帧
        if mn in ("push", "pushq", "pushl", "pushw") and "rbp" in operands_str:
            return True, "abi_frame_setup"
        if mn in ("pop", "popq", "popl", "popw") and "rbp" in operands_str:
            return True, "abi_frame_teardown"

        # mov rbp, rsp / mov rsp, rbp
        if mn in ("mov", "movq", "movl", "movw"):
            regs = extract_all_registers(parsed)
            has_bp = any(r in regs for r in ("rbp", "ebp", "bp"))
            has_sp = any(r in regs for r in ("rsp", "esp", "sp"))
            if has_bp and has_sp:
                return True, "abi_frame_pointer"

        # sub rsp, XX / add rsp, XX
        if mn in ("sub", "subq", "subl", "subw",
                "add", "addq", "addl", "addw") and "rsp" in operands_str:
            return True, "stack_allocation"

        # push/pop 其他寄存器
        if mn in ("push", "pushq", "pushl", "pushw",
                "pop", "popq", "popl", "popw"):
            return True, "register_save_restore"

        return False, "none"


# ====================================================================
# 第五部分：循环摘要感知
# ====================================================================

class LoopAwareness(object):
    """
    循环摘要感知模块。

    通过 anchor 的语义标签和 strong_objects 的角色识别
    循环体内指令和循环边界指令。
    """

    def __init__(self, anchors, strong_objects):
        self.loop_bound_pcs = set()
        self.loop_body_pcs = set()
        self._analyze(anchors, strong_objects)

    def _analyze(self, anchors, strong_objects):
        """分析循环相关指令"""
        # 收集 loop_bound_constant 相关的 PC
        loop_bound_obj_ids = set()
        for obj in strong_objects:
            role = obj.get("causal_role_class", "")
            tags = set(obj.get("semantic_tags", []))
            if role == "loop_bound_constant" or "loop_bound_constant" in tags:
                loop_bound_obj_ids.add(obj.get("object_id", ""))

        for anchor in anchors:
            pc = anchor.get("pc", "")
            kinds = set(anchor.get("anchor_kinds", []))
            causal_objs = set(anchor.get("causal_objects", []))

            # 循环边界：涉及 loop_bound_constant 对象
            if causal_objs & loop_bound_obj_ids:
                self.loop_bound_pcs.add(pc)

            # 循环边界：有 loop_bound_anchor kind
            if "loop_bound_anchor" in kinds:
                self.loop_bound_pcs.add(pc)

        # 简单启发：循环边界附近的比较指令视为循环头/尾
        # 循环边界 PC 之间的 PC 视为循环体
        # 这是一个粗略近似，更精确的需要 CFG
        sorted_bound_pcs = sorted(self.loop_bound_pcs)
        if len(sorted_bound_pcs) >= 2:
            # 取最小和最大的循环边界之间的 anchor 为循环体
            for anchor in anchors:
                pc = anchor.get("pc", "")
                if pc in self.loop_bound_pcs:
                    continue
                # 检查 PC 是否在任意两个边界之间
                for k in range(len(sorted_bound_pcs) - 1):
                    low = sorted_bound_pcs[k]
                    high = sorted_bound_pcs[k + 1]
                    if low < pc < high:
                        self.loop_body_pcs.add(pc)
                        break

    def get_probability_modifier(self, pc):
        """获取循环感知的概率修正因子"""
        if pc in self.loop_bound_pcs:
            return LOOP_BOUND_BOOST
        if pc in self.loop_body_pcs:
            return LOOP_BODY_DECAY
        return 1.0

# ====================================================================
# 第六部分：随机指令生成器（修复版 - 严格 AT&T 语法）
# ====================================================================

class RandomInstructionGenerator(object):
    """
    随机汇编指令生成器（严格 AT&T 语法）。

    AT&T 语法规则（必须严格遵守）:
      1. 操作数顺序: 源在前, 目标在后  → `movq $5, %rax` (NOT `movq %rax, $5`)
      2. 寄存器加 % 前缀                → `%rax`
      3. 立即数加 $ 前缀                → `$10`
      4. 指令必须有宽度后缀 b/w/l/q    → `movq` (NOT `mov`)
      5. movzx/movsx 必须双后缀         → `movzbq` = move zero-extend byte to quad
      6. 内存寻址: disp(base,index,scale) → `8(%rax,%rcx,4)`
      7. imul 三操作数: imm, src, dst   → `imulq $5, %rax, %rbx`
      8. 操作数宽度必须严格匹配
    """

    # 安全寄存器池 (排除 rsp/rbp/rip)
    SAFE_R64 = ["%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi",
                "%r8", "%r9", "%r10", "%r11"]
    SAFE_R32 = ["%eax", "%ebx", "%ecx", "%edx", "%esi", "%edi",
                "%r8d", "%r9d", "%r10d", "%r11d"]
    SAFE_R16 = ["%ax", "%bx", "%cx", "%dx", "%si", "%di",
                "%r8w", "%r9w", "%r10w", "%r11w"]
    SAFE_R8  = ["%al", "%bl", "%cl", "%dl", "%sil", "%dil",
                "%r8b", "%r9b", "%r10b", "%r11b"]

    # 各类别选择权重
    CATEGORY_WEIGHTS = {
        "nop_like":       0.20,
        "arithmetic":     0.18,
        "move":           0.12,
        "compare":        0.08,
        "memory":         0.08,
        "fence":          0.20,
        "speculation":    0.08,
        "stack":          0.06,
    }

    # ----------------------------------------------------------------
    # 内部生成器: 每类指令独立的生成函数
    # ----------------------------------------------------------------

    @classmethod
    def _gen_nop_like(cls):
        """生成等效 NOP 的指令（不破坏程序状态）"""
        choices = [
            lambda: "\tnop",
            lambda: "\tnop",
            lambda: "\tnop",
            # xchg reg, reg (相同寄存器) = nop
            lambda: (
                lambda _pick_same: cls._fmt2(
                    "xchgq", 
                    random.choice(cls.SAFE_R64), 
                    "{}".format(_pick_same)
                )
            )(random.choice(cls.SAFE_R64)),  # 将赋值逻辑提前处理
            # mov reg32, reg32 (相同) - 零扩展但不改语义
            lambda: (lambda r: cls._fmt2("movl", r, r))(random.choice(cls.SAFE_R32)),
            # test reg, reg (只设 flags)
            lambda: (lambda r: cls._fmt2("testq", r, r))(random.choice(cls.SAFE_R64)),
        ]
        return random.choice(choices)()

    @classmethod
    def _gen_arithmetic(cls):
        """生成算术指令（AT&T 顺序: src, dst）"""
        choices = [
            # add $imm, %reg
            lambda: cls._fmt2("addq", cls._imm8(), random.choice(cls.SAFE_R64)),
            # sub $imm, %reg
            lambda: cls._fmt2("subq", cls._imm8(), random.choice(cls.SAFE_R64)),
            # xor %reg, %reg
            lambda: cls._fmt2_diff_reg("xorq"),
            # and %reg, %reg
            lambda: cls._fmt2_diff_reg("andq"),
            # or %reg, %reg
            lambda: cls._fmt2_diff_reg("orq"),
            # shl $shift, %reg
            lambda: cls._fmt2("shlq", cls._shift(), random.choice(cls.SAFE_R64)),
            # shr $shift, %reg
            lambda: cls._fmt2("shrq", cls._shift(), random.choice(cls.SAFE_R64)),
            # inc %reg
            lambda: cls._fmt1("incq", random.choice(cls.SAFE_R64)),
            # dec %reg
            lambda: cls._fmt1("decq", random.choice(cls.SAFE_R64)),
            # neg %reg
            lambda: cls._fmt1("negq", random.choice(cls.SAFE_R64)),
            # not %reg
            lambda: cls._fmt1("notq", random.choice(cls.SAFE_R64)),
            # imul $imm, %src, %dst (三操作数: AT&T 顺序为 imm, src, dst)
            lambda: cls._fmt3_imul(),
        ]
        return random.choice(choices)()

    @classmethod
    def _gen_move(cls):
        """生成移动指令（AT&T 顺序: src, dst）"""
        choices = [
            # movq $imm, %reg
            lambda: cls._fmt2("movq", cls._imm32(), random.choice(cls.SAFE_R64)),
            # movl $imm, %reg32
            lambda: cls._fmt2("movl", cls._imm32(), random.choice(cls.SAFE_R32)),
            # movq %src, %dst
            lambda: cls._fmt2_diff_reg("movq"),
            # movl %src, %dst (32-bit)
            lambda: cls._fmt2_diff_reg("movl", cls.SAFE_R32),
            # movzbq %src8, %dst64 (zero-extend byte to quad)
            lambda: cls._fmt2("movzbq", random.choice(cls.SAFE_R8),
                              random.choice(cls.SAFE_R64)),
            # movzwq %src16, %dst64 (zero-extend word to quad)
            lambda: cls._fmt2("movzwq", random.choice(cls.SAFE_R16),
                              random.choice(cls.SAFE_R64)),
            # movzbl %src8, %dst32 (zero-extend byte to long)
            lambda: cls._fmt2("movzbl", random.choice(cls.SAFE_R8),
                              random.choice(cls.SAFE_R32)),
            # leaq disp(%base), %dst
            lambda: cls._fmt_lea(),
            # xchgq %src, %dst
            lambda: cls._fmt2_diff_reg("xchgq"),
        ]
        return random.choice(choices)()

    @classmethod
    def _gen_compare(cls):
        """生成比较指令（AT&T 顺序: src, dst — cmp 比较 dst-src）"""
        choices = [
            # cmpq $imm, %reg  → 比较 reg 与 imm
            lambda: cls._fmt2("cmpq", cls._imm8(), random.choice(cls.SAFE_R64)),
            # cmpq %src, %dst
            lambda: cls._fmt2_diff_reg("cmpq"),
            # testq $imm, %reg
            lambda: cls._fmt2("testq", cls._imm32(), random.choice(cls.SAFE_R64)),
            # testq %reg, %reg
            lambda: (lambda r: cls._fmt2("testq", r, r))(random.choice(cls.SAFE_R64)),
        ]
        return random.choice(choices)()

    @classmethod
    def _gen_memory(cls):
        """生成内存访问指令（保守：仅基址寻址，无副作用）"""
        choices = [
            # movq (%base), %dst — 加载
            lambda: (lambda b, d: cls._fmt2("movq", "({})".format(b), d))(
                random.choice(cls.SAFE_R64), random.choice(cls.SAFE_R64)),
            # leaq disp(%base), %dst
            lambda: cls._fmt_lea(),
            # prefetcht0 (%reg) — 无副作用
            lambda: "\tprefetcht0 ({})".format(random.choice(cls.SAFE_R64)),
            # prefetchnta (%reg)
            lambda: "\tprefetchnta ({})".format(random.choice(cls.SAFE_R64)),
        ]
        return random.choice(choices)()

    @classmethod
    def _gen_fence(cls):
        """生成内存屏障指令（无操作数，最安全）"""
        return "\t" + random.choice(["mfence", "lfence", "sfence", "pause"])

    @classmethod
    def _gen_speculation(cls):
        """生成推测执行相关指令"""
        choices = [
            "\tlfence",
            "\tpause",
            "\tnop",
            # rdtsc/cpuid 会破坏 rax/rdx, 谨慎使用; 这里改用更安全的
            "\tlfence",
            "\tmfence",
        ]
        return random.choice(choices)

    @classmethod
    def _gen_stack(cls):
        """生成栈操作指令（成对生成以保持栈平衡）"""
        # 注意: 单条 push/pop 会破坏栈平衡, 这里只生成自平衡的
        choices = [
            # 单 nop (栈中性)
            lambda: "\tnop",
            # pushq %reg + popq %reg (自平衡, 但分成两次会被随机插入分割)
            # 因此这里只生成 nop 类的安全替代
            lambda: "\tnop",
            lambda: "\tlfence",
        ]
        return random.choice(choices)()

    # ----------------------------------------------------------------
    # 格式化辅助函数 (确保 AT&T 语法正确)
    # ----------------------------------------------------------------

    @staticmethod
    def _fmt1(mnemonic, op):
        """单操作数指令: `\tmnemonic op`"""
        return "\t{} {}".format(mnemonic, op)

    @staticmethod
    def _fmt2(mnemonic, src, dst):
        """双操作数指令 (AT&T): `\tmnemonic src, dst`"""
        return "\t{} {}, {}".format(mnemonic, src, dst)

    @classmethod
    def _fmt2_diff_reg(cls, mnemonic, pool=None):
        """生成两个不同寄存器的双操作数指令"""
        if pool is None:
            pool = cls.SAFE_R64
        src = random.choice(pool)
        dst = random.choice([r for r in pool if r != src])
        return cls._fmt2(mnemonic, src, dst)

    @classmethod
    def _fmt3_imul(cls):
        """imul 三操作数 (AT&T): `imulq $imm, %src, %dst`"""
        imm = cls._imm8()
        src = random.choice(cls.SAFE_R64)
        dst = random.choice([r for r in cls.SAFE_R64 if r != src])
        return "\timulq {}, {}, {}".format(imm, src, dst)

    @classmethod
    def _fmt_lea(cls):
        """leaq disp(%base), %dst"""
        disp = random.choice([0, 4, 8, 16, 32, 64, -8, -16])
        base = random.choice(cls.SAFE_R64)
        dst = random.choice(cls.SAFE_R64)
        if disp == 0:
            return "\tleaq ({}), {}".format(base, dst)
        return "\tleaq {}({}), {}".format(disp, base, dst)

    @staticmethod
    def _imm8():
        """生成 8-bit 立即数 (AT&T 格式: $value)"""
        return "${}".format(random.choice([0, 1, 2, 4, 8, 16, 32, 64]))

    @staticmethod
    def _imm32():
        """生成 32-bit 立即数"""
        return "${}".format(random.choice(
            [0, 1, 2, 16, 256, 0xFF, 0xFFFF, 0x10000]))

    @staticmethod
    def _shift():
        """生成位移量 (1-31 之间)"""
        return "${}".format(random.choice([1, 2, 3, 4, 8, 12, 16]))

    # ----------------------------------------------------------------
    # 公共接口
    # ----------------------------------------------------------------

    # 类别 → 生成函数 映射
    _GENERATORS = None  # 延迟初始化

    @classmethod
    def _get_generators(cls):
        if cls._GENERATORS is None:
            cls._GENERATORS = {
                "nop_like":     cls._gen_nop_like,
                "arithmetic":   cls._gen_arithmetic,
                "move":         cls._gen_move,
                "compare":      cls._gen_compare,
                "compare_branch": cls._gen_compare,  # 别名
                "memory":       cls._gen_memory,
                "fence":        cls._gen_fence,
                "speculation":  cls._gen_speculation,
                "stack":        cls._gen_stack,
            }
        return cls._GENERATORS

    @classmethod
    def generate_one(cls, category=None, context=None):
        """
        生成一条 AT&T 语法的随机指令。

        参数:
          category: 指令类别 (None 时按权重随机)
          context:  上下文信息 (保留接口)

        返回:
          str: 单行汇编指令 (不含末尾换行符)
        """
        generators = cls._get_generators()

        if category is None or category not in generators:
            categories = list(cls.CATEGORY_WEIGHTS.keys())
            weights = [cls.CATEGORY_WEIGHTS[c] for c in categories]
            category = random.choices(categories, weights=weights, k=1)[0]

        try:
            return generators[category]()
        except Exception as e:
            logger.debug("RandomInstructionGenerator failed for {}: {}".format(
                category, e))
            return "\tnop"  # 兜底

    @classmethod
    def generate_sequence(cls, min_count=1, max_count=3, context=None):
        """生成多条随机指令"""
        count = random.randint(min_count, max_count)
        return [cls.generate_one(context=context) for _ in range(count)]

    # 兼容旧接口 (TEMPLATES 不再使用, 但保留属性避免外部引用报错)
    TEMPLATES = {}

    @classmethod
    def _fill_template(cls, template):
        """
        兼容旧接口 (已废弃, 重定向到 generate_one)。
        旧代码中可能调用此方法, 直接生成一条安全 nop 替代。
        """
        return "\tnop"



# ====================================================================
# 第七部分：变异算子实现（42 个）
# ====================================================================

class MutationOperators(object):
    """变异算子集合（完整版：42 个算子）"""

    # ================================================================
    # ✅ 新增：受保护的栈帧相关指令（不可变异）
    # ================================================================
    PROTECTED_STACK_MNEMONICS = {
        "push", "pushq", "pushl", "pushw",
        "pop", "popq", "popl", "popw",
        "enter", "leave",
        "mov", "movq", "movl",  # 仅当操作数涉及 rbp/rsp 时保护
    }

    @staticmethod
    def _is_stack_frame_instruction(parsed):
        """
        判断指令是否涉及栈帧操作（需要保护）。
        
        保护规则：
        1. push/pop 系列指令
        2. enter/leave 指令
        3. mov 指令且操作数包含 rbp 或 rsp
        """
        mn = parsed["mnemonic"].lower()
        
        # 规则 1 & 2: push/pop/enter/leave
        if mn in {"push", "pushq", "pushl", "pushw",
                  "pop", "popq", "popl", "popw",
                  "enter", "leave"}:
            return True
        
        # 规则 3: mov 涉及 rbp/rsp
        if mn in {"mov", "movq", "movl", "movw"}:
            operands_str = " ".join(parsed.get("operands", [])).lower()
            if "rbp" in operands_str or "rsp" in operands_str or \
               "ebp" in operands_str or "esp" in operands_str:
                return True
        
        return False
    
    @staticmethod
    def insert_flush_before(parsed, context):
        """
        在当前指令前插入 flush 指令（AT&T 语法）。
        
        策略（调整后）：
        1. 向前回看最多 10 条指令
        2. 收集所有包含内存操作数的指令
        3. 对每个内存操作数，检查其从出现位置到当前点是否稳定（依赖寄存器未被改写）
        4. 筛选出所有稳定的 mem_op，构成合法候选集合
        5. 如果合法候选集合为空，放弃本轮 flush（返回原指令）
        6. 如果合法候选集合非空，随机选择一个，生成 clflush 或 clflushopt
        
        参数:
            parsed: 当前指令的解析结果
            context: 上下文字典，包含：
                    - asm_lines: 汇编代码行列表
                    - current_idx: 当前指令索引
                    - line_map: pc → idx 映射
                    - reverse_line_map: idx → pc 映射
        
        返回:
            list: [flush_line, original_line] 或 [original_line]（失败时）
        """
        asm_lines = context.get("asm_lines", [])
        current_idx = context.get("current_idx", 0)
        
        if current_idx < 1:
            # 没有前向指令可回看
            return [parsed["raw"].rstrip('\n')]
        
        # ============================================================
        # Step 1: 向前回看最多 10 条指令，收集候选内存操作数
        # ============================================================
        window = 10
        candidates = []  # [(mem_op, src_idx), ...]
        
        start_idx = max(0, current_idx - window)
        for src_idx in range(start_idx, current_idx):
            src_line = asm_lines[src_idx]
            src_parsed = parse_asm_line(src_line)
            
            if src_parsed["kind"] != "instruction":
                continue
            
            mem_op = extract_memory_operand(src_parsed)
            if mem_op is None:
                continue
            
            # 检查稳定性
            if not is_memory_operand_stable(mem_op, src_idx, current_idx, asm_lines):
                continue
            
            # 加入合法候选集合
            candidates.append((mem_op, src_idx))
        
        # ============================================================
        # Step 2: 如果没有合法候选，放弃本轮 flush
        # ============================================================
        if not candidates:
            return [parsed["raw"].rstrip('\n')]
        
        # ============================================================
        # Step 3: 从合法候选中随机选择一个
        # ============================================================
        chosen_mem_op, _ = random.choice(candidates)
        
        # ============================================================
        # Step 4: 生成 flush 指令（clflush 或 clflushopt）
        # ============================================================
        flush_type = random.choice(["clflush", "clflushopt"])
        flush_line = "\t{} {}".format(flush_type, chosen_mem_op)
        
        # ============================================================
        # Step 5: 返回 [flush_line, original_line]
        # ============================================================
        return [flush_line, parsed["raw"].rstrip('\n')]

    # ================================================================
    # Part 1: 控制流语义算子（7个）
    # ================================================================

    @staticmethod
    def delete_instruction(parsed, context):
        """
        删除指令（探索性，可能破坏程序逻辑）。
        
        ✅ 保护：栈帧相关指令不删除
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"]
        
        # 不删除关键控制流指令
        if mn in ("ret", "retq", "call", "callq"):
            return [parsed["raw"].rstrip('\n')]
        
        # 删除指令
        return []

    @staticmethod
    def insert_nop(parsed, context):
        """
        在指令前插入 nop（探索瞬态执行窗口）。
        
        ✅ 保护：栈帧相关指令前不插入 nop
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        n = random.randint(1, 4)
        nops = ["\tnop\n"] * n
        return nops + [parsed["raw"].rstrip('\n')]

    @staticmethod
    def replace_with_nop(parsed, context):
        """
        将整条指令替换为 nop（不同于 insert_nop 是在前面"插入"）。
        
        语义：保留指令位置但移除其语义效果，等价于"软删除"。
        相比 delete_instruction，它保留了一个占位指令，
        更不容易破坏后续指令的相对寻址或对齐。
        
        ✅ 保护：栈帧相关指令不替换为 nop（会破坏栈平衡）
        ✅ 保护：控制流指令（call/jmp/ret/分支）不替换
        """
        # 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"].lower()
        
        # 控制流指令保护
        CONTROL_FLOW = {
            "call", "callq", "ret", "retq",
            "jmp", "jmpq",
            "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
            "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno",
            "jc", "jnc", "jp", "jnp", "jecxz", "jrcxz",
        }
        if mn in CONTROL_FLOW or mn.startswith("loop"):
            return [parsed["raw"].rstrip('\n')]
        
        # 标签或伪指令不替换
        if parsed.get("kind") != "instruction":
            return [parsed["raw"].rstrip('\n')]
        
        # 使用与原指令相同的缩进
        indent = parsed.get("indent", "\t")
        return ["{}nop\n".format(indent)]

    @staticmethod
    def insert_fence(parsed, context):
        """
        插入内存屏障（lfence/mfence/sfence）。
        
        ✅ 保护：栈帧相关指令前不插入 fence
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        fence = random.choice(["lfence", "mfence", "sfence"])
        return ["\t{}\n".format(fence), parsed["raw"].rstrip('\n')]

    @staticmethod
    def mutate_branch_condition(parsed, context):
        """
        变异分支条件（je ↔ jne, jl ↔ jge 等）。
        
        ✅ 保护：无需保护（分支指令不涉及栈帧）
        """
        mn = parsed["mnemonic"]
        for group in BRANCH_SWAP_GROUPS:
            if mn in group:
                candidates = [m for m in group if m != mn]
                if candidates:
                    new_mn = random.choice(candidates)
                    line = reconstruct_line(
                        new_mn, parsed["operands"],
                        parsed.get("indent", "\t"),
                        parsed.get("comment", ""))
                    return [line]
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def invert_branch_condition(parsed, context):
        """别名：变异分支条件"""
        return MutationOperators.mutate_branch_condition(parsed, context)

    @staticmethod
    def mutate_branch_target(parsed, context):
        """
        修改分支目标（高风险，可能破坏控制流）。
        
        ✅ 保护：无需保护（分支指令不涉及栈帧）
        
        策略：暂不实现（风险过高）
        """
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def duplicate_instruction(parsed, context):
        """
        重复指令（探索瞬态执行）。
        
        ✅ 保护：栈帧相关指令不重复
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"]
        
        # 不重复控制流指令
        if mn in ("ret", "retq", "call", "callq", "jmp", "jmpq") or \
           mn.startswith("j"):
            return [parsed["raw"].rstrip('\n')]
        
        n = random.randint(1, 3)
        return [parsed["raw"].rstrip('\n')] * (n + 1)
    
    # ================================================================
    # Part 1 补全：缺失的插入类算子和别名
    # ================================================================

    @staticmethod
    def insert_nop_after(parsed, context):
        """在指令后插入 nop"""
        return [parsed["raw"].rstrip('\n'), "\tnop"]

    @staticmethod
    def insert_fence_after(parsed, context):
        """在指令后插入内存屏障"""
        fence = random.choice(["mfence", "lfence", "sfence"])
        return [parsed["raw"].rstrip('\n'), "\t{}".format(fence)]

    @staticmethod
    def insert_random_instruction(parsed, context):
        """
        插入随机生成的指令（默认在指令前插入）。
        别名：等价于 insert_random_instruction_before
        """
        random_inst = RandomInstructionGenerator.generate_one(context=context)
        return [random_inst, parsed["raw"].rstrip('\n')]

    @staticmethod
    def insert_random_sequence(parsed, context):
        """
        在指令前/后插入随机指令序列（1~3 条）。

        50% 在前，50% 在后，避免破坏控制流。
        """
        # 控制流指令只允许在前面插入（不能在 ret/jmp 后面插入垃圾代码）
        mn = parsed.get("mnemonic", "")
        control_flow = (
            BRANCH_MNEMONICS | UNCONDITIONAL_JUMP_MNEMONICS |
            {"call", "callq", "ret", "retq", "leave", "leaveq"}
        )

        seq = RandomInstructionGenerator.generate_sequence(
            min_count=1, max_count=3, context=context)
        original = parsed["raw"].rstrip('\n')

        if mn in control_flow:
            # 控制流指令前插入
            return seq + [original]

        if random.random() < 0.5:
            return seq + [original]
        else:
            return [original] + seq

    @staticmethod
    def replace_with_random_instruction(parsed, context):
        """
        用随机生成的指令替换当前指令。

        排除控制流指令（避免删除标签引用导致 undefined reference 或栈不平衡）。
        """
        mn = parsed.get("mnemonic", "")

        unsafe_to_replace = (
            BRANCH_MNEMONICS | UNCONDITIONAL_JUMP_MNEMONICS |
            {"call", "callq", "ret", "retq", "leave", "leaveq",
             "push", "pushq", "pop", "popq",
             "syscall", "sysenter", "int"}
        )
        if mn in unsafe_to_replace:
            return [parsed["raw"].rstrip('\n')]  # 拒绝变异

        random_inst = RandomInstructionGenerator.generate_one(context=context)
        return [random_inst]

    @staticmethod
    def nop_insertion(parsed, context):
        """别名：插入 nop（等价于 insert_nop_before）"""
        return MutationOperators.insert_nop_before(parsed, context)

    @staticmethod
    def random_instruction_insertion(parsed, context):
        """别名：插入随机指令（等价于 insert_random_instruction_before）"""
        return MutationOperators.insert_random_instruction_before(parsed, context)
    
    @staticmethod
    def _mutate_immediate_value(val, context=None):
        """立即数值变异（多策略组合）"""
        import random
        strategies = [
            lambda v: v + random.choice([-4, -3, -2, -1, 1, 2, 3, 4]),
            lambda v: v ^ (1 << random.randint(0, 15)),
            lambda v: random.choice([0, 1, -1, 2, 4, 8, 16, 32, 64, 128,
                                     255, 256, 0xFF, 0xFFFF, 0x10000]),
            lambda v: v * random.choice([2, 4, 8]) if v != 0 else random.randint(1, 16),
            lambda v: -v if v != 0 else 1,
            lambda v: v << random.randint(1, 3) if 0 < abs(v) < 0x1000
                      else (v >> 1 if v != 0 else 1),
            lambda v: random.randint(-128, 127) if abs(v) < 256
                      else (random.randint(-32768, 32767) if abs(v) < 65536
                            else random.randint(-0x1000, 0x1000)),
            lambda v: v - 1 if v > 0 else v + 1,
            lambda v: (v // 64) * 64 + random.choice([0, 64, 128]) if abs(v) > 64
                      else v + random.choice([-64, 64]),
        ]
        mutator = random.choice(strategies)
        try:
            new_val = mutator(val)
            if abs(new_val) > 0x7FFFFFFFFFFFFFFF:
                new_val = val + random.choice([-1, 1])
            return new_val
        except Exception:
            return val + 1

    # ================================================================
    # Part 2: 立即数语义算子（7个）
    # ================================================================

    @staticmethod
    def mutate_address_offset(parsed, context):
        """
        修改地址偏移量。
        
        ✅ 保护：涉及 rbp/rsp 的偏移不变异
        """
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            # ✅ 栈帧保护：跳过涉及 rbp/rsp 的操作数
            if "rbp" in op.lower() or "rsp" in op.lower() or \
               "ebp" in op.lower() or "esp" in op.lower():
                continue
            
            if '[' not in op and '(' not in op:
                continue
            
            imm_result = extract_immediate(op)
            if imm_result is not None:
                match_str, val = imm_result
                delta = random.choice([-8, -4, -1, 1, 4, 8, 16])
                new_val = val + delta
                
                if match_str.startswith('$'):
                    new_str = "${}".format(new_val)
                else:
                    new_str = str(new_val)
                
                new_op = op.replace(match_str, new_str, 1)
                operands[i] = new_op
                line = reconstruct_line(mn, operands,
                                        parsed.get("indent", "\t"),
                                        parsed.get("comment", ""))
                return [line]

        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def mutate_shift_amount(parsed, context):
        """
        变异位移量（±1, ±4）。
        
        ✅ 保护：无需保护（位移指令不涉及栈帧）
        """
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            if '[' in op or '(' in op:
                continue
            imm_result = extract_immediate(op)
            if imm_result is not None:
                match_str, val = imm_result
                delta = random.choice([-4, -1, 1, 4])
                new_val = max(0, min(63, val + delta))
                
                if match_str.startswith('$'):
                    new_str = "${}".format(new_val)
                else:
                    new_str = str(new_val)
                
                new_op = op.replace(match_str, new_str, 1)
                operands[i] = new_op
                line = reconstruct_line(mn, operands,
                                        parsed.get("indent", "\t"),
                                        parsed.get("comment", ""))
                return [line]

        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def mutate_immediate_value(parsed, context):
        """
        通用立即数变异（多种策略）。
        
        ✅ 保护：涉及栈帧的立即数不变异
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            if '[' in op or '(' in op:
                continue
            imm_result = extract_immediate(op)
            if imm_result is not None:
                match_str, val = imm_result
                new_val = MutationOperators._mutate_immediate_value(val, context)
                
                if match_str.startswith('$'):
                    if new_val < 0:
                        new_str = "${}".format(new_val)
                    elif new_val > 255:
                        new_str = "$0x{:x}".format(new_val & 0xFFFFFFFFFFFFFFFF)
                    else:
                        new_str = "${}".format(new_val)
                else:
                    if new_val < 0:
                        new_str = str(new_val)
                    elif new_val > 255:
                        new_str = "0x{:x}".format(new_val & 0xFFFFFFFFFFFFFFFF)
                    else:
                        new_str = str(new_val)
                
                new_op = op.replace(match_str, new_str, 1)
                operands[i] = new_op
                line = reconstruct_line(mn, operands,
                                        parsed.get("indent", "\t"),
                                        parsed.get("comment", ""))
                return [line]

        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def mutate_immediate(parsed, context):
        """
        变异立即数（严格安全版）。
        
        ✅ 保护：栈帧相关指令不变异
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"].lower()
        
        BLACKLIST_MNEMONICS = {
            "call", "callq", "jmp", "jmpq",
            "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
            "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno",
            "jc", "jnc", "jp", "jnp",
            "lea", "leaq", "leal",
        }
        
        if mn in BLACKLIST_MNEMONICS:
            return [parsed["raw"].rstrip('\n')]
        
        operands = list(parsed["operands"])
        
        for i, op in enumerate(operands):
            op_stripped = op.strip()
            
            if not op_stripped.startswith('$'):
                continue
            
            val_str = op_stripped[1:]
            
            if not re.match(r'^-?(0x[0-9a-fA-F]+|\d+)$', val_str):
                continue
            
            try:
                if val_str.startswith('-0x'):
                    val = -int(val_str[3:], 16)
                elif val_str.startswith('0x'):
                    val = int(val_str[2:], 16)
                else:
                    val = int(val_str)
            except ValueError:
                continue
            
            new_val = MutationOperators._mutate_immediate_value(val, context)
            
            if abs(new_val) > 0xFFFFFF:
                continue
            
            operands[i] = "${}".format(new_val)
            
            line = reconstruct_line(mn, operands,
                                    parsed.get("indent", "\t"),
                                    parsed.get("comment", ""))
            return [line]
        
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def immediate_value_mutation(parsed, context):
        """别名：通用立即数变异"""
        return MutationOperators.mutate_immediate_value(parsed, context)

    # ================================================================
    # Part 3: 寄存器语义算子（9个）
    # ================================================================

    @staticmethod
    def swap_operands(parsed, context):
        """
        交换操作数（适用于可交换指令）。
        
        ✅ 保护：栈帧相关指令不交换
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        if len(operands) != 2:
            return [parsed["raw"].rstrip('\n')]

        commutative = {"add", "and", "or", "xor", "test"}
        comparison = {"cmp"}

        if mn in commutative or mn in comparison:
            swapped = [operands[1], operands[0]]
            line = reconstruct_line(mn, swapped,
                                    parsed.get("indent", "\t"),
                                    parsed.get("comment", ""))
            return [line]

        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def swap_comparison_operands(parsed, context):
        """别名：交换比较操作数"""
        return MutationOperators.swap_operands(parsed, context)

    @staticmethod
    def swap_arithmetic_operands(parsed, context):
        """别名：交换算术操作数"""
        return MutationOperators.swap_operands(parsed, context)

    @staticmethod
    def replace_with_constant(parsed, context):
        """
        将寄存器操作数替换为常量。
        
        ✅ 保护：栈帧相关指令不替换
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        if len(operands) < 2:
            return [parsed["raw"].rstrip('\n')]

        if mn in ("lea", "leaq", "xchg", "xchgq"):
            return [parsed["raw"].rstrip('\n')]
        
        dst_op = operands[-1]
        if '[' in dst_op or '(' in dst_op:
            return [parsed["raw"].rstrip('\n')]

        const = random.choice([0, 1, -1, 2, 4, 8, 16, 0xFF])
        operands[-2] = "${}".format(const)
        
        line = reconstruct_line(mn, operands,
                                parsed.get("indent", "\t"),
                                parsed.get("comment", ""))
        return [line]

    @staticmethod
    def mutate_address_base(parsed, context):
        """
        修改地址基址寄存器。
        
        ✅ 保护：涉及 rbp/rsp 的基址不变异
        """
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            if '[' not in op and '(' not in op:
                continue
            
            # ✅ 栈帧保护
            if "rbp" in op.lower() or "rsp" in op.lower() or \
               "ebp" in op.lower() or "esp" in op.lower():
                continue
            
            regs = extract_registers(op)
            if not regs:
                continue
            
            base_reg = list(regs)[0]
            pool = get_register_pool(base_reg)
            if not pool:
                continue
            
            new_reg = random.choice(pool)
            new_op = re.sub(r'\b{}\b'.format(re.escape(base_reg)),
                            new_reg, op, count=1)
            operands[i] = new_op
            line = reconstruct_line(mn, operands,
                                    parsed.get("indent", "\t"),
                                    parsed.get("comment", ""))
            return [line]

        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def swap_address_components(parsed, context):
        """
        交换地址计算的基址和索引。
        
        ✅ 保护：涉及 rbp/rsp 的地址不交换
        """
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            if '[' not in op and '(' not in op:
                continue
            
            # ✅ 栈帧保护
            if "rbp" in op.lower() or "rsp" in op.lower() or \
               "ebp" in op.lower() or "esp" in op.lower():
                continue
            
            regs = list(extract_registers(op))
            if len(regs) < 2:
                continue
            
            reg1, reg2 = regs[0], regs[1]
            new_op = op.replace(reg1, "TEMP_REG_SWAP", 1)
            new_op = new_op.replace(reg2, reg1, 1)
            new_op = new_op.replace("TEMP_REG_SWAP", reg2, 1)
            
            operands[i] = new_op
            line = reconstruct_line(mn, operands,
                                    parsed.get("indent", "\t"),
                                    parsed.get("comment", ""))
            return [line]

        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def mutate_address_index(parsed, context):
        """
        修改地址索引寄存器。
        
        ✅ 保护：涉及 rbp/rsp 的索引不变异
        """
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            if '[' not in op and '(' not in op:
                continue
            
            # ✅ 栈帧保护
            if "rbp" in op.lower() or "rsp" in op.lower() or \
               "ebp" in op.lower() or "esp" in op.lower():
                continue
            
            regs = list(extract_registers(op))
            if len(regs) < 2:
                continue
            
            index_reg = regs[1]
            pool = get_register_pool(index_reg)
            if not pool:
                continue
            
            new_reg = random.choice(pool)
            parts = op.split(index_reg, 2)
            if len(parts) >= 3:
                new_op = parts[0] + index_reg + parts[1] + new_reg + parts[2]
            else:
                new_op = op.replace(index_reg, new_reg, 1)
            
            operands[i] = new_op
            line = reconstruct_line(mn, operands,
                                    parsed.get("indent", "\t"),
                                    parsed.get("comment", ""))
            return [line]

        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def replace_register(parsed, context):
        """
        替换寄存器（通用）。
        
        ✅ 保护：栈帧相关指令的寄存器不替换
        """
        # ✅ 栈帧保护
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        replaceable = []
        for i, op in enumerate(operands):
            for reg in extract_registers(op):
                # ✅ 额外保护：不替换 rbp/rsp
                if reg.lower() in {"rbp", "rsp", "ebp", "esp"}:
                    continue
                pool = get_register_pool(reg)
                if pool:
                    replaceable.append((i, reg, pool))

        if not replaceable:
            return [parsed["raw"].rstrip('\n')]

        op_idx, old_reg, pool = random.choice(replaceable)
        new_reg = random.choice(pool)
        new_op = re.sub(r'\b{}\b'.format(re.escape(old_reg)),
                        new_reg, operands[op_idx], count=1)
        operands[op_idx] = new_op
        line = reconstruct_line(mn, operands,
                                parsed.get("indent", "\t"),
                                parsed.get("comment", ""))
        return [line]

    @staticmethod
    def mutate_register(parsed, context):
        """别名：替换寄存器"""
        return MutationOperators.replace_register(parsed, context)

    @staticmethod
    def operand_mutation(parsed, context):
        """别名：操作数变异"""
        if random.random() < 0.5:
            return MutationOperators.replace_register(parsed, context)
        else:
            return MutationOperators.mutate_immediate_value(parsed, context)

    # ================================================================
    # Part 4: 栈/内存语义算子（5个）
    # ================================================================

    @staticmethod
    def delete_stack_operation(parsed, context):
        """
        删除栈操作（探索性，可能破坏栈平衡）。
        
        ✅ 保护：rbp 相关的 push/pop 不删除
        """
        mn = parsed["mnemonic"]
        
        if mn in ("push", "pushq", "pop", "popq"):
            operands = parsed.get("operands", [])
            if operands:
                reg = operands[0].strip().lstrip('%')
                # ✅ 保护 rbp（帧指针）
                if reg in ("rbp", "ebp"):
                    return [parsed["raw"].rstrip('\n')]
                # 删除其他寄存器的 push/pop
                return []
        
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def mutate_array_index(parsed, context):
        """别名：修改数组索引"""
        return MutationOperators.mutate_address_index(parsed, context)

    @staticmethod
    def mutate_array_base(parsed, context):
        """别名：修改数组基址"""
        return MutationOperators.mutate_address_base(parsed, context)

    @staticmethod
    def mutate_memory_offset(parsed, context):
        """别名：修改内存偏移"""
        return MutationOperators.mutate_address_offset(parsed, context)

    @staticmethod
    def mutate_memory_operand(parsed, context):
        """通用内存操作数变异"""
        strategy = random.choice([
            MutationOperators.mutate_address_base,
            MutationOperators.mutate_address_index,
            MutationOperators.mutate_address_offset,
        ])
        return strategy(parsed, context)

    @staticmethod
    def mutate_displacement(parsed, context):
        """
        变异内存操作数的位移（通用版, AT&T 语法）。
        
        ✅ 保护：涉及 rbp/rsp 的位移不变异
        """
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            if '(' not in op:
                continue
            
            # ✅ 栈帧保护
            if "rbp" in op.lower() or "rsp" in op.lower() or \
               "ebp" in op.lower() or "esp" in op.lower():
                continue
            
            paren_idx = op.index('(')
            disp_part = op[:paren_idx]
            
            stripped = disp_part.strip()
            if stripped and not re.match(r'^-?(0x[0-9a-fA-F]+|\d+)$', stripped):
                continue
            
            if not stripped:
                disp = 0
            else:
                try:
                    if stripped.startswith('-0x') or stripped.startswith('-'):
                        if stripped.startswith('-0x'):
                            disp = -int(stripped[3:], 16)
                        else:
                            disp = -int(stripped[1:])
                    elif stripped.startswith('0x'):
                        disp = int(stripped[2:], 16)
                    else:
                        disp = int(stripped)
                except ValueError:
                    continue

            new_disp = MutationOperators._mutate_immediate_value(disp, context)
            
            if abs(new_disp) > 0x10000:
                new_disp = new_disp % 0x10000
            
            if new_disp == 0:
                new_disp_str = ""
            elif new_disp > 0:
                new_disp_str = str(new_disp)
            else:
                new_disp_str = "-" + str(-new_disp)
            
            new_op = new_disp_str + op[paren_idx:]
            operands[i] = new_op
            line = reconstruct_line(mn, operands,
                                    parsed.get("indent", "\t"),
                                    parsed.get("comment", ""))
            return [line]

        return [parsed["raw"].rstrip('\n')]

    # ================================================================
    # Part 5: 操作码语义算子（4个）
    # ================================================================

    @staticmethod
    def replace_arithmetic_opcode(parsed, context):
        """
        替换算术操作码。
        
        ✅ 保护：无需保护（算术指令不涉及栈帧）
        """
        mn = parsed["mnemonic"]
        for group in ARITHMETIC_SWAP_GROUPS:
            if mn in group:
                candidates = [m for m in group if m != mn]
                if candidates:
                    new_mn = random.choice(candidates)
                    line = reconstruct_line(
                        new_mn, parsed["operands"],
                        parsed.get("indent", "\t"),
                        parsed.get("comment", ""))
                    return [line]
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def mutate_opcode_arithmetic(parsed, context):
        """别名：替换算术操作码"""
        return MutationOperators.replace_arithmetic_opcode(parsed, context)

    @staticmethod
    def opcode_replacement(parsed, context):
        """别名：操作码替换"""
        return MutationOperators.replace_arithmetic_opcode(parsed, context)

    @staticmethod
    def replace_comparison_opcode(parsed, context):
        """
        替换比较操作码（cmp ↔ test）。
        
        ✅ 保护：无需保护（比较指令不涉及栈帧）
        """
        mn = parsed["mnemonic"]
        operands = list(parsed["operands"])
        
        if mn == "cmp":
            new_mn = "test"
        elif mn == "test":
            new_mn = "cmp"
            if len(operands) == 2 and operands[0] == operands[1]:
                operands[1] = "$0"
        else:
            return [parsed["raw"].rstrip('\n')]

        line = reconstruct_line(
            new_mn, operands,
            parsed.get("indent", "\t"),
            parsed.get("comment", ""))
        return [line]
    
        # ================================================================
    # Part 5.5: 分支语义算子（补全）
    # ================================================================

    @staticmethod
    def invert_branch_condition(parsed, context):
        """
        翻转条件分支（je ↔ jne, jl ↔ jge 等）。

        适用场景：
          - je .L1  →  jne .L1   （改变控制流方向）
          - jl .L2  →  jge .L2
        """
        mn = parsed.get("mnemonic", "").lower()
        if mn not in BRANCH_INVERSION:
            return [parsed["raw"].rstrip('\n')]

        new_mn = BRANCH_INVERSION[mn]
        line = reconstruct_line(
            new_mn, parsed["operands"],
            parsed.get("indent", "\t"),
            parsed.get("comment", ""))
        return [line]

    @staticmethod
    def replace_branch_condition(parsed, context):
        """
        替换分支条件为同类候选条件（不一定是反转）。

        适用场景：
          - je .L1  →  jl .L1   （改变比较语义）
          - jg .L2  →  jge .L2  （边界扩展）
        """
        mn = parsed.get("mnemonic", "").lower()
        if mn not in BRANCH_ALTERNATIVES:
            # 退回反转策略
            return MutationOperators.invert_branch_condition(parsed, context)

        candidates = BRANCH_ALTERNATIVES[mn]
        if not candidates:
            return [parsed["raw"].rstrip('\n')]

        new_mn = random.choice(candidates)
        line = reconstruct_line(
            new_mn, parsed["operands"],
            parsed.get("indent", "\t"),
            parsed.get("comment", ""))
        return [line]

    @staticmethod
    def mutate_branch_condition(parsed, context):
        """
        变异分支条件（综合：50% 反转 + 50% 替换）。

        关键算子：被 _select_mutator_for_non_anchor 和 combo_spectre_v1 调用。
        """
        mn = parsed.get("mnemonic", "").lower()

        # 仅处理条件分支
        if mn not in BRANCH_MNEMONICS:
            return [parsed["raw"].rstrip('\n')]

        # 不可反转的分支（loop 类）直接返回
        if mn in ("loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz"):
            return [parsed["raw"].rstrip('\n')]

        if random.random() < 0.5:
            return MutationOperators.invert_branch_condition(parsed, context)
        else:
            return MutationOperators.replace_branch_condition(parsed, context)

    # ================================================================
    # Part 5.6: 比较交换算子（补全）
    # ================================================================

    @staticmethod
    def mutate_comparison_swap(parsed, context):
        """
        比较指令操作数交换（改变比较方向语义）。

        关键算子：被 _select_mutator_for_non_anchor 调用。

        AT&T 语法注意：cmp src, dst 实际计算 dst - src，
        交换后语义反转，需要后续分支配合（这里只交换，不改分支）。

        适用场景：
          - cmpq %rbx, %rax  →  cmpq %rax, %rbx
          - testq %rbx, %rax  →  testq %rax, %rbx
        """
        mn = parsed.get("mnemonic", "").lower()
        operands = list(parsed["operands"])

        # 仅适用于比较类指令
        if mn not in COMPARE_MNEMONICS and mn not in (
                "cmpq", "cmpl", "cmpw", "cmpb",
                "testq", "testl", "testw", "testb"):
            return [parsed["raw"].rstrip('\n')]

        if len(operands) != 2:
            return [parsed["raw"].rstrip('\n')]

        # 不能交换：源是立即数（立即数不能作为目标）
        op0_stripped = operands[0].strip()
        if op0_stripped.startswith('$'):
            return [parsed["raw"].rstrip('\n')]

        swapped = [operands[1], operands[0]]
        line = reconstruct_line(
            mn, swapped,
            parsed.get("indent", "\t"),
            parsed.get("comment", ""))
        return [line]

    # ================================================================
    # Part 5.7: 地址偏移变异（补全 - 关键缺失项）
    # ================================================================

    @staticmethod
    def mutate_address_offset(parsed, context):
        """
        修改内存操作数的位移偏移（AT&T 语法：disp(base,index,scale)）。

        关键算子：被 mutate_memory_offset、mutate_memory_operand、
        mutate_displacement 等多处调用，缺失会导致 AttributeError。

        AT&T 语法约束：
          1. 仅处理含 '(' 的内存操作数
          2. 仅匹配 '(' 前的纯数字 disp（排除符号引用如 array1(%rip)）
          3. 偏移量限制在合理范围（避免段错误）

        适用场景：
          - movq 8(%rbx), %rax    →  movq 16(%rbx), %rax
          - movq -16(%rbp), %rax  →  movq -24(%rbp), %rax
          - movq (%rbx,%rcx,4), %rax → movq 8(%rbx,%rcx,4), %rax
        """
        mn = parsed.get("mnemonic", "")
        operands = list(parsed["operands"])

        for i, op in enumerate(operands):
            if '(' not in op:
                continue

            paren_idx = op.index('(')
            disp_part = op[:paren_idx].strip()

            # 排除符号引用（如 array1(%rip), .L6+8(%rip)）
            if disp_part and not re.match(
                    r'^-?(0x[0-9a-fA-F]+|\d+)$', disp_part):
                continue

            # 解析当前 disp
            if not disp_part:
                disp = 0
            else:
                try:
                    if disp_part.startswith('-0x'):
                        disp = -int(disp_part[3:], 16)
                    elif disp_part.startswith('0x'):
                        disp = int(disp_part[2:], 16)
                    elif disp_part.startswith('-'):
                        disp = -int(disp_part[1:])
                    else:
                        disp = int(disp_part)
                except ValueError:
                    continue

            # 应用变异：小幅 ±1~32 / cache line 跳变 / 翻倍
            strategy = random.choice([
                lambda d: d + random.choice([-32, -16, -8, -4, 4, 8, 16, 32]),
                lambda d: d + random.choice([-64, 64]),  # cache line
                lambda d: d * 2 if abs(d) < 0x1000 else d // 2,
                lambda d: -d if d != 0 else 8,
                lambda d: 0,  # 退化为零偏移
            ])

            try:
                new_disp = strategy(disp)
            except Exception:
                new_disp = disp + 8

            # 边界检查：避免极端偏移导致段错误
            if abs(new_disp) > 0x10000:
                new_disp = new_disp % 0x10000

            # 格式化（AT&T）
            if new_disp == 0:
                new_disp_str = ""
            elif new_disp > 0:
                new_disp_str = str(new_disp)
            else:
                new_disp_str = "-" + str(-new_disp)

            new_op = new_disp_str + op[paren_idx:]
            operands[i] = new_op
            line = reconstruct_line(
                mn, operands,
                parsed.get("indent", "\t"),
                parsed.get("comment", ""))
            return [line]

        return [parsed["raw"].rstrip('\n')]

    # ================================================================
    # Part 5.8: 指令复制算子（补全）
    # ================================================================

    @staticmethod
    def duplicate_instruction(parsed, context):
        """
        复制指令（连续两次执行同一指令）。

        适用场景：制造冗余执行、影响微架构状态
          - mov %rax, %rbx  →  mov %rax, %rbx; mov %rax, %rbx

        约束：不复制控制流指令（避免重复跳转/返回/调用）
        """
        mn = parsed.get("mnemonic", "")

        unsafe_to_duplicate = (
            BRANCH_MNEMONICS | UNCONDITIONAL_JUMP_MNEMONICS |
            {"call", "callq", "ret", "retq", "leave", "leaveq",
             "push", "pushq", "pop", "popq",
             "syscall", "sysenter", "int"}
        )
        if mn in unsafe_to_duplicate:
            return [parsed["raw"].rstrip('\n')]

        original = parsed["raw"].rstrip('\n')
        return [original, original]

    # ================================================================
    # Part 6: 组合算子（9个）- 占位符
    # ================================================================

    @staticmethod
    def combo_cmp_branch(parsed, context):
        """组合变异：比较+分支（调度器层面实现）"""
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def combo_same_object_batch(parsed, context):
        """组合变异：同对象批量（调度器层面实现）"""
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def combo_spectre_v1(parsed, context):
        """组合变异：Spectre v1（调度器层面实现）"""
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def combo_spectre_rsb(parsed, context):
        """组合变异：Spectre RSB（调度器层面实现）"""
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def combo_spectre_v4(parsed, context):
        """组合变异：Spectre v4（调度器层面实现）"""
        return [parsed["raw"].rstrip('\n')]

    @staticmethod
    def combo_transient_window_extension(parsed, context):
        """组合变异：瞬态窗口扩展（调度器层面实现）"""
        return [parsed["raw"].rstrip('\n')]

    #=======
    @staticmethod
    def insert_random_instruction_after(parsed, context):
        """在指令后插入一条随机生成的指令"""
        random_inst = RandomInstructionGenerator.generate_one(context=context)
        return [parsed["raw"].rstrip('\n'), random_inst]

    @staticmethod
    def fence_insertion(parsed, context):
        """别名：插入屏障（指向 insert_fence_before）"""
        return MutationOperators.insert_fence_before(parsed, context)

    @staticmethod
    def instruction_deletion(parsed, context):
        """别名：删除指令（指向 delete_instruction）"""
        return MutationOperators.delete_instruction(parsed, context)

    # ================================================================
    # Part 7: 别名兼容（来自 anchors.json）
    # ================================================================

    @staticmethod
    def call_skip_or_replace(parsed, context):
        """
        ✅ 修订：根据用户要求，call 指令不再变异。
        
        原因：用户要求保护栈帧相关指令，但不包含函数调用、跳转。
        然而实践表明，删除/替换 call 极易破坏控制流（缺少 ret 配对、
        ABI 寄存器约定等），因此本算子改为 no-op。
        
        如需变异 call，建议通过 combo_spectre_rsb 在 call 周围插入
        lfence/nop/pause（不修改 call 本身）。
        """
        return [parsed["raw"].rstrip('\n')]
    
    @staticmethod
    def insert_random_instruction_before(parsed, context):
        """
        在指令前插入一条"良性随机指令"。
        
        ✅ 保护：栈帧/控制流指令不变异
        ✅ 安全：只插入对寄存器/栈无副作用的指令
                （xor %eax,%eax 之类会破坏寄存器状态，避免使用）
        """
        if MutationOperators._is_stack_frame_instruction(parsed):
            return [parsed["raw"].rstrip('\n')]
        if parsed.get("kind") != "instruction":
            return [parsed["raw"].rstrip('\n')]
        
        # 良性指令池：完全无副作用（仅占据 ROB 槽位）
        BENIGN_INSNS = [
            "nop",
            "nop",            # 多次出现以提高权重
            "pause",
            "lfence",
            "data16 nop",
            "xchg %ax, %ax",  # 等价 nop
        ]
        import random
        chosen = random.choice(BENIGN_INSNS)
        indent = parsed.get("indent", "\t")
        original = parsed["raw"].rstrip('\n')
        return ["{}{}\n".format(indent, chosen), original]
    

    
    # ---- 插入类（_before 后缀） ----
    insert_nop_before = insert_nop
    insert_fence_before = insert_fence
    
    # ---- 替换为 nop ----
    # 已在前面单独实现，这里仅作引用确认
    # replace_with_nop = replace_with_nop  # 已存在
    
    # ---- 立即数变异系列 ----
    mutate_comparison_constant = mutate_immediate_value
    mutate_loop_bound = mutate_immediate_value
    mutate_stack_offset = mutate_address_offset
    scale_loop_bound = mutate_immediate_value
    
    # ---- 比较/分支系列 ----
    flip_comparison_sign = mutate_branch_condition
    replace_branch_target = mutate_branch_target

    @staticmethod
    def comparison_swap(parsed, context):
        """别名：mutate_comparison_swap"""
        return MutationOperators.mutate_comparison_swap(parsed, context)

    @staticmethod
    def address_offset_mutation(parsed, context):
        """别名：mutate_address_offset"""
        return MutationOperators.mutate_address_offset(parsed, context)

    @staticmethod
    def branch_condition_mutation(parsed, context):
        """别名：mutate_branch_condition"""
        return MutationOperators.mutate_branch_condition(parsed, context)


# ====================================================================
# 第八部分：组合变异策略
# ====================================================================

class ComboMutationPatterns(object):
    """组合变异模式检测与应用"""

    @staticmethod
    def detect_patterns(anchors):
        """
        检测可应用组合变异的指令模式。

        返回 list of dict:
          pattern_name:  模式名称
          anchors:       涉及的 anchor 列表
          probability:   应用概率
        """
        patterns = []

        # ---- 模式 1: Spectre v1 比较 + 分支对 ----
        for i, anchor in enumerate(anchors):
            kinds = set(anchor.get("anchor_kinds", []))
            if "comparison_anchor" not in kinds:
                continue
            for j in range(i + 1, min(i + 6, len(anchors))):
                next_a = anchors[j]
                next_mn = next_a.get("mnemonic", "").lower()
                next_kinds = set(next_a.get("anchor_kinds", []))
                if next_mn in BRANCH_MNEMONICS or "branch_anchor" in next_kinds:
                    patterns.append({
                        "pattern_name": "spectre_v1_cmp_branch",
                        "anchors": [anchor, next_a],
                        "probability": 0.45,
                    })
                    break

        # ---- 模式 2: 同一 causal_object 涉及多个 anchor ----
        obj_to_anchors = {}
        for anchor in anchors:
            for obj_ref in anchor.get("causal_objects", []):
                if obj_ref not in obj_to_anchors:
                    obj_to_anchors[obj_ref] = []
                obj_to_anchors[obj_ref].append(anchor)

        for obj_ref, obj_anchors in obj_to_anchors.items():
            if 2 <= len(obj_anchors) <= 5:
                patterns.append({
                    "pattern_name": "same_causal_object_batch",
                    "anchors": obj_anchors,
                    "shared_object": obj_ref,
                    "probability": 0.30,
                })

        # ---- 模式 3: Spectre v4 store-load ----
        stores = []
        loads = []
        for anchor in anchors:
            kinds = set(anchor.get("anchor_kinds", []))
            if "memory_value_anchor" not in kinds:
                continue
            disasm = anchor.get("disasm", "").lower()
            # Intel 语法：第一个操作数是目标
            # store: mov [mem], reg → '[' 在第一个操作数
            # load:  mov reg, [mem] → '[' 在第二个操作数
            parts = disasm.split(',', 1)
            if len(parts) == 2:
                if '[' in parts[0]:
                    stores.append(anchor)
                elif '[' in parts[1]:
                    loads.append(anchor)

        for sa in stores:
            sa_objs = set(sa.get("causal_objects", []))
            for la in loads:
                la_objs = set(la.get("causal_objects", []))
                shared = sa_objs & la_objs
                if shared:
                    patterns.append({
                        "pattern_name": "spectre_v4_store_load",
                        "anchors": [sa, la],
                        "shared_objects": list(shared),
                        "probability": 0.25,
                    })

        # ---- 模式 4: Spectre RSB call ----
        for anchor in anchors:
            mn = anchor.get("mnemonic", "").lower()
            if mn not in ("call", "callq"):
                continue
            disasm = anchor.get("disasm", "")
            is_protected = any(t in disasm for t in PROTECTED_CALL_TARGETS)
            if not is_protected:
                patterns.append({
                    "pattern_name": "spectre_rsb_call",
                    "anchors": [anchor],
                    "probability": 0.20,
                })

        # ---- 模式 5: 瞬态窗口扩展 ----
        for anchor in anchors:
            kinds = set(anchor.get("anchor_kinds", []))
            if "memory_value_anchor" in kinds and \
               "address_calc_anchor" in kinds:
                patterns.append({
                    "pattern_name": "transient_window_extension",
                    "anchors": [anchor],
                    "probability": 0.20,
                })

        return patterns

    @staticmethod
    def apply_pattern(pattern, asm_lines, line_map):
        """
        应用组合变异模式。

        返回:
          (mutated_pcs: set, applied: bool)
        """
        name = pattern["pattern_name"]
        anchors = pattern["anchors"]

        if name == "spectre_v1_cmp_branch":
            return ComboMutationPatterns._apply_spectre_v1(
                anchors, asm_lines, line_map)
        elif name == "same_causal_object_batch":
            return ComboMutationPatterns._apply_same_object_batch(
                anchors, asm_lines, line_map)
        elif name == "spectre_v4_store_load":
            return ComboMutationPatterns._apply_spectre_v4(
                anchors, asm_lines, line_map)
        elif name == "spectre_rsb_call":
            return ComboMutationPatterns._apply_spectre_rsb(
                anchors, asm_lines, line_map)
        elif name == "transient_window_extension":
            return ComboMutationPatterns._apply_window_extension(
                anchors, asm_lines, line_map)
        return set(), False

    @staticmethod
    def _apply_spectre_v1(anchors, asm_lines, line_map):
        """Spectre v1: 比较+分支对变异"""
        cmp_a, br_a = anchors[0], anchors[1]
        cmp_pc, br_pc = cmp_a.get("pc"), br_a.get("pc")
        cmp_idx = line_map.get(cmp_pc)
        br_idx = line_map.get(br_pc)
        if cmp_idx is None or br_idx is None:
            return set(), False

        mutated = set()
        strategy = random.choice([
            "invert_branch",
            "mutate_bound",
            "insert_fence_between",
            "nop_comparison",
            "swap_cmp_operands",
        ])

        if strategy == "invert_branch":
            parsed = parse_asm_line(asm_lines[br_idx])
            result = MutationOperators.mutate_branch_condition(parsed, {})
            if result != [parsed["raw"].rstrip('\n')]:
                asm_lines[br_idx] = result[0] + "\n"
                mutated.add(br_pc)

        elif strategy == "mutate_bound":
            parsed = parse_asm_line(asm_lines[cmp_idx])
            result = MutationOperators.mutate_immediate(parsed, {})
            if result != [parsed["raw"].rstrip('\n')]:
                asm_lines[cmp_idx] = result[0] + "\n"
                mutated.add(cmp_pc)

        elif strategy == "insert_fence_between":
            insert_idx = min(cmp_idx, br_idx) + 1
            asm_lines.insert(insert_idx, "\tlfence\n")
            _shift_line_map(line_map, insert_idx, 1)
            mutated.add(cmp_pc)

        elif strategy == "nop_comparison":
            asm_lines[cmp_idx] = "\tnop\n"
            mutated.add(cmp_pc)

        elif strategy == "swap_cmp_operands":
            parsed = parse_asm_line(asm_lines[cmp_idx])
            ops = parsed.get("operands", [])
            if len(ops) == 2:
                swapped = [ops[1], ops[0]]
                line = reconstruct_line(parsed["mnemonic"], swapped,
                                        parsed.get("indent", "\t"),
                                        parsed.get("comment", ""))
                asm_lines[cmp_idx] = line + "\n"
                mutated.add(cmp_pc)

        return mutated, len(mutated) > 0

    @staticmethod
    def _apply_same_object_batch(anchors, asm_lines, line_map):
        """同一 causal_object 批量变异"""
        mutated = set()
        strategy = random.choice([
            "mutate_all_immediates",
            "nop_all",
            "insert_fences_all",
        ])

        for anchor in anchors:
            pc = anchor.get("pc")
            idx = line_map.get(pc)
            if idx is None or idx >= len(asm_lines):
                continue
            parsed = parse_asm_line(asm_lines[idx])
            if parsed["kind"] != "instruction":
                continue

            if strategy == "mutate_all_immediates":
                result = MutationOperators.mutate_immediate(parsed, {})
                if result != [parsed["raw"].rstrip('\n')]:
                    asm_lines[idx] = result[0] + "\n"
                    mutated.add(pc)
            elif strategy == "nop_all":
                asm_lines[idx] = "\tnop\n"
                mutated.add(pc)
            elif strategy == "insert_fences_all":
                fence = random.choice(["mfence", "lfence", "sfence"])
                asm_lines.insert(idx, "\t{}\n".format(fence))
                _shift_line_map(line_map, idx, 1)
                mutated.add(pc)

        return mutated, len(mutated) > 0

    @staticmethod
    def _apply_spectre_v4(anchors, asm_lines, line_map):
        """Spectre v4: store-load"""
        store_a, load_a = anchors[0], anchors[1]
        store_idx = line_map.get(store_a.get("pc"))
        load_idx = line_map.get(load_a.get("pc"))
        if store_idx is None or load_idx is None:
            return set(), False

        mutated = set()
        strategy = random.choice([
            "insert_fence_between",
            "mutate_store_displacement",
            "nop_store",
        ])

        if strategy == "insert_fence_between":
            pos = min(store_idx, load_idx) + 1
            asm_lines.insert(pos, "\tmfence\n")
            _shift_line_map(line_map, pos, 1)
            mutated.add(store_a.get("pc"))
        elif strategy == "mutate_store_displacement":
            parsed = parse_asm_line(asm_lines[store_idx])
            result = MutationOperators.mutate_displacement(parsed, {})
            if result != [parsed["raw"].rstrip('\n')]:
                asm_lines[store_idx] = result[0] + "\n"
                mutated.add(store_a.get("pc"))
        elif strategy == "nop_store":
            asm_lines[store_idx] = "\tnop\n"
            mutated.add(store_a.get("pc"))

        return mutated, len(mutated) > 0

    @staticmethod
    def _apply_spectre_rsb(anchors, asm_lines, line_map):
        """Spectre RSB: 在 call 附近插入栈操作干扰 (修复版: 移除危险的 duplicate_call)"""
        call_a = anchors[0]
        call_idx = line_map.get(call_a.get("pc"))
        if call_idx is None:
            return set(), False

        mutated = set()
        # 移除 "duplicate_call" - 它会破坏控制流导致 SIGSEGV
        strategy = random.choice([
            "insert_lfence_before",
            "insert_nops_after",
            "insert_pause_before",
        ])

        if strategy == "insert_lfence_before":
            asm_lines.insert(call_idx, "\tlfence\n")
            _shift_line_map(line_map, call_idx, 1)
            mutated.add(call_a.get("pc"))

        elif strategy == "insert_nops_after":
            n = random.randint(1, 4)
            for offset in range(n):
                asm_lines.insert(call_idx + 1 + offset, "\tnop\n")
            _shift_line_map(line_map, call_idx + 1, n)
            mutated.add(call_a.get("pc"))

        elif strategy == "insert_pause_before":
            asm_lines.insert(call_idx, "\tpause\n")
            _shift_line_map(line_map, call_idx, 1)
            mutated.add(call_a.get("pc"))

        return mutated, len(mutated) > 0

    @staticmethod
    def _apply_window_extension(anchors, asm_lines, line_map):
        """瞬态窗口扩展：在内存访问前插入慢指令"""
        anchor = anchors[0]
        idx = line_map.get(anchor.get("pc"))
        if idx is None:
            return set(), False

        slow_choices = [
            ["\timul $0x42, %rcx, %rcx\n"],
            ["\timul $0x37, %rcx, %rcx\n"],
            ["\tpause\n"],
            ["\tnop\n", "\tnop\n", "\tnop\n", "\tnop\n"],
            ["\tlfence\n"],
        ]
        inserts = random.choice(slow_choices)
        for offset, il in enumerate(inserts):
            asm_lines.insert(idx + offset, il)
        _shift_line_map(line_map, idx, len(inserts))

        return {anchor.get("pc")}, True


def _shift_line_map(line_map, from_idx, delta):
    """插入/删除行后更新 PC→行索引映射"""
    updated = {}
    for pc, idx in line_map.items():
        if idx >= from_idx:
            updated[pc] = idx + delta
        else:
            updated[pc] = idx
    line_map.clear()
    line_map.update(updated)


# ====================================================================
# 第九部分：PC → 行索引映射
# ====================================================================

class PcLineMapper(object):
    """
    PC → 汇编行索引映射器。

    使用多级策略：
      1. 精确匹配 disasm 中的关键特征
      2. 助记符 + 操作数模糊匹配
      3. 记录所有 anchor 的 disasm 特征用于反向查找
    """

    def __init__(self, anchors, asm_lines):
        self.anchors = anchors
        self.asm_lines = asm_lines
        self.pc_to_line = {}
        self.line_to_pc = {}
        self._build_map()

    def _build_map(self):
        """构建映射（双向归一化匹配版）"""
        parsed_lines = []
        for i, line in enumerate(self.asm_lines):
            parsed_lines.append(parse_asm_line(line))

        # 行已被占用集合（避免多个 anchor 抢同一行的最高分时全部映射到同一行）
        used_lines = set()

        # 按 anchor 顺序匹配，每个 anchor 找一个未被占用的最佳行
        for anchor in self.anchors:
            pc_raw = anchor.get("pc", "")
            pc_norm = normalize_pc(pc_raw)
            if not pc_norm:
                continue

            target_mn = anchor.get("mnemonic", "") or ""
            target_disasm = (anchor.get("disasm", "") or "").lower()

            if not target_mn:
                continue

            best_idx = None
            best_score = -1

            for i, parsed in enumerate(parsed_lines):
                if i in used_lines:
                    continue
                if parsed["kind"] != "instruction":
                    continue

                # 关键修复：双向归一化匹配
                if not mnemonics_match(parsed["mnemonic"], target_mn):
                    continue

                score = 10  # 助记符匹配基础分

                if target_disasm:
                    score += self._operand_similarity(
                        parsed, target_disasm, anchor)

                if score > best_score:
                    best_score = score
                    best_idx = i

            if best_idx is not None and best_score >= 10:
                self.pc_to_line[pc_norm] = best_idx
                self.line_to_pc[best_idx] = pc_norm
                used_lines.add(best_idx)

        # 诊断日志
        matched_count = len(self.pc_to_line)
        total_anchors = len(self.anchors)
        if total_anchors > 0:
            ratio = 100.0 * matched_count / total_anchors
            logger.info(
                "[PcLineMapper] Matched {}/{} anchors ({:.1f}%)".format(
                    matched_count, total_anchors, ratio))
            if ratio < 50.0:
                # 统计未匹配的助记符分布
                unmatched_by_mn = {}
                for anchor in self.anchors:
                    pc_raw = anchor.get("pc", "")
                    pc_norm = normalize_pc(pc_raw)
                    if pc_norm and pc_norm not in self.pc_to_line:
                        mn = anchor.get("mnemonic", "?")
                        unmatched_by_mn[mn] = unmatched_by_mn.get(mn, 0) + 1
                if unmatched_by_mn:
                    top = sorted(unmatched_by_mn.items(),
                                 key=lambda x: -x[1])[:10]
                    logger.warning(
                        "[PcLineMapper] Low match ratio. "
                        "Top unmatched mnemonics: {}".format(top))

    def _operand_similarity(self, parsed, target_disasm, anchor):
        """计算操作数相似度（保持原逻辑不变）"""
        score = 0
        line_ops = " ".join(parsed.get("operands", [])).lower()

        for obj_ref in anchor.get("causal_objects", []):
            if obj_ref.startswith("reg:"):
                reg = obj_ref[4:]
                if reg in line_ops:
                    score += 3
            elif obj_ref.startswith("var:"):
                var = obj_ref[4:]
                if var in line_ops:
                    score += 5
            elif obj_ref.startswith("stack:"):
                stack_expr = obj_ref[6:]
                if "rbp" in line_ops:
                    score += 2
                m = re.search(r'0x([0-9a-f]+)', stack_expr)
                if m and m.group(1) in line_ops:
                    score += 3

        for obj_ref in anchor.get("explanatory_objects", []):
            if obj_ref.startswith("imm_occurrence:"):
                parts = obj_ref.split(":")
                if len(parts) >= 5:
                    imm_val = parts[4]
                    try:
                        val = int(imm_val, 16) if imm_val.startswith("0x") \
                              else int(imm_val)
                        if val > 0x7FFFFFFFFFFFFFFF:
                            val = val - 0x10000000000000000
                        short_hex = hex(abs(val))
                        if short_hex[2:] in line_ops:
                            score += 4
                    except ValueError:
                        pass

        return score

    def get_line(self, pc):
        """获取 PC 对应的行索引"""
        npc = normalize_pc(pc)
        return self.pc_to_line.get(npc)

    def get_pc(self, line_idx):
        """获取行索引对应的 PC"""
        return self.line_to_pc.get(line_idx)

    def get_map(self):
        """获取完整映射（可变引用，供组合变异使用）"""
        return self.pc_to_line


# ====================================================================
# 第十部分：主变异调度器
# ====================================================================

class MutationScheduler(object):
    """变异调度器（完整实现）"""

    def __init__(self, anchors, strong_objects, stage=1):
        """
        参数:
          anchors:        assembly_anchor_candidates.json 的列表
          strong_objects: strong_causal_objects.json 的列表
          stage:          当前阶段 (1/2/3)
        """
        self.anchors = anchors if anchors else []
        self.strong_objects = strong_objects if strong_objects else []
        #self.anchors = []  # 原本是 anchors
        #self.strong_objects = []  # 原本是 strong_objects
        self.stage = stage

        # 预处理索引
        self.anchor_by_pc = {}
        self.strong_object_ids = set()
        self.strong_object_by_id = {}
        self.anchor_priorities = {}

        self._precompute()

        # 保护判定器
        self.protection = ProtectionChecker()

        # 循环感知
        self.loop_awareness = LoopAwareness(self.anchors, self.strong_objects)

        self._validate_mutator_registry()
        self._current_constraint_ctx = None

    def _scan_referenced_labels(self, asm_lines):
            """
            扫描汇编中所有被引用的局部标签 (.L\d+, .Lxxx 等)。
            
            这些标签必须保护其定义行不被删除, 否则链接器会报
            'undefined reference' 错误。
            
            返回: set of label names (含点前缀)
            """
            referenced = set()
            # 匹配 jmp/jXX/call 等指令的目标
            # 也匹配 leaq .L6(%rip), %rax 这种地址加载
            label_pattern = re.compile(r'(\.L[A-Za-z0-9_]+)')
            
            for line in asm_lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                # 跳过标签定义行本身 (避免把定义算作引用)
                if stripped.endswith(':') and stripped.startswith('.L'):
                    continue
                for m in label_pattern.finditer(line):
                    referenced.add(m.group(1))
            
            return referenced

    def _validate_mutator_registry(self):
        """
        验证变异算子注册表（完整版）。
        
        检查所有 anchors 中的 recommended_mutations 和
        _build_semantic_operator_pool 中使用的算子是否都已实现。
        """
        expected = set([
            # 通用算子
            "instruction_deletion",
            "nop_insertion",
            "fence_insertion",
            "random_instruction_insertion",
            "insert_flush_before",
            
            # 立即数语义算子
            "mutate_comparison_constant",
            "flip_comparison_sign",
            "mutate_loop_bound",
            "scale_loop_bound",
            "mutate_stack_offset",
            "mutate_address_offset",
            "mutate_shift_amount",
            "mutate_immediate_value",
            
            # 寄存器语义算子
            "swap_operands",
            "replace_with_constant",
            "mutate_address_base",
            "swap_address_components",
            "mutate_address_index",
            "swap_comparison_operands",
            "swap_arithmetic_operands",
            "replace_register",
            
            # 栈/内存语义算子
            "delete_stack_operation",
            "mutate_array_index",
            "mutate_array_base",
            "mutate_memory_offset",
            "mutate_memory_operand",
            
            # 操作码语义算子
            "replace_arithmetic_opcode",
            "replace_comparison_opcode",
            "invert_branch_condition",
            "replace_branch_target",
            
            # 组合算子
            "combo_cmp_branch",
            "combo_same_object_batch",
            "combo_spectre_v1",
            "combo_spectre_rsb",
        ])

        # 从 anchors 中收集 recommended_mutations
        for a in self.anchors:
            for m in a.get("recommended_mutations", []):
                expected.add(m)

        # 别名映射（将旧名称映射到新实现）
        alias = {
            # 通用算子别名
            "instruction_deletion": "delete_instruction",
            "nop_insertion": "insert_nop_before",
            "fence_insertion": "insert_fence_before",
            "random_instruction_insertion": "insert_random_instruction_before",
            "fence_insertion": "insert_fence_before",
            
            # anchors.json 中的别名
            "call_skip_or_replace": "call_skip_or_replace",
            "immediate_value_mutation": "mutate_immediate_value",
            "opcode_replacement": "replace_arithmetic_opcode",
            "operand_mutation": "operand_mutation",
            
            # 立即数语义算子（已实现，无需别名）
            "mutate_comparison_constant": "mutate_comparison_constant",
            "flip_comparison_sign": "flip_comparison_sign",
            "mutate_loop_bound": "mutate_loop_bound",
            "scale_loop_bound": "scale_loop_bound",
            "mutate_stack_offset": "mutate_stack_offset",
            "mutate_address_offset": "mutate_address_offset",
            "mutate_shift_amount": "mutate_shift_amount",
            "mutate_immediate_value": "mutate_immediate_value",
            
            # 寄存器语义算子（已实现，无需别名）
            "swap_operands": "swap_operands",
            "replace_with_constant": "replace_with_constant",
            "mutate_address_base": "mutate_address_base",
            "swap_address_components": "swap_address_components",
            "mutate_address_index": "mutate_address_index",
            "swap_comparison_operands": "swap_comparison_operands",
            "swap_arithmetic_operands": "swap_arithmetic_operands",
            "replace_register": "replace_register",
            
            # 栈/内存语义算子（已实现，无需别名）
            "delete_stack_operation": "delete_stack_operation",
            "mutate_array_index": "mutate_array_index",
            "mutate_array_base": "mutate_array_base",
            "mutate_memory_offset": "mutate_memory_offset",
            "mutate_memory_operand": "mutate_memory_operand",
            
            # 操作码语义算子（已实现，无需别名）
            "replace_arithmetic_opcode": "replace_arithmetic_opcode",
            "replace_comparison_opcode": "replace_comparison_opcode",
            "invert_branch_condition": "invert_branch_condition",
            "replace_branch_target": "replace_branch_target",
            
            # 组合算子（已实现，无需别名）
            "combo_cmp_branch": "combo_cmp_branch",
            "combo_same_object_batch": "combo_same_object_batch",
            "combo_spectre_v1": "combo_spectre_v1",
            "combo_spectre_rsb": "combo_spectre_rsb",
        }

        # 验证所有算子是否已实现
        missing = []
        for name in sorted(expected):
            resolved = alias.get(name, name)
            if getattr(MutationOperators, resolved, None) is None:
                missing.append((name, resolved))

        if missing:
            logger.warning("Missing mutators detected at startup:")
            for name, resolved in missing:
                logger.warning("  selected=%s resolved=%s", name, resolved)
        else:
            logger.info("All {} mutators validated successfully".format(len(expected)))

    def _get_anchor_pc(self, anchor):
        """获取 anchor 的 PC（归一化输出）"""
        raw = anchor.get("pc", "") if isinstance(anchor, dict) else ""
        return normalize_pc(raw)

    def _precompute(self):
        """预计算优先级和索引"""
        for obj in self.strong_objects:
            oid = obj.get("object_id", "")
            self.strong_object_ids.add(oid)
            self.strong_object_by_id[oid] = obj

        for anchor in self.anchors:
            pc = self._get_anchor_pc(anchor)
            self.anchor_by_pc[pc] = anchor
            priority = self._compute_priority(anchor)
            self.anchor_priorities[pc] = priority

        if self.anchor_priorities:
            sorted_p = sorted(self.anchor_priorities.items(),
                              key=lambda x: -x[1])
            logger.info("Stage {}: {} anchors prioritized".format(
                self.stage, len(sorted_p)))
            for pc, pri in sorted_p[:5]:
                logger.debug("  Top anchor: PC={}, priority={:.1f}".format(
                    pc, pri))

    def _compute_priority(self, anchor):
        """计算 anchor 优先级分数"""
        priority = 0.0

        tier = anchor.get("anchor_tier", "")
        tier_weights = {"primary": 30, "secondary": 15, "contextual": 5}
        priority += tier_weights.get(tier, 1)

        kinds = anchor.get("anchor_kinds", [])
        stage_kind_weights = {
            1: {"comparison_anchor": 25, "branch_anchor": 20,
                "immediate_anchor": 15, "loop_bound_anchor": 15,
                "arithmetic_anchor": 5, "memory_value_anchor": 3,
                "address_calc_anchor": 3},
            2: {"memory_value_anchor": 25, "address_calc_anchor": 20,
                "immediate_anchor": 15, "arithmetic_anchor": 15,
                "comparison_anchor": 5, "branch_anchor": 5},
            3: {"memory_value_anchor": 20, "address_calc_anchor": 15,
                "comparison_anchor": 10, "immediate_anchor": 15,
                "arithmetic_anchor": 10, "branch_anchor": 10},
        }
        kind_w = stage_kind_weights.get(self.stage, {})
        for k in kinds:
            priority += kind_w.get(k, 0)

        for obj_ref in anchor.get("causal_objects", []):
            obj = self.strong_object_by_id.get(obj_ref)
            if obj:
                dist = obj.get("backward_distance")
                if dist is not None:
                    priority += max(0, 10 - dist * 2)
                role = obj.get("causal_role_class", "")
                role_weights = {
                    "key_constant": 15, "comparison_participant": 12,
                    "loop_bound_constant": 10, "arithmetic_participant": 8,
                    "variable": 10, "generic_mutable_object": 5,
                }
                priority += role_weights.get(role, 0)

        if anchor.get("is_prologue_epilogue", False):
            priority *= PROLOGUE_EPILOGUE_DECAY

        return max(priority, 0.01)

    def _compute_mutation_probability(self, pc, anchor, locked_pcs):
        """
        计算单条指令的变异概率。

        概率 = base_tier_prob × causal_boost × prologue_decay
                               × loop_modifier
        """
        if pc in locked_pcs:
            return 0.0

        # 基础概率
        if anchor:
            # ---- Anchor 指令 ----
            tier = anchor.get("anchor_tier", "contextual")
            base_prob = TIER_BASE_PROBABILITY.get(tier, 0.35)
            
            # 强因果对象加成/衰减
            causal_objs = set(anchor.get("causal_objects_full_mutation", []))
            if causal_objs & self.strong_object_ids:
                # ✅ 强相关 Anchor：加成
                base_prob *= STRONG_CAUSAL_BOOST  # 1.3
            else:
                # ✅ 非强相关 Anchor：衰减
                base_prob *= WEAK_CAUSAL_DECAY  # 0.7
            
            # 序言/尾声衰减
            if anchor.get("is_prologue_epilogue", False):
                base_prob *= PROLOGUE_EPILOGUE_DECAY
            
            # 循环感知修正
            loop_mod = self.loop_awareness.get_probability_modifier(pc)
            base_prob *= loop_mod
        
        else:
            # ---- 非 Anchor 指令 ----
            base_prob = NON_ANCHOR_BASE_PROBABILITY  # 0.10

        return min(max(base_prob, 0.0), 1.0)

    def _select_mutator_for_anchor(self, anchor, parsed):
        """
        为 anchor 指令选择变异算子（对象语义驱动版）。

        策略：
          1. 根据强相关对象的语义类型动态选择算子
          2. recommended_mutations 仅作为参考（不强制）
          3. 所有指令都有概率应用通用/特殊/组合算子

        增约束（选项 A）：
          - Stage >= 2 且 anchor 为 CFG 敏感 → 返回 noop（强制保留原行）
          - Stage >= 2 且当前行在软锁集中 → 仅允许等价变异（无可用则 noop）
          - Stage == 1 保持原有逻辑
        """
        # ============================================================
        # 第一步：根据对象语义构建算子池
        # ============================================================
        semantic_operators = self._build_semantic_operator_pool(anchor, parsed)
        
        # ============================================================
        # 第二步：添加通用算子（所有指令都有概率）
        # ============================================================
        all_operators = self._merge_with_generic_operators(
            semantic_operators, 
            generic_weight=0.15  # 15% 权重给通用算子
        )
        
        # ============================================================
        # 第三步：添加特殊算子（基于指令类型）
        # ============================================================
        all_operators = self._add_special_operators(all_operators, parsed)
        
        # ============================================================
        # 第四步：添加组合算子（特定模式）
        # ============================================================
        all_operators = self._add_combo_operators(all_operators, anchor, parsed)

        # ---- 新增：CFG 闸门 ----
        if self.stage >= 2:
            # 闸门 1：anchor 本身 CFG 敏感 → 不变异
            if is_cfg_sensitive_anchor(anchor) or \
               is_cfg_sensitive_instruction(parsed):
                return self._noop_mutator, "cfg_protected_noop"

            # 闸门 2：当前行在软锁集中 → 仅等价变异
            ctx = self._current_constraint_ctx
            if ctx is not None:
                cur_line = ctx.get("line_idx", -1)
                soft_set = ctx.get("soft_locked_lines") or set()
                if cur_line in soft_set:
                    eq_choice = self._select_equivalent_mutator(parsed)
                    if eq_choice is not None:
                        return eq_choice
                    return self._noop_mutator, "soft_locked_noop"
        
        # ============================================================
        # 第五步：概率加权选择
        # ============================================================
        return self._weighted_select_from_dict(all_operators)
    
    def _build_semantic_operator_pool(self, anchor, parsed):
        """
        根据强相关对象的语义类型构建算子池。

        返回: {operator_name: weight}
        """
        operators = {}
        
        causal_objs = anchor.get("causal_objects_full_mutation", [])
        mn = parsed.get("mnemonic", "")
        
        # ---- 遍历所有因果对象 ----
        for obj_id in causal_objs:
            if obj_id not in self.strong_object_by_id:
                continue
            
            obj = self.strong_object_by_id[obj_id]
            obj_type = obj.get("object_type", "")
            tags = set(obj.get("semantic_tags", []))
            role = obj.get("causal_role_class", "")
            
            # ============================================================
            # 立即数对象
            # ============================================================
            if obj_type == "imm":
                if "comparison_constant" in tags:
                    # 比较常量：±1, ±2, 翻转符号
                    operators["mutate_comparison_constant"] = 0.35
                    operators["flip_comparison_sign"] = 0.15
                
                elif "loop_bound_constant" in tags:
                    # 循环边界：±1, ×2, ÷2
                    operators["mutate_loop_bound"] = 0.30
                    operators["scale_loop_bound"] = 0.15
                
                elif "frame_offset_constant" in tags or "stack_offset" in tags:
                    # 栈帧偏移：±8 (对齐)
                    operators["mutate_stack_offset"] = 0.25
                
                elif "address_offset_constant" in tags:
                    # 地址偏移：±cache_line_size
                    operators["mutate_address_offset"] = 0.28
                
                elif "shift_amount" in tags:
                    # 位移量：±1, ±4
                    operators["mutate_shift_amount"] = 0.22
                
                else:
                    # 通用立即数
                    operators["mutate_immediate_value"] = 0.20
            
            # ============================================================
            # 寄存器对象
            # ============================================================
            elif obj_type == "reg":
                if "controlling_operand" in tags:
                    # 控制操作数：交换、替换为常量
                    operators["swap_operands"] = 0.25
                    operators["replace_with_constant"] = 0.15
                
                elif "address_base" in tags:
                    # 地址基址：修改基址寄存器
                    operators["mutate_address_base"] = 0.28
                    operators["swap_address_components"] = 0.12
                
                elif "address_index" in tags:
                    # 地址索引：修改索引寄存器
                    operators["mutate_address_index"] = 0.26
                
                elif "comparison_participant" in tags:
                    # 比较参与者：交换操作数
                    operators["swap_comparison_operands"] = 0.30
                
                elif "arithmetic_operand" in tags:
                    # 算术操作数：交换、替换
                    operators["swap_arithmetic_operands"] = 0.22
                    operators["replace_register"] = 0.15
                
                else:
                    # 通用寄存器
                    operators["replace_register"] = 0.18
            
            # ============================================================
            # 栈对象
            # ============================================================
            elif obj_type == "stack":
                if "local_variable" in tags:
                    # 局部变量：修改偏移
                    operators["mutate_stack_offset"] = 0.25
                
                elif "function_argument" in tags:
                    # 函数参数：修改偏移（谨慎）
                    operators["mutate_stack_offset"] = 0.15
                
                elif "saved_register" in tags:
                    # 保存的寄存器：删除（探索性）
                    operators["delete_stack_operation"] = 0.12
                
                else:
                    # 通用栈操作
                    operators["mutate_stack_offset"] = 0.20
            
            # ============================================================
            # 内存对象
            # ============================================================
            elif obj_type == "mem":
                if "array_access" in tags:
                    # 数组访问：修改索引/基址
                    operators["mutate_array_index"] = 0.28
                    operators["mutate_array_base"] = 0.15
                
                elif "pointer_dereference" in tags:
                    # 指针解引用：修改偏移
                    operators["mutate_memory_offset"] = 0.22
                
                else:
                    # 通用内存操作
                    operators["mutate_memory_operand"] = 0.20
        
        # ============================================================
        # 操作码相关（基于指令类型）
        # ============================================================
        if mn in ARITHMETIC_MNEMONICS:
            operators["replace_arithmetic_opcode"] = 0.22
        
        if mn in COMPARE_MNEMONICS:
            operators["replace_comparison_opcode"] = 0.18
        
        if mn in BRANCH_MNEMONICS:
            operators["invert_branch_condition"] = 0.35
            operators["replace_branch_target"] = 0.10
        
        # ============================================================
        # 归一化权重
        # ============================================================
        total = sum(operators.values())
        if total > 0:
            operators = {k: v/total for k, v in operators.items()}
        
        return operators
    
    def _merge_with_generic_operators(self, semantic_ops, generic_weight=0.15):
        """
        融合通用算子。

        参数:
          semantic_ops:   语义算子字典 {operator_name: weight}
          generic_weight: 通用算子的总权重（默认 15%）

        返回: 融合后的算子字典
        """
        # 通用算子池
        generic_ops = {
            "instruction_deletion": 0.05,
            "nop_insertion": 0.03,
            "fence_insertion": 0.04,
            "random_instruction_insertion": 0.03,
        }
        
        # 语义算子占 (1 - generic_weight)
        semantic_weight = 1.0 - generic_weight
        
        merged = {}
        
        # 缩放语义算子
        for op, weight in semantic_ops.items():
            merged[op] = weight * semantic_weight
        
        # 添加通用算子
        for op, weight in generic_ops.items():
            merged[op] = weight * generic_weight
        
        return merged


    def _add_special_operators(self, operators, parsed):
        """
        添加特殊算子（基于指令类型）。

        参数:
          operators: 当前算子字典
          parsed:    解析后的指令

        返回: 更新后的算子字典
        """
        mn = parsed.get("mnemonic", "")
        
        # 分支指令特殊算子
        if mn in BRANCH_MNEMONICS:
            operators["invert_branch_condition"] = operators.get("invert_branch_condition", 0) + 0.05
        
        # 比较指令特殊算子
        if mn in COMPARE_MNEMONICS:
            operators["replace_comparison_opcode"] = operators.get("replace_comparison_opcode", 0) + 0.04
        
        # 算术指令特殊算子
        if mn in ARITHMETIC_MNEMONICS:
            operators["replace_arithmetic_opcode"] = operators.get("replace_arithmetic_opcode", 0) + 0.04
        
        # 内存访问特殊算子
        if parsed.get("has_memory_operand"):
            operators["mutate_memory_operand"] = operators.get("mutate_memory_operand", 0) + 0.03
        
        # 归一化
        total = sum(operators.values())
        if total > 0:
            operators = {k: v/total for k, v in operators.items()}
        
        return operators
    
    def _add_combo_operators(self, operators, anchor, parsed):
        """
        添加组合算子（特定模式）。

        参数:
          operators: 当前算子字典
          anchor:    锚点信息
          parsed:    解析后的指令

        返回: 更新后的算子字典
        """
        mn = parsed.get("mnemonic", "")
        
        # cmp + jcc 组合
        if mn in COMPARE_MNEMONICS:
            operators["combo_cmp_branch"] = 0.08
        
        # 同对象批量变异
        causal_objs = anchor.get("causal_objects_full_mutation", [])
        if len(causal_objs) > 1:
            operators["combo_same_object_batch"] = 0.05
        
        # Spectre 模式（Stage 1）
        if self.stage == 1:
            operators["combo_spectre_v1"] = 0.06
            operators["combo_spectre_rsb"] = 0.04
        
        # 归一化
        total = sum(operators.values())
        if total > 0:
            operators = {k: v/total for k, v in operators.items()}
        
        return operators
    
    
    def _weighted_select_from_dict(self, operators):
        """
        从算子字典中加权随机选择。

        参数:
          operators: {operator_name: weight}

        返回: (mutator_func, mutator_name)
        """
        if not operators:
            # 兜底：返回删除指令
            return (MutationOperators.delete_instruction, "delete_instruction")
        
        # 构建候选列表
        ops = list(operators.keys())
        weights = list(operators.values())
        
        # 加权随机选择
        selected_name = random.choices(ops, weights=weights, k=1)[0]
        
        # 获取对应的函数
        mutator_func = getattr(MutationOperators, selected_name, None)
        if mutator_func is None:
            # 如果函数不存在，返回删除指令
            logger.warning(f"Mutator function not found: {selected_name}")
            return (MutationOperators.delete_instruction, "delete_instruction")
        
        return (mutator_func, selected_name)


    def _select_mutator_for_non_anchor(self, parsed):
        """为非 anchor 指令选择变异算子"""
        mn = parsed.get("mnemonic", "")

        candidates = [
            (MutationOperators.delete_instruction,
             "delete_instruction", 0.08),
            (MutationOperators.replace_with_nop,
             "replace_with_nop", 0.12),
            (MutationOperators.insert_nop_before,
             "insert_nop_before", 0.10),
            (MutationOperators.insert_fence_before,
             "insert_fence_before", 0.08),
            (MutationOperators.insert_random_instruction_before,
             "insert_random_before", 0.10),
            (MutationOperators.insert_random_instruction_after,
             "insert_random_after", 0.10),
            (MutationOperators.insert_random_sequence,
             "insert_random_sequence", 0.06),
            (MutationOperators.replace_with_random_instruction,
             "replace_with_random", 0.08),

            (MutationOperators.insert_flush_before,
             "insert_flush_before", 0.05),
        ]

        if mn in BRANCH_MNEMONICS:
            candidates.append((MutationOperators.mutate_branch_condition,
                               "mutate_branch_condition", 0.12))
        has_imm = any(
            extract_immediate(op) is not None
            for op in parsed.get("operands", [])
        )

        if mn in COMPARE_MNEMONICS or has_imm:
            candidates.append((MutationOperators.mutate_immediate,
                            "mutate_immediate", 0.12))

        if mn in COMPARE_MNEMONICS:
            candidates.append((MutationOperators.mutate_comparison_swap,
                               "mutate_comparison", 0.08))
        if mn in ARITHMETIC_MNEMONICS:
            candidates.append((MutationOperators.mutate_opcode_arithmetic,
                               "mutate_opcode_arithmetic", 0.10))

        for op in parsed.get("operands", []):
            if extract_immediate(op) is not None:
                candidates.append((MutationOperators.mutate_immediate,
                                   "mutate_immediate", 0.12))
                break

        if has_memory_operand(parsed):
            candidates.append((MutationOperators.mutate_displacement,
                               "mutate_displacement", 0.10))
            
        # ---- 新增：CFG 闸门 ----
        if self.stage >= 2:
            # 闸门 1：当前行 CFG 敏感 → 不变异
            if is_cfg_sensitive_instruction(parsed):
                return self._noop_mutator, "cfg_protected_noop"

            # 闸门 2：软锁集
            ctx = self._current_constraint_ctx
            if ctx is not None:
                cur_line = ctx.get("line_idx", -1)
                soft_set = ctx.get("soft_locked_lines") or set()
                if cur_line in soft_set:
                    eq_choice = self._select_equivalent_mutator(parsed)
                    if eq_choice is not None:
                        return eq_choice
                    return self._noop_mutator, "soft_locked_noop"

        return self._weighted_select(candidates)
    
    def _noop_mutator(self, parsed, context):
        """
        空操作变异算子。返回 None 表示不改变（apply_mutation 主循环会保留原行）。
        """
        return None
    
    # =================================================================
    # 新增工具：等价变异算子选择
    # =================================================================
    def _select_equivalent_mutator(self, parsed):
        """
        为软锁定行选择等价变异算子。

        策略：
          - 优先选择 insert_nop_before / insert_nop_after（最安全）
          - 其次 insert_fence_before
          - 若无可用 → 返回 None

        返回 (mutator_func, mutator_name) 或 None
        """
        # 这些算子需要在你的 mutator 模块中实际存在
        # 若不存在，可以使用此处提供的轻量内置实现
        candidates = [
            (self._equiv_insert_nop_before, "insert_nop_before"),
            (self._equiv_insert_nop_after, "insert_nop_after"),
            (self._equiv_insert_lfence_before, "insert_fence_before"),
        ]

        # 按 EQUIVALENT_MUTATORS 白名单过滤（防御性）
        valid = [(f, n) for (f, n) in candidates
                 if n in EQUIVALENT_MUTATORS]
        if not valid:
            return None

        return random.choice(valid)
    
    # =================================================================
    # 新增工具：内置等价变异算子实现
    # =================================================================
    def _equiv_insert_nop_before(self, parsed, context):
        """在原指令前插入 1 条 nop。等价变异：完全不改变寄存器/内存状态。"""
        indent = parsed.get("indent", "\t")
        original_raw = parsed.get("raw", "")
        if not original_raw.endswith('\n'):
            original_raw += '\n'
        return [indent + "nop\n", original_raw]
    
    def _equiv_insert_nop_after(self, parsed, context):
        """在原指令后插入 1 条 nop。"""
        indent = parsed.get("indent", "\t")
        original_raw = parsed.get("raw", "")
        if not original_raw.endswith('\n'):
            original_raw += '\n'
        return [original_raw, indent + "nop\n"]
    
    def _equiv_insert_lfence_before(self, parsed, context):
        """在原指令前插入 lfence。等价变异：仅插入串行化屏障，不改变寄存器值。"""
        indent = parsed.get("indent", "\t")
        original_raw = parsed.get("raw", "")
        if not original_raw.endswith('\n'):
            original_raw += '\n'
        return [indent + "lfence\n", original_raw]


    def _weighted_select(self, candidates):
        """
        加权随机选择，压缩概率差距确保多样性。

        返回: (func, name)
        """
        if not candidates:
            return (MutationOperators.replace_with_nop, "replace_with_nop")

        weights = [w for _, _, w in candidates]
        min_w = min(weights)
        max_w = max(weights)

        # 压缩：最高不超过最低的 4 倍
        if max_w > min_w * 4:
            compressed_weights = []
            for _, _, w in candidates:
                new_w = min_w + (w - min_w) / (max_w - min_w) * (min_w * 3)
                compressed_weights.append(new_w)
        else:
            compressed_weights = weights

        total = sum(compressed_weights)
        if total <= 0:
            return candidates[0][0], candidates[0][1]

        r = random.random() * total
        cumulative = 0.0
        for idx, (func, name, _) in enumerate(candidates):
            cumulative += compressed_weights[idx]
            if r <= cumulative:
                return func, name

        return candidates[-1][0], candidates[-1][1]

    # ----------------------------------------------------------------
    # 兼容旧接口
    # ----------------------------------------------------------------

    def select_anchor(self, cross_stage_locked_pcs=None):
        """加权随机选择单个 anchor（兼容旧接口）"""
        exclude = set(cross_stage_locked_pcs) \
            if cross_stage_locked_pcs else set()

        candidates = []
        for a in self.anchors:
            pc = self._get_anchor_pc(a)
            if pc in exclude:
                continue
            pri = self.anchor_priorities.get(pc, 0.01)
            candidates.append((a, pri))

        if not candidates:
            return None

        weights = [p ** 2 for _, p in candidates]
        selected_idx = random.choices(range(len(candidates)),
                                      weights=weights, k=1)[0]
        return candidates[selected_idx][0]

    # ----------------------------------------------------------------
    # 核心入口
    # ----------------------------------------------------------------

    def apply_mutation(self, seed_asm_path, anchor_or_none, work_dir,
                       cross_stage_locked_pcs=None,
                       stage3_config=None):
        """
        应用一轮完整变异（含跨阶段约束 + CFG 闸门 + 软锁集 + 结果后置校验）。

        新增行为：
          - 跨阶段硬锁定 PC 通过双向归一化后查表，避免 mnemonic 后缀失配
          - 计算硬锁定行的数据依赖前驱作为软锁集
          - Stage >= 2 时拒绝任何变异结果中包含 CFG 敏感指令
          - 软锁集行仅允许等价变异
        """
        # ---- 锁定集归一化 ----
        locked_pcs = normalize_pc_set(cross_stage_locked_pcs) \
            if cross_stage_locked_pcs else set()

        # ---- 读取文件 ----
        try:
            with open(seed_asm_path, 'r', encoding='utf-8') as f:
                asm_lines = f.readlines()
        except Exception as e:
            logger.error("Failed to read seed: {}".format(e))
            return None

        # ---- 扫描所有被引用的局部标签 ----
        referenced_labels = self._scan_referenced_labels(asm_lines)
        logger.debug("Protected referenced labels: {} found".format(
            len(referenced_labels)))

        # ---- 建立 PC→行映射（已使用双向归一化匹配的修复版）----
        mapper = PcLineMapper(self.anchors, asm_lines)
        line_map = mapper.get_map()  # key 已归一化

        # ---- 计算软锁集（仅 Stage >= 2）----
        if self.stage >= 2 and locked_pcs:
            lock_info = compute_soft_locked_line_indices(
                asm_lines=asm_lines,
                hard_locked_pcs=locked_pcs,
                pc_to_line_map=line_map,
                max_lookback=20,
                max_depth=3,
            )
            hard_locked_lines = lock_info["hard_locked_lines"]
            soft_locked_lines = lock_info["soft_locked_lines"]
            logger.info(
                "[Stage {}] Cross-stage locks: {} hard PCs → "
                "{} hard lines + {} soft (predecessor) lines".format(
                    self.stage, len(locked_pcs),
                    len(hard_locked_lines), len(soft_locked_lines)))
        else:
            hard_locked_lines = set()
            soft_locked_lines = set()

        # 安装约束上下文（供选择器读取）
        self._current_constraint_ctx = {
            "stage": self.stage,
            "soft_locked_lines": soft_locked_lines,
            "line_idx": -1,
        }

        try:
            # ============================================================
            # 阶段 1: 组合变异
            # ============================================================
            combo_mutated_pcs = set()  # 此集合中的 PC 均为归一化字符串
            combo_applied = []

            patterns = ComboMutationPatterns.detect_patterns(self.anchors)
            random.shuffle(patterns)

            for pattern in patterns:
                # anchor PC 归一化
                pattern_pcs = set()
                for a in pattern["anchors"]:
                    npc = normalize_pc(self._get_anchor_pc(a))
                    if npc:
                        pattern_pcs.add(npc)

                # 跳过已锁定或已变异的
                if pattern_pcs & locked_pcs:
                    continue
                if pattern_pcs & combo_mutated_pcs:
                    continue

                # 新增 CFG 闸门：Stage >= 2 禁止涉及 CFG 敏感 anchor 的组合模式
                if self.stage >= 2:
                    has_cfg_anchor = any(
                        is_cfg_sensitive_anchor(a)
                        for a in pattern["anchors"]
                    )
                    if has_cfg_anchor:
                        continue

                if random.random() < pattern["probability"]:
                    mutated, applied = ComboMutationPatterns.apply_pattern(
                        pattern, asm_lines, line_map)
                    if applied:
                        # 归一化结果 PC
                        mutated_norm = normalize_pc_set(mutated)
                        combo_mutated_pcs |= mutated_norm
                        combo_applied.append({
                            "pattern": pattern["pattern_name"],
                            "mutated_pcs": sorted(list(mutated_norm)),
                        })

            # ============================================================
            # 阶段 2: 逐行变异
            # ============================================================
            line_mutations = []
            new_asm_lines = []
            recent_labels = []
            label_line_map = {}

            i = 0
            while i < len(asm_lines):
                line = asm_lines[i]
                parsed = parse_asm_line(line)

                # 更新当前行索引到约束上下文
                self._current_constraint_ctx["line_idx"] = i

                # 更新标签上下文
                if parsed["kind"] == "label":
                    label_name = parsed["label"]
                    recent_labels.append(label_name)
                    if len(recent_labels) > 10:
                        recent_labels = recent_labels[-10:]
                    label_line_map[label_name] = i
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # 非指令行直接保留
                if parsed["kind"] != "instruction":
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # 保护判定
                prot_ctx = {
                    "recent_labels": list(recent_labels),
                    "label_line_map": label_line_map,
                    "line_idx": i,
                }
                if self.protection.is_protected(parsed, prot_ctx):
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # 查找对应 PC（归一化）
                line_pc = mapper.get_pc(i)  # 已是归一化字符串或 None

                # 已被组合变异处理 → 跳过
                if line_pc and line_pc in combo_mutated_pcs:
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # ---- 硬锁定判定（强化）----
                # 同时检查 PC 命中 与 行索引命中
                is_hard_locked = False
                if line_pc and line_pc in locked_pcs:
                    is_hard_locked = True
                elif i in hard_locked_lines:
                    is_hard_locked = True

                if is_hard_locked:
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # ---- 新增：Stage >= 2 的全局 CFG 闸门（双保险）----
                # 即使该指令不是 anchor，只要它是 CFG 敏感的，Stage 2/3 一律不变异
                if self.stage >= 2 and is_cfg_sensitive_instruction(parsed):
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # ---- 栈帧指令处理 ----
                is_stack, stack_type = \
                    self.protection.is_stack_frame_instruction(parsed)
                if is_stack:
                    if stack_type in ("abi_frame_setup",
                                      "abi_frame_teardown",
                                      "abi_frame_pointer"):
                        if random.random() < 0.10:
                            random_inst = \
                                RandomInstructionGenerator.generate_one(
                                    category="stack")
                            # 新增：若生成的指令是 CFG 敏感（理论上不会，但防御）
                            # 或 Stage >= 2 且结果不安全，则不插入
                            candidate = [random_inst + "\n"]
                            if self.stage >= 2 and \
                               not is_result_cfg_safe(candidate):
                                # 拒绝插入，直接保留原行
                                new_asm_lines.append(line)
                                i += 1
                                continue
                            new_asm_lines.append(random_inst + "\n")
                            line_mutations.append({
                                "line_idx": i, "pc": line_pc,
                                "mutator": "rsb_insert_before_frame",
                            })
                        new_asm_lines.append(line)
                        i += 1
                        continue
                    elif stack_type == "stack_allocation":
                        pass

                # ---- 概率决策 ----
                anchor = self.anchor_by_pc.get(line_pc) if line_pc else None
                prob = self._compute_mutation_probability(
                    line_pc or "", anchor, locked_pcs)

                if random.random() >= prob:
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # ---- 选择并应用变异算子 ----
                # 选择器内部已应用 CFG 闸门 + 软锁集判定
                if anchor:
                    mutator_func, mutator_name = \
                        self._select_mutator_for_anchor(anchor, parsed)
                else:
                    mutator_func, mutator_name = \
                        self._select_mutator_for_non_anchor(parsed)

                # 软锁集行的算子合法性二次校验（防御性）
                if i in soft_locked_lines and \
                   not is_equivalent_mutator(mutator_name) and \
                   mutator_name not in ("cfg_protected_noop",
                                        "soft_locked_noop"):
                    logger.debug(
                        "Reject non-equivalent mutator '{}' "
                        "on soft-locked line {}".format(mutator_name, i))
                    new_asm_lines.append(line)
                    i += 1
                    continue

                                # 为当前 mutator 构造可回看的汇编上下文。
                # 这里不能直接传原始 asm_lines，否则 flush 看不到已经生成到
                # new_asm_lines 中的前序变异结果。
                scan_asm_lines = list(new_asm_lines) + asm_lines[i:]

                context = {
                    "anchor": anchor,
                    "stage": self.stage,
                    "line_idx": i,                 # 原始输入中的行号
                    "current_idx": len(new_asm_lines),  # scan_asm_lines 中当前行位置
                    "asm_lines": scan_asm_lines,
                    "pc": line_pc,
                    "strong_objects_map": self.strong_object_by_id,
                }

                try:
                    result = mutator_func(parsed, context)
                except Exception as e:
                    logger.debug(
                        "Mutator {} failed: {}".format(mutator_name, e))
                    new_asm_lines.append(line)
                    i += 1
                    continue

                # 统一兼容：如果某些 mutator 返回单个字符串，这里转成 list
                if isinstance(result, str):
                    result = [result]

                # ---- 新增：结果后置 CFG 校验 ----
                # Stage >= 2 时，任何包含 CFG 敏感指令的结果都拒绝
                if self.stage >= 2 and result is not None:
                    if not is_result_cfg_safe(result):
                        logger.debug(
                            "Reject CFG-sensitive result from mutator "
                            "'{}' on line {}".format(mutator_name, i))
                        new_asm_lines.append(line)
                        i += 1
                        continue

                # 处理结果
                if isinstance(result, list):
                    normalized_result = []
                    for rline in result:
                        if rline is None:
                            continue
                        if not rline.endswith('\n'):
                            rline += '\n'
                        normalized_result.append(rline)

                    original_line = line if line.endswith('\n') else (line + '\n')

                    # 关键修正：
                    # 对于 [original_line] 这种结果，视为"放弃本轮变异"，
                    # 不能记 mutation，也不能算真正修改。
                    is_noop_result = (
                        len(normalized_result) == 1 and
                        normalized_result[0] == original_line
                    )

                    if not normalized_result or is_noop_result:
                        new_asm_lines.append(line)
                    else:
                        for rline in normalized_result:
                            new_asm_lines.append(rline)

                        line_mutations.append({
                            "line_idx": i,
                            "pc": line_pc,
                            "mutator": mutator_name,
                            "original": line.rstrip('\n'),
                            "result_count": len(normalized_result),
                        })
                else:
                    # None 或其它非 list/str → 保留原行
                    new_asm_lines.append(line)

                i += 1

            # ============================================================
            # 写入变异文件
            # ============================================================
            mutant_dir = tempfile.mkdtemp(prefix="mutant_", dir=work_dir)
            mutant_path = os.path.join(mutant_dir, "mutant.s")

            try:
                with open(mutant_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_asm_lines)
            except Exception as e:
                logger.error("Failed to write mutant: {}".format(e))
                return None

            # Stage 3 配置
            if self.stage == 3:
                if stage3_config is None:
                    stage3_config = generate_stage3_config_variant()
                config_path = os.path.join(
                    mutant_dir, "stage3_config.json")
                write_stage3_config(stage3_config, config_path)

            # ---- 构建 mutation_info ----
            all_mutated_pcs = set()
            for lm in line_mutations:
                if lm.get("pc"):
                    all_mutated_pcs.add(lm["pc"])
            all_mutated_pcs |= combo_mutated_pcs

            mutation_info = {
                "anchor_pc": sorted(list(all_mutated_pcs))[0]
                             if all_mutated_pcs else None,
                "anchor_tier": "",
                "anchor_kinds": [],
                "mutation_type": "multi_point",
                "total_line_mutations": len(line_mutations),
                "total_combo_mutations": len(combo_applied),
                "mutated_pcs": sorted(list(all_mutated_pcs)),
                "combo_patterns": combo_applied,
                "line_mutation_details": line_mutations[:30],
                "stage3_config":
                    stage3_config if self.stage == 3 else None,
                # 新增诊断字段
                "constraint_summary": {
                    "stage": self.stage,
                    "hard_locked_pcs": len(locked_pcs),
                    "hard_locked_lines": len(hard_locked_lines),
                    "soft_locked_lines": len(soft_locked_lines),
                },
            }

            mutator_summary = {}
            for lm in line_mutations:
                name = lm.get("mutator", "unknown")
                mutator_summary[name] = mutator_summary.get(name, 0) + 1

            if line_mutations or combo_applied:
                logger.info(
                    "Mutation: {} line + {} combo, mutators: {}".format(
                        len(line_mutations), len(combo_applied),
                        mutator_summary))
            else:
                logger.warning(
                    "Mutation produced 0 changes (asm unchanged)")

            return mutant_path, mutation_info

        finally:
            # 清理约束上下文，避免影响下一次调用
            self._current_constraint_ctx = None


# ====================================================================
# 第十一部分：崩溃处理
# ====================================================================

SIGNAL_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
    5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
    9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
    13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
}


class ExecutionResult(object):
    """执行结果"""

    def __init__(self):
        self.success = False
        self.stdout = ""
        self.stderr = ""
        self.returncode = 0
        self.signal_num = None
        self.signal_name = ""
        self.timed_out = False
        self.crashed = False
        self.crash_type = ""

    def __repr__(self):
        if self.success:
            return "ExecutionResult(success)"
        elif self.timed_out:
            return "ExecutionResult(timeout)"
        elif self.crashed:
            return "ExecutionResult(crashed={}, signal={})".format(
                self.crash_type, self.signal_name)
        else:
            return "ExecutionResult(failed, rc={})".format(self.returncode)


def run_with_crash_handling(cmd, timeout=30, env=None, cwd=None):
    """
    运行外部命令，捕获崩溃。

    返回 ExecutionResult。
    """
    import subprocess

    result = ExecutionResult()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
        result.stdout = proc.stdout.decode("utf-8", errors="replace")
        result.stderr = proc.stderr.decode("utf-8", errors="replace")
        result.returncode = proc.returncode

        if proc.returncode == 0:
            result.success = True
        elif proc.returncode < 0:
            sig = -proc.returncode
            result.crashed = True
            result.signal_num = sig
            result.signal_name = SIGNAL_NAMES.get(sig, "SIG{}".format(sig))
            crash_map = {
                4: "illegal_instruction", 6: "abort",
                7: "bus_error", 8: "fpe",
                11: "segfault",
            }
            result.crash_type = crash_map.get(sig, "signal_{}".format(sig))
        else:
            result.success = False

    except subprocess.TimeoutExpired:
        result.timed_out = True

    except Exception as e:
        result.stderr = str(e)

    return result


def extract_partial_output(result, stage=1):
    """从崩溃/超时输出中提取部分有用信号"""
    if not result.stdout:
        return None

    lines = result.stdout.strip().split('\n')
    partial = {
        "lines": lines,
        "line_count": len(lines),
        "crashed": result.crashed,
        "crash_type": result.crash_type,
    }

    if stage == 1:
        for line in lines:
            if "BR_MISP" in line or "UOPS" in line:
                partial["has_pmu_data"] = True
                break
    elif stage == 2:
        for line in lines:
            if "L1D_MISS" in line or "CACHE" in line:
                partial["has_stage2_data"] = True
                break
    elif stage == 3:
        for line in lines:
            if "MATCH" in line or "SUCCESS" in line:
                partial["has_stage3_data"] = True
                break

    return partial

# ====================================================================
# 启动自检：确保所有被引用的算子都已实现
# ====================================================================
def _self_check_operators():
    """检查 MutationOperators 是否提供所有被引用的算子。"""
    REQUIRED_OPERATORS = [
        # ---- Part 1: 控制流 ----
        "delete_instruction", "insert_nop", "insert_fence",
        "mutate_branch_condition", "invert_branch_condition",
        "mutate_branch_target", "duplicate_instruction",
        "replace_with_nop",
        # ---- Part 2: 立即数 ----
        "mutate_address_offset", "mutate_shift_amount",
        "mutate_immediate_value", "mutate_immediate",
        "immediate_value_mutation",
        # ---- Part 3: 寄存器 ----
        "swap_operands", "swap_comparison_operands",
        "swap_arithmetic_operands", "replace_with_constant",
        "mutate_address_base", "swap_address_components",
        "mutate_address_index", "replace_register",
        "mutate_register", "operand_mutation",
        # ---- Part 4: 栈/内存 ----
        "delete_stack_operation", "mutate_array_index",
        "mutate_array_base", "mutate_memory_offset",
        "mutate_memory_operand", "mutate_displacement",
        # ---- Part 5: 操作码 ----
        "replace_arithmetic_opcode", "mutate_opcode_arithmetic",
        "opcode_replacement", "replace_comparison_opcode",
        # ---- Part 6: 组合 ----
        "combo_cmp_branch", "combo_same_object_batch",
        "combo_spectre_v1", "combo_spectre_rsb",
        "combo_spectre_v4", "combo_transient_window_extension",
        # ---- Part 7: 兼容别名（关键！ ----
        "call_skip_or_replace",
        "insert_nop_before", "insert_fence_before",
        "insert_random_instruction_before",
        "mutate_comparison_constant", "mutate_loop_bound",
        "mutate_stack_offset", "scale_loop_bound",
        "flip_comparison_sign", "replace_branch_target",
    ]
    missing = []
    for name in REQUIRED_OPERATORS:
        if not hasattr(MutationOperators, name):
            missing.append(name)
    if missing:
        import sys
        sys.stderr.write(
            "[mutation_scheduler] CRITICAL: Missing operators in "
            "MutationOperators class:\n")
        for m in missing:
            sys.stderr.write("  - {}\n".format(m))
        raise AttributeError(
            "MutationOperators missing methods: {}".format(missing))

_self_check_operators()
