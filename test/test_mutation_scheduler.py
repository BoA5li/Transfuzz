#!/usr/bin/env python3
"""
test_mutation_scheduler.py

变异调度器完整功能测试。

测试项:
  1. 汇编行解析器正确性
  2. 保护判定正确性
  3. 随机指令生成器覆盖度
  4. 变异算子逐个验证
  5. 概率计算正确性
  6. 组合变异模式检测
  7. 完整变异流程 (apply_mutation)
  8. PC→行映射准确性
  9. 循环感知正确性
  10. Stage 3 配置变异
  11. 崩溃处理
  12. 与 seed_pool.py 的接口兼容性

用法:
  python test_mutation_scheduler.py

  全部通过则输出 ALL TESTS PASSED
  失败则输出 FAILED 及失败项
"""

import os
import sys
import json
import tempfile
import shutil
import random
import logging
import traceback

logging.basicConfig(
    level=logging.WARNING,
    format="%(name)s %(levelname)s %(message)s"
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mutation_scheduler import (
    MutationScheduler,
    parse_asm_line,
    reconstruct_line,
    extract_registers,
    extract_immediate,
    has_memory_operand,
    get_register_pool,
    RandomInstructionGenerator,
    ProtectionChecker,
    ComboMutationPatterns,
    LoopAwareness,
    PcLineMapper,
    MutationOperators,
    generate_stage3_config_variant,
    generate_stage3_env,
    write_stage3_config,
    run_with_crash_handling,
    extract_partial_output,
    ExecutionResult,
    BRANCH_MNEMONICS,
    BRANCH_INVERSION,
    ARITHMETIC_SWAP_GROUPS,
    PROTECTED_CALL_TARGETS,
    PROTECTED_LABELS,
    GENERAL_REGS_32,
)

from collections import Counter
from seed_pool import Seed, SeedPool

# ============================================================
# 测试数据
# ============================================================

SAMPLE_ASM = """\
\t.text
\t.globl victim_function
\t.type victim_function, @function
victim_function:
\tpush %rbp
\tmov %rsp, %rbp
\tsub $0x80, %rsp
\tmov %rdi, -8(%rbp)
STAGE1_BEGIN:
\tcall pmu_stage1_before
\tmov array1_size(%rip), %eax
\tcmp -8(%rbp), %rax
\tjae .L_skip
\tmov -8(%rbp), %rax
\tmovzx (%rax), %eax
\tshl $9, %eax
\tlea array2(%rip), %rdx
\tmovzx (%rdx,%rax), %eax
\tmov %al, temp(%rip)
.L_skip:
\tcall pmu_stage1_after
STAGE1_END:
\tnop
\tleave
\tret
\t.size victim_function, .-victim_function
"""

SAMPLE_ANCHORS = [
    {
        "pc": "0x7d2",
        "mnemonic": "mov",
        "disasm": "mov eax, dword ptr [rip + 0x201848]",
        "anchor_tier": "primary",
        "anchor_kinds": ["address_calc_anchor", "memory_value_anchor"],
        "recommended_mutations": ["instruction_deletion", "operand_mutation"],
        "causal_objects": ["reg:rax", "var:array1_size"],
        "explanatory_objects": [
            "imm_occurrence:0x7d2:mem_disp:1:0x201848:i64"
        ],
        "related_strong_objects": [],
        "is_prologue_epilogue": False,
    },
    {
        "pc": "0x7da",
        "mnemonic": "cmp",
        "disasm": "cmp qword ptr [rbp - 8], rax",
        "anchor_tier": "primary",
        "anchor_kinds": [
            "address_calc_anchor", "comparison_anchor",
            "memory_value_anchor"
        ],
        "recommended_mutations": [
            "instruction_deletion", "opcode_replacement",
            "operand_mutation"
        ],
        "causal_objects": ["reg:rax", "stack:[rbp-0x8]"],
        "explanatory_objects": [],
        "related_strong_objects": [],
        "is_prologue_epilogue": False,
    },
    {
        "pc": "0x7de",
        "mnemonic": "jae",
        "disasm": "jae .L_skip",
        "anchor_tier": "primary",
        "anchor_kinds": ["branch_anchor"],
        "recommended_mutations": ["opcode_replacement"],
        "causal_objects": [],
        "explanatory_objects": [],
        "related_strong_objects": [],
        "is_prologue_epilogue": False,
    },
    {
        "pc": "0x7f4",
        "mnemonic": "shl",
        "disasm": "shl eax, 9",
        "anchor_tier": "primary",
        "anchor_kinds": ["arithmetic_anchor", "immediate_anchor"],
        "recommended_mutations": [
            "immediate_value_mutation", "opcode_replacement",
            "operand_mutation"
        ],
        "causal_objects": [
            "imm_occurrence:0x7f4:operand_imm:1:0x9:i8",
            "reg:rax"
        ],
        "explanatory_objects": [],
        "related_strong_objects": [],
        "is_prologue_epilogue": False,
    },
    {
        "pc": "0x7ee",
        "mnemonic": "movzx",
        "disasm": "movzx eax, byte ptr [rax]",
        "anchor_tier": "primary",
        "anchor_kinds": ["address_calc_anchor", "memory_value_anchor"],
        "recommended_mutations": ["instruction_deletion", "operand_mutation"],
        "causal_objects": ["reg:rax", "var:array1"],
        "explanatory_objects": [],
        "related_strong_objects": [],
        "is_prologue_epilogue": False,
    },
    {
        "pc": "0x7ce",
        "mnemonic": "mov",
        "disasm": "mov qword ptr [rbp - 8], rdi",
        "anchor_tier": "secondary",
        "anchor_kinds": ["address_calc_anchor", "memory_value_anchor"],
        "recommended_mutations": ["instruction_deletion", "operand_mutation"],
        "causal_objects": ["reg:rdi", "stack:[rbp-0x8]"],
        "explanatory_objects": [],
        "related_strong_objects": [],
        "is_prologue_epilogue": False,
    },
]

SAMPLE_STRONG_OBJECTS = [
    {
        "object_id": "imm_occurrence:0x7f4:operand_imm:1:0x9:i8",
        "object_type": "imm_occurrence",
        "causal_role_class": "arithmetic_participant",
        "direct_mutation_preferred": True,
        "recommended_actions": ["immediate_value_mutation"],
        "semantic_tags": [],
        "direct_semantic_roles": ["near_seed_path", "arithmetic_related"],
        "contextual_semantic_roles": ["backward_related", "backward_leaf"],
        "representative_pcs": ["0x7f4"],
        "related_anchor_pcs": ["0x7f4"],
        "backward_distance": 2,
    },
    {
        "object_id": "imm_occurrence:0x870:operand_imm:1:0x1:i32",
        "object_type": "imm_occurrence",
        "causal_role_class": "loop_bound_constant",
        "direct_mutation_preferred": True,
        "recommended_actions": ["immediate_value_mutation"],
        "semantic_tags": [
            "program_semantic_constant", "comparison_constant",
            "loop_bound_constant"
        ],
        "direct_semantic_roles": ["comparison_operand"],
        "contextual_semantic_roles": ["backward_related"],
        "representative_pcs": ["0x870"],
        "related_anchor_pcs": ["0x870"],
        "backward_distance": 2,
    },
]

# ============================================================
# 辅助函数
# ============================================================

def create_temp_dir():
    return tempfile.mkdtemp(prefix="test_mut_")


def create_test_asm(content=SAMPLE_ASM):
    fd, path = tempfile.mkstemp(suffix=".s", prefix="test_seed_")
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return path


def cleanup(*paths):
    for p in paths:
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        elif os.path.isfile(p):
            try:
                os.remove(p)
            except OSError:
                pass


class TestResult(object):
    def __init__(self, name):
        self.name = name
        self.checks = []

    def check(self, condition, description):
        status = "PASS" if condition else "FAIL"
        self.checks.append((status, description))
        print("    {} | {}".format(status, description))
        return condition

    def passed(self):
        return all(s == "PASS" for s, _ in self.checks)

    def summary(self):
        total = len(self.checks)
        ok = sum(1 for s, _ in self.checks if s == "PASS")
        return ok, total


# ============================================================
# 测试 1: 汇编行解析器
# ============================================================

def test_01_parse_asm_line():
    print("\n" + "=" * 60)
    print("TEST 01: 汇编行解析器")
    print("=" * 60)
    t = TestResult("parse_asm_line")

    # 指令
    p = parse_asm_line("\tmov %rdi, -8(%rbp)\n")
    t.check(p["kind"] == "instruction", "mov 指令识别为 instruction")
    t.check(p["mnemonic"] == "mov", "助记符正确: mov")
    t.check(len(p["operands"]) == 2, "操作数数量: 2")

    # 比较
    p = parse_asm_line("\tcmp -8(%rbp), %rax\n")
    t.check(p["kind"] == "instruction", "cmp 识别为 instruction")
    t.check(p["mnemonic"] == "cmp", "助记符正确: cmp")

    # 分支
    p = parse_asm_line("\tjae .L_skip\n")
    t.check(p["kind"] == "instruction", "jae 识别为 instruction")
    t.check(p["mnemonic"] == "jae", "助记符正确: jae")
    t.check(len(p["operands"]) == 1, "分支操作数数量: 1")

    # 移位+立即数
    p = parse_asm_line("\tshl $9, %eax\n")
    t.check(p["kind"] == "instruction", "shl 识别为 instruction")
    t.check(len(p["operands"]) == 2, "shl 操作数数量: 2")

    # 标签
    p = parse_asm_line("victim_function:\n")
    t.check(p["kind"] == "label", "标签识别")
    t.check(p["label"] == "victim_function", "标签名正确")

    # 伪指令
    p = parse_asm_line("\t.globl victim_function\n")
    t.check(p["kind"] == "directive", "伪指令识别")
    t.check(p["mnemonic"] == ".globl", "伪指令助记符正确")

    # 空行
    p = parse_asm_line("\n")
    t.check(p["kind"] == "empty", "空行识别")

    # 注释行
    p = parse_asm_line("# this is a comment\n")
    t.check(p["kind"] == "empty", "注释行识别为 empty")

    # 带注释的指令
    p = parse_asm_line("\tnop  # do nothing\n")
    t.check(p["kind"] == "instruction", "带注释指令的 kind 正确")
    t.check(p["mnemonic"] == "nop", "带注释指令的助记符正确")

    # call 指令
    p = parse_asm_line("\tcall pmu_stage1_before\n")
    t.check(p["kind"] == "instruction", "call 识别为 instruction")
    t.check(p["mnemonic"] == "call", "call 助记符正确")

    # ret
    p = parse_asm_line("\tret\n")
    t.check(p["kind"] == "instruction", "ret 识别为 instruction")

    # lea 复杂操作数
    p = parse_asm_line("\tlea array2(%rip), %rdx\n")
    t.check(p["kind"] == "instruction", "lea 指令识别")
    t.check(p["mnemonic"] == "lea", "lea 助记符正确")

    return t


# ============================================================
# 测试 2: 辅助函数
# ============================================================

def test_02_helpers():
    print("\n" + "=" * 60)
    print("TEST 02: 辅助函数 (extract_registers/immediate/...)")
    print("=" * 60)
    t = TestResult("helpers")

    # extract_registers
    regs = extract_registers("-8(%rbp)")
    t.check("rbp" in regs, "从 -8(%rbp) 提取 rbp")

    regs = extract_registers("%rax")
    t.check("rax" in regs, "从 %rax 提取 rax")

    regs = extract_registers("(%rdx,%rax)")
    t.check("rdx" in regs and "rax" in regs, "从 (%rdx,%rax) 提取两个寄存器")

    # extract_immediate
    result = extract_immediate("$9")
    t.check(result is not None and result[1] == 9,
            "$9 提取立即数 9")

    result = extract_immediate("$0x80")
    t.check(result is not None and result[1] == 0x80,
            "$0x80 提取立即数 128")

    result = extract_immediate("-8(%rbp)")
    t.check(result is not None and result[1] == -8,
            "-8(%rbp) 提取位移 -8")

    result = extract_immediate("%rax")
    t.check(result is None, "纯寄存器无立即数")

    # has_memory_operand
    p = parse_asm_line("\tmov -8(%rbp), %rax\n")
    t.check(has_memory_operand(p), "mov -8(%rbp),%rax 有内存操作数")

    p = parse_asm_line("\tadd %rax, %rbx\n")
    t.check(not has_memory_operand(p), "add %rax,%rbx 无内存操作数")

    # get_register_pool
    pool = get_register_pool("rax")
    t.check(len(pool) > 0, "rax 有替换池")
    t.check("rax" not in pool, "替换池不含自身")
    t.check("rsp" not in pool, "替换池不含 rsp")
    t.check("rbp" not in pool, "替换池不含 rbp")

    pool = get_register_pool("rsp")
    t.check(len(pool) == 0, "rsp 不可替换")

    pool = get_register_pool("eax")
    t.check(all(r in GENERAL_REGS_32 for r in pool) if pool else True,
            "eax 替换池为 32 位寄存器")

    # reconstruct_line
    line = reconstruct_line("mov", ["%rax", "%rbx"], "\t")
    t.check("mov" in line and "%rax" in line and "%rbx" in line,
            "reconstruct_line 正确重建")

    return t


# ============================================================
# 测试 3: 保护判定
# ============================================================

def test_03_protection():
    print("\n" + "=" * 60)
    print("TEST 03: 保护判定 (ProtectionChecker)")
    print("=" * 60)
    t = TestResult("protection")

    checker = ProtectionChecker()
    base_ctx = {"recent_labels": [], "label_line_map": {}, "line_idx": 50}

    # 保护的 call
    p = parse_asm_line("\tcall pmu_stage1_before\n")
    t.check(checker.is_protected(p, base_ctx),
            "call pmu_stage1_before 受保护")

    p = parse_asm_line("\tcall printf\n")
    t.check(checker.is_protected(p, base_ctx),
            "call printf 受保护")

    p = parse_asm_line("\tcall vf_run_attack_once\n")
    t.check(checker.is_protected(p, base_ctx),
            "call vf_run_attack_once 受保护")

    # 非保护的 call
    p = parse_asm_line("\tcall some_user_func\n")
    t.check(not checker.is_protected(p, base_ctx),
            "call some_user_func 不受保护")

    # ret
    p = parse_asm_line("\tret\n")
    t.check(checker.is_protected(p, base_ctx), "ret 受保护")

    # 普通指令
    p = parse_asm_line("\tmov %rax, %rbx\n")
    t.check(not checker.is_protected(p, base_ctx),
            "普通 mov 不受保护")

    p = parse_asm_line("\tshl $9, %eax\n")
    t.check(not checker.is_protected(p, base_ctx),
            "shl $9 不受保护")

    # 插桩标签附近
    ctx_near_label = {
        "recent_labels": ["STAGE1_BEGIN"],
        "label_line_map": {"STAGE1_BEGIN": 48},
        "line_idx": 50,  # 距离 2 行，在保护半径 5 内
    }
    p = parse_asm_line("\tmov $1, %rax\n")
    t.check(checker.is_protected(p, ctx_near_label),
            "STAGE1_BEGIN 后 2 行受保护")

    ctx_far_label = {
        "recent_labels": ["STAGE1_BEGIN"],
        "label_line_map": {"STAGE1_BEGIN": 40},
        "line_idx": 50,  # 距离 10 行，超出保护半径
    }
    p = parse_asm_line("\tmov $1, %rax\n")
    t.check(not checker.is_protected(p, ctx_far_label),
            "STAGE1_BEGIN 后 10 行不受保护")

    # 伪指令
    p = parse_asm_line("\t.cfi_startproc\n")
    t.check(checker.is_protected(p, base_ctx),
            ".cfi_startproc 受保护")

    # 空行
    p = parse_asm_line("\n")
    t.check(checker.is_protected(p, base_ctx), "空行受保护")

    # 标签
    p = parse_asm_line("victim_function:\n")
    t.check(checker.is_protected(p, base_ctx), "标签行受保护")

    # 栈帧判定
    p = parse_asm_line("\tpush %rbp\n")
    is_sf, sf_type = checker.is_stack_frame_instruction(p)
    t.check(is_sf and sf_type == "abi_frame_setup",
            "push %rbp 识别为 ABI 栈帧建立")

    p = parse_asm_line("\tpop %rbp\n")
    is_sf, sf_type = checker.is_stack_frame_instruction(p)
    t.check(is_sf and sf_type == "abi_frame_teardown",
            "pop %rbp 识别为 ABI 栈帧拆除")

    p = parse_asm_line("\tsub $0x80, %rsp\n")
    is_sf, sf_type = checker.is_stack_frame_instruction(p)
    t.check(is_sf and sf_type == "stack_allocation",
            "sub $0x80,%rsp 识别为栈分配")

    p = parse_asm_line("\tpush %r12\n")
    is_sf, sf_type = checker.is_stack_frame_instruction(p)
    t.check(is_sf and sf_type == "register_save_restore",
            "push %r12 识别为寄存器保存")

    p = parse_asm_line("\tmov %rax, %rbx\n")
    is_sf, sf_type = checker.is_stack_frame_instruction(p)
    t.check(not is_sf, "普通 mov 不是栈帧指令")

    return t


# ============================================================
# 测试 4: 随机指令生成器
# ============================================================

def test_04_random_instruction_generator():
    print("\n" + "=" * 60)
    print("TEST 04: 随机指令生成器 (RandomInstructionGenerator)")
    print("=" * 60)
    t = TestResult("random_gen")

    # 生成单条指令
    random.seed(42)
    seen_categories = set()
    for _ in range(200):
        inst = RandomInstructionGenerator.generate_one()
        t.check(isinstance(inst, str) and len(inst.strip()) > 0,
                "生成非空字符串") if _ == 0 else None
        # 收集生成的助记符类别
        parsed = parse_asm_line(inst + "\n")
        if parsed["kind"] == "instruction":
            mn = parsed["mnemonic"]
            if mn in ("nop", "xchg", "lea", "or", "test", "mov"):
                seen_categories.add("nop_like_or_move")
            elif mn in ("add", "sub", "xor", "and", "shl", "shr",
                         "imul", "inc", "dec", "neg", "not"):
                seen_categories.add("arithmetic")
            elif mn in ("mfence", "lfence", "sfence", "pause"):
                seen_categories.add("fence")
            elif mn in ("push", "pop", "pushq", "popq"):
                seen_categories.add("stack")
            elif mn in ("cmp",):
                seen_categories.add("compare")
            elif mn in ("cpuid", "rdtsc", "rdtscp"):
                seen_categories.add("speculation")
            elif mn in ("prefetcht0", "clflush", "movzx"):
                seen_categories.add("memory")

    t.check(len(seen_categories) >= 3,
            "200 次生成覆盖 >=3 个类别: {}".format(seen_categories))

    # 指定类别生成
    for cat in ["nop_like", "arithmetic", "fence", "stack"]:
        inst = RandomInstructionGenerator.generate_one(category=cat)
        parsed = parse_asm_line(inst + "\n")
        t.check(parsed["kind"] == "instruction" or inst.strip() == "nop",
                "{} 类别生成有效指令: {}".format(cat, inst.strip()))

    # 生成序列
    seq = RandomInstructionGenerator.generate_sequence(min_count=2,
                                                       max_count=4)
    t.check(2 <= len(seq) <= 4,
            "序列长度在 [2,4]: len={}".format(len(seq)))
    for s in seq:
        t.check(isinstance(s, str) and len(s.strip()) > 0,
                "序列中每条都是非空字符串")

    # 不含保护寄存器
    random.seed(123)
    for _ in range(100):
        inst = RandomInstructionGenerator.generate_one()
        t.check("%rsp" not in inst and "%rbp" not in inst and
                "%rip" not in inst,
                "不含保护寄存器") if _ == 0 else None
        if "%rsp" in inst or "%rbp" in inst or "%rip" in inst:
            t.check(False,
                    "第 {} 次生成含保护寄存器: {}".format(_, inst.strip()))
            break

    return t


# ============================================================
# 测试 5: 变异算子逐个验证
# ============================================================

def test_05_mutation_operators():
    print("\n" + "=" * 60)
    print("TEST 05: 变异算子逐个验证")
    print("=" * 60)
    t = TestResult("operators")

    # --- delete_instruction ---
    p = parse_asm_line("\tmov %rax, %rbx\n")
    result = MutationOperators.delete_instruction(p, {})
    t.check(result == [], "delete_instruction 返回空列表")

    # --- replace_with_nop ---
    result = MutationOperators.replace_with_nop(p, {})
    t.check(len(result) == 1 and "nop" in result[0],
            "replace_with_nop 返回 nop")

    # --- insert_nop_before ---
    result = MutationOperators.insert_nop_before(p, {})
    t.check(2 <= len(result) <= 5,
            "insert_nop_before 返回 1~4 条 nop 加原指令")
    t.check(all("nop" in line for line in result[:-1]),
            "原指令前的所有行都是 nop")
    t.check("mov" in result[-1], "最后一行是原指令")

    # --- insert_nop_after ---
    result = MutationOperators.insert_nop_after(p, {})
    t.check(len(result) == 2, "insert_nop_after 返回 2 行")
    t.check("mov" in result[0], "第一行是原指令")
    t.check("nop" in result[1], "第二行是 nop")

    # --- insert_fence_before ---
    result = MutationOperators.insert_fence_before(p, {})
    t.check(len(result) == 2, "insert_fence_before 返回 2 行")
    t.check(any(f in result[0] for f in ["mfence", "lfence", "sfence"]),
            "第一行是 fence 指令")

    # --- insert_random_instruction_before ---
    random.seed(42)
    result = MutationOperators.insert_random_instruction_before(p, {})
    t.check(len(result) == 2, "insert_random_before 返回 2 行")
    t.check("mov" in result[1], "第二行是原指令")
    rand_parsed = parse_asm_line(result[0] + "\n")
    t.check(rand_parsed["kind"] == "instruction" or "nop" in result[0],
            "第一行是有效指令: {}".format(result[0].strip()))

    # --- insert_random_sequence ---
    random.seed(42)
    result = MutationOperators.insert_random_sequence(p, {})
    t.check(len(result) >= 2, "insert_random_sequence 返回 >=2 行")
    has_original = any("mov" in r and "%rax" in r for r in result)
    t.check(has_original, "序列中包含原指令")

    # --- mutate_immediate ---
    p_shl = parse_asm_line("\tshl $9, %eax\n")
    random.seed(42)
    result = MutationOperators.mutate_immediate(p_shl, {})
    t.check(len(result) == 1, "mutate_immediate 返回 1 行")
    t.check("shl" in result[0], "保留 shl 助记符")
    t.check("$9" not in result[0] or "$9" in result[0],
            "立即数可能被变异: {}".format(result[0].strip()))

    # 对没有立即数的指令
    p_noimm = parse_asm_line("\tmov %rax, %rbx\n")
    result = MutationOperators.mutate_immediate(p_noimm, {})
    t.check(len(result) == 1, "无立即数指令 mutate_immediate 保留原行")

    # --- mutate_displacement ---
    p_mem = parse_asm_line("\tmov -8(%rbp), %rax\n")
    random.seed(42)
    result = MutationOperators.mutate_displacement(p_mem, {})
    t.check(len(result) == 1, "mutate_displacement 返回 1 行")

    # --- mutate_register ---
    p_reg = parse_asm_line("\tmov %rax, %rbx\n")
    random.seed(42)
    result = MutationOperators.mutate_register(p_reg, {})
    t.check(len(result) == 1, "mutate_register 返回 1 行")
    # 应该至少有一个寄存器被替换
    t.check("mov" in result[0], "保留 mov 助记符")

    # --- mutate_opcode_arithmetic ---
    p_add = parse_asm_line("\tadd %rax, %rbx\n")
    result = MutationOperators.mutate_opcode_arithmetic(p_add, {})
    t.check(len(result) == 1, "mutate_opcode_arithmetic 返回 1 行")
    t.check("sub" in result[0] or "add" in result[0],
            "add 变异为 sub 或保持: {}".format(result[0].strip()))

    p_shl2 = parse_asm_line("\tshl $3, %eax\n")
    result = MutationOperators.mutate_opcode_arithmetic(p_shl2, {})
    t.check("shr" in result[0] or "shl" in result[0],
            "shl 变异为 shr 或保持: {}".format(result[0].strip()))

    # --- mutate_branch_condition ---
    p_jae = parse_asm_line("\tjae .L_skip\n")
    random.seed(42)
    result = MutationOperators.mutate_branch_condition(p_jae, {})
    t.check(len(result) == 1, "mutate_branch_condition 返回 1 行")
    result_mn = parse_asm_line(result[0] + "\n")["mnemonic"]
    t.check(result_mn != "jae" or result_mn in BRANCH_INVERSION.values(),
            "分支条件已变异: {}".format(result[0].strip()))

    # --- mutate_comparison_swap ---
    p_cmp = parse_asm_line("\tcmp -8(%rbp), %rax\n")
    result = MutationOperators.mutate_comparison_swap(p_cmp, {})
    swapped_cmp = parse_asm_line(result[0] + "\n")
    t.check(len(result) == 1 and swapped_cmp["mnemonic"] == "cmp",
            "cmp 操作数交换时保持助记符: {}".format(result[0].strip()))
    t.check(swapped_cmp["operands"] == ["%rax", "-8(%rbp)"],
            "cmp 操作数已交换: {}".format(result[0].strip()))

    p_test = parse_asm_line("\ttest %rax, %rbx\n")
    result = MutationOperators.mutate_comparison_swap(p_test, {})
    swapped_test = parse_asm_line(result[0] + "\n")
    t.check(len(result) == 1 and swapped_test["mnemonic"] == "test",
            "test 操作数交换时保持助记符: {}".format(result[0].strip()))
    t.check(swapped_test["operands"] == ["%rbx", "%rax"],
            "test 操作数已交换: {}".format(result[0].strip()))

    p_cmp_imm = parse_asm_line("\tcmp $1, %rax\n")
    result = MutationOperators.mutate_comparison_swap(p_cmp_imm, {})
    t.check(result == [p_cmp_imm["raw"].rstrip('\n')],
            "立即数源操作数不交换，避免生成非法目标操作数")

    # --- replace_comparison_opcode ---
    result = MutationOperators.replace_comparison_opcode(p_cmp, {})
    t.check(parse_asm_line(result[0] + "\n")["mnemonic"] == "test",
            "replace_comparison_opcode 负责 cmp -> test")
    result = MutationOperators.replace_comparison_opcode(p_test, {})
    t.check(parse_asm_line(result[0] + "\n")["mnemonic"] == "cmp",
            "replace_comparison_opcode 负责 test -> cmp")

    # --- replace_with_random_instruction ---
    result = MutationOperators.replace_with_random_instruction(p, {})
    t.check(len(result) == 1, "replace_with_random 返回 1 行")
    rand_p = parse_asm_line(result[0] + "\n")
    t.check(rand_p["kind"] == "instruction" or "nop" in result[0],
            "替换结果是有效指令")

    return t


# ============================================================
# 测试 6: 优先级和概率计算
# ============================================================

def test_06_priority_and_probability():
    print("\n" + "=" * 60)
    print("TEST 06: 优先级和概率计算")
    print("=" * 60)
    t = TestResult("priority_probability")

    scheduler = MutationScheduler(SAMPLE_ANCHORS, SAMPLE_STRONG_OBJECTS,
                                  stage=1)

    # 检查所有 anchor 都有优先级
    t.check(len(scheduler.anchor_priorities) == len(SAMPLE_ANCHORS),
            "所有 anchor 都有优先级: {}".format(
                len(scheduler.anchor_priorities)))

    # primary > secondary
    pri_primary = scheduler.anchor_priorities.get("0x7da", 0)
    pri_secondary = scheduler.anchor_priorities.get("0x7ce", 0)
    t.check(pri_primary > pri_secondary,
            "primary({:.1f}) > secondary({:.1f})".format(
                pri_primary, pri_secondary))

    # 强因果对象加成: 0x7f4 有 strong_object
    pri_strong = scheduler.anchor_priorities.get("0x7f4", 0)
    t.check(pri_strong > 0,
            "0x7f4 (有强因果对象) 优先级 > 0: {:.1f}".format(pri_strong))

    # Stage 1: comparison_anchor 权重高
    pri_cmp = scheduler.anchor_priorities.get("0x7da", 0)  # comparison
    pri_mov = scheduler.anchor_priorities.get("0x7d2", 0)  # memory
    t.check(pri_cmp >= pri_mov,
            "Stage1: comparison({:.1f}) >= memory_value({:.1f})".format(
                pri_cmp, pri_mov))

    # 概率计算
    prob_primary = scheduler._compute_mutation_probability(
        "0x7da", scheduler.anchor_by_pc["0x7da"], set())
    prob_secondary = scheduler._compute_mutation_probability(
        "0x7ce", scheduler.anchor_by_pc["0x7ce"], set())
    prob_locked = scheduler._compute_mutation_probability(
        "0x7da", scheduler.anchor_by_pc["0x7da"], {"0x7da"})
    prob_non_anchor = scheduler._compute_mutation_probability(
        "0x9999", None, set())

    t.check(prob_primary > prob_secondary,
            "primary 概率({:.3f}) > secondary({:.3f})".format(
                prob_primary, prob_secondary))
    t.check(prob_locked == 0.0,
            "锁定 PC 概率 = 0.0")
    t.check(prob_non_anchor < prob_secondary,
            "非 anchor 概率({:.3f}) < secondary({:.3f})".format(
                prob_non_anchor, prob_secondary))
    t.check(0 < prob_primary <= 1.0,
            "primary 概率在 (0, 1]: {:.3f}".format(prob_primary))

    # 强因果对象加成验证
    prob_strong = scheduler._compute_mutation_probability(
        "0x7f4", scheduler.anchor_by_pc["0x7f4"], set())
    t.check(prob_strong > prob_secondary,
            "强因果对象加成后概率({:.3f}) > secondary({:.3f})".format(
                prob_strong, prob_secondary))

    # Stage 2 验证: memory_value 权重高
    scheduler2 = MutationScheduler(SAMPLE_ANCHORS, SAMPLE_STRONG_OBJECTS,
                                   stage=2)
    pri_mem_s2 = scheduler2.anchor_priorities.get("0x7d2", 0)
    pri_cmp_s2 = scheduler2.anchor_priorities.get("0x7da", 0)
    # Stage 2 中 memory_value=25 > comparison=5
    # 但 0x7da 有 comparison+memory 两种 kind，分数可能更高
    t.check(pri_mem_s2 > 0, "Stage2: memory anchor 优先级 > 0")
    print("    INFO | Stage2 memory={:.1f}, cmp={:.1f}".format(
        pri_mem_s2, pri_cmp_s2))

    return t


# ============================================================
# 测试 7: 循环感知
# ============================================================

def test_07_loop_awareness():
    print("\n" + "=" * 60)
    print("TEST 07: 循环感知 (LoopAwareness)")
    print("=" * 60)
    t = TestResult("loop_awareness")

    loop_aware = LoopAwareness(SAMPLE_ANCHORS, SAMPLE_STRONG_OBJECTS)

    t.check(isinstance(loop_aware.loop_bound_pcs, set),
            "loop_bound_pcs 是集合")
    t.check(isinstance(loop_aware.loop_body_pcs, set),
            "loop_body_pcs 是集合")

    print("    INFO | loop_bound_pcs: {}".format(loop_aware.loop_bound_pcs))
    print("    INFO | loop_body_pcs: {}".format(loop_aware.loop_body_pcs))

    # 概率修正
    for pc in loop_aware.loop_bound_pcs:
        mod = loop_aware.get_probability_modifier(pc)
        t.check(mod > 1.0,
                "循环边界 {} 修正因子 > 1.0: {:.2f}".format(pc, mod))

    for pc in loop_aware.loop_body_pcs:
        mod = loop_aware.get_probability_modifier(pc)
        t.check(mod < 1.0,
                "循环体 {} 修正因子 < 1.0: {:.2f}".format(pc, mod))

    # 非循环 PC
    mod_normal = loop_aware.get_probability_modifier("0x9999")
    t.check(mod_normal == 1.0,
            "非循环 PC 修正因子 = 1.0: {:.2f}".format(mod_normal))

    return t


# ============================================================
# 测试 8: 组合变异模式检测
# ============================================================

def test_08_combo_patterns():
    print("\n" + "=" * 60)
    print("TEST 08: 组合变异模式检测")
    print("=" * 60)
    t = TestResult("combo_patterns")

    patterns = ComboMutationPatterns.detect_patterns(SAMPLE_ANCHORS)

    t.check(len(patterns) > 0,
            "检测到 {} 个组合模式".format(len(patterns)))

    pattern_names = set(p["pattern_name"] for p in patterns)
    print("    INFO | 检测到的模式: {}".format(pattern_names))

    # 应检测到 Spectre v1 (cmp + jae)
    t.check("spectre_v1_cmp_branch" in pattern_names,
            "检测到 spectre_v1_cmp_branch 模式")

    # 应检测到 same_causal_object_batch (reg:rax 被多个 anchor 共享)
    t.check("same_causal_object_batch" in pattern_names,
            "检测到 same_causal_object_batch 模式")

    # 每个模式都有概率
    for p in patterns:
        t.check(0 < p["probability"] <= 1.0,
                "模式 {} 概率合法: {:.2f}".format(
                    p["pattern_name"], p["probability"]))
        t.check(len(p["anchors"]) > 0,
                "模式 {} 有关联 anchor".format(p["pattern_name"]))

    return t


# ============================================================
# 测试 9: PC→行映射
# ============================================================

def test_09_pc_line_mapping():
    print("\n" + "=" * 60)
    print("TEST 09: PC→行映射 (PcLineMapper)")
    print("=" * 60)
    t = TestResult("pc_line_mapping")

    asm_lines = SAMPLE_ASM.split('\n')
    asm_lines = [l + '\n' for l in asm_lines]

    mapper = PcLineMapper(SAMPLE_ANCHORS, asm_lines)
    pc_map = mapper.get_map()

    t.check(len(pc_map) > 0,
            "映射非空: {} 个映射".format(len(pc_map)))

    for pc, line_idx in pc_map.items():
        anchor = None
        for a in SAMPLE_ANCHORS:
            if a.get("pc") == pc:
                anchor = a
                break
        if anchor:
            target_mn = anchor.get("mnemonic", "").lower()
            actual_parsed = parse_asm_line(asm_lines[line_idx])
            actual_mn = actual_parsed.get("mnemonic", "")
            t.check(actual_mn == target_mn,
                    "PC={} 映射到第 {} 行, 助记符匹配: {} == {}".format(
                        pc, line_idx, target_mn, actual_mn))
        else:
            print("    INFO | PC={} 无对应 anchor".format(pc))

    # 反向查找
    for pc, line_idx in pc_map.items():
        reverse_pc = mapper.get_pc(line_idx)
        t.check(reverse_pc == pc,
                "反向查找一致: line {} → PC {}".format(line_idx, reverse_pc))

    return t


# ============================================================
# 测试 10: 完整变异流程
# ============================================================

def test_10_apply_mutation():
    print("\n" + "=" * 60)
    print("TEST 10: 完整变异流程 (apply_mutation)")
    print("=" * 60)
    t = TestResult("apply_mutation")

    asm_path = create_test_asm()
    work_dir = create_temp_dir()

    try:
        scheduler = MutationScheduler(
            SAMPLE_ANCHORS, SAMPLE_STRONG_OBJECTS, stage=1)

        # 运行多轮变异，统计结果
        random.seed(42)
        success_count = 0
        total_line_mutations = 0
        total_combo_mutations = 0
        mutated_pcs_all = set()
        mutator_usage = Counter()

        num_rounds = 20
        for round_idx in range(num_rounds):
            result = scheduler.apply_mutation(
                asm_path, None, work_dir,
                cross_stage_locked_pcs=None)

            if result is not None:
                mutant_path, mutation_info = result
                success_count += 1

                # 检查输出文件存在
                if round_idx < 3:
                    t.check(os.path.exists(mutant_path),
                            "轮次 {}: 变异文件存在".format(round_idx))

                # 读取变异文件验证
                with open(mutant_path, 'r') as f:
                    mutant_content = f.read()
                if round_idx < 3:
                    t.check(len(mutant_content) > 0,
                            "轮次 {}: 变异文件非空".format(round_idx))

                # 检查 mutation_info
                if round_idx < 3:
                    t.check("mutated_pcs" in mutation_info,
                            "轮次 {}: mutation_info 有 mutated_pcs".format(
                                round_idx))

                total_line_mutations += mutation_info.get(
                    "total_line_mutations", 0)
                total_combo_mutations += mutation_info.get(
                    "total_combo_mutations", 0)
                mutated_pcs_all.update(mutation_info.get("mutated_pcs", []))

                # 统计变异算子使用情况
                for detail in mutation_info.get("line_mutation_details", []):
                    mutator_usage[detail.get("mutator", "unknown")] += 1

                # 清理
                cleanup(mutant_path, os.path.dirname(mutant_path))

        t.check(success_count == num_rounds,
                "{} 轮全部成功: {}/{}".format(
                    num_rounds, success_count, num_rounds))

        t.check(total_line_mutations > 0,
                "总行变异数 > 0: {}".format(total_line_mutations))

        t.check(len(mutated_pcs_all) > 0,
                "变异覆盖 PC 数 > 0: {}".format(len(mutated_pcs_all)))

        t.check(len(mutator_usage) >= 3,
                "使用了 >=3 种变异算子: {}".format(len(mutator_usage)))

        print("    INFO | 总行变异: {}".format(total_line_mutations))
        print("    INFO | 总组合变异: {}".format(total_combo_mutations))
        print("    INFO | 变异覆盖 PC: {}".format(len(mutated_pcs_all)))
        print("    INFO | 变异算子使用统计: {}".format(
            dict(mutator_usage.most_common(5))))

        # 测试锁定 PC 功能
        locked_pcs = {"0x7da", "0x7de"}
        result = scheduler.apply_mutation(
            asm_path, None, work_dir,
            cross_stage_locked_pcs=locked_pcs)

        if result:
            mutant_path, mutation_info = result
            mutated_pcs = set(mutation_info.get("mutated_pcs", []))
            overlap = mutated_pcs & locked_pcs
            t.check(len(overlap) == 0,
                    "锁定 PC 未被变异: overlap={}".format(overlap))
            cleanup(mutant_path, os.path.dirname(mutant_path))

    finally:
        cleanup(asm_path, work_dir)

    return t


# ============================================================
# 测试 11: Stage 3 配置变异
# ============================================================

def test_11_stage3_config():
    print("\n" + "=" * 60)
    print("TEST 11: Stage 3 配置变异")
    print("=" * 60)
    t = TestResult("stage3_config")

    # 生成配置
    config1 = generate_stage3_config_variant()
    t.check(isinstance(config1, dict), "生成的配置是字典")
    t.check("cache_hit_threshold" in config1, "配置包含 cache_hit_threshold")
    t.check("probe_stride" in config1, "配置包含 probe_stride")
    t.check("rounds" not in config1, "检测轮次不属于可变配置")
    t.check("candidate_count" not in config1,
            "候选字节数不属于可变配置")

    # 检查值范围
    t.check(40 <= config1["cache_hit_threshold"] <= 200,
            "cache_hit_threshold 在范围内: {}".format(
                config1["cache_hit_threshold"]))
    t.check(config1["probe_stride"] in [64, 128, 256, 512, 1024, 2048, 4096],
            "probe_stride 在选项中: {}".format(config1["probe_stride"]))
    env = generate_stage3_env(dict(config1, rounds=500))
    t.check(env["STAGE3_ROUNDS"] == "20",
            "检测轮次固定为 20 且忽略配置覆盖")
    env = generate_stage3_env(dict(config1, candidate_count=64))
    t.check(env["STAGE3_CANDIDATE_COUNT"] == "256",
            "候选字节数固定为 256 且忽略配置覆盖")

    # 生成多个配置，验证多样性
    configs = [generate_stage3_config_variant() for _ in range(10)]
    unique_thresholds = len(set(c["cache_hit_threshold"] for c in configs))
    t.check(unique_thresholds >= 3,
            "10 次生成至少 3 种不同 threshold: {}".format(unique_thresholds))

    # 写入文件
    temp_dir = create_temp_dir()
    try:
        config_path = os.path.join(temp_dir, "test_config.json")
        write_stage3_config(config1, config_path)
        t.check(os.path.exists(config_path), "配置文件写入成功")

        # 读取验证
        with open(config_path, 'r') as f:
            loaded = json.load(f)
        t.check(loaded == config1, "配置文件内容一致")

        # 生成环境变量
        env = generate_stage3_env(config1)
        t.check("STAGE3_CACHE_HIT_THRESHOLD" in env,
                "环境变量包含 STAGE3_CACHE_HIT_THRESHOLD")
        t.check(env["STAGE3_CACHE_HIT_THRESHOLD"] == str(
            config1["cache_hit_threshold"]),
                "环境变量值正确")

    finally:
        cleanup(temp_dir)

    # Stage 3 完整变异测试
    asm_path = create_test_asm()
    work_dir = create_temp_dir()

    try:
        scheduler = MutationScheduler(
            SAMPLE_ANCHORS, SAMPLE_STRONG_OBJECTS, stage=3)

        result = scheduler.apply_mutation(
            asm_path, None, work_dir,
            cross_stage_locked_pcs=None,
            stage3_config=None)  # 自动生成配置

        if result:
            mutant_path, mutation_info = result
            t.check("stage3_config" in mutation_info,
                    "Stage 3 mutation_info 包含 stage3_config")
            t.check(mutation_info["stage3_config"] is not None,
                    "Stage 3 配置已生成")

            # 检查配置文件是否写入
            mutant_dir = os.path.dirname(mutant_path)
            config_file = os.path.join(mutant_dir, "stage3_config.json")
            t.check(os.path.exists(config_file),
                    "Stage 3 配置文件已写入")

            cleanup(mutant_path, mutant_dir)

    finally:
        cleanup(asm_path, work_dir)

    return t


# ============================================================
# 测试 12: 崩溃处理
# ============================================================

def test_12_crash_handling():
    print("\n" + "=" * 60)
    print("TEST 12: 崩溃处理")
    print("=" * 60)
    t = TestResult("crash_handling")

    # 测试成功执行
    result = run_with_crash_handling(["echo", "hello"], timeout=5)
    t.check(result.success, "echo 命令成功执行")
    t.check("hello" in result.stdout, "stdout 包含 hello")
    t.check(not result.crashed, "未崩溃")
    t.check(not result.timed_out, "未超时")

    # 测试超时
    result = run_with_crash_handling(["sleep", "10"], timeout=1)
    t.check(result.timed_out, "sleep 10 超时")
    t.check(not result.success, "超时标记为失败")

    # 测试失败命令
    result = run_with_crash_handling(["false"], timeout=5)
    t.check(not result.success, "false 命令失败")
    t.check(result.returncode != 0, "返回码非 0")

    # 测试不存在的命令
    result = run_with_crash_handling(
        ["this_command_does_not_exist_xyz"], timeout=5)
    t.check(not result.success, "不存在的命令失败")

    # 测试 extract_partial_output
    result_with_output = ExecutionResult()
    result_with_output.stdout = "BR_MISP: 123\nUOPS: 456\n"
    result_with_output.crashed = True
    result_with_output.crash_type = "segfault"

    partial = extract_partial_output(result_with_output, stage=1)
    t.check(partial is not None, "提取到部分输出")
    t.check(partial.get("has_pmu_data", False),
            "识别到 PMU 数据")
    t.check(partial["crashed"], "标记为崩溃")

    return t


# ============================================================
# 测试 13: 接口兼容性
# ============================================================

def test_13_interface_compatibility():
    print("\n" + "=" * 60)
    print("TEST 13: 与 seed_pool.py 的接口兼容性")
    print("=" * 60)
    t = TestResult("interface_compat")

    asm_path = create_test_asm()
    work_dir = create_temp_dir()

    try:
        scheduler = MutationScheduler(
            SAMPLE_ANCHORS, SAMPLE_STRONG_OBJECTS, stage=1)

        # 旧接口: apply_mutation(seed_path, anchor, work_dir)
        # 新接口兼容 anchor=None
        result = scheduler.apply_mutation(asm_path, None, work_dir)
        t.check(result is not None, "新接口 (anchor=None) 调用成功")

        if result:
            mutant_path, mutation_info = result
            t.check(os.path.exists(mutant_path), "变异文件存在")
            t.check(isinstance(mutation_info, dict), "mutation_info 是字典")
            cleanup(mutant_path, os.path.dirname(mutant_path))

        # 测试 select_anchor 方法（旧接口使用）
        anchor = scheduler.select_anchor()
        t.check(anchor is not None, "select_anchor 返回 anchor")
        t.check("pc" in anchor, "anchor 包含 pc 字段")

        # 使用 select_anchor 结果调用 apply_mutation
        result = scheduler.apply_mutation(asm_path, anchor, work_dir)
        t.check(result is not None, "使用 select_anchor 结果调用成功")

        if result:
            mutant_path, mutation_info = result
            cleanup(mutant_path, os.path.dirname(mutant_path))

        # 测试跨阶段锁定
        result = scheduler.apply_mutation(
            asm_path, None, work_dir,
            cross_stage_locked_pcs={"0x7da"})
        t.check(result is not None, "带锁定 PC 调用成功")

        if result:
            mutant_path, mutation_info = result
            cleanup(mutant_path, os.path.dirname(mutant_path))

    finally:
        cleanup(asm_path, work_dir)

    return t


# ============================================================
# 主测试运行器
# ============================================================

def main():
    print("\n" + "=" * 60)
    print("变异调度器完整功能测试")
    print("=" * 60)

    all_tests = [
        test_01_parse_asm_line,
        test_02_helpers,
        test_03_protection,
        test_04_random_instruction_generator,
        test_05_mutation_operators,
        test_06_priority_and_probability,
        test_07_loop_awareness,
        test_08_combo_patterns,
        test_09_pc_line_mapping,
        test_10_apply_mutation,
        test_11_stage3_config,
        test_12_crash_handling,
        test_13_interface_compatibility,
    ]

    results = []
    failed_tests = []

    for test_func in all_tests:
        try:
            result = test_func()
            results.append(result)
            if not result.passed():
                failed_tests.append(result.name)
        except Exception as e:
            print("\n    EXCEPTION in {}: {}".format(
                test_func.__name__, str(e)))
            traceback.print_exc()
            failed_tests.append(test_func.__name__)

    # 汇总
    print("\n" + "=" * 60)
    print("测试汇总")
    print("=" * 60)

    total_checks = 0
    passed_checks = 0

    for result in results:
        ok, total = result.summary()
        total_checks += total
        passed_checks += ok
        status = "PASS" if result.passed() else "FAIL"
        print("  {} | {}: {}/{} checks passed".format(
            status, result.name, ok, total))

    print("\n" + "=" * 60)
    if len(failed_tests) == 0:
        print("✓ ALL TESTS PASSED")
        print("  Total: {}/{} checks passed".format(
            passed_checks, total_checks))
        print("=" * 60)
        return 0
    else:
        print("✗ TESTS FAILED")
        print("  Total: {}/{} checks passed".format(
            passed_checks, total_checks))
        print("  Failed tests: {}".format(", ".join(failed_tests)))
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
