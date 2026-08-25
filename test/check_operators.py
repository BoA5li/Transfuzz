#!/usr/bin/env python3
"""变异算子可达性自检脚本"""
import sys
import os

# 添加变异器所在目录到路径（按你的实际路径调整）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, '..')  # 如果 mutation_scheduler.py 在上级目录

# 导入你的变异器模块（按实际文件名调整）
from mutation_scheduler import MutationOperators

required = [
    "delete_instruction", "replace_with_nop", "insert_nop_before",
    "insert_fence_before", "insert_random_instruction_before",
    "insert_random_instruction_after", "insert_random_sequence",
    "replace_with_random_instruction", "mutate_branch_condition",
    "mutate_immediate", "mutate_comparison_swap",
    "mutate_opcode_arithmetic", "mutate_displacement",
    "mutate_address_offset", "invert_branch_condition",
    "replace_branch_condition", "duplicate_instruction",
    # 补充原始引用中可能用到的别名
    "mutate_immediate_value", "immediate_value_mutation",
    "mutate_register", "replace_register", "operand_mutation",
    "mutate_memory_offset", "mutate_memory_operand",
    "mutate_address_base", "mutate_address_index",
    "swap_operands", "swap_comparison_operands", "swap_arithmetic_operands",
    "replace_arithmetic_opcode", "opcode_replacement",
    "replace_comparison_opcode",
    "mutate_comparison_constant", "flip_comparison_sign",
    "mutate_loop_bound", "scale_loop_bound", "mutate_shift_amount",
    "replace_with_constant",
    "delete_stack_operation", "mutate_array_index", "mutate_array_base",
    "swap_address_components",
    "combo_cmp_branch", "combo_same_object_batch",
    "combo_spectre_v1", "combo_spectre_rsb", "combo_spectre_v4",
    "combo_transient_window_extension",
    "call_skip_or_replace",
    "instruction_deletion", "nop_insertion", "fence_insertion",
    "random_instruction_insertion", "insert_random_instruction",
    "insert_nop_after", "insert_fence_after",
]

missing = [n for n in required if not hasattr(MutationOperators, n)]
if missing:
    print("❌ Still missing ({}):".format(len(missing)))
    for n in missing:
        print("   - {}".format(n))
    sys.exit(1)
else:
    print("✓ All {} operators present".format(len(required)))
    sys.exit(0)
