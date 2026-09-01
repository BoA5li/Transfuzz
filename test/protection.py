#!/usr/bin/env python3
"""
protection.py

变异保护机制，防止破坏关键插桩和驱动函数。
"""

import re
from typing import Set, Tuple, Dict, List
from asm_parser import AsmParser, AsmInstruction


# 保护配置
PROTECTION_CONFIG = {
    "labels": [
        "STAGE1_BEGIN",
        "STAGE1_END",
        "STAGE2_BEGIN",
        "STAGE2_END",
        "STAGE3_BEGIN",
        "STAGE3_END",
    ],
    
    "functions": [
        # PMU 相关
        "pmu_stage1_before",
        "pmu_stage1_after",
        "pmu_stage1_indirect_before",
        "pmu_stage1_indirect_after",
        "pmu_stage1_disambiguation_before",
        "pmu_stage1_disambiguation_after",
        "pmu_stage1_return_before",
        "pmu_stage1_return_after",
        "pmu_stage1_set_phase",
        "pmu_read_l1d_miss",
        "pmu_read_uops",
        
        # Victim 框架 API
        "vf_set_secret",
        "vf_run_attack_once",
        "vf_get_probe_addr_for_secret",
        "vf_prepare_probe_region",
        
        # Stage 3 观测器
        "stage3_run_single_reuse_secret",
        "stage3_flush_line",
        "stage3_reload_timed",
    ],
    
    "symbols": [
        "probe_array",
        "array1",
        "array2",
        "array1_size",
        "secret",
        "temp",
    ],
    
    "registers": [
        "rsp",  # 栈指针
        "rbp",  # 帧指针（Spectre RSB 需要变异，但需谨慎）
    ],
    
    "semantic_tags_exclude": [
        "crt_startup",
        "plt_got_stub",
    ],
    
    "semantic_tags_low_priority": [
        "prologue_instruction",
        "epilogue_instruction",
        "stack_setup",
        "stack_teardown",
    ],
}


class ProtectionEngine:
    """保护引擎"""
    
    def __init__(self, asm_parser: AsmParser, config: Dict = None):
        self.parser = asm_parser
        self.config = config or PROTECTION_CONFIG
        
        # 构建保护区域
        self.protected_regions = []
        self._build_protected_regions()
    
    def _build_protected_regions(self):
        """构建保护区域"""
        
        # 1. 保护插桩标签及其后续指令
        for label in self.config["labels"]:
            line_idx = self.parser.find_label(label)
            if line_idx is not None:
                # 保护标签后的 5 条指令
                self.protected_regions.append({
                    "start": line_idx,
                    "end": line_idx + 5,
                    "reason": f"插桩标签 {label}",
                    "type": "instrumentation",
                })
        
        # 2. 保护函数调用及其参数准备
        for func in self.config["functions"]:
            call_lines = self._find_function_calls(func)
            for call_line in call_lines:
                param_start = self._find_param_prep_start(call_line)
                self.protected_regions.append({
                    "start": param_start,
                    "end": call_line + 1,
                    "reason": f"函数调用 {func} 及参数准备",
                    "type": "function_call",
                })
    
    def _find_function_calls(self, func_name: str) -> List[int]:
        """查找函数调用位置"""
        call_lines = []
        
        for line_idx, inst in self.parser.instructions.items():
            if inst.mnemonic == 'call':
                if func_name in inst.raw_line:
                    call_lines.append(line_idx)
        
        return call_lines
    
    def _find_param_prep_start(self, call_line: int) -> int:
        """向前查找参数准备指令的起始位置"""
        param_regs = {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
                      'edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d'}
        
        start = call_line
        
        for i in range(call_line - 1, max(0, call_line - 10), -1):
            inst = self.parser.get_instruction(i)
            if not inst or not inst.is_instruction():
                continue
            
            # 检查是否是参数准备指令
            if inst.mnemonic in ['mov', 'lea']:
                regs = inst.extract_registers()
                if any(r in param_regs for r in regs):
                    start = i
                else:
                    break
            else:
                break
        
        return start
    
    def is_protected(self, line_idx: int, anchor: Dict = None) -> Tuple[bool, str]:
        """判断指令是否受保护"""
        
        # 1. 检查保护区域
        for region in self.protected_regions:
            if region["start"] <= line_idx <= region["end"]:
                return True, region["reason"]
        
        # 2. 检查符号引用
        inst = self.parser.get_instruction(line_idx)
        if inst:
            for symbol in self.config["symbols"]:
                if symbol in inst.raw_line:
                    # 检查是否是定义（允许）还是删除（禁止）
                    if inst.mnemonic in ['mov', 'lea', 'add', 'sub']:
                        # 允许对符号的值进行变异
                        pass
                    else:
                        return True, f"引用受保护符号 {symbol}"
        
        # 3. 检查寄存器写入
        if inst and inst.is_instruction():
            for reg in self.config["registers"]:
                if reg in inst.operands and inst.operands.index(reg) == 0:
                    # 第一个操作数是目标寄存器
                    if reg == "rsp":
                        # 栈指针绝对不可变异
                        return True, f"写入栈指针 {reg}"
                    elif reg == "rbp":
                        # 帧指针：Spectre RSB 可能需要变异，但需要检查上下文
                        if anchor and "rsb" not in str(anchor.get("kinds", [])).lower():
                            return True, f"写入帧指针 {reg}（非 RSB 上下文）"
        
        # 4. 检查语义标签
        if anchor:
            tags = set(anchor.get("semantic_tags", []))
            for tag in self.config["semantic_tags_exclude"]:
                if tag in tags:
                    return True, f"语义标签排除 {tag}"
        
        return False, ""
    
    def get_mutation_probability_modifier(self, anchor: Dict) -> float:
        """根据保护策略调整变异概率"""
        
        tags = set(anchor.get("semantic_tags", []))
        
        # 低优先级标签降低概率
        for tag in self.config["semantic_tags_low_priority"]:
            if tag in tags:
                return 0.3  # 降低到 30%
        
        return 1.0  # 不调整
