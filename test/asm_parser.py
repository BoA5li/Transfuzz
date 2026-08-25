#!/usr/bin/env python3
"""
asm_parser.py

汇编指令解析器，提供指令级别的结构化访问。
"""

import re
from typing import Dict, List, Optional, Tuple


class AsmInstruction:
    """汇编指令结构化表示"""
    
    def __init__(self, line_idx: int, raw_line: str, pc: Optional[str] = None):
        self.line_idx = line_idx
        self.raw_line = raw_line
        self.pc = pc
        
        # 解析指令
        self.label = None
        self.mnemonic = None
        self.operands = []
        self.comment = None
        
        self._parse()
    
    def _parse(self):
        """解析指令"""
        stripped = self.raw_line.strip()
        
        # 移除注释
        if '#' in stripped:
            parts = stripped.split('#', 1)
            stripped = parts[0].strip()
            self.comment = parts[1].strip()
        
        # 检查是否是标签
        if stripped.endswith(':'):
            self.label = stripped[:-1]
            return
        
        # 解析指令
        parts = stripped.split(None, 1)
        if not parts:
            return
        
        self.mnemonic = parts[0].lower()
        
        if len(parts) > 1:
            # 解析操作数
            operand_str = parts[1]
            self.operands = [op.strip() for op in operand_str.split(',')]
    
    def is_label(self) -> bool:
        return self.label is not None
    
    def is_instruction(self) -> bool:
        return self.mnemonic is not None
    
    def is_empty(self) -> bool:
        return not self.is_label() and not self.is_instruction()
    
    def is_memory_access(self) -> bool:
        """判断是否是内存访问指令"""
        if not self.mnemonic:
            return False
        
        # 检查操作数中是否有 []
        for op in self.operands:
            if '[' in op and ']' in op:
                return True
        
        return False
    
    def is_branch(self) -> bool:
        """判断是否是分支指令"""
        if not self.mnemonic:
            return False
        
        return (self.mnemonic.startswith('j') or 
                self.mnemonic.startswith('loop') or
                self.mnemonic in ['call', 'ret'])
    
    def is_comparison(self) -> bool:
        """判断是否是比较指令"""
        return self.mnemonic in ['cmp', 'test']
    
    def get_memory_operand(self) -> Optional[str]:
        """获取内存操作数"""
        for op in self.operands:
            if '[' in op and ']' in op:
                return op
        return None
    
    def extract_immediate(self) -> List[Tuple[int, str]]:
        """提取立即数 (index, value)"""
        immediates = []
        
        for i, op in enumerate(self.operands):
            # 匹配十六进制立即数
            m = re.search(r'0x[0-9a-fA-F]+', op)
            if m:
                immediates.append((i, m.group(0)))
                continue
            
            # 匹配十进制立即数
            m = re.search(r'\b\d+\b', op)
            if m:
                immediates.append((i, m.group(0)))
        
        return immediates
    
    def extract_registers(self) -> List[str]:
        """提取寄存器"""
        registers = []
        
        # x86-64 寄存器模式
        reg_pattern = r'\b(r[a-z]{2}|e[a-z]{2}|[a-z]{2}l|[a-z]{2}h|r\d+[dwb]?|rip|rsp|rbp)\b'
        
        for op in self.operands:
            matches = re.findall(reg_pattern, op, re.IGNORECASE)
            registers.extend(matches)
        
        return registers
    
    def to_string(self) -> str:
        """转换回汇编字符串"""
        if self.is_label():
            return f"{self.label}:"
        
        if not self.is_instruction():
            return self.raw_line
        
        parts = [f"\t{self.mnemonic}"]
        
        if self.operands:
            parts.append(", ".join(self.operands))
        
        result = " ".join(parts)
        
        if self.comment:
            result += f"  # {self.comment}"
        
        return result


class AsmParser:
    """汇编文件解析器"""
    
    def __init__(self, asm_path: str):
        self.asm_path = asm_path
        self.lines = []
        self.instructions = {}  # line_idx -> AsmInstruction
        self.pc_to_line = {}    # pc -> line_idx
        self.labels = {}        # label_name -> line_idx
        
        self._load()
    
    def _load(self):
        """加载汇编文件"""
        with open(self.asm_path, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()
        
        # 解析每一行
        for i, line in enumerate(self.lines):
            inst = AsmInstruction(i, line)
            self.instructions[i] = inst
            
            if inst.is_label():
                self.labels[inst.label] = i
    
    def get_instruction(self, line_idx: int) -> Optional[AsmInstruction]:
        """获取指令"""
        return self.instructions.get(line_idx)
    
    def get_instruction_by_pc(self, pc: str) -> Optional[AsmInstruction]:
        """通过 PC 获取指令"""
        line_idx = self.pc_to_line.get(pc)
        if line_idx is not None:
            return self.instructions.get(line_idx)
        return None
    
    def find_label(self, label_name: str) -> Optional[int]:
        """查找标签位置"""
        return self.labels.get(label_name)
    
    def get_lines_in_range(self, start: int, end: int) -> List[AsmInstruction]:
        """获取范围内的指令"""
        return [self.instructions[i] for i in range(start, end + 1) 
                if i in self.instructions]
    
    def write(self, output_path: str):
        """写入汇编文件"""
        with open(output_path, 'w', encoding='utf-8') as f:
            for i in sorted(self.instructions.keys()):
                inst = self.instructions[i]
                f.write(inst.to_string() + '\n')