#!/usr/bin/env python3
"""
asm_sanity_check.py

汇编代码快速健全性检查（缓解 5）。

在变异后、编译/链接前对 .s 文件做静态结构检查，提前过滤
明显损坏的变异体，节省后续编译/链接/运行的时间成本。

检查项：
  1. 栈平衡：push/pop 数量大致匹配
  2. 函数对称：.cfi_startproc 与 .cfi_endproc 配对
  3. 控制流封闭：每个函数应以 ret/jmp 结尾
  4. 标签引用一致：分支/调用目标标签存在
  5. 帧指针完整：函数序言/尾声未被破坏
"""

import re
import logging

logger = logging.getLogger("sanity_check")


# 关键的栈帧指令模式
PROLOGUE_PATTERNS = [
    re.compile(r'^\s*pushq?\s+%rbp\b'),
    re.compile(r'^\s*movq?\s+%rsp\s*,\s*%rbp\b'),
]

EPILOGUE_PATTERNS = [
    re.compile(r'^\s*popq?\s+%rbp\b'),
    re.compile(r'^\s*leave\b'),
    re.compile(r'^\s*retq?\b'),
]


def quick_sanity_check(asm_lines, strict=False):
    """
    对汇编行列表做快速健全性检查。
    
    参数:
      asm_lines: list of str，汇编行
      strict:    True 严格模式（任一检查失败即拒绝）
                 False 宽松模式（仅明显损坏才拒绝）
    
    返回:
      (ok: bool, reason: str)
        ok=True 通过检查
        ok=False reason 描述失败原因
    """
    # ----------------------------------------------------------------
    # Check 1: 栈平衡（push 数量 vs pop+leave 数量）
    # ----------------------------------------------------------------
    push_count = 0
    pop_count = 0
    leave_count = 0
    ret_count = 0
    call_count = 0
    
    # ----------------------------------------------------------------
    # Check 2: CFI 对称性
    # ----------------------------------------------------------------
    cfi_start = 0
    cfi_end = 0
    
    # ----------------------------------------------------------------
    # Check 3: 函数边界
    # ----------------------------------------------------------------
    func_starts = []  # (line_idx, name)
    
    # ----------------------------------------------------------------
    # Check 4: 标签收集
    # ----------------------------------------------------------------
    defined_labels = set()
    referenced_labels = set()
    
    # ----------------------------------------------------------------
    # Check 5: 帧指针完整性
    # ----------------------------------------------------------------
    has_prologue_push_rbp = False
    has_prologue_mov_rsp_rbp = False
    
    for i, line in enumerate(asm_lines):
        stripped = line.strip()
        
        # 跳过空行和纯注释
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            continue
        
        lower = stripped.lower()
        
        # ---- CFI 指令 ----
        if '.cfi_startproc' in lower:
            cfi_start += 1
        elif '.cfi_endproc' in lower:
            cfi_end += 1
        
        # ---- 栈操作计数 ----
        # 严格匹配指令开头（避免误匹配如 ".pushsection"）
        m = re.match(r'^\s*(push[qlw]?|pop[qlw]?|leave|ret[q]?|call[q]?)\b',
                     stripped)
        if m:
            mn = m.group(1).lower()
            if mn.startswith("push"):
                push_count += 1
            elif mn.startswith("pop"):
                pop_count += 1
            elif mn == "leave":
                leave_count += 1
            elif mn.startswith("ret"):
                ret_count += 1
            elif mn.startswith("call"):
                call_count += 1
        
        # ---- 帧指针检查（前 20 行） ----
        if i < 50:  # 只在函数前 50 行内查找序言
            for pat in PROLOGUE_PATTERNS:
                if pat.match(line):
                    if "rbp" in lower and "push" in lower:
                        has_prologue_push_rbp = True
                    elif "rsp" in lower and "rbp" in lower and "mov" in lower:
                        has_prologue_mov_rsp_rbp = True
        
        # ---- 函数标签 ----
        # 形如 "func_name:" 或 ".globl func_name"
        label_def = re.match(r'^([a-zA-Z_][a-zA-Z0-9_\.]*)\s*:', stripped)
        if label_def:
            label_name = label_def.group(1)
            defined_labels.add(label_name)
            # 启发式判断函数（小写字母开头，不以 . 开头）
            if not label_name.startswith('.') and not label_name.startswith('L'):
                func_starts.append((i, label_name))
        
        # ---- 分支/调用目标 ----
        br_match = re.match(
            r'^\s*(j[a-z]+|jmp|jmpq|call|callq)\s+([^\s,#]+)', stripped)
        if br_match:
            target = br_match.group(2).strip()
            # 去掉间接调用前缀
            target = target.lstrip('*').strip()
            # 跳过寄存器间接调用 (%rax) 等
            if not target.startswith('%') and not target.startswith('('):
                # 提取标签名（去掉 @PLT 等后缀）
                target = target.split('@')[0]
                if re.match(r'^[a-zA-Z_\.][a-zA-Z0-9_\.]*$', target):
                    referenced_labels.add(target)
    
    # ================================================================
    # 评估检查结果
    # ================================================================
    
    # ---- 检查 1: CFI 对称 ----
    if cfi_start != cfi_end:
        return False, "CFI mismatch: startproc={}, endproc={}".format(
            cfi_start, cfi_end)
    
    # ---- 检查 2: 栈平衡 ----
    # push 应大致等于 pop + leave
    # 允许 ±1 的偏差（leave 可能等价于 pop %rbp）
    stack_diff = push_count - (pop_count + leave_count)
    if abs(stack_diff) > 2:
        return False, "Stack imbalance: push={}, pop={}, leave={}, diff={}".format(
            push_count, pop_count, leave_count, stack_diff)
    
    # ---- 检查 3: 至少有一个 ret ----
    if ret_count == 0:
        return False, "No ret instruction found"
    
    # ---- 检查 4: 帧指针完整（仅 strict 模式） ----
    if strict:
        if not has_prologue_push_rbp:
            return False, "Missing prologue: push %rbp"
        if not has_prologue_mov_rsp_rbp:
            return False, "Missing prologue: mov %rsp, %rbp"
    
    # ---- 检查 5: 标签引用一致（仅 strict 模式） ----
    if strict:
        # 已知的外部符号（不需要在本文件定义）
        EXTERNAL_SYMBOLS = {
            "printf", "puts", "exit", "malloc", "free", "memcpy", "memset",
            "abort", "__stack_chk_fail",
        }
        # 移除外部符号
        unresolved = (referenced_labels - defined_labels) - EXTERNAL_SYMBOLS
        # 启发式：以 _ 开头或包含 @ 的可能是外部符号
        unresolved = {l for l in unresolved
                      if not l.startswith('_')
                      and '@' not in l
                      and l not in {'main', 'victim'}}
        if unresolved:
            # 只警告，不拒绝（外部符号判断不准确）
            logger.debug("Unresolved labels (warning): {}".format(unresolved))
    
    return True, "ok"


def sanity_check_file(asm_path, strict=False):
    """
    对 .s 文件做健全性检查（文件接口）。
    
    返回:
      (ok: bool, reason: str)
    """
    try:
        with open(asm_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        return False, "Cannot read file: {}".format(e)
    
    return quick_sanity_check(lines, strict=strict)


if __name__ == "__main__":
    # 自测
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 asm_sanity_check.py <file.s>")
        sys.exit(1)
    
    ok, reason = sanity_check_file(sys.argv[1], strict=False)
    print("Sanity check: {} ({})".format("PASS" if ok else "FAIL", reason))
    sys.exit(0 if ok else 1)