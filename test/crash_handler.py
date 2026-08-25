#!/usr/bin/env python3
"""
crash_handler.py

变异程序崩溃处理模块。

设计说明:
  - 保留所有崩溃（不做语义引导规避）
  - 捕获崩溃信号，保证流水线持续运行
  - 对崩溃种子标记但不丢弃（meltdown 等漏洞可能依赖异常）
  - 尝试从崩溃前的部分输出中提取有用信号

Compatible with Python 3.6+.
"""

import signal
import subprocess
import logging
import re

logger = logging.getLogger("crash_handler")

# 信号名称映射
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


def run_with_crash_handling(cmd, timeout=30, env=None,
                            cwd=None, stdin_data=None):
    """
    运行外部命令，捕获崩溃信号。

    参数:
      cmd:        命令列表 [exe_path, arg1, ...]
      timeout:    超时时间 (秒)
      env:        环境变量字典
      cwd:        工作目录
      stdin_data: 标准输入数据

    返回:
      ExecutionResult
    """
    result = ExecutionResult()

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
            cwd=cwd,
            input=stdin_data,
        )

        result.stdout = proc.stdout.decode("utf-8", errors="replace")
        result.stderr = proc.stderr.decode("utf-8", errors="replace")
        result.returncode = proc.returncode

        if proc.returncode == 0:
            result.success = True
        elif proc.returncode < 0:
            # 被信号终止
            sig = -proc.returncode
            result.crashed = True
            result.signal_num = sig
            result.signal_name = SIGNAL_NAMES.get(sig, "SIG{}".format(sig))

            if sig == 11:  # SIGSEGV
                result.crash_type = "segfault"
            elif sig == 4:  # SIGILL
                result.crash_type = "illegal_instruction"
            elif sig == 8:  # SIGFPE
                result.crash_type = "floating_point_exception"
            elif sig == 7:  # SIGBUS
                result.crash_type = "bus_error"
            elif sig == 6:  # SIGABRT
                result.crash_type = "abort"
            else:
                result.crash_type = "signal_{}".format(sig)

            logger.debug("Process crashed: {} (signal {})".format(
                result.signal_name, sig))
        else:
            # 非零退出码但非信号
            result.success = False

    except subprocess.TimeoutExpired:
        result.timed_out = True
        result.crashed = False
        logger.debug("Process timed out after {}s".format(timeout))

    except Exception as e:
        result.success = False
        result.stderr = str(e)
        logger.debug("Process execution error: {}".format(e))

    return result


def extract_partial_output(result, stage=1):
    """
    从崩溃/超时的进程输出中提取部分有用信号。

    即使进程崩溃，崩溃前的 printf 输出可能已经刷新到 stdout。
    """
    if not result.stdout:
        return None

    lines = result.stdout.strip().split('\n')
    if not lines:
        return None

    partial = {
        "lines": lines,
        "line_count": len(lines),
        "crashed": result.crashed,
        "crash_type": result.crash_type,
    }

    # 尝试提取阶段特定的信号
    if stage == 1:
        # Stage 1: 查找 PMU 输出
        for line in lines:
            if "BR_MISP" in line or "UOPS" in line:
                partial["has_pmu_data"] = True
                break

    elif stage == 2:
        # Stage 2: 查找 cache hit 信息
        for line in lines:
            if "STAGE2_ROUND" in line:
                partial["has_stage2_data"] = True
                break

    elif stage == 3:
        # Stage 3: 查找 flush-reload 结果
        for line in lines:
            if "STAGE3_ROUND" in line:
                partial["has_stage3_data"] = True
                break
            m = re.search(r'STAGE3_ROUND\d+_MATCH=(\d+)', line)
            if m and m.group(1) == "1":
                partial["has_match"] = True

    return partial