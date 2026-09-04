#!/usr/bin/env python3
"""Fail-closed preflight for the Stage 2 L1D-miss PMU path."""

import os
import re
import subprocess


_OK_RE = re.compile(r"L1D_PMU_PREFLIGHT_STATUS=OK\s+value=(\d+)")


def _read_optional_text(path):
    try:
        with open(path, "r") as source:
            return source.read().strip()
    except OSError:
        return None


def run_stage2_pmu_preflight(cc, pmu_helper_obj, work_dir,
                             compile_timeout=20, run_timeout=10,
                             probe_source=None):
    """Compile and run a probe linked to the production PMU helper object."""
    result = {
        "ok": False,
        "reason": "unknown Stage 2 L1D PMU preflight failure",
        "event": "MEM_LOAD_RETIRED.L1_MISS",
        "raw_event": "0x08d1",
        "value": None,
        "system_context": {
            "perf_event_paranoid": _read_optional_text(
                "/proc/sys/kernel/perf_event_paranoid"),
            "cpu_pmu_present": os.path.isdir(
                "/sys/bus/event_source/devices/cpu"),
        },
    }
    if not pmu_helper_obj or not os.path.isfile(pmu_helper_obj):
        result["reason"] = "PMU helper object not found: {}".format(
            pmu_helper_obj)
        return result
    if probe_source is None:
        probe_source = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "pmu_l1d_preflight.c")
    if not os.path.isfile(probe_source):
        result["reason"] = "L1D PMU preflight source not found: {}".format(
            probe_source)
        return result

    os.makedirs(work_dir, exist_ok=True)
    probe_exe = os.path.join(work_dir, "stage2_l1d_pmu_preflight")
    try:
        compiled = subprocess.run(
            [cc, probe_source, pmu_helper_obj, "-o", probe_exe],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=compile_timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = "L1D PMU preflight compile failed: {}".format(exc)
        return result
    if compiled.returncode != 0:
        stderr = compiled.stderr.decode("utf-8", errors="replace").strip()
        result["reason"] = "L1D PMU preflight compile failed: {}".format(
            stderr or "compiler returned {}".format(compiled.returncode))
        return result

    try:
        probe_env = os.environ.copy()
        probe_env["TRANSFUZZ_PMU_STAGE"] = "2"
        probed = subprocess.run(
            [probe_exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=run_timeout, env=probe_env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = "L1D PMU preflight execution failed: {}".format(exc)
        return result

    stdout = probed.stdout.decode("utf-8", errors="replace")
    stderr = probed.stderr.decode("utf-8", errors="replace")
    match = _OK_RE.search(stdout)
    if probed.returncode != 0:
        diagnostic = "\n".join(
            part.strip() for part in (stderr, stdout) if part.strip())
        result["reason"] = "L1D PMU unavailable or unreadable: {}".format(
            diagnostic or "probe returned {}".format(probed.returncode))
        return result
    if match is None:
        diagnostic = "\n".join(
            part.strip() for part in (stderr, stdout) if part.strip())
        result["reason"] = (
            "L1D PMU probe completed without an OK marker: {}".format(
                diagnostic or "empty output"))
        return result

    result.update({"ok": True, "reason": "ok", "value": int(match.group(1))})
    return result
