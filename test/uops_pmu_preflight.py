#!/usr/bin/env python3
"""Fail-closed preflight for the Stage 1 UOPS PMU measurement path."""

import os
import re
import subprocess


_OK_RE = re.compile(
    r"UOPS_PREFLIGHT_STATUS=OK\s+mode=(\S+)\s+"
    r"profile=(\S+)\s+issued=(\d+)\s+retired=(\d+)")


def _read_optional_text(path):
    try:
        with open(path, "r") as source:
            return source.read().strip()
    except OSError:
        return None


def run_uops_pmu_preflight(cc, pmu_uops_obj, work_dir,
                           compile_timeout=20, run_timeout=10,
                           probe_source=None):
    """Compile and execute a probe using the exact production PMU object."""
    result = {
        "ok": False,
        "reason": "unknown UOPS PMU preflight failure",
        "mode": None,
        "profile": "intel_family6_model85",
        "raw_events": {
            "uops_issued_any": "0x010e",
            "uops_retired_retire_slots": "0x02c2",
        },
        "system_context": {
            "perf_event_paranoid": _read_optional_text(
                "/proc/sys/kernel/perf_event_paranoid"),
            "cpu_rdpmc_policy": _read_optional_text(
                "/sys/bus/event_source/devices/cpu/rdpmc"),
            "cpu_pmu_present": os.path.isdir(
                "/sys/bus/event_source/devices/cpu"),
        },
        "issued": None,
        "retired": None,
    }
    if not pmu_uops_obj or not os.path.isfile(pmu_uops_obj):
        result["reason"] = "UOPS PMU object not found: {}".format(
            pmu_uops_obj)
        return result

    if probe_source is None:
        probe_source = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "pmu_uops_preflight.c")
    if not os.path.isfile(probe_source):
        result["reason"] = "UOPS PMU preflight source not found: {}".format(
            probe_source)
        return result

    os.makedirs(work_dir, exist_ok=True)
    probe_exe = os.path.join(work_dir, "uops_pmu_preflight")
    compile_cmd = [
        cc, probe_source, pmu_uops_obj,
        "-I", os.path.dirname(probe_source), "-o", probe_exe,
    ]
    try:
        compiled = subprocess.run(
            compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=compile_timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = "UOPS PMU preflight compile failed: {}".format(exc)
        return result
    if compiled.returncode != 0:
        stderr = compiled.stderr.decode("utf-8", errors="replace").strip()
        result["reason"] = "UOPS PMU preflight compile failed: {}".format(
            stderr or "compiler returned {}".format(compiled.returncode))
        return result

    try:
        probed = subprocess.run(
            [probe_exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=run_timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = "UOPS PMU preflight execution failed: {}".format(
            exc)
        return result

    stdout = probed.stdout.decode("utf-8", errors="replace")
    stderr = probed.stderr.decode("utf-8", errors="replace")
    match = _OK_RE.search(stdout)
    if probed.returncode != 0:
        diagnostic = "\n".join(
            part.strip() for part in (stderr, stdout) if part.strip())
        result["reason"] = "UOPS PMU unavailable or unreadable: {}".format(
            diagnostic or "probe returned {}".format(probed.returncode))
        return result
    if match is None:
        diagnostic = "\n".join(
            part.strip() for part in (stderr, stdout) if part.strip())
        result["reason"] = (
            "UOPS PMU probe completed without an OK marker: {}".format(
                diagnostic or "empty output"))
        return result

    result.update({
        "ok": True,
        "reason": "ok",
        "mode": match.group(1),
        "profile": match.group(2),
        "issued": int(match.group(3)),
        "retired": int(match.group(4)),
    })
    return result
