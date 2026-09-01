#!/usr/bin/env python3
"""Fail-closed preflight for the selected Stage 1 raw PMU event."""

import os
import re
import subprocess

from run_stage_pipeline_stage1_2_3 import normalize_stage1_pmu_event


_OK_RE = re.compile(r"STAGE1_PMU_PREFLIGHT_STATUS=OK\s+value=(\d+)")
_EVENTS = {
    "conditional": {
        "name": "BR_MISP_RETIRED.CONDITIONAL", "raw": "0x01c5",
        "define": None,
    },
    "indirect": {
        "name": "BR_MISP_EXEC.INDIRECT", "raw": "0xe489",
        "define": "STAGE1_PMU_EVENT_INDIRECT",
    },
    "disambiguation": {
        "name": "MACHINE_CLEARS.DISAMBIGUATION", "raw": "0x08c3",
        "define": "STAGE1_PMU_EVENT_DISAMBIGUATION",
    },
    "return": {
        "name": "BR_MISP_RETIRED.RETURN", "raw": "0xf7c5",
        "define": "STAGE1_PMU_EVENT_RETURN",
    },
}


def _read_optional_text(path):
    try:
        with open(path, "r") as source:
            return source.read().strip()
    except OSError:
        return None


def run_stage1_pmu_preflight(cc, pmu_helper_obj, event_name, work_dir,
                             compile_timeout=20, run_timeout=10,
                             probe_source=None):
    """Compile and run a probe linked to the exact production helper object."""
    try:
        event_key = normalize_stage1_pmu_event(event_name)
    except ValueError as exc:
        return {"ok": False, "reason": str(exc), "event": None,
                "raw_event": None, "value": None}

    event = _EVENTS[event_key]
    result = {
        "ok": False,
        "reason": "unknown Stage 1 PMU preflight failure",
        "event_key": event_key,
        "event": event["name"],
        "raw_event": event["raw"],
        "value": None,
        "system_context": {
            "perf_event_paranoid": _read_optional_text(
                "/proc/sys/kernel/perf_event_paranoid"),
            "cpu_pmu_present": os.path.isdir(
                "/sys/bus/event_source/devices/cpu"),
        },
    }
    if not pmu_helper_obj or not os.path.isfile(pmu_helper_obj):
        result["reason"] = "Stage 1 PMU helper object not found: {}".format(
            pmu_helper_obj)
        return result

    if probe_source is None:
        probe_source = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "pmu_stage1_preflight.c")
    if not os.path.isfile(probe_source):
        result["reason"] = "Stage 1 PMU preflight source not found: {}".format(
            probe_source)
        return result

    os.makedirs(work_dir, exist_ok=True)
    probe_exe = os.path.join(work_dir, "stage1_pmu_preflight")
    compile_cmd = [cc]
    if event["define"]:
        compile_cmd.append("-D{}".format(event["define"]))
    compile_cmd.extend([probe_source, pmu_helper_obj, "-o", probe_exe])
    try:
        compiled = subprocess.run(
            compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=compile_timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = "Stage 1 PMU preflight compile failed: {}".format(
            exc)
        return result
    if compiled.returncode != 0:
        stderr = compiled.stderr.decode("utf-8", errors="replace").strip()
        result["reason"] = "Stage 1 PMU preflight compile failed: {}".format(
            stderr or "compiler returned {}".format(compiled.returncode))
        return result

    try:
        probed = subprocess.run(
            [probe_exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=run_timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["reason"] = "Stage 1 PMU preflight execution failed: {}".format(
            exc)
        return result

    stdout = probed.stdout.decode("utf-8", errors="replace")
    stderr = probed.stderr.decode("utf-8", errors="replace")
    match = _OK_RE.search(stdout)
    if probed.returncode != 0:
        diagnostic = "\n".join(
            part.strip() for part in (stderr, stdout) if part.strip())
        result["reason"] = (
            "Stage 1 PMU event unavailable or unreadable: {}".format(
                diagnostic or "probe returned {}".format(probed.returncode)))
        return result
    if match is None:
        diagnostic = "\n".join(
            part.strip() for part in (stderr, stdout) if part.strip())
        result["reason"] = (
            "Stage 1 PMU probe completed without an OK marker: {}".format(
                diagnostic or "empty output"))
        return result

    result.update({"ok": True, "reason": "ok", "value": int(match.group(1))})
    return result
