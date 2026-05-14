"""
Symbolic execution wrapper (angr).

For a sanitizer-built binary, find a concrete input that drives execution
from a source address to a target address.

Use case: the data-flow engine says "this path is reachable in principle";
this oracle proves it with a witness input you can paste into a reproducer.

This is the highest-cost / lowest-coverage oracle in Layer 3. We surface
it for the cases where fuzzing struggles (paths gated by deep conditional
chains that random mutation rarely hits).

Implementation notes:
  - angr is heavy (~500MB resident, slow startup). Spawn as subprocess
    with a hard time limit. Default 60s per query.
  - Targets are specified as either (function_name) or (address). If
    function_name, we resolve via the binary's symbol table.
  - Returns concrete input as base64 to stay JSON-safe.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass


@dataclass
class SymexResult:
    binary_path: str
    source: str            # function name or "main"
    target: str
    timeout_s: int
    reachable: bool = False
    concrete_input_b64: str | None = None
    path_summary: str | None = None
    explored_states: int = 0
    duration_s: int = 0
    error_message: str | None = None


# We embed the angr driver script as a string. It's launched as a subprocess
# so we get hard timeout enforcement, and angr's verbose logging doesn't
# pollute our process.
ANGR_DRIVER = r'''
import sys, json, base64

binary_path  = sys.argv[1]
source_name  = sys.argv[2]
target_name  = sys.argv[3]
timeout_s    = int(sys.argv[4])

try:
    import angr
    import angr.exploration_techniques as tech
except ImportError:
    print(json.dumps({"error": "angr not installed"}))
    sys.exit(2)

try:
    proj = angr.Project(binary_path, auto_load_libs=False)
    src_sym = proj.loader.find_symbol(source_name)
    tgt_sym = proj.loader.find_symbol(target_name)
    if not src_sym:
        print(json.dumps({"error": f"source symbol not found: {source_name}"}))
        sys.exit(0)
    if not tgt_sym:
        print(json.dumps({"error": f"target symbol not found: {target_name}"}))
        sys.exit(0)

    state = proj.factory.call_state(src_sym.rebased_addr)
    simgr = proj.factory.simulation_manager(state)
    simgr.use_technique(tech.Explorer(find=tgt_sym.rebased_addr))

    import threading
    done = threading.Event()
    def stop_after():
        done.wait(timeout_s)
    t = threading.Thread(target=stop_after, daemon=True); t.start()

    while simgr.active and not done.is_set():
        simgr.step()
        if simgr.found:
            break

    if simgr.found:
        s = simgr.found[0]
        # Try to extract stdin or initial argv as the concrete input
        stdin_bytes = b""
        try:
            stdin_bytes = s.posix.dumps(0)
        except Exception:
            pass
        print(json.dumps({
            "reachable": True,
            "concrete_input_b64": base64.b64encode(stdin_bytes).decode(),
            "path_summary": f"explored {len(simgr.deadended) + len(simgr.found)} states",
            "explored_states": len(simgr.deadended) + len(simgr.found),
        }))
    else:
        print(json.dumps({
            "reachable": False,
            "path_summary": "target not reached in budget",
            "explored_states": len(simgr.deadended),
        }))
except Exception as e:
    print(json.dumps({"error": f"angr exception: {e}"}))
'''


def symex_reach(
    binary_path: str | os.PathLike,
    source: str,
    target: str,
    timeout_seconds: int = 60,
) -> SymexResult:
    """Run angr to find a witness input from `source` to `target`."""
    start = time.time()
    binary_path = str(binary_path)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False,
    ) as f:
        f.write(ANGR_DRIVER)
        driver = f.name

    cmd = [
        sys.executable, driver,
        binary_path, source, target, str(timeout_seconds),
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_seconds + 30,
        )
    except subprocess.TimeoutExpired:
        return SymexResult(
            binary_path=binary_path, source=source, target=target,
            timeout_s=timeout_seconds, reachable=False,
            duration_s=int(time.time() - start),
            error_message="symex driver process timed out",
        )
    finally:
        try:
            os.unlink(driver)
        except OSError:
            pass

    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return SymexResult(
            binary_path=binary_path, source=source, target=target,
            timeout_s=timeout_seconds, reachable=False,
            duration_s=int(time.time() - start),
            error_message=f"could not parse angr output: {proc.stderr[:300]}",
        )

    if "error" in data:
        return SymexResult(
            binary_path=binary_path, source=source, target=target,
            timeout_s=timeout_seconds, reachable=False,
            duration_s=int(time.time() - start),
            error_message=data["error"],
        )

    return SymexResult(
        binary_path=binary_path, source=source, target=target,
        timeout_s=timeout_seconds,
        reachable=data.get("reachable", False),
        concrete_input_b64=data.get("concrete_input_b64"),
        path_summary=data.get("path_summary"),
        explored_states=data.get("explored_states", 0),
        duration_s=int(time.time() - start),
    )


def to_dict(r: SymexResult) -> dict:
    return {
        "binary_path": r.binary_path,
        "source": r.source, "target": r.target,
        "timeout_s": r.timeout_s, "reachable": r.reachable,
        "concrete_input_b64": r.concrete_input_b64,
        "path_summary": r.path_summary,
        "explored_states": r.explored_states,
        "duration_s": r.duration_s,
        "error_message": r.error_message,
    }
