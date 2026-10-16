"""Ghidra drafts: decompiled C for platforms m2c doesn't read (x86, AArch64, Xbox 360 PowerPC, SuperH...).

Optional: Ghidra is large (540 MB) and needs Java 21+. Headless Ghidra analyses a unit's target object once
and decompiles all its functions; the result is cached next to the project, so the cost (tens of seconds,
mostly starting the JVM) is paid once per source file.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from importlib import resources
from pathlib import Path

from .. import toolchains
from ..limits import capped


def available() -> bool:
    return toolchains.installed("ghidra") is not None and toolchains.java_version() >= 21


def _headless() -> Path:
    base = toolchains.path("ghidra") / "support"
    return base / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")


def decompile_object(obj: Path, cache_dir: Path, timeout: float = 900) -> dict[str, str]:
    """name -> decompiled C for every function in an object file (cached by the object's content)."""
    data = obj.read_bytes()
    key = hashlib.sha1(data).hexdigest()[:16]
    cache = cache_dir / f"{obj.stem}-{key}.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if not available():
        return {}
    with tempfile.TemporaryDirectory(prefix="decompwtf-ghidra-") as tmp:
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        src = resources.files("decompnet.forks").joinpath("ghidra_scripts", "DecompWtfExport.java")
        (scripts / "DecompWtfExport.java").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        out = Path(tmp) / "out.jsonl"
        target = Path(tmp) / obj.name
        shutil.copyfile(obj, target)
        argv = [str(_headless()), tmp, "decompwtf", "-import", str(target), "-scriptPath", str(scripts),
                "-postScript", "DecompWtfExport.java", str(out), "-deleteProject"]
        try:
            subprocess.run(capped(argv), capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return {}
        result = {}
        if out.exists():
            for line in out.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                result[row["name"]] = row["c"]
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(result), encoding="utf-8")
    return result


def decompile_binary(path: Path, cache_dir: Path, timeout: float = 1800) -> list[dict]:
    """Every function of a whole binary, each with its address: [{"name", "address", "c"}].

    Importing the whole file is the better deal for a draft. The analysis runs once, so the
    JVM start is paid once rather than once per function, and the decompiler sees what a
    single-function object cannot: the real data sections, the real call graph, the real
    jumptable the switch indexes, and the types other functions imply. A synthetic target
    object has the table *zeroed* with relocations (which is what makes it match under
    objdiff), so decompiling one loses exactly the information the decompiler needs.

    Cached by the file's content hash, so repeated requests never re-analyse.
    """
    data = path.read_bytes()
    key = hashlib.sha1(data).hexdigest()[:16]
    cache = cache_dir / f"{path.stem}-{key}.functions.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if not available():
        return []
    rows: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="decompwtf-ghidra-") as tmp:
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        src = resources.files("decompnet.forks").joinpath("ghidra_scripts", "DecompWtfExport.java")
        (scripts / "DecompWtfExport.java").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        out = Path(tmp) / "out.jsonl"
        target = Path(tmp) / path.name
        shutil.copyfile(path, target)
        argv = [str(_headless()), tmp, "decompwtf", "-import", str(target), "-scriptPath", str(scripts),
                "-postScript", "DecompWtfExport.java", str(out), "-deleteProject"]
        try:
            subprocess.run(capped(argv), capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return []
        if out.exists():
            for line in out.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                rows.append({"name": row["name"], "address": row.get("address"), "c": row["c"]})
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(rows), encoding="utf-8")
    return rows


def drafts_by_rva(path: Path, cache_dir: Path, image_base: int) -> dict[int, dict]:
    """{rva: {"name", "address", "c"}} for a whole binary: cache by content hash, look up by RVA.

    An RVA is the key that survives everything that matters here -- ASLR moving the load
    address, a symbol-less binary where every function is `FUN_1400011b0`, and the fact that
    our own recovered function table is in RVAs too.
    """
    out: dict[int, dict] = {}
    for row in decompile_binary(path, cache_dir):
        address = row.get("address")
        if address is not None:
            out[address - image_base] = row
    return out
