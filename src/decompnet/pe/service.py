"""Importing a Windows application, as one operation the HTTP routes and the MCP tools share.

Both front ends call the functions here, so the browser and an agent create exactly the same
project -- there is no second implementation to drift.

An import is three steps and all three can take a while on a real binary (Ghidra decompiles
every function it finds), so each is a background job that reports progress as it goes:

    create   an application project with one module in it
    module   another EXE or DLL added to a project that already exists
    analyse  re-run discovery on a module already imported

Nothing here executes the binary. Analysis is static: the headers are read, the code is
disassembled, and Ghidra parses it out of process. An imported DLL is never loaded.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from ..forks import ghidra
from . import appproject as ap
from .image import PEImage


class Cancelled(Exception):
    """Raised when the user stops an import. Nothing partial is registered: the project
    directory is removed rather than left half-built and looking real."""


def _ticker(log, every: int = 250):
    """A progress reporter for a long loop. Saying nothing for 28 seconds looks like a hang."""
    import time

    state = {"n": 0, "t": time.time()}

    def step(what: str, total: int) -> None:
        state["n"] += 1
        if state["n"] % every == 0 or state["n"] == total:
            rate = state["n"] / max(0.001, time.time() - state["t"])
            log(f"{what}: {state['n']}/{total} ({rate:.0f}/s)")
    return step

# a name the filesystem and a URL can both carry
SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug_for(name: str) -> str:
    return SLUG_RE.sub("-", name.lower()).strip("-") or "project"


def unique_slug(home: Path, wanted: str, taken: set[str]) -> str:
    """A directory name that is free on disk and in the database. Never reuses a name: an
    import that quietly merged into an existing project would look like it had worked."""
    base = slug_for(wanted)
    slug, n = base, 2
    while slug in taken or (home / slug).exists():
        slug, n = f"{base}-{n}", n + 1
    return slug


def drafts_for(path: Path, cache: Path, log=print, should_stop=None) -> dict[int, str]:
    """Ghidra drafts for every function, keyed by RVA.

    One whole-binary pass, not one per function: it is faster by an order of magnitude, and it
    is the only way the switch statements come out right. A synthetic target object has its jump
    table zeroed and relocated -- which is what makes it match in objdiff -- so a decompiler
    reading that object cannot see the table at all, while reading the linked image it can.
    """
    try:
        import image_base_of  # noqa: F401  (never true; kept for import-order clarity)
    except ImportError:
        pass
    if not ghidra.available():
        log("Ghidra is not installed: the project will be created without C drafts")
        return {}
    img = PEImage.load(path)
    t0 = time.time()
    if should_stop and should_stop():
        raise Cancelled("stopped before Ghidra started")
    log("Ghidra: analysing the whole binary (this is the slow part on a large one)")
    rows = ghidra.drafts_by_rva(path, cache, img.image_base)
    log(f"Ghidra: {len(rows)} of {len(rows)} functions decompiled in {time.time() - t0:.0f}s")
    return {rva: row["c"] for rva, row in rows.items()}


def _report(path: Path, log) -> PEImage:
    img = PEImage.load(path)
    kind = "DLL" if img.is_dll else "EXE"
    log(f"{path.name}: {img.machine_name} {kind}, image base {img.image_base:#x}, "
        f"{'no symbols' if img.is_stripped else 'has symbols'}")
    return img


def create(name: str, binary: Path, home: Path, net, *, drafts: bool = True,
           no_inline: bool = True, log=print, should_stop=None) -> dict:
    """Make a new application project holding `binary` as its first module.

    `home` is DECOMP_HOME: the project is created inside it, where every other project lives,
    so it survives a restart and appears in the project list like anything else.
    """
    binary = Path(binary)
    if not binary.is_file():
        raise ValueError(f"no file at {binary}")
    _report(binary, log)

    taken = {r["slug"] for r in net.store.all("SELECT slug FROM projects")}
    slug = unique_slug(home, name or binary.stem, taken)
    dest = home / slug
    home.mkdir(parents=True, exist_ok=True)

    log(f"creating {slug} at {dest}")
    ap.create_application_project(dest, name or binary.stem, log=log)

    if should_stop and should_stop():
        _discard(dest, log)
        raise Cancelled("stopped before analysis began")
    found = drafts_for(binary, home / ".decomp" / "ghidra", log=log,
                       should_stop=should_stop) if drafts else {}
    log(f"building the project: {len(found)} draft(s)")
    ap.add_module(dest, binary, drafts=found, no_inline=no_inline, log=log)

    _git_init(dest, log)

    log("registering it with decomp.wtf")
    registered = net.forks.clone(str(dest), name=name or binary.stem, platform="win-x64", log=log)
    log(f"done: {registered}")
    return {"slug": registered, "modules": module_names(dest)}


def add_module(net, slug: str, binary: Path, home: Path, *, drafts: bool = True,
               no_inline: bool = True, log=print, should_stop=None) -> dict:
    """Add an EXE or DLL to an application project that already exists.

    The existing modules are not touched: `add_module` stages the new one and moves it in, so
    sources, notes, claims, attempts and scores in the project survive unchanged.
    """
    binary = Path(binary)
    if not binary.is_file():
        raise ValueError(f"no file at {binary}")
    project = net.project_row(slug)
    dest = Path(project["root"])
    before = module_names(dest)
    log(f"{slug}: {len(before)} module(s) now ({', '.join(before) or 'none'})")
    _report(binary, log)

    if binary.name in before or _same_content(dest, binary, before):
        log(f"{binary.name} is already a module of {slug}")

    found = drafts_for(binary, home / ".decomp" / "ghidra", log=log) if drafts else {}
    ap.add_module(dest, binary, drafts=found, no_inline=no_inline, log=log)
    after = module_names(dest)
    log(f"{slug}: {len(after)} module(s) ({', '.join(after)})")

    # the app reads the tree from disk, but its unit index is cached: re-measuring picks the
    # new module's functions up without restarting anything
    net.forks.check(slug, log=log)
    return {"slug": slug, "added": sorted(set(after) - set(before)), "modules": after}


def _same_content(dest: Path, binary: Path, modules: list[str]) -> bool:
    import hashlib

    want = hashlib.sha1(binary.read_bytes()).hexdigest()
    for name in modules:
        for candidate in (dest / "binaries").glob(f"{name}.*"):
            if hashlib.sha1(candidate.read_bytes()).hexdigest() == want:
                return True
    return False



def _git_init(dest: Path, log=print) -> None:
    """forks.clone() clones a repository, so the project has to be one.

    Without this the clone fails with "give a GitHub/GitLab/Codeberg repository URL", which
    says nothing about the real problem. Committing the generated tree also means the built
    objects travel with the clone -- and the clone is what the app measures, so a project whose
    build/ was not committed will read near zero for reasons that have nothing to do with the C.
    """
    import subprocess

    if (dest / ".git").exists():
        return
    def git(*args):
        return subprocess.run(["git", *args], cwd=str(dest), capture_output=True, text=True)
    git("init", "-q")
    git("add", "-A")
    git("-c", "user.email=import@decomp.wtf", "-c", "user.name=decomp.wtf",
        "commit", "-qm", "Imported from a PE64 binary")
    log("initialised the project as a git repository")


def module_names(dest: Path) -> list[str]:
    return [m["name"] for m in ap.load_manifest(dest).get("modules", [])]


def modules(dest: Path) -> list[dict]:
    """What the UI shows for each module: identity, size, and how analysis went."""
    out = []
    for m in ap.load_manifest(dest).get("modules", []):
        out.append({
            "id": m["id"], "name": m["name"], "kind": m["kind"], "arch": m["arch"],
            "binary": m["binary"], "image_base": m["image_base"], "entry_point": m["entry_point"],
            "sha1": m["sha1"], "size": m["size"], "linker": m.get("linker"),
            "imports": list((m.get("imports") or {})), "unresolved": m.get("unresolved", []),
            "functions": len(m.get("functions", [])),
            "counts": m.get("counts", {}),
            "status": module_counts(dest, m),
            "pdb": m.get("pdb"),
        })
    return out


def module_functions(dest: Path, module: str, *, offset: int = 0, limit: int = 0,
                     status: str = "") -> dict:
    """A page of one module's functions.

    A 30,000-function module cannot be sent to a browser in one response: it is megabytes of
    JSON that the page then has to build a row for. `limit=0` returns the page size the UI uses by
    default; the caller pages with `offset` until `next_offset` comes back empty.
    """
    rows = None
    for m in ap.load_manifest(dest).get("modules", []):
        if m["name"] == module or m["id"] == module:
            rows = m.get("functions", [])
            break
    if rows is None:
        raise ValueError(f"no module {module} in this project")
    total = len(rows)
    if status:
        rows = [r for r in rows if r.get("state", "") == status]
    page_size = limit or 500
    offset = max(0, int(offset))
    window = rows[offset:offset + page_size]
    return {"module": module, "total": total, "matched_filter": len(rows) if status else total,
            "offset": offset, "limit": page_size, "returned": len(window),
            "next_offset": offset + page_size if offset + page_size < len(rows) else None,
            "functions": window}


def is_application(dest: Path) -> bool:
    """Whether this project was made by the PE64 importer, so the UI can offer Add Module."""
    try:
        return ap.load_manifest(dest).get("kind") == "pe64-application"
    except (OSError, ValueError):
        return False


# --- honest status --------------------------------------------------------------------------

def decomp_home(net) -> Path:
    """DECOMP_HOME: the directory projects live in.

    Not `net.home`, which is the internal `.decomp` directory -- putting a project there hides it
    from the project list and loses it on a clean-up. Falls back to an existing project's parent.
    """
    for attr in ("decomp_home", "workspace"):
        value = getattr(net, attr, None)
        if value and Path(value).name != ".decomp":
            return Path(value)
    row = net.store.one("SELECT root FROM projects ORDER BY id LIMIT 1")
    if row and row["root"]:
        return Path(row["root"]).parent
    home = getattr(net, "home", None)
    if home and Path(home).name == ".decomp":
        return Path(home).parent
    raise ValueError("cannot find DECOMP_HOME")


ERROR_RE = re.compile(r"^(.+?)\((\d+)\)\s*:\s*(?:fatal\s+)?error\s+(\w+)?\s*:?\s*(.*)$")


def compile_errors(dest: Path, *, log=None) -> dict[str, str]:
    """Build the project and collect the compiler's complaints, keyed by source file.

    A draft that does not compile is the ordinary case, not an import failure: the project still
    measures because a function with no candidate is a function not yet written. What must not
    happen is that the absence of an error is read as success -- so the errors are collected and
    shown rather than swallowed.
    """
    import shutil
    import subprocess
    import sys

    ninja = shutil.which("ninja")
    if not ninja:
        for candidate in (Path(sys.executable).parent / "ninja", Path("/usr/bin/ninja")):
            if candidate.exists():
                ninja = str(candidate)
                break
    if not ninja:
        return {}
    try:
        res = subprocess.run([ninja, "-C", str(dest)], capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    out: dict[str, str] = {}
    for line in (res.stdout + res.stderr).splitlines():
        m = ERROR_RE.match(line.strip())
        if not m:
            continue
        where = m.group(1).replace("\\", "/").lstrip("./")
        code = (m.group(3) or "error").upper()
        out[where] = f"{code}: {m.group(4).strip()}"[:300]
    return out


def placeholder_bytes(symbol: str) -> bytes:
    """Exactly what add_module writes when a source does not compile."""
    from .coff import build_object

    return build_object(symbol, b"\xc3", [])



def module_counts(dest: Path, m: dict) -> dict:
    """How many of a module's functions have C the compiler accepted, without running the build.

    `compiled` means build/<module>/<symbol>.obj exists and is not the one-instruction stand-in
    add_module writes when a source does not compile. Everything else is `stand_in`, and a match
    percentage that counts a stand-in is not progress -- which is the whole reason this exists.
    """
    out = {"compiled": 0, "stand_in": 0, "with_draft": 0}
    for fn in m.get("functions", []):
        symbol = fn["symbol"]
        src = dest / "src" / m["name"] / f"{symbol}.c"
        obj = dest / "build" / m["name"] / f"{symbol}.obj"
        if src.exists() and "No draft was available" not in src.read_text(encoding="utf-8"):
            out["with_draft"] += 1
        try:
            if obj.exists() and obj.read_bytes() != placeholder_bytes(symbol):
                out["compiled"] += 1
                continue
        except OSError:
            pass
        out["stand_in"] += 1
    return out


def function_status(dest: Path, net=None, slug: str = "", errors: dict | None = None) -> list[dict]:
    """One honest row per function, told from what is on disk rather than from intent.

        matched     the project's own record says this function matches byte for byte
        compiled    the compiler produced this function's object from the C in src/
        failed      a draft exists, the compiler rejected it (the error is attached)
        untried     no draft and no object: nothing has been written for it yet

    `compiled` and `failed` both have an object in build/, because objdiff needs one either way.
    Only `compiled` is a candidate anyone wrote.
    """
    errors = compile_errors(dest) if errors is None else errors
    matched: set[str] = set()
    if net is not None and slug:
        for row in net.store.all(
                "SELECT f.name FROM functions f JOIN projects p ON p.id = f.project_id "
                "WHERE p.slug = ? AND f.status = 'matched'", slug):
            matched.add(row["name"])
    out: list[dict] = []
    for m in ap.load_manifest(dest).get("modules", []):
        for fn in m.get("functions", []):
            symbol = fn["symbol"]
            src = dest / "src" / m["name"] / f"{symbol}.c"
            obj = dest / "build" / m["name"] / f"{symbol}.obj"
            drafted = src.exists() and "No draft was available" not in src.read_text(encoding="utf-8")
            built = obj.exists() and obj.read_bytes() != placeholder_bytes(symbol)
            if symbol in matched:
                state = "matched"
            elif built:
                state = "compiled"
            elif drafted:
                state = "failed"
            else:
                state = "untried"
            err = errors.get(f"src/{m['name']}/{symbol}.c")
            out.append({"module": m["name"], "symbol": symbol, "rva": f"{fn['rva']:#x}",
                        "size": fn["size"], "discovered_by": fn["discovered_by"],
                        "status": state, "has_draft": drafted, "placeholder": not built,
                        "error": err, "jump_tables": fn.get("jump_tables", []),
                        "relocations": len(fn.get("relocations", []))})
    return out


def status_summary(rows: list[dict]) -> dict:
    """Counts for a project header. `stand_ins` is the number that must never be read as
    progress: those objects exist so objdiff can run, not because anything compiled."""
    counts = {"matched": 0, "compiled": 0, "failed": 0, "untried": 0}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"functions": len(rows), **counts,
            "stand_ins": sum(1 for r in rows if r["placeholder"]),
            "with_errors": sum(1 for r in rows if r["error"]),
            "by_module": {m: sum(1 for r in rows if r["module"] == m)
                          for m in sorted({r["module"] for r in rows})}}


def import_status(net, slug: str) -> dict:
    """Everything the UI and an agent need to know about an application project."""
    row = net.project_row(slug)
    dest = Path(row["root"])
    if not is_application(dest):
        return {"application": False, "slug": slug}
    rows = function_status(dest, net, slug)
    return {"application": True, "slug": slug, "root": str(dest),
            "modules": modules(dest), "summary": status_summary(rows),
            "functions": rows}


def _discard(dest: Path, log=print) -> None:
    """Remove a project that was stopped before it was registered, so a half-built tree does not
    sit there looking like a real project."""
    import shutil

    try:
        if dest.exists():
            shutil.rmtree(dest)
            log(f"removed the unfinished project at {dest}")
    except OSError as e:
        log(f"could not remove {dest}: {e}")


# Above this many units a project is imported but not compiled: objdiff needs one object per
# unit, so building it means that many cl.exe processes, which is minutes of thrashing for a
# result nobody asked for yet. The targets, sources and listings are all still generated.
BUILD_LIMIT = 1500


def buildable(count: int) -> tuple[bool, str]:
    if count > BUILD_LIMIT:
        return False, (f"{count} functions is more than the {BUILD_LIMIT} the importer will "
                       f"compile in one go. The project is ready to work on: compile a unit when "
                       f"you want to diff it, or raise BUILD_LIMIT in pe/service.py.")
    return True, ""


# --- repair ----------------------------------------------------------------------------------

def repair_functions(net, slug: str, *, module: str = "", symbols: list[str] | None = None,
                     force: bool = False, log=print) -> dict:
    """Repair drafts that do not compile. The browser and the MCP tools both come here.

    Bounded and deterministic: a fixed set of rules keyed to the compiler's own diagnostics, a
    maximum number of passes, and nothing invented. A file a person has edited is left alone. A
    function is only reported as repaired if the compiler accepts it afterwards, and a repaired
    file is still only a candidate -- whether it matches is objdiff's answer.
    """
    from . import repair

    row = net.project_row(slug)
    dest = Path(row["root"])
    if not is_application(dest):
        raise ValueError(f"{slug} is not a Windows application project")

    targets = []
    for m in modules(dest):
        if module and m["name"] != module:
            continue
        for f in module_functions(dest, m["name"])["functions"]:
            targets.append((m["name"], f["symbol"]))
    if symbols:
        wanted = set(symbols)
        targets = [(mod, sym) for mod, sym in targets if sym in wanted]

    rows = {(r["module"], r["symbol"]): r for r in function_status(dest, net, slug)}
    todo = [(mod, sym) for mod, sym in targets if rows.get((mod, sym), {}).get("status") == "failed"]
    log(f"{len(todo)} function(s) do not compile"
        + (f" in {module}" if module else ""))

    outcomes = []
    for mod, sym in todo:
        o = repair.repair_function(dest, mod, sym, log=log, force=force)
        outcomes.append(o)
    if outcomes:
        history = repair_module_history(dest, module or (outcomes[0].symbol and ""))
        _record_repairs(dest, module, outcomes, history)

    fixed = sum(1 for o in outcomes if o.after == "compiled")
    log(f"repaired {fixed} of {len(outcomes)}; the rest are recorded for an agent")
    return {"repaired": fixed, "attempted": len(outcomes),
            "outcomes": [{"symbol": o.symbol, "before": o.before, "after": o.after,
                          "repairs": [r.__dict__ for r in o.repairs],
                          "deferred": o.deferred} for o in outcomes]}


def _record_repairs(dest: Path, module: str, outcomes, previous) -> None:
    import json as _json

    path = dest / "notes" / "repairs.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = {}
    for e in previous:
        entries[e["symbol"]] = e
    for o in outcomes:
        entries[o.symbol] = {"symbol": o.symbol, "before": o.before, "after": o.after,
                             "repairs": [r.__dict__ for r in o.repairs], "deferred": o.deferred}
    path.write_text(_json.dumps({"module": module, "functions": sorted(
        entries.values(), key=lambda e: e["symbol"])}, indent=2) + "\n", encoding="utf-8")


def repair_module_history(dest: Path, module: str = "") -> list[dict]:
    import json as _json

    path = dest / "notes" / "repairs.json"
    if not path.exists():
        return []
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return []
    rows = data.get("functions", [])
    if module and data.get("module") and data["module"] != module:
        return [r for r in rows if r.get("module") == module]
    return rows
