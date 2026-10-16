"""Turn a PE32+ executable into a working objdiff project.

The whole point of the importer: a stripped Windows binary has no object files and no
symbols, and everything downstream in decomp.wtf -- claims, notes, per-function diffs,
matching, agents, progress -- is driven by a fork whose `objdiff.json` names a target
and a base object per unit. So the job is to manufacture that shape:

    target/<function>.obj   a synthetic COFF object carved out of the image, with the
                            relocations a compiler would have emitted (pe/coff.py) and
                            any jump table put back where the object kept it (pe/tables.py)
    build/<function>.obj    what MSVC produces from src/<function>.c, the reconstructed C
    src/<function>.c        the reconstructed source, seeded with a Ghidra draft
    asm/<function>.s        the original assembly, for reading next to the C

and one unit per function, so a function is the unit of work -- which is what the rest of
decomp.wtf already assumes.

Naming: a stripped image has no names, so functions are called `sub_<rva>`. That is also why
everything is keyed by RVA (pe/ghidra.py): a name can be supplied from a map file, a PDB or a
disassembler, but the address is what the image actually guarantees, and it is what joins the
inventory, the target object and the draft together.

Two things are deliberately *not* done here. Real symbol names are not invented (`names` can
supply them from a real source). And nothing is claimed to match: the drafts are starting
points, and a generated function whose C does not build yet shows up as a broken unit rather
than a match.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .coff import Reloc
from .discover import Found, call_targets, discover, unwind_regions
from .image import PEImage
from .tables import table_aware_object

# Ghidra's decompiler emits its own type vocabulary. These shims let a raw draft be compiled
# by MSVC as a starting point. `code` (an unknown callee) has no honest C spelling, so drafts
# that call through one will not build until they are fixed -- which is the work, not a bug.
GHIDRA_TYPES = """\
/* Types Ghidra's decompiler uses, so its drafts compile as a starting point.
   `code` (an indirect call through something it could not resolve) has no C equivalent:
   a function using it will not build until it is rewritten. That is the work. */
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char undefined;
typedef signed char sbyte;
typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned short wchar16;
"""

# what a generated source starts from when there is no draft
STUB = """\
/* sub_{rva}: recovered at rva {rva:#x}, {size} bytes. No draft was available.
   Replace the body with C that compiles to the target object in target/{name}.obj. */
int {name}(void)
{{
    return 0;
}}
"""


def find_cl() -> str | None:
    """MSVC's x64 compiler, as a path this WSL can exec (Windows paths go through interop)."""
    if shutil.which("cl"):                      # already on PATH (an MSVC environment)
        return "cl"
    roots = sorted(Path("/mnt/c/Program Files (x86)/Microsoft Visual Studio").glob("*/*/VC/Tools/MSVC/*"))
    roots += sorted(Path("/mnt/c/Program Files/Microsoft Visual Studio").glob("*/*/VC/Tools/MSVC/*"))
    for toolset in reversed(roots):
        cl = toolset / "bin/Hostx64/x64/cl.exe"
        if cl.exists():
            return str(cl)
    return None


@dataclass
class RecoveredFunction:
    name: str
    rva: int
    size: int
    discovered_by: str                       # "pdata" | "call" | "sweep"
    end: int = 0
    relocs: list[Reloc] = field(default_factory=list)
    tables: list[int] = field(default_factory=list)      # RVAs of recovered jump tables
    note: str = ""

    def as_json(self) -> dict:
        return {"name": self.name, "rva": self.rva, "size": self.size, "end": self.end,
                "discovered_by": self.discovered_by,
                "relocations": [{"offset": r.offset, "type": r.type,
                                 "type_name": r.type_name, "target_rva": r.target_rva}
                                for r in self.relocs],
                "jump_tables": self.tables}


def inventory(img: PEImage, *, names: dict[int, str] | None = None,
              min_size: int = 1) -> list[RecoveredFunction]:
    """Every function the importer can justify, in address order.

    Names come from `names` (a map file, a PDB, a disassembler export) when it has one for
    the address, and are `sub_<rva>` otherwise: a stripped image has no names to invent.
    """
    found: list[Found] = [f for f in discover(img) if f.size >= min_size]
    ordered = sorted(found, key=lambda f: f.rva)
    out: list[RecoveredFunction] = []
    for i, f in enumerate(ordered):
        nxt = ordered[i + 1].rva if i + 1 < len(ordered) else None
        name = (names or {}).get(f.rva) or f"sub_{f.rva:x}"
        out.append(RecoveredFunction(name=name, rva=f.rva, size=f.size,
                                     discovered_by=f.source, end=nxt or f.rva + f.size))
    return out


def _asm_listing(img: PEImage, fn: RecoveredFunction) -> str:
    """The original assembly, as a listing to read next to the C."""
    import capstone

    code = img.bytes_at(fn.rva, fn.size) or b""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    md.skipdata = True
    lines = [f"; {fn.name}  rva {fn.rva:#x}  {fn.size} bytes  (recovered by {fn.discovered_by})",
             f"; original bytes of the linked image; the target object is target/{fn.name}.obj",
             "", f"{fn.name}:"]
    for ins in md.disasm(code, fn.rva):
        lines.append(f"    {ins.address:#010x}  {ins.bytes.hex():<22} {ins.mnemonic} {ins.op_str}".rstrip())
    return "\n".join(lines) + "\n"


def _source_for(fn: RecoveredFunction, draft: str | None) -> str:
    """The C a unit starts from: the Ghidra draft, renamed to our own function name."""
    if draft:
        text = draft.replace(fn.name, fn.name)          # already ours
        # Ghidra names it FUN_<address> or entry; use the project's name so objdiff pairs
        # the built object with the target object by symbol
        text = re.sub(r"\bFUN_[0-9a-fA-F]{6,}\b", fn.name, text)
        text = re.sub(r"\bentry\b", fn.name, text) if "entry" in text else text
        return f'#include "../include/ghidra_types.h"\n\n{text.strip()}\n'
    return ('#include "../include/ghidra_types.h"\n\n'
            + STUB.format(rva=fn.rva, size=fn.size, name=fn.name))


def build_project(exe: Path, dest: Path, *, slug: str | None = None, names: dict[int, str] | None = None,
                  drafts: dict[int, str] | None = None, cl: str | None = None,
                  no_inline: bool = False, log=print) -> dict:
    """Write a complete objdiff project for `exe` into `dest`; returns its metadata.

    A local git repository, because that is what decomp.wtf's fork workflow registers
    (`forks.clone` accepts a path to one). Nothing is pushed anywhere.
    """
    img = PEImage.load(exe)
    data = exe.read_bytes()
    digest = hashlib.sha1(data).hexdigest()
    slug = slug or f"{re.sub(r'[^a-zA-Z0-9]+', '-', exe.stem).strip('-').lower()}-pe64"
    drafts = drafts or {}

    # An application project (pe/appproject.py) can hold several modules; regenerating the
    # tree would destroy every one of them. Refuse instead of doing it.
    if (dest / ".decomp.wtf.json").exists():
        existing = json.loads((dest / ".decomp.wtf.json").read_text(encoding="utf-8"))
        if existing.get("kind") == "pe64-application" or existing.get("modules"):
            raise ValueError(
                f"{dest} is an application project: use pe.appproject.add_module() to add a "
                f"module, or a new destination. build_project would delete every module in it.")
    if dest.exists():
        shutil.rmtree(dest)
    for sub in ("target", "build", "src", "asm", "include", "notes"):
        (dest / sub).mkdir(parents=True, exist_ok=True)
    (dest / "include/ghidra_types.h").write_text(GHIDRA_TYPES, encoding="utf-8")

    functions = inventory(img, names=names)
    log(f"{exe.name}: {len(functions)} functions recovered from {img.machine_name} "
        f"{'PE32+' if img.optional_magic == 0x20B else 'PE32'}")

    cl = cl if cl is not None else find_cl()
    units = []
    for fn in functions:
        obj, relocs, tables, notes = table_aware_object(
            img, fn.rva, fn.size, fn.name, next_rva=fn.end if fn.end > fn.rva else None)
        (dest / "target" / f"{fn.name}.obj").write_bytes(obj)
        fn.relocs = relocs
        fn.tables = [t.rva for t in tables]
        fn.note = "; ".join(notes)

        draft = drafts.get(fn.rva)
        (dest / "src" / f"{fn.name}.c").write_text(_source_for(fn, draft), encoding="utf-8")
        (dest / "asm" / f"{fn.name}.s").write_text(_asm_listing(img, fn), encoding="utf-8")
        units.append({"name": fn.name, "path": f"{fn.name}.obj",
                      "metadata": {"source_path": f"src/{fn.name}.c",
                                   "complete": False,
                                   "draft": "ghidra" if draft else "none",
                                   "rva": f"{fn.rva:#x}"}})

    (dest / "objdiff.json").write_text(json.dumps({
        "target_dir": "target", "base_dir": "build", "custom_make": "ninja",
        "options": {"functionRelocDiffs": "none",
                    "combineDataSections": True, "combineTextSections": True},
        "units": units,
    }, indent=2) + "\n", encoding="utf-8")

    opt = "/Od" if no_inline else "/O2"
    ninja = ["# Building reconstructed C with MSVC, driven from WSL through interop.",
             "# The path is quoted: it has spaces and parentheses.",
             f'cl = "{cl}"' if cl else "# cl was not found: set it before building",
             f"cflags = {opt} /GS- /c /nologo /Iinclude", "",
             "rule cc", "  command = $cl $cflags /Fo:$out $in", "  description = cl $in", ""]
    for fn in functions:
        ninja.append(f"build build/{fn.name}.obj: cc src/{fn.name}.c")
    ninja.append("")
    ninja.append("default " + " ".join(f"build/{fn.name}.obj" for fn in functions))
    (dest / "build.ninja").write_text("\n".join(ninja) + "\n", encoding="utf-8")

    meta = {
        "kind": "pe64-import",
        "slug": slug,
        "generated": time.time(),
        "source": {"name": exe.name, "sha1": digest, "size": len(data),
                   "machine": img.machine_name, "image_base": f"{img.image_base:#x}",
                   "entry_point": f"{img.entry_point:#x}",
                   "linker": f"{img.linker_version[0]}.{img.linker_version[1]}",
                   "pdb": (img.pdb() or [None])[0] if img.pdb() else None,
                   "stripped": img.is_stripped},
        "toolchain": {"compiler": cl, "optimisation": opt},
        "counts": {"functions": len(functions),
                   "with_draft": sum(1 for f in functions if drafts.get(f.rva)),
                   "with_jump_tables": sum(1 for f in functions if f.tables),
                   "with_relocations": sum(1 for f in functions if f.relocs)},
        "functions": [f.as_json() for f in functions],
    }
    (dest / ".decomp.wtf.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    (dest / "README.md").write_text(_readme(exe, img, meta, functions), encoding="utf-8")
    (dest / "notes" / "functions.md").write_text(_inventory_md(functions), encoding="utf-8")
    seeded = seed_base_objects(dest, [f.as_json() for f in functions])
    if seeded:
        log(f"seeded {len(seeded)} base object(s) for sources that do not build yet")
    built = run_build(dest, log=log)
    if built:
        # a real object replaces the stand-in; the stand-ins stay for whatever did not build
        log(f"built {built} of {len(functions)} sources")
    seed_base_objects(dest, [f.as_json() for f in functions])
    # build/ is committed on purpose: the fork workflow clones the repo, which skips
    # ignored files, and the project has to be measurable the moment it is imported
    (dest / ".gitignore").write_text(".ninja_log\n.ninja_deps\n", encoding="utf-8")

    _git(dest, "init", "-q", "-b", "main")
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m",
         f"import {exe.name} ({img.machine_name}, {len(functions)} functions recovered)")
    log(f"wrote {dest} ({len(functions)} units, drafts for "
        f"{meta['counts']['with_draft']}, jump tables in {meta['counts']['with_jump_tables']})")
    return meta


def run_build(dest: Path, *, log=print) -> int:
    """Run the generated build.ninja; returns how many sources compiled.

    decomp.wtf's fork workflow clones the repository, so anything not committed is absent
    from the project the app actually opens. Building here, before the commit, is therefore
    not an optimisation: without it a clone would hold nothing but the stand-ins and measure
    near zero for reasons that have nothing to do with the C.
    """
    ninja = shutil.which("ninja")
    if not ninja:
        for candidate in (Path(sys.executable).parent / "ninja", Path("/usr/bin/ninja")):
            if candidate.exists():
                ninja = str(candidate)
                break
    if not ninja:
        log("ninja not found: build the project before using it")
        return 0
    try:
        res = subprocess.run([ninja, "-C", str(dest)], capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"the build did not run: {e}")
        return 0
    tail = (res.stdout + res.stderr).strip().splitlines()
    if res.returncode != 0 and tail:
        log("build: " + tail[-1][:120])
    return len(list((dest / "build").glob("*.obj")))


def seed_base_objects(dest: Path, functions: list[dict]) -> list[str]:
    """Give every unit a base object, so a half-written project still measures.

    objdiff's report needs one for each unit. A generated source that does not compile yet
    would otherwise take the whole project's report down with it, which is the wrong failure:
    an unwritten function should score near zero, not make the project unreadable. The
    stand-in is a single `ret`, and a real build overwrites it.
    """
    from .coff import build_object

    filled: list[str] = []
    for fn in functions:
        path = dest / "build" / f"{fn['name']}.obj"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(build_object(fn["name"], b"\xc3", []))
            filled.append(fn["name"])
    return filled


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                   env={"PATH": "/usr/bin:/bin", "HOME": str(cwd),
                        "GIT_AUTHOR_NAME": "decomp.wtf", "GIT_AUTHOR_EMAIL": "import@decomp.wtf",
                        "GIT_COMMITTER_NAME": "decomp.wtf", "GIT_COMMITTER_EMAIL": "import@decomp.wtf"})


def _readme(exe: Path, img: PEImage, meta: dict, functions: list[RecoveredFunction]) -> str:
    c = meta["counts"]
    return f"""# {exe.name} (imported)

A Windows {img.machine_name} executable imported into decomp.wtf: no original object files,
no symbols, no PDB.

    source      {exe.name}, {meta['source']['size']} bytes
    sha1        {meta['source']['sha1']}
    image base  {meta['source']['image_base']}
    linker      {meta['source']['linker']}
    stripped    {meta['source']['stripped']}

## How a function is worked on

Each function is a unit. `target/{'{name}'}.obj` is a synthetic COFF object carved out of the
image: the function's own bytes with the relocations a compiler would have emitted, and any
jump table put back where the compiler kept it. `src/{'{name}'}.c` is the C to write -- a
Ghidra draft of the whole executable, or a stub. `build.ninja` compiles the C with MSVC and
objdiff compares the two.

    ninja -C .          # build every src/*.c
    objdiff-cli report generate -p . -o report.json

The drafts come from one whole-binary Ghidra pass, not from decompiling the objects: the
target object has its jump table zeroed so it can match, which is exactly what a decompiler
needs to see.

## What is here

    {c['functions']} functions recovered
    {c['with_relocations']} with relocations reconstructed
    {c['with_jump_tables']} with jump tables recovered
    {c['with_draft']} with a Ghidra draft

`ninja` will not build every source as generated -- a draft is a starting point, and one
that calls through an unresolved `code` pointer cannot compile until it is rewritten. Those
units simply show as unfinished.

## Where they came from

A function is recovered from `.pdata`, from a direct call, or from a sweep of what is left;
`discovered_by` in `.decomp.wtf.json` says which. The sweep is the only source that finds a
function nothing references -- and the only one that can invent something, so it is listed
separately on purpose.

Full inventory: `notes/functions.md`.
"""


def _inventory_md(functions: list[RecoveredFunction]) -> str:
    by = {}
    for f in functions:
        by[f.discovered_by] = by.get(f.discovered_by, 0) + 1
    out = ["# Recovered functions", "",
           f"{len(functions)} functions. By source: " + ", ".join(f"{k} {v}" for k, v in sorted(by.items())),
           "", "| function | rva | size | found by | relocs | jump table | draft |",
           "|---|---|---|---|---|---|---|"]
    for f in functions:
        out.append(f"| `{f.name}` | {f.rva:#x} | {f.size} | {f.discovered_by} | "
                   f"{len(f.relocs)} | {', '.join(hex(t) for t in f.tables) or '-'} | "
                   f"{'yes' if f.note or f.relocs is not None else '-'} |")
    return "\n".join(out) + "\n"
