"""An application project: one identity, many modules.

A Windows application is not one binary. It is an executable, its DLLs, plugins loaded at
runtime, and the PDBs that may or may not come with them. This module holds all of them
without pretending they are one file:

    .decomp.wtf.json     the application: name, modules[] with id/sha1/arch/image base/imports
    objdiff.json         one unit per function, named "<module>_<symbol>"
    binaries/<module>    each module's binary, kept with the project
    target/<module>/...  synthetic COFF objects carved out of that module
    src/<module>/...     the C to write
    asm/<module>/...     that module's original assembly

**Why function symbols carry the module name.** decomp.wtf identifies a function by
`UNIQUE(project_id, name)`, and every Windows module has its own `.text` near its own base: in
the two-module fixture, `app.exe` and `plugin.dll` both have functions at rva 0x1000, 0x1020,
0x1040 and 0x10a0. Unqualified, those collide in the database and one module's work would land
on the other's row. Qualifying the symbol (`app_sub_1000`, `plugin_sub_1000`) is what makes the
*existing* schema correct for several modules without changing it. The alternative -- a
`module_id` column with `UNIQUE(project_id, module_id, name)` -- needs the `functions` table
rebuilt, and that is a destructive migration: it is written up in docs/modules.md rather than
applied quietly.

**Why module identity is a content hash.** A filename is a label someone can change, reuse or
duplicate; `sha1(binary)` is not. The id is the hash, so re-importing an unchanged module
refreshes it in place instead of duplicating it, and the *name* is only a short slug for paths
and unit names, made unique when two modules would otherwise share one.

**Nothing here removes what is already there.** `add_module` analyses the new module into a
staging directory and only then moves it in, so a failure leaves the project exactly as it was.
The legacy `project.build_project` opens with `shutil.rmtree(dest)`, which is precisely the
wrong primitive once a project can hold more than one module; it is kept only for the
single-binary path that existing projects use.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

from .coff import build_object
from .discover import discover
from .image import PEImage
from .project import GHIDRA_TYPES, _asm_listing, _source_for, find_cl, run_build
from .tables import table_aware_object

MANIFEST = ".decomp.wtf.json"
STAGING = ".staging"


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "module"


# --- the manifest ---------------------------------------------------------------------------

def load_manifest(dest: Path) -> dict:
    path = dest / MANIFEST
    if not path.exists():
        return {"kind": "pe64-application", "name": dest.name, "modules": [], "generated": time.time()}
    return json.loads(path.read_text(encoding="utf-8"))


def save_manifest(dest: Path, manifest: dict) -> None:
    (dest / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def module_of(dest: Path, module_id: str) -> dict | None:
    return next((m for m in load_manifest(dest)["modules"] if m["id"] == module_id), None)


def all_units(manifest: dict) -> list[dict]:
    """Every unit of every module, in module order: the flat list objdiff.json wants."""
    out: list[dict] = []
    for m in manifest["modules"]:
        out.extend(m.get("units", []))
    return out


# --- per-module discovery -------------------------------------------------------------------

def discover_module(img: PEImage, module_name: str) -> list[dict]:
    """Every function of one module, named so it cannot collide with another module's.

    The symbol is `<module>_<rva>`, not `<rva>`: two modules both have a `sub_1000`, and the
    database (and objdiff, and the filesystem) would otherwise have to choose between them.
    """
    ordered = sorted(discover(img), key=lambda f: f.rva)
    out: list[dict] = []
    for i, f in enumerate(ordered):
        nxt = ordered[i + 1].rva if i + 1 < len(ordered) else f.rva + f.size
        local = f"sub_{f.rva:x}"
        out.append({"symbol": f"{module_name}_{local}", "local": local, "rva": f.rva,
                    "size": f.size, "end": nxt, "discovered_by": f.source})
    return out


def delay_imports(img: PEImage) -> dict[str, list[str]]:
    """The delay-load import directory (data directory 13). Recorded, not required to resolve."""
    rva, size = img.directory(13)
    out: dict[str, list[str]] = {}
    if not rva or size < 32:
        return out
    off = img.rva_to_offset(rva)
    if off is None:
        return out
    for i in range(size // 32):
        desc = img.data[off + i * 32: off + i * 32 + 32]
        if len(desc) < 32:
            break
        name_rva, = struct.unpack_from("<I", desc, 4)
        if not name_rva:
            break
        no = img.rva_to_offset(name_rva)
        if no is not None:
            out[img.data[no:].split(b"\0")[0].decode("latin1", "replace")] = []
    return out


def unresolved_imports(entry: dict, modules: list[dict]) -> list[str]:
    """Imports no module in the project provides. Recorded, not treated as a failure: an import
    table naming a DLL we do not have is normal, and nothing here needs it to resolve."""
    have = {m["name"].lower() for m in modules}
    have |= {Path(m["binary"]).name.lower() for m in modules}
    return sorted(d for d in entry.get("imports", {}) if d.lower() not in have)


def analyze_module(dest: Path, module_id: str, *, log=print) -> dict:
    """(Re)discover a module's functions and imports from its binary."""
    manifest = load_manifest(dest)
    entry = module_of(dest, module_id)
    if entry is None:
        raise KeyError(f"no module {module_id} in this project")
    img = PEImage.load(dest / entry["binary"])
    entry["functions"] = discover_module(img, entry["name"])
    entry["imports"] = img.imports()
    entry["delay_imports"] = delay_imports(img)
    entry["unresolved"] = unresolved_imports(entry, manifest["modules"])
    save_manifest(dest, manifest)
    log(f"{entry['name']}: {len(entry['functions'])} functions, "
        f"{len(entry['unresolved'])} unresolved import(s)")
    return entry


# --- the project ----------------------------------------------------------------------------

def create_application_project(dest: Path, name: str, *, log=print) -> dict:
    """An empty application project. Idempotent: an existing one is left alone."""
    if (dest / MANIFEST).exists():
        log(f"{dest} is already a project: add modules to it")
        return load_manifest(dest)
    for sub in ("binaries", "target", "build", "src", "asm", "include", "notes", "docs"):
        (dest / sub).mkdir(parents=True, exist_ok=True)
    (dest / "include/ghidra_types.h").write_text(GHIDRA_TYPES, encoding="utf-8")
    manifest = {"kind": "pe64-application", "name": name, "slug": slugify(name),
                "generated": time.time(), "toolchain": {"compiler": find_cl(), "optimisation": "/Od"},
                "modules": []}
    save_manifest(dest, manifest)
    write_objdiff_and_build(dest, manifest)
    (dest / ".gitignore").write_text(f".ninja_log\n.ninja_deps\n{STAGING}/\n", encoding="utf-8")
    log(f"created application project {dest.name}")
    return manifest


def add_module(dest: Path, binary: Path, *, name: str | None = None,
               drafts: dict[int, str] | None = None, cl: str | None = None,
               no_inline: bool = True, log=print, should_stop=None, build: bool = True,
               build_limit: int = 1500) -> dict:
    """Add one module to an application project, or refresh it if its content is already here.

    Nothing existing is removed. The module is analysed and written into a staging directory
    first; only when every file is in place are they moved in and the manifest updated. A
    failure leaves the project exactly as it was -- which matters because the alternative,
    regenerating the tree, would throw away the work done on the modules already in it.
    """
    if not (dest / MANIFEST).exists():
        create_application_project(dest, binary.stem, log=log)
    manifest = load_manifest(dest)
    data = binary.read_bytes()
    sha1 = hashlib.sha1(data).hexdigest()
    img = PEImage.load(binary)

    existing = next((m for m in manifest["modules"] if m["sha1"] == sha1), None)
    if existing is not None:
        log(f"{binary.name} is already module '{existing['name']}' (sha1 {sha1[:12]}): refreshing")
        return analyze_module(dest, existing["id"], log=log)

    taken = {m["name"] for m in manifest["modules"]}
    base = slugify(name or binary.stem)
    module_name, n = base, 2
    while module_name in taken:
        module_name, n = f"{base}{n}", n + 1
    module_id = sha1[:16]
    suffix = binary.suffix.lower() or (".dll" if img.is_dll else ".exe")
    stage = dest / STAGING / module_id

    # --- stage: everything for the new module, before the project is touched at all
    if stage.exists():
        shutil.rmtree(stage)
    for sub in ("target", "src", "asm"):
        (stage / sub).mkdir(parents=True, exist_ok=True)

    opt = "/Od" if no_inline else "/O2"
    funcs, unit_list = [], []
    for n, fn in enumerate(discover_module(img, module_name)):
        if should_stop and should_stop():
            shutil.rmtree(stage, ignore_errors=True)
            raise RuntimeError("stopped while building the module")
        if n and n % 500 == 0:
            log(f"{module_name}: {n} functions prepared")
        obj, relocs, tables, notes = table_aware_object(
            img, fn["rva"], fn["size"], fn["symbol"],
            next_rva=fn["end"] if fn["end"] > fn["rva"] else None)
        (stage / "target" / f"{fn['symbol']}.obj").write_bytes(obj)
        fn["relocations"] = [{"offset": r.offset, "type": r.type, "type_name": r.type_name,
                              "target_rva": r.target_rva} for r in relocs]
        fn["jump_tables"] = [t.rva for t in tables]
        fn["note"] = "; ".join(notes)
        draft = (drafts or {}).get(fn["rva"])
        (stage / "src" / f"{fn['symbol']}.c").write_text(
            _source_for(_Fn(fn), draft), encoding="utf-8")
        (stage / "asm" / f"{fn['symbol']}.s").write_text(
            _asm_listing(img, _Fn(fn)), encoding="utf-8")
        funcs.append(fn)
        unit_list.append({"name": fn["symbol"], "path": f"{module_name}/{fn['symbol']}.obj",
                      "metadata": {"source_path": f"src/{module_name}/{fn['symbol']}.c",
                                   "complete": False, "draft": "ghidra" if draft else "none",
                                   "module": module_name, "rva": f"{fn['rva']:#x}"}})

    # --- commit: move into place, then merge into the manifest
    (dest / "binaries").mkdir(exist_ok=True)
    shutil.copyfile(binary, dest / "binaries" / f"{module_name}{suffix}")
    for sub in ("target", "src", "asm"):
        (stage / sub).rename(dest / sub / module_name)
    shutil.rmtree(stage, ignore_errors=True)

    pdb = img.pdb()
    entry = {"id": module_id, "name": module_name, "binary": f"binaries/{module_name}{suffix}",
             "kind": "dll" if img.is_dll else "exe", "arch": img.machine_name,
             "image_base": f"{img.image_base:#x}", "entry_point": f"{img.entry_point:#x}",
             "sha1": sha1, "size": len(data),
             "linker": f"{img.linker_version[0]}.{img.linker_version[1]}",
             "imports": img.imports(), "delay_imports": delay_imports(img),
             "pdb": pdb[0] if pdb else None, "added": time.time(), "stripped": img.is_stripped,
             "counts": {"functions": len(funcs),
                        "with_jump_tables": sum(1 for f in funcs if f["jump_tables"]),
                        "with_relocations": sum(1 for f in funcs if f["relocations"])},
             "functions": funcs, "units": unit_list}
    entry["unresolved"] = unresolved_imports(entry, manifest["modules"] + [entry])
    manifest["modules"].append(entry)
    manifest.setdefault("toolchain", {})["compiler"] = cl or find_cl()
    manifest["toolchain"]["optimisation"] = opt
    for m in manifest["modules"]:          # a new module may resolve another's imports
        m["unresolved"] = unresolved_imports(m, manifest["modules"])
    save_manifest(dest, manifest)
    log(f"added {module_name} ({entry['kind']}, {len(funcs)} functions)")

    write_objdiff_and_build(dest, manifest)
    if build and len(funcs) > build_limit:
        # one object per unit means one cl.exe per unit: 30,000 of them is minutes of process
        # thrashing for a result nobody asked for. Everything else about the project is ready.
        log(f"{len(funcs)} functions is more than the {build_limit} this will compile in one go: "
            f"the targets, sources and listings are all here. Compile a unit when you want its diff.")
        build = False
    if build:
        run_build(dest, log=log)
    else:
        log("not compiling now")
    # stand-ins exist so objdiff can report on a project that IS being compiled. For one too
    # large to compile they are pure cost: tens of thousands of placeholder objects nobody asked
    # for, in a project whose whole point is that it was not built.
    seeded = seed_missing(dest, manifest) if build else []
    if seeded:
        log(f"seeded {len(seeded)} stand-in(s) for sources that do not build yet")
    write_readme(dest, manifest)
    write_inventory(dest, manifest)
    return entry


class _Fn:
    """The little view _source_for/_asm_listing want, over a dict."""

    def __init__(self, d: dict):
        self.symbol = d["symbol"]
        self.local = d["local"]
        self.rva = d["rva"]
        self.size = d["size"]
        self.discovered_by = d["discovered_by"]
        self.name = d["symbol"]


def rebuild_module(dest: Path, module_id: str, *, log=print) -> int:
    """Rebuild the sources. All units share one tree, so this is the project's build; what it
    never touches is another module's target objects, sources or scores."""
    manifest = load_manifest(dest)
    if module_of(dest, module_id) is None:
        raise KeyError(f"no module {module_id} in this project")
    n = run_build(dest, log=log)
    seed_missing(dest, manifest)
    return n


def write_objdiff_and_build(dest: Path, manifest: dict) -> None:
    units = all_units(manifest)
    (dest / "objdiff.json").write_text(json.dumps(
        {"target_dir": "target", "base_dir": "build", "custom_make": "ninja",
         "options": {"functionRelocDiffs": "none", "combineDataSections": True,
                     "combineTextSections": True}, "units": units}, indent=2) + "\n",
        encoding="utf-8")
    cl = manifest.get("toolchain", {}).get("compiler") or find_cl()
    opt = manifest.get("toolchain", {}).get("optimisation", "/Od")
    ninja = ["# Building reconstructed C with MSVC, driven from WSL through interop.",
             "# The path is quoted: it has spaces and parentheses.",
             f'cl = "{cl}"' if cl else "# cl was not found: set it before building",
             f"cflags = {opt} /GS- /c /nologo /Iinclude", "",
             "rule cc", "  command = $cl $cflags /Fo:$out $in", "  description = cl $in", ""]
    ordered = sorted(units, key=lambda u: u["name"])
    for u in ordered:
        ninja.append(f"build build/{u['path']}: cc {u['metadata']['source_path']}")
    ninja.append("")
    if ordered:
        ninja.append("default " + " ".join(f"build/{u['path']}" for u in ordered))
    (dest / "build.ninja").write_text("\n".join(ninja) + "\n", encoding="utf-8")


def seed_missing(dest: Path, manifest: dict) -> list[str]:
    """A stand-in for every unit whose source does not build, so the project always measures.
    objdiff's report needs a base object per unit, and one missing object takes the whole report
    down: an unwritten function should read as unfinished, not break the project."""
    filled = []
    for u in all_units(manifest):
        path = dest / "build" / u["path"]
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(build_object(u["name"], b"\xc3", []))
            filled.append(u["name"])
    return filled


# --- what the project says about itself -----------------------------------------------------

def write_readme(dest: Path, manifest: dict) -> None:
    mods = manifest["modules"]
    total = sum(len(m.get("functions", [])) for m in mods)
    lines = [f"# {manifest.get('name', dest.name)} (imported)", "",
             f"A Windows application imported from {len(mods)} module(s): no original object "
             "files, no symbols, no PDB.", "",
             "| module | kind | arch | functions | image base | sha1 |",
             "|---|---|---|---|---|---|"]
    for m in mods:
        lines.append(f"| `{m['name']}` | {m['kind']} | {m['arch']} | {len(m.get('functions', []))} | "
                     f"{m['image_base']} | `{m['sha1'][:12]}` |")
    lines += ["", f"{total} functions in total.", "",
              "## Working on a function", "",
              "Each function is a unit named `<module>_<symbol>`. `target/<module>/<unit>.obj` is a "
              "synthetic COFF object carved out of that module; `src/<module>/<unit>.c` is the C to "
              "write; `build.ninja` compiles it with MSVC and objdiff compares the two.", "",
              "    ninja -C .", "",
              "Modules keep separate inventories, objects, sources and scores; adding one never "
              "touches another.", ""]
    if any(m.get("unresolved") for m in mods):
        lines += ["## Imports not supplied", "",
                  "Imported by a module, but no module in the project provides them. Analysis does "
                  "not need them; the references stay unresolved until one is added.", ""]
        for m in mods:
            if m.get("unresolved"):
                lines.append(f"* `{m['name']}`: " + ", ".join(f"`{d}`" for d in m["unresolved"]))
        lines.append("")
    (dest / "README.md").write_text("\n".join(lines), encoding="utf-8")


def write_inventory(dest: Path, manifest: dict) -> None:
    lines = ["# Recovered functions", ""]
    for m in manifest["modules"]:
        fns = m.get("functions", [])
        by: dict[str, int] = {}
        for f in fns:
            by[f["discovered_by"]] = by.get(f["discovered_by"], 0) + 1
        lines += [f"## {m['name']} ({m['kind']}, {m['arch']}, {m['sha1'][:12]})", "",
                  f"{len(fns)} functions. By source: "
                  + ", ".join(f"{k} {v}" for k, v in sorted(by.items())),
                  "", "| function | rva | size | found by | relocs | jump table |",
                  "|---|---|---|---|---|---|"]
        for f in fns:
            lines.append(f"| `{f['symbol']}` | {f['rva']:#x} | {f['size']} | {f['discovered_by']} | "
                         f"{len(f['relocations'])} | "
                         f"{', '.join(hex(t) for t in f['jump_tables']) or '-'} |")
        lines.append("")
    (dest / "notes/functions.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def remap_calls(dest: Path, module: str, *, log=print) -> dict:
    """Give every remaining FUN_<addr> in a module's sources a real name.

    After _source_for, a draft that calls another function still refers to it as FUN_140001278.
    If that address is a function this module recovered, the call becomes that symbol -- which is
    how two functions in the same module end up calling each other by name. If it is not recovered
    (an import, or something discovery missed) it is declared `extern`, so the draft compiles and
    the address stays visible as exactly that.
    """
    entry = next((m for m in load_manifest(dest).get("modules", []) if m["name"] == module), None)
    if entry is None:
        raise ValueError(f"no module {module} in this project")
    base = int(entry["image_base"], 16)
    by_rva = {f["rva"]: f["symbol"] for f in entry.get("functions", [])}

    renamed = unresolved = 0
    for src in sorted((dest / "src" / module).glob("*.c")):
        text = src.read_text(encoding="utf-8")
        refs = sorted(set(re.findall(r"\bFUN_([0-9a-fA-F]{6,})\b", text)))
        if not refs:
            continue
        externs = []
        for hexaddr in refs:
            addr = int(hexaddr, 16)
            symbol = by_rva.get(addr - base if addr >= base else addr)
            if symbol:
                text = re.sub(rf"\bFUN_{hexaddr}\b", symbol, text)
                renamed += 1
            else:
                externs.append(f"extern void FUN_{hexaddr}(void);   /* not recovered */")
                unresolved += 1
        if externs:
            lines = text.splitlines()
            at = 1 if lines and lines[0].startswith("#include") else 0
            text = "\n".join(lines[:at] + externs + lines[at:]) + "\n"
        src.write_text(text, encoding="utf-8")
    log(f"{module}: {renamed} call reference(s) mapped to recovered symbols, "
        f"{unresolved} left as extern addresses")
    return {"renamed": renamed, "unresolved": unresolved}
