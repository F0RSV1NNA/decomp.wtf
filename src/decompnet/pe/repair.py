"""Deterministic repair of a Ghidra draft that does not compile.

The rules here exist because of what MSVC actually said about setupcl.exe's drafts -- each one is
keyed to a diagnostic and the line it points at, not to a guess about Ghidra.

    C2065 'code': undeclared identifier          Ghidra's `code` type had no spelling in our
                                                 header: it is a function pointer, and the
                                                 standard mapping is `typedef void code(void);`.
                                                 That was a bug in the shim, not in the draft.
    C2065 'DWORD64' / 'PRUNTIME_FUNCTION'        the draft calls the Windows API, so it needs the
                                                 SDK's types. Supplied in windows_types.h.
    C2065 'DAT_140003000': undeclared            the draft reads and writes a global it never
                                                 declares. Declared `extern`, once, with the
                                                 width taken from the name.
    C2065 'NtQuerySystemTime': undeclared        an imported function with no prototype. Declared
                                                 `extern`, with the return type taken from how the
                                                 call is used in the draft.

What is *not* here, on purpose: `C2059 syntax error` (Ghidra emitted something malformed and only
a reader can say what it meant), `C2186 '=': an operand cannot have type 'void'` (the draft
assigns from a call that returns nothing -- the correct fix depends on what the function really
returns), and `C2064 term does not evaluate to a function` (something was called that is not a
function). Guessing at those would invent behaviour, so they are reported and left for an agent.

Every change is recorded with what it is and why, the original draft is kept, and nothing is
marked as repaired unless the compiler accepts it afterwards. A repaired file is a *candidate*:
whether it matches is objdiff's answer, not ours.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .project import find_cl

# Ghidra's decompiler types, as MSVC needs to see them. `code` is the one that was missing: it is
# how Ghidra names an indirect call, and `typedef void code(void);` makes `code *f` a function
# pointer, which is what the drafts then call.
GHIDRA_BUILTINS = {
    "code": "typedef void code(void);",
    "undefined": "typedef unsigned char undefined;",
    "undefined1": "typedef unsigned char undefined1;",
    "undefined2": "typedef unsigned short undefined2;",
    "undefined4": "typedef unsigned int undefined4;",
    "undefined8": "typedef unsigned long long undefined8;",
    "code_ptr": "typedef void *code_ptr;",
    "wchar_t": "typedef unsigned short wchar_t;",
    "wchar16": "typedef unsigned short wchar16;",
    "sbyte": "typedef signed char sbyte;",
    "byte": "typedef unsigned char byte;",
    "ushort": "typedef unsigned short ushort;",
    "uint": "typedef unsigned int uint;",
    "ulong": "typedef unsigned long ulong;",
    "longlong": "typedef long long longlong;",
    "ulonglong": "typedef unsigned long long ulonglong;",
}

# Windows types a draft reaches for by name, and what they actually are. Standard SDK spellings,
# not inventions: DWORD64 is `unsigned long long` on x64 and PRUNTIME_FUNCTION is a pointer to the
# three-field record in the x64 exception data.
WINDOWS_TYPES = {
    "DWORD64": "typedef unsigned long long DWORD64;",
    "DWORD32": "typedef unsigned int DWORD32;",
    "DWORD": "typedef unsigned long DWORD;",
    "WORD": "typedef unsigned short WORD;",
    "BYTE": "typedef unsigned char BYTE;",
    "BOOL": "typedef int BOOL;",
    "BOOLEAN": "typedef unsigned char BOOLEAN;",
    "UINT": "typedef unsigned int UINT;",
    "INT": "typedef int INT;",
    "ULONG": "typedef unsigned long ULONG;",
    "LONG": "typedef long LONG;",
    "ULONG_PTR": "typedef unsigned long long ULONG_PTR;",
    "LONG_PTR": "typedef long long LONG_PTR;",
    "SIZE_T": "typedef unsigned long long SIZE_T;",
    "NTSTATUS": "typedef long NTSTATUS;",
    "PVOID": "typedef void *PVOID;",
    "LPVOID": "typedef void *LPVOID;",
    "HANDLE": "typedef void *HANDLE;",
    "HMODULE": "typedef void *HMODULE;",
    "FARPROC": "typedef long long (*FARPROC)(void);",
    "PSTR": "typedef char *PSTR;",
    "PWSTR": "typedef unsigned short *PWSTR;",
    "PCWSTR": "typedef const unsigned short *PCWSTR;",
    "PUNICODE_STRING": "typedef void *PUNICODE_STRING;",
    "PCONTEXT": "typedef void *PCONTEXT;",
    "PEXCEPTION_RECORD": "typedef void *PEXCEPTION_RECORD;",
    "LARGE_INTEGER": "typedef union { long long QuadPart; } LARGE_INTEGER;",
    "RUNTIME_FUNCTION": ("typedef struct { DWORD BeginAddress; DWORD EndAddress; DWORD UnwindData; } "
                         "RUNTIME_FUNCTION;"),
    "PRUNTIME_FUNCTION": "typedef RUNTIME_FUNCTION *PRUNTIME_FUNCTION;",
    "PUNWIND_HISTORY_TABLE": "typedef void *PUNWIND_HISTORY_TABLE;",
    "EXCEPTION_POINTERS": ("typedef struct { void *ExceptionRecord; void *ContextRecord; } "
                           "EXCEPTION_POINTERS;"),
    # globals the drafts read by name instead of through a call
    "ProcessEnvironmentBlock": "extern void *ProcessEnvironmentBlock;",
    "NtCurrentTeb": "extern void *NtCurrentTeb(void);",
    "_StackCookie": "extern unsigned long long _StackCookie;",
    "__security_cookie": "extern unsigned long long __security_cookie;",
}

# width from the name, for a global the draft never declared. DAT_ is Ghidra's default for
# untyped data and 8 bytes is its usual assumption; the narrower prefixes say what they are.
DATA_NAMES = [
    (re.compile(r"^_?DAT_[0-9a-fA-F]+$"), 8),
    (re.compile(r"^qword_[0-9a-fA-F]+$"), 8),
    (re.compile(r"^dword_[0-9a-fA-F]+$"), 4),
    (re.compile(r"^word_[0-9a-fA-F]+$"), 2),
    (re.compile(r"^byte_[0-9a-fA-F]+$"), 1),
    (re.compile(r"^UNK_[0-9a-fA-F]+$"), 8),
]
WIDTH_C_TYPE = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}

DIAG = re.compile(r"^\s*(.+?)\((\d+)\)\s*:\s*(?:fatal\s+)?error\s+(\w+)\s*:\s*(.*)$")
UNDECLARED = re.compile(r"error C2065:\s*'([^']+)'\s*:\s*undeclared identifier")
CALLS = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

MAX_PASSES = 4


@dataclass
class Repair:
    rule: str
    symbol: str
    change: str
    why: str
    assumed: bool = False


@dataclass
class Outcome:
    symbol: str
    before: str = "failed"
    after: str = "failed"
    repairs: list[Repair] = field(default_factory=list)
    deferred: list[str] = field(default_factory=list)


def compile_one(project: Path, source: Path, cl: str | None = None) -> tuple[bool, str]:
    """Compile one source the way the project's build.ninja does. Returns (ok, output)."""
    cl = cl or find_cl()
    if not cl:
        return False, "no compiler"
    rel = source.relative_to(project)
    res = subprocess.run([cl, "/c", "/Od", "/GS-", "/nologo", "/Iinclude",
                          f"/Fo:{Path('/tmp') / (source.stem + '.obj')}", str(rel)],
                         cwd=str(project), capture_output=True, text=True, timeout=300)
    return res.returncode == 0, res.stdout + res.stderr


def diagnostics(output: str) -> list[tuple[str, int, str, str]]:
    """(file, line, code, message) for every error the compiler reported."""
    out = []
    for line in output.splitlines():
        m = DIAG.match(line.strip())
        if m:
            out.append((m.group(1), int(m.group(2)), m.group(3).upper(), m.group(4).strip()))
    return out


def _used_as_value(text: str, line_no: int, name: str) -> bool:
    """Whether a call's result is used, i.e. whether it needs a return type other than void."""
    lines = text.splitlines()
    if not (1 <= line_no <= len(lines)):
        return False
    stripped = lines[line_no - 1].strip()
    call = re.search(rf"\b{re.escape(name)}\s*\(", stripped)
    if not call:
        return False
    before = stripped[:call.start()].strip()
    after = stripped[call.end():].strip()
    # `x = Name(...)`, `return Name(...)`, `if (Name(...))`: the value is read
    if before.endswith("=") or before.endswith("return") or before.endswith("("):
        return not after.startswith(";")
    return bool(after) and not after.startswith(";")


def plan(text: str, diags: list[tuple[str, int, str, str]]) -> tuple[dict, list[Repair], list[str]]:
    """What to change, from the diagnostics alone. Nothing is applied here."""
    builtins, windows, data, protos = {}, {}, {}, {}
    repairs: list[Repair] = []
    deferred: list[str] = []

    for _file, line_no, code, message in diags:
        m = UNDECLARED.search(f"error {code}: {message}")
        if not m:
            if code in ("C2059", "C2186", "C2064", "C2440", "C2106"):
                note = f"{code} line {line_no}: {message[:70]}"
                if note not in deferred:
                    deferred.append(note)
            continue
        name = m.group(1)
        if name in GHIDRA_BUILTINS:
            builtins[name] = GHIDRA_BUILTINS[name]
            repairs.append(Repair("builtin type", name, f"added `{GHIDRA_BUILTINS[name]}`",
                                  "Ghidra's decompiler type, missing from the shim header"))
            continue
        if name in WINDOWS_TYPES:
            windows[name] = WINDOWS_TYPES[name]
            repairs.append(Repair("windows type", name, f"added `{WINDOWS_TYPES[name]}`",
                                  "the SDK type the draft references by name"))
            continue
        width = next((w for rx, w in DATA_NAMES if rx.match(name)), None)
        if width is not None:
            ctype = WIDTH_C_TYPE[width]
            data[name] = f"extern {ctype} {name};"
            repairs.append(Repair("global", name, f"declared `extern {ctype} {name};`",
                                  f"referenced but never declared; width {width} byte(s) taken "
                                  f"from the name", assumed=width == 8 and name.startswith("DAT_")))
            continue
        if re.search(rf"\b{re.escape(name)}\s*\(", text):
            used = _used_as_value(text, line_no, name)
            proto = f"extern {'long long' if used else 'void'} {name}();"
            protos[name] = proto
            repairs.append(Repair("prototype", name, f"declared `{proto}`",
                                  "called but never declared; return type "
                                  + ("read at the call site" if used else "not used at the call site"),
                                  assumed=True))
            continue
        note = f"C2065 {name} (line {line_no}): no rule applies"
        if note not in deferred:
            deferred.append(note)
    return {"builtins": builtins, "windows": windows, "data": data, "protos": protos}, repairs, deferred


def apply_to(file: Path, header: Path, text: str, items: dict) -> str:
    """Insert the declarations at the top of the file, after its includes."""
    adds = []
    if items["builtins"] or items["windows"]:
        adds.append("/* Types this draft uses that the shim did not define. */")
        adds.extend(sorted(items["builtins"].values()))
        adds.extend(sorted(items["windows"].values()))
    if items["data"]:
        adds.append("/* Globals the draft references. Declared, not defined: they live in the "
                    "image. */")
        adds.extend(sorted(items["data"].values()))
    if items["protos"]:
        adds.append("/* Imports the draft calls. Declared, not defined. */")
        adds.extend(sorted(items["protos"].values()))
    if not adds:
        return text

    lines = text.splitlines()
    at = 0
    for i, line in enumerate(lines):
        if line.startswith("#include"):
            at = i + 1
    block = adds + [""]
    return "\n".join(lines[:at] + block + lines[at:]) + "\n"


def _fingerprint(text: str) -> str:
    import hashlib

    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def automated(text: str) -> bool:
    """Whether this source is still one we generated, rather than something a person wrote.

    Repair must never silently overwrite hand-written work, and "did a human touch this" cannot be
    answered by inspecting the C. So the generator records a fingerprint of what it wrote, and a
    file whose contents no longer match that fingerprint is treated as someone's -- it is kept, and
    the repair declines with a reason instead of guessing.
    """
    head = text.split("\n")[:1]
    return bool(head) and ("ghidra_types.h" in head[0] or "no draft was available" in text.lower())


def repair_function(project: Path, module: str, symbol: str, *, cl: str | None = None,
                    log=print, force: bool = False) -> Outcome:
    """Repair one draft, bounded, keeping the original and recording every change."""
    src_dir = project / "src" / module
    source = src_dir / f"{symbol}.c"
    keep_dir = src_dir / ".drafts"
    keep_dir.mkdir(parents=True, exist_ok=True)
    original = keep_dir / f"{symbol}.c"

    out = Outcome(symbol=symbol)
    if not source.exists():
        out.deferred.append("no source file")
        return out
    current = source.read_text(encoding="utf-8")
    stamp = keep_dir / f"{symbol}.sha1"
    known = stamp.read_text(encoding="utf-8").strip() if stamp.exists() else ""
    if not force and known and _fingerprint(current) != known:
        out.deferred.append("edited by hand since we wrote it: left untouched (pass force=True "
                            "to repair anyway)")
        log(f"  {symbol}: skipped, the source was edited by hand")
        return out

    if not original.exists():
        shutil.copyfile(source, original)          # the draft as Ghidra produced it
    stamp.write_text(_fingerprint(current), encoding="utf-8")

    ok, output = compile_one(project, source, cl)
    if ok:
        out.after = "compiled"
        return out
    out.before = "failed"

    header = project / "include/ghidra_types.h"
    for _pass in range(MAX_PASSES):
        diags = diagnostics(output)
        if not diags:
            break
        items, repairs, deferred = plan(source.read_text(encoding="utf-8"), diags)
        if not any(items.values()):
            out.deferred.extend(d for d in deferred if d not in out.deferred)
            break
        text = apply_to(source, header, source.read_text(encoding="utf-8"), items)
        source.write_text(text, encoding="utf-8")
        stamp.write_text(_fingerprint(text), encoding="utf-8")
        for r in repairs:
            if not any(x.rule == r.rule and x.change == r.change for x in out.repairs):
                out.repairs.append(r)
        ok, output = compile_one(project, source, cl)
        if ok:
            out.after = "compiled"
            break
    else:
        out.deferred.append(f"still failing after {MAX_PASSES} passes")

    if not ok:
        out.deferred.insert(0, "the compiler reported "
                               f"{len(diagnostics(output))} error(s); the first is "
                               "usually the only real one and the rest are its cascade")
        out.deferred.extend(d for d in
                            [f"{c} line {ln}: {msg[:60]}" for _f, ln, c, msg in diagnostics(output)]
                            if d not in out.deferred)
    return out


def repair_module(project: Path, module: str, *, limit: int = 0, log=print) -> dict:
    """Repair every draft in a module that does not compile, and report exactly what happened."""
    from . import service as pe

    rows = [r for r in pe.function_status(project, None, "") if r["module"] == module]
    failing = [r for r in rows if r["status"] == "failed"]
    if limit:
        failing = failing[:limit]
    log(f"{module}: {len(rows)} functions, {len(failing)} draft(s) do not compile")

    outcomes = []
    for r in failing:
        o = repair_function(project, module, r["symbol"], log=log)
        outcomes.append(o)
        log(f"  {o.symbol:<28} {o.before} -> {o.after}"
            + (f"  ({len(o.repairs)} repair(s))" if o.repairs else "")
            + (f"  deferred: {len(o.deferred)}" if o.deferred else ""))

    path = project / "notes" / "repairs.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8")).get("functions", [])
        except ValueError:
            existing = []
    by_symbol = {e["symbol"]: e for e in existing}
    for o in outcomes:
        by_symbol[o.symbol] = {**asdict(o), "at": time.time()}
    path.write_text(json.dumps({"module": module, "passes": MAX_PASSES,
                                "functions": sorted(by_symbol.values(), key=lambda e: e["symbol"])},
                               indent=2) + "\n", encoding="utf-8")

    fixed = sum(1 for o in outcomes if o.after == "compiled")
    log(f"repaired {fixed} of {len(outcomes)}; the rest are recorded and left for an agent")
    return {"module": module, "attempted": len(outcomes), "repaired": fixed,
            "outcomes": [asdict(o) for o in outcomes]}
