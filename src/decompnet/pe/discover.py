"""Finding the functions in a linked x64 image.

An executable has no symbol table once it ships, so the boundaries have to be
recovered. Three sources, in decreasing order of trust:

1. **.pdata** (the exception directory). The first instinct -- "one RUNTIME_FUNCTION
   per function" -- is wrong, and measurably so. A record describes an *unwind region*:
   a function can have several (chained unwind info), and a function with no frame and
   no call (a leaf) has none at all. On the two lab builds this reported 9 of 15
   functions (/Od, 6 missing) and 4 of 6 (/O2, where one function had 3 records).
   Records that do exist are *exact*: BeginAddress is the entry and EndAddress is the
   true end of the code with no alignment padding -- map-derived sizes overstate.

2. **Direct call targets.** Every `call rel32` whose destination lands inside the
   executable section is a function entry (or a local label). This finds leaf functions
   .pdata misses -- but only ones something calls, and only if the call site is reached
   by linear disassembly (indirect calls and jump tables hide them).

3. **A linear sweep of what is left.** Decode the gaps in address order; after a
   terminator plus padding, if the next bytes look like a prologue, call that a start.
   This is the weakest source and the one that invents things: padding, jump tables and
   embedded data all look like something. Everything it returns is marked `"sweep"` so a
   caller can treat it with suspicion, and it never overrides 1 or 2.

Nothing here claims the result is complete or correct: `discover()` carries provenance
with every entry, so the accuracy of each source can be measured rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass

import capstone

from .image import PEImage

_CS_MODE = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# x64 prologues MSVC emits. A byte test, deliberately short and boring: this only decides
# whether a *candidate* is worth keeping, it never places a function on its own.
PROLOGUES = (
    b"\x48\x83\xec",        # sub rsp, imm8
    b"\x48\x81\xec",        # sub rsp, imm32
    b"\x48\x89\x5c\x24",    # mov [rsp+x], rbx     (the classic /Od save)
    b"\x48\x89\x4c\x24",    # mov [rsp+x], rcx
    b"\x48\x89\x54\x24",    # mov [rsp+x], rdx
    b"\x48\x89\x74\x24",    # mov [rsp+x], rsi
    b"\x48\x89\x7c\x24",    # mov [rsp+x], rdi
    b"\x4c\x89\x44\x24",    # mov [rsp+x], r8
    b"\x4c\x89\x4c\x24",    # mov [rsp+x], r9
    b"\x4c\x89\x5c\x24",    # mov [rsp+x], r11
    # the 32-bit-register forms: MSVC's /Od prologue saves the incoming arguments with
    # `89 4c 24 08` (mov [rsp+8], ecx), not the REX.W form. Without these the sweep found
    # neither the first function in a gap nor the one after it.
    b"\x89\x4c\x24", b"\x89\x54\x24", b"\x89\x5c\x24", b"\x89\x74\x24", b"\x89\x7c\x24",
    b"\x44\x89\x44\x24", b"\x44\x89\x4c\x24",
    b"\x40\x53", b"\x40\x55", b"\x40\x56", b"\x40\x57",   # push rbx/rbp/rsi/rdi
    b"\x53", b"\x55", b"\x56", b"\x57",
    b"\x41\x54", b"\x41\x55", b"\x41\x56", b"\x41\x57",   # push r12-r15
    b"\xf3\x0f\x1e\xfa",    # endbr64
    b"\x48\x8b\xc4",        # mov rax, rsp  (some frame setups)
    b"\x48\x83\xe4",        # and rsp, -16  (alloca-style frame)
)

PADDING = {0xCC, 0x00, 0x90}                 # what a linker pads between functions with
TERMINATORS = {"ret", "retf", "jmp", "int3", "ud2", "hlt"}


@dataclass(frozen=True)
class Found:
    """One recovered region. `source` says which method produced it."""

    rva: int
    size: int
    source: str  # "pdata" | "call" | "sweep"

    @property
    def end(self) -> int:
        return self.rva + self.size


def _md() -> capstone.Cs:
    md = capstone.Cs(*_CS_MODE)
    md.detail = True
    # skipdata: without it disasm() STOPS at the first byte it can't decode, and since a
    # linked .text always contains padding, jump tables and literal pools, a linear sweep
    # silently ends early and everything past that point is invisible. Measured on the /Od
    # fixture: it died at 0x1219 and found 0 of the 8 call targets; with skipdata it finds
    # them all. (decompnet.scoring sets this too.)
    md.skipdata = True
    return md


def _looks_like_prologue(code: bytes, at: int) -> bool:
    window = code[at:at + 4]
    return any(window[:len(p)] == p for p in PROLOGUES)


def _is_padding(code: bytes, at: int, count: int = 2) -> bool:
    return at >= 0 and at + count <= len(code) and all(b in PADDING for b in code[at:at + count])


def call_targets(img: PEImage, base: int | None = None) -> set[int]:
    """RVAs inside the executable section that some `call rel32` in it targets.

    Found by linear disassembly, so a call sitting inside a jump table or a data blob can
    contribute a bogus target: this is a candidate set, not a verdict.
    """
    code = img.code_bytes()
    if base is None:
        base = img.code_rva_base()
    lo, hi = base, base + len(code)
    out: set[int] = set()
    for ins in _md().disasm(code, base):
        if ins.mnemonic == "call" and ins.operands:
            op = ins.operands[0]
            if op.type == capstone.x86.X86_OP_IMM and lo <= op.imm < hi:
                out.add(op.imm)
    return out


def unwind_regions(img: PEImage) -> list[Found]:
    """The .pdata records, named for what they are.

    Adjacent or overlapping records that describe one function (chained unwind info) are
    merged, since a caller almost always wants the function rather than the regions.
    Merging is deliberately conservative: it only joins records that actually touch.
    """
    merged: list[Found] = []
    for r in img.runtime_functions():
        if merged and r.begin <= merged[-1].end:
            prev = merged[-1]
            merged[-1] = Found(prev.rva, max(prev.end, r.end) - prev.rva, "pdata")
        else:
            merged.append(Found(r.begin, r.size, "pdata"))
    return merged


def sweep_gap(lo: int, hi: int, base: int, code: bytes) -> list[int]:
    """Candidate function starts in [lo, hi), by decoding in order.

    A candidate is kept only at a *boundary*: the start of the gap, or the byte just past
    a terminator plus a run of padding -- and only if it looks like a prologue.
    """
    md = _md()
    starts: list[int] = []
    offset, end_off = lo - base, hi - base
    boundary = True
    while offset < end_off:
        if boundary and _looks_like_prologue(code, offset):
            starts.append(base + offset)
        ins = next(md.disasm(code[offset:end_off], base + offset, count=1), None)
        if ins is None:                      # undecodable byte: step over it, not a boundary
            offset += 1
            boundary = False
            continue
        if ins.mnemonic in TERMINATORS:
            j = offset + ins.size
            while j < end_off and code[j] in PADDING:
                j += 1
            if j >= end_off:
                break
            offset, boundary = j, True
            continue
        offset += ins.size
        boundary = False
    return sorted(set(starts))


def discover(img: PEImage, *, use_sweep: bool = True) -> list[Found]:
    """Everything we can justify finding, sorted by address, each with its provenance.

    .pdata first (exact where it speaks), then call targets, then a sweep of only the
    ranges neither of those covered.
    """
    base = img.code_rva_base()
    code = img.code_bytes()
    if not code:
        return []
    text_hi = base + len(code)

    found: dict[int, Found] = {}
    for f in unwind_regions(img):
        found[f.rva] = f

    for target in call_targets(img, base):
        found.setdefault(target, Found(target, 0, "call"))  # size filled in later

    if use_sweep:
        cursor = base
        for f in sorted(found.values(), key=lambda x: x.rva):
            if f.rva > cursor:                              # a hole before this one
                for s in sweep_gap(cursor, f.rva, base, code):
                    found.setdefault(s, Found(s, 0, "sweep"))
            cursor = max(cursor, f.end)
        if cursor < text_hi:                                # a hole after the last one
            for s in sweep_gap(cursor, text_hi, base, code):
                found.setdefault(s, Found(s, 0, "sweep"))

    starts = sorted(found)
    out: list[Found] = []
    for i, rva in enumerate(starts):
        f = found[rva]
        if f.size:
            out.append(f)                                   # .pdata gave an exact size
        else:
            nxt = starts[i + 1] if i + 1 < len(starts) else text_hi
            out.append(Found(rva, max(1, nxt - rva), f.source))
    return out
