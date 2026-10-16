"""Referenced data and jump tables: recover what a linked image resolved, and give it back.

Some references in an x64 function do not look like references once the linker is done.

A RIP-relative operand is obvious -- `lea rcx, [rip+x]` -- and `coff.py` already rebuilds
those. A **jump table** is not. MSVC lowers a dense switch to

    lea     rcx, [rip + __ImageBase]        ; object: REL32 -> __ImageBase, whose value is 0
    mov     eax, [rcx + rax*4 + TABLE]      ; object: disp32 = 0 with ADDR32NB -> the table
    add     rax, rcx
    jmp     rax

with the table a run of `dd case_label` entries, each carrying an ADDR32NB relocation.
`IMAGE_REL_AMD64_ADDR32NB` means "RVA of the symbol", so the linker resolves a zeroed field
into an address and the result stops looking like a relocation at all: the `mov`'s
displacement becomes the table's RVA and each entry becomes the RVA of its case label.
The load is *not* RIP-relative -- it is indexed off a register -- so nothing in `coff.py`
can see it.

Three things had to be right, and each was measured against the MSVC object rather than
assumed. With only the first, `sw` sat at 60.85%; with all three it is 100.00%:

  1. **Where the table lives.** It stays in **.text**, not in a .rdata the object does not
     even have: ref.obj's sections are .drectve/.debug$S/.bss/.data/.text$mn/.xdata/.pdata/
     .chks64, and the bytes at `.text$mn + 0x220` are all zero. Moving the table into a new
     .rdata section was tried and made the score worse (16.7%), which is the measurement
     that pointed here.
  2. **Its representation.** Entries are zeroed with one ADDR32NB relocation each, at
     +0x70, +0x74 ... +0x8c in the object -- which is what this module reconstructs.
  3. **The function's extent.** The symbol runs to the *next* symbol, not to the end of
     .pdata's unwind region: 160 bytes, code (112) + table (32) + 16 bytes of `0xcc` padding.
     .pdata stops at 144, so a function made only of what .pdata describes is 16 bytes short
     and still does not compare (58.97% without the padding, 100.00% with it).

Not every indexed load off the image base is a table, so a target whose bytes are not a run
of plausible code addresses is left alone and reported in `notes` instead of guessed at.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import capstone

from .coff import (IMAGE_REL_AMD64_ADDR32NB, IMAGE_SYM_CLASS_EXTERNAL, Reloc, _md,
                   build_object, reconstruct_relocations)
from .image import PEImage

MAX_TABLE_ENTRIES = 4096      # a switch longer than this is not believed
PADDING_BYTE = 0xCC           # what MSVC pads the gap between functions with


@dataclass
class Table:
    """A jump table recovered from the image.

    `offset` is where it starts inside the function, which is where its entries have to be
    zeroed and relocated: the table does not move sections, it stays put in .text.
    """

    rva: int
    offset: int
    entries: list[int]

    @property
    def size(self) -> int:
        return 4 * len(self.entries)


@dataclass
class Recovered:
    """What a function refers to, and anything ambiguous that was left alone."""

    code_relocs: list[Reloc] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _in_code(img: PEImage, v: int) -> bool:
    sec = img.text_section()
    return sec is not None and sec.rva <= v < sec.rva + sec.loaded_size


def read_table(img: PEImage, rva: int) -> list[int]:
    """The RVA entries of a jump table starting at `rva`, or [] if it isn't one.

    Boundaries can only be decided by content, since nothing else is available: an entry
    has to be an address inside the executable section. Reading stops at the first 4 bytes
    that are not -- padding, the next function's data, or an unrelated table. This can cut
    a table short (if its first entry somehow isn't a code address) and can run on past a
    table if the following bytes happen to look like code addresses. It does not invent
    entries out of padding, which is the failure that would actually corrupt a match.
    """
    entries: list[int] = []
    off = img.rva_to_offset(rva)
    while off is not None and len(entries) < MAX_TABLE_ENTRIES and off + 4 <= len(img.data):
        v, = struct.unpack_from("<I", img.data, off)
        if v == 0 or not _in_code(img, v):
            break
        entries.append(v)
        off += 4
    return entries


def find_referenced_data(code: bytes, base_rva: int, img: PEImage, *,
                         size: int | None = None) -> Recovered:
    """Every switch table a function indexes, and the data each entry points at.

    Only the shape MSVC actually emits is understood, and only when it is unambiguous.
    """
    out = Recovered()
    image_base_regs: set[int] = set()
    seen: set[int] = set()

    md = _md()
    for ins in md.disasm(code, base_rva):
        off = ins.address - base_rva
        if off < 0 or off + ins.size > len(code):
            break
        if ins.id == 0:                      # a skipped data byte in SKIPDATA mode
            continue

        # `lea REG, [rip+x]` landing on rva 0 is MSVC's __ImageBase
        if ins.mnemonic == "lea" and len(ins.operands) > 1:
            dst, src = ins.operands[0], ins.operands[1]
            if (dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM
                    and src.mem.base == capstone.x86.X86_REG_RIP):
                if ins.address + ins.size + ins.disp == 0:
                    image_base_regs.add(dst.reg)
                    continue

        # `[base + index*4 + disp]` with the base = the image base: a table index
        for op in ins.operands:
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            if op.mem.base not in image_base_regs or op.mem.index == 0 or op.mem.scale != 4:
                continue
            table_rva = op.mem.disp
            field = ins.disp_offset
            if not table_rva or field is None or field < 0 or field + 4 > ins.size:
                continue
            if off + field + 4 > len(code):
                continue
            if img.rva_to_offset(table_rva) is None:
                out.notes.append(f"+{off:#x}: indexes off the image base at rva {table_rva:#x}, "
                                 f"which is not mapped: left alone")
                continue
            entries = read_table(img, table_rva)
            if not entries:
                out.notes.append(f"+{off:#x}: indexes off the image base at rva {table_rva:#x}, "
                                 f"but the bytes there are not a run of code addresses: not "
                                 f"treated as a table")
                continue
            out.code_relocs.append(Reloc(off + field, IMAGE_REL_AMD64_ADDR32NB, table_rva))
            if table_rva not in seen:
                seen.add(table_rva)
                out.tables.append(Table(rva=table_rva, offset=table_rva - base_rva, entries=entries))

    out.code_relocs.sort(key=lambda r: r.offset)
    out.tables.sort(key=lambda t: t.offset)
    return out


def table_aware_object(img: PEImage, rva: int, size: int, name: str, *,
                       next_rva: int | None = None):
    """(object, relocations, tables, notes) for one function, jump tables included.

    `size` is the region the image attributes to the function. That is what .pdata gives,
    and it is not the same as the symbol's extent: .pdata stops at the end of the code plus
    any table, while the object's symbol runs to the next symbol. `next_rva` supplies the
    next function's address so the .text can be padded out to the same extent, which is what
    makes the last of the three corrections above -- 16 bytes of 0xcc -- let it match.
    """
    code = img.bytes_at(rva, size) or b""
    relocs = reconstruct_relocations(code, rva, size=size)
    rec = find_referenced_data(code, rva, img, size=size)

    taken = {r.offset for r in relocs}      # a field is never relocated twice
    relocs += [r for r in rec.code_relocs if r.offset not in taken]
    for t in rec.tables:
        # the entries are relocated in place; build_object zeroes every field a relocation
        # covers, which is exactly the object's form (the bytes there are all zero)
        relocs += [Reloc(t.offset + 4 * i, IMAGE_REL_AMD64_ADDR32NB, e)
                   for i, e in enumerate(t.entries)]
    relocs.sort(key=lambda r: r.offset)

    pad_to = (next_rva - rva) if next_rva else 0
    if pad_to > len(code):
        code = code + bytes([PADDING_BYTE]) * (pad_to - len(code))
    return build_object(name, code, relocs), relocs, rec.tables, rec.notes
