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

Recovering it needs three things:
  * recognise the register holding the image base, so the `mov` reads as an indexed load
    off it rather than an ordinary load with a large displacement;
  * put the ADDR32NB relocation back on the displacement and zero the field;
  * carry the referenced bytes into a second section, with a relocation per entry.

Not every indexed load off the image base is a table, so the two are kept apart: if the
bytes at the target are not a run of plausible code addresses it is left alone and reported
in `notes` as ambiguous, rather than guessed at.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import capstone

from .coff import (IMAGE_REL_AMD64_ADDR32NB, IMAGE_SYM_CLASS_EXTERNAL,
                   IMAGE_SYM_DTYPE_FUNCTION, Reloc, _md, _mask, _name)
from .image import PEImage

IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_ALIGN_16BYTES = 0x00500000
RDATA_CHARACTERISTICS = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_16BYTES

MAX_TABLE_ENTRIES = 4096   # a switch longer than this is not believed


@dataclass
class Blob:
    """Bytes recovered from the image that a function refers to, to be re-emitted."""

    name: str
    rva: int
    data: bytes
    relocs: list[Reloc] = field(default_factory=list)   # offsets are within `data`

    def __len__(self) -> int:
        return len(self.data)


@dataclass
class Recovered:
    """What a function refers to, and anything ambiguous that was left alone."""

    code_relocs: list[Reloc] = field(default_factory=list)
    blobs: list[Blob] = field(default_factory=list)
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
    """Every switch table a function indexes, and the bytes of each.

    Only the shape MSVC actually emits is understood, and only when it is unambiguous.
    """
    end = base_rva + (size if size is not None else len(code))
    out = Recovered()
    image_base_regs: set[int] = set()
    seen: dict[int, Blob] = {}

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
                                 f"but the bytes there are not a run of code addresses: not treated "
                                 f"as a table")
                continue
            out.code_relocs.append(Reloc(off + field, IMAGE_REL_AMD64_ADDR32NB, table_rva))
            if table_rva not in seen:
                # the object's entries are zeroed with a relocation each; recover that shape
                blob = Blob(name=f"table_{table_rva:X}", rva=table_rva,
                            data=b"\0" * (4 * len(entries)),
                            relocs=[Reloc(4 * i, IMAGE_REL_AMD64_ADDR32NB, v)
                                    for i, v in enumerate(entries)])
                seen[table_rva] = blob
                out.blobs.append(blob)

    del end  # size is only used to bound the scan above
    out.code_relocs.sort(key=lambda r: r.offset)
    out.blobs.sort(key=lambda b: b.rva)
    return out


def build_with_data(function_name: str, code: bytes, relocs: list[Reloc], blobs: list[Blob], *,
                    target_name=lambda rva: f"sub_{rva:X}") -> bytes:
    """A COFF object with the function in .text and the data it refers to in .rdata.

    Symbols: the function, then one defined symbol per blob, then one undefined symbol per
    address neither of those defines. Relocations to a blob point at the blob symbol, which
    is what a compiler emits for a table it defines itself.
    """
    code = bytes(_mask(bytearray(code), relocs))

    strings = bytearray()

    def name_field(nm: str) -> bytes:
        f, extra = _name(nm)
        if f is not None:
            return f
        o = len(strings) + 4
        strings.extend(extra)
        return b"\0\0\0\0" + struct.pack("<I", o)

    # .rdata contents, and where each blob sits in it
    rdata = bytearray()
    blob_offset: dict[int, int] = {}
    for b in blobs:
        blob_offset[b.rva] = len(rdata)
        rdata.extend(b.data)

    syms: list[tuple[bytes, int, int, int, int]] = []      # name, value, section, type, storage
    syms.append((name_field(function_name), 0, 1, IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_CLASS_EXTERNAL))
    blob_sym: dict[int, int] = {}
    for b in blobs:
        blob_sym[b.rva] = len(syms)
        syms.append((name_field(b.name), blob_offset[b.rva], 2, 0, IMAGE_SYM_CLASS_EXTERNAL))

    undef: dict[int, int] = {}

    def sym_for(rva: int) -> int:
        """The blob symbol if we define that address, else an undefined one."""
        if rva in blob_sym:
            return blob_sym[rva]
        if rva not in undef:
            undef[rva] = len(syms)
            syms.append((name_field(target_name(rva)), 0, 0, 0, IMAGE_SYM_CLASS_EXTERNAL))
        return undef[rva]

    text_records = b"".join(struct.pack("<IIH", r.offset, sym_for(r.target_rva), r.type)
                            for r in relocs)
    rdata_records = bytearray()
    for b in blobs:
        base = blob_offset[b.rva]
        for r in b.relocs:
            rdata_records.extend(
                struct.pack("<IIH", base + r.offset, sym_for(r.target_rva), r.type))

    n_sections = 2 if blobs else 1
    raw_off = 20 + 40 * n_sections
    text_off = raw_off
    rdata_off = text_off + len(code)
    text_rel_off = rdata_off + len(rdata)
    rdata_rel_off = text_rel_off + len(text_records)
    sym_off = rdata_rel_off + len(rdata_records)

    out = [struct.pack("<HHIIIHH", 0x8664, n_sections, 0, sym_off, len(syms), 0, 0)]
    out.append(b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0, 0, len(code), text_off,
                                            text_rel_off if relocs else 0, 0, len(relocs), 0,
                                            0x60500020))
    if blobs:
        out.append(b".rdata\0\0" + struct.pack("<IIIIIIHHI", 0, 0, len(rdata), rdata_off,
                                               rdata_rel_off if rdata_records else 0, 0,
                                               len(rdata_records), 0, RDATA_CHARACTERISTICS))
    out.append(code)
    out.append(bytes(rdata))
    out.append(text_records)
    out.append(bytes(rdata_records))
    out.append(b"".join(n8 + struct.pack("<IhHBB", v, secn, t, st, 0)
                        for n8, v, secn, t, st in syms))
    out.append(struct.pack("<I", 4 + len(strings)) + bytes(strings))
    return b"".join(out)


def function_object_with_data(img: PEImage, rva: int, size: int, name: str) -> tuple[bytes, list[Reloc], list[Blob], list[str]]:
    """(object, code relocations, data blobs, notes) for one function of an image.

    `size` is the whole region the image attributes to the function, which is what .pdata
    gives: its EndAddress covers trailing *data* too, not just code.

    Cutting the code back at the table was tried and made things worse (60.8% -> 16.7%), so
    the code is passed through whole and the table is copied out as well. Leaving the table
    in .text does not cost a match on its own -- coff.py's 13 functions match with their
    bytes passed through unchanged -- and what is still not matching here is not yet
    understood. See the notes in tests/test_pe_tables.py.
    """
    from .coff import reconstruct_relocations   # local import: coff does not know about tables

    code = img.bytes_at(rva, size) or b""
    relocs = reconstruct_relocations(code, rva, size=size)
    rec = find_referenced_data(code, rva, img, size=size)
    taken = {r.offset for r in relocs}   # a field is never relocated twice
    relocs += [r for r in rec.code_relocs if r.offset not in taken]
    relocs.sort(key=lambda r: r.offset)
    return build_with_data(name, code, relocs, rec.blobs), relocs, rec.blobs, rec.notes
