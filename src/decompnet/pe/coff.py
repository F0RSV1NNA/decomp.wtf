"""Synthetic COFF objects: make one function carved out of a linked image look like
something a compiler produced, so objdiff can compare it.

A linked x64 image is not an object file. The differences that matter:

  * **Relocations are gone.** Every reference is resolved: `call target` holds the real
    rel32, and `mov eax, [rip+x]` holds the real displacement. A compiler's object has a
    relocation and (for COFF) a zeroed field. If we hand objdiff the linked bytes as-is,
    every reference compares against a zero and the function reads as a mismatch no matter
    how right the C is. So references are *reconstructed*: decode the function, work out
    what each RIP-relative displacement and each direct call points at, zero the field and
    write a relocation naming that address.
  * **The symbol table is gone**, so the relocation targets have no names. Nothing here
    invents names: addresses are named positionally (`sub_140001234` style). objdiff is
    told `functionRelocDiffs=none` by the project, which compares the instruction and
    ignores which symbol a relocation points at -- so a name we cannot know does not cost
    a match.
  * **Sections differ.** The linker merged every .text$mn into one .text and placed .rdata
    and .data somewhere else. A function's bytes are copied out byte for byte, which is
    what matters: code refers to everything else by displacement.

What is NOT reconstructed (and cannot be, from the image alone):
  * the linker's own rewrites -- `call f` turned into a thunk jump, an import resolved
    through the IAT, identical-code folding, incremental-link padding;
  * jump tables and literal pools, which live in .rdata as *data* and are only reachable
    through `.rdata` bytes, not through code;
  * anything the compiler inlined away, because there is nothing left to find.

So a synthetic object is good evidence, not proof: a function whose bytes survive linking
unrewritten compares exactly, and one the linker rewrote does not.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import capstone

from .image import PEImage

_CS_MODE = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_ALIGN_16BYTES = 0x00500000
TEXT_CHARACTERISTICS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_16BYTES

IMAGE_REL_AMD64_ADDR64 = 0x0001
IMAGE_REL_AMD64_ADDR32 = 0x0002
IMAGE_REL_AMD64_ADDR32NB = 0x0003
IMAGE_REL_AMD64_REL32 = 0x0004  # ... REL32_1..REL32_5 follow, adding the bytes after the field

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_DTYPE_FUNCTION = 0x20

RELOC_NAMES = {1: "ADDR64", 2: "ADDR32", 3: "ADDR32NB", 4: "REL32", 5: "REL32_1",
               6: "REL32_2", 7: "REL32_3", 8: "REL32_4", 9: "REL32_5"}


@dataclass(frozen=True)
class Reloc:
    offset: int  # within the function
    type: int
    target_rva: int  # what the reference resolves to, as an RVA in the image

    @property
    def type_name(self) -> str:
        return RELOC_NAMES.get(self.type, f"0x{self.type:x}")


def _md() -> capstone.Cs:
    md = capstone.Cs(*_CS_MODE)
    md.detail = True
    md.skipdata = True  # see pe/discover.py: without it the sweep stops at the first odd byte
    return md


def reconstruct_relocations(code: bytes, base_rva: int, *, size: int | None = None,
                            text_lo: int = 0, text_hi: int = 0) -> list[Reloc]:
    """Every reference in `code` that the linker resolved, as a relocation.

    Two kinds, matching what a compiler's object carries:
      * `call rel32` anywhere, and `jmp rel32` to a target OUTSIDE this function, -> REL32
      * a RIP-relative memory operand (`[rip+disp]`)                             -> REL32(+n)

    A `jmp` inside the function is NOT a relocation: the compiler emits the displacement
    itself and the object has no relocation there. Emitting one would zero a field the
    compiler filled in, and the function would then never compare. (Measured: `classify`
    and `clamp` came out at 0% for exactly this reason before it was fixed.)

    `size` is the function's length; without it nothing is treated as intra-function.
    """
    end = base_rva + (size if size is not None else len(code))
    out: list[Reloc] = []
    md = _md()
    for ins in md.disasm(code, base_rva):
        off = ins.address - base_rva
        if off < 0 or off + ins.size > len(code):
            break
        if ins.id == 0:          # a skipped data byte in SKIPDATA mode: .operands raises
            continue
        if ins.mnemonic in ("call", "jmp") and ins.operands:
            op = ins.operands[0]
            if op.type == capstone.x86.X86_OP_IMM:
                inside = base_rva <= op.imm < end
                if ins.mnemonic == "call" or not inside:
                    # rel32 occupies the last four bytes of the instruction
                    out.append(Reloc(off + ins.size - 4, IMAGE_REL_AMD64_REL32, op.imm))
                continue
        for op in ins.operands:
            if op.type != capstone.x86.X86_OP_MEM or op.mem.base != capstone.x86.X86_REG_RIP:
                continue
            # [rip+disp] is relative to the end of the instruction
            target = ins.address + ins.size + ins.disp
            field = ins.disp_offset
            after = ins.size - field - 4  # bytes between the field and the instruction's end
            if after < 0:
                continue
            out.append(Reloc(off + field, IMAGE_REL_AMD64_REL32 + after, target))
    out.sort(key=lambda r: r.offset)
    return out


def _mask(code: bytearray, relocs: list[Reloc]) -> bytearray:
    """Zero the fields a relocation covers: what a compiler leaves for the linker."""
    for r in relocs:
        width = 8 if r.type == IMAGE_REL_AMD64_ADDR64 else 4
        code[r.offset:r.offset + width] = b"\0" * width
    return code


def _name(name: str) -> tuple[bytes, bytes]:
    """(the 8-byte inline name or /offset, the string to append to the string table)."""
    raw = name.encode("latin1")
    if len(raw) <= 8:
        return raw.ljust(8, b"\0"), b""
    return None, raw + b"\0"


def build_object(function_name: str, code: bytes, relocs: list[Reloc], *,
                 target_name=lambda rva: f"sub_{rva:X}") -> bytes:
    """A one-function COFF object objdiff can read: one .text section, one defined
    function symbol, one undefined symbol per relocation target."""
    code = bytes(_mask(bytearray(code), relocs))

    strings = bytearray()
    syms: list[tuple[bytes, int, int, int, int]] = []  # (name8, value, secnum, type, storage)
    name8, extra = _name(function_name)
    if name8 is None:
        off = len(strings) + 4
        strings += extra
        name8 = b"\0\0\0\0" + struct.pack("<I", off)  # the binary long-name form MSVC and objdiff use
    syms.append((name8, 0, 1, IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_CLASS_EXTERNAL))

    index_of: dict[int, int] = {}
    for r in relocs:
        if r.target_rva not in index_of:
            nm = target_name(r.target_rva)
            n8, extra = _name(nm)
            if n8 is None:
                off = len(strings) + 4
                strings += extra
                n8 = b"\0\0\0\0" + struct.pack("<I", off)  # the binary long-name form MSVC and objdiff use
            index_of[r.target_rva] = len(syms)
            syms.append((n8, 0, 0, 0, IMAGE_SYM_CLASS_EXTERNAL))  # section 0 = undefined

    n_sections = 1
    header_size = 20
    sect_size = 40 * n_sections
    raw_off = header_size + sect_size
    raw_size = len(code)
    rel_off = raw_off + raw_size
    rel_size = 10 * len(relocs)
    sym_off = rel_off + rel_size
    sym_size = 18 * len(syms)
    str_off = sym_off + sym_size

    header = struct.pack("<HHIIIHH", IMAGE_FILE_MACHINE_AMD64, n_sections, 0,
                         sym_off, len(syms), 0, 0)
    section = (b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0, 0, raw_size, raw_off,
                                            rel_off if relocs else 0, 0, len(relocs), 0,
                                            TEXT_CHARACTERISTICS))
    if len(section) != 40:
        raise AssertionError("section header must be 40 bytes")

    relocs_bytes = b"".join(struct.pack("<IIH", r.offset, index_of[r.target_rva], r.type) for r in relocs)
    symbols = b"".join(n8 + struct.pack("<IhHBB", value, secnum, typ, storage, 0)
                       for n8, value, secnum, typ, storage in syms)
    strtab = struct.pack("<I", 4 + len(strings)) + bytes(strings)
    return b"".join([header, section, code, relocs_bytes, symbols, strtab])


def function_object(img: PEImage, rva: int, size: int, name: str) -> tuple[bytes, list[Reloc]]:
    """(the object, the relocations it was built from) for one function of an image."""
    code = img.bytes_at(rva, size) or b""
    base = img.code_rva_base()
    relocs = reconstruct_relocations(code, rva, size=size)
    return build_object(name, code, relocs), relocs
