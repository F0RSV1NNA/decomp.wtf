"""PE32+ (Windows x64) reading.

Enough of the format to import a stripped third-party executable: the headers, the
section table, RVA <-> file-offset mapping, the exception directory (.pdata), the
debug directory (a PDB path, when the binary was built with one) and the import table.
No dependencies beyond the standard library.

Everything here works on RVAs, never on the ImageBase: a linked image is based at its
preferred address and moved by ASLR, and the bytes on disk are the same either way.

Section sizing needs care, because the two sizes mean different things and neither is
"the size of the section" on its own:
  * VirtualSize   -- how many bytes the loader maps. This is the real content length.
  * SizeOfRawData -- the file bytes, rounded up to FileAlignment. Usually larger.
The loaded extent is VirtualSize when it is non-zero (falling back to SizeOfRawData),
and bytes past it are file padding the loader never maps. The .text of the /Od lab
fixture is exactly this: VirtualSize 1136, SizeOfRawData 1536.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

# --- constants we actually use -------------------------------------------------------------

DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\0\0"
OPTIONAL_PE32 = 0x10B
OPTIONAL_PE32PLUS = 0x20B

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_DLL = 0x2000

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

# data directory indices
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY = 0, 1, 2, 3, 4
DIR_BASERELOC, DIR_DEBUG, DIR_ARCHITECTURE, DIR_GLOBALPTR, DIR_TLS = 5, 6, 7, 8, 9
DIR_LOAD_CONFIG, DIR_BOUND_IMPORT, DIR_IAT, DIR_DELAY_IMPORT = 10, 11, 12, 13

DIRECTORY_NAMES = {0: "export", 1: "import", 2: "resource", 3: "exception", 4: "security",
                   5: "basereloc", 6: "debug", 7: "architecture", 8: "globalptr", 9: "tls",
                   10: "load_config", 11: "bound_import", 12: "iat", 13: "delay_import"}

MACHINE_NAMES = {0x8664: "AMD64", 0x014C: "I386", 0xAA64: "ARM64", 0x01C0: "ARM"}

# IMAGE_DEBUG_TYPE_CODEVIEW
DEBUG_TYPE_CODEVIEW = 2


class PEError(ValueError):
    """The file is not a PE image this reader understands."""


@dataclass(frozen=True)
class Section:
    name: str
    rva: int  # VirtualAddress
    vsize: int  # VirtualSize: what the loader maps (0 -> use raw_size)
    raw_ptr: int  # PointerToRawData: file offset of the section's bytes
    raw_size: int  # SizeOfRawData: file bytes, rounded up to FileAlignment
    characteristics: int

    @property
    def loaded_size(self) -> int:
        """How many bytes of this section exist in the loaded image."""
        return self.vsize or self.raw_size

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE) or bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def is_discardable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_DISCARDABLE)

    @property
    def file_end(self) -> int:
        return self.raw_ptr + self.raw_size

    def covers_rva(self, rva: int) -> bool:
        return self.rva <= rva < self.rva + self.loaded_size


@dataclass(frozen=True)
class RuntimeFunction:
    """One .pdata entry: RUNTIME_FUNCTION { BeginAddress, EndAddress, UnwindInfoAddress }.

    x64 Windows writes one of these per *unwind region*, which is not the same thing as a
    function: a function with a frame and a call usually has exactly one, a leaf function
    (no frame, no call) has none, and a function with chained unwind info has several.
    Records that exist are exact -- BeginAddress is the entry point and EndAddress is the
    true end of the code, with no alignment padding.

    See pe/discover.py for what that means in practice.
    """

    begin: int  # RVA
    end: int  # RVA, exclusive
    unwind: int  # RVA of the UNWIND_INFO

    @property
    def size(self) -> int:
        return self.end - self.begin


@dataclass
class PEImage:
    path: Path | None
    data: bytes
    machine: int
    characteristics: int
    timestamp: int
    optional_magic: int
    linker_version: tuple[int, int]
    image_base: int
    section_alignment: int
    file_alignment: int
    entry_point: int  # RVA
    subsystem: int
    size_of_image: int
    size_of_headers: int
    sections: list[Section] = field(default_factory=list)
    directories: list[tuple[int, int]] = field(default_factory=list)  # (RVA, size) by index
    _text_cache: bytes | None = field(default=None, repr=False, compare=False)

    # ---- loading ---------------------------------------------------------------------------

    @classmethod
    def load(cls, src: bytes | str | Path) -> "PEImage":
        data = Path(src).read_bytes() if isinstance(src, (str, Path)) else src
        path = Path(src) if isinstance(src, (str, Path)) else None
        return cls._parse(data, path)

    @classmethod
    def _parse(cls, data: bytes, path: Path | None) -> "PEImage":
        if len(data) < 0x40 or data[:2] != DOS_MAGIC:
            raise PEError("not a PE image (no MZ header)")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != PE_SIGNATURE:
            raise PEError("not a PE image (no PE signature)")

        (machine, nsec, timestamp, _symtab, _nsym, opt_size,
         characteristics) = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
        opt = e_lfanew + 24
        if opt + opt_size > len(data):
            raise PEError("truncated optional header")
        magic, major_lv, minor_lv = struct.unpack_from("<HBB", data, opt)
        if magic not in (OPTIONAL_PE32, OPTIONAL_PE32PLUS):
            raise PEError(f"unknown optional header magic {magic:#x}")
        plus = magic == OPTIONAL_PE32PLUS

        entry_point, = struct.unpack_from("<I", data, opt + 16)
        # PE32+ has a 64-bit ImageBase at +24, PE32 a 32-bit one at +28 (later fields differ too)
        image_base, = struct.unpack_from("<Q" if plus else "<I", data, opt + (24 if plus else 28))
        sec_align, file_align = struct.unpack_from("<II", data, opt + 32)
        subsystem, = struct.unpack_from("<H", data, opt + 68)
        size_of_image, size_of_headers = struct.unpack_from("<II", data, opt + 56)
        n_dirs, = struct.unpack_from("<I", data, opt + (108 if plus else 92))
        dirs_at = opt + (112 if plus else 96)
        directories = [struct.unpack_from("<II", data, dirs_at + i * 8) for i in range(min(n_dirs, 16))]

        sections = []
        sec_at = opt + opt_size
        for i in range(nsec):
            o = sec_at + i * 40
            if o + 40 > len(data):
                raise PEError("truncated section table")
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, rva, raw_size, raw_ptr, _rel, _ln, _nrel, _nln, chars = struct.unpack_from("<IIIIIIHHI", data, o + 8)
            sections.append(Section(name, rva, vsize, raw_ptr, raw_size, chars))

        return cls(path=path, data=data, machine=machine, characteristics=characteristics,
                   timestamp=timestamp, optional_magic=magic, linker_version=(major_lv, minor_lv),
                   image_base=image_base, section_alignment=sec_align, file_alignment=file_align,
                   entry_point=entry_point, subsystem=subsystem, size_of_image=size_of_image,
                   size_of_headers=size_of_headers, sections=sections, directories=directories)

    # ---- little accessors ------------------------------------------------------------------

    @property
    def machine_name(self) -> str:
        return MACHINE_NAMES.get(self.machine, f"{self.machine:#06x}")

    @property
    def is_x64(self) -> bool:
        return self.machine == IMAGE_FILE_MACHINE_AMD64

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & IMAGE_FILE_DLL)

    @property
    def _coff_offset(self) -> int:
        return struct.unpack_from("<I", self.data, 0x3C)[0] + 4

    @property
    def is_stripped(self) -> bool:
        """No COFF symbol table: the usual case for a shipped executable."""
        return struct.unpack_from("<I", self.data, self._coff_offset + 8)[0] == 0

    def section(self, name: str) -> Section | None:
        return next((s for s in self.sections if s.name == name), None)

    def section_of(self, rva: int) -> Section | None:
        return next((s for s in self.sections if s.covers_rva(rva)), None)

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    # ---- RVA <-> file offset ---------------------------------------------------------------

    def rva_to_offset(self, rva: int) -> int | None:
        """File offset holding the loaded byte at `rva`, or None.

        None when the RVA is unmapped (inside the headers, or past the image) and also when
        it is inside a section's file padding past VirtualSize, which the loader never maps.
        """
        sec = self.section_of(rva)
        if sec is None:
            return None
        delta = rva - sec.rva
        if delta >= sec.raw_size:
            return None
        off = sec.raw_ptr + delta
        return off if off < len(self.data) else None

    def offset_to_rva(self, offset: int) -> int | None:
        for s in self.sections:
            if s.raw_ptr <= offset < s.file_end:
                delta = offset - s.raw_ptr
                # only offsets the loader would map have an RVA
                return s.rva + delta if delta < s.loaded_size else None
        return None

    def bytes_at(self, rva: int, size: int) -> bytes | None:
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        return self.data[off:off + size]

    def bytes_of(self, begin_rva: int, end_rva: int) -> bytes | None:
        return self.bytes_at(begin_rva, end_rva - begin_rva)

    # ---- code ------------------------------------------------------------------------------

    def text_section(self) -> Section | None:
        """The executable section code lives in: conventionally .text, but a packed or
        renamed image can call it anything, so fall back to the first executable one."""
        named = self.section(".text")
        if named is not None and named.is_code:
            return named
        return next((s for s in self.sections if s.is_code and not s.is_discardable), None)

    def code_bytes(self) -> bytes:
        """The executable section as loaded: exactly `loaded_size` bytes, zero-filled past
        the file bytes when VirtualSize is the larger of the two."""
        if self._text_cache is not None:
            return self._text_cache
        sec = self.text_section()
        if sec is None:
            self._text_cache = b""
            return self._text_cache
        size = sec.loaded_size
        raw = self.data[sec.raw_ptr:sec.raw_ptr + size]
        if len(raw) < size:
            raw = raw + b"\0" * (size - len(raw))
        self._text_cache = raw
        return raw

    def code_rva_base(self) -> int:
        sec = self.text_section()
        return sec.rva if sec else 0

    # ---- .pdata ----------------------------------------------------------------------------

    def runtime_functions(self) -> list[RuntimeFunction]:
        """The exception directory as RUNTIME_FUNCTION records, sorted by address.

        These are unwind regions; see the class docstring and pe/discover.py.
        """
        rva, size = self.directory(DIR_EXCEPTION)
        out: list[RuntimeFunction] = []
        if not rva or size < 12:
            return out
        off = self.rva_to_offset(rva)
        if off is None:
            return out
        for i in range(size // 12):
            begin, end, unwind = struct.unpack_from("<III", self.data, off + i * 12)
            if begin == 0 and end == 0:
                continue  # an empty/chained slot
            if end <= begin or end - begin > 0x100000:
                continue  # not a plausible region
            out.append(RuntimeFunction(begin, end, unwind))
        out.sort(key=lambda r: r.begin)
        return out

    # ---- debug directory (PDB) -------------------------------------------------------------

    def pdb(self) -> tuple[str, bytes, int] | None:
        """(path, RSDS guid, age) from the CodeView entry, or None. Present only when the
        image was linked with /DEBUG."""
        entry = self.debug_entry(DEBUG_TYPE_CODEVIEW)
        if entry is None:
            return None
        _type, _size, offset = entry
        if self.data[offset:offset + 4] != b"RSDS":
            return None
        guid = self.data[offset + 4:offset + 20]
        age, = struct.unpack_from("<I", self.data, offset + 20)
        name = self.data[offset + 24:].split(b"\0")[0].decode("latin1", "replace")
        return name, guid, age

    def debug_entry(self, want_type: int) -> tuple[int, int, int] | None:
        """(type, size, file offset of the payload) for one debug directory entry."""
        rva, size = self.directory(DIR_DEBUG)
        off = self.rva_to_offset(rva) if rva else None
        if off is None:
            return None
        for i in range(size // 28):
            o = off + i * 28
            d_type, d_size, _addr, ptr = struct.unpack_from("<IIII", self.data, o + 12)
            if d_type == want_type and ptr:
                return d_type, d_size, ptr
        return None

    # ---- imports ---------------------------------------------------------------------------

    def imports(self) -> dict[str, list[str]]:
        """{dll name: [imported names]}. A name may be an ordinal, "#123"."""
        rva, _size = self.directory(DIR_IMPORT)
        out: dict[str, list[str]] = {}
        if not rva:
            return out
        o = self.rva_to_offset(rva)
        if o is None:
            return out
        while True:
            desc = self.data[o:o + 20]
            if len(desc) < 20:
                break
            oft, _ts, _fc, name_rva, first_thunk = struct.unpack("<IIIII", desc)
            if name_rva == 0 and first_thunk == 0:
                break
            no = self.rva_to_offset(name_rva)
            dll = self.data[no:].split(b"\0")[0].decode("latin1", "replace") if no else "?"
            names: list[str] = []
            to = self.rva_to_offset(oft or first_thunk)
            while to:
                value, = struct.unpack_from("<Q", self.data, to)
                if value == 0:
                    break
                if value & (1 << 63):
                    names.append(f"#{value & 0xFFFF}")
                else:
                    ho = self.rva_to_offset(value & 0x7FFFFFFF)
                    if ho is None:
                        break
                    names.append(self.data[ho + 2:].split(b"\0")[0].decode("latin1", "replace"))
                to += 8
            out[dll] = names
            o += 20
        return out

    # ---- reporting -------------------------------------------------------------------------

    def summary(self) -> str:
        lines = [f"{self.path.name if self.path else '<bytes>'}: {self.machine_name} "
                 f"{'PE32+' if self.optional_magic == OPTIONAL_PE32PLUS else 'PE32'}, "
                 f"{len(self.sections)} sections, linker {self.linker_version[0]}.{self.linker_version[1]}",
                 f"  ImageBase {self.image_base:#x}  entry RVA {self.entry_point:#x}  "
                 f"align sect/file {self.section_alignment}/{self.file_alignment}"]
        for s in self.sections:
            lines.append(f"  {s.name:<9} RVA {s.rva:>#9x}  loaded {s.loaded_size:>7}  raw {s.raw_size:>7}")
        for i, (rva, size) in enumerate(self.directories):
            if rva or size:
                lines.append(f"  dir[{i}] {DIRECTORY_NAMES.get(i, '?'):<12} RVA {rva:>#10x}  size {size}")
        rf = self.runtime_functions()
        lines.append(f"  .pdata: {len(rf)} RUNTIME_FUNCTION records (unwind regions), "
                     f"covering {sum(r.size for r in rf)} bytes")
        pdb = self.pdb()
        lines.append(f"  PDB: {pdb[0] if pdb else '<none>'}")
        return "\n".join(lines)
