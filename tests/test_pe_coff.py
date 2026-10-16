"""Synthetic COFF targets: carve a function out of a linked image and let objdiff judge it.

The milestone this file pins: *stripped PE64 -> recovered functions -> synthetic COFF
target -> MSVC candidate -> meaningful objdiff comparison*.

The base objects (`tests/data/ref_od.obj`, `main_od.obj`) are the MSVC objects that built
`test_od.exe`, compiled with the same compiler and flags. So if the reconstruction is
faithful, objdiff must say 100%, and anything less is the reconstruction's fault.

Measured: 13 of the 14 functions in `ref.od.obj` compare EXACTLY -- including `bump`
(5 reconstructed relocations), `pipeline` (5), `read_globals` (3) and `caller` (3). The
14th is `sw`, at 60.8%, and it is the switch statement: it compiles to a jump table that
lives in `.rdata` as *data*, which an image cannot give back to a code-only object.

(`main` is not tested here: it is defined in `main_od.obj`, not `ref_od.obj`.)

Three bugs were found and fixed by exactly this measurement, so they are pinned below:
  * a `jmp` inside the function is NOT a relocation -- relocating it zeroed a field the
    compiler had filled in and took `classify` and `clamp` to 0%;
  * capstone needs `skipdata`, or `.operands` raises on data bytes and the scan stops;
  * a name longer than 8 bytes must use the BINARY long-name form (`\\0\\0\\0\\0` + offset).
    The ASCII "/4" form is legal COFF, but objdiff shows it literally as the symbol name,
    so every function with a name over 8 characters silently failed to match.
"""

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.pe import PEImage, discover
from decompnet.pe.coff import (IMAGE_REL_AMD64_REL32, build_object, function_object,
                               reconstruct_relocations)

DATA = Path(__file__).parent / "data"
EXE = DATA / "test_od.exe"
REF = DATA / "ref_od.obj"

# the 14 functions ref.c defines, and how they compare (measured, see the module docstring)
EXPECTED_EXACT = ["add_mul", "bump", "caller", "clamp", "classify", "deep", "mixed_math",
                  "my_strlen", "pipeline", "read_globals", "shifts", "stacky", "use_string"]
EXPECTED_DIFFERENT = {"sw": "jump table in .rdata"}

# installed() returns the tool's metadata; require() returns the directory it lives in
OBJDIFF = str(Path(toolchains.require("objdiff-cli")) / "objdiff-cli") \
    if toolchains.installed("objdiff-cli") else None

needs_objdiff = pytest.mark.skipif(OBJDIFF is None,
                                   reason="needs objdiff-cli")


def coff_symbols(obj: bytes) -> dict[str, tuple[int, int, int, int]]:
    """{name: (value, section, type, storage)} -- a reader small enough to be obviously right."""
    _machine, _nsec, _ts, sym_off, nsym, optsz, _chars = struct.unpack_from("<HHIIIHH", obj, 0)
    strtab = obj[sym_off + nsym * 18:]
    out = {}
    for k in range(nsym):
        rec = obj[sym_off + k * 18:sym_off + k * 18 + 18]
        raw = rec[:8]
        if raw[:4] == b"\0\0\0\0":
            off = struct.unpack("<I", raw[4:8])[0]
            name = strtab[off:strtab.index(b"\0", off)].decode("latin1")
        else:
            name = raw.rstrip(b"\0").decode("latin1")
        out[name] = struct.unpack_from("<IhHBB", rec, 8)[:4]  # value, section, type, storage
    return out


@pytest.fixture(scope="module")
def image():
    return PEImage.load(EXE)


# --- the object itself ----------------------------------------------------------------------

def test_a_built_object_is_a_well_formed_coff():
    obj = build_object("f", b"\x90\xc3", [])
    machine, nsec, _ts, sym_off, nsym, optsz, _c = struct.unpack_from("<HHIIIHH", obj, 0)
    assert machine == 0x8664, "AMD64"
    assert nsec == 1 and optsz == 0, "no optional header"
    assert nsym == 1
    name, section = obj[20:28], obj[20:28]
    assert obj[20:28].rstrip(b"\0") == b".text"
    size, _va, raw_size, raw_ptr, rel_ptr, _ln, n_rel, _nln, chars = struct.unpack_from("<IIIIIIHHI", obj, 28)
    assert raw_size == 2 and rel_ptr == 0 and n_rel == 0
    assert chars & 0x20, "IMAGE_SCN_CNT_CODE"
    assert obj[raw_ptr:raw_ptr + 2] == b"\x90\xc3"
    assert len(obj) == sym_off + nsym * 18 + 4, "the string table follows the symbols"


def test_the_function_symbol_is_defined_and_typed_as_a_function():
    obj = build_object("f", b"\x90\xc3", [])
    syms = coff_symbols(obj)
    value, section, typ, storage = syms["f"]
    assert (value, section, typ, storage) == (0, 1, 0x20, 2)


def test_relocation_targets_become_undefined_symbols():
    relocs = [reconstruct_relocations(b"\xe8\x00\x00\x00\x00\xc3", 0x1000, size=6)[0]]
    obj = build_object("f", b"\xe8\x00\x00\x00\x00\xc3", relocs)
    syms = coff_symbols(obj)
    assert sorted(syms) == ["f", "sub_1005"]
    assert syms["sub_1005"][1] == 0, "section 0 = undefined"
    # one relocation record, at the field, pointing at the second symbol
    n_rel = struct.unpack_from("<H", obj, 20 + 32)[0]
    assert n_rel == 1
    rel_ptr = struct.unpack_from("<I", obj, 20 + 24)[0]
    off, sym_index, rtype = struct.unpack_from("<IIH", obj, rel_ptr)
    assert (off, sym_index, rtype) == (1, 1, IMAGE_REL_AMD64_REL32)


def test_a_long_name_uses_the_binary_form_objdiff_reads():
    """The regression: objdiff shows the ASCII "/4" form literally as the symbol name.

    MSVC emits `\\0\\0\\0\\0` + a 32-bit offset. So does this now. Anything with a name
    over 8 characters failed to match while it emitted "/N" instead.
    """
    obj = build_object("thirteenchars", b"\xc3", [])
    _m, _n, _t, sym_off, _nsym, _o, _c = struct.unpack_from("<HHIIIHH", obj, 0)
    raw = obj[sym_off:sym_off + 8]
    assert raw[:4] == b"\0\0\0\0", "the binary long-name form, not '/N'"
    assert struct.unpack("<I", raw[4:8])[0] == 4, "first string sits right after the length field"
    assert coff_symbols(obj) == {"thirteenchars": (0, 1, 0x20, 2)}


def test_a_short_name_stays_inline():
    obj = build_object("f", b"\xc3", [])
    _m, _n, _t, sym_off, _nsym, _o, _c = struct.unpack_from("<HHIIIHH", obj, 0)
    assert obj[sym_off:sym_off + 8] == b"f\0\0\0\0\0\0\0"


def test_relocated_fields_are_zeroed_for_the_linker():
    """What a compiler leaves behind: the field the relocation covers is empty."""
    code = b"\xe8\x11\x22\x33\x44\xc3"          # call rel32 with a resolved displacement
    relocs = reconstruct_relocations(code, 0x1000, size=6)
    assert len(relocs) == 1 and relocs[0].offset == 1
    obj = build_object("f", code, relocs)
    raw_ptr = struct.unpack_from("<I", obj, 20 + 20)[0]
    assert obj[raw_ptr:raw_ptr + 6] == b"\xe8\x00\x00\x00\x00\xc3"


# --- which references become relocations ----------------------------------------------------

def test_a_call_becomes_a_relocation():
    relocs = reconstruct_relocations(b"\xe8\x00\x00\x00\x00\xc3", 0x1000, size=6)
    assert [(r.offset, r.type, r.target_rva) for r in relocs] == [(1, IMAGE_REL_AMD64_REL32, 0x1005)]


def test_a_jump_inside_the_function_is_not_a_relocation():
    """The regression that took classify and clamp to 0%: the compiler fills this field
    itself and emits no relocation, so zeroing it can never match."""
    code = b"\x75\x02\x90\x90\xc3"              # jne +2 (inside), nop, nop, ret
    assert reconstruct_relocations(code, 0x1000, size=5) == []


def test_a_jump_outside_the_function_is_a_tail_call_relocation():
    code = b"\xe9\x00\x00\x00\x00"              # jmp far
    relocs = reconstruct_relocations(code, 0x1000, size=5)
    assert [(r.offset, r.target_rva) for r in relocs] == [(1, 0x1005)]


def test_a_rip_relative_operand_becomes_a_relocation_with_the_right_type():
    code = b"\x8b\x05\x00\x00\x00\x00\xc3"      # mov eax, [rip+disp]
    relocs = reconstruct_relocations(code, 0x1000, size=7)
    assert [(r.offset, r.type, r.target_rva) for r in relocs] == [(2, IMAGE_REL_AMD64_REL32, 0x1006)]


def test_the_reloc_type_counts_the_bytes_after_the_field():
    """REL32+n is how COFF says 'n bytes follow the field'; objdiff needs it to place it."""
    code = b"\x83\x3d\x00\x00\x00\x00\x07"      # cmp dword ptr [rip+disp], 7  -> field not last
    relocs = reconstruct_relocations(code, 0x1000, size=7)
    assert len(relocs) == 1
    assert relocs[0].type == IMAGE_REL_AMD64_REL32 + 1


def test_skipdata_is_required_or_the_scan_stops_early():
    """Regression: `.operands` raises on a skipped data byte, and without skipdata the
    disassembly stops at the first undecodable byte instead."""
    code = b"\xff\xff\xff\xff\xe8\x00\x00\x00\x00"   # 4 junk bytes, then a call
    relocs = reconstruct_relocations(code, 0x1000, size=9)
    assert [(r.offset, r.target_rva) for r in relocs] == [(5, 0x1009)], (
        "the call after the junk must still be found")


# --- end to end, judged by objdiff ----------------------------------------------------------

@needs_objdiff
def test_every_recovered_function_matches_the_compiler_object(image, tmp_path):
    """The milestone, measured: synthetic COFF from the exe vs the object it was linked from."""
    import json

    found = {f.rva: f for f in discover(image)}
    truth = json.loads((DATA / "test_truth.json").read_text())["od"]["functions"]
    # the base is ref_od.obj, which holds ref.c's functions only; `main` was compiled into
    # main_od.obj. Judging it against the wrong object would only measure the fixture.
    in_base = set(coff_symbols(REF.read_bytes()))
    assert "main" not in in_base, "the fixture moved: main is expected in main_od.obj"
    scores = {}
    for f in truth:
        name = f["name"]
        if name not in in_base:
            continue
        obj, _ = function_object(image, f["rva"], found[f["rva"]].size, name)
        p = tmp_path / f"{name}.obj"
        p.write_bytes(obj)
        r = subprocess.run([OBJDIFF, "--no-color", "diff",
                            "-1", str(p), "-2", str(REF), "-c", "functionRelocDiffs=none",
                            "--format", "json", "-o", "-", name],
                           capture_output=True, text=True, timeout=120)
        d = json.loads(r.stdout)
        sco = next((s.get("match_percent") for s in d["left"]["symbols"] if s["name"] == name), None)
        scores[name] = sco

    exact = [n for n, v in scores.items() if v == 100.0]
    assert sorted(exact) == sorted(EXPECTED_EXACT), f"exact matches changed: {scores}"
    rest = {n: v for n, v in scores.items() if v != 100.0}
    assert set(rest) == set(EXPECTED_DIFFERENT), f"unexpected non-matches: {rest}"
    assert 50 < rest["sw"] < 70, f"sw is the jump-table case, measured ~61%: {rest['sw']}"


@needs_objdiff
def test_a_function_with_relocations_matches_exactly(image, tmp_path):
    """Singled out because it is the case that proves relocation reconstruction works:
    `bump` references two globals four times, and still compares byte for byte."""
    found = {f.rva: f for f in discover(image)}
    rva = next(f["rva"] for f in
               __import__("json").loads((DATA / "test_truth.json").read_text())["od"]["functions"]
               if f["name"] == "bump")
    obj, relocs = function_object(image, rva, found[rva].size, "bump")
    assert len(relocs) == 5
    p = tmp_path / "bump.obj"
    p.write_bytes(obj)
    import json
    r = subprocess.run([OBJDIFF, "--no-color", "diff",
                        "-1", str(p), "-2", str(REF), "-c", "functionRelocDiffs=none",
                        "--format", "json", "-o", "-", "bump"], capture_output=True, text=True, timeout=120)
    d = json.loads(r.stdout)
    pct = next(s.get("match_percent") for s in d["left"]["symbols"] if s["name"] == "bump")
    assert pct == 100.0
