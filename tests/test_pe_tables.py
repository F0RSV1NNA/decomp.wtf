"""Referenced data and jump tables.

MSVC lowers a dense switch to an indexed load off `__ImageBase`, and the linker resolves
the table's ADDR32NB relocations into plain addresses -- so the reference stops looking like
a reference and the entry values stop looking like symbols. This file pins what is recovered
from the linked image against what the MSVC object actually contained.

The one thing here that is NOT finished is the objdiff comparison of `sw` itself: it sits at
60.87% and the tests say so rather than pretending otherwise. The recovery is right (the
table is 8 entries, exactly the case labels, with the right relocation type); what is still
unknown is why the comparison stays at 60%. Cutting the table out of .text was tried and made
it worse (16.7%), so that is not the reason. Do not "fix" this by touching objdiff options.
"""

import json
import struct
import subprocess
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.pe import PEImage
from decompnet.pe.coff import IMAGE_REL_AMD64_REL32
from decompnet.pe.tables import (IMAGE_REL_AMD64_ADDR32NB, build_with_data, find_referenced_data,
                                function_object_with_data, read_table)

DATA = Path(__file__).parent / "data"
EXE, REF = DATA / "test_od.exe", DATA / "ref_od.obj"
SW_RVA, SW_SIZE = 0x11B0, 144
TABLE_RVA = 0x1220
CASES = [0x11DC, 0x11E3, 0x11EA, 0x11F1, 0x11F8, 0x11FF, 0x1206, 0x120D]


@pytest.fixture(scope="module")
def image():
    return PEImage.load(EXE)


# --- the table ------------------------------------------------------------------------------

def test_read_table_finds_the_case_labels(image):
    assert read_table(image, TABLE_RVA) == CASES


def test_read_table_stops_at_the_first_non_code_word(image):
    """Boundaries are decided by content: an entry has to be an address inside .text.

    The 9th word here is padding, so the table ends. This is the property that keeps the
    recovery from inventing entries -- and it is also its blind spot, since a table whose
    next word happened to look like a code address would run on.
    """
    after = TABLE_RVA + 4 * len(CASES)
    word, = struct.unpack_from("<I", image.data, image.rva_to_offset(after))
    assert word == 0 or not (0x1000 <= word < 0x1470), f"word after the table is {word:#x}"


def test_read_table_says_no_to_something_that_is_not_a_table(image):
    """Ordinary data must not be mistaken for a jump table."""
    assert read_table(image, 0x1000) == []       # code, not a table of code addresses
    assert read_table(image, 0x3000) == []       # .data: integers, not code addresses
    assert read_table(image, 0) == []


def test_the_reference_to_the_table_is_found_and_typed(image):
    """`mov eax, [rcx + rax*4 + table]` is NOT RIP-relative, so nothing else can see it."""
    code = image.bytes_at(SW_RVA, SW_SIZE)
    rec = find_referenced_data(code, SW_RVA, image, size=SW_SIZE)
    assert [(r.offset, r.type, r.target_rva) for r in rec.code_relocs] == [
        (0x23, IMAGE_REL_AMD64_ADDR32NB, TABLE_RVA)], (
        "the displacement field of the indexed load, relocated as ADDR32NB, "
        "which is exactly what MSVC emitted before the linker resolved it")
    assert not rec.notes


def test_the_recovered_blob_is_the_object_form_of_the_table(image):
    """The object holds zeroed entries with a relocation each, not the linked RVAs."""
    rec = find_referenced_data(image.bytes_at(SW_RVA, SW_SIZE), SW_RVA, image, size=SW_SIZE)
    assert len(rec.blobs) == 1
    blob = rec.blobs[0]
    assert blob.rva == TABLE_RVA and blob.name == "table_1220"
    assert blob.data == b"\0" * 32, "zeroed, as a compiler leaves it for the linker"
    assert [(r.offset, r.type, r.target_rva) for r in blob.relocs] == [
        (4 * i, IMAGE_REL_AMD64_ADDR32NB, v) for i, v in enumerate(CASES)]


def test_an_indexed_load_off_something_that_is_not_the_image_base_is_ignored(image):
    """A table indexed off a normal pointer (say a global array) is not this pattern."""
    # lea rcx, [rip+0x1000] (not rva 0) ; mov eax, [rcx+rax*4+0x1220] ; ret
    code = (b"\x48\x8d\x0d\x00\x10\x00\x00"
            b"\x8b\x84\x81\x20\x12\x00\x00"
            b"\xc3")
    rec = find_referenced_data(code, 0x1000, image, size=len(code))
    assert rec.code_relocs == [] and rec.blobs == []


# --- the object -----------------------------------------------------------------------------

def test_build_with_data_emits_two_sections():
    obj = build_with_data("sw", b"\xc3", [], [])
    _m, nsec, _t, _so, nsym, _o, _c = struct.unpack_from("<HHIIIHH", obj, 0)
    assert nsec == 1 and nsym == 1, "no blobs, no .rdata"

    codes = [(r.offset, r.type, r.target_rva) for r in
             find_referenced_data(PEImage.load(EXE).bytes_at(SW_RVA, SW_SIZE), SW_RVA,
                                  PEImage.load(EXE), size=SW_SIZE).code_relocs]
    from decompnet.pe.coff import Reloc
    rec = find_referenced_data(PEImage.load(EXE).bytes_at(SW_RVA, SW_SIZE), SW_RVA,
                               PEImage.load(EXE), size=SW_SIZE)
    obj = build_with_data("sw", PEImage.load(EXE).bytes_at(SW_RVA, SW_SIZE),
                          [Reloc(o, t, v) for o, t, v in codes], rec.blobs)
    _m, nsec, _t, sym_off, nsym, _o, _c = struct.unpack_from("<HHIIIHH", obj, 0)
    assert nsec == 2, "the table needs somewhere to live"
    assert obj[20 + 40:20 + 48] == b".rdata\0\0"
    # "table_1220" is 10 bytes, so it goes through the string table; just look for it there
    assert b"table_1220\0" in obj, "the blob is named"
    # one symbol per section: the function in .text (1), the table in .rdata (2)
    kinds = {struct.unpack_from("<h", obj, sym_off + k * 18 + 12)[0] for k in range(nsym)}
    # section 0 is the case labels: they are undefined here, being other functions
    assert {1, 2} <= kinds, f"expected a symbol in each section, got {kinds}"


# --- end to end, judged by objdiff ----------------------------------------------------------

_objdiff = toolchains.installed("objdiff-cli")
OBJDIFF = str(Path(toolchains.require("objdiff-cli")) / "objdiff-cli") if _objdiff else None


@pytest.mark.skipif(OBJDIFF is None, reason="needs objdiff-cli")
def test_sw_is_recovered_but_still_does_not_match(image, tmp_path):
    """sw's data is recovered correctly and its comparison is still not 100%.

    Recorded rather than asserted-as-successful: this is the one function of the fifteen
    that does not compare, and the jump table is a real part of the reason (objdiff scores
    the untouched bytes at 60.85% and the reconstructed ones at 60.87%). Fixing it is open
    work; making the number look better by relaxing the comparison is not fixing it.
    """
    obj, relocs, blobs, notes = function_object_with_data(image, SW_RVA, SW_SIZE, "sw")
    assert len(blobs) == 1 and len(relocs) == 2
    p = tmp_path / "sw.obj"
    p.write_bytes(obj)
    r = subprocess.run([OBJDIFF, "--no-color", "diff", "-1", str(p), "-2", str(REF),
                        "-c", "functionRelocDiffs=none", "--format", "json", "-o", "-", "sw"],
                       capture_output=True, text=True, timeout=120)
    d = json.loads(r.stdout)
    pct = next(s.get("match_percent") for s in d["left"]["symbols"] if s["name"] == "sw")
    assert 60.0 < pct < 61.0, f"sw moved: {pct}% -- if this now reaches 100, delete this test"
    assert pct < 100.0
