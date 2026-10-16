"""PE32+ reading and function discovery, against a linker ground truth.

The fixtures are two real PE64 executables built in the lab from the same 15 source
functions (tests/data/test_od.exe at /Od, test_o2.exe at /O2), plus test_truth.json: the
function list and boundaries taken from the LINKER's /MAP output, which is exact.

Two things here are the point of the exercise, and both contradict the obvious guess:

  * .pdata does NOT give one RUNTIME_FUNCTION per function. It gives one per *unwind
    region*: a leaf function has none at all, and at /O2 one function here has three.
  * a linear disassembly has to set capstone's `skipdata`, or it stops at the first byte
    it cannot decode -- and a linked .text always contains padding and literal pools.

Discovery is measured, not asserted: the tests check the numbers we actually got
(15/15 at /Od, 6/6 at /O2, no invented entries) and would fail if they got worse.
"""

import json
import struct
from pathlib import Path

import pytest

from decompnet.pe import PEImage, PEError, call_targets, discover, unwind_regions
from decompnet.pe.image import DIR_EXCEPTION, OPTIONAL_PE32PLUS

DATA = Path(__file__).parent / "data"
OD, O2 = DATA / "test_od.exe", DATA / "test_o2.exe"
TRUTH = json.loads((DATA / "test_truth.json").read_text())


@pytest.fixture(scope="module")
def od():
    return PEImage.load(OD)


@pytest.fixture(scope="module")
def o2():
    return PEImage.load(O2)


# --- headers and sections ------------------------------------------------------------------

def test_it_is_a_pe32plus_x64_image(od):
    assert od.is_x64 and od.machine_name == "AMD64"
    assert od.optional_magic == OPTIONAL_PE32PLUS
    assert not od.is_dll
    assert od.image_base > 0x100000000, "a PE32+ image has a 64-bit ImageBase"
    assert od.section_alignment > 0 and od.file_alignment > 0


def test_a_non_pe_is_refused(tmp_path):
    bad = tmp_path / "nope.bin"
    bad.write_bytes(b"\x7fELF" + b"\0" * 100)
    with pytest.raises(PEError):
        PEImage.load(bad)


def test_truncated_and_signatureless_files_are_refused(tmp_path):
    for content in (b"", b"MZ", b"MZ" + b"\0" * 0x3C, b"\0" * 0x80):
        f = tmp_path / "x.bin"
        f.write_bytes(content)
        with pytest.raises(PEError):
            PEImage.load(f)


def test_sections_are_read_with_the_right_names(od):
    names = [s.name for s in od.sections]
    assert ".text" in names and ".pdata" in names
    text = od.section(".text")
    assert text.is_code and text.raw_size > 0 and text.raw_ptr > 0
    assert od.text_section() is text


def test_every_section_rva_is_inside_the_image(od):
    for s in od.sections:
        assert s.rva >= od.section_alignment, f"{s.name} sits inside the headers"
        assert s.rva < od.size_of_image


# --- RVA <-> file offset --------------------------------------------------------------------

def test_rva_mapping_round_trips_for_every_loaded_code_byte(od):
    text = od.text_section()
    for rva in range(text.rva, text.rva + text.loaded_size):
        off = od.rva_to_offset(rva)
        assert off is not None
        assert od.offset_to_rva(off) == rva


def test_file_padding_past_virtual_size_is_not_mapped(od):
    """SizeOfRawData is rounded up to FileAlignment; those bytes are not loaded.

    On this fixture .text has VirtualSize 1136 and SizeOfRawData 1536, so the last 400
    file bytes are alignment padding. Treating raw_size as the section length (the
    obvious reading) both over-reports the code and invents RVAs that are not there.
    """
    text = od.text_section()
    assert text.vsize < text.raw_size, "this fixture is the interesting case"
    last_mapped = text.rva + text.loaded_size - 1
    assert od.rva_to_offset(last_mapped) is not None
    assert od.rva_to_offset(last_mapped + 1) is None
    assert len(od.code_bytes()) == text.loaded_size
    assert od.section_of(last_mapped + 1) is None, "and it is out of the section entirely"


def test_bytes_at_reads_the_section_contents(od):
    text = od.text_section()
    raw = od.data[text.raw_ptr:text.raw_ptr + 32]
    assert od.bytes_at(text.rva, 32) == raw


def test_unmapped_rvas_give_none(od):
    assert od.rva_to_offset(0) is None            # inside the headers
    assert od.rva_to_offset(od.size_of_image + 0x1000) is None
    assert od.offset_to_rva(len(od.data) + 1) is None


def test_code_bytes_is_the_section_padded_to_virtual_size(od):
    code = od.code_bytes()
    assert len(code) == od.text_section().vsize
    assert code[:4] == od.data[od.text_section().raw_ptr:od.text_section().raw_ptr + 4]


# --- the exception directory ----------------------------------------------------------------

def test_the_exception_directory_is_present_and_parsed(od):
    rva, size = od.directory(DIR_EXCEPTION)
    assert rva and size % 12 == 0
    assert len(od.runtime_functions()) == size // 12


def test_runtime_functions_are_well_formed(od):
    rf = od.runtime_functions()
    assert rf
    text = od.text_section()
    for r in rf:
        assert text.rva <= r.begin < r.end <= text.rva + text.vsize
        assert r.size == r.end - r.begin


def test_pdata_records_are_unwind_regions_not_functions(od, o2):
    """The assumption worth pinning: a record is not a function."""
    od_truth = TRUTH["od"]
    # a leaf function (no frame, no call) appears in the truth but has no record at all
    assert "add_mul" in od_truth["no_record"]
    starts = {f["rva"] for f in od_truth["functions"]}
    recorded = {r.begin for r in od.runtime_functions()}
    assert recorded < starts, "every .pdata start should be a function start, but not vice versa"

    # and one function can be described by several records
    assert TRUTH["o2"]["multi_record"] == ["pipeline"]
    assert len(o2.runtime_functions()) == 4


def test_unwind_regions_merges_chaininfo_but_keeps_a_function_size_sane(o2):
    regions = unwind_regions(o2)
    names = {f["name"]: f for f in TRUTH["o2"]["functions"]}
    pipe = next(f for f in regions if f.rva == names["pipeline"]["rva"])
    assert pipe.size == 236, "the three chained records describe one function"
    assert pipe.size < names["pipeline"]["size_upper_bound"], (
        "and .pdata's end is tighter than the map's next-symbol distance, which includes padding")


# --- discovery ------------------------------------------------------------------------------

@pytest.mark.parametrize("tag", ["od", "o2"])
def test_discovery_finds_every_function_and_invents_nothing(tag):
    truth = TRUTH[tag]
    img = PEImage.load(DATA / truth["exe"])
    found = discover(img)
    true_starts = {f["rva"] for f in truth["functions"]}
    got = {f.rva for f in found}
    assert got - true_starts == set(), f"invented: {sorted(hex(a) for a in got - true_starts)}"
    assert true_starts - got == set(), f"missed: {sorted(hex(a) for a in true_starts - got)}"
    assert len(found) == len(true_starts)


def test_the_sources_contribute_in_order_of_trust():
    """.pdata alone is not enough; call targets close most of the gap; the sweep closes it."""
    truth = TRUTH["od"]
    img = PEImage.load(DATA / truth["exe"])
    true_starts = {f["rva"] for f in truth["functions"]}

    pd = {f.rva for f in unwind_regions(img)}
    assert len(pd & true_starts) == 9, "measured: 9 of 15 functions have an unwind record"
    assert len(true_starts - pd) == 6

    with_calls = pd | call_targets(img)
    assert len(with_calls & true_starts) == 14
    assert true_starts - with_calls == {0x1020}, "the one unreferenced function is still missing"

    assert len({f.rva for f in discover(img)} & true_starts) == 15
    assert len(discover(img)) == 15


def test_the_unreferenced_function_is_the_sweeps_only_contribution():
    truth = TRUTH["od"]
    img = PEImage.load(DATA / truth["exe"])
    swept = [f for f in discover(img) if f.source == "sweep"]
    assert [f.rva for f in swept] == [0x1020]
    assert swept[0].size == 32


def test_skipdata_is_required_for_call_targets(od):
    """Regression for the bug that made this find nothing.

    Without skipdata, capstone's disasm() stops at the first undecodable byte. On this
    fixture that is inside .text, so the sweep ended early and every call after it was
    invisible: 8 call targets, 0 found. decompnet.scoring sets skipdata for the same reason.
    """
    import capstone
    from decompnet.pe.discover import _CS_MODE

    base, code = od.code_rva_base(), od.code_bytes()
    md = capstone.Cs(*_CS_MODE)
    md.detail = True
    without = sorted(md.disasm(code, base), key=lambda i: i.address)
    md.skipdata = True
    with_ = sorted(md.disasm(code, base), key=lambda i: i.address)
    assert with_[-1].address > without[-1].address, "skipdata must reach further"
    assert len(call_targets(od)) >= 8, "and that is what reveals the calls"


def test_discovery_can_be_asked_not_to_sweep(od):
    """A caller that trusts only .pdata + calls can say so, and gets no inventions."""
    found = discover(od, use_sweep=False)
    assert all(f.source in ("pdata", "call") for f in found)
    assert 0x1020 not in {f.rva for f in found}
