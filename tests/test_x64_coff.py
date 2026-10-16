"""Windows x64 (COFF) objects in a fork: matching must not depend on an ELF reader.

objdiff-cli reads every object format decomp.wtf works with, so a fork can be built with
MSVC or clang-cl and produce x86-64 COFF objects. The literal check that runs for a function
that reaches 100% (forks/literals.py) compares MIPS and PowerPC data and therefore only ever
reads ELF. pyelftools raises ELFError on a COFF object -- and ELFError is not an OSError or a
ValueError, so it escaped `except (OSError, ValueError)` in mismatches().

The effect was the worst possible place to fail: objdiff.diff() calls literals.mismatches()
only when match_percent >= 100, so *every function that matched* in a COFF project raised
instead of being recorded as matched. Nothing could ever match.

These tests pin both halves: a COFF pair gives no verdict instead of raising, and the ELF
path the check exists for still finds a real literal mismatch.
"""

import struct
import subprocess
from io import BytesIO

import pytest

from decompnet import toolchains
from decompnet.forks import literals

# --- a real (if small) x86-64 COFF object, built by hand so the test needs no Windows tools -

TEXT = bytes.fromhex("8d044df9ffffff03c203c1c3")  # add_mul: lea eax,[rcx*2-7]; add; add; ret
SEC_OFF, RAW_OFF, SYM_OFF, STR_OFF = 20, 60, 72, 90


def _coff_object() -> bytes:
    """One .text section holding `add_mul`, one symbol, as MSVC/clang-cl emit it."""
    header = struct.pack("<HHIIIHH", 0x8664, 1, 0, SYM_OFF, 1, 0, 0)  # AMD64, 1 section, 1 symbol
    section = b".text\0\0\0" + struct.pack("<IIIIIIHHI", len(TEXT), 0, len(TEXT), RAW_OFF, 0, 0, 0, 0, 0x60500020)
    symbol = b"add_mul\0".ljust(8, b"\0") + struct.pack("<IhHBB", 0, 1, 0x20, 2, 0)  # value, sec, type, storage, naux
    assert len(header) == SEC_OFF and len(section) == 40
    return header + section + TEXT + symbol + struct.pack("<I", 4)  # 4 = empty string table's size field


def test_the_fixture_really_is_a_coff_object():
    obj = _coff_object()
    assert obj[:2] == b"\x64\x86"  # IMAGE_FILE_MACHINE_AMD64
    assert obj[RAW_OFF:RAW_OFF + len(TEXT)] == TEXT


def test_pyelftools_refuses_coff_with_a_type_the_old_guard_missed():
    """The premise of the bug: the exception is neither an OSError nor a ValueError."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    with pytest.raises(ELFError):
        ELFFile(BytesIO(_coff_object()))
    assert not issubclass(ELFError, (OSError, ValueError)), (
        "if ELFError were an OSError/ValueError the old guard would have caught it, and this test is moot")


def test_a_coff_pair_gives_no_literal_verdict(tmp_path):
    """The regression: this is the call objdiff.diff() makes for every function at 100%.

    It must answer 'no verdict' -- not raise. Before the fix this raised ELFError, so no
    function in a COFF project could ever be saved as matched.
    """
    obj = _coff_object()
    (tmp_path / "target.obj").write_bytes(obj)
    (tmp_path / "base.obj").write_bytes(obj)
    got = literals.mismatches(tmp_path / "target.obj", tmp_path / "base.obj", "add_mul",
                              [(0, "lea"), (7, "add"), (9, "add")])
    assert got == []


def test_a_non_elf_file_gives_no_literal_verdict(tmp_path):
    """Not an object at all: still no verdict rather than a crash."""
    (tmp_path / "a.o").write_bytes(b"not an object")
    (tmp_path / "b.o").write_bytes(b"not an object")
    assert literals.mismatches(tmp_path / "a.o", tmp_path / "b.o", "f", []) == []


def test_a_missing_file_gives_no_literal_verdict(tmp_path):
    assert literals.mismatches(tmp_path / "gone.o", tmp_path / "gone2.o", "f", []) == []


# --- the ELF path the check exists for must still work -------------------------------------

MIPS_ASM = """\
\t.set noreorder
\t.set noat
\t.section .rodata
\t.align 3
\t.globl slot
slot:
\t.word 0x{lo:08X}, 0x{hi:08X}
\t.text
\t.align 2
\t.globl read_it
\t.type read_it,@function
\t.ent read_it
read_it:
\tlui $at, %hi(slot)
\tldc1 $f0, %lo(slot)($at)
\tjr $ra
\tnop
\t.end read_it
.Lfe:
\t.size read_it,.Lfe-read_it
"""

needs_kmc = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None,
                              reason="needs gcc-2.7.2-kmc")


def _mips_object(where, value: float):
    """A MIPS object whose `read_it` loads `value` from .rodata (big-endian doubles)."""
    where.mkdir(parents=True, exist_ok=True)
    tc = toolchains.require("gcc-2.7.2-kmc")
    lo, hi = struct.unpack(">II", struct.pack(">d", value))  # the .word pair as the assembler sees it
    src = where / "lit.s"
    src.write_text(MIPS_ASM.format(lo=lo, hi=hi))
    obj = where / "lit.o"
    subprocess.run([str(tc / "as"), "-mips3", "-EB", "-o", str(obj), str(src)], check=True, capture_output=True)
    return obj


@needs_kmc
def test_a_real_mips_literal_mismatch_is_still_found(tmp_path):
    """The check exists to catch 'loads 1.1 where the original loads 2.2'. Fixing the COFF crash
    by disabling the check would be a silent regression, so this pins that it still fires."""
    found = literals.mismatches(_mips_object(tmp_path / "a", 2.2), _mips_object(tmp_path / "b", 1.1),
                                "read_it", [(0, "lui"), (4, "ldc1")])
    assert len(found) == 1, found
    assert found[0].mnemonic == "ldc1"


@needs_kmc
def test_identical_mips_objects_have_no_mismatch(tmp_path):
    obj = _mips_object(tmp_path, 2.2)
    assert literals.mismatches(obj, obj, "read_it", [(0, "lui"), (4, "ldc1")]) == []
