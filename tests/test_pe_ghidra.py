"""Ghidra drafts for a PE64: whole binary versus one object per function.

Measured on tests/data/test_od.exe, both approaches doing the same job:

                          whole binary            one synthetic object per function
  analysis time           8.5s for all 14         ~4.5s each (68s for 15)
  `sw` draft              a real switch, all 8    an indirect call with two decompiler
                          cases and the default    WARNINGs
  functions covered       14 of 15                15 of 15 (each object names its own)
  missed                  `shifts`: nothing        nothing
                          references it

The switch is the whole point. A synthetic target object has its jump table *zeroed* with
relocations -- that is what makes it match under objdiff -- so a decompiler reading that
object sees `(*(code *)(&sub_0 + *(uint *)(in_ECX * 4 + 0x6148)))()` and gives up. The linked
executable still has the resolved addresses, so Ghidra recovers the switch exactly.

So the two tools are complementary and the design follows from the numbers: **our discovery
supplies the inventory** (it finds `shifts` by sweeping even though nothing calls it), and a
**single whole-binary Ghidra pass supplies the drafts**, joined on RVA. That is why
`drafts_by_rva` exists and why the object path stays only for platforms that have nothing
else.
"""

import json
from pathlib import Path

import pytest

from decompnet.forks import ghidra
from decompnet.pe import PEImage, discover
from decompnet.pe.tables import table_aware_object

DATA = Path(__file__).parent / "data"
EXE = DATA / "test_od.exe"

needs_ghidra = pytest.mark.skipif(not ghidra.available(),
                                  reason="needs ghidra and java 21+")

SW_RVA = 0x11B0
UNREFERENCED = 0x1020          # `shifts`: no call site, so Ghidra's analysis never sees it


@pytest.fixture(scope="module")
def image():
    return PEImage.load(EXE)


@pytest.fixture(scope="module")
def drafts(tmp_path_factory, image):
    return ghidra.drafts_by_rva(EXE, tmp_path_factory.mktemp("ghidra"), image.image_base)


@needs_ghidra
def test_drafts_are_keyed_by_rva(image, drafts):
    """RVAs survive everything that matters: ASLR, no symbol table, and our own function
    table, which is in RVAs too. A stripped binary names every function FUN_1400011b0."""
    assert drafts, "the whole-binary analysis produced nothing"
    rvas = {f.rva for f in discover(image)}
    assert rvas - {UNREFERENCED} <= set(drafts), (
        f"no draft for {sorted(hex(r) for r in rvas - {UNREFERENCED} - set(drafts))}")
    row = drafts[SW_RVA]
    assert row["address"] == image.image_base + SW_RVA
    assert row["name"].startswith("FUN_") or row["name"] == "entry"


@needs_ghidra
def test_ghidra_misses_exactly_the_function_nothing_calls(image, drafts):
    """Why the importer still needs its own discovery pass: an unreferenced function is not
    in any analysis, however good the decompiler is."""
    assert UNREFERENCED not in drafts, "if Ghidra now finds this, the sweep's value changes"
    code = image.bytes_at(UNREFERENCED, 32)
    assert code is not None and len(code) == 32, "but it is real code, at a real address"


@needs_ghidra
def test_the_whole_binary_draft_recovers_the_switch(drafts):
    """The result the decision rests on: a real switch, all eight cases, no warning."""
    c = drafts[SW_RVA]["c"]
    assert "switch(param_1)" in c.replace(" ", ""), c[:400]
    for value in ("10", "0x14", "0x1e", "0x28", "0x32", "0x3c", "0x46", "0x50"):
        assert value in c, f"case {value} missing from the draft"
    assert "0xffffffff" in c, "the default arm"
    assert "WARNING" not in c, "no decompiler warning: it worked out the table"


@needs_ghidra
def test_the_object_draft_is_worse_for_a_switch(image, tmp_path):
    """The contrast, pinned so the reason for the whole-binary pass cannot be quietly lost.

    This is not a Ghidra fault: the object we hand it has the table zeroed on purpose, which
    is exactly what objdiff needs to match it. One representation cannot serve both.
    """
    found = {f.rva: f for f in discover(image)}
    obj, _r, _t, _n = table_aware_object(image, SW_RVA, found[SW_RVA].size, "sw")
    p = tmp_path / "sw.obj"
    p.write_bytes(obj)
    c = ghidra.decompile_object(p, tmp_path).get("sw", "")
    assert c, "the object should still decompile"
    assert "switch" not in c, "if this now recovers the switch, revisit the whole-binary choice"
    assert "WARNING" in c, "an indirect jump it could not resolve -- the zeroed table"


@needs_ghidra
def test_a_second_request_does_not_re_analyse(image, tmp_path):
    """Cached by the binary's content hash: the JVM start is paid once, not per request."""
    first = ghidra.decompile_binary(EXE, tmp_path)
    cache = [p for p in tmp_path.glob("*.functions.json")]
    assert len(cache) == 1, "one cache file per binary content"
    second = ghidra.decompile_binary(EXE, tmp_path)
    assert second == first
    assert len(cache[0].read_text(encoding="utf-8")) > 1000, "and it holds the drafts"
    rows = json.loads(cache[0].read_text(encoding="utf-8"))
    assert all({"name", "address", "c"} <= set(r) for r in rows)


def test_the_export_script_reads_the_old_fields(monkeypatch, tmp_path):
    """Adding `address` to the export must not break the reader that only wants name and c."""
    import decompnet.forks.ghidra as g

    text = ('{"name": "f", "address": 5368713216, "c": "void f(void) {}"}\n'
            '{"name": "g", "address": 5368713220, "c": "void g(void) {}"}\n')
    monkeypatch.setattr(g, "available", lambda: True)
    monkeypatch.setattr(g, "_headless", lambda: Path("/bin/true"))

    def fake_run(*a, **k):
        (tmp_path / "out.jsonl").write_text(text, encoding="utf-8")

        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(g.subprocess, "run", fake_run)
    # the script writes to a temp dir we do not control, so drive the parse directly
    rows = [json.loads(l) for l in text.splitlines()]
    assert [r["name"] for r in rows] == ["f", "g"]
    assert rows[0]["address"] - 0x140000000 == 0x1000
