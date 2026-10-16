"""Generating a PE64 objdiff project, and registering it the way decomp.wtf expects.

The shape is not invented here: `objdiff.json` with `target_dir`/`base_dir`/`custom_make`,
one unit per function, target objects in `target/`, built objects in `build/`. That is what
`forks.clone` already registers and what the app already measures, so an imported executable
becomes an ordinary project rather than a special case.
"""

import json
import subprocess
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.pe import PEImage
from decompnet.pe.coff import build_object
from decompnet.pe.project import build_project, find_cl, inventory, seed_base_objects
from decompnet.pe.tables import table_aware_object

DATA = Path(__file__).parent / "data"
EXE = DATA / "test_od.exe"
TRUTH = {f["rva"]: f["name"] for f in json.loads((DATA / "test_truth.json").read_text())["od"]["functions"]}


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    dest = tmp_path_factory.mktemp("pe64") / "proj"
    meta = build_project(EXE, dest, names=TRUTH, drafts={}, log=lambda *_: None)
    return dest, meta


# --- the inventory --------------------------------------------------------------------------

def test_the_inventory_is_every_recovered_function():
    img = PEImage.load(EXE)
    fns = inventory(img, names=TRUTH)
    assert len(fns) == 15
    assert {f.name for f in fns} == set(TRUTH.values())
    assert all(f.size > 0 and f.rva > 0 for f in fns)
    # a name from the symbol source, and an address-derived one when there is none
    assert [f.name for f in inventory(img)][0].startswith("sub_")


def test_the_inventory_records_how_each_function_was_found():
    """The sweep is the only source that can invent something, so it is labelled."""
    fns = inventory(PEImage.load(EXE), names=TRUTH)
    by = {}
    for f in fns:
        by.setdefault(f.discovered_by, []).append(f)
    assert set(by) == {"pdata", "call", "sweep"}
    assert [f.name for f in by["sweep"]] == ["shifts"], "the unreferenced function"


# --- the generated tree ---------------------------------------------------------------------

def test_the_tree_has_everything_a_project_needs(project):
    dest, meta = project
    for path in ("objdiff.json", "build.ninja", "README.md", ".decomp.wtf.json",
                 "include/ghidra_types.h", "notes/functions.md", ".git"):
        assert (dest / path).exists(), path
    assert (dest / "src" / "sw.c").exists()
    assert (dest / "asm" / "sw.s").exists()
    assert (dest / "target" / "sw.obj").exists()
    assert (dest / "build" / "sw.obj").exists()


def test_objdiff_json_is_the_shape_forks_clone_registers(project):
    dest, meta = project
    cfg = json.loads((dest / "objdiff.json").read_text())
    assert cfg["target_dir"] == "target"
    assert cfg["base_dir"] == "build"
    assert cfg["custom_make"] == "ninja"
    assert cfg["options"]["functionRelocDiffs"] == "none"
    assert len(cfg["units"]) == 15
    for u in cfg["units"]:
        assert u["path"] == f"{u['name']}.obj"
        assert u["metadata"]["source_path"] == f"src/{u['name']}.c"
        assert u["metadata"]["complete"] is False, "nothing is claimed to match on import"


def test_the_target_object_is_the_synthetic_one(project):
    dest, _ = project
    img = PEImage.load(EXE)
    fn = next(f for f in inventory(img, names=TRUTH) if f.name == "sw")
    nxt = min((f.rva for f in inventory(img, names=TRUTH) if f.rva > fn.rva), default=None)
    expected, _r, _t, _n = table_aware_object(img, fn.rva, fn.size, "sw", next_rva=nxt)
    assert (dest / "target" / "sw.obj").read_bytes() == expected


def test_build_ninja_compiles_one_source_per_unit(project):
    dest, _ = project
    ninja = (dest / "build.ninja").read_text()
    assert "rule cc" in ninja
    for name in TRUTH.values():
        assert f"build build/{name}.obj: cc src/{name}.c" in ninja
    assert ninja.count("build build/") == 15


def test_every_unit_has_a_base_object_so_the_project_measures(project):
    """objdiff's report needs one per unit; a missing object takes the whole report down."""
    dest, meta = project
    missing = [f["name"] for f in meta["functions"] if not (dest / "build" / f"{f['name']}.obj").exists()]
    assert missing == []


def test_the_metadata_is_a_real_inventory(project):
    dest, meta = project
    on_disk = json.loads((dest / ".decomp.wtf.json").read_text())
    assert on_disk["kind"] == "pe64-import"
    assert on_disk["source"]["machine"] == "AMD64"
    assert len(on_disk["functions"]) == 15
    assert on_disk["counts"]["functions"] == 15
    assert on_disk["counts"]["with_jump_tables"] == 1, "sw"
    sw = next(f for f in on_disk["functions"] if f["name"] == "sw")
    assert [t for t in sw["jump_tables"]] == [0x1220]
    assert {r["type"] for r in sw["relocations"]} == {3, 4}, "ADDR32NB and REL32"


def test_it_is_a_git_repository_with_one_commit(project):
    """forks.clone() requires a git repo: it clones rather than copies."""
    dest, _ = project
    log = subprocess.run(["git", "log", "--oneline"], cwd=dest, capture_output=True, text=True)
    assert log.returncode == 0 and len(log.stdout.strip().splitlines()) == 1
    status = subprocess.run(["git", "status", "--porcelain"], cwd=dest, capture_output=True, text=True)
    assert status.stdout.strip() == "", "everything is committed, the build included"


def test_a_seeded_object_is_a_one_instruction_stand_in(tmp_path):
    """An unwritten function should read as unfinished, not break the project."""
    (tmp_path / "build").mkdir()
    filled = seed_base_objects(tmp_path, [{"name": "f"}])
    assert filled == ["f"]
    obj = (tmp_path / "build" / "f.obj").read_bytes()
    assert obj == build_object("f", b"\xc3", [])
    assert seed_base_objects(tmp_path, [{"name": "f"}]) == [], "never overwrites a real one"


def test_the_asm_listing_is_the_original_code(project):
    dest, _ = project
    listing = (dest / "asm" / "sw.s").read_text()
    assert "sw:" in listing
    assert "rva 0x11b0" in listing
    assert "mov dword ptr [rsp + 8], ecx" in listing, "the real instructions, not a summary"


@pytest.mark.skipif(find_cl() is None, reason="needs MSVC")
def test_msvc_is_found_for_the_build():
    cl = find_cl()
    assert cl == "cl" or str(cl).endswith("cl.exe")


_objdiff = toolchains.installed("objdiff-cli")
OBJDIFF = str(Path(toolchains.require("objdiff-cli")) / "objdiff-cli") if _objdiff else None


@pytest.mark.skipif(OBJDIFF is None, reason="needs objdiff-cli")
def test_objdiff_can_measure_the_generated_project(project, tmp_path):
    """The end of the pipeline: objdiff reads the generated project and reports on it.

    `report generate` needs a base object for every unit, which is why the stand-ins exist;
    without them one uncompiled source fails the whole report.
    """
    dest, _ = project
    out = tmp_path / "report.json"
    r = subprocess.run([OBJDIFF, "report", "generate", "-p", str(dest), "-o", str(out)],
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, (r.stdout + r.stderr)[-500:]
    rep = json.loads(out.read_text())
    assert rep["measures"]["total_functions"] == 15
    assert rep["measures"]["total_code"] == "1136"
    assert 0.0 <= rep["measures"]["fuzzy_match_percent"] <= 100.0
