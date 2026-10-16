"""An application project: many modules, one identity, no collisions.

The fixtures are a purpose-built pair -- `app.exe` and `plugin.dll`, both compiled /Od from
sources whose function bodies are identical -- so their functions land at the *same addresses*:
0x1000, 0x1020, 0x1040 and 0x10a0 exist in both. That is the case a single-module project
cannot hold: decomp.wtf identifies a function by `UNIQUE(project_id, name)`, so unqualified they
would collide in the database and one module's work would land on the other's row. The symbol
carries the module for that reason, and these tests are what stops that being quietly undone.

Nothing here is destructive: `add_module` stages into `.staging/<id>/` and moves files in only
once they are all written.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from decompnet.pe import appproject as ap

DATA = Path(__file__).parent / "data"
APP, PLUGIN = DATA / "app.exe", DATA / "plugin.dll"

pytestmark = pytest.mark.skipif(not (APP.exists() and PLUGIN.exists()),
                                reason="needs the two-module fixture")

# the addresses both modules genuinely share
COLLIDING = [0x1000, 0x1020, 0x1040, 0x10A0]


@pytest.fixture
def project(tmp_path):
    dest = tmp_path / "app"
    ap.create_application_project(dest, "appfix", log=lambda *_: None)
    return dest


# --- creating -------------------------------------------------------------------------------

def test_a_new_project_has_no_modules_and_is_idempotent(project):
    man = ap.load_manifest(project)
    assert man["kind"] == "pe64-application"
    assert man["modules"] == []
    assert (project / "objdiff.json").exists()
    assert json.loads((project / "objdiff.json").read_text())["units"] == []
    again = ap.create_application_project(project, "something else", log=lambda *_: None)
    assert again["name"] == "appfix", "an existing project is left alone"


# --- adding modules -------------------------------------------------------------------------

def test_a_module_is_identified_by_its_content_not_its_name(project):
    ap.add_module(project, APP, log=lambda *_: None)
    m = ap.load_manifest(project)["modules"][0]
    assert m["id"] == m["sha1"][:16], "the id is the content hash"
    assert len(m["sha1"]) == 40
    assert m["kind"] == "exe" and m["arch"] == "AMD64"
    assert m["image_base"] == "0x140000000"
    assert m["counts"]["functions"] == 5
    assert (project / m["binary"]).exists(), "the binary is kept with the project"


def test_two_modules_keep_their_colliding_functions_apart(project):
    ap.add_module(project, APP, log=lambda *_: None)
    ap.add_module(project, PLUGIN, log=lambda *_: None)
    man = ap.load_manifest(project)
    assert [m["name"] for m in man["modules"]] == ["app", "plugin"]

    app_fns = {f["rva"] for f in man["modules"][0]["functions"]}
    dll_fns = {f["rva"] for f in man["modules"][1]["functions"]}
    shared = sorted(app_fns & dll_fns)
    assert shared == COLLIDING, "the fixture must actually collide, or it proves nothing"

    symbols = [f["symbol"] for m in man["modules"] for f in m["functions"]]
    assert len(symbols) == len(set(symbols)), f"symbols collide: {symbols}"
    for rva in COLLIDING:
        a = next(f for f in man["modules"][0]["functions"] if f["rva"] == rva)
        b = next(f for f in man["modules"][1]["functions"] if f["rva"] == rva)
        assert a["symbol"] == f"app_sub_{rva:x}"
        assert b["symbol"] == f"plugin_sub_{rva:x}"


def test_module_paths_and_unit_names_carry_the_module(project):
    ap.add_module(project, APP, log=lambda *_: None)
    ap.add_module(project, PLUGIN, log=lambda *_: None)
    units = json.loads((project / "objdiff.json").read_text())["units"]
    assert len(units) == 9
    assert len({u["name"] for u in units}) == 9, "unit names must be unique"
    for u in units:
        module = u["metadata"]["module"]
        assert u["path"].startswith(f"{module}/"), u["path"]
        assert u["metadata"]["source_path"].startswith(f"src/{module}/")
        assert (project / "target" / u["path"]).exists(), "objdiff would fail to open this"
    for module in ("app", "plugin"):
        assert (project / "src" / module).is_dir()
        assert (project / "asm" / module).is_dir()


# --- duplicates and preservation ------------------------------------------------------------

def test_re_importing_the_same_binary_does_not_duplicate(project):
    ap.add_module(project, APP, log=lambda *_: None)
    before = ap.load_manifest(project)
    ap.add_module(project, APP, log=lambda *_: None)
    after = ap.load_manifest(project)
    assert len(after["modules"]) == len(before["modules"]) == 1
    assert len(ap.all_units(after)) == len(ap.all_units(before)) == 5
    assert after["modules"][0]["sha1"] == before["modules"][0]["sha1"]


def test_the_same_content_under_another_filename_is_still_the_same_module(project, tmp_path):
    """Identity is the hash, so a copy is a refresh -- not a second module."""
    ap.add_module(project, APP, log=lambda *_: None)
    copy = tmp_path / "renamed.dll"
    shutil.copyfile(APP, copy)
    ap.add_module(project, copy, log=lambda *_: None)
    assert len(ap.load_manifest(project)["modules"]) == 1


def test_adding_a_module_preserves_the_other_modules_work(project):
    """The point of the staging directory: a second module must not disturb the first."""
    ap.add_module(project, APP, log=lambda *_: None)
    # work done on the first module, of the kind that must survive
    src = project / "src" / "app" / "app_sub_1000.c"
    src.write_text("/* reconstructed by hand */\nint app_sub_1000(void) { return 1; }\n",
                   encoding="utf-8")
    score = project / "src" / "app" / ".scored"
    score.write_text("100", encoding="utf-8")
    names_before = sorted(p.name for p in (project / "src" / "app").glob("*"))

    ap.add_module(project, PLUGIN, log=lambda *_: None)

    assert src.read_text(encoding="utf-8").startswith("/* reconstructed by hand */")
    assert score.read_text(encoding="utf-8") == "100"
    assert sorted(p.name for p in (project / "src" / "app").glob("*")) == names_before
    assert (project / "src" / "plugin").is_dir(), "and the new module arrived"
    assert len(ap.load_manifest(project)["modules"]) == 2


def test_a_second_module_does_not_lose_the_first_modules_units(project):
    ap.add_module(project, APP, log=lambda *_: None)
    first = {u["name"] for u in ap.all_units(ap.load_manifest(project))}
    ap.add_module(project, PLUGIN, log=lambda *_: None)
    now = {u["name"] for u in ap.all_units(ap.load_manifest(project))}
    assert first < now, f"app's units disappeared: {first - now}"


# --- imports across modules -----------------------------------------------------------------

def test_cross_module_imports_are_recorded_and_resolved(project):
    ap.add_module(project, APP, log=lambda *_: None)
    app = ap.load_manifest(project)["modules"][0]
    assert "plugin.dll" in app["imports"], "app.exe must actually import the dll"
    assert "plugin.dll" in app["unresolved"], "nothing provides it yet"

    ap.add_module(project, PLUGIN, log=lambda *_: None)
    app = ap.load_manifest(project)["modules"][0]
    assert app["unresolved"] == [], "the dll now provides it"
    assert app["imports"]["plugin.dll"] == ["plugin_entry"]


def test_an_import_no_module_provides_is_recorded_not_fatal(project, tmp_path):
    """An import table naming a DLL we do not have is normal, and analysis does not need it."""
    man = ap.load_manifest(project)
    entry = {"name": "x", "binary": "binaries/x.exe", "imports": {"kernel32.dll": ["x"], "gone.dll": []}}
    assert ap.unresolved_imports(entry, []) == ["gone.dll", "kernel32.dll"]
    assert ap.unresolved_imports(entry, [{"name": "kernel32", "binary": "binaries/kernel32.dll"}]) == ["gone.dll"]


def test_delay_imports_are_recorded():
    """Data directory 13, kept beside the normal ones. Absent here, so it is an empty map."""
    from decompnet.pe import PEImage
    img = PEImage.load(APP)
    assert ap.delay_imports(img) == {}
    assert img.imports()["plugin.dll"] == ["plugin_entry"]


# --- the build ------------------------------------------------------------------------------

def test_every_unit_has_a_base_object(project):
    """objdiff's report needs one per unit; one missing object fails the whole report."""
    ap.add_module(project, APP, log=lambda *_: None)
    ap.add_module(project, PLUGIN, log=lambda *_: None)
    for u in ap.all_units(ap.load_manifest(project)):
        assert (project / "build" / u["path"]).exists(), u["path"]
    assert json.loads((project / "objdiff.json").read_text())["custom_make"] == "ninja"


def test_analyze_module_rediscovers_without_touching_files(project):
    ap.add_module(project, APP, log=lambda *_: None)
    m = ap.load_manifest(project)["modules"][0]
    before = sorted(p.name for p in (project / "src" / "app").glob("*"))
    again = ap.analyze_module(project, m["id"], log=lambda *_: None)
    assert len(again["functions"]) == 5
    assert sorted(p.name for p in (project / "src" / "app").glob("*")) == before


def test_rebuild_module_refuses_an_unknown_module(project):
    ap.add_module(project, APP, log=lambda *_: None)
    with pytest.raises(KeyError):
        ap.rebuild_module(project, "nosuchid", log=lambda *_: None)


# --- the legacy destructive path ------------------------------------------------------------

def test_the_legacy_single_binary_builder_refuses_to_eat_an_application_project(project):
    """project.build_project opens with rmtree(dest). Once a project can hold several modules
    that would destroy every one of them, so it now refuses rather than doing it."""
    from decompnet.pe.project import build_project
    ap.add_module(project, APP, log=lambda *_: None)
    before = len(ap.load_manifest(project)["modules"])
    with pytest.raises(Exception) as e:
        build_project(APP, project, log=lambda *_: None)
    assert "application project" in str(e.value).lower()
    assert len(ap.load_manifest(project)["modules"]) == before, "still intact"


# --- objdiff, end to end --------------------------------------------------------------------

_objdiff = __import__("decompnet.toolchains", fromlist=["x"])
OBJDIFF = str(Path(_objdiff.require("objdiff-cli")) / "objdiff-cli") if _objdiff.installed("objdiff-cli") else None


@pytest.mark.skipif(OBJDIFF is None, reason="needs objdiff-cli")
def test_objdiff_measures_the_whole_two_module_project(project, tmp_path):
    ap.add_module(project, APP, log=lambda *_: None)
    ap.add_module(project, PLUGIN, log=lambda *_: None)
    out = tmp_path / "report.json"
    r = subprocess.run([OBJDIFF, "report", "generate", "-p", str(project), "-o", str(out)],
                       capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, (r.stdout + r.stderr)[-400:]
    m = json.loads(out.read_text())["measures"]
    assert m["total_units"] == 9
    assert m["total_functions"] == 9
    assert int(m["total_code"]) > 0
