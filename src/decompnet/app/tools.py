"""The tools a decompiling agent gets, served over MCP to CLI agents and called directly by the
built-in API agent. Every tool works on the project the agent was started on."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Callable

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .. import __version__
from ..network import Agent, NetworkError
from .engine import RomNetwork

GUIDES = {
    "workflow": "the matching loop, reading diffs, priorities",
    "mips": "MIPS registers, calling convention, delay slots, types from instructions",
    "gcc-kmc": "matching KMC GCC 2.7.2 code",
    "ido": "matching IDO 5.3/7.1 code",
    "m2c": "reading the machine-generated draft",
    "data": "globals, strings, tables, floats, data you define",
    "structs": "working out struct layouts from offsets",
    "n64": "N64 memory map, OS library, graphics/audio data",
    "naming": "naming functions and data",
    "fork": "working in a fork of a public decomp: the loop, conventions, what's allowed",
    "objdiff": "reading objdiff's diffs and match percentages",
    "ppc": "PowerPC (GameCube, Wii): registers, calling convention, common patterns",
    "mwcc": "matching Metrowerks CodeWarrior code (GameCube, Wii, DS)",
    "cpp": "decompiling C++: classes, vtables, constructors, inlines, name mangling",
    "psx": "matching PlayStation (PSY-Q GCC + maspsx) code",
    "ps2": "matching PlayStation 2 (EE-GCC, MWCC PS2) code",
    "arm": "ARM and Thumb (GBA, DS, 3DS): registers, conditional code, literal pools",
    "agbcc": "matching Game Boy Advance code built with agbcc",
    "x86": "x86 and MSVC (PC, Xbox): calling conventions, SEH, matching MSVC output",
    "aarch64": "AArch64 and Clang (Switch): registers, matching Clang output",
    "similarity": "finding similar functions and reusing matched code",
}

# Guides worth reading first on each platform.
PLATFORM_GUIDES = {
    "n64": ["mips"], "ps": ["mips", "psx"], "ps2": ["mips", "ps2"], "psp": ["mips"],
    "gc": ["ppc", "mwcc", "cpp"], "wii": ["ppc", "mwcc", "cpp"], "nds": ["arm", "mwcc"], "3ds": ["arm", "cpp"],
    "gba": ["arm", "agbcc"], "switch": ["aarch64", "cpp"], "win32": ["x86", "cpp"], "xbox": ["x86", "cpp"],
    "xbox360": ["ppc", "cpp"],
}

INSTRUCTIONS = """\
decomp.wtf: you are decompiling a game ROM that the user owns into C that compiles to exactly the same
machine code. Your C is compiled with the game's original compiler, linked at the function's real address
and compared with the ROM: score 0 means byte-identical, and the function is saved as matched.
Start with project_info, then claim_function -> compile_and_diff (repeat). guide(topic) has know-how.
Everything runs on the user's computer. The game's code is the user's: never publish it anywhere.
"""

WORK_PROMPT = """\
You are a decompilation agent in decomp.wtf, working on {title}. Other agents may be working on other
functions of the same game at the same time; the tools keep you from colliding.

Your job: turn functions of this game into C that compiles to *exactly* the original machine code.
Use only the decomp tools. Repeat for up to {count} claims (a batch is one), then stop:

1. claim_function(count=4) gives you the next function, and when it's small, its neighbours with it (small
   functions mostly match on the first try): assembly, location, calls, data it uses, the best previous
   attempt and notes (start from those!), a machine-generated draft, and identical matched code if any.
2. get_context() shows the shared header every compile includes.
3. Write the C functions (same names as the assembly) and judge them: compile_and_diff(function="a, b, c",
   source=all the definitions) for a batch, one name for one. Read the diff: '<' '>' missing/extra
   instructions, 'i' operands, 'o' order, 'r' registers, 's' stack. Fix structure first, registers last.
   The workflow and {compiler_guide} guides are below. find_similar(function) shows look-alike functions;
   a matched one is the best starting point.
4. Score 0 = matched and saved. Before moving on, share what you learned: edit_context for prototypes and
   structs you worked out, rename_symbol for functions/data whose purpose is now clear, and add_note (no
   function) for a compiler quirk or convention every agent here should know: the next sessions start with it.
5. compile_and_diff says when to move on (no better after 4 compiles in a row; up to 10 for big functions):
   then release_function with precise notes (what you tried, what is left) and claim the next one.

Write plausible original code, pure C (no inline asm). Be brief in your messages: work, don't narrate.
"""

FORK_PROMPT = """\
You are a decompilation agent in decomp.wtf, continuing {title}: a public matching-decompilation project
for {platform}. Other agents may be working on other functions of the same project at the same time; the
tools keep you from colliding.

Your job: write functions in the project's own source files so they compile to *exactly* the original
machine code, judged by objdiff. Use only the decomp tools. Repeat for up to {count} claims (a batch is one), then stop:

1. claim_function(count=4) gives you the next function, and when it's small, its neighbours in the same
   file (small functions mostly match on the first try): target assembly, the current diff, its source
   file, the best previous attempt and notes (start from those!), functions already matched in that file,
   and identical matched code elsewhere if there is any.
2. The brief usually has what you need. When it doesn't: read_file on the source file and its headers,
   search_code for the types, structs and helpers it uses. Reuse what exists; never redefine it.
   find_similar(function) finds look-alike functions: start from a matched one.
3. compile_and_diff(function, source) with the complete definition (plus any #include "...", prototypes
   or #pragma lines it needs); several at once: function="a, b, c" with all definitions in source. Each
   goes into the source file in place of the old one, the file is built with the project's compiler and
   diffed. Fix structure first (control flow, calls), then types and expressions, registers last.
4. 100% = matched, committed to git. Structs, prototypes, globals or helpers you need go in with
   edit_file (a header or the top of the source file); an edit that breaks any match is undone. Found a
   compiler quirk or project convention others should know? add_note with no function: every new session
   starts with those notes.
5. The goal is linked files: the game built from the C, byte for byte. When a match finishes a file's
   functions, you're shown its data next to the original's: fix what differs (order, const, statics,
   values) with edit_file until file_status says it matches; decomp.wtf then links the file.
6. compile_and_diff says when to move on (no better after 4 compiles in a row; up to 10 for big functions):
   then release_function with precise notes (what you tried, what is left) and claim the next. Very large
   functions: get the structure right first; a near miss is worth the extra compiles.

Rules: C/C++ only (no inline asm, asm functions or asm includes); don't touch targets, configs or build
scripts (the tools refuse). Write code a human would have written: match the file's style and names.
Guides: {guides}. Be brief in your messages: work, don't narrate.
"""


def _guide(topic: str = "") -> str:
    topic = topic.strip().lower()
    if topic not in GUIDES:
        listing = "\n".join(f"- {k}: {v}" for k, v in GUIDES.items())
        return f"Guides (call guide with one of these topics):\n{listing}"
    return resources.files("decompnet.app").joinpath("guide", f"{topic}.md").read_text(encoding="utf-8")


def _fork(net: RomNetwork, slug: str, what: str) -> str:
    if not net.fork_slug(slug):
        raise NetworkError(f"{what} is for forks of public decomps; in a ROM project the shared header is get_context")
    return slug


def project_info(net: RomNetwork, slug: str) -> str:
    wish = net.instructions(slug)
    text = _project_info(net, slug)
    return text + (f"\nThe user's instructions for this project (they come first):\n{wish}" if wish else "")


def _project_info(net: RomNetwork, slug: str) -> str:
    if net.fork_slug(slug):
        return net.forks.info(slug)
    ov = net.overview(slug)
    pct = 100 * ov["matched_bytes"] / (ov["bytes"] or 1)
    return (f"{ov['title']} ({ov['rom']['game_code']}, {ov['rom']['region']})\n"
            f"compiler: {ov['compiler']['name']} {' '.join(ov['compiler']['flags'])}\n"
            f"progress: {ov['matched']}/{ov['functions']} functions matched ({pct:.1f}% of code), "
            f"{ov['attempts']} compiles so far, context.h v{ov['context_version']}\n"
            f"Next: claim_function(). Guides: guide().")


# name -> handler(net, agent, slug, **args); every handler returns text for the model
def _claim(net: RomNetwork, agent: Agent, slug: str, function: str, strategy: str, count: int = 1) -> str:
    """A claim; one asked for that's matched, hand-written assembly or someone else's is the next free function
    instead (an agent asking for those has nothing better to do than the next one, and is told why). count > 1: a
    batch of small ones."""
    strategy = strategy or ("finish" if net.fork_slug(slug) else "easiest")
    if not function and int(count or 1) > 1:
        return net.claim_many(agent, slug, int(count), strategy)
    try:
        return net.claim(agent, slug, function or None, strategy)
    except NetworkError as e:
        if not function or not re.search(r"already matched|is hand-written assembly|is claimed by", str(e)):
            raise
        return f"({e}. Here's the next free function instead.)\n\n" + net.claim(agent, slug, None, strategy)


def _compile(net: RomNetwork, agent: Agent, slug: str, function: str, source: str) -> str:
    """compile_and_diff; several names ("a, b, c") judge several definitions sent together."""
    names = [n.strip() for n in function.split(",") if n.strip()]
    if len(names) <= 1:
        return net.compile_and_diff(agent, names[0] if names else function, source, slug)
    return net.attempt_many(agent, [net.resolve_function(agent, slug, n) for n in names], source, slug)


def _pe_home(net) -> Path:
    from ..pe import service as pe

    return pe.decomp_home(net)


def _pe_create(net, path: str, project_name: str = "") -> str:
    """Create an application project from one EXE or DLL. Returns the slug."""
    from ..pe import service as pe

    binary = Path(path)
    if not binary.is_file():
        return f"error: no file at {binary} (give a path this computer can read)"
    result = pe.create(project_name or binary.stem, binary, _pe_home(net), net, log=lambda m: None)
    return (f"created {result['slug']} from {binary.name} with module(s) "
            f"{', '.join(result['modules'])}. Open it with open_project(\"{result['slug']}\").")


def _pe_module_add(net, path: str, project: str = "", session_slug: str = "") -> str:
    """Add an EXE or DLL to an existing application project."""
    from ..pe import service as pe

    slug = project or session_slug
    if not slug:
        return "error: give the project to add the module to"
    binary = Path(path)
    if not binary.is_file():
        return f"error: no file at {binary} (give a path this computer can read)"
    result = pe.add_module(net, slug, binary, _pe_home(net), log=lambda m: None)
    added = ", ".join(result["added"]) or "(nothing new: that module is already in the project)"
    return f"{slug} now has {len(result['modules'])} module(s): {', '.join(result['modules'])}. Added {added}."


def _pe_modules(net, project: str = "", session_slug: str = "") -> str:
    """What an application project is made of."""
    from ..pe import service as pe

    slug = project or session_slug
    if not slug:
        return "error: give a project"
    row = net.project_row(slug)
    dest = Path(row["root"])
    if not pe.is_application(dest):
        return f"{slug} is not a Windows application project (it has no modules)."
    mods = pe.modules(dest)
    lines = [f"{slug}: {len(mods)} module(s)"]
    for m in mods:
        lines.append(f"  {m['name']}  {m['kind']} {m['arch']}  image base {m['image_base']}  "
                     f"{m['functions']} functions  sha1 {m['sha1'][:12]}")
        lines.append(f"    imports: {', '.join(m['imports']) or 'none'}"
                     + (f" (not supplied: {', '.join(m['unresolved'])})" if m["unresolved"] else ""))
    lines.append(f"Functions are named <module>_<symbol>; use get_pe_module_functions(\"{slug}\", "
                 f"\"{mods[0]['name'] if mods else ''}\") to list one module's.")
    return "\n".join(lines)


def _pe_functions(net, module: str, project: str = "", session_slug: str = "", status: str = "") -> str:
    """One module's functions and where each one actually stands."""
    from ..pe import service as pe

    slug = project or session_slug
    if not slug:
        return "error: give a project"
    dest = Path(net.project_row(slug)["root"])
    if not pe.is_application(dest):
        return f"{slug} is not a Windows application project."
    rows = [r for r in pe.function_status(dest, net, slug) if r["module"] == module]
    if not rows:
        return f"no module {module!r} in {slug}. Modules: " + ", ".join(pe.module_names(dest))
    if status:
        rows = [r for r in rows if r["status"] == status]
    head = pe.status_summary([r for r in pe.function_status(dest, net, slug) if r["module"] == module])
    lines = [f"{slug}/{module}: {head['functions']} functions — {head['matched']} matched, "
             f"{head['compiled']} compiled, {head['failed']} draft failed, {head['untried']} untried",
             f"({head['stand_ins']} object(s) in build/ are stand-ins so objdiff can run; they are "
             f"not compiled candidates.)"]
    for r in rows[:60]:
        note = f"  {r['error']}" if r["error"] else ""
        lines.append(f"  {r['symbol']:<28} rva {r['rva']:<10} {r['size']:>4}B  {r['status']:<9}"
                     f" found by {r['discovered_by']}{note}")
    if len(rows) > 60:
        lines.append(f"  ... and {len(rows) - 60} more")
    return "\n".join(lines)


def _pe_status(net, project: str = "", session_slug: str = "") -> str:
    """How far along an application project is, honestly."""
    from ..pe import service as pe

    slug = project or session_slug
    if not slug:
        return "error: give a project"
    info = pe.import_status(net, slug)
    if not info.get("application"):
        return f"{slug} is not a Windows application project."
    s = info["summary"]
    lines = [f"{slug}: {len(info['modules'])} module(s), {s['functions']} functions",
             f"  matched  {s['matched']}   (byte-identical)",
             f"  compiled {s['compiled']}   (the compiler accepted the C in src/)",
             f"  failed   {s['failed']}   (a draft exists and does not compile)",
             f"  untried  {s['untried']}   (nothing written for it yet)",
             f"  {s['stand_ins']} stand-in object(s) in build/ so objdiff can produce a report. "
             f"Anything measured against those is not progress."]
    for m in info["modules"]:
        lines.append(f"  module {m['name']}: {m['functions']} functions, {m['kind']} {m['arch']}")
    if s["with_errors"]:
        lines.append("  first compiler errors:")
        for r in [r for r in info["functions"] if r["error"]][:5]:
            lines.append(f"    {r['symbol']}: {r['error']}")
    return "\n".join(lines)


def _pe_repair(net, module: str = "", project: str = "", symbol: str = "",
                session_slug: str = "") -> str:
    """Repair drafts that do not compile."""
    from ..pe import service as pe

    slug = project or session_slug
    if not slug:
        return "error: give a project"
    symbols = [symbol] if symbol else None
    result = pe.repair_functions(net, slug, module=module, symbols=symbols, log=lambda *_: None)
    lines = [f"{result['repaired']} of {result['attempted']} draft(s) now compile"]
    for o in result["outcomes"]:
        lines.append(f"  {o['symbol']}: {o['before']} -> {o['after']}")
        for r in o["repairs"]:
            lines.append(f"    - {r['rule']}: {r['change']}" + ("  [ASSUMED]" if r.get("assumed") else ""))
            lines.append(f"      why: {r['why']}")
        for d in o["deferred"][:4]:
            lines.append(f"    ! {d}")
    if not result["attempted"]:
        lines.append("  (nothing to repair: every draft compiles)")
    return "\n".join(lines)


def _pe_repair_history(net, project: str = "", symbol: str = "", session_slug: str = "") -> str:
    """Every repair applied so far, with its justification and its assumptions."""
    from ..pe import service as pe

    slug = project or session_slug
    if not slug:
        return "error: give a project"
    rows = pe.repair_module_history(Path(net.project_row(slug)["root"]))
    if symbol:
        rows = [r for r in rows if r["symbol"] == symbol]
    if not rows:
        return f"{slug}: no repairs recorded"
    lines = [f"{slug}: {len(rows)} function(s) with a repair record"]
    for r in rows:
        lines.append(f"  {r['symbol']}: {r['before']} -> {r['after']}")
        for x in r["repairs"]:
            lines.append(f"    - {x['rule']}: {x['change']}" + ("  [ASSUMED]" if x.get("assumed") else ""))
        for d in r["deferred"][:3]:
            lines.append(f"    ! {d}")
    return "\n".join(lines)


HANDLERS: dict[str, Callable[..., str]] = {
    "project_info": lambda net, agent, slug: project_info(net, slug),
    "claim_function": lambda net, agent, slug, function="", strategy="", count=1:
        _claim(net, agent, slug, function, strategy, count),
    "get_function": lambda net, agent, slug, function: net.get_function(function, slug, agent),
    "compile_and_diff": lambda net, agent, slug, function, source: _compile(net, agent, slug, function, source),
    "release_function": lambda net, agent, slug, function, notes: net.release(agent, function, notes, slug),
    "get_context": lambda net, agent, slug, function="": net.get_context(slug, function or None),
    "edit_context": lambda net, agent, slug, old, new, message, function="":
        net.edit_context(agent, slug, old, new, message, function or None),
    "rename_symbol": lambda net, agent, slug, old, new, message="": net.rename_symbol(agent, slug, old, new, message),
    "split_function": lambda net, agent, slug, function, at, new_name="":
        net.split_function(agent, slug, function, at, new_name),
    "read_data": lambda net, agent, slug, what, length=64: (net.forks.read_data(agent, slug, what, length)
                                                            if net.fork_slug(slug) else net.read_data(slug, what, length)),
    "list_functions": lambda net, agent, slug, status="open", limit=40: net.list_functions(slug, status, limit),
    "add_note": lambda net, agent, slug, text, function="": net.add_note(agent, slug, text, function or None),
    "search_notes": lambda net, agent, slug, query: net.search_notes(slug, query),
    "find_similar": lambda net, agent, slug, function, limit=5: net.find_similar(slug, function, limit),
    "guide": lambda net, agent, slug, topic="": _guide(topic),
    "read_file": lambda net, agent, slug, path, start=1, count=200:
        net.forks.read_file(_fork(net, slug, "read_file"), path, start, count),
    "search_code": lambda net, agent, slug, pattern, glob="": net.forks.search(_fork(net, slug, "search_code"), pattern, glob),
    "edit_file": lambda net, agent, slug, path, old, new, message:
        net.forks.edit_file(agent, _fork(net, slug, "edit_file"), path, old, new, message),
    "file_status": lambda net, agent, slug, path: net.forks.file_status(_fork(net, slug, "file_status"), path),
    "split_file": lambda net, agent, slug, path, at, new_name="", data="":
        net.forks.split_file(agent, _fork(net, slug, "split_file"), path, at, new_name, data),
    # Windows (PE64) application projects: the same pe/service.py the browser routes call.
    "create_pe_project": lambda net, agent, slug, path, project_name="": _pe_create(net, path, project_name),
    "add_pe_module": lambda net, agent, slug, path, project="": _pe_module_add(net, path, project, slug),
    "list_pe_modules": lambda net, agent, slug, project="": _pe_modules(net, project, slug),
    "get_pe_module_functions": lambda net, agent, slug, module, project="", status="":
        _pe_functions(net, module, project, slug, status),
    "get_pe_import_status": lambda net, agent, slug, project="": _pe_status(net, project, slug),
    "repair_pe_draft": lambda net, agent, slug, module="", project="", symbol="":
        _pe_repair(net, module, project, symbol, slug),
    "get_pe_repair_history": lambda net, agent, slug, project="", symbol="":
        _pe_repair_history(net, project, symbol, slug),
}

ROM_ONLY = {"get_context", "edit_context", "rename_symbol", "split_function"}
FORK_ONLY = {"read_file", "search_code", "edit_file", "file_status", "split_file"}


def tool_names(fork: bool) -> list[str]:
    """The tools that make sense for a project: forks and ROM projects share the core loop."""
    skip = ROM_ONLY if fork else FORK_ONLY
    return [n for n in HANDLERS if n not in skip]


def _named(net: RomNetwork, agent: Agent, slug: str, args: dict) -> dict:
    """Function names as agents write them (a plain symbol that repeats across files, symbol@unit, Class::method)
    turned into the stored name, preferring the function the agent holds."""
    if args.get("function") and "," not in args["function"]:  # (several are resolved one by one, see _compile)
        args = {**args, "function": net.resolve_function(agent, slug, args["function"])}
    return args


def call(net: RomNetwork, agent: Agent, slug: str, name: str, args: dict) -> str:
    """Run one tool for the built-in agent; errors come back as text the model can act on."""
    if name not in HANDLERS:
        return f"error: unknown tool {name!r}"
    try:
        return HANDLERS[name](net, agent, slug, **_named(net, agent, slug, args))
    except NetworkError as e:
        return f"error: {e}"
    except TypeError as e:
        return f"error: bad arguments for {name}: {e}"


# Antigravity CLI otherwise finds MCP tools on demand (an extra step each, through its generic dispatcher):
# decomp.wtf's tools are all there is to the job, so they are loaded up front.
ALWAYS_LOAD = {"antigravity/alwaysLoad": True}


def build_mcp(net: RomNetwork, agent_of: Callable[[Context], tuple[Agent, str]]) -> MCPServer:
    """MCP server for CLI agents. `agent_of` maps a request to (agent, project slug)."""
    mcp = MCPServer(name="decomp", title="decomp.wtf", instructions=INSTRUCTIONS, version=__version__)

    async def run(ctx: Context, name: str, **args) -> str:
        try:
            agent, slug = agent_of(ctx)
        except NetworkError as e:
            raise ToolError(str(e)) from None
        try:
            return await anyio.to_thread.run_sync(lambda: HANDLERS[name](net, agent, slug, **_named(net, agent, slug, args)))
        except NetworkError as e:
            raise ToolError(str(e)) from None

    async def run_pe(ctx: Context, name: str, **args) -> str:
        """Project-level tools that do not belong to whichever project the session is in:
        creating one has to work before there is one."""
        try:
            agent, slug = agent_of(ctx)
        except NetworkError:
            agent, slug = None, ""
        try:
            return await anyio.to_thread.run_sync(
                lambda: HANDLERS[name](net, agent, slug, **args))
        except NetworkError as e:
            raise ToolError(str(e)) from None

    @mcp.tool(meta=ALWAYS_LOAD)
    async def project_info(ctx: Context) -> str:
        """Which game you're working on, its compiler, and progress so far."""
        return await run(ctx, "project_info")

    @mcp.tool(meta=ALWAYS_LOAD)
    async def claim_function(ctx: Context, function: str = "", strategy: str = "", count: int = 1) -> str:
        """Claim the next function to decompile (or a specific one by name or address).

        Returns its assembly, the best previous attempt and notes from earlier agents, plus (ROM projects)
        calls, data and a machine-made draft or (forks) the current diff and its source file. Each compile
        renews the claim.

        Args:
            function: optional name or address (0x80001234) of a specific function
            strategy: finish (forks' default: the files closest to being linked first), easiest (fewest
                instructions; ROM projects' default), closest (nearly matched already), hardest, random
            count: up to 6: small functions come as a batch (neighbours in one file) to write together and
                judge in one compile_and_diff; a big one comes alone
        """
        return await run(ctx, "claim_function", function=function, strategy=strategy, count=count)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_function(ctx: Context, function: str) -> str:
        """Show any function (by name or address): assembly, status, best attempt, notes. Read matched
        functions to learn how this codebase is written."""
        return await run(ctx, "get_function", function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def compile_and_diff(ctx: Context, function: str, source: str) -> str:
        """Compile your code for `function` and diff it against the original; score 0 = byte-identical.

        ROM projects: compiled with the game's compiler (context.h included), linked at the function's
        address and compared with the ROM. Forks: send the complete definition (plus any #include "...",
        prototypes, externs or #pragma lines it needs); it replaces the function in its source file, which is
        built with the project's build system and diffed with objdiff. Several functions ("a, b, c"): send all
        their definitions in one source; each is judged on its own."""
        return await run(ctx, "compile_and_diff", function=function, source=source)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def release_function(ctx: Context, function: str, notes: str) -> str:
        """Give up a function you're stuck on. Notes are required: what you tried, what is left. Your best
        attempt is kept for the next agent."""
        return await run(ctx, "release_function", function=function, notes=notes)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_context(ctx: Context, function: str = "") -> str:
        """The shared header (types, structs, prototypes) included before every compile."""
        return await run(ctx, "get_context", function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def edit_context(ctx: Context, old: str, new: str, message: str, function: str = "") -> str:
        """Edit the shared header: replace `old` (must occur exactly once) with `new`, or append `new` when
        old is "". Accepted only if every matched function still matches. Add prototypes and structs here."""
        return await run(ctx, "edit_context", old=old, new=new, message=message, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def rename_symbol(ctx: Context, old: str, new: str, message: str = "") -> str:
        """Give a function or data address a real name (e.g. func_80001234 -> player_update). Updates the
        assembly everyone sees, matched sources and the header; never breaks a match."""
        return await run(ctx, "rename_symbol", old=old, new=new, message=message)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def split_function(ctx: Context, function: str, at: str, new_name: str = "") -> str:
        """Split a function the disassembler merged with the next one (e.g. after a function that never
        returns). `at` is the address where the second function starts."""
        return await run(ctx, "split_function", function=function, at=at, new_name=new_name)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def read_data(ctx: Context, what: str, length: int = 64) -> str:
        """Hex dump of the original's data: an address or symbol (ROM projects), a data symbol such as
        lbl_1_data_10 (forks); text, pointers and floats decoded."""
        return await run(ctx, "read_data", what=what, length=length)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def list_functions(ctx: Context, status: str = "open", limit: int = 40) -> str:
        """List functions by status: open, matched or all."""
        return await run(ctx, "list_functions", status=status, limit=limit)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def add_note(ctx: Context, text: str, function: str = "") -> str:
        """Leave a note for other agents, on a function or the whole project."""
        return await run(ctx, "add_note", text=text, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def search_notes(ctx: Context, query: str) -> str:
        """Search notes left by agents."""
        return await run(ctx, "search_notes", query=query)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def find_similar(ctx: Context, function: str, limit: int = 5) -> str:
        """Functions whose instructions look like this one's (copy-pasted code, the same inlined helper,
        template instances), matched ones first, with the matching source of the best one. Start there."""
        return await run(ctx, "find_similar", function=function, limit=limit)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def guide(ctx: Context, topic: str = "") -> str:
        """Decompilation know-how. Call without a topic for the list (workflow, mips, gcc-kmc, ido, m2c,
        data, structs, n64, naming)."""
        return await run(ctx, "guide", topic=topic)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def read_file(ctx: Context, path: str, start: int = 1, count: int = 200) -> str:
        """Forks only: read a file of the project (path relative to its root), with line numbers."""
        return await run(ctx, "read_file", path=path, start=start, count=count)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def search_code(ctx: Context, pattern: str, glob: str = "") -> str:
        """Forks only: search the project's C/C++ sources and headers with a regular expression. `glob`
        narrows the files (e.g. "include/**/*.h")."""
        return await run(ctx, "search_code", pattern=pattern, glob=glob)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def edit_file(ctx: Context, path: str, old: str, new: str, message: str) -> str:
        """Forks only: change a C/C++ source or header file. Replace `old` (exactly once) with `new`, or
        append `new` when old is "". The project is rebuilt and measured; the edit is undone if any matched
        function stops matching. Use it for structs, prototypes, globals and helpers."""
        return await run(ctx, "edit_file", path=path, old=old, new=new, message=message)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def file_status(ctx: Context, path: str) -> str:
        """Forks only: how far a source file (or a function's file) is from being linked into the game: which
        functions still differ, its data next to the original's (with what to fix), why the last link failed.
        A file is linked (the game built from its C) once every function and all its data match."""
        return await run(ctx, "file_status", path=path)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def split_file(ctx: Context, path: str, at: str, new_name: str = "", data: str = "") -> str:
        """Forks only (GameCube/Wii): divide a source file in two where the game's original files divided: the
        function `at` (name or .text offset) and every one after it in the file go to a new file `new_name`
        (default: text_<offset> next to it), with their C. `data` moves the end of each data section too
        (".rodata:0x88 .data:0x28": where the new file's part starts; file_status shows the ranges). Kept only if
        the game still builds byte for byte and every match still matches. A file links only when its code and
        data are exactly one original file's."""
        return await run(ctx, "split_file", path=path, at=at, new_name=new_name, data=data)

    @mcp.prompt(title="Decompile", description="Work loop: claim functions and match them byte for byte.")
    def work(count: str = "5") -> str:
        return "Call project_info first, then follow the decomp.wtf work loop for up to " + count + " functions."

    @mcp.tool(meta=ALWAYS_LOAD)
    async def create_pe_project(ctx: Context, path: str, project_name: str = "") -> str:
        """Create a project from a Windows EXE or DLL at a path on this computer.

        Analysis is static: the file is read and disassembled, never run. Discovery, synthetic
        objdiff targets and Ghidra drafts are generated, and the project opens like any other.
        Do not send the file itself -- give a path the server can read.

        Args:
            path: full path to the .exe or .dll (e.g. /home/me/apps/app.exe)
            project_name: optional name for the project (defaults to the file's name)
        """
        return await run_pe(ctx, "create_pe_project", path=path, project_name=project_name)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def add_pe_module(ctx: Context, path: str, project: str = "") -> str:
        """Add another EXE or DLL to an application project, keeping the modules already in it.

        Sources, notes, claims, attempts and scores of the existing modules are untouched.

        Args:
            path: full path to the .exe or .dll
            project: the project slug (defaults to the project this session is in)
        """
        return await run_pe(ctx, "add_pe_module", path=path, project=project)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def list_pe_modules(ctx: Context, project: str = "") -> str:
        """The modules of an application project: kind, architecture, image base and how many
        functions each has."""
        return await run_pe(ctx, "list_pe_modules", project=project)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_pe_module_functions(ctx: Context, module: str, project: str = "", status: str = "") -> str:
        """One module's functions, with where each one actually stands.

        status is one of matched, compiled, failed, untried, or empty for all. 'compiled' means
        the compiler accepted C someone wrote; an object in build/ that is not listed as compiled
        is a stand-in put there so objdiff can run, and measuring against it is not progress.

        Args:
            module: the module name, as list_pe_modules gives it
            project: the project slug (defaults to this session's)
            status: filter by status
        """
        return await run_pe(ctx, "get_pe_module_functions", module=module, project=project, status=status)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_pe_import_status(ctx: Context, project: str = "") -> str:
        """How far along an application project is: modules, and functions matched / compiled /
        draft-failed / untried, with the first compiler errors."""
        return await run_pe(ctx, "get_pe_import_status", project=project)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def repair_pe_draft(ctx: Context, module: str = "", symbol: str = "", project: str = "") -> str:
        """Repair Ghidra drafts that do not compile, using the compiler's own diagnostics.

        Deterministic and bounded: missing declarations, absent types and unknown globals are
        supplied from the diagnostic and the name; nothing is invented to silence an error. A
        source file a person has edited is left untouched. A repair that makes something compile
        is still only a candidate -- objdiff decides whether it matches.

        Args:
            module: the module to repair (empty for all of them)
            symbol: one function (empty for every draft that fails)
            project: the project slug (defaults to this session's)
        """
        return await run_pe(ctx, "repair_pe_draft", module=module, symbol=symbol, project=project)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_pe_repair_history(ctx: Context, symbol: str = "", project: str = "") -> str:
        """Every repair applied to a project: what changed, why, and what was assumed."""
        return await run_pe(ctx, "get_pe_repair_history", symbol=symbol, project=project)

    return mcp
