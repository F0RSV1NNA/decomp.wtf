#!/usr/bin/env python3
"""Deploy the fork to the main decomp.wtf installation, safely and repeatably.

The git checkout is the source of truth; the installed copy under
`~/.local/share/uv/tools/decompnet/` is a build artefact of it. This is the only thing that
writes between them, and it refuses to run if it cannot first make a verified backup.

    python3 tools/deploy.py                  # full deployment
    python3 tools/deploy.py --dry-run        # show what would happen, change nothing
    python3 tools/deploy.py --skip-tests     # for a docs-only commit (says so in the log)
    python3 tools/deploy.py --rollback /path/to/backup-dir

Order matters and is the whole point: **back up, then test, then replace, then verify**.
Nothing is replaced until the tests pass and the database copy reopens with its contents
intact, because the failure this exists to prevent is destroying a project's history while
trying to deploy a code change.

DECOMP_HOME, the database, settings, projects, notes and agents are never written by this
script except through the app itself. It does not copy any development database anywhere.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG_NAME = "decompnet"
DEFAULT_HOME = Path.home() / "Decomp"
DEFAULT_TOOL = Path.home() / ".local/share/uv/tools/decompnet"
MARKER = "FORK-DEPLOY.json"
BASELINE = REPO / "tools/deploy-baseline.txt"


def log(msg: str) -> None:
    print(msg, flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# --- git ------------------------------------------------------------------------------------

def git_state() -> dict:
    head = run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO)
    subject = run(["git", "log", "-1", "--pretty=%s"], cwd=REPO)
    dirty = run(["git", "status", "--porcelain"], cwd=REPO)
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=REPO)
    return {"commit": head.stdout.strip(), "subject": subject.stdout.strip(),
            "branch": branch.stdout.strip(), "dirty": dirty.stdout.strip(), "repo": str(REPO)}


# --- backup ---------------------------------------------------------------------------------

def backup(home: Path, tool: Path) -> Path:
    """A verified, WAL-consistent copy of everything the deployment could possibly hurt."""
    internal = home / ".decomp"
    db = internal / "decomp.db"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = Path.home() / f"decomp-backup-{stamp}"
    dest.mkdir(parents=True, exist_ok=False)
    log(f"  backing up to {dest}")

    if db.exists():
        # sqlite3's backup API: consistent even with the server writing to it, and it folds in
        # whatever is in the -wal. A plain copy would miss exactly that, which is where the
        # most recent work is.
        src = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        out = sqlite3.connect(dest / "decomp.db")
        with out:
            src.backup(out)
        out.close()
        src.close()
        log(f"    decomp.db  {os.path.getsize(dest / 'decomp.db'):>12,} bytes (backup API)")
    for name in ("settings.json", "server.json"):
        if (internal / name).exists():
            shutil.copyfile(internal / name, dest / name)
            log(f"    {name:<10} {os.path.getsize(dest / name):>12,} bytes")

    internal_path = home.resolve()
    for entry in sorted(home.iterdir()):
        if entry.name == ".decomp" or not entry.is_dir():
            continue
        tar = dest / f"{entry.name}.tar.gz"
        with tarfile.open(tar, "w:gz") as t:
            t.add(entry, arcname=entry.name)
        log(f"    {tar.name:<10} {os.path.getsize(tar):>12,} bytes")
    agents = internal / "agents"
    if agents.exists():
        with tarfile.open(dest / "agents.tar.gz", "w:gz") as t:
            t.add(agents, arcname="agents")

    if (tool / PKG_NAME).exists():
        shutil.copytree(tool / f"lib/python3.12/site-packages/{PKG_NAME}",
                        dest / "installed-package", ignore=shutil.ignore_patterns("__pycache__"))
        log("    installed package kept")
    return dest


def verify_backup(dest: Path) -> dict:
    """The backup is worthless unless it reopens with the work still in it."""
    db = dest / "decomp.db"
    if not db.exists():
        raise SystemExit(f"  no database in the backup ({dest})")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    check = con.execute("PRAGMA integrity_check").fetchone()[0]
    rows = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("projects", "functions", "attempts", "claims")}
    projects = [r["slug"] for r in con.execute("SELECT slug FROM projects")]
    matched = con.execute("SELECT COUNT(*) FROM functions WHERE status='matched'").fetchone()[0]
    con.close()
    if check != "ok":
        raise SystemExit(f"  backup failed integrity_check: {check}")
    log(f"    integrity_check ok | {rows['functions']} functions, {matched} matched, "
        f"{rows['attempts']} attempts | projects {projects}")
    return {"integrity": check, "counts": rows, "projects": projects, "matched": matched}


# --- tests ----------------------------------------------------------------------------------

def test_failures(python: str) -> set[str]:
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    res = subprocess.run([python, "-m", "pytest", "tests", "-q", "--tb=no", "-p", "no:cacheprovider"],
                         cwd=REPO, env=env, capture_output=True, text=True, timeout=3600)
    tail = (res.stdout + res.stderr).strip().splitlines()
    log("    " + (tail[-1] if tail else "no output"))
    return {l.split(" - ")[0].strip() for l in res.stdout.splitlines()
            if l.startswith(("FAILED", "ERROR"))}


def run_tests(python: str, *, force: bool) -> None:
    log("  running the test suite against the checkout")
    failures = test_failures(python)
    if not BASELINE.exists():
        log(f"    no baseline at {BASELINE}; recording {len(failures)} known failure(s)")
        BASELINE.write_text("".join(f"{f}\n" for f in sorted(failures)), encoding="utf-8")
        return
    known = {l.strip() for l in BASELINE.read_text(encoding="utf-8").splitlines() if l.strip()}
    new = failures - known
    if new and not force:
        log(f"    {len(new)} NEW failure(s), which the baseline does not know about:")
        for f in sorted(new):
            log(f"      {f}")
        raise SystemExit("  refusing to deploy a regression. Fix it, or pass --force to override.")
    log(f"    {len(failures)} failure(s), all in the baseline of {len(known)}")


# --- install --------------------------------------------------------------------------------

def install_files(tool: Path, home: Path) -> Path:
    site = tool / "lib/python3.12/site-packages"
    pkg, fork = site / PKG_NAME, REPO / "src" / PKG_NAME
    if not fork.is_dir():
        raise SystemExit(f"  no package at {fork}")
    keep = site / f"{PKG_NAME}.previous"
    if keep.exists():
        shutil.rmtree(keep)
    if pkg.exists():
        log(f"  keeping the current installed package at {keep.name}")
        shutil.copytree(pkg, keep, ignore=shutil.ignore_patterns("__pycache__"))
    log(f"  copying {fork} -> {pkg}")
    for src in fork.rglob("*"):
        if "__pycache__" in src.parts or src.is_dir():
            continue
        rel = src.relative_to(fork)
        dst = pkg / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    for pc in list(pkg.rglob("__pycache__")):
        shutil.rmtree(pc, ignore_errors=True)
    return keep


def mark_deployed(tool: Path, state: dict) -> None:
    """Leave a record that this install is the fork, so an upstream update is not silent."""
    site = tool / "lib/python3.12/site-packages"
    (site / MARKER).write_text(json.dumps(
        {"fork": state["repo"], "commit": state["commit"], "branch": state["branch"],
         "deployed": time.time()}, indent=2) + "\n", encoding="utf-8")
    log(f"  wrote {site / MARKER} (an upstream update now warns instead of replacing silently)")


def health(port: int, tries: int = 30) -> str | None:
    for _ in range(tries):
        time.sleep(2)
        r = run(["curl", "-s", "-m", "3", f"http://127.0.0.1:{port}/health"])
        if r.stdout.strip():
            return r.stdout.strip()
    return None


def mcp_tools(name: str = "deploy-check") -> list[str]:
    """Ask the MCP bridge for its tool list, the way a client does: handshake, then list."""
    bridge = Path.home() / ".local/bin/decomp"
    if not bridge.exists():
        return []
    script = "".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": name, "version": "1"}}}) + "\n",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n",
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n",
    ])
    proc = subprocess.Popen([str(bridge), "mcp", "--name", name], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        out, _ = proc.communicate(script, timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        return []
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg.get("result"), dict) and "tools" in msg["result"]:
            return [t["name"] for t in msg["result"]["tools"]]
    return []


def restart(tool: Path, home: Path, port: int) -> None:
    import signal

    state_file = home / ".decomp" / "server.json"
    if state_file.exists():
        pid = json.loads(state_file.read_text())["pid"]
        log(f"  stopping the server (pid {pid})")
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        for _ in range(20):
            time.sleep(1)
            if not run(["curl", "-s", "-m", "2", f"http://127.0.0.1:{port}/health"]).stdout.strip():
                break
    log(f"  starting it again on {port}")
    subprocess.Popen([str(tool / "bin/python"), "-m", "decompnet.app.cli",
                      "--port", str(port), "--no-browser"],
                     cwd=str(home), env=dict(os.environ, DECOMP_HOME=str(home)),
                     stdout=open("/tmp/decomp-deploy.log", "wb"), stderr=subprocess.STDOUT,
                     stdin=subprocess.DEVNULL, start_new_session=True)


def preflight(tool: Path, home: Path) -> None:
    if not (tool / "lib/python3.12/site-packages" / PKG_NAME).exists():
        raise SystemExit(f"  no decompnet installed under {tool}")
    if not home.is_dir():
        raise SystemExit(f"  DECOMP_HOME {home} does not exist")
    if not (home / ".decomp" / "decomp.db").exists():
        log(f"  note: {home}/.decomp/decomp.db does not exist yet; a fresh one will be made")


def deploy(args) -> int:
    tool = Path(args.tool)
    home = Path(args.home)
    state = git_state()
    log(f"deploying {state['repo']}")
    log(f"  branch {state['branch']}  commit {state['commit']}  {state['subject']}")
    if state["dirty"] and not args.allow_dirty:
        log("  the checkout has uncommitted changes:")
        for line in state["dirty"].splitlines()[:12]:
            log("    " + line)
        raise SystemExit("  commit them first, or pass --allow-dirty. The checkout is the "
                         "source of truth, so what is deployed has to be a commit.")
    preflight(tool, home)
    if args.dry_run:
        log("  dry run: nothing was written")
        return 0

    log("1. backup")
    dest = backup(home, tool)
    info = verify_backup(dest)

    if not args.skip_tests:
        log("2. tests")
        run_tests(str(tool / "bin/python"), force=args.force)
    else:
        log("2. tests SKIPPED (--skip-tests)")

    log("3. install")
    keep = install_files(tool, home)
    mark_deployed(tool, state)

    log("4. restart and verify")
    restart(tool, home, args.port)
    h = health(args.port)
    if not h:
        log(f"    the server did not answer; see /tmp/decomp-deploy.log")
        log(f"    ROLLBACK: tools/deploy.py --rollback {dest}")
        return 1
    log(f"    health: {h}")
    tools_found = mcp_tools()
    log(f"    MCP tools: {len(tools_found)}" + (f" ({', '.join(tools_found[:6])}...)" if tools_found else ""))
    if len(tools_found) < 20:
        log("    WARNING: fewer tools than expected; check the bridge")
    log(f"    database: {info['counts']['functions']} functions, {info['matched']} matched, "
        f"projects {info['projects']}")

    log("")
    log(f"deployed commit {state['commit']}")
    log(f"  backup   : {dest}")
    log(f"  previous : {keep}")
    log(f"  rollback : {Path(__file__).resolve()} --rollback {dest}")
    return 0


def rollback(args) -> int:
    dest = Path(args.rollback)
    tool = Path(args.tool)
    home = Path(args.home)
    site = tool / "lib/python3.12/site-packages"
    pkg = site / PKG_NAME
    backup_pkg = dest / "installed-package"
    if not backup_pkg.is_dir():
        raise SystemExit(f"  {dest} has no installed-package: cannot roll the code back")
    log(f"rolling the code back from {backup_pkg}")
    if pkg.exists():
        shutil.rmtree(pkg)
    shutil.copytree(backup_pkg, pkg)
    marker = site / MARKER
    if marker.exists():
        marker.unlink()
    log("  code restored. The database was NOT touched.")
    log(f"  its copy is at {dest}/decomp.db if you need it:")
    log(f"    {dest}/decomp.db  (replace {home}/.decomp/decomp.db only if you mean to)")
    restart(tool, home, args.port)
    log(f"  health: {health(args.port)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tool", default=str(DEFAULT_TOOL))
    ap.add_argument("--home", default=os.environ.get("DECOMP_HOME", str(DEFAULT_HOME)))
    ap.add_argument("--port", type=int, default=6464)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--force", action="store_true", help="deploy despite new test failures")
    ap.add_argument("--allow-dirty", action="store_true")
    ap.add_argument("--rollback", default="")
    return rollback(ap.parse_args()) if "--rollback" in sys.argv else deploy(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
