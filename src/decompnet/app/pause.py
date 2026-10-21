"""Pausing a project.

Pausing is not stopping the application: it is stopping the machines *inside* it that spend
money or CPU on one project. Three of them:

    API agents   the only thing that makes a billable provider call (app/agents.py _run_api)
    autopilot    free, but it schedules work on its own for as long as the app runs
    Permuter     free, but it burns spare CPU looking for near-misses

The state lives in the project's own `config`, so it survives a restart, applies per project
rather than per server, and needs no schema change.

**Resuming restores eligibility; it does not restart anything.** A pause that resumed by
starting eight paid agents would make pausing a trap, so resuming only clears the flag: agents
run again when something asks for them. `was_running` records what was running at the moment of
the pause so the UI can say what stopping cost, without acting on it.

Every place a worker can start checks this, because a guard in one place is not a guard:

    Manager._prepare     forbids the Permuter starting itself after agents claim
    Manager.start        refuses to launch a new session for a paused project
    Permuter.start       the near-miss search does not begin
    autopilot            scheduling stops at the top of the run and inside the loop
"""

from __future__ import annotations

import json
import time


def is_paused(net, slug: str) -> bool:
    """Whether this project is paused. Unknown projects read as not paused: the guard must not
    take down a caller that is merely asking about a slug that has gone."""
    if not slug:
        return False
    try:
        row = net.store.one("SELECT config FROM projects WHERE slug=?", slug)
    except Exception:
        return False
    if not row:
        return False
    try:
        return bool(json.loads(row["config"] or "{}").get("paused"))
    except (TypeError, ValueError):
        return False


def paused_reason(net, slug: str) -> str:
    row = net.store.one("SELECT config FROM projects WHERE slug=?", slug)
    if not row:
        return ""
    try:
        return json.loads(row["config"] or "{}").get("paused_reason", "") or ""
    except (TypeError, ValueError):
        return ""


def set_paused(net, slug: str, paused: bool, *, reason: str = "", log=print) -> dict:
    """Pause or resume one project. Returns its new state."""
    row = net.store.one("SELECT id, config FROM projects WHERE slug=?", slug)
    if not row:
        raise ValueError(f"no project {slug}")
    cfg = json.loads(row["config"] or "{}")
    if paused and not cfg.get("paused"):
        # what was running when it was paused, so the UI can say what resuming would not restart
        cfg["was_running"] = _running(net, slug)
    cfg["paused"] = bool(paused)
    if paused:
        cfg["paused_at"] = time.time()
        if reason:
            cfg["paused_reason"] = reason
    else:
        cfg.pop("paused_at", None)
        cfg.pop("paused_reason", None)
    net.store.conn.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), row["id"]))
    net.store.conn.commit()
    log(f"{slug}: {'paused' if paused else 'resumed'}")
    if paused:
        stopped = _stop(net, slug, log=log)
        cfg["stopped"] = stopped
    return cfg


def state(net, slug: str) -> dict:
    """What the UI shows: running, paused, or stopped, and what is actually alive."""
    from . import agents as agents_mod  # noqa: F401  (kept for symmetry; manager is passed in)

    row = net.store.one("SELECT config FROM projects WHERE slug=?", slug)
    cfg = {}
    if row:
        try:
            cfg = json.loads(row["config"] or "{}")
        except (TypeError, ValueError):
            cfg = {}
    running = _running(net, slug)
    paused = bool(cfg.get("paused"))
    return {
        "slug": slug,
        "paused": paused,
        "paused_at": cfg.get("paused_at"),
        "reason": cfg.get("paused_reason", ""),
        # three states, not two: a project with nothing running is not "paused", it is idle
        "state": "paused" if paused else ("running" if running else "stopped"),
        "running": running,
        "was_running": cfg.get("was_running") or [],
        "autopilot": bool((net.autopilot_status(slug) or {}).get("running")) if hasattr(net, "autopilot_status") else False,
        "permuter": _permuter_running(net, slug),
    }


def _running(net, slug: str) -> list[str]:
    """The API/CLI agent sessions alive for this project."""
    try:
        manager = getattr(net, "agents", None) or getattr(net, "manager", None)
        if manager is None:
            return []
        return sorted(getattr(s, "name", "") or getattr(s, "kind", "")
                      for s in manager.sessions(slug) if getattr(s, "alive", True))
    except Exception:
        return []


def _permuter_running(net, slug: str) -> bool:
    try:
        return bool(net.permuter.running(slug))
    except Exception:
        return False


def _stop(net, slug: str, *, log=print) -> list[str]:
    """Stop what a pause has to stop. Each is independent: one failing must not leave the
    others running, so they are tried in turn and the result is reported."""
    stopped = []
    try:
        if hasattr(net, "stop_autopilot"):
            net.stop_autopilot(slug)
            stopped.append("autopilot")
    except Exception as e:
        log(f"{slug}: could not stop autopilot: {e}")
    try:
        net.permuter.stop(slug)
        stopped.append("permuter")
    except Exception as e:
        log(f"{slug}: could not stop the permuter: {e}")
    try:
        manager = getattr(net, "agents", None) or getattr(net, "manager", None)
        if manager is not None:
            manager.stop(slug)
            stopped.append("agents")
    except Exception as e:
        log(f"{slug}: could not stop the agents: {e}")
    log(f"{slug}: stopped {', '.join(stopped) or 'nothing (none was running)'}")
    return stopped
