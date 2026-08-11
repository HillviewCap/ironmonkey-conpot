#!/usr/bin/env python3
"""PID-1 supervisor that restarts Conpot when its gevent hub is starved.

Why this exists
---------------
Conpot is single-threaded gevent: every protocol (Modbus, S7comm, IEC-104,
HTTP) is a greenlet on one hub. A greenlet that busy-loops without ever
yielding starves the hub, and *all* protocols stop accepting — the ports still
complete a TCP handshake via docker-proxy, so from the outside the sensor looks
alive while capturing nothing.

That is not hypothetical. On 2026-08-07 an unguarded EOF loop in
`IEC104_server.py` wedged the NYC sensor three minutes after deploy and it went
unnoticed for three days, yielding exactly one session. That specific bug is
fixed, but the failure mode is structural to gevent, so this guards the class.

Why a supervisor rather than a Docker HEALTHCHECK
-------------------------------------------------
Docker does not restart a container merely for going unhealthy — `restart:`
only reacts to process exit. And a healthcheck cannot remediate from inside:
the kernel discards signals sent to PID 1 from within its own PID namespace
unless PID 1 installed a handler for them, so a probe cannot kill a wedged
Conpot. Running Conpot as a *child* of this process sidesteps both problems —
a child is an ordinary PID and can simply be killed.

The alternative, an autoheal sidecar, would need the Docker socket mounted on
an internet-exposed, assumed-compromisable box. Not worth it for this.

Detection
---------
Unhealthy requires BOTH signals, sampled every `CHECK_INTERVAL` seconds:

  1. the Conpot child is burning >= `CPU_THRESHOLD` of one core, and
  2. the JSON event log has not grown since the previous sample.

Requiring both is what keeps a real flood — which pins the CPU *and* grows the
log fast — from being read as a wedge and restarted at the worst moment. A
wedged hub logs nothing by definition.

After `STRIKES` consecutive bad samples the child gets SIGTERM, then SIGKILL if
it does not exit within `TERM_GRACE`, and is respawned.

Env knobs: CONPOT_LOG, CHECK_INTERVAL, CPU_THRESHOLD, STRIKES, TERM_GRACE,
HEALTH_FILE. Defaults are set below.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

CONPOT_LOG = os.environ.get("CONPOT_LOG", "/var/log/conpot/conpot.json")
CHECK_INTERVAL = float(os.environ.get("CHECK_INTERVAL", "30"))
CPU_THRESHOLD = float(os.environ.get("CPU_THRESHOLD", "0.95"))
STRIKES = int(os.environ.get("STRIKES", "3"))
TERM_GRACE = float(os.environ.get("TERM_GRACE", "15"))
HEALTH_FILE = os.environ.get("HEALTH_FILE", "/tmp/conpot-health")
# Overridable so the supervisor can be exercised against a stub child.
CONPOT_BIN = os.environ.get("CONPOT_BIN", "conpot")

CLK_TCK = os.sysconf("SC_CLK_TCK")

_child: subprocess.Popen | None = None
_shutting_down = False


def log(msg: str) -> None:
    """Unbuffered stderr so lines interleave correctly with Conpot's own."""
    print(f"[supervisor] {msg}", file=sys.stderr, flush=True)


def _write_health(status: str) -> None:
    """Publish the verdict for the Docker HEALTHCHECK to read.

    Best-effort: a supervisor that cannot write /tmp should keep supervising
    rather than die and take Conpot down with it.
    """
    try:
        with open(HEALTH_FILE, "w") as fh:
            fh.write(status)
    except OSError as exc:
        log(f"could not write {HEALTH_FILE}: {exc}")


def _cpu_ticks(pid: int) -> int | None:
    """utime + stime for `pid`, in clock ticks. None if the process is gone.

    The comm field can contain spaces and parentheses, so split after the
    final ')' rather than on whitespace from the start.
    """
    try:
        with open(f"/proc/{pid}/stat") as fh:
            data = fh.read()
    except OSError:
        return None
    try:
        fields = data[data.rindex(")") + 2 :].split()
        return int(fields[11]) + int(fields[12])
    except (ValueError, IndexError):
        return None


def _log_size() -> int:
    try:
        return os.stat(CONPOT_LOG).st_size
    except OSError:
        return -1


def _spawn(argv: list[str]) -> subprocess.Popen:
    log(f"starting conpot: {' '.join(argv)}")
    return subprocess.Popen(argv)


def _stop_child(proc: subprocess.Popen) -> None:
    """SIGTERM, then SIGKILL after TERM_GRACE. A wedged child ignores TERM."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=TERM_GRACE)
        return
    except subprocess.TimeoutExpired:
        log(f"conpot ignored SIGTERM after {TERM_GRACE}s — sending SIGKILL")
    proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log("conpot survived SIGKILL; giving up on a clean stop")


def _forward_signal(signum, _frame) -> None:
    """Pass shutdown signals to the child so `docker stop` stays clean."""
    global _shutting_down
    _shutting_down = True
    log(f"received signal {signum}; forwarding to conpot")
    if _child is not None and _child.poll() is None:
        _stop_child(_child)


def main() -> int:
    global _child

    argv = [CONPOT_BIN, *sys.argv[1:]]

    signal.signal(signal.SIGTERM, _forward_signal)
    signal.signal(signal.SIGINT, _forward_signal)

    _child = _spawn(argv)
    _write_health("ok")

    prev_ticks = _cpu_ticks(_child.pid)
    prev_size = _log_size()
    prev_time = time.monotonic()
    strikes = 0

    while not _shutting_down:
        time.sleep(CHECK_INTERVAL)
        if _shutting_down:
            break

        rc = _child.poll()
        if rc is not None:
            # Conpot exited on its own. Respawn — this is the same intent as
            # `restart: unless-stopped`, which cannot see inside the container.
            log(f"conpot exited with code {rc}; restarting")
            _child = _spawn(argv)
            prev_ticks = _cpu_ticks(_child.pid)
            prev_size = _log_size()
            prev_time = time.monotonic()
            strikes = 0
            _write_health("ok")
            continue

        now = time.monotonic()
        ticks = _cpu_ticks(_child.pid)
        size = _log_size()
        elapsed = now - prev_time

        if ticks is None or prev_ticks is None or elapsed <= 0:
            prev_ticks, prev_size, prev_time = ticks, size, now
            continue

        cores = (ticks - prev_ticks) / CLK_TCK / elapsed
        log_stalled = size >= 0 and size == prev_size

        if cores >= CPU_THRESHOLD and log_stalled:
            strikes += 1
            log(
                f"wedge suspected ({strikes}/{STRIKES}): "
                f"cpu={cores:.2f} cores, log stalled at {size} bytes"
            )
            _write_health("wedged" if strikes >= STRIKES else "suspect")
        else:
            if strikes:
                log(f"recovered: cpu={cores:.2f} cores, log at {size} bytes")
            strikes = 0
            _write_health("ok")

        if strikes >= STRIKES:
            log("gevent hub starved — restarting conpot")
            _stop_child(_child)
            _child = _spawn(argv)
            ticks = _cpu_ticks(_child.pid)
            size = _log_size()
            now = time.monotonic()
            strikes = 0
            _write_health("ok")

        prev_ticks, prev_size, prev_time = ticks, size, now

    if _child is not None:
        _stop_child(_child)
        return _child.returncode or 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
