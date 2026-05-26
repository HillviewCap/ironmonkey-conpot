"""Conpot → IronPot log forwarder (Story 17.3 AC #4, #6).

Tails /var/log/conpot/conpot.json, maps each JSON record to the IronPot
HoneypotEvent schema, and POSTs to IronPot. Runs as a sidecar container in
the same compose stack as Conpot (shared /var/log/conpot volume).

Correlation strategy (Redis-breadcrumb approach from Story 17.3 Dev Notes):
  When IronPot processes an IT (Honeygo) event, it writes:
    honeypot:breadcrumb:<source_ip> → <session_id>  (TTL 900s)
  This forwarder reads that key when it sees an OT event from the same IP
  and includes the parent_session_id in the POST payload, letting IronPot
  emit the STIX `relationship` linking IT→OT.

Resilience:
  - Inode-tracking tail: detects log rotation and reopens the file
  - Bounded retry with linear backoff on POST failures
  - structlog JSON output so the container logs are grep-able
"""

import json
import os
import sys
import time
from typing import Any

import httpx
import redis
import structlog

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
log = structlog.get_logger()

IRONPOT_URL = os.environ.get("IRONPOT_URL", "http://localhost:8003")
WEBHOOK_TOKEN = os.environ.get("HONEYPOT_WEBHOOK_TOKEN", "")
SENSOR_ID = os.environ.get("SENSOR_ID", "sensor-lab-snakeplskn-01-ot")
CONPOT_LOG = os.environ.get("CONPOT_LOG", "/var/log/conpot/conpot.json")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
POST_MAX_RETRIES = int(os.environ.get("POST_MAX_RETRIES", "3"))
POST_BACKOFF_SECONDS = float(os.environ.get("POST_BACKOFF_SECONDS", "2"))
# Where to spool events when IronPot is unreachable after POST_MAX_RETRIES.
# Lives on a dedicated forwarder-owned volume (`forwarder-dead-letter` ->
# /var/spool/conpot-forwarder) so the unprivileged forwarder user can append
# without colliding with conpot's UID on the shared log volume.
# Empty string disables the dead-letter spool (kept for tests / local dev).
DEAD_LETTER_PATH = os.environ.get(
    "DEAD_LETTER_PATH", "/var/spool/conpot-forwarder/dead-letter.jsonl"
)
# Soft size cap. When the spool grows past this many bytes, rotate the file
# to <path>.1 (clobbering any prior .1) and start fresh. Bounds on-disk usage
# at 2x cap. 0 disables rotation (file grows unboundedly). Default 50 MB.
MAX_DEAD_LETTER_BYTES = int(os.environ.get("MAX_DEAD_LETTER_BYTES", str(50 * 1024 * 1024)))

# Conpot binds internally to non-privileged ports; the host exposes standard
# OT ports via Docker port mappings. Conpot's log records local.port from the
# inside, so we normalize to the standard port the attacker actually hit.
_PORT_MAP: dict[int, int] = {
    5020: 502,    # Modbus/TCP
    10201: 102,   # S7Comm (ISO-TSAP)
    2404: 2404,   # IEC-104 (same)
    8800: 80,     # HTTP SCADA
}

_REDIS: redis.Redis | None = None


def _redis() -> redis.Redis:
    global _REDIS
    if _REDIS is None:
        _REDIS = redis.from_url(REDIS_URL, decode_responses=True)
    return _REDIS


def _get_parent_session_id(source_ip: str) -> str | None:
    try:
        return _redis().get(f"honeypot:breadcrumb:{source_ip}")
    except Exception as exc:
        log.warning("redis_breadcrumb_lookup_failed", error=str(exc))
        return None


def _parse_modbus_request(raw: str | None) -> dict[str, int]:
    """Extract FC / start / count from Conpot's stringified Modbus PDU.

    Conpot logs `request` as a Python repr like `b'00010000000601030000000a'`
    -- the full MBAP+PDU as hex inside a bytes literal. Layout:
      [0..1]  txid    [2..3]  proto   [4..5]  len   [6] unit
      [7]     fc      [8..9]  start   [10..11] count
    Returns {} on parse failure (forwarder still POSTs without structured
    fields rather than dropping the event).
    """
    if not raw:
        return {}
    cleaned = raw.strip()
    if cleaned.startswith("b'") and cleaned.endswith("'"):
        cleaned = cleaned[2:-1]
    elif cleaned.startswith('b"') and cleaned.endswith('"'):
        cleaned = cleaned[2:-1]
    try:
        b = bytes.fromhex(cleaned)
    except ValueError:
        return {}
    if len(b) < 12:
        return {}
    return {
        "function_code": b[7],
        "start_address": int.from_bytes(b[8:10], "big"),
        "count": int.from_bytes(b[10:12], "big"),
    }


def _map_record(record: dict[str, Any]) -> dict[str, Any] | None:
    # Skip connection lifecycle records -- they have no PDU and would
    # produce empty bundles. Only forward records with an actual exchange.
    event_type = record.get("event_type")
    if event_type in ("NEW_CONNECTION", "CONNECTION_LOST"):
        return None

    data_type = (record.get("data_type") or "unknown").lower()
    request = record.get("request")

    # Conpot 0.6.0 emits flat src_ip/src_port/dst_port at the top level
    # (the nested remote/local shape some older docs reference does not
    # match the actual JSON output of this version).
    source_ip = record.get("src_ip")
    if not source_ip:
        return None

    internal_port = record.get("dst_port") or 0
    try:
        dst_port = _PORT_MAP.get(int(internal_port), int(internal_port))
    except (TypeError, ValueError):
        dst_port = 0

    protocol_data: dict[str, Any] = {
        "asset_type": "plc",
        "vendor": "Siemens",
        "model": "S7-315-2 PN/DP",
    }

    if data_type == "modbus":
        # `request` is a string like `b'00010000000601030000000a'` in 0.6.0;
        # parse it back into structured FC/start/count for downstream.
        if isinstance(request, str):
            protocol_data.update(_parse_modbus_request(request))
        elif isinstance(request, dict):
            protocol_data["function_code"] = request.get("function_code")
            protocol_data["start_address"] = request.get("start_address")
            protocol_data["count"] = request.get("count")
    elif data_type in ("iec104", "iec-104") and isinstance(request, dict):
        protocol_data["type_id"] = request.get("type_id")
        protocol_data["cot"] = request.get("cot")
        protocol_data["ioa"] = request.get("ioa")
    elif data_type == "s7comm" and isinstance(request, dict):
        protocol_data["s7_function"] = request.get("function")

    # Drop None values to keep the payload compact.
    protocol_data = {k: v for k, v in protocol_data.items() if v is not None}

    parent_session_id = _get_parent_session_id(source_ip)

    return {
        "timestamp": record.get("timestamp", ""),
        "sensor_id": SENSOR_ID,
        "source_ip": source_ip,
        "source_country": None,
        "source_asn": None,
        "dst_port": dst_port,
        "service": data_type,
        "session_id": record.get("id"),
        "username": None,
        "password": None,
        "source_type": "ot",
        "protocol_data": protocol_data,
        "parent_session_id": parent_session_id,
    }


def _write_dead_letter(event: dict[str, Any], reason: str, detail: Any) -> None:
    """Append a failed event to DEAD_LETTER_PATH for later replay.

    Each line is a self-contained JSON object with the original event plus
    enough metadata for an operator (or future replay tool) to understand
    why it landed here. Best-effort: a dead-letter write failure logs but
    never crashes the forwarder loop.
    """
    if not DEAD_LETTER_PATH:
        return
    record = {
        "spooled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason,
        "detail": detail,
        "event": event,
    }
    try:
        # Create parent dir on first write — the volume is mounted at the path
        # itself in production, so the dir already exists; this covers local tests.
        parent = os.path.dirname(DEAD_LETTER_PATH)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Size-cap rotation: when the spool grows past MAX_DEAD_LETTER_BYTES,
        # move it to <path>.1 (replacing any prior rotation) and start fresh.
        # Caps on-disk usage at 2x the configured size.
        if MAX_DEAD_LETTER_BYTES > 0:
            try:
                if os.path.getsize(DEAD_LETTER_PATH) >= MAX_DEAD_LETTER_BYTES:
                    os.replace(DEAD_LETTER_PATH, DEAD_LETTER_PATH + ".1")
                    log.warning(
                        "dead_letter_rotated",
                        path=DEAD_LETTER_PATH,
                        cap_bytes=MAX_DEAD_LETTER_BYTES,
                    )
            except FileNotFoundError:
                pass  # First write — nothing to rotate.
        with open(DEAD_LETTER_PATH, "a") as fh:
            fh.write(json.dumps(record) + "\n")
        log.warning(
            "ironpot_post_dead_lettered",
            path=DEAD_LETTER_PATH,
            reason=reason,
            session_id=event.get("session_id"),
        )
    except OSError as exc:
        log.error(
            "dead_letter_write_failed",
            error=str(exc),
            path=DEAD_LETTER_PATH,
            session_id=event.get("session_id"),
        )


def _post_event(event: dict[str, Any]) -> bool:
    """POST with bounded linear retry. Returns True on 2xx; False if all retries exhausted.

    On terminal failure (retries exhausted or non-429 4xx) the event is
    spooled to DEAD_LETTER_PATH so a sustained IronPot outage does not
    vaporize OT events.
    """
    last_status: int | None = None
    last_err: str | None = None
    for attempt in range(1, POST_MAX_RETRIES + 1):
        try:
            resp = httpx.post(
                f"{IRONPOT_URL}/honeypot/events",
                json=event,
                headers={"Authorization": f"Bearer {WEBHOOK_TOKEN}"},
                timeout=5.0,
            )
            if 200 <= resp.status_code < 300:
                return True
            last_status = resp.status_code
            # 4xx (other than 429) is unlikely to succeed on retry — give up early.
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                log.warning(
                    "ironpot_post_rejected_no_retry",
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                _write_dead_letter(
                    event,
                    reason="rejected_4xx",
                    detail={"status": resp.status_code, "body": resp.text[:200]},
                )
                return False
        except Exception as exc:
            last_err = str(exc)

        if attempt < POST_MAX_RETRIES:
            time.sleep(POST_BACKOFF_SECONDS * attempt)

    log.warning(
        "ironpot_post_failed",
        attempts=POST_MAX_RETRIES,
        last_status=last_status,
        last_error=last_err,
    )
    _write_dead_letter(
        event,
        reason="retries_exhausted",
        detail={"attempts": POST_MAX_RETRIES, "last_status": last_status, "last_error": last_err},
    )
    return False


def _open_log() -> tuple[Any, int] | None:
    """Open CONPOT_LOG and seek to end. Returns (file, inode) or None if missing."""
    if not os.path.exists(CONPOT_LOG):
        return None
    try:
        fh = open(CONPOT_LOG)
        fh.seek(0, 2)  # Tail — don't replay history on (re)start.
        inode = os.fstat(fh.fileno()).st_ino
        return fh, inode
    except OSError as exc:
        log.warning("log_open_failed", error=str(exc), path=CONPOT_LOG)
        return None


def _file_rotated(path: str, current_inode: int) -> bool:
    """True when the path now points at a different inode than the open handle."""
    try:
        return os.stat(path).st_ino != current_inode
    except OSError:
        return False


def tail_and_forward() -> None:
    log.info(
        "conpot_forwarder_starting",
        log_file=CONPOT_LOG,
        ironpot_url=IRONPOT_URL,
        sensor_id=SENSOR_ID,
    )

    while True:
        opened = _open_log()
        if opened is None:
            log.info("waiting_for_conpot_log", path=CONPOT_LOG)
            time.sleep(5)
            continue
        fh, inode = opened
        log.info("log_opened", path=CONPOT_LOG, inode=inode)

        with fh:
            rotation_check_counter = 0
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.5)
                    # Check for log rotation every ~10s of idle (20 × 0.5s).
                    rotation_check_counter += 1
                    if rotation_check_counter >= 20:
                        rotation_check_counter = 0
                        if _file_rotated(CONPOT_LOG, inode):
                            log.info("log_rotation_detected", path=CONPOT_LOG)
                            break  # reopen
                    continue

                rotation_check_counter = 0
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    log.warning("json_parse_failed", error=str(exc), line=line[:100])
                    continue

                event = _map_record(record)
                if event is None:
                    continue

                _post_event(event)


if __name__ == "__main__":
    try:
        tail_and_forward()
    except KeyboardInterrupt:
        sys.exit(0)
