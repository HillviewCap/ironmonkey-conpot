"""Tests for the Conpot → IronPot forwarder dead-letter path (Story 17.3 review item #3).

Focused on the failure path: when IronPot is unreachable after retries, the
forwarder MUST spool the event to DEAD_LETTER_PATH so it can be replayed
later. A sustained IronPot outage should never silently vaporize OT events.
"""

import json
import os
import sys
from unittest.mock import patch

import httpx
import pytest

sys.path.insert(0, os.path.dirname(__file__))


def _reload_module(
    dead_letter_path: str | None = None,
    max_dead_letter_bytes: int | None = None,
):
    """Reimport the forwarder so env-bound constants pick up monkey-patched values."""
    import importlib

    if dead_letter_path is not None:
        os.environ["DEAD_LETTER_PATH"] = dead_letter_path
    if max_dead_letter_bytes is not None:
        os.environ["MAX_DEAD_LETTER_BYTES"] = str(max_dead_letter_bytes)
    os.environ.setdefault("HONEYPOT_WEBHOOK_TOKEN", "test-token")
    os.environ["POST_MAX_RETRIES"] = "2"
    os.environ["POST_BACKOFF_SECONDS"] = "0"  # don't actually sleep in tests
    import conpot_forwarder as cf

    importlib.reload(cf)
    return cf


@pytest.fixture
def event() -> dict:
    return {
        "session_id": "test-session-001",
        "sensor_id": "sensor-lab-test-01-ot",
        "source_ip": "203.0.113.42",
        "dst_port": 502,
        "service": "modbus",
        "source_type": "ot",
        "protocol_data": {"function_code": 3, "start_address": 0, "count": 10},
        "parent_session_id": None,
    }


def test_retries_exhausted_writes_dead_letter(tmp_path, event):
    """Network failures across all retries → event appended to DEAD_LETTER_PATH."""
    dl = tmp_path / "dead-letter.jsonl"
    cf = _reload_module(dead_letter_path=str(dl))

    def boom(*_a, **_kw):
        raise httpx.ConnectError("ironpot down")

    with patch.object(cf.httpx, "post", side_effect=boom):
        result = cf._post_event(event)

    assert result is False
    assert dl.exists(), "dead-letter file should be created on terminal failure"

    lines = dl.read_text().splitlines()
    assert len(lines) == 1, "exactly one record per failed event"
    record = json.loads(lines[0])
    assert record["reason"] == "retries_exhausted"
    assert record["event"]["session_id"] == "test-session-001"
    assert record["detail"]["attempts"] == 2
    assert "ironpot down" in record["detail"]["last_error"]


def test_non_429_4xx_writes_dead_letter_immediately(tmp_path, event):
    """Non-retryable 4xx → no retries, dead-letter with reason=rejected_4xx."""
    dl = tmp_path / "dead-letter.jsonl"
    cf = _reload_module(dead_letter_path=str(dl))

    class FakeResp:
        status_code = 422
        text = "missing required field"

    with patch.object(cf.httpx, "post", return_value=FakeResp()) as post:
        result = cf._post_event(event)

    assert result is False
    assert post.call_count == 1, "non-429 4xx should NOT retry"

    lines = dl.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["reason"] == "rejected_4xx"
    assert record["detail"]["status"] == 422


def test_429_retries_then_dead_letters(tmp_path, event):
    """429 is retryable; after all retries exhaust, falls through to dead-letter."""
    dl = tmp_path / "dead-letter.jsonl"
    cf = _reload_module(dead_letter_path=str(dl))

    class FakeResp:
        status_code = 429
        text = "rate limited"

    with patch.object(cf.httpx, "post", return_value=FakeResp()) as post:
        result = cf._post_event(event)

    assert result is False
    assert post.call_count == 2, "429 should retry up to POST_MAX_RETRIES"

    record = json.loads(dl.read_text().splitlines()[0])
    assert record["reason"] == "retries_exhausted"
    assert record["detail"]["last_status"] == 429


def test_success_does_not_write_dead_letter(tmp_path, event):
    """Happy path: 200 OK → no dead-letter file created."""
    dl = tmp_path / "dead-letter.jsonl"
    cf = _reload_module(dead_letter_path=str(dl))

    class FakeResp:
        status_code = 200
        text = ""

    with patch.object(cf.httpx, "post", return_value=FakeResp()):
        result = cf._post_event(event)

    assert result is True
    assert not dl.exists(), "happy path must not touch the dead-letter file"


def test_disabled_dead_letter_does_not_crash(tmp_path, event):
    """Empty DEAD_LETTER_PATH disables spooling — used in tests / local dev."""
    cf = _reload_module(dead_letter_path="")

    def boom(*_a, **_kw):
        raise httpx.ConnectError("ironpot down")

    with patch.object(cf.httpx, "post", side_effect=boom):
        result = cf._post_event(event)

    assert result is False  # still returns False; just no spool side-effect


def test_dead_letter_append_preserves_prior_events(tmp_path, event):
    """Multiple failed events accumulate as separate JSONL rows."""
    dl = tmp_path / "dead-letter.jsonl"
    cf = _reload_module(dead_letter_path=str(dl))

    def boom(*_a, **_kw):
        raise httpx.ConnectError("ironpot down")

    with patch.object(cf.httpx, "post", side_effect=boom):
        cf._post_event({**event, "session_id": "s1"})
        cf._post_event({**event, "session_id": "s2"})
        cf._post_event({**event, "session_id": "s3"})

    lines = dl.read_text().splitlines()
    assert len(lines) == 3
    ids = [json.loads(line)["event"]["session_id"] for line in lines]
    assert ids == ["s1", "s2", "s3"]


def test_dead_letter_rotates_when_size_cap_exceeded(tmp_path, event):
    """When the spool grows past MAX_DEAD_LETTER_BYTES it is rotated to .1.

    This is a drop-oldest policy: when the .1 file already exists, it is
    overwritten. Bounds on-disk usage at ~2x the cap. Operators who care
    about every event must drain .1 before another rotation clobbers it.
    """
    dl = tmp_path / "dead-letter.jsonl"
    # Pick a cap large enough to hold one record, small enough that the
    # second write triggers rotation.
    cap = 300
    cf = _reload_module(dead_letter_path=str(dl), max_dead_letter_bytes=cap)

    def boom(*_a, **_kw):
        raise httpx.ConnectError("ironpot down")

    with patch.object(cf.httpx, "post", side_effect=boom):
        cf._post_event({**event, "session_id": "s1"})  # first write — fits
        # Verify s1 landed in the current file.
        assert dl.read_text().count('"session_id": "s1"') == 1
        cf._post_event({**event, "session_id": "s2"})  # triggers rotation

    rotated = tmp_path / "dead-letter.jsonl.1"
    assert rotated.exists(), "prior dead-letter file must be rotated to .1"
    # s1 moved into .1; s2 lives in the fresh file.
    assert '"session_id": "s1"' in rotated.read_text()
    assert '"session_id": "s2"' in dl.read_text()


def test_dead_letter_rotation_disabled_when_cap_zero(tmp_path, event):
    """MAX_DEAD_LETTER_BYTES=0 disables rotation; file grows unboundedly."""
    dl = tmp_path / "dead-letter.jsonl"
    cf = _reload_module(dead_letter_path=str(dl), max_dead_letter_bytes=0)

    def boom(*_a, **_kw):
        raise httpx.ConnectError("ironpot down")

    with patch.object(cf.httpx, "post", side_effect=boom):
        for sid in ["a", "b", "c", "d", "e"]:
            cf._post_event({**event, "session_id": sid})

    assert not (tmp_path / "dead-letter.jsonl.1").exists()
    assert len(dl.read_text().splitlines()) == 5
