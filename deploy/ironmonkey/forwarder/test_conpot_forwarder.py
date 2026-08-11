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


# ── Story 17.6: function-code-aware Modbus PDU parsing ─────────────────────
#
# Every `REAL_*` constant below is a verbatim `request` string captured from the
# snakeplskn lab-bench Conpot on 2026-08-11 by driving raw PDUs at port 502, so
# these tests assert against bytes Conpot actually logged rather than bytes we
# assumed it would. Layout comments give the absolute offsets into the decoded
# ADU: [0..1] txid, [2..3] proto, [4..5] len, [6] unit, [7] fc, [8...] fc data.

#                       txid  proto len   u  fc start count
REAL_FC1 = "b'00010000000601010000000a'"   # read coils        start=0  qty=10
REAL_FC3 = "b'00020000000601030000000a'"   # read holding      start=0  qty=10
#                       txid  proto len   u  fc addr  value
REAL_FC5_ON = "b'00030000000601050010ff00'"    # write coil    addr=16 val=0xFF00
REAL_FC5_OFF = "b'000400000006010500100000'"   # write coil    addr=16 val=0x0000
REAL_FC5_ODD = "b'000500000006010500101234'"   # write coil    addr=16 val=0x1234
REAL_FC6 = "b'0006000000060106001000ff'"       # write register addr=16 val=0x00FF
#                       txid  proto len   u  fc start qty   bc data
REAL_FC15 = "b'000700000009010f0000000a02cd01'"          # 10 coils, 2 bytes
REAL_FC16 = "b'00080000000b01100010000204000a0102'"      # 2 regs, 4 bytes
#                       txid  proto len   u  fc ref   and   or
REAL_FC22 = "b'0009000000080116000400f20025'"  # mask write ref=4
#                       txid  proto len   u  fc sub   data
REAL_FC8 = "b'000a00000006010800040000'"       # diagnostics sub=4
#                    txid  proto len   u  fc rds  rdq  wrs  wrq  bc data
REAL_FC23 = "b'000b0000000d011700000002001000010200ab'"
REAL_FC43 = "b'000c00000005012b0e0100'"        # read device identification
REAL_FC100 = "b'000d00000006016400000001'"     # vendor-defined / unknown


def _mbap(pdu_hex: str, txid: int = 1, unit: int = 1) -> str:
    """Wrap a PDU hex string in an MBAP header, in Conpot's bytes-repr form."""
    pdu = bytes.fromhex(pdu_hex)
    header = txid.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big")
    return "b'" + (header + bytes([unit]) + pdu).hex() + "'"


class TestModbusParse:
    """AC #9 — per-function-code interpretation of the logged Modbus ADU."""

    def test_fc3_read_unchanged(self):
        """(a) Read family keeps the pre-17.6 output exactly — regression guard."""
        cf = _reload_module()
        assert cf._parse_modbus_request(REAL_FC3) == {
            "function_code": 3,
            "start_address": 0,
            "count": 10,
        }
        assert cf._parse_modbus_request(REAL_FC1) == {
            "function_code": 1,
            "start_address": 0,
            "count": 10,
        }

    def test_fc6_emits_written_value_and_no_count(self):
        """(b) The whole point: bytes 10-11 are the value, and `count` is a lie."""
        cf = _reload_module()
        parsed = cf._parse_modbus_request(REAL_FC6)
        assert parsed == {
            "function_code": 6,
            "start_address": 16,
            "written_value": 0x00FF,
        }
        assert "count" not in parsed

    def test_fc5_coil_state_both_ways_and_non_canonical(self):
        """(c) 0xFF00/0x0000 map to on/off; anything else keeps only the raw value."""
        cf = _reload_module()
        on = cf._parse_modbus_request(REAL_FC5_ON)
        assert on == {
            "function_code": 5,
            "start_address": 16,
            "written_value": 0xFF00,
            "coil_state": "on",
        }
        off = cf._parse_modbus_request(REAL_FC5_OFF)
        assert off["coil_state"] == "off"
        assert off["written_value"] == 0x0000

        odd = cf._parse_modbus_request(REAL_FC5_ODD)
        assert odd["written_value"] == 0x1234
        assert "coil_state" not in odd
        assert "count" not in odd

    def test_fc16_count_and_values_consistent(self):
        """(d) Quantity is real for FC16, and the data block decodes alongside it."""
        cf = _reload_module()
        assert cf._parse_modbus_request(REAL_FC16) == {
            "function_code": 16,
            "start_address": 16,
            "count": 2,
            "written_values": [0x000A, 0x0102],
        }

    def test_fc15_bit_unpacking_lsb_first(self):
        """(e) Coil bits are LSB-first within each byte, truncated to `count`."""
        cf = _reload_module()
        parsed = cf._parse_modbus_request(REAL_FC15)
        # data = 0xCD 0x01 -> 0xCD is 1100_1101, LSB first: 1,0,1,1,0,0,1,1
        # then 0x01 contributes 1,0 to reach the declared 10 coils.
        assert parsed["written_values"] == [1, 0, 1, 1, 0, 0, 1, 1, 1, 0]
        assert parsed["count"] == 10
        assert len(parsed["written_values"]) == parsed["count"]

    def test_fc22_masks_and_no_count(self):
        """(f) Mask write carries two masks and no quantity at all."""
        cf = _reload_module()
        parsed = cf._parse_modbus_request(REAL_FC22)
        assert parsed == {
            "function_code": 22,
            "start_address": 4,
            "and_mask": 0x00F2,
            "or_mask": 0x0025,
        }
        assert "count" not in parsed

    def test_fc23_both_halves(self):
        """FC23 enumerates and actuates in one round trip — keep both halves."""
        cf = _reload_module()
        assert cf._parse_modbus_request(REAL_FC23) == {
            "function_code": 23,
            "start_address": 0,
            "count": 2,
            "write_start_address": 16,
            "write_count": 1,
            "written_values": [0x00AB],
        }

    def test_fc8_sub_function_is_16_bit(self):
        """Sub-function 4 (Force Listen Only) must not read as 0 from b[8] alone."""
        cf = _reload_module()
        assert cf._parse_modbus_request(REAL_FC8) == {
            "function_code": 8,
            "sub_function": 4,
        }

    def test_written_values_capped_but_count_is_true(self):
        """(g) 100 registers → 64 values + a truncation flag; `count` still says 100."""
        cf = _reload_module()
        registers = b"".join(i.to_bytes(2, "big") for i in range(100))
        pdu = "10" + (16).to_bytes(2, "big").hex() + (100).to_bytes(2, "big").hex() \
            + bytes([200]).hex() + registers.hex()
        parsed = cf._parse_modbus_request(_mbap(pdu))
        assert parsed["count"] == 100
        assert parsed["values_truncated"] is True
        assert len(parsed["written_values"]) == 64
        assert parsed["written_values"][0] == 0
        assert parsed["written_values"][63] == 63

    def test_fc15_bits_capped(self):
        """The cap applies to coil bits too, not just registers."""
        cf = _reload_module()
        coil_bytes = bytes([0xFF] * 13)  # 104 bits available, 100 declared
        pdu = "0f" + (0).to_bytes(2, "big").hex() + (100).to_bytes(2, "big").hex() \
            + bytes([13]).hex() + coil_bytes.hex()
        parsed = cf._parse_modbus_request(_mbap(pdu))
        assert parsed["count"] == 100
        assert len(parsed["written_values"]) == 64
        assert parsed["values_truncated"] is True
        # We capped it; the PDU itself carried everything it declared.
        assert "values_incomplete" not in parsed

    def test_fc16_declaring_more_registers_than_it_carries_is_flagged(self):
        """A byte count that cannot cover the declared quantity is a distinct fact.

        `values_truncated` means WE dropped the tail at the cap. This means the
        PDU lied -- a malformed or probing frame. Conflating the two let an
        analyst read "count: 50, 2 values, no flag" as a complete 2-register
        write.
        """
        cf = _reload_module()
        # quantity 50, byte_count 4 -> only 2 registers actually present
        pdu = "10" + "0010" + "0032" + "04" + "deadbeef"
        parsed = cf._parse_modbus_request(_mbap(pdu))
        assert parsed["count"] == 50
        assert parsed["written_values"] == [0xDEAD, 0xBEEF]
        assert parsed["values_incomplete"] is True
        assert "values_truncated" not in parsed

    def test_fc15_declaring_more_coils_than_it_carries_is_flagged(self):
        """Same for coils, where the shortfall otherwise surfaces as padding bits."""
        cf = _reload_module()
        # quantity 100, byte_count 2 -> 16 bits available
        pdu = "0f" + "0000" + "0064" + "02" + "cd01"
        parsed = cf._parse_modbus_request(_mbap(pdu))
        assert parsed["count"] == 100
        assert len(parsed["written_values"]) == 16
        assert parsed["values_incomplete"] is True

    def test_fc23_incompleteness_is_measured_against_the_write_count(self):
        """FC23's data block is sized by write_count, not by the read `count`."""
        cf = _reload_module()
        # read qty 2, write qty 4, but only 2 registers of data present
        pdu = "17" + "0000" + "0002" + "0010" + "0004" + "04" + "000a0102"
        parsed = cf._parse_modbus_request(_mbap(pdu))
        assert parsed["count"] == 2          # read half, untouched
        assert parsed["write_count"] == 4
        assert parsed["written_values"] == [0x000A, 0x0102]
        assert parsed["values_incomplete"] is True

    def test_a_complete_write_carries_neither_flag(self):
        """Guard against the flags becoming noise on well-formed traffic."""
        cf = _reload_module()
        pdu = "10" + "0010" + "0002" + "04" + "000a0102"
        parsed = cf._parse_modbus_request(_mbap(pdu))
        assert parsed["written_values"] == [0x000A, 0x0102]
        assert "values_incomplete" not in parsed
        assert "values_truncated" not in parsed

    @pytest.mark.parametrize(
        "label,fc,pdu_hex",
        [
            ("fc3 read, count field 1 byte short", 3, "03" + "0000" + "00"),
            ("fc6 write, no value", 6, "06" + "0010"),
            ("fc22 mask, missing or_mask", 22, "16" + "0004" + "00f2"),
            ("fc16 byte count exceeds frame", 16, "10" + "0010" + "0002" + "04" + "000a"),
            ("fc15 byte count exceeds frame", 15, "0f" + "0000" + "000a" + "02" + "cd"),
            ("fc23 truncated before data", 23, "17" + "0000" + "0002" + "0010" + "0001" + "02"),
            ("fc8 single-byte sub function", 8, "08" + "00"),
        ],
    )
    def test_short_pdu_keeps_the_function_code_and_never_raises(self, label, fc, pdu_hex):
        """(h) A short frame degrades to the FC alone -- it must not erase the exchange.

        Returning {} here is destructive rather than merely lossy: the session
        row is still written (asset identity keeps protocol_data non-NULL), so
        it overwrites the same session id's earlier real exchange and the
        commands writer deletes that exchange's MITRE-labelled row. Keeping the
        function code also keeps every OT rule firing, since they match on it
        alone. Nothing is invented from the bytes that were not there.
        """
        cf = _reload_module()
        assert cf._parse_modbus_request(_mbap(pdu_hex)) == {"function_code": fc}, label

    def test_short_write_frame_still_carries_its_write_function_code(self):
        """The regression that made the {}-return an evidence-wipe, pinned directly.

        An FC22 missing its or_mask used to parse to {}. Appending one such
        frame to a session in which a coil had already been forced destroyed
        both that session's protocol_data and its ATT&CK labels, because Conpot
        reuses one session id across TCP connections.
        """
        cf = _reload_module()
        parsed = cf._parse_modbus_request(_mbap("16" + "0004" + "00f2"))
        assert parsed["function_code"] == 22
        assert "and_mask" not in parsed
        assert "start_address" not in parsed

    def test_frame_too_short_for_a_function_code(self):
        """Below 8 bytes there is not even an FC to report."""
        cf = _reload_module()
        assert cf._parse_modbus_request("b'0001000000060103'"[:16] + "'") == {}
        assert cf._parse_modbus_request("b'000100000006'") == {}

    def test_unknown_fc_reports_only_the_function_code(self):
        """(i) No layout is guessed for FC43 or vendor codes."""
        cf = _reload_module()
        assert cf._parse_modbus_request(REAL_FC43) == {"function_code": 43}
        assert cf._parse_modbus_request(REAL_FC100) == {"function_code": 100}

    @pytest.mark.parametrize("raw", [None, "", "not-hex-at-all", "b'zzzz'", "b'0001020'"])
    def test_unparseable_request_returns_empty(self, raw):
        """(j) Existing contract: {} lets the forwarder still POST the event."""
        cf = _reload_module()
        assert cf._parse_modbus_request(raw) == {}

    def test_double_quoted_bytes_repr_accepted(self):
        """Conpot's repr may use double quotes; both forms must decode."""
        cf = _reload_module()
        assert cf._parse_modbus_request('b"0006000000060106001000ff"') == {
            "function_code": 6,
            "start_address": 16,
            "written_value": 0x00FF,
        }


class TestMapRecordLifecycle:
    """Lifecycle filtering and the dict-shaped-request fallback in _map_record."""

    @pytest.mark.parametrize(
        "event_type",
        ["NEW_CONNECTION", "CONNECTION_LOST", "CONNECTION_TERMINATED"],
    )
    def test_lifecycle_records_are_not_forwarded(self, event_type):
        """CONNECTION_TERMINATED leaked through as a phantom exchange before 17.6."""
        cf = _reload_module()
        record = {
            "event_type": event_type,
            "data_type": "modbus",
            "src_ip": "203.0.113.9",
            "dst_port": 5020,
            "request": None,
            "id": "sess-1",
        }
        assert cf._map_record(record) is None

    def test_write_payload_reaches_protocol_data(self):
        """An FC6 record carries the written value through to the POST payload."""
        cf = _reload_module()
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record({
                "event_type": None,
                "data_type": "modbus",
                "src_ip": "203.0.113.9",
                "dst_port": 5020,
                "request": REAL_FC6,
                "id": "sess-2",
                "timestamp": "2026-08-11T14:51:01.724936",
            })
        assert mapped is not None
        assert mapped["protocol_data"]["written_value"] == 0x00FF
        assert mapped["protocol_data"]["function_code"] == 6
        assert "count" not in mapped["protocol_data"]
        assert mapped["dst_port"] == 502  # internal 5020 normalized to the bait port

    def test_dict_request_passes_through_write_keys(self):
        """Conpot 0.6.0 never emits a dict, but if it did, writes must not be relabeled."""
        cf = _reload_module()
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record({
                "event_type": None,
                "data_type": "modbus",
                "src_ip": "203.0.113.9",
                "dst_port": 5020,
                "request": {"function_code": 6, "start_address": 16, "written_value": 255},
                "id": "sess-3",
                "timestamp": "2026-08-11T14:51:01.724936",
            })
        assert mapped is not None
        assert mapped["protocol_data"]["written_value"] == 255
        assert "count" not in mapped["protocol_data"]
