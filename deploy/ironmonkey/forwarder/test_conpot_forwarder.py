"""Tests for the Conpot → IronPot forwarder dead-letter path (Story 17.3 review item #3).

Focused on the failure path: when IronPot is unreachable after retries, the
forwarder MUST spool the event to DEAD_LETTER_PATH so it can be replayed
later. A sustained IronPot outage should never silently vaporize OT events.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
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


def _s7_frame(
    params: bytes, data: bytes = b"", *, tpdu_type: int = 0xF0, pdu_type: int = 1
) -> str:
    """Wrap an S7 params/data pair in COTP+TPKT, in Conpot's bytes-repr form.

    Mirrors `_mbap` above for S7comm's extra protocol layer. `cotp_length`
    is set to the true `1 (tpdu_type) + 1 (opt_field) + 0 (no COTP payload)`
    Conpot itself always sends, i.e. 2 -- real S7 content rides in the COTP
    trailer, not the COTP payload.
    """
    s7_header = (
        bytes([0x32, pdu_type])
        + b"\x00\x00"  # reserved
        + b"\x00\x01"  # request_id
        + len(params).to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
    )
    cotp = bytes([2, tpdu_type, 0x80]) if tpdu_type == 0xF0 else bytes([2, tpdu_type])
    trailer = s7_header + params + data if tpdu_type == 0xF0 else b""
    tpkt_payload = cotp + trailer
    tpkt = bytes([3, 0]) + len(tpkt_payload).to_bytes(2, "big") + tpkt_payload
    return "b'" + tpkt.hex() + "'"


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


class TestS7commParse:
    """`_parse_s7comm_request` — the stringified TPKT+COTP+S7 request frame.

    The branch this replaces gated on `isinstance(request, dict)`, which
    Conpot's actual `b'...'` hex-string request never satisfies -- dead code,
    same bug shape as the OT-HTTP gap.
    """

    def test_plc_stop_reports_the_param_byte(self):
        cf = _reload_module()
        raw = _s7_frame(params=bytes([0x29]))
        assert cf._parse_s7comm_request(raw) == {"s7_function": 0x29}

    def test_szl_module_identification_reports_the_ssl_id_not_the_param_byte(self):
        """Every SZL read shares param 0x00 -- the ssl_id in DATA is what
        actually distinguishes "module identification" (17) from any other
        system status list, so it's what has to end up in `s7_function` for
        the `ot-s7comm-szl-read` rule (which matches on 17, not 0x00) to fire.
        """
        cf = _reload_module()
        params = bytes(8)  # diagnostics header, only its presence is checked
        data = bytes([0x00, 0x00]) + (2).to_bytes(2, "big") + (17).to_bytes(2, "big")
        raw = _s7_frame(params=params, data=data)
        assert cf._parse_s7comm_request(raw) == {"s7_function": 17}

    def test_szl_component_identification_reports_the_ssl_id(self):
        """Same shape as module identification (SZL 17), but SZL 28 (0x001C,
        Component Identification) -- the other identification SZL the
        s7-315-substation template serves, and the one `ot-s7comm-szl-read`
        didn't match until it was widened alongside this test.
        """
        cf = _reload_module()
        params = bytes(8)  # diagnostics header, only its presence is checked
        data = bytes([0x00, 0x00]) + (2).to_bytes(2, "big") + (28).to_bytes(2, "big")
        raw = _s7_frame(params=params, data=data)
        assert cf._parse_s7comm_request(raw) == {"s7_function": 28}

    def test_szl_with_zero_next_bytes_falls_back_to_the_param_byte(self):
        cf = _reload_module()
        params = bytes(8)
        data = bytes([0x00, 0x00, 0x00, 0x00])  # next_bytes == 0, no ssl_id
        raw = _s7_frame(params=params, data=data)
        assert cf._parse_s7comm_request(raw) == {"s7_function": 0x00}

    def test_other_function_code_reported_generically(self):
        """(i) No layout is guessed for read/write/block-transfer params --
        the code is kept, mirroring the Modbus parser's unknown-FC fallback.
        """
        cf = _reload_module()
        raw = _s7_frame(params=bytes([0x04]))  # "read", not implemented by Conpot
        assert cf._parse_s7comm_request(raw) == {"s7_function": 0x04}

    def test_connection_request_tpdu_has_no_s7_payload(self):
        """tpdu_type 0xE0 (COTP CR) precedes any S7 exchange -- nothing to
        parse yet, not a parse failure.
        """
        cf = _reload_module()
        raw = _s7_frame(params=bytes([0x29]), tpdu_type=0xE0)
        assert cf._parse_s7comm_request(raw) == {}

    @pytest.mark.parametrize(
        "raw", [None, "", "not-hex-at-all", "b'zz'", "b'03000004'"]
    )
    def test_unparseable_request_returns_empty(self, raw):
        """Existing contract: {} lets the forwarder still POST the event."""
        cf = _reload_module()
        assert cf._parse_s7comm_request(raw) == {}

    def test_short_frame_with_no_params_returns_empty(self):
        """A negotiate/other PDU declaring param_length but truncated before
        it degrades to {}, not a wrong function code.
        """
        cf = _reload_module()
        raw = _s7_frame(params=b"")  # param_length == 0 -- nothing to report
        assert cf._parse_s7comm_request(raw) == {}


class TestHttpParse:
    """`_parse_http_request` — the stringified (path, headers, body) tuple."""

    REQUEST_INDEX_HTML = (
        "('/index.html', [('Host', '10.0.0.5:8800'), "
        "('User-Agent', 'curl/7.68.0'), ('Accept', '*/*')], None)"
    )
    REQUEST_WITH_QUERY_AND_BODY = (
        "('/index.html?debug=1', [('Host', '10.0.0.5:8800'), "
        "('User-Agent', 'python-requests/2.31.0'), "
        "('Authorization', 'Basic YWRtaW46YWRtaW4=')], b'user=admin&pass=admin')"
    )

    def test_known_page_hit(self):
        cf = _reload_module()
        parsed = cf._parse_http_request(self.REQUEST_INDEX_HTML, 200)
        assert parsed == {
            "http_status": 200,
            "http_path": "/index.html",
            "http_host": "10.0.0.5:8800",
            "http_user_agent": "curl/7.68.0",
        }

    def test_query_string_and_body_and_auth_header_captured(self):
        cf = _reload_module()
        parsed = cf._parse_http_request(self.REQUEST_WITH_QUERY_AND_BODY, "404")
        assert parsed["http_status"] == 404
        assert parsed["http_path"] == "/index.html"
        assert parsed["http_query"] == "debug=1"
        assert parsed["http_user_agent"] == "python-requests/2.31.0"
        assert parsed["http_authorization"] == "Basic YWRtaW46YWRtaW4="
        assert parsed["http_body"] == "user=admin&pass=admin"
        assert parsed["http_body_length"] == len(b"user=admin&pass=admin")

    def test_path_with_no_query_omits_query_key(self):
        cf = _reload_module()
        parsed = cf._parse_http_request(self.REQUEST_INDEX_HTML, 200)
        assert "http_query" not in parsed

    def test_response_only_status_still_int_coerced(self):
        """`response` is logged as a stringified status, e.g. \"200\"."""
        cf = _reload_module()
        parsed = cf._parse_http_request(None, "503")
        assert parsed == {"http_status": 503}

    @pytest.mark.parametrize(
        "raw", [None, "", "not-a-tuple-at-all", "('/x',", "(1, 2)"]
    )
    def test_unparseable_request_degrades_to_status_only(self, raw):
        """Same degrade-gracefully contract as `_parse_modbus_request`."""
        cf = _reload_module()
        parsed = cf._parse_http_request(raw, 200)
        assert parsed == {"http_status": 200}

    def test_long_body_is_capped_and_flagged(self):
        cf = _reload_module()
        long_body = "A" * (cf._MAX_HTTP_TEXT_CHARS + 50)
        raw = f"('/index.html', [], b'{long_body}')"
        parsed = cf._parse_http_request(raw, 200)
        assert len(parsed["http_body"]) == cf._MAX_HTTP_TEXT_CHARS
        assert parsed["http_body_truncated"] is True
        assert parsed["http_body_length"] == len(long_body)

    def test_repeated_header_first_occurrence_wins(self):
        cf = _reload_module()
        raw = (
            "('/index.html', [('User-Agent', 'first'), "
            "('User-Agent', 'second')], None)"
        )
        parsed = cf._parse_http_request(raw, 200)
        assert parsed["http_user_agent"] == "first"


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

    def test_http_request_reaches_protocol_data(self):
        """The bug this closes: HTTP had no branch at all, so every OT-HTTP
        touch collapsed to the 3 default asset keys and nothing else."""
        cf = _reload_module()
        request = (
            "('/index.html', [('Host', '10.0.0.5:8800'), "
            "('User-Agent', 'Mozilla/5.0 (Nmap Scripting Engine)')], None)"
        )
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record({
                "event_type": None,
                "data_type": "http",
                "src_ip": "203.0.113.9",
                "dst_port": 8800,
                "request": request,
                "response": "200",
                "method": "GET",
                "id": "sess-4",
                "timestamp": "2026-08-11T14:51:01.724936",
            })
        assert mapped is not None
        assert mapped["dst_port"] == 80  # internal 8800 normalized to the bait port
        pd = mapped["protocol_data"]
        assert pd["http_method"] == "GET"
        assert pd["http_path"] == "/index.html"
        assert pd["http_status"] == 200
        assert pd["http_user_agent"] == "Mozilla/5.0 (Nmap Scripting Engine)"
        assert pd["http_host"] == "10.0.0.5:8800"
        # Still carries the default asset identity alongside the new fields.
        assert pd["vendor"] == "Siemens"

    def test_http_probe_of_unknown_path_returns_404(self):
        cf = _reload_module()
        request = "('/awp/Bootstrapper', [('User-Agent', 'curl/7.68.0')], None)"
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record({
                "event_type": None,
                "data_type": "http",
                "src_ip": "203.0.113.9",
                "dst_port": 8800,
                "request": request,
                "response": "404",
                "method": "GET",
                "id": "sess-5",
                "timestamp": "2026-08-11T14:51:01.724936",
            })
        assert mapped["protocol_data"]["http_path"] == "/awp/Bootstrapper"
        assert mapped["protocol_data"]["http_status"] == 404

    def test_s7comm_plc_stop_reaches_protocol_data(self):
        """The bug this closes: `isinstance(request, dict)` never matched
        Conpot's real hex-string request, so s7_function never populated."""
        cf = _reload_module()
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record({
                "event_type": None,
                "data_type": "s7comm",
                "src_ip": "203.0.113.9",
                "dst_port": 10201,
                "request": _s7_frame(params=bytes([0x29])),
                "id": "sess-6",
                "timestamp": "2026-08-11T14:51:01.724936",
            })
        assert mapped is not None
        assert mapped["dst_port"] == 102  # internal 10201 normalized to the bait port
        assert mapped["protocol_data"]["s7_function"] == 0x29

    def test_s7comm_dict_request_still_passes_through_legacy_shape(self):
        """Defensive compat: if a future Conpot ever emits a dict here."""
        cf = _reload_module()
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record({
                "event_type": None,
                "data_type": "s7comm",
                "src_ip": "203.0.113.9",
                "dst_port": 10201,
                "request": {"function": 17},
                "id": "sess-7",
                "timestamp": "2026-08-11T14:51:01.724936",
            })
        assert mapped["protocol_data"]["s7_function"] == 17


class TestObservationTimestamp:
    """Story 18.16 — the forwarder stamps its own per-record observation time.

    Before this, `_map_record` copied `record["timestamp"]`, which Conpot sets
    ONCE per AttackSession and stamps on every event in it. `_exchange_key`
    hashes (exchange_ts, service, protocol_data), so with no time entropy it
    collapsed to sha1(protocol_data) and repeated identical PDUs became one row.
    """

    _REC = {
        "event_type": None,
        "data_type": "modbus",
        "src_ip": "203.0.113.9",
        "dst_port": 5020,
        "request": {"function_code": 3, "start_address": 4, "count": 1},
        "id": "sess-obs",
        "timestamp": "2026-08-11T14:51:01.724936",
    }

    def test_same_record_twice_yields_two_distinct_stamps(self):
        """AC #1 — this is the whole story: identical input, distinct stamps."""
        cf = _reload_module()
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            first = cf._map_record(dict(self._REC))
            second = cf._map_record(dict(self._REC))

        assert first["timestamp"] != second["timestamp"]
        # and neither is the Conpot session-open time it used to copy
        assert first["timestamp"] != self._REC["timestamp"]
        assert second["timestamp"] != self._REC["timestamp"]

    def test_stamp_is_strictly_monotonic_under_a_frozen_clock(self):
        """AC #2 — a coarse clock or an NTP step back must not re-collide keys.

        HARNESS TRAP: `_reload_module` ends in `importlib.reload`, which resets
        the module-level last-emitted value. Reload ONCE, then map three records
        against that same module object — calling the helper between maps makes
        this pass for the wrong reason.
        """
        cf = _reload_module()
        frozen = datetime(2026, 8, 12, 13, 21, 42, 317029, tzinfo=timezone.utc)

        class _FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return frozen

        with patch.object(cf, "datetime", _FrozenDatetime):
            stamps = [cf._observation_ts() for _ in range(3)]

        assert stamps == sorted(stamps), "stamps must be strictly increasing"
        assert len(set(stamps)) == 3
        parsed = [datetime.fromisoformat(s) for s in stamps]
        assert parsed[1] - parsed[0] == timedelta(microseconds=1)
        assert parsed[2] - parsed[1] == timedelta(microseconds=1)

    def test_stamp_always_carries_microseconds(self):
        """AC #1 — bare .isoformat() drops the subsecond part on a whole second,
        which would vary the shape of a hash input and a STIX field."""
        cf = _reload_module()
        whole_second = datetime(2026, 8, 12, 13, 21, 42, 0, tzinfo=timezone.utc)

        class _FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return whole_second

        with patch.object(cf, "datetime", _FrozenDatetime):
            stamp = cf._observation_ts()

        assert stamp == "2026-08-12T13:21:42.000000+00:00"

    def test_retries_reuse_the_same_baked_stamp(self, tmp_path):
        """AC #3 — the stamp is computed once in `_map_record`, never re-derived.

        If a retry re-read the clock the exchange_key would differ and the
        ON CONFLICT (session_id, exchange_key) DO NOTHING guard would not fire,
        so every IronPot hiccup would duplicate a row.

        HARNESS TRAP: `_reload_module` pins POST_MAX_RETRIES="2", so there are
        two attempts, not three. Assert on two bodies.
        """
        cf = _reload_module(dead_letter_path=str(tmp_path / "dl.jsonl"))
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record(dict(self._REC))

        bodies: list[dict] = []

        def _capture(*_a, **kw):
            bodies.append(json.loads(json.dumps(kw["json"])))
            raise httpx.ConnectError("ironpot down")

        with patch.object(cf.httpx, "post", side_effect=_capture):
            cf._post_event(mapped)

        assert len(bodies) == 2, "harness pins POST_MAX_RETRIES=2"
        assert bodies[0]["timestamp"] == bodies[1]["timestamp"] == mapped["timestamp"]

    def test_payload_key_set_is_unchanged(self):
        """AC #4 — no new key. A new forwarder key must clear two independent
        allow-lists upstream and each drops an unknown key SILENTLY."""
        cf = _reload_module()
        with patch.object(cf, "_get_parent_session_id", return_value=None):
            mapped = cf._map_record(dict(self._REC))

        assert sorted(mapped.keys()) == sorted([
            "timestamp", "sensor_id", "source_ip", "source_country", "source_asn",
            "dst_port", "service", "session_id", "username", "password",
            "source_type", "protocol_data", "parent_session_id",
        ])
        # never inside protocol_data -- it is an _exchange_key input
        assert not any("time" in k or "ts" in k for k in mapped["protocol_data"])
