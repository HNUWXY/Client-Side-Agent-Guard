import pytest

from dlp.detectors.pii_scanner import PIIScanner
from dlp.logger import DLPLogger
from dlp.sanitizers.pii_redactor import PIIRedactor


def test_scan_returns_spans_for_multiple_types():
    text = "Email a@b.com, phone 415-555-2671, ip 1.2.3.4, ric 11010519491231002X."
    scanner = PIIScanner()
    detections = scanner.scan(text)
    assert len(detections) >= 4
    for d in detections:
        assert 0 <= d.start_pos < d.end_pos <= len(text)


def test_scan_china_id_allows_lowercase_x():
    text = "id 11010519491231002x"
    scanner = PIIScanner(pii_types=["ric"])
    detections = scanner.scan(text)
    assert len(detections) == 1
    d = detections[0]
    assert text[d.start_pos:d.end_pos] == "11010519491231002x"


def test_redact_masks_same_length():
    text = "Contact: a@b.com and 415-555-2671."
    redactor = PIIRedactor(mask_char="*")
    out = redactor.redact(text)
    assert out != text

    # Ensure the exact substrings are masked with same length.
    assert "a@b.com" not in out
    assert "415-555-2671" not in out

    # Find where they were and check lengths are preserved overall.
    assert len(out) == len(text)


def test_redact_no_pii_is_noop():
    text = "hello world, nothing sensitive here"
    redactor = PIIRedactor()
    assert redactor.redact(text) == text


def test_redact_empty_is_noop():
    redactor = PIIRedactor()
    assert redactor.redact("") == ""


def test_mask_char_validation():
    with pytest.raises(ValueError):
        PIIRedactor(mask_char="")
    with pytest.raises(ValueError):
        PIIRedactor(mask_char="**")


def test_logger_writes_input_and_summary_output(tmp_path):
    logs_dir = tmp_path / "logs"
    logger = DLPLogger(str(logs_dir), output_summary_chars=10)
    redactor = PIIRedactor(logger=logger)

    text = "Email a@b.com and phone 415-555-2671."
    _ = redactor.redact(text)

    # Find the JSONL file and read it back.
    files = list(logs_dir.glob("io_*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2

    import json

    rec_in = json.loads(lines[0])
    rec_out = json.loads(lines[-1])

    assert rec_in["direction"] == "input"
    assert rec_in["text"] == text  # raw input stored

    assert rec_out["direction"] == "output"
    assert len(rec_out["text"]) <= 11  # 10 chars + ellipsis
    assert rec_out["metadata"]["full_len"] >= len(rec_out["text"])

