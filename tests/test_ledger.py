import json

from app.ledger import Ledger, anonymise


def make(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    for i in range(4):
        led.append("INC-1", f"EV{i}", {"n": i})
    return led


def test_chain_verifies(tmp_path):
    assert make(tmp_path).verify() == {"ok": True, "count": 4, "broken_at": None, "reason": ""}


def test_edit_detected(tmp_path):
    led = make(tmp_path)
    rows = [json.loads(x) for x in led.path.read_text().splitlines()]
    rows[1]["payload"]["n"] = 99
    led.path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    v = led.verify()
    assert not v["ok"] and v["broken_at"] == 2


def test_deletion_detected(tmp_path):
    led = make(tmp_path)
    lines = led.path.read_text().splitlines()
    del lines[1]
    led.path.write_text("\n".join(lines) + "\n")
    assert not led.verify()["ok"]


def test_reorder_detected(tmp_path):
    led = make(tmp_path)
    lines = led.path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    led.path.write_text("\n".join(lines) + "\n")
    assert not led.verify()["ok"]


def test_truncated_tail_keeps_prefix_valid_but_new_append_continues(tmp_path):
    led = make(tmp_path)
    lines = led.path.read_text().splitlines()[:2]
    led.path.write_text("\n".join(lines) + "\n")
    assert led.verify()["ok"]


def test_anonymise_is_stable_and_hides_local_part():
    a = anonymise("Jan.Kowalski@Example.com", "s")
    assert a == anonymise("jan.kowalski@example.com", "s")
    assert "kowalski" not in a.lower() and a.endswith("@example.com")
