"""End to end flow with a stubbed SES v2 client (no network)."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app.main import create_app
from app.mailer import MailError, RecipientNotAllowed, SesMailer
from app.models import Incident
from app.service import Service

SAMPLES = Path(__file__).resolve().parent.parent / "app" / "samples"


class StubSes:
    def __init__(self, fail_for=None):
        self.calls = []
        self.fail_for = fail_for or set()

    def send_email(self, **kw):
        to = kw["Destination"]["ToAddresses"][0]
        if to in self.fail_for:
            raise ClientError({"Error": {"Code": "MessageRejected", "Message": "x"}}, "SendEmail")
        self.calls.append(kw)
        return {"MessageId": f"stub-{len(self.calls)}"}


def sample(name, **over):
    data = json.loads((SAMPLES / f"{name}.json").read_text())
    data["discovered_at"] = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    data.update(over)
    return data


@pytest.fixture
def env(tmp_path):
    stub = StubSes()
    svc = Service(tmp_path, SesMailer(client=stub, sender="agent@example.test"))
    return TestClient(create_app(svc)), stub, svc


def test_full_flow_sends_only_after_approval(env):
    client, stub, svc = env
    r = client.post("/api/incidents", json=sample("public_bucket"))
    assert r.status_code == 200 and r.json()["status"] == "DRAFTED"
    assert r.json()["assessment"]["outcome"] == "NOTIFY_AUTHORITY_AND_SUBJECTS"
    # sending without approval is refused and nothing reaches SES
    assert client.post("/api/incidents/INC-2026-101/send").status_code == 409
    assert stub.calls == []
    a = client.post("/api/incidents/INC-2026-101/approve", json={"approver": "Anna Nowak"})
    assert a.status_code == 200 and a.json()["status"] == "APPROVED"
    s = client.post("/api/incidents/INC-2026-101/send")
    assert s.status_code == 200 and s.json()["status"] == "SENT"
    assert len(stub.calls) == 4  # DPO copy + 3 subjects
    ids = [x["message_id"] for x in s.json()["sends"]]
    assert all(i.startswith("stub-") for i in ids)
    events = [e["event"] for e in svc.ledger.entries("INC-2026-101")]
    assert events[:4] == ["INTAKE", "ASSESSED", "DRAFTED", "SEND_REFUSED"] or "SENT" in events
    assert svc.ledger.verify()["ok"]


def test_no_notification_case_cannot_be_approved(env):
    client, stub, _ = env
    r = client.post("/api/incidents", json=sample("misdirected_email"))
    assert r.json()["status"] == "NO_NOTIFICATION"
    assert client.post("/api/incidents/INC-2026-102/approve", json={"approver": "Anna Nowak"}).status_code == 409
    assert stub.calls == []


def test_approver_name_required(env):
    client, _, _ = env
    client.post("/api/incidents", json=sample("public_bucket"))
    assert client.post("/api/incidents/INC-2026-101/approve", json={"approver": " "}).status_code == 409


def test_edit_is_hashed_and_recorded(env):
    client, stub, svc = env
    client.post("/api/incidents", json=sample("public_bucket"))
    edited = {"subject_en": {"body": "Edited by the DPO."}}
    a = client.post("/api/incidents/INC-2026-101/approve", json={"approver": "Anna Nowak", "edited": edited})
    assert a.json()["approval"]["edited_by_human"] is True
    client.post("/api/incidents/INC-2026-101/send")
    assert any("Edited by the DPO." in c["Content"]["Simple"]["Body"]["Text"]["Data"] for c in stub.calls)


def test_tampering_after_approval_blocks_send(env):
    client, stub, svc = env
    client.post("/api/incidents", json=sample("public_bucket"))
    client.post("/api/incidents/INC-2026-101/approve", json={"approver": "Anna Nowak"})
    state = svc.get("INC-2026-101")
    state["drafts"]["subject_en"]["body"] = "tampered"
    svc._save("INC-2026-101", drafts=json.dumps(state["drafts"]))
    assert client.post("/api/incidents/INC-2026-101/send").status_code == 409
    assert stub.calls == []


def test_recipient_allowlist_blocks_real_addresses(env):
    client, stub, svc = env
    client.post("/api/incidents", json=sample("public_bucket", recipients=["person@real-company.pl"]))
    client.post("/api/incidents/INC-2026-101/approve", json={"approver": "Anna Nowak"})
    r = client.post("/api/incidents/INC-2026-101/send").json()
    assert r["status"] == "SEND_PARTIAL"
    assert all(c["Destination"]["ToAddresses"][0].endswith("simulator.amazonses.com") for c in stub.calls)
    assert any(e["event"] == "SEND_REFUSED" for e in svc.ledger.entries("INC-2026-101"))


def test_ses_failure_is_logged_and_retry_does_not_duplicate(tmp_path):
    stub = StubSes(fail_for={"bounce@simulator.amazonses.com"})
    svc = Service(tmp_path, SesMailer(client=stub, sender="agent@example.test"))
    client = TestClient(create_app(svc))
    client.post("/api/incidents", json=sample("public_bucket"))
    client.post("/api/incidents/INC-2026-101/approve", json={"approver": "Anna Nowak"})
    first = client.post("/api/incidents/INC-2026-101/send").json()
    assert first["status"] == "SEND_PARTIAL"
    sent_first = len(stub.calls)
    stub.fail_for.clear()
    second = client.post("/api/incidents/INC-2026-101/send").json()
    assert second["status"] == "SENT"
    assert len(stub.calls) == sent_first + 1  # only the failed one is retried
    assert any(e["event"] == "SEND_FAILED" for e in svc.ledger.entries("INC-2026-101"))


def test_duplicate_incident_conflict(env):
    client, _, _ = env
    client.post("/api/incidents", json=sample("public_bucket"))
    assert client.post("/api/incidents", json=sample("public_bucket")).status_code == 409


def test_invalid_payload_rejected(env):
    client, _, _ = env
    bad = sample("public_bucket")
    bad["discovered_at"] = "2026-10-28T08:00:00"
    assert client.post("/api/incidents", json=bad).status_code == 422


def test_ui_pages_render(env):
    client, _, _ = env
    assert client.get("/").status_code == 200
    client.post("/api/incidents", json=sample("public_bucket"))
    assert "Human approval" in client.get("/incidents/INC-2026-101").text
    assert "SHA-256" in client.get("/ledger").text


def test_mailer_missing_sender_and_domain_check(monkeypatch):
    monkeypatch.delenv("SES_FROM", raising=False)
    with pytest.raises(MailError):
        SesMailer(client=StubSes(), sender="").send("success@simulator.amazonses.com", "s", "b")
    with pytest.raises(RecipientNotAllowed):
        SesMailer(client=StubSes(), sender="a@b.test").send("x@evil.example", "s", "b")
