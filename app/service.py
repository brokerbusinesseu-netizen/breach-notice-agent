"""Workflow: intake -> assessment -> drafts -> human approval -> send -> evidence."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .ledger import Ledger, anonymise, canonical
from .mailer import MailError, RecipientNotAllowed, SesMailer
from .models import Incident
from .notices import build_drafts
from .risk import NONE, assess, deadline_for


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def drafts_hash(drafts: dict) -> str:
    return hashlib.sha256(canonical(drafts).encode("utf-8")).hexdigest()


class Service:
    def __init__(self, data_dir: str | os.PathLike | None = None, mailer: SesMailer | None = None):
        data = Path(data_dir or os.environ.get("DATA_DIR", "./data"))
        data.mkdir(parents=True, exist_ok=True)
        self.db_path = data / "incidents.db"
        self.ledger = Ledger(data / "ledger.jsonl")
        self.mailer = mailer or SesMailer()
        self.salt = os.environ.get("LEDGER_SALT", "dev-salt")
        self._lock = threading.Lock()
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS incidents ("
                "id TEXT PRIMARY KEY, incident TEXT NOT NULL, assessment TEXT NOT NULL, drafts TEXT NOT NULL, "
                "status TEXT NOT NULL, approval TEXT, sends TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL)"
            )

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        return db

    # ---- reads
    def list(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        return [self._row(r) for r in rows]

    def get(self, incident_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            raise NotFound(incident_id)
        return self._row(row)

    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        return {
            "id": r["id"],
            "incident": json.loads(r["incident"]),
            "assessment": json.loads(r["assessment"]),
            "drafts": json.loads(r["drafts"]),
            "status": r["status"],
            "approval": json.loads(r["approval"]) if r["approval"] else None,
            "sends": json.loads(r["sends"]),
            "created_at": r["created_at"],
        }

    def _save(self, incident_id: str, **fields) -> None:
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._db() as db:
            db.execute(f"UPDATE incidents SET {cols} WHERE id = ?", (*fields.values(), incident_id))

    # ---- steps
    def intake(self, inc: Incident, now: datetime | None = None) -> dict:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            with self._db() as db:
                if db.execute("SELECT 1 FROM incidents WHERE id = ?", (inc.incident_id,)).fetchone():
                    raise Conflict(f"incident {inc.incident_id} already exists")
            self.ledger.append(
                inc.incident_id,
                "INTAKE",
                {
                    "title": inc.title,
                    "breach_type": inc.breach_type,
                    "discovered_at": inc.discovered_at.isoformat(),
                    "deadline_72h": deadline_for(inc.discovered_at).isoformat(),
                    "subjects_count": inc.subjects_count,
                    "categories": list(inc.data_categories),
                },
                ts=now,
            )
            a = assess(inc, now)
            self.ledger.append(inc.incident_id, "ASSESSED", a.to_dict(), ts=now)
            drafts = build_drafts(inc, a)
            status = "NO_NOTIFICATION" if a.outcome == NONE else "DRAFTED"
            self.ledger.append(
                inc.incident_id,
                "DRAFTED" if drafts else "REGISTERED_NO_NOTIFICATION",
                {"drafts_sha256": drafts_hash(drafts), "kinds": sorted(drafts)},
                ts=now,
            )
            with self._db() as db:
                db.execute(
                    "INSERT INTO incidents (id, incident, assessment, drafts, status, created_at) VALUES (?,?,?,?,?,?)",
                    (
                        inc.incident_id,
                        inc.model_dump_json(),
                        json.dumps(a.to_dict()),
                        json.dumps(drafts),
                        status,
                        now.isoformat(),
                    ),
                )
        return self.get(inc.incident_id)

    def approve(self, incident_id: str, approver: str, edited: dict | None = None) -> dict:
        approver = (approver or "").strip()
        if len(approver) < 3:
            raise Conflict("approver name is required")
        with self._lock:
            state = self.get(incident_id)
            if state["status"] != "DRAFTED":
                raise Conflict(f"cannot approve an incident in status {state['status']}")
            original = state["drafts"]
            drafts = json.loads(json.dumps(original))
            for key, fields in (edited or {}).items():
                if key in drafts:
                    for fname in ("subject", "body"):
                        if fname in fields and fields[fname] is not None:
                            drafts[key][fname] = fields[fname]
            was_edited = drafts_hash(drafts) != drafts_hash(original)
            approval = {
                "approved_by": approver,
                "approved_at": datetime.now(timezone.utc).isoformat(),
                "drafts_sha256": drafts_hash(drafts),
                "edited_by_human": was_edited,
            }
            self.ledger.append(incident_id, "APPROVED", approval)
            self._save(incident_id, drafts=json.dumps(drafts), approval=json.dumps(approval), status="APPROVED")
        return self.get(incident_id)

    def send(self, incident_id: str) -> dict:
        with self._lock:
            state = self.get(incident_id)
            if state["status"] not in ("APPROVED", "SEND_PARTIAL"):
                self.ledger.append(incident_id, "SEND_REFUSED", {"reason": f"status {state['status']}"})
                raise Conflict(f"human approval is required before sending (status {state['status']})")
            approval = state["approval"]
            if drafts_hash(state["drafts"]) != approval["drafts_sha256"]:
                self.ledger.append(incident_id, "SEND_REFUSED", {"reason": "drafts changed after approval"})
                raise Conflict("drafts changed after approval")

            inc = Incident.model_validate(state["incident"])
            drafts = state["drafts"]
            already = {s["to_ref"] + s["kind"] for s in state["sends"] if s["ok"]}
            sends = list(state["sends"])

            jobs: list[tuple[str, str, str, str]] = []  # kind, to, subject, body
            auth_body = drafts["authority_pl"]["body"] + "\n\n-----\n\n" + drafts["authority_en"]["body"]
            jobs.append(("authority_draft_to_dpo", inc.dpo_email, drafts["authority_en"]["subject"], auth_body))
            if "subject_pl" in drafts:
                body = drafts["subject_pl"]["body"] + "\n\n-----\n\n" + drafts["subject_en"]["body"]
                for rcpt in inc.recipients:
                    jobs.append(("subject_notice", rcpt, drafts["subject_en"]["subject"], body))

            for kind, to, subject, body in jobs:
                ref = anonymise(to, self.salt)
                if ref + kind in already:
                    continue
                self.ledger.append(incident_id, "SEND_ATTEMPT", {"kind": kind, "to_ref": ref})
                try:
                    message_id = self.mailer.send(to, subject, body)
                except RecipientNotAllowed as exc:
                    self.ledger.append(incident_id, "SEND_REFUSED", {"kind": kind, "to_ref": ref, "reason": str(exc)})
                    sends.append({"kind": kind, "to_ref": ref, "ok": False, "error": str(exc)})
                except MailError as exc:
                    self.ledger.append(incident_id, "SEND_FAILED", {"kind": kind, "to_ref": ref, "error": str(exc)})
                    sends.append({"kind": kind, "to_ref": ref, "ok": False, "error": str(exc)})
                else:
                    self.ledger.append(
                        incident_id, "SENT", {"kind": kind, "to_ref": ref, "ses_message_id": message_id}
                    )
                    sends.append({"kind": kind, "to_ref": ref, "ok": True, "message_id": message_id})

            ok_all = all(
                any(s["ok"] and s["to_ref"] == anonymise(to, self.salt) and s["kind"] == kind for s in sends)
                for kind, to, _, _ in jobs
            )
            status = "SENT" if ok_all else "SEND_PARTIAL"
            self._save(incident_id, sends=json.dumps(sends), status=status)
        return self.get(incident_id)
