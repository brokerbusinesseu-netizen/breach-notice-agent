"""FastAPI application: Breach Notice Agent."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import ValidationError

from . import web
from .models import Incident
from .service import Conflict, NotFound, Service

SAMPLES_DIR = Path(__file__).parent / "samples"
security = HTTPBasic(auto_error=False)


def require_auth(creds: HTTPBasicCredentials | None = Depends(security)) -> None:
    """Optional HTTP Basic protection, enabled when APP_PASSWORD is set."""
    password = os.environ.get("APP_PASSWORD", "")
    if not password:
        return
    ok = creds is not None and secrets.compare_digest(creds.password.encode(), password.encode())
    if not ok:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"}, detail="authentication required")


def create_app(service: Service | None = None) -> FastAPI:
    app = FastAPI(title="Breach Notice Agent", version="1.0.0", dependencies=[Depends(require_auth)])
    svc = service or Service()
    app.state.service = svc

    def sample_names() -> list[str]:
        return sorted(p.stem for p in SAMPLES_DIR.glob("*.json"))

    def load_sample(name: str) -> str:
        if name not in sample_names():
            return ""
        return (SAMPLES_DIR / f"{name}.json").read_text(encoding="utf-8")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    # ---- JSON API
    @app.post("/api/incidents")
    def api_create(incident: Incident):
        try:
            return svc.intake(incident)
        except Conflict as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/incidents")
    def api_list():
        return svc.list()

    @app.get("/api/incidents/{incident_id}")
    def api_get(incident_id: str):
        try:
            return svc.get(incident_id)
        except NotFound:
            raise HTTPException(404, "incident not found")

    @app.post("/api/incidents/{incident_id}/approve")
    def api_approve(incident_id: str, body: dict):
        try:
            return svc.approve(incident_id, body.get("approver", ""), body.get("edited"))
        except NotFound:
            raise HTTPException(404, "incident not found")
        except Conflict as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/incidents/{incident_id}/send")
    def api_send(incident_id: str):
        try:
            return svc.send(incident_id)
        except NotFound:
            raise HTTPException(404, "incident not found")
        except Conflict as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/ledger")
    def api_ledger():
        return {"verify": svc.ledger.verify(), "entries": svc.ledger.entries()}

    @app.get("/api/ledger/verify")
    def api_verify():
        return svc.ledger.verify()

    # ---- HTML UI
    @app.get("/", response_class=HTMLResponse)
    def index(sample: str = ""):
        return web.render(
            web.INDEX,
            rows=svc.list(),
            verify=svc.ledger.verify(),
            samples=sample_names(),
            payload=load_sample(sample),
            error="",
        )

    @app.post("/ui/incidents", response_class=HTMLResponse)
    def ui_create(payload: str = Form(...)):
        try:
            inc = Incident.model_validate(json.loads(payload))
            state = svc.intake(inc)
        except json.JSONDecodeError as exc:
            return _index_error(f"Invalid JSON: {exc.msg}", payload)
        except ValidationError as exc:
            msgs = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
            return _index_error(msgs, payload)
        except Conflict as exc:
            return _index_error(str(exc), payload)
        return RedirectResponse(f"/incidents/{state['id']}", status_code=303)

    def _index_error(message: str, payload: str) -> HTMLResponse:
        html = web.render(
            web.INDEX,
            rows=svc.list(),
            verify=svc.ledger.verify(),
            samples=sample_names(),
            payload=payload,
            error=message,
        )
        return HTMLResponse(html, status_code=400)

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    def detail(incident_id: str):
        try:
            state = svc.get(incident_id)
        except NotFound:
            raise HTTPException(404, "incident not found")
        return web.render(
            web.DETAIL, s=state, a=state["assessment"], log=svc.ledger.entries(incident_id)
        )

    @app.post("/incidents/{incident_id}/approve")
    async def ui_approve(incident_id: str, request: Request):
        form = await request.form()
        edited: dict = {}
        for key, value in form.items():
            if key.startswith("subject__"):
                edited.setdefault(key[len("subject__"):], {})["subject"] = str(value)
            elif key.startswith("body__"):
                edited.setdefault(key[len("body__"):], {})["body"] = str(value)
        try:
            svc.approve(incident_id, str(form.get("approver", "")), edited)
        except NotFound:
            raise HTTPException(404, "incident not found")
        except Conflict as exc:
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/incidents/{incident_id}", status_code=303)

    @app.post("/incidents/{incident_id}/send")
    def ui_send(incident_id: str):
        try:
            svc.send(incident_id)
        except NotFound:
            raise HTTPException(404, "incident not found")
        except Conflict as exc:
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/incidents/{incident_id}", status_code=303)

    @app.get("/ledger", response_class=HTMLResponse)
    def ledger_page():
        return web.render(web.LEDGER, rows=svc.ledger.entries(), verify=svc.ledger.verify())

    return app


app = create_app() if os.environ.get("BNA_NO_AUTOSTART") != "1" else None
