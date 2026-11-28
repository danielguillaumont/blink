"""``blink serve``: the local dashboard and API (FastAPI + Jinja2 + HTMX, no build step)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, ValidationError

from ..alerts import ACCEPTED, ACKNOWLEDGED, ACTIVE, OPEN, RESOLVED, STATES, AlertManager
from ..errors import BlinkError
from ..project import Project
from ..scan import blink_version
from ..store import Store
from . import views
from .security import SESSION_COOKIE, Guard, csrf_token, security_middleware

ACTIONS = {"ack": ACKNOWLEDGED, "resolve": RESOLVED, "accept": ACCEPTED, "reopen": OPEN}
SWAGGER_VERSION = "5.17.14"
SWAGGER_JS_SRI = "sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep"
SWAGGER_CSS_SRI = "sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn"


class AlertAction(BaseModel):
    by: str = Field(min_length=1, max_length=200, description="who is making the change")
    note: str = Field(default="", max_length=2000)


class Approval(BaseModel):
    justification: str = Field(min_length=1, max_length=2000)
    owner: str = Field(min_length=1, max_length=200)
    approved_by: str = Field(min_length=1, max_length=200)
    dynamic: bool = False
    notes: str | None = Field(default=None, max_length=2000)


def _templates() -> Jinja2Templates:
    directory = str(files("blink_visual.server") / "templates")
    templates = Jinja2Templates(directory=directory)
    templates.env.autoescape = True
    templates.env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, sort_keys=True)
    return templates


async def _payload(request: Request) -> dict[str, Any]:
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            data = await request.json()
        except ValueError:
            raise HTTPException(400, "invalid JSON body") from None
        if not isinstance(data, dict):
            raise HTTPException(400, "the JSON body must be an object")
        return data
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


def create_app(project: Project, *, token: str, loopback: bool = True) -> FastAPI:
    app = FastAPI(
        title="Blink",
        version=blink_version(),
        description="Payment page integrity monitoring (PCI DSS 6.4.3 / 11.6.1). "
        "Non-GET endpoints need `Authorization: Bearer <token>` (see `.blink/blink.token`).",
        docs_url=None,
        redoc_url=None,
    )
    guard = Guard(token=token, loopback=loopback)
    app.middleware("http")(security_middleware(guard))
    app.mount(
        "/static",
        StaticFiles(directory=str(files("blink_visual.server") / "static")),
        name="static",
    )
    templates = _templates()

    @contextmanager
    def store() -> Iterator[Store]:
        with project.open_store() as opened:
            yield opened

    def page(request: Request, name: str, **context: Any) -> HTMLResponse:
        context.update(
            request=request,
            csrf=csrf_token(request),
            version=app.version,
            loopback=loopback,
            nav=name.split(".")[0],
        )
        return templates.TemplateResponse(request, name, context)

    def partial(request: Request, name: str, **context: Any) -> HTMLResponse:
        context.update(csrf=csrf_token(request))
        return templates.TemplateResponse(request, name, context)

    @app.exception_handler(ValidationError)
    async def invalid(request: Request, exc: ValidationError) -> Response:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'body'}: {e['msg']}" for e in exc.errors()
        )
        return JSONResponse({"detail": problems}, status_code=422)

    @app.exception_handler(BlinkError)
    async def blink_error(request: Request, exc: BlinkError) -> Response:
        message = str(exc)
        status = 404 if message.startswith("unknown") else 400
        if request.url.path.startswith("/api/") or request.headers.get("hx-request"):
            return JSONResponse({"detail": message}, status_code=status)
        response = page(request, "error.html", message=message, status=status)
        response.status_code = status
        return response

    # -- HTML pages --------------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def targets_page(request: Request) -> HTMLResponse:
        with store() as s:
            return page(request, "targets.html", targets=views.targets_overview(project, s))

    @app.get("/runs", response_class=HTMLResponse, include_in_schema=False)
    def runs_page(request: Request) -> HTMLResponse:
        with store() as s:
            return page(request, "runs.html", runs=views.runs(s))

    @app.get("/runs/{run_id}", response_class=HTMLResponse, include_in_schema=False)
    def run_page(request: Request, run_id: str) -> HTMLResponse:
        with store() as s:
            return page(request, "run.html", **views.run_detail(s, run_id))

    @app.get(
        "/findings/{run_id}/{fingerprint}", response_class=HTMLResponse, include_in_schema=False
    )
    def finding_page(request: Request, run_id: str, fingerprint: str) -> HTMLResponse:
        with store() as s:
            return page(request, "finding.html", **views.finding_detail(s, run_id, fingerprint))

    @app.get("/inventory", response_class=HTMLResponse, include_in_schema=False)
    def inventory_page(request: Request) -> HTMLResponse:
        with store() as s:
            return page(request, "inventory.html", rows=views.inventory_rows(project, s))

    @app.get("/alerts", response_class=HTMLResponse, include_in_schema=False)
    def alerts_page(request: Request, state: str = "active") -> HTMLResponse:
        wanted = ACTIVE if state == "active" else ({state} if state in STATES else set(STATES))
        with store() as s:
            alerts = [a.to_dict() for a in AlertManager(s).all(wanted)]
        return page(request, "alerts.html", alerts=alerts, state=state, states=STATES)

    @app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
    def settings_page(request: Request) -> HTMLResponse:
        text = yaml.safe_dump(views.settings(project), sort_keys=False, allow_unicode=True)
        return page(
            request, "settings.html", config_yaml=text, config_path=str(project.config_path)
        )

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    def login_page(request: Request) -> HTMLResponse:
        return page(request, "login.html", failed=False)

    @app.post("/login", include_in_schema=False)
    async def login(request: Request) -> Response:
        data = await _payload(request)
        if not Guard.form_csrf_ok(request, str(data.get("csrf_token", ""))):
            raise HTTPException(403, "CSRF check failed; reload the login page")
        if not guard.token_ok(str(data.get("token", ""))):
            rejected = page(request, "login.html", failed=True)
            rejected.status_code = 401
            return rejected
        response = Response(status_code=303, headers={"location": "/"})
        response.set_cookie(
            SESSION_COOKIE,
            guard.session_value,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )
        return response

    @app.get("/blobs/{digest}", include_in_schema=False)
    def blob(digest: str) -> Response:
        with store() as s:
            media_type = views.blob_media_type(s, digest)
            if media_type not in views.IMAGE_TYPES:
                raise HTTPException(404, "only image evidence is served")
            data = s.get_blob(digest)
        return Response(data, media_type=media_type)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        with store() as s:
            s.db.query_one("SELECT 1")
        return {"status": "ok", "version": app.version}

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        from ..metrics import render

        with store() as s:
            return PlainTextResponse(render(s), media_type="text/plain; version=0.0.4")

    @app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
    def docs(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "docs.html",
            {
                "swagger_version": SWAGGER_VERSION,
                "js_sri": SWAGGER_JS_SRI,
                "css_sri": SWAGGER_CSS_SRI,
            },
        )

    # -- JSON API --------------------------------------------------------------------------------
    @app.get("/api/targets", tags=["read"])
    def api_targets() -> list[dict[str, Any]]:
        with store() as s:
            return views.targets_overview(project, s)

    @app.get("/api/runs", tags=["read"])
    def api_runs(limit: int = 200) -> list[dict[str, Any]]:
        with store() as s:
            return views.runs(s, limit=max(1, min(limit, 1000)))

    @app.get("/api/runs/{run_id}", tags=["read"])
    def api_run(run_id: str) -> dict[str, Any]:
        with store() as s:
            return views.run_detail(s, run_id)

    @app.get("/api/findings/{run_id}/{fingerprint}", tags=["read"])
    def api_finding(run_id: str, fingerprint: str) -> dict[str, Any]:
        with store() as s:
            return views.finding_detail(s, run_id, fingerprint)

    @app.get("/api/alerts", tags=["read"])
    def api_alerts(state: str | None = None) -> list[dict[str, Any]]:
        with store() as s:
            return [a.to_dict() for a in AlertManager(s).all([state] if state else None)]

    @app.get("/api/inventory", tags=["read"])
    def api_inventory() -> list[dict[str, Any]]:
        with store() as s:
            return views.inventory_rows(project, s)

    @app.get("/api/ledger", tags=["read"])
    def api_ledger() -> dict[str, Any]:
        with store() as s:
            return s.ledger.verify().to_dict()

    @app.post("/api/alerts/{alert_id}/{action}", tags=["write"])
    async def api_alert_action(request: Request, alert_id: str, action: str) -> Response:
        if action not in ACTIONS:
            raise HTTPException(404, f"unknown action '{action}'")
        body = AlertAction.model_validate(await _payload(request))
        with store() as s:
            alert = AlertManager(s).transition(
                alert_id, ACTIONS[action], actor=body.by, note=body.note
            )
        if request.headers.get("hx-request"):
            return partial(request, "_alert_row.html", alert=alert.to_dict())
        return JSONResponse(alert.to_dict())

    @app.post("/api/inventory/{entry_id}/approve", tags=["write"])
    async def api_approve(request: Request, entry_id: str) -> Response:
        from ..commands.inventory import approve_entries

        data = await _payload(request)
        if "dynamic" in data and isinstance(data["dynamic"], str):
            data["dynamic"] = data["dynamic"].lower() in {"1", "true", "on", "yes"}
        body = Approval.model_validate(data)
        (entry,) = approve_entries(
            project,
            [entry_id],
            justification=body.justification,
            owner=body.owner,
            approved_by=body.approved_by,
            dynamic=body.dynamic,
            notes=body.notes,
        )
        with store() as s:
            row = views.inventory_row(project, s, entry.id)
        if request.headers.get("hx-request"):
            return partial(request, "_inventory_row.html", row=row)
        return JSONResponse(row)

    return app


__all__ = ["create_app"]
