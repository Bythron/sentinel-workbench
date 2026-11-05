"""Optional FastAPI adapter, intended for loopback with an operator token."""

import hmac
import os
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .core import audit_own_device, compare, report
from .plugins import CAPABILITIES, list_plugins
from .policy import Authorization, AuthorizationError
from .store import EvidenceStore


class AuditRequest(BaseModel):
    confirm_own_device: bool
    operator: str
    plugin: Literal["local-inventory", "network-interfaces"] = "local-inventory"


def create_app(*, db_path: str, token: str) -> FastAPI:
    if len(token) < 24:
        raise ValueError("Use an API token of at least 24 characters")
    app = FastAPI(title="Sentinel Workbench", version="0.2.0")

    def authenticate(value: str | None) -> None:
        if not value or not hmac.compare_digest(value, f"Bearer {token}"):
            raise HTTPException(status_code=401, detail="Invalid token")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/v1/plugins")
    def plugins(authorization: str | None = Header(default=None)):
        authenticate(authorization)
        return list_plugins()

    @app.post("/v1/audits/local")
    def audit(request: AuditRequest, authorization: str | None = Header(default=None)):
        authenticate(authorization)
        try:
            scope = Authorization.for_own_device(confirmed=request.confirm_own_device, asserted_by=request.operator,
                                                 action=CAPABILITIES[request.plugin])
        except AuthorizationError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        store = EvidenceStore(db_path)
        try:
            return audit_own_device(store, scope, request.plugin)
        finally:
            store.close()

    @app.get("/v1/report")
    def get_report(authorization: str | None = Header(default=None)):
        authenticate(authorization)
        store = EvidenceStore(db_path)
        try:
            return report(store)
        finally:
            store.close()

    @app.get("/v1/compare/{first}/{second}")
    def get_comparison(first: int, second: int, authorization: str | None = Header(default=None)):
        authenticate(authorization)
        if first < 1 or second < 1:
            raise HTTPException(status_code=422, detail="Evidence IDs must be positive")
        store = EvidenceStore(db_path)
        try:
            try:
                return compare(store, first, second)
            except ValueError as error:
                raise HTTPException(status_code=404, detail=str(error)) from error
        finally:
            store.close()

    return app


def main() -> None:
    import uvicorn
    token = os.environ.get("SENTINEL_API_TOKEN", "")
    db_path = os.environ.get("SENTINEL_DB", "evidence.sqlite3")
    port = int(os.environ.get("SENTINEL_API_PORT", "8765"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid API port")
    app = create_app(db_path=db_path, token=token)
    uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()

