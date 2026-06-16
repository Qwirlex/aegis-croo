from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from .audit import audit as _default_audit

app = FastAPI(title="Aegis Engine")
_audit_fn = _default_audit


def _set_audit(fn):
    """Test seam to inject a custom audit function."""
    global _audit_fn
    _audit_fn = fn


class AuditRequest(BaseModel):
    source: str | None = None
    address: str | None = None


@app.post("/audit")
def audit_endpoint(req: AuditRequest):
    """Audit a smart contract source or address."""
    return _audit_fn(source=req.source, address=req.address).model_dump()


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"ok": True}
