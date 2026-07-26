from __future__ import annotations

import json
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .audit import audit as _default_audit
from .deep_audit import prepare_target, run_deep_audit, run_quick_scan
from .jobs import JobStore
from .source import ExplorerUnavailable
from .static_analysis import SlitherCompileError

# Injection seams. Tests replace these module attributes, production keeps the
# defaults. They are module level rather than constructor arguments because the
# app object itself is what uvicorn imports.
_audit_fn = _default_audit
_prepare_fn = prepare_target
_deep_fn = run_deep_audit
_scan_fn = run_quick_scan
_store = JobStore()
_report_dir = Path(os.environ.get("AUDIT_REPORT_DIR", ".reports"))
_run_in_background = True


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # A paid job that was mid flight when the process died must not look alive,
    # and old jobs must not pile up on disk forever.
    _store.recover_interrupted()
    _store.purge_expired()
    yield


app = FastAPI(title="Aegis Engine", lifespan=_lifespan)


def _set_audit(fn):
    """Test seam to inject a custom audit function."""
    global _audit_fn
    _audit_fn = fn


class AuditRequest(BaseModel):
    source: str | None = None
    address: str | None = None


class JobRequest(BaseModel):
    source: str | None = None
    address: str | None = None
    chain: str = "base"


@app.post("/audit")
def audit_endpoint(req: AuditRequest):
    """Legacy single pass audit, still used by the CROO provider."""
    return _audit_fn(source=req.source, address=req.address).model_dump()


def _prepare_or_http(req: JobRequest):
    """Run the pre charge gate and translate every failure into a status code.

    The seller maps these one to one, and because the x402 middleware settles a
    payment only on a 2xx, every path here that is not a 200 means the buyer
    pays nothing. That is why an outage must never be dressed up as a 4xx and a
    bad request must never be dressed up as a 5xx.
    """
    try:
        return _prepare_fn(source=req.source, address=req.address, chain=req.chain)
    except SlitherCompileError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ExplorerUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        msg = str(e)
        code = 400 if "chain not supported" in msg or "must provide" in msg else 422
        raise HTTPException(status_code=code, detail=msg)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"upstream unavailable: {e}")


def _write_report(job_id: str, report: dict) -> None:
    """Hand the finished report to the web app through a shared directory.

    The engine never calls the web app, it just drops the file where the report
    page reads it, which keeps the two services independent.
    """
    _report_dir.mkdir(parents=True, exist_ok=True)
    (_report_dir / f"{job_id}.json").write_text(json.dumps(report), encoding="utf-8")


def _run_job(job_id: str, prepared) -> None:
    try:
        _store.mark_running(job_id)
        report = _deep_fn(prepared).model_dump()
        _write_report(job_id, report)
        _store.complete(job_id, report=report)
    except Exception as e:
        _store.fail(job_id, reason=str(e))


def _start(job_id: str, prepared) -> None:
    if _run_in_background:
        threading.Thread(target=_run_job, args=(job_id, prepared), daemon=True).start()
    else:
        _run_job(job_id, prepared)


@app.post("/audit/jobs")
def create_job(req: JobRequest):
    prepared = _prepare_or_http(req)
    job = _store.create(target={
        "address": req.address,
        "chain": getattr(prepared, "chain", req.chain),
        "contract_name": getattr(prepared, "contract_name", "unknown"),
        "compiler": getattr(prepared, "compiler", "unknown"),
    })
    _start(job["id"], prepared)
    return {"job_id": job["id"], "state": "running", "target": job["target"]}


@app.get("/audit/jobs/{job_id}")
def get_job(job_id: str):
    job = _store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return job


@app.post("/audit/jobs/{job_id}/retry")
def retry_job(job_id: str):
    job = _store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job")
    try:
        _store.retry(job_id)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    prepared = _prepare_or_http(JobRequest(address=job["target"].get("address"),
                                           chain=job["target"].get("chain", "base")))
    _start(job_id, prepared)
    return {"job_id": job_id, "state": "running"}


@app.post("/scan")
def scan_endpoint(req: JobRequest):
    prepared = _prepare_or_http(req)
    try:
        return _scan_fn(prepared).model_dump()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"scan failed: {e}")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"ok": True}
