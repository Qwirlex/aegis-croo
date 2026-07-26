from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

# A job id is exactly twelve lowercase hex characters. Nothing else may reach
# the filesystem, which is what makes a path like ../etc/passwd a miss rather
# than a traversal.
_ID_RE = re.compile(r"^[0-9a-f]{12}$")


class JobStore:
    """One JSON file per job so a paid job survives a process restart.

    The restart case is the one that matters. The buyer has already paid by the
    time a job exists, so losing it quietly would be theft. A job interrupted by
    a restart comes back as failed with its free retry intact.
    """

    def __init__(self, dir: str | None = None, ttl_days: int | None = None):
        self.dir = Path(dir or os.environ.get("AUDIT_JOB_DIR", ".jobs"))
        self.ttl_days = ttl_days if ttl_days is not None else int(
            os.environ.get("AUDIT_JOB_TTL_DAYS", "7"))
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, job_id: str) -> Path | None:
        if not _ID_RE.match(job_id or ""):
            return None
        return self.dir / f"{job_id}.json"

    def _write(self, job: dict) -> dict:
        path = self._path(job["id"])
        assert path is not None
        path.write_text(json.dumps(job), encoding="utf-8")
        return job

    def create(self, *, target: dict, tier: str = "audit") -> dict:
        job = {
            "id": secrets.token_hex(6),
            "state": "queued",
            "tier": tier,
            "target": target,
            "progress": {"stage": "queued"},
            "report": None,
            "reason": None,
            "retries_left": 1,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        with self._lock:
            return self._write(job)

    def get(self, job_id: str) -> dict | None:
        path = self._path(job_id)
        if path is None or not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            # A half written file reads as missing rather than raising, so one
            # damaged job cannot take down the status route for every other job.
            return None

    def _update(self, job_id: str, **fields) -> dict:
        with self._lock:
            job = self.get(job_id)
            if job is None:
                raise ValueError("unknown job")
            job.update(fields)
            job["updated_at"] = time.time()
            return self._write(job)

    def mark_running(self, job_id: str) -> dict:
        return self._update(job_id, state="running", progress={"stage": "analysing"})

    def set_progress(self, job_id: str, progress: dict) -> dict:
        return self._update(job_id, progress=progress)

    def complete(self, job_id: str, *, report: dict) -> dict:
        # Keep whatever detail the run recorded on the way, such as how many
        # lenses finished, and only move the stage. A buyer reading the status
        # after the fact can still see what the run actually did.
        job = self.get(job_id)
        progress = {**(job or {}).get("progress", {}), "stage": "complete"}
        return self._update(job_id, state="done", report=report,
                            progress=progress, reason=None)

    def fail(self, job_id: str, *, reason: str) -> dict:
        return self._update(job_id, state="failed", reason=reason[:400],
                            progress={"stage": "failed"})

    def retry(self, job_id: str) -> dict:
        job = self.get(job_id)
        if job is None:
            raise ValueError("unknown job")
        if job.get("retries_left", 0) < 1:
            raise ValueError("no retry left for this job")
        return self._update(job_id, state="queued", reason=None,
                            retries_left=job["retries_left"] - 1,
                            progress={"stage": "queued"})

    def recover_interrupted(self) -> list[str]:
        """Turn jobs that were mid flight at shutdown into honest failures.

        Leaving them as running would show a buyer a job that is quietly dead,
        so they come back as failed and keep their free rerun.
        """
        out = []
        for path in sorted(self.dir.glob("*.json")):
            job = self.get(path.stem)
            if job and job.get("state") in ("running", "queued"):
                self.fail(job["id"], reason="the engine restarted while this job was running")
                out.append(job["id"])
        return out

    def purge_expired(self) -> int:
        cutoff = time.time() - self.ttl_days * 86400
        n = 0
        for path in sorted(self.dir.glob("*.json")):
            job = self.get(path.stem)
            if job is None or job.get("created_at", 0) < cutoff:
                path.unlink(missing_ok=True)
                n += 1
        return n
