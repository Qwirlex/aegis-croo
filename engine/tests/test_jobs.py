import json
import time
from pathlib import Path

import pytest

from aegis_engine.jobs import JobStore


def store(tmp_path: Path) -> JobStore:
    return JobStore(dir=str(tmp_path), ttl_days=7)


def test_create_returns_a_twelve_hex_id_and_a_queued_job(tmp_path):
    s = store(tmp_path)
    job = s.create(target={"address": "0xabc", "chain": "base"})
    assert len(job["id"]) == 12
    assert all(c in "0123456789abcdef" for c in job["id"])
    assert job["state"] == "queued"
    assert (tmp_path / f"{job['id']}.json").exists()


def test_two_jobs_do_not_collide(tmp_path):
    s = store(tmp_path)
    ids = {s.create(target={})["id"] for _ in range(20)}
    assert len(ids) == 20


def test_progress_and_completion_are_persisted(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    s.mark_running(job["id"])
    s.set_progress(job["id"], {"stage": "lenses", "lenses_done": 3})
    s.complete(job["id"], report={"verdict": "caution"})
    got = s.get(job["id"])
    assert got["state"] == "done"
    assert got["progress"]["lenses_done"] == 3
    assert got["report"]["verdict"] == "caution"


def test_a_finished_job_is_readable_by_a_fresh_store_after_a_restart(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    s.complete(job["id"], report={"verdict": "looks_ok"})
    assert store(tmp_path).get(job["id"])["report"]["verdict"] == "looks_ok"


def test_failure_records_the_reason_and_offers_one_retry(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    s.fail(job["id"], reason="model down")
    got = s.get(job["id"])
    assert got["state"] == "failed"
    assert got["reason"] == "model down"
    assert got["retries_left"] == 1


def test_retry_is_allowed_once_and_then_refused(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    s.fail(job["id"], reason="x")
    assert s.retry(job["id"])["state"] == "queued"
    s.fail(job["id"], reason="x again")
    with pytest.raises(ValueError) as e:
        s.retry(job["id"])
    assert "no retry left" in str(e.value)


def test_a_job_left_running_by_a_crash_is_recovered_as_failed_with_a_retry(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    s.mark_running(job["id"])
    recovered = store(tmp_path).recover_interrupted()
    assert recovered == [job["id"]]
    got = store(tmp_path).get(job["id"])
    assert got["state"] == "failed"
    assert got["retries_left"] == 1
    assert "restart" in got["reason"]


def test_recovery_leaves_finished_jobs_alone(tmp_path):
    s = store(tmp_path)
    done = s.create(target={})
    s.complete(done["id"], report={"verdict": "looks_ok"})
    assert store(tmp_path).recover_interrupted() == []
    assert store(tmp_path).get(done["id"])["state"] == "done"


def test_expired_jobs_are_purged(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    stale = json.loads((tmp_path / f"{job['id']}.json").read_text())
    stale["created_at"] = time.time() - 8 * 86400
    (tmp_path / f"{job['id']}.json").write_text(json.dumps(stale))
    assert s.purge_expired() == 1
    assert s.get(job["id"]) is None


def test_a_fresh_job_survives_a_purge(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    assert s.purge_expired() == 0
    assert s.get(job["id"]) is not None


def test_unknown_and_malformed_ids_return_none(tmp_path):
    s = store(tmp_path)
    assert s.get("deadbeefdead") is None
    assert s.get("../etc/passwd") is None
    assert s.get("") is None
    assert s.get("ABCDEF123456") is None


def test_a_corrupt_job_file_reads_as_missing_rather_than_raising(tmp_path):
    s = store(tmp_path)
    job = s.create(target={})
    (tmp_path / f"{job['id']}.json").write_text("{not json")
    assert s.get(job["id"]) is None


def test_updating_an_unknown_job_raises(tmp_path):
    s = store(tmp_path)
    with pytest.raises(ValueError):
        s.mark_running("deadbeefdead")
