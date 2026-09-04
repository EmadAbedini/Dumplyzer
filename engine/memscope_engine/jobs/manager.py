"""Background job manager for long-running analyses."""

from __future__ import annotations

import json
import logging
import threading
import traceback
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from memscope_engine.errors import AppError
from memscope_engine.storage import Database

log = logging.getLogger("memscope.analysis")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


JobHandler = Callable[[Database, dict[str, Any], Callable[[], bool], Callable[[str], None]], dict[str, Any]]


class JobManager:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._handlers: dict[str, JobHandler] = {}
        self._queue: list[str] = []
        self._cv = threading.Condition()
        self._cancel_flags: dict[str, threading.Event] = {}
        self._worker = threading.Thread(target=self._loop, name="memscope-jobs", daemon=True)
        self._started = False

    def register(self, kind: str, handler: JobHandler) -> None:
        self._handlers[kind] = handler

    def start(self) -> None:
        if not self._started:
            self._started = True
            self._worker.start()

    def submit(
        self,
        kind: str,
        *,
        evidence_id: str | None = None,
        process_id: str | None = None,
        pid: int | None = None,
        params: dict[str, Any] | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        if kind not in self._handlers:
            raise AppError(
                code="unknown_job_kind",
                message=f"Unknown job kind: {kind}",
                entity="job",
            )
        job_id = str(uuid4())
        now = _utcnow()
        self._db.execute(
            """
            INSERT INTO jobs (
              id, kind, status, evidence_id, process_id, pid, analysis_run_id,
              created_at, started_at, finished_at, progress_kind, message,
              error_json, result_json, params_json, cancel_requested
            ) VALUES (?, ?, 'queued', ?, ?, ?, NULL, ?, NULL, NULL, 'indeterminate', ?, NULL, NULL, ?, 0)
            """,
            (
                job_id,
                kind,
                evidence_id,
                process_id,
                pid,
                now,
                message or kind,
                json.dumps(params or {}),
            ),
        )
        self._cancel_flags[job_id] = threading.Event()
        with self._cv:
            self._queue.append(job_id)
            self._cv.notify()
        log.info("job queued", extra={"channel": "analysis", "job_id": job_id})
        return self.get(job_id)

    def cancel(self, job_id: str) -> dict[str, Any]:
        row = self._db.fetchone("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise AppError(code="job_missing", message="Job not found.", entity="job")
        if row["status"] in ("completed", "failed", "cancelled"):
            return self._dto(row)
        self._db.execute(
            "UPDATE jobs SET cancel_requested = 1, message = ? WHERE id = ?",
            ("Cancel requested", job_id),
        )
        flag = self._cancel_flags.get(job_id)
        if flag:
            flag.set()
        # If still queued, mark cancelled immediately
        with self._cv:
            if job_id in self._queue:
                self._queue.remove(job_id)
                self._db.execute(
                    """
                    UPDATE jobs SET status = 'cancelled', finished_at = ?, message = ?
                    WHERE id = ? AND status = 'queued'
                    """,
                    (_utcnow(), "Cancelled before start", job_id),
                )
        return self.get(job_id)

    def get(self, job_id: str) -> dict[str, Any]:
        row = self._db.fetchone("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise AppError(code="job_missing", message="Job not found.", entity="job")
        return self._dto(row)

    def list_jobs(
        self, *, evidence_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        if evidence_id:
            rows = self._db.fetchall(
                """
                SELECT * FROM jobs WHERE evidence_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (evidence_id, limit),
            )
        else:
            rows = self._db.fetchall(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        return [self._dto(r) for r in rows]

    def _loop(self) -> None:
        while True:
            with self._cv:
                while not self._queue:
                    self._cv.wait()
                job_id = self._queue.pop(0)
            self._run_one(job_id)

    def _run_one(self, job_id: str) -> None:
        row = self._db.fetchone("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            return
        if row["cancel_requested"] or row["status"] == "cancelled":
            self._db.execute(
                "UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE id = ?",
                (_utcnow(), job_id),
            )
            return

        kind = row["kind"]
        handler = self._handlers.get(kind)
        if not handler:
            self._fail(job_id, AppError(code="unknown_job_kind", message=f"No handler for {kind}"))
            return

        try:
            params = json.loads(row["params_json"] or "{}")
        except json.JSONDecodeError:
            params = {}
        params.setdefault("evidence_id", row["evidence_id"])
        params.setdefault("process_id", row["process_id"])
        params.setdefault("pid", row["pid"])
        params["job_id"] = job_id

        cancel_event = self._cancel_flags.setdefault(job_id, threading.Event())

        def cancelled() -> bool:
            if cancel_event.is_set():
                return True
            r = self._db.fetchone(
                "SELECT cancel_requested FROM jobs WHERE id = ?", (job_id,)
            )
            return bool(r and r["cancel_requested"])

        def progress(msg: str) -> None:
            self._db.execute(
                "UPDATE jobs SET message = ? WHERE id = ?",
                (msg, job_id),
            )

        self._db.execute(
            "UPDATE jobs SET status = 'running', started_at = ?, message = ? WHERE id = ?",
            (_utcnow(), f"Running {kind}", job_id),
        )
        try:
            result = handler(self._db, params, cancelled, progress)
            if cancelled():
                self._db.execute(
                    """
                    UPDATE jobs SET status = 'cancelled', finished_at = ?, message = ?,
                      result_json = ? WHERE id = ?
                    """,
                    (_utcnow(), "Cancelled", json.dumps(result or {}), job_id),
                )
            else:
                self._db.execute(
                    """
                    UPDATE jobs SET status = 'completed', finished_at = ?, message = ?,
                      result_json = ? WHERE id = ?
                    """,
                    (
                        _utcnow(),
                        "Completed",
                        json.dumps(result or {}, default=str),
                        job_id,
                    ),
                )
        except AppError as exc:
            if cancelled():
                self._db.execute(
                    "UPDATE jobs SET status = 'cancelled', finished_at = ?, message = ? WHERE id = ?",
                    (_utcnow(), "Cancelled", job_id),
                )
            else:
                self._fail(job_id, exc)
        except Exception as exc:  # noqa: BLE001
            if cancelled():
                self._db.execute(
                    "UPDATE jobs SET status = 'cancelled', finished_at = ?, message = ? WHERE id = ?",
                    (_utcnow(), "Cancelled", job_id),
                )
            else:
                self._fail(
                    job_id,
                    AppError(
                        code="job_failed",
                        message=f"Job {kind} failed.",
                        details=f"{type(exc).__name__}: {exc}",
                        data={"traceback": traceback.format_exc()},
                    ),
                )

    def _fail(self, job_id: str, exc: AppError) -> None:
        self._db.execute(
            """
            UPDATE jobs SET status = 'failed', finished_at = ?, message = ?, error_json = ?
            WHERE id = ?
            """,
            (_utcnow(), exc.message, json.dumps(exc.to_dict()), job_id),
        )

    def _dto(self, row: dict[str, Any]) -> dict[str, Any]:
        def _json(val: Any) -> Any:
            if not val:
                return None
            if isinstance(val, (dict, list)):
                return val
            try:
                return json.loads(val)
            except (TypeError, json.JSONDecodeError):
                return val

        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "evidence_id": row.get("evidence_id"),
            "process_id": row.get("process_id"),
            "pid": row.get("pid"),
            "analysis_run_id": row.get("analysis_run_id"),
            "created_at": row.get("created_at"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
            "progress_kind": row.get("progress_kind") or "indeterminate",
            "message": row.get("message"),
            "error": _json(row.get("error_json")),
            "result": _json(row.get("result_json")),
            "params": _json(row.get("params_json")) or {},
            "cancel_requested": bool(row.get("cancel_requested")),
        }
