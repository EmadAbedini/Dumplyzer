"""Background job manager for long-running analyses."""

from __future__ import annotations

import json
import logging
import threading
import time
import traceback
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from memscope_engine.errors import AppError, JobCancelled
from memscope_engine.storage import Database

log = logging.getLogger("memscope.analysis")

# Side-channel so a running Volatility worker can observe cancel without waiting
# for the single-threaded RPC loop to acquire the GIL.
CANCEL_MARKER_DIRNAME = "job-cancel"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evidence_filename(row: dict[str, Any]) -> str | None:
    named = row.get("evidence_filename") or row.get("filename")
    if isinstance(named, str) and named.strip():
        return named.strip()
    return None


_JOB_SELECT = """
SELECT jobs.*,
  (SELECT filename FROM evidence WHERE evidence.id = jobs.evidence_id) AS evidence_filename
FROM jobs
"""

# Jobs UI only needs scalars + progress/error labels. Full result_json can be
# megabytes (plugin rows, FLOSS strings) and freezes the desktop webview.
_JOB_LIST_SELECT = """
SELECT
  jobs.id,
  jobs.kind,
  jobs.status,
  jobs.evidence_id,
  jobs.process_id,
  jobs.pid,
  jobs.analysis_run_id,
  jobs.created_at,
  jobs.started_at,
  jobs.finished_at,
  jobs.progress_kind,
  jobs.message,
  jobs.cancel_requested,
  (SELECT filename FROM evidence WHERE evidence.id = jobs.evidence_id) AS evidence_filename,
  json_extract(jobs.result_json, '$.percent') AS result_percent,
  json_extract(jobs.result_json, '$.phase') AS result_phase,
  json_extract(jobs.result_json, '$.evidence.filename') AS result_evidence_filename,
  json_extract(jobs.params_json, '$.profile') AS param_profile,
  json_extract(jobs.params_json, '$.filename') AS param_filename,
  json_extract(jobs.params_json, '$.path') AS param_path,
  json_extract(jobs.error_json, '$.message') AS error_message,
  json_extract(jobs.error_json, '$.suggestion') AS error_suggestion,
  COALESCE(
    json_extract(jobs.error_json, '$.code'),
    json_extract(jobs.error_json, '$.app_code')
  ) AS error_code
FROM jobs
"""


ProgressFn = Callable[..., None]
JobHandler = Callable[[Database, dict[str, Any], Callable[[], bool], ProgressFn], dict[str, Any]]


class JobManager:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._handlers: dict[str, JobHandler] = {}
        self._queue: list[str] = []
        self._cv = threading.Condition()
        self._cancel_flags: dict[str, threading.Event] = {}
        self._worker = threading.Thread(target=self._loop, name="memscope-jobs", daemon=True)
        self._started = False
        self._current_job_id: str | None = None
        # Jobs UI is session/case scoped. Rows may remain in SQLite for job.get
        # during this process, but historical jobs are never listed after restart
        # or a new evidence import.
        self._visible_since = _utcnow()

    def register(self, kind: str, handler: JobHandler) -> None:
        self._handlers[kind] = handler

    def has_live_work(self) -> bool:
        """True when this process is actually running or about to run a job."""
        if self._current_job_id:
            return True
        with self._cv:
            return bool(self._queue)

    def _live_job_ids(self) -> set[str]:
        live: set[str] = set()
        if self._current_job_id:
            live.add(self._current_job_id)
        with self._cv:
            live.update(self._queue)
        return live

    def abandon_orphans(self) -> None:
        """Close queued/running rows left by a previous engine process."""
        live = self._live_job_ids()
        rows = self._db.fetchall(
            "SELECT id FROM jobs WHERE status IN ('queued', 'running')"
        )
        now = _utcnow()
        for row in rows:
            job_id = str(row["id"])
            if job_id in live:
                continue
            self._db.execute(
                """
                UPDATE jobs SET status = 'cancelled', cancel_requested = 1,
                  finished_at = ?, message = ?
                WHERE id = ? AND status IN ('queued', 'running')
                """,
                (now, "Abandoned after restart", job_id),
            )
            self._clear_cancel_marker(job_id)

    def start(self) -> None:
        if self._started and self._worker.is_alive():
            self.abandon_orphans()
            return
        if self._started and not self._worker.is_alive():
            log.warning("job worker thread died; restarting", extra={"channel": "analysis"})
            stuck = self._current_job_id
            self._current_job_id = None
            if stuck:
                with self._cv:
                    if stuck not in self._queue:
                        self._queue.insert(0, stuck)
                    self._cv.notify()
            self._worker = threading.Thread(
                target=self._loop, name="memscope-jobs", daemon=True
            )
        self.abandon_orphans()
        self._started = True
        self._worker.start()
        log.info("job worker started", extra={"channel": "analysis"})

    def reset_visible_jobs(self) -> None:
        """Drop previous-case jobs from the active list without deleting analysis data."""
        self._visible_since = _utcnow()

    def cancel_active(self) -> None:
        """Request cancel for queued/running jobs so a new import can take the worker."""
        self.abandon_orphans()
        rows = self._db.fetchall(
            "SELECT id FROM jobs WHERE status IN ('queued', 'running')"
        )
        for row in rows:
            try:
                self.cancel(str(row["id"]))
            except AppError:
                continue

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

    def _cancel_marker_dir(self) -> Path:
        return self._db.path.parent / "tmp" / CANCEL_MARKER_DIRNAME

    def _cancel_marker_path(self, job_id: str) -> Path | None:
        if not job_id or len(job_id) > 80:
            return None
        if any(c not in "0123456789abcdefABCDEF-_" for c in job_id):
            return None
        return self._cancel_marker_dir() / job_id

    def _write_cancel_marker(self, job_id: str) -> None:
        path = self._cancel_marker_path(job_id)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("1", encoding="utf-8")
        except OSError:
            log.warning("could not write cancel marker", extra={"channel": "analysis", "job_id": job_id})

    def _clear_cancel_marker(self, job_id: str) -> None:
        path = self._cancel_marker_path(job_id)
        if path is None:
            return
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def _cancel_marker_exists(self, job_id: str) -> bool:
        path = self._cancel_marker_path(job_id)
        return bool(path and path.is_file())

    def cancel(self, job_id: str) -> dict[str, Any]:
        row = self._db.fetchone("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise AppError(code="job_missing", message="Job not found.", entity="job")
        if row["status"] in ("completed", "failed", "cancelled"):
            return self._dto(row)
        if job_id not in self._live_job_ids():
            self._db.execute(
                """
                UPDATE jobs SET status = 'cancelled', cancel_requested = 1,
                  finished_at = ?, message = ?
                WHERE id = ? AND status IN ('queued', 'running')
                """,
                (_utcnow(), "Abandoned after restart", job_id),
            )
            self._clear_cancel_marker(job_id)
            return self.get(job_id)
        self._write_cancel_marker(job_id)
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
                self._clear_cancel_marker(job_id)
        return self.get(job_id)

    def get(self, job_id: str) -> dict[str, Any]:
        row = self._db.fetchone(f"{_JOB_SELECT} WHERE jobs.id = ?", (job_id,))
        if not row:
            raise AppError(code="job_missing", message="Job not found.", entity="job")
        return self._dto(row)

    def list_jobs(
        self, *, evidence_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        since = self._visible_since
        if evidence_id:
            rows = self._db.fetchall(
                f"""
                {_JOB_LIST_SELECT}
                WHERE jobs.evidence_id = ? AND jobs.created_at >= ?
                ORDER BY jobs.created_at DESC LIMIT ?
                """,
                (evidence_id, since, limit),
            )
        else:
            rows = self._db.fetchall(
                f"""
                {_JOB_LIST_SELECT}
                WHERE jobs.created_at >= ?
                ORDER BY jobs.created_at DESC LIMIT ?
                """,
                (since, limit),
            )
        return [
            self._list_dto(r)
            for r in rows
            if r.get("kind") != "kernel_symbols_fetch"
            and r.get("error_code") != "kernel_symbols_required"
        ]

    def _loop(self) -> None:
        while True:
            try:
                with self._cv:
                    while not self._queue:
                        self._cv.wait()
                    job_id = self._queue.pop(0)
                self._run_one(job_id)
            except Exception:  # noqa: BLE001
                log.exception("job worker loop error")

    def _run_one(self, job_id: str) -> None:
        self._current_job_id = job_id
        try:
            self._execute_job(job_id)
        finally:
            self._current_job_id = None
            self._clear_cancel_marker(job_id)

    def _execute_job(self, job_id: str) -> None:
        row = self._db.fetchone("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            return
        if (
            row["cancel_requested"]
            or row["status"] == "cancelled"
            or self._cancel_marker_exists(job_id)
        ):
            self._db.execute(
                """
                UPDATE jobs SET status = 'cancelled', cancel_requested = 1,
                  finished_at = ?, message = ? WHERE id = ?
                """,
                (_utcnow(), "Cancelled before start", job_id),
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
        last_cancel_io = 0.0
        last_progress_write = 0.0
        last_progress_phase: Any = object()
        last_progress_pct: float | None = None

        def cancelled() -> bool:
            nonlocal last_cancel_io
            if cancel_event.is_set():
                return True
            now = time.monotonic()
            if now - last_cancel_io < 0.2:
                return False
            last_cancel_io = now
            if self._cancel_marker_exists(job_id):
                cancel_event.set()
                self._db.execute(
                    """
                    UPDATE jobs SET cancel_requested = 1, message = ?
                    WHERE id = ? AND cancel_requested = 0
                      AND status NOT IN ('completed', 'failed', 'cancelled')
                    """,
                    ("Cancel requested", job_id),
                )
                return True
            r = self._db.fetchone(
                "SELECT cancel_requested FROM jobs WHERE id = ?", (job_id,)
            )
            if r and r["cancel_requested"]:
                cancel_event.set()
                return True
            return False

        def progress(msg: str, extra: dict[str, Any] | None = None) -> None:
            nonlocal last_progress_write, last_progress_phase, last_progress_pct
            if cancelled():
                return
            extra = extra or {}
            pct_raw = extra.get("percent")
            try:
                pct = float(pct_raw) if pct_raw is not None else None
            except (TypeError, ValueError):
                pct = None
            phase = extra.get("phase")
            now = time.monotonic()
            same_phase = phase == last_progress_phase
            small_pct = (
                pct is not None
                and last_progress_pct is not None
                and abs(pct - last_progress_pct) < 1.0
            )
            has_coverage = extra.get("coverage") is not None
            if last_progress_write > 0:
                if has_coverage:
                    if now - last_progress_write < 0.15:
                        return
                elif same_phase and (pct is None or small_pct) and now - last_progress_write < 0.25:
                    return
            last_progress_write = now
            last_progress_phase = phase
            last_progress_pct = pct
            current = self._db.fetchone(
                "SELECT progress_kind, result_json FROM jobs WHERE id = ?",
                (job_id,),
            )
            previous: dict[str, Any] = {}
            raw = current.get("result_json") if current else None
            if raw:
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) else raw
                except (TypeError, json.JSONDecodeError):
                    parsed = None
                if isinstance(parsed, dict):
                    previous = parsed
            payload = dict(previous)
            if extra:
                payload.update(extra)
            payload["message"] = msg
            progress_kind = (
                "determinate"
                if payload.get("percent") is not None
                else ((current.get("progress_kind") if current else None) or "indeterminate")
            )
            self._db.execute(
                """
                UPDATE jobs SET message = ?, progress_kind = ?, result_json = ?
                WHERE id = ?
                """,
                (msg, progress_kind, json.dumps(payload, default=str), job_id),
            )

        log.info("job starting", extra={"channel": "analysis", "job_id": job_id})
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
        except JobCancelled:
            self._db.execute(
                "UPDATE jobs SET status = 'cancelled', finished_at = ?, message = ? WHERE id = ?",
                (_utcnow(), "Cancelled", job_id),
            )
        except AppError as exc:
            if cancelled():
                self._db.execute(
                    "UPDATE jobs SET status = 'cancelled', finished_at = ?, message = ? WHERE id = ?",
                    (_utcnow(), "Cancelled", job_id),
                )
            else:
                log.error(
                    "job failed: %s (%s)",
                    exc.message,
                    exc.code,
                    extra={
                        "channel": "analysis",
                        "job_id": job_id,
                        "code": exc.code,
                        "details": exc.details,
                    },
                )
                self._fail(job_id, exc)
        except Exception as exc:  # noqa: BLE001
            if cancelled():
                self._db.execute(
                    "UPDATE jobs SET status = 'cancelled', finished_at = ?, message = ? WHERE id = ?",
                    (_utcnow(), "Cancelled", job_id),
                )
            else:
                log.exception(
                    "job crashed: %s",
                    kind,
                    extra={"channel": "analysis", "job_id": job_id},
                )
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
            "evidence_filename": _evidence_filename(row),
        }

    def _list_dto(self, row: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] | None = None
        percent = row.get("result_percent")
        phase = row.get("result_phase")
        evidence_name = row.get("result_evidence_filename")
        if percent is not None or phase or evidence_name:
            result = {}
            if percent is not None:
                result["percent"] = percent
            if isinstance(phase, str) and phase:
                result["phase"] = phase
            if isinstance(evidence_name, str) and evidence_name.strip():
                result["evidence"] = {"filename": evidence_name.strip()}

        params: dict[str, Any] = {}
        for key, column in (
            ("profile", "param_profile"),
            ("filename", "param_filename"),
            ("path", "param_path"),
        ):
            value = row.get(column)
            if isinstance(value, str) and value.strip():
                params[key] = value.strip()

        error: dict[str, Any] | None = None
        err_message = row.get("error_message")
        err_suggestion = row.get("error_suggestion")
        err_code = row.get("error_code")
        if err_message or err_suggestion or err_code:
            error = {}
            if isinstance(err_message, str) and err_message:
                error["message"] = err_message
            if isinstance(err_suggestion, str) and err_suggestion:
                error["suggestion"] = err_suggestion
            if isinstance(err_code, str) and err_code:
                error["code"] = err_code

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
            "error": error,
            "result": result,
            "params": params,
            "cancel_requested": bool(row.get("cancel_requested")),
            "evidence_filename": _evidence_filename(row),
        }
