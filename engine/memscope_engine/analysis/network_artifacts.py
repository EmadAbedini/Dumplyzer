"""Network artifact extraction from recovered memory-analysis records.

Harvests indicators that already exist in Dumplyzer (netscan connections,
bulk_extractor features, IOCs, FLOSS strings). Does not invent endpoints.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION

log = logging.getLogger("memscope.analysis")

MAX_ARTIFACTS = 25_000
MAX_IOC_INSERT = 10_000

NETWORK_IOC_TYPES = frozenset(
    {"ipv4", "ipv6", "ip", "url", "http", "domain", "dns", "mac", "network", "tcp"}
)

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r"\b(?!(?:\d+\.)+\d+\b)(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|edu|gov|mil|io|co|info|biz|ru|cn|uk|de|fr|local)\b",
    re.IGNORECASE,
)

ProgressFn = Callable[..., None]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_exists(db: Database, name: str) -> bool:
    row = db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (name,),
    )
    return row is not None


def _json_load(raw: Any, default: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return default


def _classify_ip(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip().strip("[]")
    if not text or text in {"*", "0", "::", ""}:
        return None
    # netscan sometimes uses IPv4-mapped or trailing %scope
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    return "ipv6" if addr.version == 6 else "ipv4"


def _protocol_family(protocol: str | None) -> str | None:
    raw = (protocol or "").strip().lower()
    if not raw:
        return None
    if raw.startswith("tcp"):
        return "tcp"
    if raw.startswith("udp"):
        return "udp"
    return raw


def _endpoint_value(address: str | None, port: int | None) -> str | None:
    if not address:
        return None
    if port is None:
        return str(address)
    return f"{address}:{port}"


def _connection_value(row: dict[str, Any]) -> str:
    proto = row.get("protocol") or "?"
    local = _endpoint_value(row.get("local_address"), row.get("local_port")) or "?"
    remote = _endpoint_value(row.get("remote_address"), row.get("remote_port")) or "?"
    state = row.get("state")
    base = f"{local} → {remote} {proto}"
    return f"{base} {state}".strip() if state else base


class _Collector:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self._seen: set[tuple[Any, ...]] = set()

    def add(self, rec: dict[str, Any]) -> bool:
        if len(self.items) >= MAX_ARTIFACTS:
            return False
        value = str(rec.get("value") or "").strip()
        if not value:
            return False
        rec = dict(rec)
        rec["value"] = value
        key = (
            rec.get("artifact_type"),
            value.lower(),
            rec.get("pid"),
            rec.get("local_address"),
            rec.get("local_port"),
            rec.get("remote_address"),
            rec.get("remote_port"),
            rec.get("source"),
        )
        if key in self._seen:
            return False
        self._seen.add(key)
        self.items.append(rec)
        return True


def harvest_network_artifacts(db: Database, evidence_id: str) -> list[dict[str, Any]]:
    """Build artifact records from already-persisted analysis. No invented evidence."""
    if not db.fetchone("SELECT id FROM evidence WHERE id = ?", (evidence_id,)):
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")
    collector = _Collector()
    _from_connections(db, evidence_id, collector)
    _from_iocs(db, evidence_id, collector)
    _from_bulk_extractor(db, evidence_id, collector)
    _from_floss(db, evidence_id, collector)
    _from_process_text(db, evidence_id, collector)
    return collector.items


def _from_connections(db: Database, evidence_id: str, collector: _Collector) -> None:
    if not _table_exists(db, "network_connections"):
        return
    rows = db.fetchall(
        "SELECT * FROM network_connections WHERE evidence_id = ?",
        (evidence_id,),
    )
    for row in rows:
        proto = _protocol_family(row.get("protocol"))
        method = "volatility.netscan"
        source = "network_connections"
        plugin = row.get("source_plugin") or "windows.netscan"
        base = {
            "connection_id": row.get("id"),
            "process_id": row.get("process_id"),
            "pid": row.get("pid"),
            "protocol": row.get("protocol"),
            "local_address": row.get("local_address"),
            "local_port": row.get("local_port"),
            "remote_address": row.get("remote_address"),
            "remote_port": row.get("remote_port"),
            "state": row.get("state"),
            "source": source,
            "source_plugin": plugin,
            "extraction_method": method,
            "source_address": row.get("offset_hex"),
            "offset_hex": row.get("offset_hex"),
            "context": f"socket {row.get('state') or ''} PID {row.get('pid')}".strip(),
            "metadata": {
                "owner": row.get("owner"),
                "created": row.get("created"),
                "analysis_run_id": row.get("analysis_run_id"),
            },
        }
        collector.add(
            {
                **base,
                "artifact_type": "connection",
                "value": _connection_value(row),
            }
        )
        endpoint_type = "tcp_endpoint" if proto == "tcp" else "udp_endpoint" if proto == "udp" else "socket"
        for addr_key, port_key, side in (
            ("local_address", "local_port", "local"),
            ("remote_address", "remote_port", "remote"),
        ):
            ep = _endpoint_value(row.get(addr_key), row.get(port_key))
            if ep:
                collector.add(
                    {
                        **base,
                        "artifact_type": endpoint_type,
                        "value": ep,
                        "context": f"{side} endpoint PID {row.get('pid')}",
                        "metadata": {**base["metadata"], "side": side},
                    }
                )
            kind = _classify_ip(row.get(addr_key))
            if kind:
                collector.add(
                    {
                        **base,
                        "artifact_type": kind,
                        "value": str(row.get(addr_key)),
                        "context": f"{side} address PID {row.get('pid')}",
                        "metadata": {**base["metadata"], "side": side},
                    }
                )
            port = row.get(port_key)
            if port is not None:
                collector.add(
                    {
                        **base,
                        "artifact_type": "port",
                        "value": str(port),
                        "context": f"{side} port {proto or row.get('protocol') or ''} PID {row.get('pid')}".strip(),
                        "metadata": {**base["metadata"], "side": side},
                    }
                )


def _from_iocs(db: Database, evidence_id: str, collector: _Collector) -> None:
    if not _table_exists(db, "iocs"):
        return
    rows = db.fetchall("SELECT * FROM iocs WHERE evidence_id = ?", (evidence_id,))
    for row in rows:
        ioc_type = str(row.get("ioc_type") or "").lower()
        if ioc_type not in NETWORK_IOC_TYPES:
            continue
        source = row.get("source") or "iocs"
        if source in {"network_artifacts", "network_connections"}:
            continue
        mapped = {
            "ip": _classify_ip(row.get("value")) or "ipv4",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
            "url": "url",
            "http": "http",
            "domain": "dns",
            "dns": "dns",
            "mac": "mac",
            "network": "network_string",
            "tcp": "tcp_endpoint",
        }.get(ioc_type, ioc_type)
        collector.add(
            {
                "process_id": row.get("process_id"),
                "pid": row.get("pid"),
                "artifact_type": mapped,
                "value": row.get("value"),
                "source": source,
                "source_plugin": source,
                "extraction_method": "ioc_extract",
                "context": row.get("context"),
                "metadata": {"ioc_id": row.get("id"), "ioc_type": ioc_type},
            }
        )


def _from_bulk_extractor(db: Database, evidence_id: str, collector: _Collector) -> None:
    if not _table_exists(db, "bulk_extractor_scans"):
        return
    if _table_exists(db, "bulk_extractor_features"):
        feat_rows = db.fetchall(
            """
            SELECT scanner, ioc_type, finding_type, value, offset, context, extra_json, scan_id
            FROM bulk_extractor_features
            WHERE evidence_id = ?
              AND category IN ('ip', 'ether', 'url', 'domain', 'httplogs', 'tcp')
            ORDER BY occurrence_count DESC
            LIMIT 8000
            """,
            (evidence_id,),
        )
        for feat in feat_rows:
            scanner = str(feat.get("scanner") or "")
            ioc_type = str(feat.get("ioc_type") or "").lower()
            mapped = _map_bulk_kind(ioc_type, scanner, feat.get("value"))
            extra = {}
            try:
                extra = json.loads(feat.get("extra_json") or "{}")
            except json.JSONDecodeError:
                extra = {}
            collector.add(
                {
                    "artifact_type": mapped,
                    "value": feat.get("value"),
                    "source": "bulk_extractor",
                    "source_plugin": "provider.bulk_extractor",
                    "extraction_method": "bulk_extractor",
                    "source_address": feat.get("offset"),
                    "offset_hex": feat.get("offset"),
                    "context": feat.get("context")
                    or f"bulk_extractor scanner {scanner}",
                    "metadata": {
                        "scan_id": feat.get("scan_id"),
                        "scanner": scanner,
                        "finding_type": feat.get("finding_type"),
                        **({k: v for k, v in extra.items() if v is not None} if isinstance(extra, dict) else {}),
                    },
                }
            )
        if feat_rows:
            return
    scans = db.fetchall(
        """
        SELECT * FROM bulk_extractor_scans
        WHERE evidence_id = ? AND status = 'completed'
        ORDER BY started_at DESC
        """,
        (evidence_id,),
    )
    for scan in scans:
        observed = _json_load(scan.get("observed_json"), {})
        features = observed.get("features")
        # Features themselves are not stored on the scan row; recover from findings/iocs
        # and from feature_files counts. Prefer IOCs already inserted by the provider.
        # Additionally map scanner names that are network-related.
        feature_files = observed.get("feature_files") or []
        for item in feature_files:
            if not isinstance(item, dict):
                continue
            scanner = str(item.get("scanner") or "")
            ioc_type = str(item.get("ioc_type") or "")
            if ioc_type not in NETWORK_IOC_TYPES and scanner not in NETWORK_IOC_TYPES:
                if scanner not in {"ip", "ether", "url", "tcp", "httplogs", "httpheaders", "domain"}:
                    continue
            # Presence of a network feature file is recorded as a source note only;
            # actual values come from iocs inserted by bulk_extractor_workflows.
        if features and isinstance(features, list):
            for feat in features:
                if not isinstance(feat, dict):
                    continue
                ioc_type = str(feat.get("ioc_type") or "").lower()
                scanner = str(feat.get("scanner") or "")
                if ioc_type not in NETWORK_IOC_TYPES and scanner not in {
                    "ip",
                    "ether",
                    "url",
                    "tcp",
                    "httplogs",
                    "httpheaders",
                    "domain",
                }:
                    continue
                mapped = _map_bulk_kind(ioc_type, scanner, feat.get("value"))
                collector.add(
                    {
                        "artifact_type": mapped,
                        "value": feat.get("value"),
                        "source": "bulk_extractor",
                        "source_plugin": "provider.bulk_extractor",
                        "extraction_method": "bulk_extractor",
                        "source_address": feat.get("offset"),
                        "offset_hex": feat.get("offset"),
                        "context": f"bulk_extractor scanner {scanner} ({feat.get('source_file')})",
                        "metadata": {
                            "scan_id": scan.get("id"),
                            "scanner": scanner,
                            "finding_type": feat.get("finding_type"),
                        },
                    }
                )


def _map_bulk_kind(ioc_type: str, scanner: str, value: Any) -> str:
    key = (ioc_type or scanner or "").lower()
    if key in {"ip"}:
        return _classify_ip(str(value or "")) or "ipv4"
    if key in {"ether", "mac"}:
        return "mac"
    if key in {"url"}:
        return "url"
    if key in {"http", "httplogs", "httpheaders"}:
        return "http"
    if key in {"domain", "dns"}:
        return "dns"
    if key in {"tcp", "network"}:
        return "network_string"
    return key or "network_string"


def _from_floss(db: Database, evidence_id: str, collector: _Collector) -> None:
    if not _table_exists(db, "floss_strings"):
        return
    rows = db.fetchall("SELECT * FROM floss_strings WHERE evidence_id = ?", (evidence_id,))
    for row in rows:
        text = row.get("value")
        if not text:
            continue
        pid = row.get("pid")
        process_id = row.get("process_id")
        for m in _RE_URL.finditer(str(text)):
            collector.add(
                {
                    "process_id": process_id,
                    "pid": pid,
                    "artifact_type": "url",
                    "value": m.group(0).rstrip(".,);"),
                    "source": "floss_strings",
                    "source_plugin": "provider.floss",
                    "extraction_method": "floss",
                    "source_address": row.get("offset"),
                    "context": f"FLOSS {row.get('kind') or 'string'}",
                    "metadata": {"scan_id": row.get("scan_id"), "floss_kind": row.get("kind")},
                }
            )
        for m in _RE_IPV4.finditer(str(text)):
            collector.add(
                {
                    "process_id": process_id,
                    "pid": pid,
                    "artifact_type": "ipv4",
                    "value": m.group(0),
                    "source": "floss_strings",
                    "source_plugin": "provider.floss",
                    "extraction_method": "floss",
                    "source_address": row.get("offset"),
                    "context": f"FLOSS {row.get('kind') or 'string'}",
                    "metadata": {"scan_id": row.get("scan_id")},
                }
            )


def _from_process_text(db: Database, evidence_id: str, collector: _Collector) -> None:
    """Command-line URLs/IPs when IOC extraction has not already stored them."""
    if not _table_exists(db, "processes"):
        return
    rows = db.fetchall(
        "SELECT id, pid, command_line FROM processes WHERE evidence_id = ?",
        (evidence_id,),
    )
    for row in rows:
        text = row.get("command_line")
        if not text:
            continue
        pid = row.get("pid")
        process_id = row.get("id")
        for m in _RE_URL.finditer(str(text)):
            collector.add(
                {
                    "process_id": process_id,
                    "pid": pid,
                    "artifact_type": "url",
                    "value": m.group(0).rstrip(".,);"),
                    "source": "processes.command_line",
                    "source_plugin": "windows.cmdline",
                    "extraction_method": "process_text",
                    "context": f"process cmdline PID {pid}",
                    "metadata": {},
                }
            )
        for m in _RE_IPV4.finditer(str(text)):
            collector.add(
                {
                    "process_id": process_id,
                    "pid": pid,
                    "artifact_type": "ipv4",
                    "value": m.group(0),
                    "source": "processes.command_line",
                    "source_plugin": "windows.cmdline",
                    "extraction_method": "process_text",
                    "context": f"process cmdline PID {pid}",
                    "metadata": {},
                }
            )
        for m in _RE_DOMAIN.finditer(str(text)):
            d = m.group(0)
            if d.lower() in {"microsoft.com", "windows.com", "www.microsoft.com"}:
                continue
            collector.add(
                {
                    "process_id": process_id,
                    "pid": pid,
                    "artifact_type": "dns",
                    "value": d,
                    "source": "processes.command_line",
                    "source_plugin": "windows.cmdline",
                    "extraction_method": "process_text",
                    "context": f"process cmdline PID {pid}",
                    "metadata": {},
                }
            )


def persist_network_artifacts(
    db: Database,
    *,
    evidence_id: str,
    items: list[dict[str, Any]],
    run_id: str,
    analysis_run_id: str | None,
    job_id: str | None,
    started_at: str,
    finished_at: str,
    status: str = "completed",
) -> dict[str, Any]:
    db.execute("DELETE FROM network_artifacts WHERE evidence_id = ?", (evidence_id,))
    if _table_exists(db, "network_artifact_runs"):
        db.execute("DELETE FROM network_artifact_runs WHERE evidence_id = ?", (evidence_id,))
    type_counts: dict[str, int] = {}
    sources: set[str] = set()
    db.execute(
        """
        INSERT INTO network_artifact_runs (
          id, evidence_id, analysis_run_id, job_id, status, artifact_count,
          type_counts_json, sources_json, observed_json, error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, 0, '{}', '[]', '{}', NULL, ?, ?)
        """,
        (run_id, evidence_id, analysis_run_id, job_id, status, started_at, finished_at),
    )
    for rec in items:
        aid = str(uuid4())
        atype = str(rec.get("artifact_type") or "network_string")
        type_counts[atype] = type_counts.get(atype, 0) + 1
        src = str(rec.get("source") or "unknown")
        sources.add(src)
        meta = rec.get("metadata") if isinstance(rec.get("metadata"), dict) else {}
        db.execute(
            """
            INSERT INTO network_artifacts (
              id, run_id, evidence_id, analysis_run_id, job_id, connection_id,
              process_id, pid, artifact_type, value, protocol, local_address,
              local_port, remote_address, remote_port, state, source,
              source_plugin, extraction_method, source_address, offset_hex,
              context, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                aid,
                run_id,
                evidence_id,
                analysis_run_id,
                job_id,
                rec.get("connection_id"),
                rec.get("process_id"),
                rec.get("pid"),
                atype,
                rec.get("value"),
                rec.get("protocol"),
                rec.get("local_address"),
                rec.get("local_port"),
                rec.get("remote_address"),
                rec.get("remote_port"),
                rec.get("state"),
                src,
                rec.get("source_plugin"),
                rec.get("extraction_method") or "unknown",
                rec.get("source_address"),
                rec.get("offset_hex"),
                rec.get("context"),
                json.dumps(meta),
                finished_at,
            ),
        )
        rec["id"] = aid

    db.execute(
        """
        UPDATE network_artifact_runs SET artifact_count=?, type_counts_json=?,
          sources_json=?, observed_json=?, finished_at=? WHERE id=?
        """,
        (
            len(items),
            json.dumps(type_counts),
            json.dumps(sorted(sources)),
            json.dumps({"artifact_count": len(items), "type_counts": type_counts}),
            finished_at,
            run_id,
        ),
    )
    _insert_iocs(db, evidence_id, items, finished_at)
    if _table_exists(db, "timeline_events"):
        db.execute(
            """
            DELETE FROM timeline_events
            WHERE evidence_id = ? AND IFNULL(source_table, '') = 'network_artifact_runs'
            """,
            (evidence_id,),
        )
        if items:
            db.execute(
                """
                INSERT INTO timeline_events (
                  id, evidence_id, event_time, time_precision, classification, event_kind,
                  summary, related_entity_type, related_entity_id, source_table, source_plugin,
                  provenance_json, created_at
                ) VALUES (?, ?, NULL, 'analysis_time', 'inferred', 'network_artifacts', ?, 'run', ?,
                  'network_artifact_runs', 'network_artifacts', ?, ?)
                """,
                (
                    str(uuid4()),
                    evidence_id,
                    f"Network artifact extraction stored {len(items)} artifact(s).",
                    run_id,
                    json.dumps(
                        {"run_id": run_id, "artifact_count": len(items), "type_counts": type_counts}
                    ),
                    finished_at,
                ),
            )
    return {
        "run_id": run_id,
        "artifact_count": len(items),
        "type_counts": type_counts,
        "sources": sorted(sources),
    }


def _insert_iocs(
    db: Database, evidence_id: str, items: list[dict[str, Any]], created_at: str
) -> None:
    if not _table_exists(db, "iocs"):
        return
    db.execute(
        "DELETE FROM iocs WHERE evidence_id = ? AND source = 'network_artifacts'",
        (evidence_id,),
    )
    seen: set[tuple[str, str, Any]] = set()
    n = 0
    ioc_types = {
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "url": "url",
        "http": "url",
        "dns": "domain",
        "mac": "mac",
    }
    for rec in items:
        mapped = ioc_types.get(str(rec.get("artifact_type")))
        if not mapped:
            continue
        value = str(rec.get("value") or "")
        key = (mapped, value.lower(), rec.get("pid"))
        if key in seen:
            continue
        seen.add(key)
        if n >= MAX_IOC_INSERT:
            break
        n += 1
        db.execute(
            """
            INSERT INTO iocs (
              id, evidence_id, process_id, pid, ioc_type, value, context, source, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'network_artifacts', ?)
            """,
            (
                str(uuid4()),
                evidence_id,
                rec.get("process_id"),
                rec.get("pid"),
                mapped,
                value,
                rec.get("context"),
                created_at,
            ),
        )


def extract_and_store(
    db: Database,
    evidence_id: str,
    *,
    analysis_run_id: str | None = None,
    job_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
    progress: ProgressFn | None = None,
) -> dict[str, Any]:
    if cancelled and cancelled():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
    if progress:
        progress("Extracting network artifacts", {"phase": "network_artifacts", "percent": 10})
    items = harvest_network_artifacts(db, evidence_id)
    if cancelled and cancelled():
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
    if progress:
        progress("Storing network artifacts", {"phase": "network_artifacts", "percent": 70})
    started = _utcnow()
    run_id = str(uuid4())
    finished = _utcnow()
    summary = persist_network_artifacts(
        db,
        evidence_id=evidence_id,
        items=items,
        run_id=run_id,
        analysis_run_id=analysis_run_id,
        job_id=job_id,
        started_at=started,
        finished_at=finished,
    )
    if progress:
        progress(
            "Network artifact extraction complete",
            {"phase": "network_artifacts", "percent": 100},
        )
    return {
        **summary,
        "evidence_id": evidence_id,
        "analysis_run_id": analysis_run_id,
        "status": "completed",
        "items": [_artifact_dto(r) for r in items],
        "total": len(items),
    }


def run_network_artifact_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: ProgressFn,
    *,
    paths: AppPaths | None = None,
) -> dict[str, Any]:
    _ = paths
    evidence_id = params.get("evidence_id")
    if not evidence_id:
        raise AppError(
            code="evidence_required",
            message="evidence_id is required for network artifact extraction.",
            entity="network_artifacts",
        )
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")

    job_id = params.get("job_id")
    analysis_run_id = str(uuid4())
    started = _utcnow()
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'network_artifact_extraction', 'running', ?, ?, ?, NULL, NULL, ?, ?)
        """,
        (
            analysis_run_id,
            evidence_id,
            started,
            SCHEMA_VERSION,
            "Network artifact extraction",
            job_id,
            json.dumps(
                [
                    {
                        "provider": "network_artifacts",
                        "target": "stored_analysis",
                        "reason": "Harvest recoverable network indicators from netscan, bulk_extractor, IOCs, and process text.",
                    }
                ]
            ),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (analysis_run_id, job_id))
    try:
        result = extract_and_store(
            db,
            evidence_id,
            analysis_run_id=analysis_run_id,
            job_id=job_id,
            cancelled=cancelled,
            progress=progress,
        )
        db.execute(
            "UPDATE analysis_runs SET status='completed', finished_at=? WHERE id=?",
            (_utcnow(), analysis_run_id),
        )
        return result
    except AppError as exc:
        status = "cancelled" if exc.code == "job_cancelled" else "failed"
        db.execute(
            """
            UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?
            """,
            (status, _utcnow(), json.dumps(exc.to_dict()), analysis_run_id),
        )
        raise


def list_network_artifacts(
    db: Database,
    evidence_id: str,
    *,
    artifact_type: str | None = None,
    pid: int | None = None,
    limit: int = 20000,
) -> dict[str, Any]:
    if not db.fetchone("SELECT id FROM evidence WHERE id = ?", (evidence_id,)):
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")
    if not _table_exists(db, "network_artifacts"):
        return {"evidence_id": evidence_id, "total": 0, "items": [], "type_counts": {}, "run": None}
    clauses = ["evidence_id = ?"]
    args: list[Any] = [evidence_id]
    if artifact_type:
        clauses.append("artifact_type = ?")
        args.append(artifact_type)
    if pid is not None:
        clauses.append("pid = ?")
        args.append(pid)
    where = " AND ".join(clauses)
    total_row = db.fetchone(
        f"SELECT COUNT(*) AS c FROM network_artifacts WHERE {where}", tuple(args)
    )
    rows = db.fetchall(
        f"""
        SELECT * FROM network_artifacts WHERE {where}
        ORDER BY artifact_type, value LIMIT ?
        """,
        tuple(args + [limit]),
    )
    type_rows = db.fetchall(
        """
        SELECT artifact_type, COUNT(*) AS c FROM network_artifacts
        WHERE evidence_id = ? GROUP BY artifact_type
        """,
        (evidence_id,),
    )
    run = db.fetchone(
        """
        SELECT * FROM network_artifact_runs WHERE evidence_id = ?
        ORDER BY started_at DESC LIMIT 1
        """,
        (evidence_id,),
    )
    names = _process_names(db, evidence_id)
    return {
        "evidence_id": evidence_id,
        "total": int((total_row or {}).get("c") or 0),
        "items": [_artifact_dto(r, names) for r in rows],
        "type_counts": {str(r["artifact_type"]): int(r["c"]) for r in type_rows},
        "run": _run_dto(run) if run else None,
    }


def list_network_artifact_runs(db: Database, evidence_id: str) -> dict[str, Any]:
    if not _table_exists(db, "network_artifact_runs"):
        return {"evidence_id": evidence_id, "items": []}
    rows = db.fetchall(
        """
        SELECT * FROM network_artifact_runs WHERE evidence_id = ?
        ORDER BY started_at DESC LIMIT 20
        """,
        (evidence_id,),
    )
    return {"evidence_id": evidence_id, "items": [_run_dto(r) for r in rows]}


def _process_names(db: Database, evidence_id: str) -> dict[int, str]:
    names: dict[int, str] = {}
    if not _table_exists(db, "processes"):
        return names
    for row in db.fetchall(
        "SELECT pid, name FROM processes WHERE evidence_id = ? AND name IS NOT NULL",
        (evidence_id,),
    ):
        names[int(row["pid"])] = str(row["name"])
    return names


def _artifact_dto(row: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
    meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else _json_load(row.get("metadata_json"), {})
    pid = row.get("pid")
    process_name = None
    if names is not None and pid is not None:
        try:
            process_name = names.get(int(pid))
        except (TypeError, ValueError):
            process_name = None
    return {
        "id": row.get("id"),
        "run_id": row.get("run_id"),
        "evidence_id": row.get("evidence_id"),
        "analysis_run_id": row.get("analysis_run_id"),
        "connection_id": row.get("connection_id"),
        "process_id": row.get("process_id"),
        "pid": pid,
        "process_name": process_name,
        "artifact_type": row.get("artifact_type"),
        "value": row.get("value"),
        "protocol": row.get("protocol"),
        "local_address": row.get("local_address"),
        "local_port": row.get("local_port"),
        "remote_address": row.get("remote_address"),
        "remote_port": row.get("remote_port"),
        "state": row.get("state"),
        "source": row.get("source"),
        "source_plugin": row.get("source_plugin"),
        "extraction_method": row.get("extraction_method"),
        "source_address": row.get("source_address"),
        "offset_hex": row.get("offset_hex"),
        "context": row.get("context"),
        "metadata": meta,
        "created_at": row.get("created_at"),
    }


def _run_dto(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    return {
        "id": row.get("id"),
        "evidence_id": row.get("evidence_id"),
        "analysis_run_id": row.get("analysis_run_id"),
        "job_id": row.get("job_id"),
        "status": row.get("status"),
        "artifact_count": row.get("artifact_count") or 0,
        "type_counts": _json_load(row.get("type_counts_json"), {}),
        "sources": _json_load(row.get("sources_json"), []),
        "observed": _json_load(row.get("observed_json"), {}),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
    }
