"""PCAP reconstruction from packet records recovered in a memory image.

Writes classic .pcap files under the analysis directory. Never modifies evidence.
Does not fabricate packet bytes or capture timestamps.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from memscope_engine.analysis.pcap_carve import (
    CarvedPacket,
    carve_image,
    filter_packets_for_flow,
    flow_key,
    overall_status,
    read_pcap,
    write_flow_pcap,
    write_pcap_pair,
)
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.providers.process_run import assert_evidence_unchanged, evidence_fingerprint
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION

log = logging.getLogger("memscope.analysis")

ProgressFn = Callable[..., None]

# External PCAP import: read-only merge of a user-supplied capture (e.g. a
# packets.pcap produced by a manual bulk_extractor run). The file is never
# written to, executed, or copied over evidence.
MAX_IMPORT_PCAP_BYTES = 512 * 1024 * 1024
_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

LIMITATIONS = [
    "A memory image is not a packet capture. Recovered records are packet-shaped bytes found in RAM, not a complete conversation.",
    "Capture timestamps are not present on carved packets; PCAP timestamps are unset (0).",
    "Missing bytes are never invented. Truncated records are stored with the recovered length only.",
    "Ethernet and raw IP records are written as separate PCAPs so a synthetic Layer-2 header is never prepended.",
    "Connection metadata from Network Connections is not a PCAP. Metadata-only flows have no packet file.",
]


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


def _normalize_proto(value: str | None) -> str:
    raw = (value or "").strip().lower()
    if raw.startswith("tcp"):
        return "tcp"
    if raw.startswith("udp"):
        return "udp"
    return raw


def _ui_state(status: str, packet_count: int) -> str:
    if status == "running":
        return "reconstructing"
    if status == "queued":
        return "queued"
    if status == "cancelled":
        return "cancelled"
    if status == "failed":
        return "failed"
    if status == "unavailable" or packet_count <= 0:
        return "unavailable"
    if status == "partially_reconstructed":
        return "partially_reconstructed"
    if status == "packets_recovered":
        return "packets_recovered"
    return status


def _display_status(status: str) -> str:
    return {
        "packets_recovered": "Packets recovered",
        "partially_reconstructed": "Partially reconstructed",
        "metadata_only": "Metadata only",
        "unavailable": "No reconstructable traffic",
        "failed": "Failed",
        "cancelled": "Cancelled",
        "reconstructing": "Reconstructing…",
        "queued": "Queued",
        "running": "Reconstructing…",
    }.get(status, status.replace("_", " "))


def _flow_status(packet_count: int, truncated_count: int, has_connection: bool) -> str:
    if packet_count <= 0:
        return "metadata_only" if has_connection else "unavailable"
    if truncated_count > 0:
        return "partially_reconstructed"
    return "packets_recovered"


def _existing_bulk_extractor_pcaps(db: Database, evidence_id: str) -> list[Path]:
    if not _table_exists(db, "bulk_extractor_outputs"):
        return []
    rows = db.fetchall(
        """
        SELECT o.relative_path, s.output_dir
        FROM bulk_extractor_outputs o
        JOIN bulk_extractor_scans s ON s.id = o.scan_id
        WHERE o.evidence_id = ? AND s.status = 'completed'
        """,
        (evidence_id,),
    )
    found: list[Path] = []
    for row in rows:
        rel = str(row.get("relative_path") or "")
        lower = rel.lower()
        if not (lower.endswith(".pcap") or lower.endswith(".pcapng")):
            continue
        root = Path(str(row.get("output_dir") or ""))
        candidate = (root / rel) if root else Path(rel)
        if candidate.is_file():
            found.append(candidate)
    return found


def validate_import_pcap(raw_path: str, *, evidence_path: Path) -> Path:
    """Validate a user-supplied external PCAP for read-only merge.

    Accepts classic pcap (little- or big-endian) only; pcapng is rejected with
    a conversion hint. The file is never modified, executed, or copied.
    """
    candidate = Path(raw_path.strip()).expanduser()
    if not candidate.is_file():
        raise AppError(
            code="pcap_import_missing",
            message="The external PCAP file was not found.",
            details=str(candidate),
            entity="pcap",
        )
    resolved = candidate.resolve()
    try:
        same_as_evidence = resolved == evidence_path.resolve()
    except OSError:
        same_as_evidence = False
    if same_as_evidence:
        raise AppError(
            code="pcap_import_denied",
            message="The memory image itself cannot be imported as a PCAP.",
            details=str(resolved),
            entity="pcap",
        )
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise AppError(
            code="pcap_import_missing",
            message="The external PCAP file could not be read.",
            details=str(exc),
            entity="pcap",
        ) from exc
    if size > MAX_IMPORT_PCAP_BYTES:
        raise AppError(
            code="pcap_import_too_large",
            message="The external PCAP is too large to import.",
            details=f"{size} bytes (limit {MAX_IMPORT_PCAP_BYTES})",
            suggestion="Split the capture or import a smaller packets.pcap.",
            entity="pcap",
        )
    try:
        with resolved.open("rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        raise AppError(
            code="pcap_import_missing",
            message="The external PCAP file could not be opened.",
            details=str(exc),
            entity="pcap",
        ) from exc
    if magic == _PCAPNG_MAGIC:
        raise AppError(
            code="pcap_import_unsupported",
            message="pcapng files are not supported for import.",
            details=str(resolved),
            suggestion="Convert it to classic pcap (e.g. with Wireshark or editcap) and import again.",
            entity="pcap",
        )
    if magic not in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE):
        raise AppError(
            code="pcap_import_invalid",
            message="The selected file is not a classic pcap capture.",
            details=str(resolved),
            suggestion="Choose a .pcap file such as the packets.pcap written by bulk_extractor.",
            entity="pcap",
        )
    return resolved


def reconstruct_packets(
    image: Path,
    *,
    cancelled: Callable[[], bool] | None = None,
    progress: ProgressFn | None = None,
    extra_pcaps: list[tuple[Path, str]] | None = None,
) -> dict[str, Any]:
    def _prog(frac: float, message: str | None = None) -> None:
        if not progress:
            return
        pct = max(1, min(89, int(frac * 80) + 5))
        progress(message or "Reconstructing packet records", {"phase": "pcap", "percent": pct})

    carved = carve_image(image, cancelled=cancelled, progress=_prog)
    if carved.cancelled:
        raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
    packets: list[CarvedPacket] = list(carved.packets)
    imported = 0
    for extra, source in extra_pcaps or []:
        if cancelled and cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        try:
            imported_pkts = read_pcap(extra, source=f"{source}:{extra.name}")
        except OSError:
            continue
        seen = {(p.offset, p.incl_len, p.src_ip, p.dst_ip, p.src_port, p.dst_port) for p in packets}
        for pkt in imported_pkts:
            key = (pkt.offset, pkt.incl_len, pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
            if key in seen:
                continue
            packets.append(pkt)
            seen.add(key)
            imported += 1
    packets.sort(key=lambda p: p.offset)
    status = overall_status(packets)
    return {
        "packets": packets,
        "status": status,
        "bytes_scanned": carved.bytes_scanned,
        "image_size": carved.image_size,
        "skipped_invalid": carved.skipped_invalid,
        "imported_pcap_packets": imported,
        "truncated_count": sum(1 for p in packets if p.truncated),
        "ethernet_count": sum(1 for p in packets if p.linktype == 1),
        "raw_ip_count": sum(1 for p in packets if p.linktype == 101),
    }


def run_pcap_reconstruction_job(
    db: Database,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: ProgressFn,
    *,
    paths: AppPaths,
) -> dict[str, Any]:
    evidence_id = params.get("evidence_id")
    if not evidence_id:
        raise AppError(
            code="evidence_required",
            message="evidence_id is required for PCAP reconstruction.",
            entity="pcap",
        )
    evidence = db.fetchone("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if not evidence:
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")
    image = Path(evidence["path"])
    if not image.is_file():
        raise AppError(
            code="evidence_not_found",
            message="Memory image file was not found.",
            details=str(image),
            entity="evidence",
        )

    import_pcap: Path | None = None
    raw_import = params.get("import_pcap_path")
    if isinstance(raw_import, str) and raw_import.strip():
        import_pcap = validate_import_pcap(raw_import, evidence_path=image)

    job_id = params.get("job_id")
    analysis_run_id = str(uuid4())
    recon_id = str(uuid4())
    started = _utcnow()
    out_dir = paths.analysis / "pcap" / recon_id
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        out_resolved = out_dir.resolve()
        analysis_root = paths.analysis.resolve()
        out_resolved.relative_to(analysis_root)
    except ValueError as exc:
        raise AppError(
            code="pcap_output_denied",
            message="PCAP output must stay under the analysis directory.",
            details=str(out_dir),
            entity="pcap",
        ) from exc

    evidence_resolved = image.resolve()
    if evidence_resolved == out_resolved or str(evidence_resolved) in str(out_resolved):
        raise AppError(
            code="pcap_output_denied",
            message="Refusing to write PCAP next to the original evidence file.",
            entity="pcap",
        )

    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, notes,
          process_id, pid, job_id, strategy_json
        ) VALUES (?, ?, 'pcap_reconstruction', 'running', ?, ?, ?, NULL, NULL, ?, ?)
        """,
        (
            analysis_run_id,
            evidence_id,
            started,
            SCHEMA_VERSION,
            "PCAP reconstruction from recovered packet records",
            job_id,
            json.dumps(
                [
                    {
                        "provider": "pcap_reconstruction",
                        "target": "memory_image",
                        "reason": "Carve structurally valid Ethernet/IP records from the imported dump.",
                    },
                    *(
                        [
                            {
                                "provider": "pcap_import",
                                "target": str(import_pcap),
                                "reason": "User-supplied external PCAP merged into the reconstruction (read-only).",
                            }
                        ]
                        if import_pcap
                        else []
                    ),
                ]
            ),
        ),
    )
    if job_id:
        db.execute("UPDATE jobs SET analysis_run_id = ? WHERE id = ?", (analysis_run_id, job_id))

    db.execute(
        """
        INSERT INTO pcap_reconstructions (
          id, evidence_id, analysis_run_id, job_id, status, ui_state,
          reconstruction_status, packet_count, truncated_count, ethernet_count,
          raw_ip_count, flow_count, output_path, output_dir, files_json,
          limitations_json, observed_json, error_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, 'running', 'reconstructing', 'unavailable',
          0, 0, 0, 0, 0, NULL, ?, '[]', ?, '{}', NULL, ?, NULL)
        """,
        (recon_id, evidence_id, analysis_run_id, job_id, str(out_dir), json.dumps(LIMITATIONS), started),
    )

    before = evidence_fingerprint(image)
    try:
        if cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        progress("Reconstructing packet records from the memory image", {"phase": "pcap", "percent": 2})
        extras: list[tuple[Path, str]] = [
            (p, "bulk_extractor") for p in _existing_bulk_extractor_pcaps(db, evidence_id)
        ]
        if import_pcap:
            extras.append((import_pcap, "external_import"))
        result = reconstruct_packets(
            image, cancelled=cancelled, progress=progress, extra_pcaps=extras
        )
        assert_evidence_unchanged(image, before, entity="pcap")
        packets: list[CarvedPacket] = result["packets"]
        written = write_pcap_pair(out_dir, packets) if packets else {"files": [], "primary_path": None}
        if cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")
        progress("Correlating recovered packets with network connections", {"phase": "pcap", "percent": 92})
        flows = _persist_flows(
            db,
            evidence_id=evidence_id,
            recon_id=recon_id,
            packets=packets,
            out_dir=out_dir,
        )
        status = result["status"] if packets else "unavailable"
        finished = _utcnow()
        observed = {
            "bytes_scanned": result.get("bytes_scanned"),
            "image_size": result.get("image_size"),
            "skipped_invalid": result.get("skipped_invalid"),
            "imported_pcap_packets": result.get("imported_pcap_packets"),
            "imported_pcap_path": str(import_pcap) if import_pcap else None,
            "timestamps": "unset",
            "limitations": LIMITATIONS,
        }
        db.execute(
            """
            UPDATE pcap_reconstructions SET
              status='completed', ui_state=?, reconstruction_status=?,
              packet_count=?, truncated_count=?, ethernet_count=?, raw_ip_count=?,
              flow_count=?, output_path=?, files_json=?, observed_json=?, finished_at=?
            WHERE id=?
            """,
            (
                _ui_state(status, len(packets)),
                status,
                len(packets),
                result.get("truncated_count") or 0,
                result.get("ethernet_count") or 0,
                result.get("raw_ip_count") or 0,
                len(flows),
                written.get("primary_path"),
                json.dumps(written.get("files") or []),
                json.dumps(observed),
                finished,
                recon_id,
            ),
        )
        db.execute(
            "UPDATE analysis_runs SET status='completed', finished_at=? WHERE id=?",
            (finished, analysis_run_id),
        )
        if _table_exists(db, "timeline_events"):
            db.execute(
                """
                DELETE FROM timeline_events
                WHERE evidence_id = ? AND IFNULL(source_table, '') = 'pcap_reconstructions'
                """,
                (evidence_id,),
            )
            if packets:
                db.execute(
                    """
                    INSERT INTO timeline_events (
                      id, evidence_id, event_time, time_precision, classification, event_kind,
                      summary, related_entity_type, related_entity_id, source_table, source_plugin,
                      provenance_json, created_at
                    ) VALUES (?, ?, NULL, 'analysis_time', 'inferred', 'pcap_reconstruction', ?, 'run', ?,
                      'pcap_reconstructions', 'pcap_reconstruction', ?, ?)
                    """,
                    (
                        str(uuid4()),
                        evidence_id,
                        f"PCAP reconstruction {status}: {len(packets)} packet record(s).",
                        recon_id,
                        json.dumps(
                            {
                                "reconstruction_id": recon_id,
                                "reconstruction_status": status,
                                "packet_count": len(packets),
                                "output_path": written.get("primary_path"),
                                "pcap_embedded": False,
                            }
                        ),
                        finished,
                    ),
                )
        after = evidence_fingerprint(image)
        if after != before:
            raise AppError(
                code="pcap_evidence_mutated",
                message="The memory image changed during PCAP reconstruction.",
                entity="pcap",
            )
        progress("PCAP reconstruction complete", {"phase": "pcap", "percent": 100})
        return get_pcap_reconstruction(db, recon_id)
    except AppError as exc:
        status = "cancelled" if exc.code == "job_cancelled" else "failed"
        db.execute(
            """
            UPDATE pcap_reconstructions SET status=?, ui_state=?, reconstruction_status=?,
              error_json=?, finished_at=? WHERE id=?
            """,
            (status, status, status, json.dumps(exc.to_dict()), _utcnow(), recon_id),
        )
        db.execute(
            "UPDATE analysis_runs SET status=?, finished_at=?, error_json=? WHERE id=?",
            (status, _utcnow(), json.dumps(exc.to_dict()), analysis_run_id),
        )
        raise
    except Exception:
        after = evidence_fingerprint(image)
        if after["size_bytes"] != before["size_bytes"] or after["mtime_ns"] != before["mtime_ns"]:
            log.error("evidence mutated during pcap reconstruction", extra={"channel": "analysis"})
        raise


def _persist_flows(
    db: Database,
    *,
    evidence_id: str,
    recon_id: str,
    packets: list[CarvedPacket],
    out_dir: Path,
) -> list[dict[str, Any]]:
    now = _utcnow()
    by_key: dict[tuple[Any, ...], list[CarvedPacket]] = {}
    for pkt in packets:
        tup = pkt.five_tuple()
        if not tup:
            continue
        key = flow_key(*tup)
        by_key.setdefault(key, []).append(pkt)

    connections = []
    if _table_exists(db, "network_connections"):
        connections = db.fetchall(
            "SELECT * FROM network_connections WHERE evidence_id = ?",
            (evidence_id,),
        )

    used_keys: set[tuple[Any, ...]] = set()
    flows: list[dict[str, Any]] = []
    flow_files = 0
    for conn in connections:
        proto = _normalize_proto(conn.get("protocol"))
        if proto not in ("tcp", "udp"):
            status = "metadata_only"
            matched: list[CarvedPacket] = []
            key = None
        elif conn.get("local_address") and conn.get("remote_address") and conn.get("local_port") is not None and conn.get("remote_port") is not None:
            key = flow_key(
                str(conn["local_address"]),
                int(conn["local_port"]),
                str(conn["remote_address"]),
                int(conn["remote_port"]),
                proto,
            )
            matched = by_key.get(key, [])
            used_keys.add(key)
            status = _flow_status(len(matched), sum(1 for p in matched if p.truncated), True)
        else:
            key = None
            matched = []
            status = "metadata_only"
        flow_path = None
        if matched and flow_files < 100:
            flow_files += 1
            dest = out_dir / f"flow-{conn['id'][:8]}.pcap"
            write_flow_pcap(dest, matched)
            flow_path = str(dest)
        rec = {
            "id": str(uuid4()),
            "reconstruction_id": recon_id,
            "evidence_id": evidence_id,
            "connection_id": conn.get("id"),
            "process_id": conn.get("process_id"),
            "pid": conn.get("pid"),
            "protocol": conn.get("protocol"),
            "local_address": conn.get("local_address"),
            "local_port": conn.get("local_port"),
            "remote_address": conn.get("remote_address"),
            "remote_port": conn.get("remote_port"),
            "status": status,
            "packet_count": len(matched),
            "truncated_count": sum(1 for p in matched if p.truncated),
            "notes": _flow_notes(status, len(matched)),
            "flow_pcap_path": flow_path,
            "created_at": now,
        }
        _insert_flow(db, rec)
        flows.append(rec)

    for key, matched in by_key.items():
        if key in used_keys:
            continue
        proto, ends = key[0], key[1]
        rec = {
            "id": str(uuid4()),
            "reconstruction_id": recon_id,
            "evidence_id": evidence_id,
            "connection_id": None,
            "process_id": None,
            "pid": None,
            "protocol": proto,
            "local_address": ends[0],
            "local_port": ends[1],
            "remote_address": ends[2],
            "remote_port": ends[3],
            "status": _flow_status(len(matched), sum(1 for p in matched if p.truncated), False),
            "packet_count": len(matched),
            "truncated_count": sum(1 for p in matched if p.truncated),
            "notes": _flow_notes("packets_recovered", len(matched)),
            "flow_pcap_path": None,
            "created_at": now,
        }
        _insert_flow(db, rec)
        flows.append(rec)
    return flows


def _flow_notes(status: str, packet_count: int) -> str:
    if status == "metadata_only":
        return "Socket/connection metadata only. No packet records were recovered for this flow."
    if status == "unavailable":
        return "No reconstructable packet records."
    if status == "partially_reconstructed":
        return (
            f"{packet_count} packet record(s) recovered; at least one is truncated in the memory image."
        )
    return (
        f"{packet_count} structurally complete packet record(s) recovered. "
        "This is not a guarantee that the original conversation is complete."
    )


def _insert_flow(db: Database, rec: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO pcap_flow_results (
          id, reconstruction_id, evidence_id, connection_id, process_id, pid,
          protocol, local_address, local_port, remote_address, remote_port,
          status, packet_count, truncated_count, notes, flow_pcap_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rec["id"],
            rec["reconstruction_id"],
            rec["evidence_id"],
            rec.get("connection_id"),
            rec.get("process_id"),
            rec.get("pid"),
            rec.get("protocol"),
            rec.get("local_address"),
            rec.get("local_port"),
            rec.get("remote_address"),
            rec.get("remote_port"),
            rec["status"],
            rec["packet_count"],
            rec["truncated_count"],
            rec.get("notes"),
            rec.get("flow_pcap_path"),
            rec["created_at"],
        ),
    )


def get_pcap_reconstruction(db: Database, reconstruction_id: str) -> dict[str, Any]:
    row = db.fetchone("SELECT * FROM pcap_reconstructions WHERE id = ?", (reconstruction_id,))
    if not row:
        raise AppError(
            code="pcap_reconstruction_missing",
            message="PCAP reconstruction not found.",
            entity="pcap",
        )
    flows = db.fetchall(
        "SELECT * FROM pcap_flow_results WHERE reconstruction_id = ? ORDER BY pid, protocol",
        (reconstruction_id,),
    )
    return {
        "reconstruction": _recon_dto(row),
        "flows": [_flow_dto(f) for f in flows],
    }


def list_pcap_reconstructions(db: Database, evidence_id: str) -> dict[str, Any]:
    if not db.fetchone("SELECT id FROM evidence WHERE id = ?", (evidence_id,)):
        raise AppError(code="evidence_missing", message="Evidence not found.", entity="evidence")
    if not _table_exists(db, "pcap_reconstructions"):
        return {"evidence_id": evidence_id, "items": [], "latest": None}
    rows = db.fetchall(
        """
        SELECT * FROM pcap_reconstructions WHERE evidence_id = ?
        ORDER BY started_at DESC LIMIT 20
        """,
        (evidence_id,),
    )
    items = []
    for row in rows:
        flows = db.fetchall(
            "SELECT * FROM pcap_flow_results WHERE reconstruction_id = ? ORDER BY pid, protocol",
            (row["id"],),
        )
        items.append({"reconstruction": _recon_dto(row), "flows": [_flow_dto(f) for f in flows]})
    return {
        "evidence_id": evidence_id,
        "items": items,
        "latest": items[0] if items else None,
    }


def export_flow_pcap(db: Database, *, reconstruction_id: str, flow_id: str, paths: AppPaths) -> dict[str, Any]:
    flow = db.fetchone(
        "SELECT * FROM pcap_flow_results WHERE id = ? AND reconstruction_id = ?",
        (flow_id, reconstruction_id),
    )
    if not flow:
        raise AppError(code="pcap_flow_missing", message="PCAP flow result not found.", entity="pcap")
    if int(flow.get("packet_count") or 0) <= 0:
        raise AppError(
            code="pcap_flow_metadata_only",
            message="This flow has connection metadata only; no packet records were recovered.",
            entity="pcap",
        )
    existing = flow.get("flow_pcap_path")
    if existing and Path(str(existing)).is_file():
        return {"path": existing, "flow": _flow_dto(flow)}
    recon = db.fetchone("SELECT * FROM pcap_reconstructions WHERE id = ?", (reconstruction_id,))
    if not recon:
        raise AppError(code="pcap_reconstruction_missing", message="PCAP reconstruction not found.", entity="pcap")
    primary = recon.get("output_path")
    if not primary or not Path(str(primary)).is_file():
        raise AppError(
            code="pcap_output_missing",
            message="Reconstructed PCAP file is not available.",
            entity="pcap",
        )
    from memscope_engine.analysis.pcap_carve import read_pcap as _read

    packets = _read(Path(str(primary)), source="reconstructed")
    files = _json_load(recon.get("files_json"), [])
    for rec in files:
        path = rec.get("path")
        if path and path != primary and Path(str(path)).is_file():
            packets.extend(_read(Path(str(path)), source="reconstructed"))
    if flow.get("local_address") is None or flow.get("remote_address") is None:
        raise AppError(code="pcap_flow_incomplete", message="Flow is missing addressing.", entity="pcap")
    key = flow_key(
        str(flow["local_address"]),
        int(flow["local_port"] or 0),
        str(flow["remote_address"]),
        int(flow["remote_port"] or 0),
        _normalize_proto(flow.get("protocol")) or "tcp",
    )
    matched = filter_packets_for_flow(packets, key)
    if not matched:
        raise AppError(
            code="pcap_flow_no_packets",
            message="No packet records in the reconstructed PCAP match this flow.",
            entity="pcap",
        )
    out_dir = Path(str(recon.get("output_dir") or (paths.analysis / "pcap" / reconstruction_id)))
    dest = out_dir / f"flow-{flow_id[:8]}.pcap"
    write_flow_pcap(dest, matched)
    db.execute(
        "UPDATE pcap_flow_results SET flow_pcap_path = ? WHERE id = ?",
        (str(dest), flow_id),
    )
    flow["flow_pcap_path"] = str(dest)
    return {"path": str(dest), "flow": _flow_dto(flow)}


def _recon_dto(row: dict[str, Any]) -> dict[str, Any]:
    status = row.get("reconstruction_status") or row.get("status")
    err = None
    if row.get("error_json"):
        try:
            err = json.loads(row["error_json"])
        except json.JSONDecodeError:
            err = {"message": row["error_json"]}
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "analysis_run_id": row.get("analysis_run_id"),
        "job_id": row.get("job_id"),
        "status": row["status"],
        "ui_state": row.get("ui_state"),
        "reconstruction_status": status,
        "display_status": _display_status(str(status or "")),
        "packet_count": row.get("packet_count") or 0,
        "truncated_count": row.get("truncated_count") or 0,
        "ethernet_count": row.get("ethernet_count") or 0,
        "raw_ip_count": row.get("raw_ip_count") or 0,
        "flow_count": row.get("flow_count") or 0,
        "output_path": row.get("output_path"),
        "output_dir": row.get("output_dir"),
        "files": _json_load(row.get("files_json"), []),
        "limitations": _json_load(row.get("limitations_json"), LIMITATIONS),
        "observed": _json_load(row.get("observed_json"), {}),
        "error": err,
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "pcap_embedded": False,
    }


def _flow_dto(row: dict[str, Any]) -> dict[str, Any]:
    status = row.get("status")
    return {
        "id": row["id"],
        "reconstruction_id": row.get("reconstruction_id"),
        "evidence_id": row.get("evidence_id"),
        "connection_id": row.get("connection_id"),
        "process_id": row.get("process_id"),
        "pid": row.get("pid"),
        "protocol": row.get("protocol"),
        "local_address": row.get("local_address"),
        "local_port": row.get("local_port"),
        "remote_address": row.get("remote_address"),
        "remote_port": row.get("remote_port"),
        "status": status,
        "display_status": _display_status(str(status or "")),
        "packet_count": row.get("packet_count") or 0,
        "truncated_count": row.get("truncated_count") or 0,
        "notes": row.get("notes"),
        "flow_pcap_path": row.get("flow_pcap_path"),
        "exportable": bool(row.get("flow_pcap_path") or (row.get("packet_count") or 0) > 0),
        "created_at": row.get("created_at"),
    }
