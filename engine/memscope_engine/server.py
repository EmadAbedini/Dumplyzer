"""NDJSON JSON-RPC 2.0 server over stdio."""

from __future__ import annotations

import json
import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable

from memscope_engine.analysis import (
    bulk_extractor_workflows,
    capa_workflows,
    floss_workflows,
    memory_artifacts,
    network_artifacts,
    pcap_reconstruction,
    pe_extraction_workflows,
    plugin_explorer,
    process_analysis,
    profiles,
    search_iocs,
    workflows,
    yara_workflows,
)
from memscope_engine.errors import AppError, rpc_error_payload
from memscope_engine.export import workflows as export_workflows
from memscope_engine.jobs.manager import JobManager
from memscope_engine.logging_setup import get_logger, setup_logging
from memscope_engine.paths import AppPaths
from memscope_engine.providers.yara_provider import detect_yara
from memscope_engine.session_temp import cleanup_session_temp
from memscope_engine.storage import Database
from memscope_engine.version import APP_VERSION

log = get_logger("app")

_STATE: dict[str, Any] = {
    "paths": None,
    "db": None,
    "jobs": None,
}


def _runtime_info() -> dict[str, Any]:
    return {
        "app_version": APP_VERSION,
        "engine_version": APP_VERSION,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "packaged": os.environ.get("MEMSCOPE_PACKAGED") == "1",
    }


def _vol_init() -> dict[str, Any]:
    import volatility3
    from volatility3.framework import automagic, constants, contexts, plugins

    try:
        vol_ver = version("volatility3")
    except PackageNotFoundError:
        vol_ver = getattr(constants, "PACKAGE_VERSION", "unknown")

    _ = contexts.Context
    _ = automagic
    _ = plugins

    return {
        "ok": True,
        **_runtime_info(),
        "volatility3_version": vol_ver,
        "volatility3_path": getattr(volatility3, "__file__", None),
        "framework_package_version": getattr(constants, "PACKAGE_VERSION", None),
    }


def handle_capabilities_status(_params: dict[str, Any]) -> dict[str, Any]:
    """One-shot health payload for About / Settings. Avoids six serial RPCs."""
    paths = _paths()
    db = _db()
    return {
        "volatility": _vol_init(),
        "pe_extraction": pe_extraction_workflows.pe_extraction_status(paths, db),
        "bulk_extractor": bulk_extractor_workflows.bulk_extractor_status(paths, db),
        "capa": capa_workflows.capa_status(paths, db),
        "floss": floss_workflows.floss_status(paths, db),
        "yara": yara_workflows.yara_status(paths, db),
    }


def _db() -> Database:
    db = _STATE.get("db")
    if db is None:
        raise AppError(
            code="engine_not_initialized",
            message="Analysis engine is not initialized.",
            suggestion="Call app.init before other methods.",
        )
    return db


def _paths() -> AppPaths:
    paths = _STATE.get("paths")
    if paths is None:
        raise AppError(
            code="engine_not_initialized",
            message="Analysis engine is not initialized.",
            suggestion="Call app.init before other methods.",
        )
    return paths


def _jobs() -> JobManager:
    jobs = _STATE.get("jobs")
    if jobs is None:
        raise AppError(
            code="engine_not_initialized",
            message="Job manager is not initialized.",
            suggestion="Call app.init before other methods.",
        )
    return jobs


def _resolve_init_root(params: dict[str, Any]) -> Path | str | None:
    """Honor DUMPLYZER_DATA_DIR / MEMSCOPE_DATA_DIR from the desktop shell."""
    env = os.environ.get("DUMPLYZER_DATA_DIR") or os.environ.get("MEMSCOPE_DATA_DIR")
    requested = params.get("data_dir")
    if env and str(env).strip():
        env_path = Path(str(env)).expanduser().resolve()
        if requested:
            try:
                req_path = Path(str(requested)).expanduser().resolve()
            except (OSError, TypeError, ValueError):
                req_path = None
            if req_path is not None and req_path != env_path:
                log.warning(
                    "ignored client data_dir override",
                    extra={"channel": "app"},
                )
        return env_path
    if requested:
        return Path(str(requested))
    return None


def handle_app_init(params: dict[str, Any]) -> dict[str, Any]:
    data_dir = _resolve_init_root(params)
    paths = AppPaths(data_dir).ensure() if data_dir else AppPaths().ensure()
    setup_logging(paths.logs)
    if _STATE.get("db") is not None:
        try:
            _STATE["db"].close()
        except Exception:  # noqa: BLE001
            pass
    db = Database(paths.db_path)
    cleanup_session_temp(paths)
    jobs = JobManager(db)
    jobs.register("evidence_import", workflows.run_evidence_import_job)
    jobs.register("basic_triage", process_analysis.run_basic_triage_job)
    jobs.register("process_recommended", process_analysis.run_process_recommended_job)
    jobs.register("analysis_profile", profiles.run_analysis_profile_job)
    jobs.register("vad_scan", memory_artifacts.run_vad_scan_job)

    def _vad_extract(db_, params, cancelled, progress):
        return memory_artifacts.run_vad_extract_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _yara_scan(db_, params, cancelled, progress):
        return yara_workflows.run_yara_artifact_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _yara_memory(db_, params, cancelled, progress):
        return yara_workflows.run_yara_memory_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _yara_extracted(db_, params, cancelled, progress):
        return yara_workflows.run_yara_extracted_files_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _pe_extract(db_, params, cancelled, progress):
        return pe_extraction_workflows.run_pe_extraction_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _capa_scan(db_, params, cancelled, progress):
        return capa_workflows.run_capa_artifact_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _floss_scan(db_, params, cancelled, progress):
        return floss_workflows.run_floss_artifact_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _bulk_extractor(db_, params, cancelled, progress):
        return bulk_extractor_workflows.run_bulk_extractor_scan_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _network_artifacts(db_, params, cancelled, progress):
        return network_artifacts.run_network_artifact_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _pcap_recon(db_, params, cancelled, progress):
        return pcap_reconstruction.run_pcap_reconstruction_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _plugin_advanced(db_, params, cancelled, progress):
        return plugin_explorer.run_advanced_plugin_job(
            db_, params, cancelled, progress, paths=paths
        )

    def _export_report(db_, params, cancelled, progress):
        return export_workflows.run_export_job(
            db_, params, cancelled, progress, paths=paths
        )

    jobs.register("vad_extract", _vad_extract)
    jobs.register("yara_artifact_scan", _yara_scan)
    jobs.register("yara_memory_scan", _yara_memory)
    jobs.register("yara_extracted_scan", _yara_extracted)
    jobs.register("pe_extraction", _pe_extract)
    jobs.register("capa_artifact", _capa_scan)
    jobs.register("floss_artifact", _floss_scan)
    jobs.register("bulk_extractor_scan", _bulk_extractor)
    jobs.register("network_artifact_extraction", _network_artifacts)
    jobs.register("pcap_reconstruction", _pcap_recon)
    jobs.register("plugin_advanced", _plugin_advanced)
    jobs.register("export_report", _export_report)
    jobs.start()
    _STATE["paths"] = paths
    _STATE["db"] = db
    _STATE["jobs"] = jobs
    log.info("engine initialized", extra={"channel": "app"})
    # Do not probe Volatility/CAPA/FLOSS/YARA rules/bulk_extractor here.
    # Those checks are expensive (imports, subprocess --version, rule compile)
    # and would block every subsequent RPC, including the UI's per-capability
    # background status calls. Honest availability stays on:
    # volatility.init, pe_extraction.status, capa.status, floss.status,
    # yara.status, bulk_extractor.status.
    return {
        "ok": True,
        "paths": paths.as_dict(),
        "schema_version": db.schema_version(),
        "app_version": APP_VERSION,
        "runtime": _runtime_info(),
        "volatility": {"ok": True, **_runtime_info()},
        "yara": detect_yara(),
        "pe_extraction": {"provider": "pe_extraction"},
        "capa": {"provider": "capa"},
        "floss": {"provider": "floss"},
        "bulk_extractor": {"provider": "bulk_extractor"},
        "plugins": {
            "model_version": 1,
        },
    }


def handle_health(_params: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "service": "memscope_engine",
        "version": APP_VERSION,
        "initialized": _STATE.get("db") is not None,
        "runtime": _runtime_info(),
    }


def handle_app_shutdown(_params: dict[str, Any]) -> dict[str, Any]:
    paths = _STATE.get("paths")
    result = {"ok": True, "cleaned": None}
    if paths is not None:
        result["cleaned"] = cleanup_session_temp(paths)
    return result


def handle_evidence_import(params: dict[str, Any]) -> dict[str, Any]:
    path = params.get("path")
    if not path:
        raise AppError(
            code="invalid_params",
            message="path is required to import a memory image.",
            entity="evidence",
        )
    jobs = _jobs()
    jobs.cancel_active()
    jobs.reset_visible_jobs()
    return jobs.submit(
        "evidence_import",
        params={"path": str(path)},
        message="Importing memory image…",
    )


def handle_analysis_run(params: dict[str, Any]) -> dict[str, Any]:
    evidence_id = params.get("evidence_id")
    if not evidence_id:
        raise AppError(
            code="evidence_required",
            message="Select imported evidence before running analysis.",
            entity="evidence",
        )
    profile = str(params.get("profile") or "custom")
    capabilities = params.get("capabilities") or []
    if not isinstance(capabilities, list):
        capabilities = []
    profiles.resolve_selection(profile, capabilities)
    return _jobs().submit(
        "analysis_profile",
        evidence_id=str(evidence_id),
        process_id=params.get("process_id"),
        pid=params.get("pid"),
        params={
            "evidence_id": evidence_id,
            "profile": profile,
            "capabilities": capabilities,
            "process_id": params.get("process_id"),
            "pid": params.get("pid"),
        },
        message=f"Analysis ({profile})",
    )


def handle_job_submit(params: dict[str, Any]) -> dict[str, Any]:
    kind = params.get("kind")
    if not kind:
        raise AppError(code="invalid_params", message="kind is required", entity="job")
    return _jobs().submit(
        kind,
        evidence_id=params.get("evidence_id"),
        process_id=params.get("process_id"),
        pid=params.get("pid"),
        params=params.get("params") or {},
        message=params.get("message"),
    )


def _artifact_get(artifact_id: str) -> dict[str, Any]:
    dto = memory_artifacts.get_artifact(_db(), artifact_id)
    yara = yara_workflows.list_yara_scans_for_artifact(_db(), artifact_id)
    dto["yara_scans"] = yara["items"]
    dto["yara_status"] = yara_workflows.yara_status(_paths(), _db())
    capa = capa_workflows.list_capa_scans_for_artifact(_db(), artifact_id)
    dto["capa_scans"] = capa["items"]
    dto["capa_status"] = capa_workflows.capa_status(_paths(), _db())
    floss = floss_workflows.list_floss_scans_for_artifact(_db(), artifact_id)
    dto["floss_scans"] = floss["items"]
    dto["floss_status"] = floss_workflows.floss_status(_paths(), _db())
    return dto


HANDLERS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "health": handle_health,
    "app.init": handle_app_init,
    "app.paths": lambda _p: _paths().as_dict(),
    "app.shutdown": handle_app_shutdown,
    "volatility.init": lambda _p: _vol_init(),
    "capabilities.status": handle_capabilities_status,
    "smoke.e2e": lambda _p: {
        "ok": True,
        "health": handle_health({}),
        "volatility": _vol_init(),
        "providers": {
            "yara": yara_workflows.yara_status(_paths(), _db()),
            "pe_extraction": pe_extraction_workflows.pe_extraction_status(_paths(), _db()),
            "capa": capa_workflows.capa_status(_paths(), _db()),
            "floss": floss_workflows.floss_status(_paths(), _db()),
            "bulk_extractor": bulk_extractor_workflows.bulk_extractor_status(_paths(), _db()),
        },
        "plugins": {
            "volatility_version": plugin_explorer.volatility_version(),
            "model_version": 1,
        },
    },
    "evidence.import": handle_evidence_import,
    "evidence.list": lambda _p: {"items": workflows.list_evidence(_db())},
    "evidence.get": lambda p: workflows.get_evidence(_db(), p["evidence_id"]),
    "analysis.profiles": lambda _p: profiles.list_profiles(),
    "analysis.run": handle_analysis_run,
    # Prefer async jobs; keep sync alias that only queues
    "evidence.analyze_basic": lambda p: _jobs().submit(
        "basic_triage",
        evidence_id=p["evidence_id"],
        message="Basic triage (info + pslist)",
    ),
    "processes.list": lambda p: workflows.list_processes(
        _db(),
        p["evidence_id"],
        search=p.get("search"),
        limit=int(p.get("limit", 5000)),
        offset=int(p.get("offset", 0)),
    ),
    "process.get": lambda p: process_analysis.get_process_deep_dive(_db(), p["process_id"]),
    "process.analyze_recommended": lambda p: _jobs().submit(
        "process_recommended",
        evidence_id=p["evidence_id"],
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"evidence_id": p["evidence_id"], "process_id": p.get("process_id"), "pid": p.get("pid")},
        message=f"Recommended analysis PID {p.get('pid')}",
    ),
    "overview.get": lambda p: workflows.overview(_db(), p["evidence_id"]),
    "network.list": lambda p: process_analysis.list_network(_db(), p["evidence_id"]),
    "network.artifacts": lambda p: network_artifacts.list_network_artifacts(
        _db(),
        p["evidence_id"],
        artifact_type=p.get("artifact_type"),
        pid=p.get("pid"),
        limit=int(p.get("limit", 20000)),
    ),
    "network.artifact_runs": lambda p: network_artifacts.list_network_artifact_runs(
        _db(), p["evidence_id"]
    ),
    "network.extract_artifacts": lambda p: _jobs().submit(
        "network_artifact_extraction",
        evidence_id=p["evidence_id"],
        params={"evidence_id": p["evidence_id"]},
        message="Network artifact extraction",
    ),
    "pcap.reconstructions": lambda p: pcap_reconstruction.list_pcap_reconstructions(
        _db(), p["evidence_id"]
    ),
    "pcap.get": lambda p: pcap_reconstruction.get_pcap_reconstruction(_db(), p["reconstruction_id"]),
    "pcap.reconstruct": lambda p: _jobs().submit(
        "pcap_reconstruction",
        evidence_id=p["evidence_id"],
        params={
            "evidence_id": p["evidence_id"],
            "import_pcap_path": p.get("import_pcap_path"),
        },
        message="PCAP reconstruction",
    ),
    "pcap.export_flow": lambda p: pcap_reconstruction.export_flow_pcap(
        _db(),
        reconstruction_id=p["reconstruction_id"],
        flow_id=p["flow_id"],
        paths=_paths(),
    ),
    "modules.list": lambda p: process_analysis.list_modules(
        _db(), p["evidence_id"], pid=p.get("pid")
    ),
    "findings.list": lambda p: process_analysis.list_findings(_db(), p["evidence_id"]),
    "search.query": lambda p: search_iocs.global_search(
        _db(),
        p["evidence_id"],
        p["query"],
        limit=int(p.get("limit", 200)),
        scope=str(p.get("scope") or "all"),
    ),
    "iocs.extract": lambda p: search_iocs.extract_iocs(_db(), p["evidence_id"]),
    "iocs.list": lambda p: search_iocs.list_iocs(
        _db(),
        p["evidence_id"],
        ioc_type=p.get("ioc_type"),
        limit=int(p["limit"]) if p.get("limit") is not None else None,
        offset=int(p.get("offset") or 0),
    ),
    "iocs.export_json": lambda p: search_iocs.write_iocs_export(
        _db(),
        _paths(),
        p["evidence_id"],
        "json",
        destination=p.get("destination") or p.get("output_path"),
    ),
    "iocs.export_xlsx": lambda p: search_iocs.write_iocs_export(
        _db(),
        _paths(),
        p["evidence_id"],
        "xlsx",
        destination=p.get("destination") or p.get("output_path"),
    ),
    "iocs.export_csv": lambda p: search_iocs.write_iocs_export(
        _db(),
        _paths(),
        p["evidence_id"],
        "xlsx",
        destination=p.get("destination") or p.get("output_path"),
    ),
    "memory.list": lambda p: memory_artifacts.list_memory_regions(
        _db(),
        p["evidence_id"],
        pid=p.get("pid"),
        process_id=p.get("process_id"),
        suspicious_only=bool(p.get("suspicious_only", False)),
        limit=int(p.get("limit", 10000)),
        offset=int(p.get("offset", 0)),
    ),
    "memory.get": lambda p: memory_artifacts.get_memory_region(_db(), p["region_id"]),
    "memory.scan": lambda p: _jobs().submit(
        "vad_scan",
        evidence_id=p["evidence_id"],
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={
            "evidence_id": p["evidence_id"],
            "process_id": p.get("process_id"),
            "pid": p.get("pid"),
        },
        message=f"VAD scan PID {p.get('pid')}",
    ),
    "memory.extract": lambda p: _jobs().submit(
        "vad_extract",
        evidence_id=p["evidence_id"],
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={
            "evidence_id": p["evidence_id"],
            "memory_region_id": p["memory_region_id"],
            "pid": p.get("pid"),
            "process_id": p.get("process_id"),
            "start_vpn": p.get("start_vpn"),
            "end_vpn": p.get("end_vpn"),
            "maxsize": p.get("maxsize"),
        },
        message="Extract VAD region",
    ),
    "timeline.build": lambda p: memory_artifacts.build_timeline(_db(), p["evidence_id"]),
    "timeline.list": lambda p: memory_artifacts.list_timeline(_db(), p["evidence_id"]),
    "artifacts.list": lambda p: memory_artifacts.list_artifacts(_db(), p["evidence_id"]),
    "artifacts.get": lambda p: _artifact_get(p["artifact_id"]),
    "yara.status": lambda _p: yara_workflows.yara_status(_paths(), _db()),
    "yara.reload": lambda _p: yara_workflows.reload_yara_rules(_paths(), _db()),
    "yara.configure": lambda p: yara_workflows.configure_yara(
        _paths(), _db(), p.get("settings") or p
    ),
    "yara.scan_artifact": lambda p: _jobs().submit(
        "yara_artifact_scan",
        evidence_id=p.get("evidence_id"),
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"artifact_id": p["artifact_id"], "evidence_id": p.get("evidence_id")},
        message="Signature Detection artifact scan",
    ),
    "yara.scan_memory": lambda p: _jobs().submit(
        "yara_memory_scan",
        evidence_id=p["evidence_id"],
        params={"evidence_id": p["evidence_id"]},
        message="Signature Detection memory dump scan",
    ),
    "yara.scan_extracted": lambda p: _jobs().submit(
        "yara_extracted_scan",
        evidence_id=p["evidence_id"],
        params={"evidence_id": p["evidence_id"]},
        message="Signature Detection extracted files scan",
    ),
    "yara.scans_for_artifact": lambda p: yara_workflows.list_yara_scans_for_artifact(
        _db(), p["artifact_id"]
    ),
    "yara.scans_for_evidence": lambda p: yara_workflows.list_yara_scans_for_evidence(
        _db(), p["evidence_id"]
    ),
    "yara.scan_get": lambda p: yara_workflows.get_yara_scan(_db(), p["scan_id"]),
    "yara.matches_for_evidence": lambda p: yara_workflows.list_yara_matches_for_evidence(
        _db(), p["evidence_id"]
    ),
    "pe_extraction.status": lambda _p: pe_extraction_workflows.pe_extraction_status(
        _paths(), _db()
    ),
    "pe_extraction.run": lambda p: _jobs().submit(
        "pe_extraction",
        evidence_id=p["evidence_id"],
        pid=p.get("pid"),
        params={
            "evidence_id": p["evidence_id"],
            "pid": p.get("pid"),
            "include_dumpfiles": bool(p.get("include_dumpfiles")),
        },
        message="PE extraction from imported memory dump",
    ),
    "pe_extraction.runs": lambda p: pe_extraction_workflows.list_pe_extraction_runs(
        _db(), p["evidence_id"]
    ),
    "pe_extraction.run_get": lambda p: pe_extraction_workflows.get_pe_extraction_run(
        _db(), p["run_id"]
    ),
    "pe_extraction.artifacts": lambda p: pe_extraction_workflows.list_extracted_pe_artifacts(
        _db(), p["evidence_id"]
    ),
    "capa.status": lambda _p: capa_workflows.capa_status(_paths(), _db()),
    "capa.configure": lambda p: capa_workflows.configure_capa(
        _paths(), _db(), p.get("settings") or p
    ),
    "capa.scan_artifact": lambda p: _jobs().submit(
        "capa_artifact",
        evidence_id=p.get("evidence_id"),
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"artifact_id": p["artifact_id"], "evidence_id": p.get("evidence_id")},
        message=f"CAPA analysis artifact {p.get('artifact_id')}",
    ),
    "capa.scans_for_artifact": lambda p: capa_workflows.list_capa_scans_for_artifact(
        _db(), p["artifact_id"]
    ),
    "capa.scan_get": lambda p: capa_workflows.get_capa_scan(_db(), p["scan_id"]),
    "floss.status": lambda _p: floss_workflows.floss_status(_paths(), _db()),
    "floss.configure": lambda p: floss_workflows.configure_floss(
        _paths(), _db(), p.get("settings") or p
    ),
    "floss.scan_artifact": lambda p: _jobs().submit(
        "floss_artifact",
        evidence_id=p.get("evidence_id"),
        process_id=p.get("process_id"),
        pid=p.get("pid"),
        params={"artifact_id": p["artifact_id"], "evidence_id": p.get("evidence_id")},
        message=f"FLOSS analysis artifact {p.get('artifact_id')}",
    ),
    "floss.scans_for_artifact": lambda p: floss_workflows.list_floss_scans_for_artifact(
        _db(), p["artifact_id"]
    ),
    "floss.scan_get": lambda p: floss_workflows.get_floss_scan(_db(), p["scan_id"]),
    "bulk_extractor.status": lambda _p: bulk_extractor_workflows.bulk_extractor_status(
        _paths(), _db()
    ),
    "bulk_extractor.configure": lambda p: bulk_extractor_workflows.configure_bulk_extractor(
        _paths(), _db(), p.get("settings") or p
    ),
    "bulk_extractor.scan": lambda p: _jobs().submit(
        "bulk_extractor_scan",
        evidence_id=p["evidence_id"],
        params={"evidence_id": p["evidence_id"]},
        message="bulk_extractor scan of imported memory image",
    ),
    "bulk_extractor.scans": lambda p: bulk_extractor_workflows.list_bulk_extractor_scans(
        _db(), p["evidence_id"]
    ),
    "bulk_extractor.scan_get": lambda p: bulk_extractor_workflows.get_bulk_extractor_scan(
        _db(), p["scan_id"]
    ),
    "bulk_extractor.features": lambda p: bulk_extractor_workflows.list_bulk_extractor_features(
        _db(),
        p["scan_id"],
        category=p.get("category"),
        scanner=p.get("scanner"),
        q=p.get("q") or p.get("query"),
        hide_weak=bool(p.get("hide_weak")),
        limit=int(p.get("limit", 500)),
        offset=int(p.get("offset", 0)),
    ),
    "plugins.list": lambda p: plugin_explorer.list_plugins_for_ui(
        _db(), p.get("evidence_id")
    ),
    "plugins.get": lambda p: plugin_explorer.get_plugin_for_ui(
        _db(), p["plugin_id"], p.get("evidence_id")
    ),
    "plugins.validate": lambda p: {
        "ok": True,
        **{
            k: v
            for k, v in plugin_explorer.validate_execution_request(
                _db(),
                evidence_id=p.get("evidence_id"),
                plugin_id=p["plugin_id"],
                parameters=p.get("parameters") or {},
            ).items()
            if k != "evidence"
        },
        "evidence_id": p.get("evidence_id"),
    },
    "plugins.execute": lambda p: _jobs().submit(
        "plugin_advanced",
        evidence_id=p["evidence_id"],
        params={
            "evidence_id": p["evidence_id"],
            "plugin_id": p["plugin_id"],
            "parameters": p.get("parameters") or {},
            "timeout_secs": p.get("timeout_secs"),
        },
        message=f"Advanced plugin {p.get('plugin_id')}",
    ),
    "plugins.execution_get": lambda p: plugin_explorer.get_execution_bundle(
        _db(),
        p["execution_id"],
        preview_limit=int(p.get("limit", 500)),
        offset=int(p.get("offset", 0)),
    ),
    "plugins.executions": lambda p: plugin_explorer.list_executions(
        _db(), p["evidence_id"], limit=int(p.get("limit", 50))
    ),
    "export.options": lambda _p: export_workflows.available_options(),
    "export.generate": lambda p: _jobs().submit(
        "export_report",
        evidence_id=p["evidence_id"],
        params={
            "evidence_id": p["evidence_id"],
            "format": p.get("format") or "html",
            "scope": p.get("scope") or "complete",
            "sections": p.get("sections"),
            "filename_hint": p.get("filename_hint"),
        },
        message="Generate investigation export",
    ),
    "export.list": lambda p: export_workflows.list_exports(
        _db(), p["evidence_id"], limit=int(p.get("limit", 50))
    ),
    "export.get": lambda p: export_workflows.get_export(_db(), p["export_id"]),
    "export.delete": lambda p: export_workflows.delete_exports(
        _db(),
        _paths(),
        evidence_id=p["evidence_id"],
        export_ids=p.get("export_ids") or [],
    ),
    "jobs.submit": handle_job_submit,
    "jobs.get": lambda p: _jobs().get(p["job_id"]),
    "jobs.list": lambda p: {
        "items": _jobs().list_jobs(
            evidence_id=p.get("evidence_id"), limit=int(p.get("limit", 50))
        )
    },
    "jobs.cancel": lambda p: _jobs().cancel(p["job_id"]),
}


def _write(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":"), default=str) + "\n")
    sys.stdout.flush()


def _error(req_id: Any, payload: dict[str, Any]) -> None:
    _write({"jsonrpc": "2.0", "id": req_id, "error": payload})


def handle_line(line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        req = json.loads(line)
    except json.JSONDecodeError as exc:
        _error(None, {"code": -32700, "message": "Parse error", "data": str(exc)})
        return

    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    if req.get("jsonrpc") != "2.0" or not isinstance(method, str):
        _error(req_id, {"code": -32600, "message": "Invalid Request"})
        return

    handler = HANDLERS.get(method)
    if handler is None:
        _error(req_id, {"code": -32601, "message": f"Method not found: {method}"})
        return

    try:
        result = handler(params)
        if req_id is not None:
            _write({"jsonrpc": "2.0", "id": req_id, "result": result})
    except Exception as exc:  # noqa: BLE001
        if not isinstance(exc, AppError):
            log.error("unhandled engine error", extra={"channel": "app"}, exc_info=exc)
        payload = rpc_error_payload(exc)
        _error(req_id, payload)


def main() -> None:
    try:
        handle_app_init({})
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"engine bootstrap failed: {exc}\n")
        raise
    for line in sys.stdin:
        handle_line(line)


if __name__ == "__main__":
    main()
