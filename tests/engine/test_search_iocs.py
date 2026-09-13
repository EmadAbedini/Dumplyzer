"""Search and IOC extraction unit tests (normalized data only)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis.search_iocs import extract_iocs, global_search, list_iocs
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.errors import AppError
from memscope_engine.storage import Database
from memscope_engine.storage.schema import SCHEMA_VERSION


def _seed(db: Database, evidence_id: str) -> str:
    run_id = str(uuid4())
    db.execute(
        """
        INSERT INTO analysis_runs (
          id, evidence_id, kind, status, started_at, schema_version, strategy_json
        ) VALUES (?, ?, 'basic_triage', 'completed', '2020-01-01T00:00:00+00:00', 3, '[]')
        """,
        (run_id, evidence_id),
    )
    pid = str(uuid4())
    db.execute(
        """
        INSERT INTO processes (
          id, evidence_id, analysis_run_id, pid, ppid, name, command_line, source_plugin
        ) VALUES (?, ?, ?, 4242, 4, 'powershell.exe',
          'powershell.exe -EncodedCommand AQID http://evil.example.com/a',
          'windows.pslist')
        """,
        (pid, evidence_id, run_id),
    )
    db.execute(
        """
        INSERT INTO network_connections (
          id, evidence_id, analysis_run_id, process_id, pid, protocol,
          local_address, local_port, remote_address, remote_port, state, source_plugin
        ) VALUES (?, ?, ?, ?, 4242, 'TCPv4', '10.0.0.5', 49152, '203.0.113.10', 443, 'ESTABLISHED', 'windows.netscan')
        """,
        (str(uuid4()), evidence_id, run_id, pid),
    )
    return pid


def test_global_search_and_iocs(tmp_path: Path) -> None:
    db = Database(tmp_path / "s.db")
    assert db.schema_version() == SCHEMA_VERSION
    img = tmp_path / "t.raw"
    img.write_bytes(b"search-test")
    ev = import_evidence(db, str(img))
    proc_id = _seed(db, ev["id"])

    res = global_search(db, ev["id"], "powershell")
    assert res["total"] >= 1
    assert any(i["entity"] == "process" for i in res["items"])

    res2 = global_search(db, ev["id"], "203.0.113.10")
    assert any(i["entity"] == "network" for i in res2["items"])

    names = global_search(db, ev["id"], "powershell", scope="process_names")
    assert names["total"] >= 1
    assert all(i["entity"] == "process" for i in names["items"])
    assert global_search(db, ev["id"], "powershell", scope="ip_addresses")["total"] == 0
    assert any(
        i["entity"] == "network"
        for i in global_search(db, ev["id"], "203.0.113.10", scope="ip_addresses")["items"]
    )
    assert global_search(db, ev["id"], "203.0.113.10", scope="process_names")["total"] == 0
    assert any(
        i["entity"] == "process"
        for i in global_search(db, ev["id"], "4242", scope="pids")["items"]
    )
    with pytest.raises(AppError):
        global_search(db, ev["id"], "powershell", scope="not-a-field")

    iocs = extract_iocs(db, ev["id"])
    assert iocs["extracted"] >= 1
    types = {i["ioc_type"] for i in iocs["items"]}
    assert "ipv4" in types or "url" in types or "domain" in types

    listed = list_iocs(db, ev["id"])
    assert listed["total"] == iocs["total"]
    assert listed["total"] == len(listed["items"])
    assert any(i.get("process_id") == proc_id or i.get("pid") == 4242 for i in listed["items"])
    capped = list_iocs(db, ev["id"], limit=1)
    assert len(capped["items"]) == 1
    assert capped["total"] == listed["total"]
    db.close()


def test_extract_iocs_keeps_bulk_extractor_rows(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    img = tmp_path / "t.raw"
    img.write_bytes(b"ioc-keep")
    ev = import_evidence(db, str(img))
    _seed(db, ev["id"])
    now = "2020-01-01T00:00:00+00:00"
    db.execute(
        """
        INSERT INTO iocs (
          id, evidence_id, process_id, pid, ioc_type, value, context, source, created_at
        ) VALUES (?, ?, NULL, NULL, 'url', 'http://kept.example', 'scan', 'bulk_extractor', ?)
        """,
        (str(uuid4()), ev["id"], now),
    )
    result = extract_iocs(db, ev["id"])
    values = {i["value"] for i in result["items"]}
    sources = {i["source"] for i in result["items"]}
    assert "http://kept.example" in values
    assert "bulk_extractor" in sources
    db.close()


def test_write_iocs_export_json_and_xlsx(tmp_path: Path) -> None:
    from xml.etree import ElementTree as ET

    from memscope_engine.analysis.search_iocs import write_iocs_export
    from memscope_engine.export.workflows import list_exports
    from memscope_engine.paths import AppPaths

    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    img = tmp_path / "t.raw"
    img.write_bytes(b"ioc-export-test")
    ev = import_evidence(db, str(img))
    _seed(db, ev["id"])
    extract_iocs(db, ev["id"])

    json_res = write_iocs_export(db, paths, ev["id"], "json")
    json_path = Path(json_res["primary_path"])
    assert json_path.is_file()
    assert json_path.name == "iocs-json.zip"
    json_path.resolve().relative_to(paths.exports.resolve())
    with zipfile.ZipFile(json_path) as zf:
        names = set(zf.namelist())
        assert names
        assert all(name.endswith(".json") for name in names)
        sample = json.loads(zf.read(next(iter(names))))
        keys = list(sample)
        assert keys[:4] == ["format", "evidence_file_name", "created_at", "sha256"]
        assert sample["format"] == "memscope-iocs-v1"
        assert sample["evidence_file_name"] == img.name
        assert sample["sha256"] == ev["sha256"]
        assert sample["created_at"]
        assert "UTC" in sample["created_at"]
        assert "," in sample["created_at"]
        assert "ioc_type" in sample
        assert sample["count"] == len(sample["iocs"])
        item = sample["iocs"][0]
        assert set(item) == {"ioc_type", "value", "pid", "source"}
        for key in ("id", "process_id", "context", "evidence_id", "created_at", "sha256", "evidence_file_name"):
            assert key not in item
    assert json_res["count"] >= 1
    assert json_res["type_count"] >= 1

    xlsx_res = write_iocs_export(db, paths, ev["id"], "xlsx")
    xlsx_path = Path(xlsx_res["primary_path"])
    assert xlsx_path.is_file()
    assert xlsx_path.name == "iocs.xlsx"
    with zipfile.ZipFile(xlsx_path) as zf:
        assert "xl/workbook.xml" in zf.namelist()
        wb = ET.fromstring(zf.read("xl/workbook.xml"))
        ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        sheets_el = wb.find("m:sheets", ns)
        assert sheets_el is not None
        sheet_names = [sheet.attrib["name"] for sheet in sheets_el.findall("m:sheet", ns)]
        assert sheet_names
        sheet1 = ET.fromstring(zf.read("xl/worksheets/sheet1.xml"))
        rows = sheet1.findall("m:sheetData/m:row", ns)
        cells = [
            (c.find("m:is/m:t", ns).text or "")
            for c in rows[0].findall("m:c", ns)
        ]
        assert cells[0] == "evidence_file_name"
        assert cells[1] == img.name
        created = [
            (c.find("m:is/m:t", ns).text or "")
            for c in rows[1].findall("m:c", ns)
        ]
        assert created[0] == "created_at"
        assert "UTC" in created[1]
        sha = [
            (c.find("m:is/m:t", ns).text or "")
            for c in rows[2].findall("m:c", ns)
        ]
        assert sha == ["sha256", ev["sha256"]]
        header = [
            (c.find("m:is/m:t", ns).text or "")
            for c in rows[4].findall("m:c", ns)
        ]
        assert header == ["ioc_type", "value", "pid", "source"]
    assert xlsx_res["count"] >= 1

    listed = list_exports(db, ev["id"])
    assert listed["total"] >= 2
    formats = {item["format"] for item in listed["items"]}
    assert "json" in formats and "xlsx" in formats

    with pytest.raises(AppError) as rejected:
        write_iocs_export(db, paths, ev["id"], "json", destination="C:\\tmp\\out.json")
    assert rejected.value.code == "export_path_rejected"

    db.close()


def test_frontend_ioc_excel_export() -> None:
    root = Path(__file__).resolve().parents[2]
    view = (root / "app" / "frontend" / "src" / "components" / "SearchIocViews.tsx").read_text(
        encoding="utf-8"
    )
    assert "Export Excel" in view
    assert "iocs.export_xlsx" in view
    assert "Export CSV" not in view
    assert "iocs.xlsx" in view
