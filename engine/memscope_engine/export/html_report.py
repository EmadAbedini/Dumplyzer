"""Self-contained offline HTML forensic report. No CDN."""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memscope_engine.export.constants import HTML_MAX_ROWS, REPORT_FORMAT, REPORT_SCHEMA_VERSION, REPORT_SECTIONS

_MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)
_ISO_TS = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$",
    re.IGNORECASE,
)

_CSS = """
:root { color-scheme: dark light; }
* { box-sizing: border-box; }
html, body { width: 100%; max-width: none; }
body {
  margin: 0; padding: 0;
  font-family: "Segoe UI", "Liberation Sans", system-ui, sans-serif;
  font-size: 13px; line-height: 1.5;
  background: #0c1118; color: #e7edf4;
}
header {
  padding: 28px 36px 22px;
  width: 100%;
  border-bottom: 1px solid #2a3546;
  background: linear-gradient(180deg, #152033 0%, #121a26 100%);
}
.brand { font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; color: #8cb4ff; font-weight: 650; }
h1 { margin: 6px 0 8px; font-size: 22px; font-weight: 650; letter-spacing: -0.02em; }
h2 {
  margin: 32px 0 12px; font-size: 15px; font-weight: 650;
  padding-bottom: 8px; border-bottom: 1px solid #2a3546;
}
h3 { margin: 18px 0 8px; font-size: 13px; font-weight: 650; }
.meta { font-size: 12px; color: #9aa6b8; }
.muted { color: #9aa6b8; }
.empty { padding: 14px 16px; border: 1px dashed #334155; border-radius: 8px; color: #9aa6b8; background: #101826; }
nav { position: sticky; top: 0; z-index: 5; padding: 10px 36px; width: 100%; border-bottom: 1px solid #2a3546; background: #121a26; font-size: 12px; }
nav a { color: #8cb4ff; text-decoration: none; margin-right: 14px; }
nav a:hover { text-decoration: underline; }
main { padding: 8px 36px 56px; width: 100%; max-width: none; }
section { width: 100%; }
.table-wrap { width: 100%; overflow-x: auto; }
.card {
  border: 1px solid #2a3546; background: #151d2a; padding: 14px 16px;
  margin: 8px 0 16px; border-radius: 8px;
}
.note {
  border: 1px solid #3d4a22; background: #172114; padding: 10px 12px;
  margin: 16px 0 20px; font-size: 12px; border-radius: 8px;
}
.kpis { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; margin: 12px 0 18px; }
.kpi { border: 1px solid #2a3546; background: #151d2a; border-radius: 8px; padding: 12px 14px; }
.kpi .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #9aa6b8; }
.kpi .val { font-size: 20px; font-weight: 650; margin-top: 4px; }
table { border-collapse: collapse; width: max-content; min-width: 100%; margin: 8px 0 18px; font-size: 12px; table-layout: auto; }
th, td {
  border: 1px solid #2a3546; padding: 7px 10px; vertical-align: top; text-align: left;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
table thead { background: #1b2534; }
th { position: relative; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #b8c2d1; min-width: 5rem; }
.col-handle {
  position: absolute; top: 0; right: 0; width: 8px; height: 100%;
  cursor: col-resize; user-select: none;
}
body.col-resizing, body.col-resizing * { cursor: col-resize !important; user-select: none !important; }
tr:nth-child(even) { background: #121a26; }
code, .mono {
  font-family: "Cascadia Code", "Consolas", monospace; font-size: 11px;
  white-space: nowrap;
}
.badge {
  display: inline-block; font-size: 10px; padding: 2px 7px; border-radius: 999px;
  border: 1px solid #3d4a5c; font-weight: 650; letter-spacing: 0.04em; text-transform: uppercase;
}
.obs { background: #14301a; color: #9be09f; border-color: #245c32; }
.inf { background: #3a2c12; color: #f0c674; border-color: #6a5420; }
.sev-high { background: #3a1518; color: #ff9b9b; border-color: #7a2e34; }
.sev-medium { background: #3a2c12; color: #f0c674; border-color: #6a5420; }
.sev-low { background: #1c2530; color: #9aa6b8; }
.sev-info { background: #15243a; color: #8cb4ff; border-color: #2a4c7a; }
footer { padding: 18px 36px 32px; width: 100%; border-top: 1px solid #2a3546; font-size: 11px; color: #9aa6b8; }
@media (prefers-color-scheme: light) {
  body { background: #f4f6fa; color: #1b2430; }
  header, nav, footer { background: #eef2f7; border-color: #d5dce8; }
  header { background: linear-gradient(180deg, #e8eef8 0%, #eef2f7 100%); }
  .brand { color: #1d4ed8; }
  table thead { background: #e6ebf3; }
  th { color: #3a4558; }
  tr:nth-child(even) { background: #f7f9fc; }
  th, td, h2, header, nav, footer { border-color: #d5dce8; }
  .card, .kpi { background: #fff; border-color: #d5dce8; }
  .note { background: #f7f3e8; border-color: #e0d4a8; }
  .empty { background: #fff; border-color: #d5dce8; color: #5c6678; }
  .muted, .meta, footer { color: #5c6678; }
  .obs { background: #d7ead8; color: #1b4d1f; border-color: #9cc9a0; }
  .inf { background: #f3e2c1; color: #6a4a12; border-color: #e0c48a; }
  .sev-high { background: #fde2e2; color: #9f1239; border-color: #f5b5b5; }
  .sev-medium { background: #f3e2c1; color: #6a4a12; }
  .sev-low { background: #e8edf4; color: #3a4558; }
  .sev-info { background: #dbe7fb; color: #1e40af; }
  a { color: #1f4e79; }
}
@media print {
  body { background: #fff; color: #111; }
  header, nav, footer, .card, .kpi, .note { background: #fff; box-shadow: none; }
  nav { display: none; }
  a { color: #111; text-decoration: none; }
  .col-handle { display: none; }
}
""".strip()

_JS = """
(function () {
  function bind(th) {
    if (th.querySelector(".col-handle")) return;
    var handle = document.createElement("span");
    handle.className = "col-handle";
    handle.title = "Drag to resize column";
    th.appendChild(handle);
    handle.addEventListener("mousedown", function (event) {
      event.preventDefault();
      event.stopPropagation();
      var startX = event.pageX;
      var startW = th.getBoundingClientRect().width;
      document.body.classList.add("col-resizing");
      function move(ev) {
        var width = Math.max(48, startW + (ev.pageX - startX));
        th.style.width = width + "px";
        th.style.minWidth = width + "px";
        th.style.maxWidth = width + "px";
      }
      function up() {
        document.body.classList.remove("col-resizing");
        document.removeEventListener("mousemove", move);
        document.removeEventListener("mouseup", up);
      }
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
    });
  }
  document.querySelectorAll("table").forEach(function (table) {
    var row = table.tHead && table.tHead.rows[0];
    if (!row) return;
    for (var i = 0; i < row.cells.length; i++) bind(row.cells[i]);
  });
})();
""".strip()


def format_html_time(value: Any) -> str | None:
    """Convert a stored ISO timestamp to the local system clock, human-readable."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or not _ISO_TS.match(raw):
        return None
    iso = raw.replace(" ", "T", 1)
    if iso.endswith(("Z", "z")):
        iso = iso[:-1] + "+00:00"
    elif re.search(r"[+-]\d{4}$", iso):
        iso = iso[:-5] + iso[-5:-2] + ":" + iso[-2:]
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone()
    offset = local.utcoffset()
    if offset is None:
        zone = ""
    else:
        total = int(offset.total_seconds())
        sign = "+" if total >= 0 else "-"
        total = abs(total)
        hours, rem = divmod(total, 3600)
        minutes = rem // 60
        zone = "UTC" if hours == 0 and minutes == 0 else f"UTC{sign}{hours}:{minutes:02d}"
    month = _MONTHS[local.month - 1]
    text = f"{month} {local.day}, {local.year}, {local.hour:02d}:{local.minute:02d}:{local.second:02d}"
    return f"{text} {zone}".strip()


def html_time(value: Any) -> str:
    formatted = format_html_time(value)
    if formatted is not None:
        return formatted
    if value is None:
        return ""
    return str(value)


def esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


class _Html(str):
    """Pre-escaped HTML fragment for table cells."""


def _cell(value: Any) -> str:
    if isinstance(value, _Html):
        return str(value)
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return esc(", ".join(str(v) for v in value))
    if isinstance(value, dict):
        return esc(str(value))
    formatted = format_html_time(value)
    if formatted is not None:
        return esc(formatted)
    return esc(value)


def _trunc_note(block: dict[str, Any] | None, noun: str) -> str:
    if not block:
        return f"<p class='muted'>No {esc(noun)} recorded.</p>"
    total = block.get("total") or 0
    shown = block.get("shown") or 0
    extra = ""
    if block.get("truncated"):
        extra = (
            f" <span class='muted'>Showing {esc(shown)} of {esc(total)}. "
            "Remaining rows are in the JSON/Excel export, not embedded here.</span>"
        )
    return f"<p class='muted'>{esc(total)} {esc(noun)}.{extra}</p>"


def _table(headers: list[str], rows: list[list[Any]], *, empty: str) -> str:
    if not rows:
        return f"<p class='empty'>{esc(empty)}</p>"
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        tds = "".join(f"<td class='mono'>{_cell(c)}</td>" for c in row)
        body.append(f"<tr>{tds}</tr>")
    return (
        "<div class='table-wrap'>"
        f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"
        "</div>"
    )


def _cls_badge(classification: str | None) -> str:
    if classification == "inferred":
        return "<span class='badge inf'>inferred</span>"
    if classification == "observed":
        return "<span class='badge obs'>observed</span>"
    return esc(classification)


def _sev_badge(severity: Any) -> _Html:
    raw = "" if severity is None else str(severity)
    key = raw.lower()
    cls = "sev-low"
    if key in ("high", "critical"):
        cls = "sev-high"
    elif key in ("medium", "moderate"):
        cls = "sev-medium"
    elif key in ("info", "informational"):
        cls = "sev-info"
    return _Html(f"<span class='badge {cls}'>{esc(raw or '—')}</span>")


def _finding_rows(items: list[dict[str, Any]]) -> list[list[Any]]:
    rows = []
    for f in items[:HTML_MAX_ROWS]:
        rows.append(
            [
                f.get("title"),
                _sev_badge(f.get("severity")),
                f.get("explanation"),
                f.get("plugin"),
                f.get("pid"),
                f.get("process_name"),
                f.get("field_name"),
                f.get("field_value"),
            ]
        )
    return rows


def render_html(doc: dict[str, Any]) -> str:
    meta = doc.get("metadata") or {}
    raw_sections = doc.get("sections_included") or []
    if isinstance(raw_sections, str):
        raw_sections = [raw_sections]
    section_set = {str(s) for s in raw_sections if str(s) in REPORT_SECTIONS}
    sections = [s for s in REPORT_SECTIONS if s in section_set]
    title = f"Dumplyzer investigation report — {meta.get('evidence_file_name') or meta.get('evidence_filename') or doc.get('evidence_file_name') or 'evidence'}"
    nav_links = []
    for s in sections:
        nav_links.append(f"<a href='#{esc(s)}'>{esc(s)}</a>")

    parts: list[str] = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{esc(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<header>",
        "<div class='brand'>Dumplyzer report</div>",
        f"<h1>{esc(title)}</h1>",
        f"<div class='meta'>Format {esc(REPORT_FORMAT)} · report schema v{esc(REPORT_SCHEMA_VERSION)} · "
        f"generated {esc(html_time(meta.get('generated_at') or doc.get('generated_at')))} · "
        f"Dumplyzer {esc(meta.get('memscope_version') or doc.get('memscope_version'))}</div>",
        "</header>",
        f"<nav>{''.join(nav_links)}</nav>",
        "<main>",
        "<div class='note'>This report is a static offline document. Forensic strings are escaped. "
        "Inferred timeline events are labeled and are not treated as directly observed evidence. "
        "No malware or risk score is assigned.</div>",
    ]

    if "metadata" in sections:
        parts.append("<section id='metadata'><h2>1. Report metadata</h2>")
        rows = [
            ["Evidence file", meta.get("evidence_file_name") or doc.get("evidence_file_name")],
            ["SHA-256", meta.get("sha256") or doc.get("sha256")],
            ["Generated at", doc.get("created_at") or doc.get("generated_at")],
            ["Size (bytes)", meta.get("size_bytes")],
            ["Path", meta.get("path")],
            ["Detected OS", meta.get("detected_os")],
            ["Architecture", meta.get("architecture")],
            ["Symbol status", meta.get("symbol_status")],
            ["Imported at", meta.get("import_timestamp")],
            ["Volatility version", meta.get("volatility_version")],
        ]
        parts.append(_table(["Field", "Value"], rows, empty="No metadata."))
        parts.append("</section>")

    if "summary" in sections:
        summary = doc.get("summary") or {}
        parts.append("<section id='summary'><h2>2. Executive summary</h2>")
        parts.append(f"<div class='card'>{esc(summary.get('text'))}</div>")
        counts = [
            ["Processes", summary.get("process_count")],
            ["Findings", summary.get("finding_count")],
            ["Network connections", summary.get("network_count")],
            ["Network artifacts", summary.get("network_artifact_count")],
            ["Modules", summary.get("module_count")],
            ["Memory regions", summary.get("memory_region_count")],
            ["Timeline events", summary.get("timeline_event_count")],
            ["Artifacts", summary.get("artifact_count")],
            ["IOCs", summary.get("ioc_count")],
            ["YARA matches", summary.get("yara_match_count")],
            ["PE extraction runs", summary.get("pe_extraction_run_count")],
            ["CAPA scans", summary.get("capa_scan_count")],
            ["FLOSS scans", summary.get("floss_scan_count")],
            ["bulk_extractor scans", summary.get("bulk_extractor_scan_count")],
            ["PCAP reconstruction", summary.get("pcap_reconstruction_status") or "not run"],
            ["Advanced Volatility executions", summary.get("advanced_execution_count")],
        ]
        kpis = "".join(
            f"<div class='kpi'><div class='lbl'>{esc(label)}</div>"
            f"<div class='val'>{esc(value if value is not None else 0)}</div></div>"
            for label, value in counts[:8]
        )
        parts.append(f"<div class='kpis'>{kpis}</div>")
        parts.append(_table(["Count", "Value"], counts, empty="No summary."))
        parts.append("<p class='muted'>No malware or risk score is generated.</p></section>")

    if "findings" in sections:
        block = doc.get("findings") or {}
        parts.append("<section id='findings'><h2>3. Findings</h2>")
        parts.append(_trunc_note(block, "finding(s)"))
        parts.append(
            _table(
                ["Title", "Severity", "Explanation", "Plugin", "PID", "Process", "Field", "Value"],
                _finding_rows(block.get("items") or []),
                empty="No findings.",
            )
        )
        parts.append("</section>")

    if "processes" in sections:
        block = doc.get("processes") or {}
        parts.append("<section id='processes'><h2>4. Processes</h2>")
        parts.append(_trunc_note(block, "process(es)"))
        rows = []
        for p in (block.get("items") or [])[:HTML_MAX_ROWS]:
            parent_s = f"{p.get('parent_pid') or ''} {p.get('parent_name') or ''}".strip()
            rows.append(
                [
                    p.get("pid"),
                    p.get("name"),
                    p.get("image_path"),
                    p.get("command_line"),
                    p.get("username"),
                    parent_s,
                    p.get("create_time"),
                    p.get("source_plugin"),
                ]
            )
        parts.append(
            _table(
                ["PID", "Name", "Executable", "Command line", "User", "Parent", "Started", "Plugin"],
                rows,
                empty="No processes.",
            )
        )
        parts.append("</section>")

    if "network" in sections:
        block = doc.get("network") or {}
        parts.append("<section id='network'><h2>5. Network</h2>")
        parts.append(_trunc_note(block, "connection(s)"))
        rows = []
        for n in (block.get("items") or [])[:HTML_MAX_ROWS]:
            rows.append(
                [
                    n.get("pid"),
                    n.get("process_name"),
                    n.get("protocol"),
                    n.get("local_address"),
                    n.get("local_port"),
                    n.get("remote_address"),
                    n.get("remote_port"),
                    n.get("state"),
                    n.get("owner") or n.get("source_plugin"),
                ]
            )
        parts.append(
            _table(
                ["PID", "Process", "Protocol", "Local", "LPort", "Remote", "RPort", "State", "Owner/plugin"],
                rows,
                empty="No network connections.",
            )
        )
        artifacts = block.get("artifacts") or {}
        type_counts = artifacts.get("type_counts") or {}
        if type_counts:
            parts.append("<h3>Network artifacts</h3>")
            parts.append(
                _table(
                    ["Type", "Count"],
                    [[k, v] for k, v in sorted(type_counts.items())],
                    empty="No network artifacts.",
                )
            )
        art_rows = []
        for a in (artifacts.get("items") or [])[:HTML_MAX_ROWS]:
            art_rows.append(
                [
                    a.get("artifact_type"),
                    a.get("value"),
                    a.get("pid"),
                    a.get("process_name"),
                    a.get("source"),
                    a.get("extraction_method"),
                    a.get("source_address"),
                ]
            )
        if art_rows or artifacts.get("total"):
            parts.append(_trunc_note(artifacts, "network artifact(s)"))
            parts.append(
                _table(
                    ["Type", "Value", "PID", "Process", "Source", "Method", "Offset"],
                    art_rows,
                    empty="No network artifacts.",
                )
            )
        pcap = block.get("pcap")
        if pcap:
            parts.append("<h3>PCAP reconstruction</h3>")
            parts.append(
                _table(
                    ["Field", "Value"],
                    [
                        ["Status", pcap.get("display_status") or pcap.get("reconstruction_status")],
                        ["Packet records", pcap.get("packet_count")],
                        ["Truncated records", pcap.get("truncated_count")],
                        ["Output path", pcap.get("output_path")],
                        ["PCAP embedded in report", "no"],
                        ["Flows with packets", pcap.get("flows_with_packets")],
                        ["Metadata-only flows", pcap.get("metadata_only_flows")],
                    ],
                    empty="PCAP reconstruction was not run.",
                )
            )
            limits = pcap.get("limitations") or []
            if limits:
                parts.append("<p class='muted'>" + esc(" ".join(str(x) for x in limits[:4])) + "</p>")
        parts.append("</section>")

    if "modules" in sections:
        block = doc.get("modules") or {}
        parts.append("<section id='modules'><h2>6. Modules</h2>")
        parts.append(_trunc_note(block, "module(s)"))
        rows = []
        for m in (block.get("items") or [])[:HTML_MAX_ROWS]:
            rows.append(
                [
                    m.get("pid"),
                    m.get("process_name"),
                    m.get("name"),
                    m.get("path"),
                    m.get("base_address"),
                    m.get("size"),
                    m.get("load_time"),
                    m.get("source_plugin"),
                ]
            )
        parts.append(
            _table(
                ["PID", "Process", "Module", "Path", "Base", "Size", "Loaded", "Plugin"],
                rows,
                empty="No modules.",
            )
        )
        parts.append("</section>")

    if "memory" in sections:
        block = doc.get("memory") or {}
        parts.append("<section id='memory'><h2>7. Memory / VAD</h2>")
        parts.append(_trunc_note(block, "region(s)"))
        rows = []
        for r in (block.get("items") or [])[:HTML_MAX_ROWS]:
            rows.append(
                [
                    r.get("pid"),
                    r.get("process_name"),
                    r.get("start_vpn"),
                    r.get("end_vpn"),
                    r.get("size_bytes"),
                    r.get("protection"),
                    r.get("tag"),
                    r.get("file_path"),
                    r.get("indicators"),
                    r.get("source_plugin"),
                ]
            )
        parts.append(
            _table(
                ["PID", "Process", "Start", "End", "Size", "Protection", "Type/tag", "Backing", "Indicators", "Plugin"],
                rows,
                empty="No memory regions.",
            )
        )
        parts.append("</section>")

    if "timeline" in sections:
        block = doc.get("timeline") or {}
        parts.append("<section id='timeline'><h2>8. Timeline</h2>")
        parts.append(_trunc_note(block, "event(s)"))
        parts.append(
            f"<p class='muted'>Observed shown: {esc(block.get('observed_count', 0))}; "
            f"inferred shown: {esc(block.get('inferred_count', 0))}. "
            "Timestamps appear only when present on the source event.</p>"
        )
        rows = []
        for e in (block.get("items") or [])[:HTML_MAX_ROWS]:
            rows.append(
                [
                    e.get("event_time") or "",
                    e.get("classification"),
                    e.get("event_kind"),
                    e.get("summary"),
                    e.get("pid"),
                    e.get("source_plugin"),
                ]
            )
        # Render classification with badges via special-case — keep escaped text in table.
        if rows:
            head = "".join(
                f"<th>{esc(h)}</th>"
                for h in ["Time", "Class", "Kind", "Summary", "PID", "Process", "Source"]
            )
            body = []
            for e in (block.get("items") or [])[:HTML_MAX_ROWS]:
                body.append(
                    "<tr>"
                    f"<td class='mono'>{esc(html_time(e.get('event_time') or ''))}</td>"
                    f"<td>{_cls_badge(e.get('classification'))}</td>"
                    f"<td class='mono'>{esc(e.get('event_kind'))}</td>"
                    f"<td>{esc(e.get('summary'))}</td>"
                    f"<td class='mono'>{esc(e.get('pid'))}</td>"
                    f"<td class='mono'>{esc(e.get('process_name'))}</td>"
                    f"<td class='mono'>{esc(e.get('source_plugin'))}</td>"
                    "</tr>"
                )
            parts.append(
                "<div class='table-wrap'>"
                f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"
                "</div>"
            )
        else:
            parts.append("<p class='muted'>No timeline events.</p>")
        parts.append("</section>")

    if "iocs" in sections:
        block = doc.get("iocs") or {}
        parts.append("<section id='iocs'><h2>9. IOCs</h2>")
        parts.append(_trunc_note(block, "IOC(s)"))
        by_type = block.get("by_type") or {}
        if by_type:
            parts.append(_table(["Type", "Count"], [[k, by_type[k]] for k in sorted(by_type)], empty=""))
        rows = []
        for i in (block.get("items") or [])[:HTML_MAX_ROWS]:
            rows.append(
                [
                    i.get("ioc_type"),
                    i.get("value"),
                    i.get("pid"),
                    i.get("process_name"),
                    i.get("source"),
                ]
            )
        parts.append(
            _table(["Type", "Value", "PID", "Process", "Source"], rows, empty="No IOCs.")
        )
        parts.append("</section>")

    if "artifacts" in sections:
        block = doc.get("artifacts") or {}
        parts.append("<section id='artifacts'><h2>10. Artifacts</h2>")
        parts.append(_trunc_note(block, "artifact(s)"))
        rows = []
        for a in (block.get("items") or [])[:HTML_MAX_ROWS]:
            rows.append(
                [
                    a.get("filename"),
                    a.get("sha256"),
                    a.get("size_bytes"),
                    a.get("file_type"),
                    a.get("extraction_method"),
                    a.get("pid"),
                    a.get("process_name"),
                    a.get("source_plugin"),
                    a.get("tool_name"),
                ]
            )
        parts.append(
            _table(
                ["Name", "SHA-256", "Size", "Type", "Extraction", "PID", "Process", "Plugin", "Tool"],
                rows,
                empty="No artifacts.",
            )
        )
        parts.append("</section>")

    if "malware" in sections:
        mal = doc.get("malware") or {}
        parts.append("<section id='malware'><h2>11. Malware-analysis results</h2>")
        parts.append(
            "<p class='muted'>Tool-produced observations are stored separately from Dumplyzer interpretation. "
            "No malware score is assigned. Optional providers may be absent.</p>"
        )
        ym = mal.get("yara_matches") or {}
        parts.append("<h3>YARA matches</h3>")
        parts.append(_trunc_note(ym, "match(es)"))
        yrows = []
        for m in (ym.get("items") or [])[:HTML_MAX_ROWS]:
            yrows.append(
                [
                    m.get("rule_name"),
                    m.get("namespace"),
                    m.get("pid"),
                    m.get("artifact_id"),
                    m.get("rule_source"),
                ]
            )
        parts.append(_table(["Rule", "Namespace", "PID", "Artifact", "Source"], yrows, empty="No YARA matches."))

        pe = mal.get("pe_extraction") or {}
        parts.append("<h3>PE Extraction</h3>")
        parts.append(f"<p class='muted'>{esc(pe.get('note'))}</p>")
        perows = []
        for item in (pe.get("items") or [])[:HTML_MAX_ROWS]:
            run = item.get("run") or {}
            perows.append(
                [
                    run.get("status"),
                    run.get("extracted_count"),
                    run.get("exe_count"),
                    run.get("dll_count"),
                    run.get("volatility_version"),
                    run.get("output_dir"),
                ]
            )
        parts.append(
            _table(
                ["Status", "Extracted", "EXE", "DLL", "Volatility", "Output"],
                perows,
                empty="No PE extraction runs.",
            )
        )

        capa = mal.get("capa") or {}
        parts.append("<h3>CAPA</h3>")
        parts.append(f"<p class='muted'>{esc(capa.get('note'))}</p>")
        caparows = []
        for item in (capa.get("items") or [])[:HTML_MAX_ROWS]:
            scan = item.get("scan") or {}
            caparows.append(
                [
                    scan.get("status"),
                    scan.get("pid"),
                    scan.get("capability_count"),
                    scan.get("capa_version"),
                    scan.get("artifact_id"),
                ]
            )
        parts.append(
            _table(
                ["Status", "PID", "Capabilities", "Version", "Artifact"],
                caparows,
                empty="No CAPA scans.",
            )
        )

        floss = mal.get("floss") or {}
        parts.append("<h3>FLOSS</h3>")
        parts.append(f"<p class='muted'>{esc(floss.get('note'))}</p>")
        flossrows = []
        for item in (floss.get("items") or [])[:HTML_MAX_ROWS]:
            scan = item.get("scan") or {}
            flossrows.append(
                [
                    scan.get("status"),
                    scan.get("pid"),
                    scan.get("string_count"),
                    scan.get("floss_version"),
                    scan.get("artifact_id"),
                ]
            )
        parts.append(
            _table(
                ["Status", "PID", "Strings", "Version", "Artifact"],
                flossrows,
                empty="No FLOSS scans.",
            )
        )

        be = mal.get("bulk_extractor") or {}
        parts.append("<h3>bulk_extractor</h3>")
        parts.append(f"<p class='muted'>{esc(be.get('note'))}</p>")
        berows = []
        for item in (be.get("items") or [])[:HTML_MAX_ROWS]:
            scan = item.get("scan") or {}
            cats = item.get("categories") or scan.get("categories") or []
            if isinstance(cats, list) and cats:
                count_s = ", ".join(
                    f"{c.get('label') or c.get('id')}={c.get('unique_count')}"
                    for c in cats
                    if isinstance(c, dict)
                )
            else:
                counts = scan.get("feature_counts") or {}
                count_s = (
                    ", ".join(f"{k}={counts[k]}" for k in sorted(counts)[:8])
                    if isinstance(counts, dict)
                    else ""
                )
            berows.append(
                [
                    scan.get("status"),
                    scan.get("bulk_extractor_version"),
                    scan.get("feature_file_count"),
                    scan.get("feature_count"),
                    count_s,
                    scan.get("output_dir"),
                ]
            )
        parts.append(
            _table(
                ["Status", "Version", "Feature files", "Unique values", "By type", "Output directory"],
                berows,
                empty="No bulk_extractor scans.",
            )
        )
        sample_priority = ("email", "telephone", "aes_keys", "ccn", "url", "domain", "winlnk")
        for item in (be.get("items") or [])[:1]:
            samples = item.get("samples") or {}
            if not isinstance(samples, dict):
                continue
            for cid in sample_priority:
                rows = samples.get(cid) or []
                if not rows:
                    continue
                label = cid.replace("_", " ")
                parts.append(f"<h4>{esc(label)}</h4>")
                srows = []
                for feat in rows[:HTML_MAX_ROWS]:
                    extra = feat.get("extra") if isinstance(feat.get("extra"), dict) else {}
                    note = extra.get("algorithm") or extra.get("path") or extra.get("note") or ""
                    srows.append(
                        [
                            feat.get("value"),
                            feat.get("count"),
                            feat.get("offset"),
                            note,
                        ]
                    )
                parts.append(
                    _table(
                        ["Value", "Count", "Offset", "Detail"],
                        srows,
                        empty=f"No {label}.",
                    )
                )
        parts.append("</section>")

    if "advanced" in sections:
        block = doc.get("advanced") or {}
        parts.append("<section id='advanced'><h2>12. Advanced Volatility executions</h2>")
        parts.append(_trunc_note(block, "execution(s)"))
        parts.append(
            "<p class='muted'>Raw TreeGrid plugin output is omitted from this HTML report. "
            "Use JSON export or Plugin Explorer for structured rows.</p>"
        )
        rows = []
        for e in (block.get("items") or [])[:HTML_MAX_ROWS]:
            summary = e.get("result_summary") or {}
            params = e.get("parameters") or {}
            param_s = ", ".join(f"{k}={params[k]}" for k in sorted(params)[:8]) if isinstance(params, dict) else ""
            rows.append(
                [
                    e.get("plugin"),
                    param_s,
                    e.get("status"),
                    "hit" if e.get("cache_hit") else "miss",
                    summary.get("row_count"),
                    summary.get("column_count"),
                    e.get("started_at"),
                    e.get("finished_at"),
                    (e.get("error") or {}).get("message") if isinstance(e.get("error"), dict) else e.get("error"),
                ]
            )
        parts.append(
            _table(
                ["Plugin", "Parameters", "Status", "Cache", "Rows", "Cols", "Started", "Finished", "Error"],
                rows,
                empty="No Advanced Volatility executions.",
            )
        )
        parts.append("</section>")

    parts.append("</main>")
    parts.append(
        "<footer>Dumplyzer forensic report · offline document · "
        f"{esc(doc.get('format'))} · provenance chain: evidence → analysis run → "
        "plugin execution → entity/artifact → finding/IOC/timeline. "
        "Do not execute artifacts or this HTML as a program.</footer>"
    )
    parts.append(f"<script>{_JS}</script>")
    parts.append("</body></html>")
    return "\n".join(parts)


def write_html_file(path: Path, doc: dict[str, Any]) -> int:
    path.write_text(render_html(doc), encoding="utf-8", newline="\n")
    return path.stat().st_size
