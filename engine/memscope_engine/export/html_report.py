"""Self-contained offline HTML forensic report. No CDN, no JavaScript."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from memscope_engine.export.constants import HTML_MAX_ROWS, REPORT_FORMAT, REPORT_SCHEMA_VERSION

_CSS = """
:root { color-scheme: dark light; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0;
  font-family: "Segoe UI", "Liberation Sans", system-ui, sans-serif;
  font-size: 13px; line-height: 1.45;
  background: #0e1116; color: #e6edf3;
}
@media (prefers-color-scheme: light) {
  body { background: #f4f1ea; color: #1b1f24; }
  header, nav, footer { background: #ebe6db; border-color: #cfc6b4; }
  table thead { background: #e3dccf; }
  tr:nth-child(even) { background: #efeae0; }
  .card, .note { background: #fffdf8; border-color: #cfc6b4; }
  .muted { color: #5c564c; }
  .obs { background: #d7ead8; color: #1b4d1f; }
  .inf { background: #f3e2c1; color: #6a4a12; }
  a { color: #1f4e79; }
}
header {
  padding: 20px 28px 16px; border-bottom: 1px solid #2b3340;
  background: #141a22;
}
h1 { margin: 0 0 4px; font-size: 20px; font-weight: 650; }
h2 { margin: 28px 0 10px; font-size: 16px; border-bottom: 1px solid #2b3340; padding-bottom: 6px; }
h3 { margin: 16px 0 8px; font-size: 13px; }
.meta { font-size: 12px; color: #9aa4b2; }
.muted { color: #9aa4b2; }
nav { padding: 10px 28px; border-bottom: 1px solid #2b3340; background: #141a22; font-size: 12px; }
nav a { color: #8cb4ff; text-decoration: none; margin-right: 12px; }
main { padding: 12px 28px 48px; }
.card {
  border: 1px solid #2b3340; background: #171e27; padding: 12px 14px; margin: 8px 0 16px; border-radius: 4px;
}
.note { border: 1px solid #3d4a22; background: #1b2314; padding: 8px 10px; margin: 8px 0 14px; font-size: 12px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 12px; }
th, td { border: 1px solid #2b3340; padding: 4px 8px; vertical-align: top; text-align: left; }
table thead { background: #1c2530; }
tr:nth-child(even) { background: #151c24; }
code, .mono { font-family: "Cascadia Code", "Consolas", monospace; font-size: 11px; word-break: break-all; }
.badge { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 3px; border: 1px solid #3d4a5c; }
.obs { background: #14301a; color: #9be09f; }
.inf { background: #3a2c12; color: #f0c674; }
.sev-high { color: #ff8a8a; }
.sev-medium { color: #f0c674; }
.sev-low { color: #9aa4b2; }
footer { padding: 16px 28px 28px; border-top: 1px solid #2b3340; font-size: 11px; color: #9aa4b2; }
""".strip()


def esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return esc(", ".join(str(v) for v in value))
    if isinstance(value, dict):
        return esc(str(value))
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
            "Remaining rows are in the JSON/CSV export, not embedded here.</span>"
        )
    return f"<p class='muted'>{esc(total)} {esc(noun)}.{extra}</p>"


def _table(headers: list[str], rows: list[list[Any]], *, empty: str) -> str:
    if not rows:
        return f"<p class='muted'>{esc(empty)}</p>"
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        tds = "".join(f"<td class='mono'>{_cell(c)}</td>" for c in row)
        body.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _cls_badge(classification: str | None) -> str:
    if classification == "inferred":
        return "<span class='badge inf'>inferred</span>"
    if classification == "observed":
        return "<span class='badge obs'>observed</span>"
    return esc(classification)


def _finding_rows(items: list[dict[str, Any]]) -> list[list[Any]]:
    rows = []
    for f in items[:HTML_MAX_ROWS]:
        rows.append(
            [
                f.get("title"),
                f.get("severity"),
                f.get("explanation"),
                f.get("plugin"),
                f.get("pid"),
                f.get("field_name"),
                f.get("field_value"),
            ]
        )
    return rows


def render_html(doc: dict[str, Any]) -> str:
    meta = doc.get("metadata") or {}
    sections = doc.get("sections_included") or []
    title = f"MemScope investigation report — {meta.get('evidence_filename') or meta.get('evidence_id') or 'evidence'}"
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
        f"<h1>{esc(title)}</h1>",
        f"<div class='meta'>Format {esc(REPORT_FORMAT)} · report schema v{esc(REPORT_SCHEMA_VERSION)} · "
        f"generated {esc(meta.get('generated_at') or doc.get('generated_at'))} · "
        f"MemScope {esc(meta.get('memscope_version') or doc.get('memscope_version'))}</div>",
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
            ["MemScope version", meta.get("memscope_version")],
            ["Generated at (UTC)", meta.get("generated_at")],
            ["Evidence id", meta.get("evidence_id")],
            ["Evidence filename", meta.get("evidence_filename")],
            ["Evidence SHA-256", meta.get("evidence_sha256")],
            ["Evidence size (bytes)", meta.get("evidence_size_bytes")],
            ["Evidence path", meta.get("evidence_path")],
            ["Detected OS", meta.get("detected_os")],
            ["Architecture", meta.get("architecture")],
            ["Symbol status", meta.get("symbol_status")],
            ["Import timestamp", meta.get("import_timestamp")],
            ["Volatility version", meta.get("volatility_version")],
            ["Analysis schema version", meta.get("analysis_schema_version")],
            ["Report schema version", meta.get("report_schema_version")],
        ]
        parts.append(_table(["Field", "Value"], rows, empty="No metadata."))
        ev_meta = meta.get("evidence_metadata") or {}
        if ev_meta:
            em_rows = [[k, ev_meta[k]] for k in sorted(ev_meta.keys())]
            parts.append("<h3>Evidence metadata</h3>")
            parts.append(_table(["Key", "Value"], em_rows, empty="None."))
        parts.append("</section>")

    if "summary" in sections:
        summary = doc.get("summary") or {}
        parts.append("<section id='summary'><h2>2. Executive summary</h2>")
        parts.append(f"<div class='card'>{esc(summary.get('text'))}</div>")
        counts = [
            ["Processes", summary.get("process_count")],
            ["Findings", summary.get("finding_count")],
            ["Network connections", summary.get("network_count")],
            ["Modules", summary.get("module_count")],
            ["Memory regions", summary.get("memory_region_count")],
            ["Timeline events", summary.get("timeline_event_count")],
            ["Artifacts", summary.get("artifact_count")],
            ["IOCs", summary.get("ioc_count")],
            ["YARA matches", summary.get("yara_match_count")],
            ["PE-sieve scans", summary.get("pe_sieve_scan_count")],
            ["mal_unpack scans", summary.get("mal_unpack_scan_count")],
            ["Advanced Volatility executions", summary.get("advanced_execution_count")],
        ]
        parts.append(_table(["Count", "Value"], counts, empty="No summary."))
        parts.append("<p class='muted'>No malware or risk score is generated.</p></section>")

    if "findings" in sections:
        block = doc.get("findings") or {}
        parts.append("<section id='findings'><h2>3. Findings</h2>")
        parts.append(_trunc_note(block, "finding(s)"))
        parts.append(
            _table(
                ["Title", "Severity", "Explanation", "Plugin", "PID", "Field", "Value"],
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
            parent = p.get("parent") or {}
            parent_s = ""
            if parent:
                parent_s = f"{parent.get('pid')} {parent.get('name') or ''}".strip()
            findings = p.get("relevant_findings") or []
            ftxt = "; ".join(
                f"{x.get('title')}:{x.get('severity')}" for x in findings[:5]
            )
            rows.append(
                [
                    p.get("pid"),
                    p.get("name"),
                    p.get("image_path"),
                    p.get("command_line"),
                    parent_s,
                    ",".join(str(c) for c in (p.get("child_pids") or [])),
                    p.get("source_plugin"),
                    ftxt,
                ]
            )
        parts.append(
            _table(
                ["PID", "Name", "Executable", "Command line", "Parent", "Children", "Plugin", "Findings"],
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
                    n.get("protocol"),
                    n.get("local_address"),
                    n.get("local_port"),
                    n.get("remote_address"),
                    n.get("remote_port"),
                    n.get("state"),
                    n.get("source_plugin"),
                ]
            )
        parts.append(
            _table(
                ["PID", "Protocol", "Local", "LPort", "Remote", "RPort", "State", "Plugin"],
                rows,
                empty="No network connections.",
            )
        )
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
                    m.get("name"),
                    m.get("path"),
                    m.get("base_address"),
                    m.get("size"),
                    m.get("source_plugin"),
                ]
            )
        parts.append(
            _table(
                ["PID", "Name", "Path", "Base", "Size", "Plugin"],
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
            inds = r.get("indicators") or []
            codes = []
            if isinstance(inds, list):
                for i in inds:
                    if isinstance(i, dict):
                        codes.append(str(i.get("code") or ""))
                    else:
                        codes.append(str(i))
            rows.append(
                [
                    r.get("pid"),
                    r.get("start_vpn"),
                    r.get("end_vpn"),
                    r.get("size_bytes"),
                    r.get("protection"),
                    r.get("tag"),
                    r.get("file_path"),
                    ", ".join(c for c in codes if c),
                    r.get("source_plugin"),
                ]
            )
        parts.append(
            _table(
                ["PID", "Start", "End", "Size", "Protection", "Type/tag", "Backing", "Indicators", "Plugin"],
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
                for h in ["Time", "Class", "Kind", "Summary", "PID", "Source"]
            )
            body = []
            for e in (block.get("items") or [])[:HTML_MAX_ROWS]:
                body.append(
                    "<tr>"
                    f"<td class='mono'>{esc(e.get('event_time') or '')}</td>"
                    f"<td>{_cls_badge(e.get('classification'))}</td>"
                    f"<td class='mono'>{esc(e.get('event_kind'))}</td>"
                    f"<td>{esc(e.get('summary'))}</td>"
                    f"<td class='mono'>{esc(e.get('pid'))}</td>"
                    f"<td class='mono'>{esc(e.get('source_plugin'))}</td>"
                    "</tr>"
                )
            parts.append(f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>")
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
                    i.get("context"),
                    i.get("source"),
                ]
            )
        parts.append(
            _table(["Type", "Value", "PID", "Context", "Source"], rows, empty="No IOCs.")
        )
        parts.append("</section>")

    if "artifacts" in sections:
        block = doc.get("artifacts") or {}
        parts.append("<section id='artifacts'><h2>10. Artifacts</h2>")
        parts.append(_trunc_note(block, "artifact(s)"))
        rows = []
        for a in (block.get("items") or [])[:HTML_MAX_ROWS]:
            prov = a.get("provenance") or {}
            rows.append(
                [
                    a.get("filename"),
                    a.get("sha256"),
                    a.get("size_bytes"),
                    a.get("file_type"),
                    a.get("extraction_method"),
                    a.get("pid"),
                    prov.get("memory_region_id") or a.get("memory_region_id"),
                    a.get("source_plugin"),
                    a.get("tool_name"),
                ]
            )
        parts.append(
            _table(
                ["Name", "SHA-256", "Size", "Type", "Extraction", "PID", "Region", "Plugin", "Tool"],
                rows,
                empty="No artifacts.",
            )
        )
        parts.append("</section>")

    if "malware" in sections:
        mal = doc.get("malware") or {}
        parts.append("<section id='malware'><h2>11. Malware-analysis results</h2>")
        parts.append(
            "<p class='muted'>Tool-produced observations are stored separately from MemScope interpretation. "
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

        pe = mal.get("pe_sieve") or {}
        parts.append("<h3>PE-sieve</h3>")
        parts.append(f"<p class='muted'>{esc(pe.get('note'))}</p>")
        perows = []
        for item in (pe.get("items") or [])[:HTML_MAX_ROWS]:
            scan = item.get("scan") or {}
            observed = scan.get("observed") or {}
            interp = scan.get("interpretation") or {}
            perows.append(
                [
                    scan.get("status"),
                    scan.get("pid"),
                    scan.get("pesieve_result"),
                    scan.get("pe_sieve_version"),
                    "observed" if observed else "",
                    "interpretation" if interp else "",
                ]
            )
        parts.append(
            _table(
                ["Status", "PID", "Tool result", "Version", "Has observed", "Has interpretation"],
                perows,
                empty="No PE-sieve scans.",
            )
        )

        mu = mal.get("mal_unpack") or {}
        parts.append("<h3>mal_unpack</h3>")
        parts.append(f"<p class='muted'>{esc(mu.get('note'))}</p>")
        murows = []
        for item in (mu.get("items") or [])[:HTML_MAX_ROWS]:
            scan = item.get("scan") or {}
            murows.append(
                [
                    scan.get("status"),
                    scan.get("pid"),
                    scan.get("unpack_result"),
                    scan.get("invoked"),
                    scan.get("mal_unpack_version"),
                    "yes" if scan.get("observed") else "",
                    "yes" if scan.get("interpretation") else "",
                ]
            )
        parts.append(
            _table(
                ["Status", "PID", "Tool result", "Invoked", "Version", "Observed", "Interpretation"],
                murows,
                empty="No mal_unpack scans.",
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
        "<footer>MemScope forensic report · offline document · "
        f"{esc(doc.get('format'))} · provenance chain: evidence → analysis run → "
        "plugin execution → entity/artifact → finding/IOC/timeline. "
        "Do not execute artifacts or this HTML as a program.</footer>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


def write_html_file(path: Path, doc: dict[str, Any]) -> int:
    path.write_text(render_html(doc), encoding="utf-8", newline="\n")
    return path.stat().st_size
