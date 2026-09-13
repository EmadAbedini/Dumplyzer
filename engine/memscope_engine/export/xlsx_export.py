"""Deterministic Office Open XML (.xlsx) writers for tabular forensic datasets."""

from __future__ import annotations

import re
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from memscope_engine.export.csv_export import CSV_COLUMNS, csv_cell

_SSML = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_OD_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
_WS_REL = f"{_OD_REL}/worksheet"
_OD_DOC_REL = f"{_OD_REL}/officeDocument"
_SHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
_WB_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"

_EXCEL_MAX_CELL = 32767
_INVALID_SHEET = re.compile(r'[:\\/?*\[\]]')
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _col_letter(index: int) -> str:
    n = index
    letters = ""
    while n:
        n, rem = divmod(n - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _xml_cell_text(value: Any) -> str:
    text = _ILLEGAL_XML.sub("", csv_cell(value))
    if len(text) > _EXCEL_MAX_CELL:
        text = text[:_EXCEL_MAX_CELL]
    return text


def sheet_name(name: str, used: set[str]) -> str:
    cleaned = _INVALID_SHEET.sub("_", str(name or "")).strip("' ").strip() or "Sheet"
    cleaned = cleaned[:31]
    base = cleaned
    n = 1
    while cleaned.lower() in {item.lower() for item in used}:
        suffix = f"_{n}"
        cleaned = (base[: 31 - len(suffix)] + suffix)
        n += 1
    used.add(cleaned)
    return cleaned


def _t_element(text: str) -> str:
    space = ' xml:space="preserve"' if text[:1].isspace() or text[-1:].isspace() else ""
    return f"<t{space}>{escape(text)}</t>"


def _row_xml(row_idx: int, values: Sequence[Any]) -> str:
    cells: list[str] = []
    for col_idx, value in enumerate(values, start=1):
        ref = f"{_col_letter(col_idx)}{row_idx}"
        cells.append(
            f'<c r="{ref}" t="inlineStr"><is>{_t_element(_xml_cell_text(value))}</is></c>'
        )
    return f'<row r="{row_idx}">{"".join(cells)}</row>'


def _sheet_xml(
    columns: Sequence[str],
    rows: Sequence[Mapping[str, Any]],
    *,
    meta: dict[str, Any] | None,
    meta_keys: Sequence[str],
) -> str:
    body: list[str] = []
    r = 1
    if meta:
        for key in meta_keys:
            body.append(_row_xml(r, [key, meta.get(key)]))
            r += 1
        body.append(_row_xml(r, [""]))
        r += 1
    body.append(_row_xml(r, list(columns)))
    r += 1
    for row in rows:
        body.append(_row_xml(r, [row.get(col) for col in columns]))
        r += 1
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{_SSML}">'
        f'<sheetData>{"".join(body)}</sheetData>'
        "</worksheet>"
    )


def write_xlsx_workbook(
    path: Path,
    sheets: Sequence[tuple[str, Sequence[str], Sequence[Mapping[str, Any]]]],
    *,
    meta: dict[str, Any] | None = None,
) -> int:
    from memscope_engine.export.shape import EXPORT_META_KEYS

    prepared = list(sheets) or [("Sheet1", ("value",), [])]
    used: set[str] = set()
    named: list[tuple[str, Sequence[str], Sequence[Mapping[str, Any]]]] = []
    for name, columns, rows in prepared:
        named.append((sheet_name(name, used), columns, rows))

    overrides = [
        f'<Override PartName="/xl/workbook.xml" ContentType="{_WB_TYPE}"/>'
    ]
    wb_rels: list[str] = []
    sheet_tags: list[str] = []
    worksheet_parts: list[tuple[str, str]] = []
    for i, (name, columns, rows) in enumerate(named, start=1):
        rid = f"rId{i}"
        part = f"xl/worksheets/sheet{i}.xml"
        overrides.append(f'<Override PartName="/{part}" ContentType="{_SHEET_TYPE}"/>')
        wb_rels.append(
            f'<Relationship Id="{rid}" Type="{_WS_REL}" Target="worksheets/sheet{i}.xml"/>'
        )
        attr_name = escape(name, {'"': "&quot;"})
        sheet_tags.append(
            f'<sheet name="{attr_name}" sheetId="{i}" r:id="{rid}"/>'
        )
        worksheet_parts.append(
            (part, _sheet_xml(columns, rows, meta=meta, meta_keys=EXPORT_META_KEYS))
        )

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Types xmlns="{_CT}">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f"{''.join(overrides)}"
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{_PKG_REL}">'
        f'<Relationship Id="rId1" Type="{_OD_DOC_REL}" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{_SSML}" xmlns:r="{_OD_REL}">'
        f'<sheets>{"".join(sheet_tags)}</sheets>'
        "</workbook>"
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{_PKG_REL}">'
        f"{''.join(wb_rels)}"
        "</Relationships>"
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types.encode("utf-8"))
        zf.writestr("_rels/.rels", root_rels.encode("utf-8"))
        zf.writestr("xl/workbook.xml", workbook.encode("utf-8"))
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels.encode("utf-8"))
        for part, xml in worksheet_parts:
            zf.writestr(part, xml.encode("utf-8"))
    return path.stat().st_size


def write_xlsx_file(
    path: Path,
    dataset: str,
    rows: list[dict[str, Any]],
    *,
    meta: dict[str, Any] | None = None,
) -> int:
    return write_xlsx_workbook(path, [(dataset, CSV_COLUMNS[dataset], rows)], meta=meta)
