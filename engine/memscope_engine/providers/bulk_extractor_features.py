"""Catalog, enrichment, and unique aggregation for bulk_extractor feature files.

bulk_extractor writes one feature file per scanner. Dumplyzer keeps the high-value
scanners (email, telephone, AES keys, LNK, …) even when noisy files such as
url.txt / domain.txt would otherwise exhaust the ingest cap.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

MAX_SCAN_ROWS_HIGH = 80_000
MAX_SCAN_ROWS_NOISY = 40_000
MAX_CONTEXT_CHARS = 400
MAX_VALUE_CHARS = 2_000
MAX_JSON_CHARS = 500

_EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,24}", re.IGNORECASE)
_AES_HEX_RE = re.compile(r"^[0-9a-fA-F ]+$")
_DIGITS_RE = re.compile(r"\D+")


@dataclass(frozen=True)
class FeatureKind:
    scanner: str
    ioc_type: str
    finding_type: str
    category: str
    label: str
    description: str
    unique_limit: int
    ioc_quota: int
    priority: int
    noisy: bool = False
    columns: tuple[str, ...] = ("Value", "Count", "Offset", "Context")


# Lower priority number is ingested first so useful scanners are not starved.
FEATURE_CATALOG: tuple[FeatureKind, ...] = (
    FeatureKind(
        "email", "email", "email", "email", "Email",
        "Email addresses carved from the memory image.",
        3_000, 1_500, 10,
    ),
    FeatureKind(
        "telephone", "telephone", "telephone", "telephone", "Phone",
        "Telephone numbers carved from the memory image.",
        1_000, 500, 20,
    ),
    FeatureKind(
        "aes_keys", "crypto", "aes_key_candidate", "aes_keys", "AES keys",
        "AES-128/AES-256 key schedules found in memory. Test patterns are flagged.",
        1_000, 400, 30,
        columns=("Algorithm", "Key", "Count", "Offset", "Note"),
    ),
    FeatureKind(
        "aes", "crypto", "aes_key_candidate", "aes_keys", "AES keys",
        "AES-128/AES-256 key schedules found in memory. Test patterns are flagged.",
        1_000, 400, 31,
        columns=("Algorithm", "Key", "Count", "Offset", "Note"),
    ),
    FeatureKind(
        "ccn", "ccn", "credit_card_candidate", "ccn", "Credit cards",
        "Credit-card number candidates (Luhn-checked by bulk_extractor).",
        400, 200, 40,
    ),
    FeatureKind(
        "ccn_track2", "ccn", "credit_card_track2_candidate", "ccn", "Credit cards",
        "Magnetic-stripe track-2 credit-card candidates.",
        200, 100, 41,
    ),
    FeatureKind(
        "rfc822", "email", "email_header", "rfc822", "Email headers",
        "RFC-822 / HTTP header-like strings (Host, Cookie, Subject, …).",
        1_500, 400, 50,
    ),
    FeatureKind(
        "httplogs", "url", "http", "httplogs", "HTTP logs",
        "HTTP request/response log lines recovered from memory.",
        2_000, 400, 60,
    ),
    FeatureKind(
        "httpheaders", "url", "http", "httplogs", "HTTP logs",
        "HTTP header strings recovered from memory.",
        1_000, 200, 61,
    ),
    FeatureKind(
        "ether", "mac", "ethernet", "ether", "MAC addresses",
        "Ethernet / MAC addresses.",
        1_000, 400, 70,
    ),
    FeatureKind(
        "ip", "ip", "ip", "ip", "IP addresses",
        "IPv4/IPv6 addresses found by bulk_extractor.",
        1_000, 400, 80,
    ),
    FeatureKind(
        "tcp", "network", "tcp", "tcp", "TCP",
        "TCP-related strings and tuples.",
        800, 200, 90,
    ),
    FeatureKind(
        "url", "url", "url", "url", "URLs",
        "URLs carved from the memory image. High volume; unique values are capped.",
        2_500, 800, 100, noisy=True,
    ),
    FeatureKind(
        "url_searches", "url", "url_search", "url", "URLs",
        "Search-engine query URLs.",
        800, 200, 101, noisy=True,
    ),
    FeatureKind(
        "url_services", "url", "url", "url", "URLs",
        "Service URLs.",
        800, 200, 102, noisy=True,
    ),
    FeatureKind(
        "domain", "domain", "domain", "domain", "Domains",
        "Domain names carved from the memory image. High volume; unique values are capped.",
        2_500, 800, 110, noisy=True,
    ),
    FeatureKind(
        "winlnk", "shortcut", "windows_lnk", "winlnk", "Shortcuts",
        "Windows .lnk shortcut metadata (paths, shares, timestamps).",
        1_500, 400, 120,
        columns=("Path", "Network", "Opened", "Created", "Count"),
    ),
    FeatureKind(
        "json", "json", "json", "json", "JSON",
        "JSON objects recovered from memory.",
        1_200, 200, 130, noisy=True,
        columns=("JSON", "Count", "Offset"),
    ),
    FeatureKind(
        "windirs", "filename", "windows_file", "windirs", "Windows files",
        "Filenames from Windows directory / MFT structures in memory.",
        2_000, 300, 140, noisy=True,
        columns=("Filename", "Size", "Modified", "Count"),
    ),
    FeatureKind(
        "sqlite_carved", "sqlite", "sqlite_carved", "sqlite", "SQLite",
        "SQLite databases carved from the memory image.",
        400, 150, 150,
        columns=("File", "Size", "SHA-1", "Offset"),
    ),
    FeatureKind(
        "evtx_carved", "evtx", "evtx_carved", "evtx", "Event logs",
        "Windows EVTX records carved from the memory image.",
        800, 100, 160, noisy=True,
        columns=("File", "Size", "SHA-1", "Offset"),
    ),
    FeatureKind(
        "zip_carved", "archive", "zip_carved", "zip", "Archives",
        "ZIP archives carved from the memory image.",
        400, 100, 170,
        columns=("File", "Size", "SHA-1", "Offset"),
    ),
    FeatureKind(
        "winpe", "pe", "winpe", "winpe", "PE headers",
        "PE headers found in memory (not reconstructed files).",
        800, 100, 180, noisy=True,
        columns=("SHA-1", "Machine", "Compiled", "Kind", "Count"),
    ),
    FeatureKind(
        "winpe_carved", "pe", "winpe_carved", "winpe", "PE headers",
        "PE files carved from the memory image.",
        400, 80, 181,
        columns=("File", "Size", "SHA-1", "Offset"),
    ),
    FeatureKind(
        "jpeg", "image", "jpeg", "jpeg", "Images",
        "JPEG images found in the memory image.",
        400, 80, 190,
        columns=("File", "Size", "SHA-1", "Offset"),
    ),
    FeatureKind(
        "exif", "image", "exif", "jpeg", "Images",
        "EXIF metadata from embedded images.",
        400, 80, 191,
    ),
    FeatureKind(
        "gps", "gps", "gps", "gps", "GPS",
        "GPS coordinates.",
        200, 80, 200,
    ),
    FeatureKind(
        "elf", "elf", "elf", "elf", "ELF",
        "ELF headers found in memory.",
        200, 50, 210,
    ),
)

FEATURE_KIND_MAP: dict[str, tuple[str, str]] = {
    item.scanner: (item.ioc_type, item.finding_type) for item in FEATURE_CATALOG
}
_KIND_BY_SCANNER: dict[str, FeatureKind] = {item.scanner: item for item in FEATURE_CATALOG}

_SKIP_FEATURE_SUFFIXES = ("_histogram.txt", "_stopped.txt")
_SKIP_NAMES = frozenset(
    {
        "alerts.txt",
        "report.xml",
        "dumplyzer-stdout.txt",
        "dumplyzer-stderr.txt",
        "duplicates.txt",
        "find.txt",
        "bulk_extractor.log",
    }
)
# Disk-forensic NTFS internals are huge and overlap windirs; skip as features.
_SKIP_SCANNERS = frozenset(
    {
        "ntfsmft_carved",
        "ntfsindx_carved",
        "ntfsusn_carved",
        "ntfslogfile_carved",
        "utmp_carved",
        "kml_carved",
        "unrar_carved",
        "rtti",
        "facebook",
        "pii",
        "vin",
        "wifi",
        "vcard",
        "sin",
        "winprefetch",
        "rar",
    }
)

CATEGORY_ORDER = (
    "email",
    "telephone",
    "aes_keys",
    "ccn",
    "url",
    "domain",
    "httplogs",
    "ether",
    "ip",
    "tcp",
    "rfc822",
    "winlnk",
    "json",
    "windirs",
    "sqlite",
    "evtx",
    "zip",
    "winpe",
    "jpeg",
    "gps",
    "elf",
    "other",
)

CATEGORY_META: dict[str, dict[str, str]] = {
    "email": {"label": "Email", "description": "Email addresses carved from memory."},
    "telephone": {"label": "Phone", "description": "Telephone numbers carved from memory."},
    "aes_keys": {
        "label": "AES keys",
        "description": "AES key schedules. Hide test keys to focus on unusual material.",
    },
    "ccn": {"label": "Credit cards", "description": "Credit-card number candidates."},
    "url": {"label": "URLs", "description": "URLs. High volume; showing unique values."},
    "domain": {"label": "Domains", "description": "Domain names. High volume; showing unique values."},
    "httplogs": {"label": "HTTP logs", "description": "HTTP log lines recovered from memory."},
    "ether": {"label": "MAC addresses", "description": "Ethernet / MAC addresses."},
    "ip": {"label": "IP addresses", "description": "IP addresses found by bulk_extractor."},
    "tcp": {"label": "TCP", "description": "TCP-related strings."},
    "rfc822": {"label": "Email headers", "description": "Host / Cookie / Subject-style headers."},
    "winlnk": {"label": "Shortcuts", "description": "Windows shortcut paths, shares, and times."},
    "json": {"label": "JSON", "description": "JSON objects recovered from memory."},
    "windirs": {"label": "Windows files", "description": "Filenames from directory / MFT structures."},
    "sqlite": {"label": "SQLite", "description": "Carved SQLite databases."},
    "evtx": {"label": "Event logs", "description": "Carved Windows event log records."},
    "zip": {"label": "Archives", "description": "Carved ZIP archives."},
    "winpe": {"label": "PE headers", "description": "PE headers found in memory."},
    "jpeg": {"label": "Images", "description": "JPEG / EXIF artifacts."},
    "gps": {"label": "GPS", "description": "GPS coordinates."},
    "elf": {"label": "ELF", "description": "ELF headers."},
    "other": {"label": "Other", "description": "Additional bulk_extractor feature files."},
}


def kind_for_scanner(scanner: str) -> FeatureKind:
    key = (scanner or "").lower()
    if key in _KIND_BY_SCANNER:
        return _KIND_BY_SCANNER[key]
    return FeatureKind(
        scanner=key or "feature",
        ioc_type=key or "feature",
        finding_type=key or "feature",
        category="other",
        label=key.replace("_", " ").strip() or "Other",
        description="Additional bulk_extractor feature file.",
        unique_limit=400,
        ioc_quota=80,
        priority=900,
        noisy=True,
    )


def feature_kind_for_stem(stem: str) -> tuple[str, str]:
    kind = kind_for_scanner(stem)
    return (kind.ioc_type, kind.finding_type)


def is_feature_filename(name: str) -> bool:
    lower = name.lower()
    if lower in _SKIP_NAMES:
        return False
    if not lower.endswith(".txt"):
        return False
    if any(lower.endswith(suf) for suf in _SKIP_FEATURE_SUFFIXES):
        return False
    stem = Path(lower).stem
    if stem in _SKIP_SCANNERS:
        return False
    return True


def parse_feature_line(line: str) -> dict[str, str] | None:
    stripped = line.strip("\n")
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split("\t")
    if len(parts) < 2:
        return None
    offset, feature = parts[0].strip(), parts[1]
    context = parts[2] if len(parts) > 2 else ""
    if not feature:
        return None
    return {"offset": offset, "feature": feature, "context": context}


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _unescape_be(text: str) -> str:
    return (
        text.replace("\\134", "\\")
        .replace("\\015", "\r")
        .replace("\\012", "\n")
        .replace("\\011", "\t")
        .replace("\\000", "")
    )


def _xml_local(tag: str) -> str:
    return tag.split("}")[-1].lower()


def _xml_texts(blob: str) -> dict[str, str]:
    text = (blob or "").strip()
    if not text.startswith("<"):
        return {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        wrapped = f"<root>{text}</root>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            return {}
    found: dict[str, str] = {}
    for el in root.iter():
        key = _xml_local(el.tag)
        if el.text and el.text.strip() and key not in found:
            found[key] = el.text.strip()
    return found


def _aes_is_weak(compact_hex: str) -> bool:
    if not compact_hex:
        return True
    if set(compact_hex) <= {"0"}:
        return True
    if set(compact_hex) <= {"f"}:
        return True
    sequential = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    if compact_hex == sequential[: len(compact_hex)]:
        return True
    return False


def _enrich_aes(row: dict[str, str]) -> dict[str, Any] | None:
    raw = (row.get("feature") or "").strip()
    if not raw or not _AES_HEX_RE.match(raw):
        return None
    compact = raw.replace(" ", "").lower()
    if len(compact) not in {32, 64}:
        return None
    alg = (row.get("context") or "").strip() or ("AES128" if len(compact) == 32 else "AES256")
    weak = _aes_is_weak(compact)
    return {
        "key": compact,
        "value": raw,
        "extra": {
            "algorithm": alg,
            "weak": weak,
            "bits": 128 if len(compact) == 32 else 256,
            "note": "test/weak pattern" if weak else None,
        },
    }


def _enrich_email(row: dict[str, str]) -> dict[str, Any] | None:
    raw = (row.get("feature") or "").strip()
    match = _EMAIL_RE.search(raw)
    if not match:
        return None
    addr = match.group(0)
    return {"key": addr.lower(), "value": addr, "extra": {"raw": raw if raw != addr else None}}


def _enrich_telephone(row: dict[str, str]) -> dict[str, Any] | None:
    raw = (row.get("feature") or "").strip()
    if not raw or "DSN:" in raw.upper():
        return None
    if raw.count(".") >= 2 or "/" in raw:
        return None
    digits = _DIGITS_RE.sub("", raw)
    if len(digits) < 7 or len(digits) > 15:
        return None
    if len(set(digits)) == 1:
        return None
    if digits in {"01234567890", "0123456789", "1234567890", "01234567894"}:
        return None
    return {"key": digits, "value": raw, "extra": {"digits": digits}}


def _enrich_winlnk(row: dict[str, str]) -> dict[str, Any] | None:
    blob = row.get("context") or row.get("feature") or ""
    fields = _xml_texts(_unescape_be(blob))
    path = (
        fields.get("local_base_path_unicode")
        or fields.get("local_base_path")
        or fields.get("common_path_suffix_unicode")
        or fields.get("common_path_suffix")
        or ""
    )
    path = _unescape_be(path)
    net = _unescape_be(fields.get("net_name") or "")
    volume = _unescape_be(fields.get("volume_label") or fields.get("device_name") or "")
    if not path and not net:
        return None
    display = path or net
    return {
        "key": f"{path.lower()}|{net.lower()}",
        "value": display,
        "extra": {
            "path": path or None,
            "net_name": net or None,
            "volume": volume or None,
            "atime": fields.get("atime"),
            "ctime": fields.get("ctime"),
            "wtime": fields.get("wtime"),
        },
    }


def _enrich_fileobject(row: dict[str, str]) -> dict[str, Any] | None:
    blob = row.get("context") or ""
    fields = _xml_texts(blob)
    name = fields.get("filename") or (row.get("feature") or "").strip()
    if not name:
        return None
    size_s = fields.get("filesize") or ""
    try:
        size = int(size_s) if size_s else None
    except ValueError:
        size = None
    sha1 = fields.get("hashdigest") or ""
    return {
        "key": (sha1 or name).lower(),
        "value": name,
        "extra": {"filename": name, "size_bytes": size, "sha1": sha1 or None},
    }


def _enrich_windirs(row: dict[str, str]) -> dict[str, Any] | None:
    name = (row.get("feature") or "").strip()
    fields = _xml_texts(row.get("context") or "")
    name = fields.get("filename") or name
    if not name:
        return None
    size_s = fields.get("filesize") or ""
    try:
        size = int(size_s) if size_s else None
    except ValueError:
        size = None
    return {
        "key": name.lower(),
        "value": name,
        "extra": {
            "filename": name,
            "size_bytes": size,
            "mtime": fields.get("mtime_si") or fields.get("mtime_fn"),
            "atime": fields.get("atime_si") or fields.get("atime_fn"),
            "ctime": fields.get("ctime_si") or fields.get("ctime_fn"),
        },
    }


def _enrich_winpe(row: dict[str, str]) -> dict[str, Any] | None:
    digest = (row.get("feature") or "").strip()
    blob = row.get("context") or ""
    machine = ""
    compiled = ""
    kind = "PE"
    try:
        root = ET.fromstring(blob) if blob.strip().startswith("<") else None
    except ET.ParseError:
        root = None
    if root is not None:
        header = None
        optional = None
        for el in root.iter():
            tag = _xml_local(el.tag)
            if tag == "fileheader" and header is None:
                header = el
            elif tag == "optionalheaderstandard" and optional is None:
                optional = el
        if header is not None:
            machine = header.attrib.get("Machine") or ""
            compiled = header.attrib.get("TimeDateStampISO") or ""
            chars = " ".join(_xml_local(c.tag) for c in header.findall(".//*"))
            if "image_file_dll" in chars.lower() or "IMAGE_FILE_DLL" in "".join(
                _xml_local(c.tag).upper() for c in header.iter()
            ):
                kind = "DLL"
            else:
                kind = "EXE"
            for el in header.iter():
                if _xml_local(el.tag) == "image_file_dll":
                    kind = "DLL"
                    break
        if optional is not None:
            magic = optional.attrib.get("Magic") or ""
            if magic:
                kind = f"{kind} {magic}".strip()
    display = digest or "PE"
    return {
        "key": digest.lower() or display.lower(),
        "value": display,
        "extra": {
            "sha1": digest or None,
            "machine": machine.replace("IMAGE_FILE_MACHINE_", "") or None,
            "compiled": compiled or None,
            "kind": kind,
        },
    }


def _enrich_json(row: dict[str, str]) -> dict[str, Any] | None:
    raw = (row.get("feature") or "").strip()
    if not raw:
        return None
    digest = (row.get("context") or "").strip()
    return {
        "key": (digest or raw)[:200].lower(),
        "value": _clip(raw, MAX_JSON_CHARS),
        "extra": {"sha1": digest or None, "full_length": len(raw)},
    }


def _enrich_generic(row: dict[str, str]) -> dict[str, Any] | None:
    value = (row.get("feature") or "").strip()
    if not value:
        return None
    return {"key": value.lower()[:500], "value": _clip(_unescape_be(value), MAX_VALUE_CHARS)}


_ENRICHERS: dict[str, Callable[[dict[str, str]], dict[str, Any] | None]] = {
    "aes_keys": _enrich_aes,
    "aes": _enrich_aes,
    "email": _enrich_email,
    "telephone": _enrich_telephone,
    "winlnk": _enrich_winlnk,
    "sqlite_carved": _enrich_fileobject,
    "evtx_carved": _enrich_fileobject,
    "zip_carved": _enrich_fileobject,
    "winpe_carved": _enrich_fileobject,
    "jpeg": _enrich_fileobject,
    "windirs": _enrich_windirs,
    "winpe": _enrich_winpe,
    "json": _enrich_json,
}


def aggregate_feature_file(
    path: Path,
    *,
    scanner: str,
    unique_limit: int | None = None,
    noisy: bool = False,
) -> dict[str, Any]:
    kind = kind_for_scanner(scanner)
    limit = unique_limit if unique_limit is not None else kind.unique_limit
    max_scan = MAX_SCAN_ROWS_NOISY if (noisy or kind.noisy) else MAX_SCAN_ROWS_HIGH
    enrich = _ENRICHERS.get(kind.scanner, _enrich_generic)
    buckets: dict[str, dict[str, Any]] = {}
    row_count = 0
    dropped = 0
    truncated_scan = False
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parsed = parse_feature_line(line)
                if parsed is None:
                    continue
                row_count += 1
                if row_count > max_scan:
                    truncated_scan = True
                    break
                enriched = enrich(parsed)
                if not enriched:
                    dropped += 1
                    continue
                key = str(enriched.get("key") or "")
                if not key:
                    dropped += 1
                    continue
                existing = buckets.get(key)
                if existing is None:
                    buckets[key] = {
                        "value": str(enriched.get("value") or parsed["feature"]),
                        "offset": parsed["offset"],
                        "context": _clip(_unescape_be(parsed.get("context") or ""), MAX_CONTEXT_CHARS),
                        "count": 1,
                        "extra": enriched.get("extra") or {},
                    }
                else:
                    existing["count"] = int(existing.get("count") or 1) + 1
    except OSError:
        return {
            "items": [],
            "row_count": 0,
            "unique_total": 0,
            "unique_kept": 0,
            "dropped": 0,
            "truncated": False,
        }

    ranked = sorted(
        buckets.values(),
        key=lambda item: (-int(item.get("count") or 0), str(item.get("value") or "")),
    )
    kept = ranked[: max(0, limit)]
    return {
        "items": kept,
        "row_count": row_count,
        "unique_total": len(buckets),
        "unique_kept": len(kept),
        "dropped": dropped,
        "truncated": truncated_scan or len(buckets) > limit,
    }


def category_summary(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for group in groups:
        cid = str(group.get("category") or "other")
        meta = CATEGORY_META.get(cid) or {"label": cid.replace("_", " "), "description": ""}
        rec = by_id.setdefault(
            cid,
            {
                "id": cid,
                "label": meta["label"],
                "description": meta["description"],
                "unique_count": 0,
                "row_count": 0,
                "scanners": [],
                "columns": group.get("columns") or ("Value", "Count", "Offset", "Context"),
            },
        )
        rec["unique_count"] += int(group.get("unique_kept") or 0)
        rec["row_count"] += int(group.get("row_count") or 0)
        scanner = group.get("scanner")
        if scanner and scanner not in rec["scanners"]:
            rec["scanners"].append(scanner)
        if group.get("columns"):
            rec["columns"] = group["columns"]
    ordered = [by_id[cid] for cid in CATEGORY_ORDER if cid in by_id]
    extra = [by_id[cid] for cid in by_id if cid not in CATEGORY_ORDER]
    return [item for item in ordered + extra if int(item.get("unique_count") or 0) > 0]
