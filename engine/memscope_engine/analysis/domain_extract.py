"""Extract hostnames using the Public Suffix List plus source context.

A TLD-allowlist regex misses ``.xyz`` / ``.app`` / ``.co.uk``. A naive
``anything.anything`` matcher floods IOCs with ``jquery.js`` and path
segments. This module:

1. Pulls URL hosts and dotted candidates from text.
2. Requires a PSL-listed suffix and a registrable (eTLD+1) name.
3. Scores the hit by where it was found (network/URL vs filesystem path).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable
from urllib.parse import urlsplit

from memscope_engine.analysis.public_suffix import PublicSuffixList, default_public_suffix_list

_RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_CANDIDATE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-zA-Z]{2,63})\b",
    re.IGNORECASE,
)
_RE_UNC_HOST = re.compile(
    r"(?:\\\\|//)([^\\/\s\"']+)",
    re.IGNORECASE,
)

# Last labels that are also common file extensions. Rejected in path-like
# context even though several (js, zip, app, dev, com) are real TLDs.
_FILEISH_SUFFIXES = frozenset(
    {
        "js",
        "ts",
        "jsx",
        "tsx",
        "mjs",
        "cjs",
        "py",
        "rb",
        "go",
        "rs",
        "zip",
        "gz",
        "xz",
        "7z",
        "rar",
        "tgz",
        "iso",
        "app",
        "dev",
        "so",
        "dll",
        "exe",
        "sys",
        "drv",
        "msi",
        "cab",
        "apk",
        "jar",
        "war",
        "ear",
        "com",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "wsf",
        "html",
        "htm",
        "css",
        "json",
        "xml",
        "txt",
        "log",
        "cfg",
        "ini",
        "dat",
        "bin",
        "tmp",
        "bak",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "mp3",
        "mp4",
        "mov",
        "avi",
        "mkv",
        "wav",
    }
)

_SKIP_REGISTRABLE = frozenset(
    {
        "microsoft.com",
        "windows.com",
        "www.microsoft.com",
        "windowsupdate.com",
        "localhost.localdomain",
    }
)

# Hostnames that are almost always OS noise when they appear as a domain IOC.
_SKIP_HOSTS = frozenset({"wpad", "localhost", "local"})

_NETWORK_SOURCES = frozenset(
    {
        "network_connections",
        "network.remote_address",
        "network.local_address",
        "network_artifacts",
    }
)
_PATH_SOURCES = frozenset(
    {
        "processes.image_path",
        "modules.path",
        "handle_entries",
    }
)
_CMDLINE_SOURCES = frozenset({"processes.command_line"})
_FLOSS_SOURCES = frozenset({"floss_strings"})


def _is_ip(value: str) -> bool:
    text = value.strip().strip("[]")
    if "%" in text:
        text = text.split("%", 1)[0]
    if ":" in text and text.rsplit(":", 1)[-1].isdigit() and text.count(":") == 1:
        text = text.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _strip_host(value: str) -> str:
    text = (value or "").strip().strip("[]").rstrip(".")
    if not text:
        return ""
    if text.startswith("*."):
        text = text[2:]
    if "%" in text:
        text = text.split("%", 1)[0]
    if ":" in text and not text.startswith("xn--") and text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = host
    return text.strip().lower()


def _path_like(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 3) : start]
    after = text[end : min(len(text), end + 2)]
    if before.endswith("://"):
        return False
    if before.endswith("\\\\") or before.endswith("//"):
        return False
    if "\\" in before or before.endswith("/") or before.endswith(":"):
        return True
    if after.startswith("\\") or after.startswith("/"):
        return True
    return False


def _fileish(host: str) -> bool:
    label = host.rsplit(".", 1)[-1].lower()
    return label in _FILEISH_SUFFIXES


def _confidence(
    source: str,
    *,
    host: str,
    path_like: bool,
    fileish: bool,
    from_url: bool,
    unc: bool,
) -> float:
    labels = host.count(".") + 1
    if from_url or unc:
        return 0.95
    if source in _NETWORK_SOURCES:
        return 0.95
    if fileish and labels < 3:
        return 0.15
    if source in _CMDLINE_SOURCES:
        if path_like and fileish:
            return 0.15
        if path_like:
            return 0.35
        return 0.7
    if source in _FLOSS_SOURCES:
        if path_like and fileish:
            return 0.15
        if fileish:
            return 0.2
        return 0.7
    if source in _PATH_SOURCES:
        if fileish or path_like:
            return 0.1
        return 0.25
    if path_like and fileish:
        return 0.1
    if path_like:
        return 0.3
    return 0.45


def _threshold(source: str) -> float:
    if source in _NETWORK_SOURCES:
        return 0.6
    if source in _CMDLINE_SOURCES:
        return 0.55
    if source in _FLOSS_SOURCES:
        return 0.6
    if source in _PATH_SOURCES:
        return 0.85
    return 0.6


def _accept_host(
    host: str,
    *,
    psl: PublicSuffixList,
    source: str,
    path_like: bool,
    from_url: bool,
    unc: bool,
) -> str | None:
    host = _strip_host(host)
    if not host or _is_ip(host):
        return None
    if any(part in _SKIP_HOSTS for part in host.split(".")):
        return None
    registrable = psl.registrable_domain(host)
    if not registrable:
        return None
    if registrable in _SKIP_REGISTRABLE or host in _SKIP_REGISTRABLE:
        return None
    score = _confidence(
        source,
        host=host,
        path_like=path_like,
        fileish=_fileish(host),
        from_url=from_url,
        unc=unc,
    )
    if score < _threshold(source):
        return None
    return host


def iter_urls(text: str | None) -> Iterable[str]:
    if not text:
        return
    for match in _RE_URL.finditer(str(text)):
        yield match.group(0).rstrip(".,);")


def extract_domains(
    text: str | None,
    *,
    source: str,
    psl: PublicSuffixList | None = None,
) -> list[str]:
    """Return accepted hostnames found in ``text`` for this record source."""
    if not text:
        return []
    raw = str(text)
    table = psl or default_public_suffix_list()
    found: list[str] = []
    seen: set[str] = set()

    def add(host: str | None) -> None:
        if not host or host in seen:
            return
        seen.add(host)
        found.append(host)

    for url in iter_urls(raw):
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        add(
            _accept_host(
                parsed.hostname or parsed.netloc,
                psl=table,
                source=source,
                path_like=False,
                from_url=True,
                unc=False,
            )
        )

    for match in _RE_UNC_HOST.finditer(raw):
        add(
            _accept_host(
                match.group(1),
                psl=table,
                source=source,
                path_like=False,
                from_url=False,
                unc=True,
            )
        )

    for match in _RE_CANDIDATE.finditer(raw):
        add(
            _accept_host(
                match.group(0),
                psl=table,
                source=source,
                path_like=_path_like(raw, match.start(), match.end()),
                from_url=False,
                unc=False,
            )
        )
    return found


def extract_network_host(
    value: str | None,
    *,
    source: str = "network_connections",
    psl: PublicSuffixList | None = None,
) -> str | None:
    """Validate a netscan/DNS hostname field (not an IP)."""
    if not value:
        return None
    text = str(value).strip()
    if not text or _is_ip(text):
        return None
    hosts = extract_domains(text, source=source, psl=psl)
    return hosts[0] if hosts else None
