"""Mozilla Public Suffix List matcher for hostname validation.

The list is a snapshot shipped with Dumplyzer (MPL-2.0). Matching follows
https://publicsuffix.org/list/ — except the implicit ``*`` fallback is
disabled so unknown TLDs are rejected (keeps IOC false positives down).
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Literal

RuleKind = Literal["normal", "wildcard", "exception"]


def _load_psl_text() -> str:
    return (
        resources.files("memscope_engine.data")
        .joinpath("public_suffix_list.dat")
        .read_text(encoding="utf-8")
    )


class PublicSuffixList:
    def __init__(self, text: str) -> None:
        exact: set[tuple[str, ...]] = set()
        wild: set[tuple[str, ...]] = set()
        exc: set[tuple[str, ...]] = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            kind: RuleKind = "normal"
            if line.startswith("!"):
                kind = "exception"
                line = line[1:]
            elif line.startswith("*."):
                kind = "wildcard"
                line = line[2:]
            labels = tuple(part.lower() for part in line.rstrip(".").split(".") if part)
            if not labels:
                continue
            if kind == "exception":
                exc.add(labels)
            elif kind == "wildcard":
                wild.add(labels)
            else:
                exact.add(labels)
        self._exact = exact
        self._wild = wild
        self._exc = exc

    def _labels(self, host: str) -> list[str] | None:
        text = (host or "").strip().lower().rstrip(".")
        if not text or " " in text or "/" in text or "\\" in text:
            return None
        if text.startswith("[") and text.endswith("]"):
            return None
        labels = [part for part in text.split(".") if part]
        if len(labels) < 2 or len(labels) != text.count(".") + 1:
            return None
        if any(len(part) > 63 or part.startswith("-") or part.endswith("-") for part in labels):
            return None
        return labels

    def _prevailing(self, labels: list[str]) -> tuple[RuleKind, int] | None:
        n = len(labels)
        matches: list[tuple[int, RuleKind, int]] = []
        for length in range(1, n + 1):
            suffix = tuple(labels[n - length :])
            if suffix in self._exc:
                matches.append((length + 100, "exception", max(1, length - 1)))
            if suffix in self._exact:
                matches.append((length, "normal", length))
            if length >= 2 and suffix[1:] in self._wild:
                matches.append((length, "wildcard", length))
            elif length == 1 and () in self._wild:
                matches.append((length, "wildcard", length))
        if not matches:
            return None
        exception = [m for m in matches if m[1] == "exception"]
        if exception:
            exception.sort(reverse=True)
            return exception[0][1], exception[0][2]
        matches.sort(reverse=True)
        return matches[0][1], matches[0][2]

    def public_suffix(self, host: str) -> str | None:
        labels = self._labels(host)
        if not labels:
            return None
        found = self._prevailing(labels)
        if not found:
            return None
        _kind, count = found
        if count <= 0 or count > len(labels):
            return None
        return ".".join(labels[-count:])

    def registrable_domain(self, host: str) -> str | None:
        """eTLD+1, or None when the host is a public suffix or not in the list."""
        labels = self._labels(host)
        if not labels:
            return None
        found = self._prevailing(labels)
        if not found:
            return None
        _kind, suffix_n = found
        if suffix_n <= 0 or suffix_n >= len(labels):
            return None
        return ".".join(labels[-(suffix_n + 1) :])

    def is_known_suffix(self, host: str) -> bool:
        return self.public_suffix(host) is not None


@lru_cache(maxsize=1)
def default_public_suffix_list() -> PublicSuffixList:
    return PublicSuffixList(_load_psl_text())
