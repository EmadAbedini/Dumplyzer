"""Dynamic Volatility 3 plugin discovery (framework APIs, not CLI)."""

from __future__ import annotations

import logging
import re
from typing import Any, Type

from memscope_engine.errors import AppError
from memscope_engine.volatility.requirements import (
    META_MODEL_VERSION,
    infer_plugin_oses,
    normalize_requirement,
)

log = logging.getLogger("memscope.tool")

PLUGIN_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")

_CATALOG: dict[str, Any] | None = None


def volatility_version() -> str:
    from volatility3.framework import constants

    return str(getattr(constants, "PACKAGE_VERSION", "unknown"))


def _import_plugin_modules() -> list[str]:
    from volatility3 import framework, plugins as vol_plugins

    failures = framework.import_files(vol_plugins, ignore_errors=True)
    return [str(x) for x in failures]


def discover_plugins(*, force_refresh: bool = False) -> dict[str, Any]:
    """Enumerate Volatility 3 plugins from the installed package registry."""
    global _CATALOG
    if _CATALOG is not None and not force_refresh:
        return _CATALOG

    from volatility3 import framework
    from volatility3.framework import constants, interfaces

    import_failures = _import_plugin_modules()
    vol_ver = getattr(constants, "PACKAGE_VERSION", "unknown")
    fw_ver = framework.interface_version()
    raw = framework.list_plugins()

    items: list[dict[str, Any]] = []
    for plugin_id, cls in sorted(raw.items(), key=lambda kv: kv[0].lower()):
        items.append(_normalize_plugin(plugin_id, cls, fw_ver))

    catalog = {
        "model_version": META_MODEL_VERSION,
        "volatility_version": str(vol_ver),
        "framework_interface_version": list(fw_ver),
        "plugin_count": len(items),
        "import_failures": import_failures,
        "items": items,
        "categories": _categories(items),
    }
    _CATALOG = catalog
    log.info(
        "plugin catalog ready",
        extra={"channel": "tool", "count": len(items), "failures": len(import_failures)},
    )
    return catalog


def _categories(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in items:
        cat = item.get("category") or "other"
        counts[cat] = counts.get(cat, 0) + 1
    return [{"id": k, "count": counts[k]} for k in sorted(counts)]


def _normalize_plugin(
    plugin_id: str,
    cls: Type[Any],
    framework_version: tuple[int, int, int],
) -> dict[str, Any]:
    discovery_errors: list[str] = []
    available = True
    requirements: list[dict[str, Any]] = []
    try:
        raw_reqs = list(cls.get_requirements())
        for req in raw_reqs:
            try:
                requirements.append(normalize_requirement(req))
            except Exception as exc:  # noqa: BLE001
                discovery_errors.append(f"requirement {getattr(req, 'name', '?')}: {exc}")
    except Exception as exc:  # noqa: BLE001
        available = False
        discovery_errors.append(f"get_requirements failed: {type(exc).__name__}: {exc}")

    required_fw = getattr(cls, "_required_framework_version", (0, 0, 0))
    try:
        from volatility3.framework import versionutils

        fw_ok = versionutils.matches_required(tuple(required_fw), framework_version)
    except Exception:  # noqa: BLE001
        fw_ok = True
    if not fw_ok:
        available = False
        discovery_errors.append(
            f"plugin requires framework {required_fw}, installed {framework_version}"
        )

    version = getattr(cls, "version", None) or getattr(cls, "_version", None)
    if isinstance(version, tuple):
        version_s = ".".join(str(x) for x in version)
        version_t = list(version)
    else:
        version_s = str(version) if version is not None else None
        version_t = None

    doc = inspect_doc(cls)
    module_path = cls.__module__
    class_name = cls.__name__
    category = _category_from_id(plugin_id, module_path)
    oses = infer_plugin_oses(requirements, cls)
    configurable = [r for r in requirements if r.get("configurable")]
    return {
        "id": plugin_id,
        "module_path": module_path,
        "class_name": class_name,
        "name": _display_name(plugin_id),
        "category": category,
        "description": doc,
        "available": available and not any("get_requirements failed" in e for e in discovery_errors),
        "version": version_s,
        "version_tuple": version_t,
        "required_framework_version": list(required_fw) if required_fw else None,
        "oses": oses,
        "architectures": _architectures(cls),
        "requirements": requirements,
        "configurable_parameters": configurable,
        "discovery_errors": discovery_errors,
        "hidden": bool(getattr(cls, "hidden", False)),
    }


def inspect_doc(cls: Type[Any]) -> str:
    doc = inspect_getdoc(cls)
    if not doc:
        return ""
    return " ".join(doc.strip().split())


def inspect_getdoc(cls: Type[Any]) -> str | None:
    import inspect

    return inspect.getdoc(cls)


def _display_name(plugin_id: str) -> str:
    parts = plugin_id.split(".")
    if len(parts) >= 2 and parts[-1][0].isupper():
        return ".".join(parts[:-1])
    return plugin_id


def _category_from_id(plugin_id: str, module_path: str) -> str:
    first = plugin_id.split(".", 1)[0].lower()
    if first in ("windows", "linux", "mac"):
        return first
    if "windows" in module_path:
        return "windows"
    if "linux" in module_path:
        return "linux"
    if ".mac." in module_path or module_path.endswith(".mac"):
        return "mac"
    return "framework"


def _architectures(cls: Type[Any]) -> list[str]:
    arches: list[str] = []
    try:
        for req in cls.get_requirements():
            child_arch = getattr(req, "architectures", None)
            if child_arch:
                arches.extend(str(a) for a in child_arch)
            for child in getattr(req, "requirements", {}).values():
                ca = getattr(child, "architectures", None)
                if ca:
                    arches.extend(str(a) for a in ca)
    except Exception:  # noqa: BLE001
        return []
    return sorted(set(arches))


def resolve_plugin_class(plugin_id: str) -> tuple[str, Type[Any]]:
    """Resolve a plugin id only through the discovered Volatility registry."""
    if not plugin_id or not isinstance(plugin_id, str):
        raise AppError(
            code="plugin_invalid_id",
            message="Plugin identifier is required.",
            entity="plugin",
        )
    ident = plugin_id.strip()
    if not PLUGIN_ID_RE.match(ident) or ".." in ident:
        raise AppError(
            code="plugin_invalid_id",
            message="Plugin identifier is not a valid Volatility plugin name.",
            details=ident,
            suggestion="Select a plugin from Plugin Explorer.",
            entity="plugin",
        )
    catalog = discover_plugins()
    items = {i["id"]: i for i in catalog["items"]}
    from volatility3 import framework

    raw = framework.list_plugins()
    if ident in raw:
        meta = items.get(ident)
        if meta and not meta.get("available", True):
            raise AppError(
                code="plugin_unavailable",
                message=f"Plugin {ident} was discovered but is not available.",
                details="; ".join(meta.get("discovery_errors") or []),
                entity="plugin",
            )
        return ident, raw[ident]
    aliases = [
        pid
        for pid in raw
        if pid.rsplit(".", 1)[0] == ident or pid.lower() == ident.lower()
    ]
    if len(aliases) == 1:
        return aliases[0], raw[aliases[0]]
    if len(aliases) > 1:
        raise AppError(
            code="plugin_ambiguous",
            message=f"Plugin identifier {ident} matches multiple plugins.",
            details=", ".join(aliases),
            entity="plugin",
        )
    raise AppError(
        code="plugin_unknown",
        message=f"Unknown Volatility plugin: {ident}",
        suggestion="Choose a plugin from the discovered catalog. Arbitrary module names are rejected.",
        entity="plugin",
    )


def get_plugin_metadata(plugin_id: str) -> dict[str, Any]:
    ident, _cls = resolve_plugin_class(plugin_id)
    catalog = discover_plugins()
    for item in catalog["items"]:
        if item["id"] == ident:
            return item
    raise AppError(code="plugin_unknown", message=f"Unknown plugin: {plugin_id}", entity="plugin")


def plugin_runnable_with_evidence(meta: dict[str, Any], evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Whether this plugin is a reasonable target for the selected evidence."""
    if not meta.get("available"):
        return {
            "runnable": False,
            "reason": "Plugin is not available in this Volatility installation.",
            "os_match": "unavailable",
        }
    if not evidence:
        return {
            "runnable": False,
            "reason": "Import evidence before running a plugin.",
            "os_match": "no_evidence",
        }
    plugin_oses = [str(x).lower() for x in (meta.get("oses") or [])]
    detected = (evidence.get("detected_os") or "") or ""
    detected_l = detected.lower()
    evidence_os = None
    if "windows" in detected_l or detected_l.startswith("nt"):
        evidence_os = "windows"
    elif "linux" in detected_l:
        evidence_os = "linux"
    elif "mac" in detected_l or "darwin" in detected_l:
        evidence_os = "mac"

    if not plugin_oses:
        return {
            "runnable": True,
            "reason": "Plugin has no OS-specific translation-layer constraint.",
            "os_match": "unspecified",
        }
    if evidence_os is None:
        return {
            "runnable": True,
            "reason": "Evidence OS is not yet identified; automagic may still fail.",
            "os_match": "unknown",
        }
    if evidence_os in plugin_oses:
        return {
            "runnable": True,
            "reason": f"Plugin targets {evidence_os}; evidence OS is {detected or evidence_os}.",
            "os_match": "match",
        }
    return {
        "runnable": False,
        "reason": (
            f"Plugin targets {', '.join(plugin_oses)} but evidence OS is "
            f"{detected or evidence_os}."
        ),
        "os_match": "mismatch",
    }
