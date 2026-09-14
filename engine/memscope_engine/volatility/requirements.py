"""Normalize and validate Volatility 3 plugin requirements."""

from __future__ import annotations

from typing import Any

from memscope_engine.errors import AppError

META_MODEL_VERSION = 1

# User-configurable simple types. Framework/internal types are resolved by the engine.
CONFIGURABLE_TYPES = {
    "BooleanRequirement",
    "IntRequirement",
    "StringRequirement",
    "ChoiceRequirement",
    "ListRequirement",
}

FRAMEWORK_TYPES = {
    "URIRequirement",
    "TranslationLayerRequirement",
    "SymbolTableRequirement",
    "LayerListRequirement",
    "ComplexListRequirement",
    "VersionRequirement",
    "PluginRequirement",
    "ModuleRequirement",
    "ClassRequirement",
    "MultiRequirement",
    "LayerRequirement",
    "BytesRequirement",
}

FORBIDDEN_PARAM_NAMES = {
    "single_location",
    "location",
    "automagic",
    "class",
    "layer_name",
    "symbol_table_name",
    "primary",
    "kernel",
    "context",
    "config_path",
}


def requirement_type_name(req: Any) -> str:
    return type(req).__name__


def is_configurable_requirement(req: Any) -> bool:
    tname = requirement_type_name(req)
    if tname == "URIRequirement":
        return False
    if tname in FRAMEWORK_TYPES:
        return False
    if tname in CONFIGURABLE_TYPES:
        return True
    # Unknown requirement: treat as framework so the UI does not offer a free-form field.
    return False


def classify_requirement(req: Any) -> str:
    tname = requirement_type_name(req)
    if tname == "URIRequirement":
        return "framework"
    if is_configurable_requirement(req):
        return "configurable"
    return "framework"


def normalize_requirement(req: Any) -> dict[str, Any]:
    tname = requirement_type_name(req)
    classification = classify_requirement(req)
    payload: dict[str, Any] = {
        "name": getattr(req, "name", None),
        "type": tname,
        "classification": classification,
        "configurable": classification == "configurable",
        "optional": bool(getattr(req, "optional", False)),
        "default": _jsonable(getattr(req, "default", None)),
        "description": getattr(req, "description", None) or "",
    }
    if tname == "ChoiceRequirement":
        payload["choices"] = list(getattr(req, "choices", []) or [])
    if tname == "ListRequirement":
        el = getattr(req, "element_type", str)
        payload["element_type"] = getattr(el, "__name__", str(el))
        payload["min_elements"] = getattr(req, "min_elements", 0)
        payload["max_elements"] = getattr(req, "max_elements", None)
    if tname == "TranslationLayerRequirement":
        payload["oses"] = list(getattr(req, "oses", []) or [])
        payload["architectures"] = list(getattr(req, "architectures", []) or [])
    if tname == "ModuleRequirement":
        nested = []
        for child in getattr(req, "requirements", {}).values():
            nested.append(
                {
                    "name": getattr(child, "name", None),
                    "type": requirement_type_name(child),
                    "oses": list(getattr(child, "oses", []) or []),
                    "architectures": list(getattr(child, "architectures", []) or []),
                }
            )
        payload["children"] = nested
    if tname == "VersionRequirement":
        component = getattr(req, "_component", None)
        payload["component"] = (
            f"{component.__module__}.{component.__name__}" if component is not None else None
        )
        ver = getattr(req, "_version", None)
        payload["required_version"] = list(ver) if isinstance(ver, tuple) else ver
    return payload


def infer_plugin_oses(normalized_reqs: list[dict[str, Any]], cls: Any) -> list[str]:
    oses: set[str] = set()
    for req in normalized_reqs:
        for o in req.get("oses") or []:
            oses.add(str(o).lower())
        for child in req.get("children") or []:
            for o in child.get("oses") or []:
                oses.add(str(o).lower())
        desc = (req.get("description") or "").lower()
        name = (req.get("name") or "").lower()
        if req.get("type") == "ModuleRequirement":
            if "windows" in desc or name == "kernel" and "windows" in desc:
                oses.add("windows")
            if "linux" in desc:
                oses.add("linux")
            if "mac" in desc or "darwin" in desc:
                oses.add("mac")
    if not oses:
        module = getattr(cls, "__module__", "")
        if ".windows." in module or module.endswith(".windows"):
            oses.add("windows")
        elif ".linux." in module:
            oses.add("linux")
        elif ".mac." in module:
            oses.add("mac")
    return sorted(oses)


def validate_user_parameters(
    meta: dict[str, Any],
    user_params: dict[str, Any] | None,
) -> dict[str, Any]:
    """Accept only configurable requirement values. Reject paths, code, extra keys."""
    incoming = dict(user_params or {})
    if not isinstance(incoming, dict):
        raise AppError(
            code="plugin_invalid_params",
            message="Plugin parameters must be an object.",
            entity="plugin",
        )
    for banned in ("__import__", "eval", "exec", "code", "python", "argv", "command", "shell"):
        if banned in incoming:
            raise AppError(
                code="plugin_invalid_params",
                message="Arbitrary code or command parameters are not allowed.",
                details=banned,
                entity="plugin",
            )
    by_name = {r["name"]: r for r in (meta.get("requirements") or []) if r.get("name")}
    configurable = {r["name"]: r for r in (meta.get("configurable_parameters") or []) if r.get("name")}
    cleaned: dict[str, Any] = {}
    for key, value in incoming.items():
        if key in FORBIDDEN_PARAM_NAMES:
            raise AppError(
                code="plugin_param_forbidden",
                message=f"Parameter '{key}' is resolved by Dumplyzer, not the analyst.",
                suggestion="Evidence location and kernel/layer requirements are filled from the imported image.",
                entity="plugin",
            )
        spec = configurable.get(key)
        if spec is None:
            req = by_name.get(key)
            if req and not req.get("configurable"):
                raise AppError(
                    code="plugin_param_forbidden",
                    message=f"Parameter '{key}' is a framework requirement and cannot be set from the UI.",
                    details=req.get("type"),
                    entity="plugin",
                )
            raise AppError(
                code="plugin_param_unknown",
                message=f"Unknown plugin parameter '{key}'.",
                suggestion="Use only the configurable requirements listed for this plugin.",
                entity="plugin",
            )
        cleaned[key] = _coerce_value(spec, value)
    for spec in configurable.values():
        if not spec.get("optional") and spec["name"] not in cleaned and spec.get("default") is None:
            raise AppError(
                code="plugin_param_required",
                message=f"Required parameter '{spec['name']}' is missing.",
                entity="plugin",
            )
    return cleaned


def _coerce_value(spec: dict[str, Any], value: Any) -> Any:
    tname = spec.get("type")
    name = spec.get("name")
    if tname == "BooleanRequirement":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in ("true", "false", "1", "0", "yes", "no"):
            return value.lower() in ("true", "1", "yes")
        if value in (0, 1):
            return bool(value)
        raise AppError(
            code="plugin_param_type",
            message=f"Parameter '{name}' must be a boolean.",
            entity="plugin",
        )
    if tname == "IntRequirement":
        try:
            if isinstance(value, bool):
                raise ValueError("bool")
            return int(value)
        except (TypeError, ValueError) as exc:
            raise AppError(
                code="plugin_param_type",
                message=f"Parameter '{name}' must be an integer.",
                entity="plugin",
            ) from exc
    if tname == "ChoiceRequirement":
        choices = spec.get("choices") or []
        sval = str(value)
        if sval not in choices:
            raise AppError(
                code="plugin_param_choice",
                message=f"Parameter '{name}' must be one of: {', '.join(choices)}.",
                entity="plugin",
            )
        return sval
    if tname == "ListRequirement":
        if value is None:
            return []
        if isinstance(value, str):
            parts = [p.strip() for p in value.split(",") if p.strip()]
        elif isinstance(value, list):
            parts = value
        else:
            raise AppError(
                code="plugin_param_type",
                message=f"Parameter '{name}' must be a list.",
                entity="plugin",
            )
        el = (spec.get("element_type") or "str").lower()
        out = []
        for item in parts:
            if el == "int":
                try:
                    if isinstance(item, bool):
                        raise ValueError("bool")
                    out.append(int(item))
                except (TypeError, ValueError) as exc:
                    raise AppError(
                        code="plugin_param_type",
                        message=f"Parameter '{name}' must be a list of integers.",
                        entity="plugin",
                    ) from exc
            elif el == "bool":
                out.append(str(item).lower() in ("true", "1", "yes"))
            else:
                out.append(str(item))
        min_el = spec.get("min_elements") or 0
        max_el = spec.get("max_elements")
        if min_el and len(out) < min_el:
            raise AppError(
                code="plugin_param_type",
                message=f"Parameter '{name}' requires at least {min_el} values.",
                entity="plugin",
            )
        if max_el and len(out) >= max_el:
            raise AppError(
                code="plugin_param_type",
                message=f"Parameter '{name}' accepts fewer than {max_el} values.",
                entity="plugin",
            )
        return out
    if tname == "StringRequirement":
        if not isinstance(value, str):
            raise AppError(
                code="plugin_param_type",
                message=f"Parameter '{name}' must be a string.",
                entity="plugin",
            )
        if _looks_like_path(value):
            raise AppError(
                code="plugin_param_path_denied",
                message=f"Parameter '{name}' cannot be a filesystem path.",
                suggestion="Evidence paths are supplied from the imported image, not typed here.",
                entity="plugin",
            )
        return value
    raise AppError(
        code="plugin_param_type",
        message=f"Parameter '{name}' has unsupported type {tname}.",
        entity="plugin",
    )


def _looks_like_path(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    if v.startswith(("file:", "http:", "https:", "\\\\", "/")):
        return True
    if len(v) >= 3 and v[1] == ":" and v[2] in ("\\", "/"):
        return True
    if "\\" in v:
        return True
    return False


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)
