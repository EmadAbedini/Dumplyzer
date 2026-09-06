"""Volatility 3 session construction and plugin execution (API-based, not CLI parse)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Type

from memscope_engine.volatility.treegrid import treegrid_to_table

vollog = logging.getLogger("memscope.tool")


@dataclass
class PluginResult:
    plugin: str
    columns: list[str]
    rows: list[list[Any]]
    transparency: dict[str, Any] = field(default_factory=dict)
    table: dict[str, Any] = field(default_factory=dict)


def _progress_mute(progress: float, description: str | None = None) -> None:
    return None


class VolatilitySession:
    """Owns a Context bound to one memory image path."""

    def __init__(self, image_path: Path) -> None:
        self.image_path = Path(image_path).resolve()
        if not self.image_path.is_file():
            raise AppError(
                code="evidence_not_found",
                message="Memory image file was not found.",
                details=str(self.image_path),
                suggestion="Select a valid memory image path.",
                entity="evidence",
            )

        from volatility3.framework import (
            automagic,
            constants,
            contexts,
            interfaces,
            plugins,
        )
        from volatility3.framework.automagic import stacker
        from volatility3.framework.configuration import requirements
        from volatility3.framework import exceptions

        self._automagic = automagic
        self._constants = constants
        self._contexts = contexts
        self._interfaces = interfaces
        self._plugins = plugins
        self._stacker = stacker
        self._requirements = requirements
        self._exceptions = exceptions

        self.context = contexts.Context()
        self.volatility_version = getattr(constants, "PACKAGE_VERSION", "unknown")
        single_location = requirements.URIRequirement.location_from_file(
            str(self.image_path)
        )
        self.context.config["automagic.LayerStacker.single_location"] = single_location

        self._base_config_path = "plugins"
        self._failures: list[str] = []

    def run_plugin(
        self,
        plugin_cls: Type[Any],
        plugin_params: dict[str, Any] | None = None,
        progress_callback: Callable[[float, str | None], None] | None = None,
        *,
        cancelled: Callable[[], bool] | None = None,
        open_method: Type[Any] | None = None,
    ) -> PluginResult:
        plugin_name = f"{plugin_cls.__module__}.{plugin_cls.__name__}"
        started = datetime.now(timezone.utc).isoformat()
        plugin_params = plugin_params or {}

        automagics = self._automagic.available(self.context)
        automagics = self._automagic.choose_automagic(automagics, plugin_cls)

        if self.context.config.get("automagic.LayerStacker.stackers", None) is None:
            self.context.config["automagic.LayerStacker.stackers"] = (
                self._stacker.choose_os_stackers(plugin_cls)
            )

        plugin_config_path = self._interfaces.configuration.path_join(
            self._base_config_path, plugin_cls.__name__
        )
        for key, value in plugin_params.items():
            self.context.config[
                self._interfaces.configuration.path_join(plugin_config_path, key)
            ] = value

        if cancelled and cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

        try:
            constructed = self._plugins.construct_plugin(
                self.context,
                automagics,
                plugin_cls,
                self._base_config_path,
                progress_callback or _progress_mute,
                open_method,
            )
        except self._exceptions.UnsatisfiedException as exc:
            unsat = [str(x) for x in exc.unsatisfied]
            raise AppError(
                code="volatility_unsatisfied",
                message=(
                    "Volatility analysis failed because plugin requirements "
                    "could not be satisfied (often missing or unresolved symbols)."
                ),
                details="; ".join(unsat) if unsat else str(exc),
                suggestion=(
                    "Verify the image is a supported memory dump, check OS/architecture, "
                    "and ensure symbol tables can be resolved (online or local symbols)."
                ),
                entity="volatility",
                data={"unsatisfied": unsat, "plugin": plugin_name},
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise AppError(
                code="volatility_construct_failed",
                message=f"Failed to construct Volatility plugin {plugin_cls.__name__}.",
                details=f"{type(exc).__name__}: {exc}",
                suggestion="Inspect engine logs and confirm the memory image is valid.",
                entity="volatility",
                data={"plugin": plugin_name},
            ) from exc

        if cancelled and cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

        try:
            grid = constructed.run()
        except Exception as exc:  # noqa: BLE001
            raise AppError(
                code="volatility_run_failed",
                message=f"Volatility plugin {plugin_cls.__name__} failed during execution.",
                details=f"{type(exc).__name__}: {exc}",
                suggestion="Retry analysis or try a different plugin/strategy.",
                entity="volatility",
                data={"plugin": plugin_name},
            ) from exc

        table = treegrid_to_table(grid)
        columns = [str(c["name"]) for c in table.get("columns") or []]
        rows = [list(r.get("cells") or []) for r in table.get("rows") or []]
        finished = datetime.now(timezone.utc).isoformat()
        transparency = {
            "tool": "volatility3",
            "tool_version": self.volatility_version,
            "plugin": plugin_name,
            "plugin_class": plugin_cls.__name__,
            "parameters": plugin_params,
            "started_at": started,
            "finished_at": finished,
            "status": "completed",
            "source_evidence_path": str(self.image_path),
        }
        vollog.info(
            "plugin completed",
            extra={"channel": "tool", "plugin": plugin_name},
        )
        return PluginResult(
            plugin=plugin_name,
            columns=columns,
            rows=rows,
            transparency=transparency,
            table=table,
        )


def _treegrid_to_rows(grid: Any) -> tuple[list[str], list[list[Any]]]:
    """Convert a Volatility TreeGrid into plain JSON-serializable rows."""
    columns = [str(c.name) for c in grid.columns]
    rows: list[list[Any]] = []

    def _visitor(node: Any, accumulator: Any) -> Any:
        values = list(node.values) if node.values is not None else []
        rows.append([_cell_to_json(v) for v in values])
        return accumulator

    grid.populate(_visitor, None)
    return columns, rows


def _cell_to_json(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bool, int, float, str)):
        return value
    # datetime
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:  # noqa: BLE001
            pass
    # format_hints.Hex and similar
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return repr(value)
