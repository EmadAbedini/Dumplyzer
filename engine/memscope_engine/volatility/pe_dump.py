"""Volatility 3 PE reconstruction from Windows memory dumps.

Uses ``windows.pedump.PEDump.dump_pe`` (IMAGE_DOS_HEADER.reconstruct) rather
than treating ``windows.dumpfiles`` as the only extraction path.

Methods:

* process executable images (pslist + PEB ImageBase)
* loaded DLLs (load-order modules)
* file-backed mapped PE images (VAD)
* unlinked / private executable regions that still start with a PE header
* cached FILE_OBJECT PE bytes (dumpfiles), only when explicitly requested

Extracted files are reconstructed PE images, not executed. Presence in memory
is not a malware verdict. The default extraction path does not run
image-wide ``windows.dumpfiles``.
"""

from __future__ import annotations

import io
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from memscope_engine.errors import AppError
from memscope_engine.providers.pe_extraction import (
    METHOD_CACHED_FILE,
    METHOD_LOADED_MODULE,
    METHOD_MAPPED_PE,
    METHOD_PROCESS_IMAGE,
    METHOD_UNLINKED,
    classify_pe_bytes,
    unique_pe_path,
)
from memscope_engine.volatility.session import VolatilitySession

log = logging.getLogger("memscope.analysis")

MAX_PE_BYTES = 100 * 1024 * 1024
MZ = b"MZ"


@dataclass
class ExtractedPe:
    pid: int | None
    process_name: str | None
    process_offset: int | None
    original_path: str | None
    pe_kind: str
    kind: str
    extraction_method: str
    source_plugin: str
    base_address: int | None
    start_vpn: str | None
    end_vpn: str | None
    memory_region: str | None
    path: Path
    sha256: str
    size_bytes: int
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def _hex(addr: int | None) -> str | None:
    if addr is None:
        return None
    return f"0x{int(addr):x}"


def _safe_str(value: Any, default: str | None = None) -> str | None:
    if value is None:
        return default
    text = str(value).strip()
    if not text or text in {"N/A", "-", "None"}:
        return default
    return text


def _make_seekable_handler(output_dir: Path, collected: list[dict[str, Any]]):
    from volatility3.framework.interfaces import plugins as iplugins

    output_dir.mkdir(parents=True, exist_ok=True)

    class SeekableFileHandler(io.BytesIO, iplugins.FileHandlerInterface):
        def __init__(self, filename: str) -> None:
            io.BytesIO.__init__(self)
            iplugins.FileHandlerInterface.__init__(self, filename)
            self.committed_path: str | None = None

        def close(self) -> None:  # type: ignore[override]
            if self.closed:
                return
            try:
                self.seek(0)
                data = self.getvalue()
            except ValueError:
                data = b""
            preferred = self.preferred_filename or "pe.bin"
            safe = iplugins.FileHandlerInterface.sanitize_filename(preferred)
            dest = output_dir / f"{uuid4().hex[:8]}.{safe}"
            dest.write_bytes(data)
            self.committed_path = str(dest)
            collected.append(
                {
                    "filename": dest.name,
                    "preferred_filename": preferred,
                    "path": dest,
                    "size_bytes": len(data),
                    "data": data,
                }
            )
            super().close()

    return SeekableFileHandler


def _import_pedump():
    try:
        from volatility3.plugins.windows.pedump import PEDump

        return PEDump
    except ImportError:
        from volatility3.framework.plugins.windows.pedump import PEDump  # type: ignore[no-redef]

        return PEDump


def _pe_table(context: Any, config_path: str) -> str:
    from volatility3.framework.symbols import intermed
    from volatility3.framework.symbols.windows.extensions import pe

    return intermed.IntermediateSymbolTable.create(
        context, config_path, "windows", "pe", class_types=pe.class_types
    )


def _reconstruct_pe(pedump_cls: Any, context: Any, pe_table_name: str, layer_name: str, base: int) -> bytes | None:
    collected: list[dict[str, Any]] = []
    handler_cls = _make_seekable_handler(Path("."), collected)
    # dump_pe writes via FileHandler; use an isolated temp via BytesIO close override
    # Redirect: write into memory only by intercepting close. Use a dedicated buffer handler.

    from volatility3.framework import constants, exceptions
    from volatility3.framework.interfaces import plugins as iplugins

    class MemoryHandler(io.BytesIO, iplugins.FileHandlerInterface):
        def __init__(self, filename: str) -> None:
            io.BytesIO.__init__(self)
            iplugins.FileHandlerInterface.__init__(self, filename)

        def close(self) -> None:  # type: ignore[override]
            if not self.closed:
                super().close()

    try:
        with MemoryHandler("reconstruct.dmp") as handle:
            dos_header = context.object(
                pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                offset=int(base),
                layer_name=layer_name,
            )
            for offset, data in dos_header.reconstruct():
                handle.seek(offset)
                handle.write(data)
            raw = handle.getvalue()
    except (OSError, exceptions.VolatilityException, OverflowError, ValueError, TypeError):
        return None
    except Exception:  # noqa: BLE001
        return None
    if not raw or len(raw) < 64:
        return None
    if len(raw) > MAX_PE_BYTES:
        return None
    if raw[:2] != MZ:
        return None
    return bytes(raw)


def _read_prefix(context: Any, layer_name: str, address: int, size: int = 64) -> bytes:
    try:
        layer = context.layers[layer_name]
        data = layer.read(int(address), size, pad=True)
        return data or b""
    except Exception:  # noqa: BLE001
        return b""


def _process_name(proc: Any) -> str | None:
    try:
        return proc.ImageFileName.cast(
            "string",
            max_length=proc.ImageFileName.vol.count,
            errors="replace",
        )
    except Exception:  # noqa: BLE001
        return None


def _module_names(mod: Any) -> tuple[str | None, str | None]:
    name = None
    path = None
    try:
        name = mod.BaseDllName.get_string()
    except Exception:  # noqa: BLE001
        pass
    try:
        path = mod.FullDllName.get_string()
    except Exception:  # noqa: BLE001
        pass
    return _safe_str(name), _safe_str(path)


def _vad_file_name(vad: Any) -> str | None:
    for attr in ("get_file_name", "FileName"):
        try:
            val = getattr(vad, attr)
            if callable(val):
                val = val()
            text = _safe_str(val)
            if text:
                return text
        except Exception:  # noqa: BLE001
            continue
    return None


def _vad_protection(vad: Any) -> str:
    try:
        from volatility3.plugins.windows import vadinfo
        from volatility3.plugins.windows.vadinfo import VadInfo

        protect = vad.get_protection(
            VadInfo.protect_values(vad._context, vad.vol.layer_name, vad.vol.symbol_table_name),
            vadinfo.winnt_protections,
        )
        return str(protect or "")
    except Exception:  # noqa: BLE001
        try:
            return str(vad.get_protection())
        except Exception:  # noqa: BLE001
            return ""


def _commit_pe(
    *,
    output_dir: Path,
    data: bytes,
    pid: int | None,
    process_name: str | None,
    original_path: str | None,
    kind: str,
    extraction_method: str,
    source_plugin: str,
    base_address: int | None,
    start: int | None,
    end: int | None,
    seen_keys: set[tuple[Any, ...]],
    seen_sha: dict[str, Path],
    results: list[ExtractedPe],
    skipped: list[dict[str, Any]],
    notes: str = "",
    extra_meta: dict[str, Any] | None = None,
) -> None:
    from memscope_engine.artifacts.store import sha256_file

    key = (pid, int(base_address) if base_address is not None else None, kind)
    if key in seen_keys:
        skipped.append({"reason": "duplicate_region", "pid": pid, "base": _hex(base_address), "kind": kind})
        return
    seen_keys.add(key)
    info = classify_pe_bytes(data)
    if not info.get("is_pe") or not info.get("parse_ok"):
        skipped.append(
            {
                "reason": "invalid_pe",
                "pid": pid,
                "base": _hex(base_address),
                "kind": kind,
                "parse_ok": bool(info.get("parse_ok")),
            }
        )
        return
    dest = unique_pe_path(
        output_dir,
        pid=pid,
        pe_kind=str(info.get("pe_kind") or "unknown"),
        original_name=original_path or process_name,
        base_address=base_address,
        method=kind,
    )
    dest.write_bytes(data)
    digest = sha256_file(dest)
    if digest in seen_sha:
        skipped.append(
            {
                "reason": "duplicate_sha256",
                "pid": pid,
                "sha256": digest,
                "existing": str(seen_sha[digest]),
                "kind": kind,
            }
        )
        # Keep the file; still record as extracted with duplicate note
        notes = (notes + " ").strip() + f"Duplicate SHA-256 of {seen_sha[digest].name}."
    else:
        seen_sha[digest] = dest
    start_s = _hex(start if start is not None else base_address)
    end_s = _hex(end)
    region = None
    if start_s and end_s:
        region = f"{start_s}-{end_s}"
    elif start_s:
        region = start_s
    results.append(
        ExtractedPe(
            pid=pid,
            process_name=process_name,
            process_offset=None,
            original_path=original_path,
            pe_kind=str(info.get("pe_kind") or "unknown"),
            kind=kind,
            extraction_method=extraction_method,
            source_plugin=source_plugin,
            base_address=base_address,
            start_vpn=start_s,
            end_vpn=end_s,
            memory_region=region,
            path=dest,
            sha256=digest,
            size_bytes=dest.stat().st_size,
            notes=notes or "Extracted PE artifact; not executed; not classified as malware.",
            metadata={"pe": info, **(extra_meta or {})},
        )
    )


def cleanup_dumpfiles_temp(output_dir: Path) -> None:
    """Remove dumpfiles scratch only. Never the dump or committed PE artifacts."""
    tmp_dir = Path(output_dir) / "_dumpfiles_tmp"
    if not tmp_dir.exists():
        return
    try:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except OSError:
        pass


def extract_pe_images(
    image_path: Path,
    output_dir: Path,
    *,
    pid_filter: int | None = None,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[str], None] | None = None,
    include_dumpfiles: bool = False,
    include_vad_scan: bool = True,
) -> dict[str, Any]:
    """Walk a Windows memory image and reconstruct PE files into output_dir.

    Default path: windows.pedump reconstruction of process images, loaded
    modules, mapped PE, and unlinked/manual-mapped MZ regions. Image-wide
    windows.dumpfiles is not invoked unless include_dumpfiles is True.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        return _extract_pe_images_impl(
            Path(image_path),
            output_dir,
            pid_filter=pid_filter,
            cancelled=cancelled,
            progress=progress,
            include_dumpfiles=bool(include_dumpfiles),
            include_vad_scan=include_vad_scan,
        )
    finally:
        cleanup_dumpfiles_temp(output_dir)


def _extract_pe_images_impl(
    image_path: Path,
    output_dir: Path,
    *,
    pid_filter: int | None,
    cancelled: Callable[[], bool] | None,
    progress: Callable[[str], None] | None,
    include_dumpfiles: bool,
    include_vad_scan: bool,
) -> dict[str, Any]:
    """Walk a Windows memory image and reconstruct PE files into output_dir."""

    def _prog(msg: str) -> None:
        if progress:
            progress(msg)

    def _cancel() -> None:
        if cancelled and cancelled():
            raise AppError(code="job_cancelled", message="Job was cancelled.", entity="job")

    output_dir.mkdir(parents=True, exist_ok=True)
    session = VolatilitySession(Path(image_path))
    from volatility3.framework import plugins
    from volatility3.framework.automagic import stacker
    from volatility3.plugins.windows import pslist

    try:
        pedump_cls = _import_pedump()
    except ImportError as exc:
        raise AppError(
            code="pe_extraction_unavailable",
            message="Volatility 3 windows.pedump is not available in this runtime.",
            details=str(exc),
            entity="pe_extraction",
        ) from exc

    automagics = session._automagic.available(session.context)
    automagics = session._automagic.choose_automagic(automagics, pslist.PsList)
    if session.context.config.get("automagic.LayerStacker.stackers", None) is None:
        session.context.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(
            pslist.PsList
        )

    _prog("Constructing Volatility process list for PE extraction")
    _cancel()
    constructed = plugins.construct_plugin(
        session.context,
        automagics,
        pslist.PsList,
        "plugins",
        lambda *_a, **_k: None,
        None,
    )
    try:
        kname = constructed.config["kernel"]
    except Exception as exc:  # noqa: BLE001
        raise AppError(
            code="volatility_unsatisfied",
            message="Could not resolve kernel module for PE extraction.",
            details=str(exc),
            entity="volatility",
        ) from exc

    pe_table_name = _pe_table(session.context, "plugins.PEDump")
    pid_list = [int(pid_filter)] if pid_filter is not None else None
    filter_func = pslist.PsList.create_pid_filter(pid_list)

    results: list[ExtractedPe] = []
    skipped: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, ...]] = set()
    seen_sha: dict[str, Path] = {}
    methods_used: list[str] = []
    errors: list[str] = []

    _prog("Extracting process executable images")
    for proc in pslist.PsList.list_processes(
        session.context,
        kname,
        filter_func=filter_func,
    ):
        _cancel()
        try:
            pid = int(proc.UniqueProcessId)
        except Exception:  # noqa: BLE001
            continue
        name = _process_name(proc)
        try:
            proc_layer = proc.add_process_layer()
        except Exception as exc:  # noqa: BLE001
            skipped.append({"reason": "process_layer", "pid": pid, "error": str(exc)})
            continue
        image_base = None
        image_path_s = None
        try:
            peb = proc.get_peb()
            image_base = int(peb.ImageBaseAddress)
        except Exception:  # noqa: BLE001
            try:
                image_base = int(proc.Peb.ImageBaseAddress)
            except Exception:  # noqa: BLE001
                image_base = None
        try:
            peb = proc.get_peb()
            image_path_s = _safe_str(peb.ProcessParameters.ImagePathName.get_string())
        except Exception:  # noqa: BLE001
            image_path_s = None
        if image_base is None:
            skipped.append({"reason": "no_image_base", "pid": pid, "name": name})
        else:
            raw = _reconstruct_pe(pedump_cls, session.context, pe_table_name, proc_layer, image_base)
            if raw:
                if METHOD_PROCESS_IMAGE not in methods_used:
                    methods_used.append(METHOD_PROCESS_IMAGE)
                _commit_pe(
                    output_dir=output_dir,
                    data=raw,
                    pid=pid,
                    process_name=name,
                    original_path=image_path_s or name,
                    kind="process_image",
                    extraction_method=METHOD_PROCESS_IMAGE,
                    source_plugin="windows.pslist+windows.pedump",
                    base_address=image_base,
                    start=image_base,
                    end=None,
                    seen_keys=seen_keys,
                    seen_sha=seen_sha,
                    results=results,
                    skipped=skipped,
                )
            else:
                skipped.append({"reason": "reconstruct_failed", "pid": pid, "kind": "process_image"})

        _prog(f"Extracting loaded modules for PID {pid}")
        try:
            modules_iter = proc.load_order_modules()
        except Exception as exc:  # noqa: BLE001
            skipped.append({"reason": "dlllist_failed", "pid": pid, "error": str(exc)})
            modules_iter = []
        for mod in modules_iter:
            _cancel()
            try:
                dll_base = int(mod.DllBase)
            except Exception:  # noqa: BLE001
                continue
            mod_name, mod_path = _module_names(mod)
            if image_base is not None and dll_base == image_base:
                continue
            raw = _reconstruct_pe(pedump_cls, session.context, pe_table_name, proc_layer, dll_base)
            if not raw:
                skipped.append(
                    {
                        "reason": "reconstruct_failed",
                        "pid": pid,
                        "kind": "loaded_module",
                        "name": mod_name,
                        "base": _hex(dll_base),
                    }
                )
                continue
            if METHOD_LOADED_MODULE not in methods_used:
                methods_used.append(METHOD_LOADED_MODULE)
            _commit_pe(
                output_dir=output_dir,
                data=raw,
                pid=pid,
                process_name=name,
                original_path=mod_path or mod_name,
                kind="loaded_module",
                extraction_method=METHOD_LOADED_MODULE,
                source_plugin="windows.dlllist+windows.pedump",
                base_address=dll_base,
                start=dll_base,
                end=None,
                seen_keys=seen_keys,
                seen_sha=seen_sha,
                results=results,
                skipped=skipped,
            )

        if not include_vad_scan:
            continue
        _prog(f"Scanning VADs for mapped/unlinked PE images PID {pid}")
        try:
            vads = proc.get_vad_root().traverse()
        except Exception as exc:  # noqa: BLE001
            skipped.append({"reason": "vad_walk_failed", "pid": pid, "error": str(exc)})
            continue
        for vad in vads:
            _cancel()
            try:
                start = int(vad.get_start())
            except Exception:  # noqa: BLE001
                continue
            try:
                end = int(vad.get_end())
            except Exception:  # noqa: BLE001
                end = None
            prefix = _read_prefix(session.context, proc_layer, start, 64)
            if prefix[:2] != MZ:
                continue
            file_name = _vad_file_name(vad)
            prot = _vad_protection(vad).upper()
            private = False
            try:
                private = bool(vad.get_private_memory())
            except Exception:  # noqa: BLE001
                private = False
            has_exec = "EXECUTE" in prot or "EXEC" in prot
            is_image = False
            try:
                tag = str(vad.get_tag() if hasattr(vad, "get_tag") else getattr(vad, "Tag", "") or "")
                is_image = "image" in tag.lower()
            except Exception:  # noqa: BLE001
                tag = ""
            if file_name or is_image:
                kind = "mapped_pe"
                method = METHOD_MAPPED_PE
                plugin = "windows.vadinfo+windows.pedump"
            elif (private or not file_name) and (has_exec or True):
                # Private / unbacked MZ: technically feasible injected or manual-mapped PE.
                kind = "unlinked_mapped"
                method = METHOD_UNLINKED
                plugin = "windows.vadinfo+windows.pedump"
                if not has_exec and not private:
                    continue
            else:
                continue
            if image_base is not None and start == image_base:
                continue
            raw = _reconstruct_pe(pedump_cls, session.context, pe_table_name, proc_layer, start)
            if not raw:
                # Keep the VAD prefix only if it already looks like a full PE reconstruct failure
                skipped.append(
                    {
                        "reason": "reconstruct_failed",
                        "pid": pid,
                        "kind": kind,
                        "base": _hex(start),
                    }
                )
                continue
            if method not in methods_used:
                methods_used.append(method)
            _commit_pe(
                output_dir=output_dir,
                data=raw,
                pid=pid,
                process_name=name,
                original_path=file_name,
                kind=kind,
                extraction_method=method,
                source_plugin=plugin,
                base_address=start,
                start=start,
                end=end,
                seen_keys=seen_keys,
                seen_sha=seen_sha,
                results=results,
                skipped=skipped,
                extra_meta={"protection": prot, "private_memory": private, "vad_tag": tag if "tag" in dir() else None},
            )

    if include_dumpfiles:
        _cancel()
        _prog("Extracting cached PE files still present in the file cache")
        try:
            dumped = _extract_dumpfiles_pe(session, output_dir, cancelled=cancelled)
            if dumped:
                if METHOD_CACHED_FILE not in methods_used:
                    methods_used.append(METHOD_CACHED_FILE)
                for item in dumped:
                    _commit_pe(
                        output_dir=output_dir,
                        data=item["data"],
                        pid=item.get("pid"),
                        process_name=item.get("process_name"),
                        original_path=item.get("original_path"),
                        kind="cached_file",
                        extraction_method=METHOD_CACHED_FILE,
                        source_plugin="windows.dumpfiles",
                        base_address=item.get("base_address"),
                        start=item.get("base_address"),
                        end=None,
                        seen_keys=seen_keys,
                        seen_sha=seen_sha,
                        results=results,
                        skipped=skipped,
                        extra_meta={
                            "dumpfiles_name": item.get("preferred_filename"),
                            "dumpfiles_fallback": True,
                        },
                    )
        except AppError:
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"dumpfiles: {type(exc).__name__}: {exc}")
            log.warning("dumpfiles PE extraction skipped", extra={"channel": "analysis"})

    return {
        "items": results,
        "skipped": skipped,
        "errors": errors,
        "methods_used": methods_used,
        "include_dumpfiles": bool(include_dumpfiles),
        "dumpfiles_used": METHOD_CACHED_FILE in methods_used,
        "volatility_version": session.volatility_version,
        "extracted_count": len(results),
        "exe_count": sum(1 for i in results if i.pe_kind == "exe"),
        "dll_count": sum(1 for i in results if i.pe_kind == "dll"),
        "skipped_count": len(skipped),
    }


def _extract_dumpfiles_pe(
    session: VolatilitySession,
    output_dir: Path,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Optional extra method: keep only PE files emitted by windows.dumpfiles."""
    try:
        from volatility3.plugins.windows.dumpfiles import DumpFiles
    except ImportError:
        try:
            from volatility3.framework.plugins.windows.dumpfiles import DumpFiles  # type: ignore[no-redef]
        except ImportError:
            return []

    collected: list[dict[str, Any]] = []
    handler = _make_seekable_handler(output_dir / "_dumpfiles_tmp", collected)
    try:
        session.run_plugin(DumpFiles, {}, cancelled=cancelled, open_method=handler)
    except AppError as exc:
        if exc.code == "job_cancelled":
            raise
        return []
    except Exception:  # noqa: BLE001
        return []

    pe_items: list[dict[str, Any]] = []
    tmp_dir = output_dir / "_dumpfiles_tmp"
    for rec in collected:
        data = rec.get("data") or b""
        path: Path = rec["path"]
        if not data and path.is_file():
            data = path.read_bytes()
        if not data.startswith(MZ):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        if len(data) > MAX_PE_BYTES:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        pe_items.append(
            {
                "data": data,
                "original_path": rec.get("preferred_filename"),
                "preferred_filename": rec.get("preferred_filename"),
                "pid": None,
                "process_name": None,
                "base_address": None,
            }
        )
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        if tmp_dir.exists():
            for leftover in tmp_dir.iterdir():
                leftover.unlink(missing_ok=True)
            tmp_dir.rmdir()
    except OSError:
        pass
    return pe_items
