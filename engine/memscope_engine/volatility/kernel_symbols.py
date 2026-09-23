"""Per-build Windows kernel symbols, with user consent.

Volatility 3 needs the ISF/PDB that matches the dump's kernel GUID. Dumplyzer
does not download the full Windows pack and does not fetch Microsoft PDBs
until the user chooses Download or provides a local file.
"""

from __future__ import annotations

import json
import logging
import lzma
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from memscope_engine.errors import AppError, JobCancelled, job_cancelled_error
from memscope_engine.paths import AppPaths
from memscope_engine.version import APP_NAME
from memscope_engine.volatility.runtime import (
    SYMBOL_SERVER_HTTPS,
    SYMBOL_USER_AGENT,
    active_paths,
    record_needed_kernel,
    safe_https_context,
)
from memscope_engine.volatility.symbol_pack import pack_is_ready

log = logging.getLogger("memscope.tool")

ACCEPTED_EXTENSIONS = (".pdb", ".json", ".json.xz", ".json.gz")
_MAX_PDB_BYTES = 80 * 1024 * 1024
_CREATE_NO_WINDOW = 0x08000000
_PDB_MAGIC = b"Microsoft C/C++"
_COMPRESSED_MAGICS = (b"SZDD", b"MSCF")
_CONVERT_LOCK = threading.Lock()
_HTTP_RETRIES = 3
_HTTP_RETRY_SLEEP_SECS = 0.4
_HTTP_TIMEOUT_SECS = 180.0
_PROGRESS_MIN_CONTENT_LENGTH = 4096


def microsoft_pdb_url(pdb_name: str, guid: str, age: int) -> str:
    name = _pdb_filename(pdb_name)
    ident = f"{guid.upper()}{int(age)}"
    return f"{SYMBOL_SERVER_HTTPS}/{name}/{ident}/{name}"


def microsoft_compressed_pdb_url(pdb_name: str, guid: str, age: int) -> str:
    name = _pdb_filename(pdb_name)
    ident = f"{guid.upper()}{int(age)}"
    compressed = f"{name[:-1]}_" if name.lower().endswith(".pdb") else f"{name}_"
    return f"{SYMBOL_SERVER_HTTPS}/{name}/{ident}/{compressed}"


def requirement_payload(
    pdb_name: str,
    guid: str,
    age: int,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    name = _pdb_filename(pdb_name)
    guid_u = guid.upper()
    age_i = int(age)
    dest = rf"%LOCALAPPDATA%\{APP_NAME}\symbols\windows"
    payload = {
        "pdb_name": name,
        "guid": guid_u,
        "age": age_i,
        "filename_pdb": name,
        "filename_isf": f"{guid_u}-{age_i}.json.xz",
        "download_url": microsoft_pdb_url(name, guid_u, age_i),
        "dest_dir": dest,
        "accepted_extensions": list(ACCEPTED_EXTENSIONS),
    }
    if extra:
        payload.update(extra)
    return payload


def kernel_symbols_required_error(
    pdb_name: str,
    guid: str,
    age: int,
) -> AppError:
    data = requirement_payload(pdb_name, guid, age)
    return AppError(
        code="kernel_symbols_required",
        message="This Windows dump needs kernel symbol tables before analysis can continue.",
        suggestion=(
            f"Choose Download to fetch {data['filename_pdb']} for this build only "
            f"(a few MB from Microsoft), or download that PDB / an ISF file "
            f"({data['filename_isf']}, .json, or .json.gz) and browse to it. "
            f"Store path: {data['dest_dir']}."
        ),
        entity="volatility",
        data=data,
    )


def maybe_kernel_symbols_error() -> AppError | None:
    from memscope_engine.volatility.runtime import last_needed_kernel

    needed = last_needed_kernel()
    if not needed:
        return None
    return kernel_symbols_required_error(
        str(needed["pdb_name"]),
        str(needed["guid"]),
        int(needed["age"]),
    )


def isf_destination(
    pdb_name: str,
    guid: str,
    age: int,
    paths: AppPaths | None = None,
) -> Path:
    resolved = paths or active_paths()
    name = _pdb_filename(pdb_name)
    ident = f"{guid.upper()}-{int(age)}"
    dest_dir = resolved.symbols / "windows" / name
    dest_dir.mkdir(parents=True, exist_ok=True)
    return dest_dir / f"{ident}.json.xz"


def import_user_symbol_file(
    source: str | Path,
    *,
    pdb_name: str,
    guid: str,
    age: int,
    paths: AppPaths | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    src = Path(source).expanduser()
    if not src.is_file():
        raise AppError(
            code="symbol_file_missing",
            message="The selected symbol file was not found.",
            suggestion="Choose a .pdb, .json, .json.xz, or .json.gz file.",
            entity="volatility",
        )
    suffix = _compound_suffix(src.name)
    if suffix not in ACCEPTED_EXTENSIONS:
        raise AppError(
            code="symbol_file_unsupported",
            message="That file type is not a kernel symbol table.",
            suggestion=(
                "Provide the Microsoft PDB (.pdb) for this kernel, or a Volatility "
                "ISF file (.json / .json.xz / .json.gz)."
            ),
            entity="volatility",
        )
    if cancelled and cancelled():
        raise job_cancelled_error()
    from memscope_engine.volatility.runtime import configure_volatility_runtime

    resolved = paths or active_paths()
    configure_volatility_runtime(resolved)
    dest = isf_destination(pdb_name, guid, age, resolved)
    if suffix == ".pdb":
        _convert_pdb_to_isf(src, dest, pdb_name=pdb_name, cancelled=cancelled)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if suffix == ".json.xz":
            shutil.copy2(src, dest)
        elif suffix == ".json.gz":
            gz_dest = dest.with_suffix("").with_suffix(".json.gz")
            shutil.copy2(src, gz_dest)
        else:
            json_dest = dest.with_suffix("").with_suffix(".json")
            shutil.copy2(src, json_dest)
    record_needed_kernel(pdb_name, guid, int(age))
    return {
        "ok": True,
        "stored": str(dest),
        **requirement_payload(pdb_name, guid, age),
    }


def save_microsoft_pdb(
    dest: str | Path,
    *,
    pdb_name: str,
    guid: str,
    age: int,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[float, str | None], None] | None = None,
) -> dict[str, Any]:
    """Fetch this build's PDB using the Microsoft symbol-server protocol.

    msdl.microsoft.com often 302s to Azure Blob Storage with a ``.blob``
    object name and no Content-Disposition. The bytes are accepted only after
    they verify as a PDB (or a compressed PDB that expands to one).
    """
    dest_path = _validated_pdb_dest(dest)
    urls = [
        microsoft_pdb_url(pdb_name, guid, age),
        microsoft_compressed_pdb_url(pdb_name, guid, age),
    ]
    last_error: Exception | None = None
    data: bytes | None = None
    for url in urls:
        if cancelled and cancelled():
            raise job_cancelled_error()
        try:
            data = _http_get_symbol_bytes(
                url, cancelled=cancelled, progress=progress
            )
        except AppError as exc:
            if exc.code == "job_cancelled":
                raise
            last_error = exc
            continue
        except (urlerror.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            continue
        if data:
            break
    if not data:
        if isinstance(last_error, AppError) and "incomplete" in last_error.message.lower():
            raise last_error
        raise AppError(
            code="kernel_symbols_download_failed",
            message="The kernel PDB could not be downloaded from Microsoft.",
            details=str(last_error) if last_error else urls[0],
            suggestion=(
                "Connect to the Internet and retry Download & Continue, or browse "
                "to a matching .pdb / ISF file you already have."
            ),
            entity="volatility",
            data=requirement_payload(pdb_name, guid, age),
        )
    payload = _normalize_pdb_bytes(data, dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_bytes(payload)
    return {
        "ok": True,
        "path": str(dest_path),
        "bytes": len(payload),
        **requirement_payload(pdb_name, guid, age),
    }


def fetch_kernel_pdb(
    *,
    pdb_name: str,
    guid: str,
    age: int,
    progress: Callable[[float, str | None], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    payload = requirement_payload(pdb_name, guid, age)
    if pack_is_ready():
        return {"ok": True, "source": "local_pack", **payload}
    from memscope_engine.volatility.runtime import configure_volatility_runtime

    configure_volatility_runtime()
    if cancelled and cancelled():
        raise job_cancelled_error()
    record_needed_kernel(pdb_name, guid, int(age))
    dest = isf_destination(pdb_name, guid, age)
    if dest.is_file() and dest.stat().st_size > 0 and _looks_like_isf(dest):
        if progress is not None:
            progress(100, "Kernel symbols ready")
        return {"ok": True, "stored": str(dest), "source": "cache", **payload}

    peak = 0.0

    def _progress(pct: float, description: str | None = None) -> None:
        nonlocal peak
        if cancelled and cancelled():
            raise JobCancelled()
        if progress is None:
            return
        try:
            value = float(pct)
        except (TypeError, ValueError):
            value = 0.0
        value = max(0.0, min(100.0, value))
        if value < peak:
            value = peak
        else:
            peak = value
        progress(value, description or "Downloading kernel symbols…")

    try:
        if progress is not None:
            _progress(1, "Downloading kernel symbols for this Windows build…")
        with tempfile.TemporaryDirectory(prefix="dumplyzer-pdb-") as tmp:
            pdb_path = Path(tmp) / _pdb_filename(pdb_name)
            save_microsoft_pdb(
                pdb_path,
                pdb_name=pdb_name,
                guid=guid,
                age=age,
                cancelled=cancelled,
                progress=lambda pct, description=None: _progress(
                    2 + min(58.0, max(0.0, pct) * 0.58),
                    description,
                ),
            )
            raw = pdb_path.read_bytes()
            if not _looks_like_pdb(raw):
                raise AppError(
                    code="kernel_symbols_download_failed",
                    message="The downloaded file is not a kernel PDB.",
                    suggestion=(
                        "Retry Download & Continue, or browse to a matching "
                        ".pdb / ISF file you already have."
                    ),
                    entity="volatility",
                    data=payload,
                )
            _progress(62, "Converting kernel symbols…")
            try:
                _convert_pdb_to_isf(
                    pdb_path,
                    dest,
                    pdb_name=pdb_name,
                    cancelled=cancelled,
                    progress=_progress,
                )
            except Exception:
                if dest.exists():
                    dest.unlink()
                raise
    except JobCancelled:
        raise job_cancelled_error()
    except AppError:
        raise
    except Exception as exc:
        log.exception(
            "kernel PDB conversion failed",
            extra={"channel": "tool"},
        )
        if dest.exists():
            dest.unlink()
        raise AppError(
            code="kernel_symbols_download_failed",
            message="The downloaded PDB could not be converted into Volatility symbols.",
            details=str(exc),
            suggestion=(
                "Retry Download & Continue, or browse to a matching .pdb / ISF "
                "file you already have."
            ),
            entity="volatility",
            data=payload,
        ) from exc
    if not dest.is_file() or dest.stat().st_size <= 0 or not _looks_like_isf(dest):
        if dest.exists():
            dest.unlink()
        raise AppError(
            code="kernel_symbols_download_failed",
            message="Kernel symbols could not be stored for this Windows build.",
            suggestion=(
                "Retry Download & Continue, or browse to a matching .pdb / ISF "
                "file you already have."
            ),
            entity="volatility",
            data=payload,
        )
    if progress is not None:
        progress(100, "Kernel symbols ready")
    return {"ok": True, "stored": str(dest), "source": "microsoft", **payload}


def run_kernel_symbols_fetch_job(
    db: Any,
    params: dict[str, Any],
    cancelled: Callable[[], bool],
    progress: Callable[[str, dict[str, Any] | None], None],
) -> dict[str, Any]:
    del db
    pdb_name = str(params.get("pdb_name") or "ntkrnlmp.pdb")
    guid = str(params.get("guid") or "")
    age = int(params.get("age") or 0)
    if not guid or age <= 0:
        raise AppError(
            code="invalid_params",
            message="Kernel symbol identity is missing.",
            entity="volatility",
        )

    def _cb(pct: float, description: str | None = None) -> None:
        try:
            value = float(pct)
        except (TypeError, ValueError):
            value = 0.0
        progress(
            description or "Downloading kernel symbols…",
            {"percent": max(0.0, min(100.0, value)), "phase": "kernel_symbols"},
        )

    return fetch_kernel_pdb(
        pdb_name=pdb_name,
        guid=guid,
        age=age,
        progress=_cb,
        cancelled=cancelled,
    )


def _pdb_filename(pdb_name: str) -> str:
    name = Path(str(pdb_name).strip() or "ntkrnlmp.pdb").name
    if not name.lower().endswith(".pdb"):
        name = f"{name}.pdb"
    return name


def _compound_suffix(filename: str) -> str:
    lower = filename.lower()
    for ext in (".json.xz", ".json.gz", ".pdb", ".json"):
        if lower.endswith(ext):
            return ext
    return Path(filename).suffix.lower()


def _validated_pdb_dest(path: str | Path) -> Path:
    dest = Path(str(path).strip()).expanduser()
    if not str(path).strip() or dest.as_posix() in {".", ""}:
        raise AppError(
            code="symbol_file_missing",
            message="Save location is empty.",
            entity="volatility",
        )
    if not dest.is_absolute():
        raise AppError(
            code="symbol_file_missing",
            message="Save location must be an absolute path.",
            entity="volatility",
        )
    if dest.is_dir():
        raise AppError(
            code="symbol_file_unsupported",
            message="Save location is a folder.",
            suggestion="Choose a .pdb file name.",
            entity="volatility",
        )
    if not dest.name.lower().endswith(".pdb"):
        dest = dest.with_name(f"{dest.name}.pdb")
    parent = dest.parent
    if parent is None or not parent.is_dir():
        raise AppError(
            code="symbol_file_missing",
            message="The save folder does not exist.",
            entity="volatility",
        )
    return dest


def _hostname(url: str) -> str:
    return (urlparse.urlparse(url).hostname or "").lower().rstrip(".")


def _is_msdl_symbol_url(url: str) -> bool:
    parsed = urlparse.urlparse(url)
    return (
        parsed.scheme == "https"
        and _hostname(url) == "msdl.microsoft.com"
        and parsed.path.startswith("/download/symbols/")
    )


def _is_azure_symbol_blob_url(url: str) -> bool:
    host = _hostname(url)
    return urlparse.urlparse(url).scheme == "https" and (
        host == "blob.core.windows.net" or host.endswith(".blob.core.windows.net")
    )


def _is_allowed_symbol_url(url: str) -> bool:
    return _is_msdl_symbol_url(url) or _is_azure_symbol_blob_url(url)


def _is_symbol_server_url(url: str) -> bool:
    return _is_msdl_symbol_url(url)


class _SymbolRedirectHandler(urlrequest.HTTPRedirectHandler):
    """Follow Microsoft's symbol-server 302s, including Azure Blob objects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not _is_allowed_symbol_url(str(newurl)):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_symbol_response(req: urlrequest.Request, timeout: float):
    https = urlrequest.HTTPSHandler(context=safe_https_context())
    opener = urlrequest.build_opener(_SymbolRedirectHandler(), https)
    return opener.open(req, timeout=timeout)


def _file_ptr_target(data: bytes) -> str | None:
    if len(data) > 4096:
        return None
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    if text.upper().startswith("PATH:"):
        text = text.split(":", 1)[1].strip()
    if text.startswith("https://") or text.startswith("http://"):
        return text.split()[0]
    return None


def _looks_like_pdb(data: bytes) -> bool:
    return data.startswith(_PDB_MAGIC)


def _looks_like_compressed_pdb(data: bytes) -> bool:
    return data.startswith(_COMPRESSED_MAGICS)


def _looks_like_html(data: bytes) -> bool:
    head = data.lstrip()[:64].lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html")


def _looks_like_isf(path: Path) -> bool:
    try:
        with lzma.open(path, "rt", encoding="utf-8") as handle:
            head = handle.read(64).lstrip()
    except (OSError, lzma.LZMAError, UnicodeDecodeError, ValueError):
        return False
    return head.startswith("{")


def _response_headers(handle: Any) -> Any:
    headers = getattr(handle, "headers", None)
    if headers is not None:
        return headers
    info = getattr(handle, "info", None)
    return info() if callable(info) else {}


def _incomplete_download_error() -> AppError:
    return AppError(
        code="kernel_symbols_download_failed",
        message="The kernel PDB download was incomplete.",
        suggestion="Retry Download & Continue.",
        entity="volatility",
    )


def _http_get_symbol_bytes(
    url: str,
    *,
    cancelled: Callable[[], bool] | None = None,
    timeout: float = _HTTP_TIMEOUT_SECS,
    progress: Callable[[float, str | None], None] | None = None,
    _seen: set[str] | None = None,
) -> bytes:
    initial = _seen is None
    if initial and not _is_msdl_symbol_url(url):
        raise AppError(
            code="kernel_symbols_download_failed",
            message="The symbol download URL is not Microsoft's symbol server.",
            entity="volatility",
        )
    if not initial and not _is_allowed_symbol_url(url):
        raise AppError(
            code="kernel_symbols_download_failed",
            message="The symbol server file pointer was not a Microsoft URL.",
            entity="volatility",
        )
    seen = _seen or set()
    if url in seen:
        raise AppError(
            code="kernel_symbols_download_failed",
            message="The symbol server returned a looping file pointer.",
            entity="volatility",
        )
    seen.add(url)

    last_error: Exception | None = None
    for attempt in range(_HTTP_RETRIES):
        if cancelled and cancelled():
            raise job_cancelled_error()
        req = urlrequest.Request(url, headers={"User-Agent": SYMBOL_USER_AGENT})
        chunks: list[bytes] = []
        total = 0
        expected = 0
        try:
            with _open_symbol_response(req, timeout) as handle:
                headers = _response_headers(handle)
                try:
                    expected = int(headers.get("Content-Length", 0) or 0)
                except (TypeError, ValueError, AttributeError):
                    expected = 0
                while True:
                    if cancelled and cancelled():
                        raise job_cancelled_error()
                    chunk = handle.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_PDB_BYTES:
                        raise AppError(
                            code="kernel_symbols_download_failed",
                            message="The kernel PDB download was larger than expected.",
                            entity="volatility",
                        )
                    chunks.append(chunk)
                    # Pointer files are tiny; reporting them as 0–100% rewinds
                    # the bar when the real Azure blob then starts at 0%.
                    if (
                        progress is not None
                        and expected > _PROGRESS_MIN_CONTENT_LENGTH
                    ):
                        progress(
                            min(100.0, total * 100.0 / expected),
                            "Downloading kernel symbols…",
                        )
        except AppError:
            raise
        except urlerror.HTTPError as exc:
            if int(getattr(exc, "code", 0) or 0) >= 500 and attempt + 1 < _HTTP_RETRIES:
                last_error = exc
                time.sleep(_HTTP_RETRY_SLEEP_SECS)
                continue
            raise AppError(
                code="kernel_symbols_download_failed",
                message="Microsoft's symbol server did not return this kernel PDB.",
                details=str(exc),
                entity="volatility",
            ) from exc
        except (urlerror.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt + 1 < _HTTP_RETRIES:
                time.sleep(_HTTP_RETRY_SLEEP_SECS)
                continue
            raise AppError(
                code="kernel_symbols_download_failed",
                message="Microsoft's symbol server did not return this kernel PDB.",
                details=str(exc),
                entity="volatility",
            ) from exc

        data = b"".join(chunks)
        target = _file_ptr_target(data)
        if target:
            if not _is_allowed_symbol_url(target):
                raise AppError(
                    code="kernel_symbols_download_failed",
                    message="The symbol server file pointer was not a Microsoft URL.",
                    entity="volatility",
                )
            return _http_get_symbol_bytes(
                target,
                cancelled=cancelled,
                timeout=timeout,
                progress=progress,
                _seen=seen,
            )
        if expected > 0 and total < expected:
            last_error = _incomplete_download_error()
            if attempt + 1 < _HTTP_RETRIES:
                time.sleep(_HTTP_RETRY_SLEEP_SECS)
                continue
            raise last_error
        if _looks_like_html(data):
            raise AppError(
                code="kernel_symbols_download_failed",
                message="Microsoft's symbol server returned a web page instead of a PDB.",
                entity="volatility",
            )
        return data

    if isinstance(last_error, AppError):
        raise last_error
    raise AppError(
        code="kernel_symbols_download_failed",
        message="Microsoft's symbol server did not return this kernel PDB.",
        details=str(last_error) if last_error else None,
        entity="volatility",
    ) from last_error


def _normalize_pdb_bytes(data: bytes, dest: Path) -> bytes:
    if _looks_like_compressed_pdb(data):
        data = _expand_compressed_pdb(data, dest)
    if _looks_like_pdb(data):
        return data
    raise AppError(
        code="kernel_symbols_download_failed",
        message="The downloaded file is not a kernel PDB.",
        suggestion=(
            "Retry Download & Continue, or browse to a .pdb / ISF file you already have."
        ),
        entity="volatility",
    )


def _expand_compressed_pdb(data: bytes, dest: Path) -> bytes:
    expand = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "expand.exe"
    if os.name != "nt" or not expand.is_file():
        raise AppError(
            code="kernel_symbols_download_failed",
            message="The PDB from Microsoft is compressed and could not be expanded.",
            suggestion="Use Download in Dumplyzer to convert this build automatically.",
            entity="volatility",
        )
    with tempfile.TemporaryDirectory(prefix="dumplyzer-pdb-") as tmp:
        src = Path(tmp) / "symbol.pd_"
        out = Path(tmp) / dest.name
        src.write_bytes(data)
        flags = _CREATE_NO_WINDOW if os.name == "nt" else 0
        completed = subprocess.run(
            [str(expand), str(src), str(out)],
            capture_output=True,
            timeout=60,
            check=False,
            creationflags=flags,
        )
        if completed.returncode != 0 or not out.is_file():
            raise AppError(
                code="kernel_symbols_download_failed",
                message="The compressed PDB from Microsoft could not be expanded.",
                suggestion="Use Download in Dumplyzer to convert this build automatically.",
                entity="volatility",
            )
        payload = out.read_bytes()
    if not payload:
        raise AppError(
            code="kernel_symbols_download_failed",
            message="The compressed PDB from Microsoft expanded to an empty file.",
            entity="volatility",
        )
    return payload


def _file_uri(path: Path) -> str:
    return Path(path).resolve().as_uri()


def _pdb_progress_cb(
    cancelled: Callable[[], bool] | None,
    progress: Callable[[float, str | None], None] | None,
) -> Callable[[float, str], None]:
    def _cb(percent: float, description: str) -> None:
        if cancelled and cancelled():
            raise JobCancelled()
        if progress is None:
            return
        try:
            value = float(percent or 0)
        except (TypeError, ValueError):
            value = 0.0
        progress(
            62.0 + min(33.0, max(0.0, value) * 0.33),
            description or "Converting kernel symbols…",
        )

    return _cb


def _load_pdb_msf_layer(context: Any, data: bytes) -> tuple[str, Any]:
    from volatility3.framework import interfaces
    from volatility3.framework.layers import msf, physical

    physical_layer_name = context.layers.free_layer_name("FileLayer")
    physical_config_path = interfaces.configuration.path_join(
        "pdbreader", physical_layer_name
    )
    new_context = context.clone()
    physical_layer = physical.BufferDataLayer(
        new_context,
        physical_config_path,
        physical_layer_name,
        buffer=data,
    )
    new_context.add_layer(physical_layer)

    msf_layer_name = context.layers.free_layer_name("MSFLayer")
    msf_config_path = interfaces.configuration.path_join("pdbreader", msf_layer_name)
    new_context.config[
        interfaces.configuration.path_join(msf_config_path, "base_layer")
    ] = physical_layer_name
    msf_layer = msf.PdbMultiStreamFormat(
        new_context, msf_config_path, msf_layer_name
    )
    new_context.add_layer(msf_layer)
    msf_layer.read_streams()
    return msf_layer_name, new_context


def _pdb_json(
    *,
    pdb_name: str,
    data: bytes | None = None,
    src: Path | None = None,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[float, str | None], None] | None = None,
) -> dict[str, Any]:
    from volatility3.framework import contexts
    from volatility3.framework.symbols.windows import pdbconv

    ctx = contexts.Context()
    callback = _pdb_progress_cb(cancelled, progress)
    location = "buffer:"
    original = pdbconv.PdbReader.load_pdb_layer
    if data is not None:

        def _from_buffer(cls: Any, context: Any, _location: str) -> tuple[str, Any]:
            del cls
            return _load_pdb_msf_layer(context, data)

        pdbconv.PdbReader.load_pdb_layer = classmethod(_from_buffer)  # type: ignore[method-assign]
    else:
        if src is None:
            raise ValueError("PDB source is required")
        location = _file_uri(src)
    try:
        return pdbconv.PdbReader(
            ctx,
            location,
            database_name=_pdb_filename(pdb_name),
            progress_callback=callback,
        ).get_json()
    finally:
        pdbconv.PdbReader.load_pdb_layer = original  # type: ignore[method-assign]


def _write_isf_json(dest: Path, converted: dict[str, Any]) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f"{dest.name}.tmp")
    try:
        with lzma.open(tmp, "wt", encoding="utf-8") as handle:
            json.dump(converted, handle, ensure_ascii=True, separators=(",", ":"))
        tmp.replace(dest)
    finally:
        if tmp.exists() and tmp != dest:
            tmp.unlink(missing_ok=True)


def _convert_pdb_to_isf(
    src: Path,
    dest: Path,
    *,
    pdb_name: str,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[float, str | None], None] | None = None,
) -> None:
    if cancelled and cancelled():
        raise job_cancelled_error()
    data = Path(src).read_bytes()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _CONVERT_LOCK:
        try:
            converted = _pdb_json(
                pdb_name=pdb_name,
                data=data,
                cancelled=cancelled,
                progress=progress,
            )
        except JobCancelled:
            raise
        except Exception as exc:
            log.warning(
                "in-memory kernel PDB convert failed: %s",
                exc,
                extra={"channel": "tool"},
            )
            converted = _pdb_json(
                pdb_name=pdb_name,
                src=Path(src),
                cancelled=cancelled,
                progress=progress,
            )
    _write_isf_json(dest, converted)
