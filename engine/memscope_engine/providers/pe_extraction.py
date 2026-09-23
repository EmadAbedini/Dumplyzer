"""PE Extraction provider: identify and classify PE images from memory dumps.

This provider does not invoke an external EXE. It exposes availability for the
Volatility 3 PE reconstruction workflow and pure helpers used by tests and the
extraction job (filename uniqueness, PE classification, candidate identification).

Extracted files are labeled as extracted PE artifacts, never as malware.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from memscope_engine.artifacts.store import sanitize_component
from memscope_engine.providers.process_run import unique_path

METHOD_PROCESS_IMAGE = "volatility3.windows.pedump.process_image"
METHOD_LOADED_MODULE = "volatility3.windows.pedump.loaded_module"
METHOD_MAPPED_PE = "volatility3.windows.pedump.mapped_image"
METHOD_UNLINKED = "volatility3.windows.pedump.unlinked_mapped"
METHOD_CACHED_FILE = "volatility3.windows.dumpfiles.pe"

IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_MACHINE_ARM = 0x1C0

DEFAULT_METHODS = (
    METHOD_PROCESS_IMAGE,
    METHOD_LOADED_MODULE,
    METHOD_MAPPED_PE,
    METHOD_UNLINKED,
)
OPTIONAL_METHODS = (METHOD_CACHED_FILE,)
EXTRACTION_METHODS = DEFAULT_METHODS + OPTIONAL_METHODS


def classify_pe_bytes(data: bytes) -> dict[str, Any]:
    """Classify bytes as PE EXE / DLL / unknown. Does not execute anything.

    A valid PE requires an MZ header, a PE signature, and a successful parse.
    MZ-only blobs are not stored as extracted PE artifacts.
    """
    if not data or len(data) < 64 or data[:2] != b"MZ":
        return {"is_pe": False, "pe_kind": None, "parse_ok": False}
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew < 0x40 or e_lfanew + 4 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return {
            "is_pe": False,
            "pe_kind": None,
            "parse_ok": False,
            "reason": "missing_pe_signature",
        }
    try:
        import pefile

        pe = pefile.PE(data=data, fast_load=True)
        chars = int(pe.FILE_HEADER.Characteristics)
        is_dll = bool(chars & IMAGE_FILE_DLL)
        kind = "dll" if is_dll else "exe"
        machine = int(pe.FILE_HEADER.Machine)
        return {
            "is_pe": True,
            "pe_kind": kind,
            "parse_ok": True,
            "characteristics": chars,
            "machine": machine,
            "architecture": _machine_architecture(machine),
            "is_dll": is_dll,
            "is_executable_image": bool(chars & IMAGE_FILE_EXECUTABLE_IMAGE),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "is_pe": False,
            "pe_kind": None,
            "parse_ok": False,
            "parse_error": f"{type(exc).__name__}: {exc}",
        }


def _machine_architecture(machine: int) -> str:
    mapping = {
        IMAGE_FILE_MACHINE_I386: "x86",
        IMAGE_FILE_MACHINE_AMD64: "x64",
        IMAGE_FILE_MACHINE_ARM64: "arm64",
        IMAGE_FILE_MACHINE_ARM: "arm",
    }
    return mapping.get(int(machine), "unknown")


def identify_pe_candidates(
    *,
    processes: list[dict[str, Any]] | None = None,
    modules: list[dict[str, Any]] | None = None,
    vads: list[dict[str, Any]] | None = None,
    cached_files: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Identify PE extraction candidates from already-normalized records.

    This does not dump bytes. It encodes which PE classes Dumplyzer will try to
    extract: process images, loaded DLLs, mapped PE, unlinked/manual-mapped MZ
    regions, and cached FILE_OBJECT PE files.
    """
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for proc in processes or []:
        pid = proc.get("pid")
        key = ("process_image", pid, proc.get("image_base") or proc.get("offset_hex"))
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "kind": "process_image",
                "pe_kind_hint": "exe",
                "pid": pid,
                "process_name": proc.get("name") or proc.get("process_name"),
                "original_path": proc.get("image_path") or proc.get("path"),
                "base_address": proc.get("image_base"),
                "extraction_method": METHOD_PROCESS_IMAGE,
                "source_plugin": "windows.pslist+windows.pedump",
            }
        )

    process_names = {
        p.get("pid"): (p.get("name") or p.get("process_name")) for p in (processes or [])
    }
    exe_bases = {
        (p.get("pid"), _as_int(p.get("image_base")))
        for p in (processes or [])
        if p.get("image_base") is not None
    }

    for mod in modules or []:
        pid = mod.get("pid")
        name = str(mod.get("name") or "")
        path = str(mod.get("path") or "")
        base = _as_int(mod.get("base_address"))
        lower = f"{name} {path}".lower()
        is_dll = lower.endswith(".dll") or ".dll" in lower
        is_exe = lower.endswith(".exe") or ".exe" in path.lower()
        if is_exe and not is_dll and (pid, base) in exe_bases:
            continue
        if is_exe and not is_dll:
            continue
        key = ("loaded_module", pid, base, name.lower())
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "kind": "loaded_module",
                "pe_kind_hint": "dll" if is_dll or not is_exe else "exe",
                "pid": pid,
                "process_name": process_names.get(pid) or mod.get("process_name"),
                "original_path": path or name,
                "base_address": base,
                "extraction_method": METHOD_LOADED_MODULE,
                "source_plugin": "windows.dlllist+windows.pedump",
            }
        )

    for vad in vads or []:
        if not vad.get("has_mz"):
            continue
        pid = vad.get("pid")
        start = vad.get("start_vpn") or vad.get("start")
        key = ("vad", pid, start)
        if key in seen:
            continue
        seen.add(key)
        file_path = vad.get("file_path")
        private = vad.get("private_memory") in (1, True)
        prot = str(vad.get("protection") or "").upper()
        has_exec = "EXECUTE" in prot or "EXEC" in prot
        tag = str(vad.get("tag") or "").lower()
        if file_path or "image" in tag:
            kind = "mapped_pe"
            method = METHOD_MAPPED_PE
        elif private and (has_exec or True):
            kind = "unlinked_mapped"
            method = METHOD_UNLINKED
        else:
            continue
        candidates.append(
            {
                "kind": kind,
                "pe_kind_hint": _hint_from_path(file_path),
                "pid": pid,
                "process_name": vad.get("process_name"),
                "original_path": file_path,
                "base_address": start,
                "start_vpn": vad.get("start_vpn") or vad.get("start"),
                "end_vpn": vad.get("end_vpn") or vad.get("end"),
                "extraction_method": method,
                "source_plugin": "windows.vadinfo+windows.pedump",
            }
        )

    for cached in cached_files or []:
        if cached.get("is_pe") is False:
            continue
        name = cached.get("name") or cached.get("filename") or cached.get("path")
        key = ("cached_file", cached.get("pid"), name)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "kind": "cached_file",
                "pe_kind_hint": _hint_from_path(name),
                "pid": cached.get("pid"),
                "process_name": cached.get("process_name"),
                "original_path": cached.get("path") or name,
                "base_address": cached.get("base_address"),
                "extraction_method": METHOD_CACHED_FILE,
                "source_plugin": "windows.dumpfiles",
            }
        )
    return candidates


def _hint_from_path(path: str | None) -> str:
    if not path:
        return "unknown"
    lower = path.lower()
    if lower.endswith(".dll") or lower.endswith(".sys"):
        return "dll"
    if lower.endswith(".exe"):
        return "exe"
    return "unknown"


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s, 16) if any(c in s for c in "abcdef") else int(s)
    except ValueError:
        return None


def build_pe_filename(
    *,
    pid: int | None,
    pe_kind: str,
    original_name: str | None,
    base_address: int | str | None,
    method: str,
) -> str:
    ext = "dll" if pe_kind == "dll" else "exe"
    raw_name = original_name or method
    try:
        stem = Path(str(raw_name).replace("\\", "/")).name
    except Exception:  # noqa: BLE001
        stem = str(raw_name)
    stem = sanitize_component(Path(stem).stem or method, max_len=48)
    addr = _as_int(base_address)
    addr_s = f"{addr:x}" if addr is not None else "unk"
    method_s = sanitize_component(method, max_len=24)
    pid_s = str(pid if pid is not None else "unk")
    return f"pid{pid_s}_{method_s}_{stem}_{addr_s}.{ext}"


def unique_pe_path(
    directory: Path,
    *,
    pid: int | None,
    pe_kind: str,
    original_name: str | None,
    base_address: int | str | None,
    method: str,
) -> Path:
    name = build_pe_filename(
        pid=pid,
        pe_kind=pe_kind,
        original_name=original_name,
        base_address=base_address,
        method=method,
    )
    return unique_path(directory, name)


class PeExtractionProvider:
    """Volatility-backed PE extraction capability."""

    name: str = "pe_extraction"

    def availability(self) -> dict[str, Any]:
        vol_ver = None
        pedump = False
        reason = None
        suggestion = None
        try:
            vol_ver = version("volatility3")
        except PackageNotFoundError as exc:
            reason = f"Volatility 3 is not installed ({type(exc).__name__})."
            suggestion = "Reinstall Dumplyzer so the bundled Volatility 3 runtime is present."
            return self._base(False, vol_ver, pedump, reason, suggestion)
        # Same Volatility 3 wheel. Do not import windows.pedump here.
        pedump = True
        if not pedump:
            reason = "Volatility 3 windows.pedump is not available."
            suggestion = "PE reconstruction requires windows.pedump from Volatility 3."
            return self._base(False, vol_ver, pedump, reason, suggestion)
        return self._base(True, vol_ver, pedump, None, None)

    def _base(
        self,
        available: bool,
        vol_ver: str | None,
        pedump: bool,
        reason: str | None,
        suggestion: str | None,
    ) -> dict[str, Any]:
        return {
            "provider": self.name,
            "available": available,
            "reason": reason,
            "suggestion": suggestion,
            "volatility_version": vol_ver,
            "pedump_available": pedump,
            "target": "memory_dump",
            "supported_target_kinds": ["memory_image"],
            "produces": "extracted_pe_artifact",
            "not_a_malware_verdict": True,
            "methods": list(DEFAULT_METHODS),
            "optional_methods": list(OPTIONAL_METHODS),
            "dumpfiles_default": False,
            "notes": (
                "Reconstructs PE images from process memory using Volatility 3 "
                "windows.pedump (process image, loaded modules, mapped PE, "
                "unlinked/manual-mapped MZ regions). windows.dumpfiles is an "
                "optional fallback and is not used for normal PE extraction. "
                "Extracted files are not executed and are not labeled malware."
            ),
        }

    def configure(self, settings: dict[str, Any]) -> dict[str, Any]:
        return self.availability()
