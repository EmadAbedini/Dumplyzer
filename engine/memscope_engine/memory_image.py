"""Identify memory dumps from file contents. The filename is never used."""

from __future__ import annotations

import gzip
import io
import lzma
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from memscope_engine.errors import AppError

NOT_MEMORY_IMAGE_CODE = "evidence_not_memory_image"
NOT_MEMORY_IMAGE_MESSAGE = "This file is not a memory dump!"
NOT_MEMORY_IMAGE_SUGGESTION = (
    "Select a real memory image (Windows crash dump, raw physical memory, LiME, or ELF core)"
)

# Volatility 3 layer magics (content only).
_PAGE_SIGNATURE = 0x45474150  # "PAGE"
_PAGE_VALID_32 = 0x504D5544  # "DUMP" → PAGEDUMP
_PAGE_VALID_64 = 0x34365544  # "DU64" → PAGEDU64
_LIME_MAGIC = 0x4C694D45
_LIME_VERSION = 1
_QEMU_MAGIC = b"\x51\x45\x56\x4d"  # QEVM
_QEMU_VERSION = b"\x00\x00\x00\x03"
_VMWARE_MAGICS = (
    b"\xd0\xbe\xd2\xbe",
    b"\xd1\xba\xd1\xba",
    b"\xd2\xbe\xd2\xbe",
    b"\xd3\xbe\xd3\xbe",
)
_HIBER_MAGICS = (b"hibr", b"HIBR", b"wake", b"WAKE", b"RSTM")
_ELF_ET_CORE = 4
_MACHO_CORE = 4
_MACHO_MAGICS = {
    0xFEEDFACE: "<",
    0xFEEDFACF: "<",
    0xCEFAEDFE: ">",
    0xCFFAEDFE: ">",
}

_KNOWN_DUMP_FORMATS = frozenset(
    {
        "windows_crashdump",
        "minidump",
        "lime",
        "elf_core",
        "macho_core",
        "hibernation",
        "qemu",
        "vmware_snapshot",
        "aff4",
    }
)

_FORMAT_LABELS = {
    "windows_crashdump": "a Windows crash dump",
    "minidump": "a Windows minidump",
    "lime": "a LiME memory image",
    "elf_core": "an ELF core dump",
    "macho_core": "a Mach-O core dump",
    "hibernation": "a Windows hibernation file",
    "qemu": "a QEMU suspend image",
    "vmware_snapshot": "a VMware snapshot",
    "aff4": "an AFF4 memory image",
    "possible_raw": "raw physical memory",
    "pe": "a Windows executable (PE)",
    "elf": "an ELF executable or library",
    "macho": "a Mach-O executable or library",
    "pdf": "a PDF document",
    "zip": "a ZIP archive or Office document",
    "ole": "an Office document",
    "png": "a PNG image",
    "jpeg": "a JPEG image",
    "gif": "a GIF image",
    "webp": "a WebP image",
    "bmp": "a bitmap image",
    "riff": "a RIFF media file",
    "mp4": "a media file",
    "7z": "a 7-Zip archive",
    "rar": "a RAR archive",
    "cab": "a Cabinet archive",
    "sqlite": "a SQLite database",
    "pcap": "a packet capture",
    "html": "an HTML or XML document",
    "json": "a JSON document",
    "text": "a text document",
}

_PREFIX = 65536
_OS_LAYER_HINTS = (
    "intel",
    "windows",
    "linux",
    "mac",
    "darwin",
    "crash",
    "lime",
    "qemu",
    "vmware",
    "hiber",
    "avml",
    "arm",
    "pagedump",
    "elfcore",
    "core dump",
)


@dataclass(frozen=True)
class ImageClassification:
    is_memory_image: bool
    format_id: str
    reason: str

    @property
    def known_dump_format(self) -> bool:
        return self.format_id in _KNOWN_DUMP_FORMATS


def classify_memory_image(path: Path) -> ImageClassification:
    """Classify by contents. Does not inspect the filename or suffix."""
    with path.open("rb") as f:
        head = f.read(_PREFIX)
    return _classify_bytes(head, path=path)


def require_memory_image(path: Path) -> ImageClassification:
    classification = classify_memory_image(path)
    if classification.is_memory_image:
        return classification
    raise not_memory_image_error(classification)


def not_memory_image_error(
    classification: ImageClassification | None = None,
    *,
    details: str | None = None,
) -> AppError:
    label = _FORMAT_LABELS.get(classification.format_id, "") if classification else ""
    if details is None:
        if label and classification and not classification.is_memory_image:
            details = (
                f"The file contents look like {label}, not a memory image. "
                "The filename is ignored."
            )
        else:
            details = (
                "The file contents could not be identified as a memory image. "
                "The filename is ignored."
            )
    return AppError(
        code=NOT_MEMORY_IMAGE_CODE,
        message=NOT_MEMORY_IMAGE_MESSAGE,
        details=details,
        suggestion=NOT_MEMORY_IMAGE_SUGGESTION,
        entity="evidence",
        data={"format": classification.format_id if classification else None},
    )


def context_has_os_memory_layer(context: Any) -> bool:
    """True when Volatility stacked an OS/CPU translation layer, not just a file."""
    try:
        names = list(context.layers)
    except Exception:
        return False
    for name in names:
        blob = str(name).lower()
        try:
            layer = context.layers[name]
            blob += " " + type(layer).__name__.lower()
            blob += " " + type(layer).__module__.lower()
        except Exception:
            pass
        if "filelayer" in blob.replace(" ", "") and not any(
            hint in blob for hint in ("crash", "lime", "qemu", "intel", "windows", "linux")
        ):
            continue
        if any(hint in blob for hint in _OS_LAYER_HINTS):
            return True
    return False


def app_error_for_unsatisfied(
    image_path: Path,
    unsatisfied: list[str],
    plugin_name: str,
    context: Any | None = None,
) -> AppError:
    """Map Volatility requirement failures to a user-facing error."""
    try:
        classification = classify_memory_image(image_path)
    except OSError:
        classification = ImageClassification(True, "possible_raw", "unreadable during classify")

    if not classification.is_memory_image:
        return not_memory_image_error(classification)

    stacked = context_has_os_memory_layer(context) if context is not None else False
    if not stacked and not classification.known_dump_format:
        return not_memory_image_error(
            classification,
            details=(
                "The file contents could not be identified as a memory image. "
                "The filename is ignored."
            ),
        )

    unsat = [str(x) for x in unsatisfied]
    from memscope_engine.volatility.runtime import symbol_hint_dir, unsatisfied_looks_like_symbols

    symbols_dir = symbol_hint_dir()
    if unsatisfied_looks_like_symbols(unsat):
        from memscope_engine.volatility.kernel_symbols import maybe_kernel_symbols_error

        needed = maybe_kernel_symbols_error()
        if needed is not None:
            return needed
        message = (
            "Volatility could not resolve kernel symbol tables for this memory dump."
        )
        suggestion = (
            "Windows dumps need the kernel PDB or ISF for that exact build "
            f"(.pdb, .json, .json.xz, or .json.gz) under {symbols_dir}\\windows. "
            "Linux/macOS dumps need an ISF you provide in the linux or mac folder."
        )
    else:
        message = (
            "Volatility analysis failed because plugin requirements "
            "could not be satisfied."
        )
        suggestion = (
            "Verify the image is a supported memory dump and matches the plugin OS "
            f"(Windows vs Linux). Local symbol tables can be placed under {symbols_dir}."
        )
    return AppError(
        code="volatility_unsatisfied",
        message=message,
        details="; ".join(unsat) if unsat else None,
        suggestion=suggestion,
        entity="volatility",
        data={"unsatisfied": unsat, "plugin": plugin_name, "symbols_dir": symbols_dir},
    )


def _classify_bytes(head: bytes, *, path: Path | None = None) -> ImageClassification:
    if not head:
        return ImageClassification(False, "empty", "empty prefix")

    dump = _match_dump_magic(head)
    if dump is not None:
        return dump

    wrapped = _classify_compressed(head, path=path)
    if wrapped is not None:
        return wrapped

    other = _match_non_dump_magic(head)
    if other is not None:
        return other

    if _looks_like_text(head):
        return ImageClassification(False, "text", "printable text document")

    return ImageClassification(True, "possible_raw", "no identifying header; may be raw physical memory")


def _match_dump_magic(head: bytes) -> ImageClassification | None:
    if len(head) >= 8:
        sig, valid = struct.unpack_from("<II", head, 0)
        if sig == _PAGE_SIGNATURE and valid in (_PAGE_VALID_32, _PAGE_VALID_64):
            return ImageClassification(True, "windows_crashdump", "PAGEDUMP header")
    if head.startswith(b"MDMP"):
        return ImageClassification(True, "minidump", "MDMP header")
    if _is_lime(head):
        return ImageClassification(True, "lime", "LiME header")
    if _elf_type(head) == _ELF_ET_CORE:
        return ImageClassification(True, "elf_core", "ELF ET_CORE")
    if _macho_filetype(head) == _MACHO_CORE:
        return ImageClassification(True, "macho_core", "Mach-O MH_CORE")
    if len(head) >= 4 and head[:4] in _HIBER_MAGICS:
        return ImageClassification(True, "hibernation", "hibernation signature")
    if len(head) >= 8 and head[:4] == _QEMU_MAGIC and head[4:8] == _QEMU_VERSION:
        return ImageClassification(True, "qemu", "QEVM header")
    if len(head) >= 4 and head[:4] in _VMWARE_MAGICS:
        return ImageClassification(True, "vmware_snapshot", "VMware snapshot magic")
    if head.startswith(b"PK\x03\x04") and _zip_looks_like_aff4(head):
        return ImageClassification(True, "aff4", "AFF4 ZIP container")
    if b"aff4://" in head[:4096]:
        return ImageClassification(True, "aff4", "AFF4 URI marker")
    return None


def _match_non_dump_magic(head: bytes) -> ImageClassification | None:
    if head.startswith(b"MZ"):
        return ImageClassification(False, "pe", "MZ/PE executable")
    elf_type = _elf_type(head)
    if elf_type is not None and elf_type != _ELF_ET_CORE:
        return ImageClassification(False, "elf", "ELF non-core")
    macho = _macho_filetype(head)
    if macho is not None and macho != _MACHO_CORE:
        return ImageClassification(False, "macho", "Mach-O non-core")
    if head.startswith(b"%PDF"):
        return ImageClassification(False, "pdf", "PDF")
    if head.startswith(b"PK\x03\x04"):
        return ImageClassification(False, "zip", "ZIP/Office archive")
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return ImageClassification(False, "ole", "OLE compound document")
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return ImageClassification(False, "png", "PNG")
    if head.startswith(b"\xff\xd8\xff"):
        return ImageClassification(False, "jpeg", "JPEG")
    if head.startswith((b"GIF87a", b"GIF89a")):
        return ImageClassification(False, "gif", "GIF")
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return ImageClassification(False, "webp", "WebP")
    if head.startswith(b"BM"):
        return ImageClassification(False, "bmp", "BMP")
    if head.startswith(b"RIFF"):
        return ImageClassification(False, "riff", "RIFF")
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return ImageClassification(False, "mp4", "ISO BMFF")
    if head.startswith(b"7z\xbc\xaf'\x1c"):
        return ImageClassification(False, "7z", "7z")
    if head.startswith((b"Rar!\x1a\x07", b"Rar!\x1a\x07\x01\x00")):
        return ImageClassification(False, "rar", "RAR")
    if head.startswith(b"MSCF"):
        return ImageClassification(False, "cab", "CAB")
    if head.startswith(b"SQLite format 3\x00"):
        return ImageClassification(False, "sqlite", "SQLite")
    if head.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")):
        return ImageClassification(False, "pcap", "PCAP")
    if head.startswith(b"\x0a\x0d\x0d\x0a"):
        return ImageClassification(False, "pcap", "PCAPNG")
    stripped = head.lstrip()
    if stripped.startswith((b"<!DOCTYPE", b"<html", b"<HTML", b"<?xml", b"<svg")):
        return ImageClassification(False, "html", "HTML/XML")
    if stripped.startswith((b"{", b"[")):
        return ImageClassification(False, "json", "JSON")
    return None


def _classify_compressed(head: bytes, *, path: Path | None) -> ImageClassification | None:
    inner: bytes | None = None
    if head.startswith(b"\x1f\x8b"):
        inner = _decompress_gzip(path, head)
    elif head.startswith(b"\xfd7zXZ\x00"):
        inner = _decompress_xz(path, head)
    elif head.startswith(b"BZh"):
        inner = _decompress_bz2(path, head)
    if inner is None:
        return None
    nested = _classify_bytes(inner, path=None)
    if nested.format_id == "possible_raw":
        return ImageClassification(True, "possible_raw", "compressed prefix; inner has no dump header")
    return nested


def _decompress_gzip(path: Path | None, head: bytes) -> bytes | None:
    try:
        if path is not None:
            with path.open("rb") as f, gzip.GzipFile(fileobj=f) as gz:
                return gz.read(_PREFIX)
        with gzip.GzipFile(fileobj=io.BytesIO(head)) as gz:
            return gz.read(_PREFIX)
    except (OSError, EOFError, gzip.BadGzipFile):
        return None


def _decompress_xz(path: Path | None, head: bytes) -> bytes | None:
    try:
        if path is not None:
            with path.open("rb") as f, lzma.open(f) as xf:
                return xf.read(_PREFIX)
        return lzma.decompress(head)[:_PREFIX]
    except (OSError, EOFError, lzma.LZMAError):
        return None


def _decompress_bz2(path: Path | None, head: bytes) -> bytes | None:
    import bz2

    try:
        if path is not None:
            with path.open("rb") as f, bz2.open(f) as bf:
                return bf.read(_PREFIX)
        return bz2.decompress(head)[:_PREFIX]
    except (OSError, EOFError, ValueError):
        return None


def _is_lime(head: bytes) -> bool:
    if len(head) < 32:
        return False
    magic, version, start, end, _reserved = struct.unpack_from("<IIQQQ", head, 0)
    if magic != _LIME_MAGIC or version != _LIME_VERSION:
        return False
    return end >= start


def _elf_type(head: bytes) -> int | None:
    if len(head) < 18 or head[:4] != b"\x7fELF":
        return None
    if head[5] == 1:
        endian = "<"
    elif head[5] == 2:
        endian = ">"
    else:
        return None
    return int(struct.unpack_from(endian + "H", head, 16)[0])


def _macho_filetype(head: bytes) -> int | None:
    if len(head) < 16:
        return None
    magic = struct.unpack_from("<I", head, 0)[0]
    endian = _MACHO_MAGICS.get(magic)
    if endian is None:
        magic_be = struct.unpack_from(">I", head, 0)[0]
        endian = _MACHO_MAGICS.get(magic_be)
        if endian is None:
            return None
    return int(struct.unpack_from(endian + "I", head, 12)[0])


def _zip_looks_like_aff4(head: bytes) -> bool:
    sample = head[:8192]
    if b"aff4://" in sample or b"information.turtle" in sample:
        return True
    offset = 0
    for _ in range(12):
        idx = head.find(b"PK\x03\x04", offset)
        if idx < 0 or idx + 30 > len(head):
            break
        name_len = struct.unpack_from("<H", head, idx + 26)[0]
        extra_len = struct.unpack_from("<H", head, idx + 28)[0]
        name_start = idx + 30
        name_end = name_start + name_len
        if name_end > len(head):
            break
        name = head[name_start:name_end].lower()
        if b"aff4" in name or name.endswith(b".turtle"):
            return True
        flags = struct.unpack_from("<H", head, idx + 6)[0]
        extra_end = name_end + extra_len
        if flags & 0x08:
            offset = extra_end
        else:
            comp_size = struct.unpack_from("<I", head, idx + 18)[0]
            offset = extra_end + comp_size
    return False


def _looks_like_text(head: bytes) -> bool:
    sample = head[:1024]
    if not sample:
        return False
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in sample:
        return False
    printable = 0
    has_space = False
    for byte in sample:
        if byte in (9, 10, 13, 32):
            printable += 1
            has_space = True
        elif 32 < byte < 127:
            printable += 1
        else:
            return False
    if printable < len(sample):
        return False
    return has_space
