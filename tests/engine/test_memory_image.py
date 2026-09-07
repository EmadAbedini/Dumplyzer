"""Memory-image identification from file contents (filename is ignored)."""

from __future__ import annotations

import gzip
import io
import struct
from pathlib import Path
from zipfile import ZipFile, ZIP_STORED

import pytest

from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.errors import AppError
from memscope_engine.memory_image import (
    NOT_MEMORY_IMAGE_CODE,
    NOT_MEMORY_IMAGE_MESSAGE,
    classify_memory_image,
    require_memory_image,
)
from memscope_engine.storage import Database


def _elf(e_type: int) -> bytes:
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2
    head[5] = 1
    head[6] = 1
    struct.pack_into("<H", head, 16, e_type)
    return bytes(head)


def _lime() -> bytes:
    return struct.pack("<IIQQQ", 0x4C694D45, 1, 0, 0xFFF, 0) + b"\x00" * 32


def test_crashdump_and_minidump_headers(tmp_path: Path) -> None:
    crash = tmp_path / "photo.jpg"
    crash.write_bytes(b"PAGEDU64" + b"\x00" * 32)
    assert classify_memory_image(crash).format_id == "windows_crashdump"
    assert classify_memory_image(crash).is_memory_image

    mini = tmp_path / "notes.txt"
    mini.write_bytes(b"MDMP" + b"\x00" * 32)
    assert classify_memory_image(mini).format_id == "minidump"


def test_lime_elf_core_qemu(tmp_path: Path) -> None:
    lime = tmp_path / "data.bin"
    lime.write_bytes(_lime())
    assert classify_memory_image(lime).format_id == "lime"

    core = tmp_path / "app.exe"
    core.write_bytes(_elf(4))
    assert classify_memory_image(core).format_id == "elf_core"

    qemu = tmp_path / "save.dat"
    qemu.write_bytes(b"QEVM\x00\x00\x00\x03" + b"\x00" * 16)
    assert classify_memory_image(qemu).format_id == "qemu"


def test_rejects_pe_pdf_zip_elf_text_by_contents(tmp_path: Path) -> None:
    pe = tmp_path / "memory.dmp"
    pe.write_bytes(b"MZ" + b"\x00" * 64)
    pdf = tmp_path / "dump.raw"
    pdf.write_bytes(b"%PDF-1.7\n1 0 obj")
    png = tmp_path / "case.mem"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    elf = tmp_path / "linux.lime"
    elf.write_bytes(_elf(3))
    text = tmp_path / "hiberfil.sys.dmp"
    text.write_bytes(b"This is a renamed text file, not a dump.\n")
    zpath = tmp_path / "image.vmem"
    buf = io.BytesIO()
    with ZipFile(buf, "w", ZIP_STORED) as zf:
        zf.writestr("readme.txt", "hello")
    zpath.write_bytes(buf.getvalue())

    for path, fmt in (
        (pe, "pe"),
        (pdf, "pdf"),
        (png, "png"),
        (elf, "elf"),
        (text, "text"),
        (zpath, "zip"),
    ):
        got = classify_memory_image(path)
        assert got.is_memory_image is False, path
        assert got.format_id == fmt, path
        with pytest.raises(AppError) as exc:
            require_memory_image(path)
        assert exc.value.code == NOT_MEMORY_IMAGE_CODE
        assert exc.value.message == NOT_MEMORY_IMAGE_MESSAGE


def test_import_rejects_renamed_executable(tmp_path: Path) -> None:
    fake = tmp_path / "evidence.dmp"
    fake.write_bytes(b"MZ" + b"PE\x00\x00" + b"\x00" * 128)
    db = Database(tmp_path / "t.db")
    with pytest.raises(AppError) as exc:
        import_evidence(db, str(fake))
    assert exc.value.code == NOT_MEMORY_IMAGE_CODE
    assert "not a memory dump" in exc.value.message.lower()
    assert "filename" in (exc.value.details or "").lower()
    assert db.fetchall("SELECT id FROM evidence") == []
    db.close()


def test_import_still_accepts_headerless_raw_bytes(tmp_path: Path) -> None:
    img = tmp_path / "sample.raw"
    img.write_bytes(b"MEMSCOPE-TEST-BYTES-0123456789")
    db = Database(tmp_path / "t.db")
    ev = import_evidence(db, str(img))
    assert ev["filename"] == "sample.raw"
    db.close()


def test_gzip_inner_pe_rejected_gzip_crashdump_accepted(tmp_path: Path) -> None:
    pe_gz = tmp_path / "wrapped.dmp"
    with gzip.open(pe_gz, "wb") as f:
        f.write(b"MZ" + b"\x00" * 32)
    assert classify_memory_image(pe_gz).is_memory_image is False

    dump_gz = tmp_path / "real.dmp"
    with gzip.open(dump_gz, "wb") as f:
        f.write(b"PAGEDUMP" + b"\x00" * 32)
    assert classify_memory_image(dump_gz).format_id == "windows_crashdump"


def test_aff4_zip_accepted_office_zip_rejected(tmp_path: Path) -> None:
    aff4 = tmp_path / "case.zip"
    buf = io.BytesIO()
    with ZipFile(buf, "w", ZIP_STORED) as zf:
        zf.writestr("information.turtle", "@prefix aff4: <aff4://example/> .")
    aff4.write_bytes(buf.getvalue())
    assert classify_memory_image(aff4).format_id == "aff4"

    xlsx = tmp_path / "sheet.dmp"
    buf = io.BytesIO()
    with ZipFile(buf, "w", ZIP_STORED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
    xlsx.write_bytes(buf.getvalue())
    assert classify_memory_image(xlsx).format_id == "zip"
    assert classify_memory_image(xlsx).is_memory_image is False


def test_unsatisfied_helper_uses_contents_not_name(tmp_path: Path) -> None:
    from memscope_engine.memory_image import app_error_for_unsatisfied

    pe = tmp_path / "win10.dmp"
    pe.write_bytes(b"MZ" + b"\x00" * 64)
    err = app_error_for_unsatisfied(pe, ["plugins.Info.kernel"], "windows.info.Info")
    assert err.code == NOT_MEMORY_IMAGE_CODE
    assert err.message == NOT_MEMORY_IMAGE_MESSAGE
