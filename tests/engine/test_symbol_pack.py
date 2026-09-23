"""Per-build kernel symbols: no auto 800 MB pack, consent before PDB fetch."""

from __future__ import annotations

import json
from pathlib import Path

from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.volatility.kernel_symbols import (
    fetch_kernel_pdb,
    import_user_symbol_file,
    kernel_symbols_required_error,
    microsoft_compressed_pdb_url,
    microsoft_pdb_url,
    requirement_payload,
    save_microsoft_pdb,
    _file_uri,
    _is_allowed_symbol_url,
    _looks_like_pdb,
    _SymbolRedirectHandler,
)
from memscope_engine.volatility.runtime import (
    last_needed_kernel,
    pdb_download_allowed,
    record_needed_kernel,
    set_pdb_download_allowed,
)
from memscope_engine.volatility.symbol_pack import (
    WINDOWS_ZIP_SHA256,
    image_may_need_windows_pack,
    pack_is_ready,
)


def test_manifest_pins_windows_zip_and_does_not_bundle_it() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (root / "packaging" / "windows" / "runtime-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    pack = manifest["windows_symbols"]
    assert pack["bundled"] is False
    assert pack["sha256"] == WINDOWS_ZIP_SHA256


def test_copied_zip_without_marker_is_promoted(monkeypatch, tmp_path: Path) -> None:
    from memscope_engine.volatility import symbol_pack as sp
    import hashlib

    payload = b"copied-windows-zip"
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(sp, "WINDOWS_ZIP_BYTES", len(payload))
    monkeypatch.setattr(sp, "WINDOWS_ZIP_SHA256", digest)
    paths = AppPaths(tmp_path / "Dumplyzer").ensure()
    dest = paths.symbols / "windows.zip"
    dest.write_bytes(payload)
    assert pack_is_ready(paths) is True


def test_image_may_need_windows_pack(tmp_path: Path) -> None:
    import struct

    crash = tmp_path / "memory.dmp"
    crash.write_bytes(b"PAGEDU64" + b"\x00" * 32)
    lime = tmp_path / "linux.lime"
    lime.write_bytes(struct.pack("<IIQQQ", 0x4C694D45, 1, 0, 0xFFF, 0) + b"\x00" * 32)
    pe = tmp_path / "not-a-dump.bin"
    pe.write_bytes(b"MZ" + b"\x00" * 64)
    assert image_may_need_windows_pack(crash) is True
    assert image_may_need_windows_pack(lime) is False
    assert image_may_need_windows_pack(pe) is False


def test_requirement_payload_names_pdb_and_isf() -> None:
    data = requirement_payload("ntkrnlmp.pdb", "aabbccdd", 1)
    assert data["filename_pdb"] == "ntkrnlmp.pdb"
    assert data["filename_isf"] == "AABBCCDD-1.json.xz"
    assert data["download_url"] == microsoft_pdb_url("ntkrnlmp.pdb", "AABBCCDD", 1)
    assert data["download_url"].endswith("/ntkrnlmp.pdb/AABBCCDD1/ntkrnlmp.pdb")
    assert microsoft_compressed_pdb_url("ntkrnlmp.pdb", "AABBCCDD", 1).endswith(
        "/ntkrnlmp.pdb/AABBCCDD1/ntkrnlmp.pd_"
    )
    assert data["dest_dir"] == r"%LOCALAPPDATA%\Dumplyzer\symbols\windows"
    assert ".pdb" in data["accepted_extensions"]


def test_kernel_symbols_required_error_code() -> None:
    err = kernel_symbols_required_error("ntkrnlmp.pdb", "abc", 2)
    assert err.code == "kernel_symbols_required"
    assert err.data["guid"] == "ABC"
    assert "ntkrnlmp.pdb" in (err.suggestion or "")


def test_import_json_copies_into_symbols(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "Dumplyzer").ensure()
    src = tmp_path / "kernel.json"
    src.write_text('{"metadata": {"windows": {}}}', encoding="utf-8")
    result = import_user_symbol_file(
        src, pdb_name="ntkrnlmp.pdb", guid="DEADBEEF", age=1, paths=paths
    )
    stored = paths.symbols / "windows" / "ntkrnlmp.pdb" / "DEADBEEF-1.json"
    assert stored.is_file()
    assert result["ok"] is True


def test_import_rejects_unknown_extension(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "Dumplyzer").ensure()
    src = tmp_path / "notes.txt"
    src.write_text("nope", encoding="utf-8")
    try:
        import_user_symbol_file(
            src, pdb_name="ntkrnlmp.pdb", guid="AA", age=1, paths=paths
        )
        raise AssertionError("expected AppError")
    except AppError as exc:
        assert exc.code == "symbol_file_unsupported"


def test_pdb_download_defaults_to_blocked() -> None:
    set_pdb_download_allowed(False)
    assert pdb_download_allowed() is False
    record_needed_kernel("ntkrnlmp.pdb", "fff", 3)
    needed = last_needed_kernel()
    assert needed is not None
    assert needed["guid"] == "FFF"
    set_pdb_download_allowed(True)
    assert pdb_download_allowed() is True
    set_pdb_download_allowed(False)
    from memscope_engine.volatility.runtime import clear_needed_kernel

    clear_needed_kernel()


_OPEN = "memscope_engine.volatility.kernel_symbols._open_symbol_response"
_PDB = b"Microsoft C/C++ MSF 7.00\r\n" + b"\x00" * 64


class _FakeHttp:
    def __init__(self, data: bytes):
        self._data = data
        self.headers = {"Content-Length": str(len(data))}

    def read(self, n: int = -1) -> bytes:
        if not self._data:
            return b""
        if n < 0:
            out = self._data
            self._data = b""
            return out
        out = self._data[:n]
        self._data = self._data[n:]
        return out

    def __enter__(self) -> "_FakeHttp":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_azure_blob_symbol_url_is_allowed() -> None:
    assert _is_allowed_symbol_url(
        "https://vsblobprod.blob.core.windows.net/container/hash.blob"
    )
    assert _is_allowed_symbol_url(microsoft_pdb_url("ntkrnlmp.pdb", "AA", 1))
    assert not _is_allowed_symbol_url("https://example.com/hash.blob")
    assert not _is_allowed_symbol_url(
        "http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/AA1/ntkrnlmp.pdb"
    )


def test_symbol_redirect_handler_allows_azure_and_blocks_offsite() -> None:
    from urllib import request as urlrequest

    handler = _SymbolRedirectHandler()
    req = urlrequest.Request(
        "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/AA1/ntkrnlmp.pdb"
    )
    azure = "https://x.blob.core.windows.net/c/hash.blob"
    followed = handler.redirect_request(req, None, 302, "Found", {}, azure)
    assert followed is not None
    assert followed.full_url.startswith("https://x.blob.core.windows.net/")
    blocked = handler.redirect_request(
        req, None, 302, "Found", {}, "https://evil.example/x.blob"
    )
    assert blocked is None


def test_save_microsoft_pdb_writes_named_file(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "ntkrnlmp.pdb"

    def fake_open(req, timeout=60):
        url = getattr(req, "full_url", str(req))
        assert url.endswith("/ntkrnlmp.pdb/AABBCCDD1/ntkrnlmp.pdb")
        assert req.get_header("User-agent") == "Microsoft-Symbol-Server/6.2.9200.16384"
        return _FakeHttp(_PDB)

    monkeypatch.setattr(_OPEN, fake_open)
    result = save_microsoft_pdb(
        dest, pdb_name="ntkrnlmp.pdb", guid="aabbccdd", age=1
    )
    assert dest.is_file()
    assert dest.read_bytes() == _PDB
    assert dest.suffix == ".pdb"
    assert result["path"] == str(dest)
    assert result["bytes"] == len(_PDB)
    assert result["guid"] == "AABBCCDD"
    assert result["age"] == 1
    assert result["filename_pdb"] == "ntkrnlmp.pdb"


def test_save_microsoft_pdb_follows_https_file_ptr(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "kernel.pdb"
    first = microsoft_pdb_url("ntkrnlmp.pdb", "DEADBEEF", 2)
    second = f"{first}-resolved"

    def fake_open(req, timeout=60):
        url = getattr(req, "full_url", str(req))
        if url == first:
            return _FakeHttp(f"PATH:{second}".encode("ascii"))
        if url == second:
            return _FakeHttp(_PDB)
        raise AssertionError(url)

    monkeypatch.setattr(_OPEN, fake_open)
    save_microsoft_pdb(dest, pdb_name="ntkrnlmp.pdb", guid="deadbeef", age=2)
    assert dest.read_bytes() == _PDB


def test_save_microsoft_pdb_follows_azure_blob_file_ptr(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "ntkrnlmp.pdb"
    first = microsoft_pdb_url("ntkrnlmp.pdb", "AABBCCDD", 1)
    azure = "https://vsblobprod.blob.core.windows.net/osscollab/hash.blob"

    def fake_open(req, timeout=60):
        url = getattr(req, "full_url", str(req))
        if url == first:
            return _FakeHttp(f"PATH:{azure}".encode("ascii"))
        if url == azure:
            return _FakeHttp(_PDB)
        raise AssertionError(url)

    monkeypatch.setattr(_OPEN, fake_open)
    save_microsoft_pdb(dest, pdb_name="ntkrnlmp.pdb", guid="aabbccdd", age=1)
    assert dest.read_bytes() == _PDB
    assert dest.name == "ntkrnlmp.pdb"


def test_save_microsoft_pdb_rejects_offsite_file_ptr(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "kernel.pdb"

    def fake_open(_req, timeout=60):
        return _FakeHttp(b"PATH:https://example.com/ntkrnlmp.pdb")

    monkeypatch.setattr(_OPEN, fake_open)
    try:
        save_microsoft_pdb(dest, pdb_name="ntkrnlmp.pdb", guid="AA", age=1)
        raise AssertionError("expected AppError")
    except AppError as exc:
        assert exc.code == "kernel_symbols_download_failed"
        assert not dest.exists()


def test_save_microsoft_pdb_rejects_truncated_body(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "ntkrnlmp.pdb"
    payload = _PDB + b"\x00" * 64

    class ShortHttp(_FakeHttp):
        def __init__(self) -> None:
            super().__init__(payload)
            self.headers = {"Content-Length": str(len(payload) + 4096)}

    def fake_open(_req, timeout=60):
        return ShortHttp()

    monkeypatch.setattr(_OPEN, fake_open)
    monkeypatch.setattr(
        "memscope_engine.volatility.kernel_symbols._HTTP_RETRY_SLEEP_SECS",
        0,
    )
    try:
        save_microsoft_pdb(dest, pdb_name="ntkrnlmp.pdb", guid="AA", age=1)
        raise AssertionError("expected AppError")
    except AppError as exc:
        assert exc.code == "kernel_symbols_download_failed"
        assert "incomplete" in exc.message.lower()
        assert not dest.exists()


def test_save_microsoft_pdb_retries_incomplete_then_succeeds(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "ntkrnlmp.pdb"
    payload = _PDB + b"\x00" * 64
    attempts = {"n": 0}

    class ShortThenFull:
        def __init__(self, data: bytes, declared: int):
            self._data = data
            self.headers = {"Content-Length": str(declared)}

        def read(self, n: int = -1) -> bytes:
            if not self._data:
                return b""
            if n < 0:
                out = self._data
                self._data = b""
                return out
            out = self._data[:n]
            self._data = self._data[n:]
            return out

        def __enter__(self) -> "ShortThenFull":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open(_req, timeout=180):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return ShortThenFull(payload, len(payload) + 4096)
        return ShortThenFull(_PDB, len(_PDB))

    monkeypatch.setattr(_OPEN, fake_open)
    monkeypatch.setattr(
        "memscope_engine.volatility.kernel_symbols._HTTP_RETRY_SLEEP_SECS",
        0,
    )
    save_microsoft_pdb(dest, pdb_name="ntkrnlmp.pdb", guid="AA", age=1)
    assert dest.read_bytes() == _PDB
    assert attempts["n"] == 2


def test_fetch_kernel_pdb_progress_is_monotonic(monkeypatch, tmp_path: Path) -> None:
    import lzma

    from memscope_engine.volatility.runtime import set_active_paths

    paths = AppPaths(tmp_path / "Dumplyzer").ensure()
    set_active_paths(paths)
    first = microsoft_pdb_url("ntkrnlmp.pdb", "AABBCCDD", 1)
    azure = "https://vsblobprod.blob.core.windows.net/osscollab/hash.blob"
    blob = _PDB + b"\x00" * 8000
    percents: list[float] = []

    def fake_open(req, timeout=180):
        url = getattr(req, "full_url", str(req))
        if url == first:
            return _FakeHttp(f"PATH:{azure}".encode("ascii"))
        if url == azure:
            return _FakeHttp(blob)
        raise AssertionError(url)

    def fake_convert(src: Path, dest: Path, **kwargs: object) -> None:
        progress = kwargs.get("progress")
        if callable(progress):
            progress(0, "Converting kernel symbols…")
            progress(50, "Converting kernel symbols…")
            progress(100, "Converting kernel symbols…")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with lzma.open(dest, "wt", encoding="utf-8") as handle:
            handle.write('{"metadata": {"windows": {}}}')

    monkeypatch.setattr(
        "memscope_engine.volatility.kernel_symbols.pack_is_ready",
        lambda *_a, **_k: False,
    )
    monkeypatch.setattr(
        "memscope_engine.volatility.runtime.configure_volatility_runtime",
        lambda *_a, **_k: {},
    )
    monkeypatch.setattr(_OPEN, fake_open)
    monkeypatch.setattr(
        "memscope_engine.volatility.kernel_symbols._convert_pdb_to_isf",
        fake_convert,
    )
    try:
        fetch_kernel_pdb(
            pdb_name="ntkrnlmp.pdb",
            guid="AABBCCDD",
            age=1,
            progress=lambda pct, _desc=None: percents.append(pct),
        )
        assert percents
        assert percents[0] >= 1
        assert percents[-1] == 100
        assert percents == sorted(percents)
    finally:
        set_active_paths(None)


def test_file_uri_is_three_slash(tmp_path: Path) -> None:
    src = tmp_path / "ntkrnlmp.pdb"
    src.write_bytes(b"x")
    uri = _file_uri(src)
    assert uri.startswith("file:///")
    assert uri.endswith("ntkrnlmp.pdb")


def test_save_microsoft_pdb_rejects_unverified_blob(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "ntkrnlmp.pdb"
    blob = b"AZURE-BLOB-NOT-A-PDB" + b"\x00" * 2048
    assert not _looks_like_pdb(blob)

    def fake_open(_req, timeout=60):
        return _FakeHttp(blob)

    monkeypatch.setattr(_OPEN, fake_open)
    try:
        save_microsoft_pdb(dest, pdb_name="ntkrnlmp.pdb", guid="AA", age=1)
        raise AssertionError("expected AppError")
    except AppError as exc:
        assert exc.code == "kernel_symbols_download_failed"
        assert "not a kernel PDB" in exc.message
        assert not dest.exists()


def test_save_microsoft_pdb_falls_back_to_compressed_url(monkeypatch, tmp_path: Path) -> None:
    dest = tmp_path / "ntkrnlmp.pdb"
    uncompressed = microsoft_pdb_url("ntkrnlmp.pdb", "ABCDEF", 1)
    compressed = microsoft_compressed_pdb_url("ntkrnlmp.pdb", "ABCDEF", 1)
    assert compressed.endswith("/ntkrnlmp.pd_")

    def fake_open(req, timeout=60):
        url = getattr(req, "full_url", str(req))
        if url == uncompressed:
            return _FakeHttp(b"<!doctype html><html>not found</html>")
        if url == compressed:
            return _FakeHttp(_PDB)
        raise AssertionError(url)

    monkeypatch.setattr(_OPEN, fake_open)
    save_microsoft_pdb(dest, pdb_name="ntkrnlmp.pdb", guid="abcdef", age=1)
    assert dest.read_bytes() == _PDB


def test_fetch_kernel_pdb_converts_verified_pdb(monkeypatch, tmp_path: Path) -> None:
    import lzma

    from memscope_engine.volatility.runtime import set_active_paths

    paths = AppPaths(tmp_path / "Dumplyzer").ensure()
    set_active_paths(paths)
    monkeypatch.setattr(
        "memscope_engine.volatility.kernel_symbols.pack_is_ready",
        lambda *_a, **_k: False,
    )
    monkeypatch.setattr(
        "memscope_engine.volatility.runtime.configure_volatility_runtime",
        lambda *_a, **_k: {},
    )

    def fake_open(_req, timeout=60):
        return _FakeHttp(_PDB)

    def fake_convert(src: Path, dest: Path, **_kwargs: object) -> None:
        assert src.is_file()
        assert src.read_bytes().startswith(b"Microsoft C/C++")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with lzma.open(dest, "wt", encoding="utf-8") as handle:
            handle.write('{"metadata": {"windows": {}}}')

    monkeypatch.setattr(_OPEN, fake_open)
    monkeypatch.setattr(
        "memscope_engine.volatility.kernel_symbols._convert_pdb_to_isf",
        fake_convert,
    )
    try:
        result = fetch_kernel_pdb(pdb_name="ntkrnlmp.pdb", guid="AABBCCDD", age=1)
        stored = Path(result["stored"])
        assert result["ok"] is True
        assert result["source"] == "microsoft"
        assert result["guid"] == "AABBCCDD"
        assert result["age"] == 1
        assert result["filename_pdb"] == "ntkrnlmp.pdb"
        assert stored.is_file()
        assert stored.name == "AABBCCDD-1.json.xz"
        assert stored.parent.name == "ntkrnlmp.pdb"
        assert list(paths.symbols.rglob("*.blob")) == []
        with lzma.open(stored, "rt", encoding="utf-8") as handle:
            assert handle.read().lstrip().startswith("{")
    finally:
        set_active_paths(None)

