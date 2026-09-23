from __future__ import annotations

import copy
import ssl
import urllib.request
from pathlib import Path

from memscope_engine.paths import AppPaths
from memscope_engine.volatility.runtime import (
    SYMBOL_SERVER_HTTPS,
    SYMBOL_USER_AGENT,
    _as_request,
    configure_symbol_paths,
    configure_volatility_runtime,
    load_windows_ca_certs,
    safe_https_context,
    symbol_hint_dir,
    unsatisfied_looks_like_symbols,
)


def test_bad_windows_ca_does_not_abort_https_context(monkeypatch) -> None:
    def _enum(store: str):
        return [(b"not-a-certificate", "x509_asn", True)]

    def _boom(*_args, **_kwargs):
        raise ssl.SSLError("nested asn1 error")

    monkeypatch.setattr(ssl, "enum_certificates", _enum, raising=False)
    monkeypatch.setattr(
        "memscope_engine.volatility.runtime._stdlib_https_context",
        _boom,
    )
    ctx = safe_https_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    loaded = load_windows_ca_certs(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    assert loaded == 0


def test_symbol_paths_prefer_user_data(tmp_path: Path) -> None:
    from volatility3 import symbols
    from volatility3.framework import constants

    old_cache = constants.CACHE_PATH
    old_paths = list(constants.SYMBOL_BASEPATHS)
    old_sym = list(symbols.__path__)
    try:
        paths = AppPaths(tmp_path / "Dumplyzer").ensure()
        info = configure_symbol_paths(paths)
        assert constants.CACHE_PATH == str(paths.volatility_cache)
        assert constants.SYMBOL_BASEPATHS[0] == str(paths.symbols)
        assert str(paths.volatility_cache / "symbols") in constants.SYMBOL_BASEPATHS[:2]
        assert list(symbols.__path__) == list(constants.SYMBOL_BASEPATHS)
        assert info["user_symbols"] == str(paths.symbols)
    finally:
        constants.CACHE_PATH = old_cache
        constants.SYMBOL_BASEPATHS[:] = old_paths
        symbols.__path__ = old_paths


def test_configure_runtime_is_idempotent(tmp_path: Path) -> None:
    from volatility3 import symbols
    from volatility3.framework import constants

    old_cache = constants.CACHE_PATH
    old_paths = list(constants.SYMBOL_BASEPATHS)
    old_sym = list(symbols.__path__)
    paths = AppPaths(tmp_path / "Dumplyzer").ensure()
    try:
        first = configure_volatility_runtime(paths)
        second = configure_volatility_runtime(paths)
        assert first["cache_path"] == second["cache_path"] == str(paths.volatility_cache)
        assert constants.SYMBOL_BASEPATHS.count(str(paths.symbols)) == 1
    finally:
        constants.CACHE_PATH = old_cache
        constants.SYMBOL_BASEPATHS[:] = old_paths
        symbols.__path__ = old_sym


def test_unsatisfied_classifier() -> None:
    assert unsatisfied_looks_like_symbols(["plugins.PsList.kernel"])
    assert unsatisfied_looks_like_symbols(["plugins.Info.ntkrnlmp"])
    assert not unsatisfied_looks_like_symbols(["plugins.PsList.pid"])


def test_symbol_hint_is_portable() -> None:
    hint = symbol_hint_dir()
    assert hint == r"%LOCALAPPDATA%\Dumplyzer\symbols"
    assert "C:\\Users\\" not in hint


def test_as_request_adds_microsoft_symbol_user_agent() -> None:
    req = _as_request("https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/ABC/ntkrnlmp.pdb")
    assert isinstance(req, urllib.request.Request)
    assert req.get_header("User-agent") == SYMBOL_USER_AGENT
    existing = urllib.request.Request("https://example.test", headers={"User-Agent": "keep-me"})
    assert _as_request(existing).get_header("User-agent") == "keep-me"


def test_configure_runtime_enables_threading(tmp_path: Path) -> None:
    import threading

    from volatility3.framework import constants
    from volatility3.framework.configuration import requirements
    from volatility3.framework.contexts import Context
    from volatility3.framework.layers.physical import FileLayer
    from volatility3.framework.layers.scanners import BytesScanner

    old = constants.PARALLELISM
    old_cache = constants.CACHE_PATH
    old_paths = list(constants.SYMBOL_BASEPATHS)
    try:
        constants.PARALLELISM = constants.Parallelism.Off
        configure_volatility_runtime(AppPaths(tmp_path / "Dumplyzer").ensure())
        assert constants.PARALLELISM is constants.Parallelism.Threading
        assert constants.PARALLELISM == constants.Parallelism.Threading
        # Volatility 3.2.28 calls threading.Pool; CPython does not provide it.
        assert getattr(threading, "Pool", None) is not None

        image = tmp_path / "scan.bin"
        image.write_bytes(b"AAAA" * 4096 + b"NEEDLE" + b"BBBB" * 4096)
        ctx = Context()
        ctx.config["FileLayer.location"] = requirements.URIRequirement.location_from_file(
            str(image)
        )
        layer = FileLayer(ctx, "FileLayer", "file")
        ctx.layers.add_layer(layer)
        from volatility3.framework.layers.physical import DummyLock

        assert not isinstance(layer._lock, DummyLock)
        hits = list(layer.scan(ctx, BytesScanner(b"NEEDLE")))
        assert hits == [16384]
        cloned_ctx = ctx.clone()
        cloned_layer = cloned_ctx.layers[layer.name]
        assert cloned_layer is not layer
        cloned_hits = list(cloned_layer.scan(cloned_ctx, BytesScanner(b"NEEDLE")))
        assert cloned_hits == [16384]
        copied = copy.deepcopy(layer)
        assert list(copied.scan(ctx, BytesScanner(b"NEEDLE"))) == [16384]
    finally:
        constants.PARALLELISM = old
        constants.CACHE_PATH = old_cache
        constants.SYMBOL_BASEPATHS[:] = old_paths


def test_configure_runtime_uses_https_symbol_server(tmp_path: Path) -> None:
    from volatility3.framework import constants

    old = constants.SYMBOL_SERVER_URL
    old_cache = constants.CACHE_PATH
    old_paths = list(constants.SYMBOL_BASEPATHS)
    try:
        configure_volatility_runtime(AppPaths(tmp_path / "Dumplyzer").ensure())
        assert constants.SYMBOL_SERVER_URL == SYMBOL_SERVER_HTTPS
        assert constants.SYMBOL_SERVER_URL.startswith("https://")
    finally:
        constants.SYMBOL_SERVER_URL = old
        constants.CACHE_PATH = old_cache
        constants.SYMBOL_BASEPATHS[:] = old_paths
