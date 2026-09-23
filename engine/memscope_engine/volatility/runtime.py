"""Point Volatility 3 at writable caches and a non-crashing HTTPS stack.

Packaged installs live under Program Files. Volatility 3 otherwise tries to
write ISF files next to the package and builds the default SSL context from
the Windows certificate store. A single malformed CA (common with extra
government roots) raises ``ssl.SSLError: [ASN1] nested asn1 error`` during
automagic; Volatility swallows that and reports unsatisfied kernel symbols.
"""

from __future__ import annotations

import logging
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from memscope_engine.paths import AppPaths
from memscope_engine.version import APP_NAME

log = logging.getLogger("memscope.tool")

_active_paths: AppPaths | None = None
_stdlib_https_context = ssl._create_default_https_context
_orig_urlopen = urllib.request.urlopen
_urlopen_wrapped = False
_pdb_gate_installed = False
_tls = threading.local()

# Volatility 3.2.28 still uses http:// and Python-urllib's default User-Agent.
# Microsoft's symbol server redirects to HTTPS and often returns 403 without a
# Microsoft-Symbol-Server UA, which Volatility reports as missing kernel ISF.
SYMBOL_SERVER_HTTPS = "https://msdl.microsoft.com/download/symbols"
SYMBOL_USER_AGENT = "Microsoft-Symbol-Server/6.2.9200.16384"


def set_active_paths(paths: AppPaths | None) -> None:
    global _active_paths
    _active_paths = paths


def active_paths() -> AppPaths:
    return _active_paths or AppPaths()


class _CloneableLock:
    """``threading.Lock`` stand-in that Volatility ``context.clone()`` can copy.

    FileLayer uses a real lock when PARALLELISM is Threading. Automagic then
    deep-copies the context for the next plugin; a raw lock raises
    ``TypeError: cannot pickle '_thread.lock' object`` and analysis stops
    even after the kernel ISF is on disk.
    """

    __slots__ = ("_lock",)

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def __enter__(self) -> bool:
        return self._lock.__enter__()

    def __exit__(self, *args: Any) -> None:
        return self._lock.__exit__(*args)

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        return self._lock.acquire(blocking, timeout)

    def release(self) -> None:
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def __deepcopy__(self, memo: dict[int, Any]) -> "_CloneableLock":
        copied = _CloneableLock()
        memo[id(self)] = copied
        return copied

    def __getstate__(self) -> dict[str, Any]:
        return {}

    def __setstate__(self, _state: dict[str, Any]) -> None:
        self._lock = threading.Lock()


def _ensure_volatility_thread_pool() -> None:
    """Volatility 3.2.28 calls ``threading.Pool()``; CPython has no such API.

    Without this alias, thread-safe layer scans catch AttributeError and yield
    no hits. ThreadPool keeps FileLayer cancel patches in-process.
    """
    if getattr(threading, "Pool", None) is not None:
        return
    from multiprocessing.pool import ThreadPool

    threading.Pool = ThreadPool  # type: ignore[attr-defined]


def _ensure_filelayer_lock_cloneable() -> None:
    """Replace FileLayer's unpickleable lock after Threading construction."""
    from volatility3.framework.layers.physical import FileLayer

    if getattr(FileLayer, "_dumplyzer_cloneable_lock", False):
        return
    original = FileLayer.__init__

    def wrapped(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        from volatility3.framework.layers.physical import DummyLock

        lock = getattr(self, "_lock", None)
        if lock is not None and not isinstance(lock, (DummyLock, _CloneableLock)):
            self._lock = _CloneableLock()

    FileLayer.__init__ = wrapped  # type: ignore[method-assign]
    FileLayer._dumplyzer_cloneable_lock = True  # type: ignore[attr-defined]


def configure_volatility_runtime(paths: AppPaths | None = None) -> dict[str, str]:
    """Install SSL workaround and send Volatility caches to user data."""
    resolved = paths or active_paths()
    resolved.volatility_cache.mkdir(parents=True, exist_ok=True)
    (resolved.volatility_cache / "symbols").mkdir(parents=True, exist_ok=True)
    resolved.symbols.mkdir(parents=True, exist_ok=True)
    from volatility3.framework import constants

    # Threading (not Multiprocessing): in-process cancel patches stay in effect
    # and FileLayer takes a lock. Layer scanners that mark thread_safe can use
    # extra cores without a second engine process. Must run before FileLayer
    # construction — the lock type is chosen at that moment.
    _ensure_volatility_thread_pool()
    _ensure_filelayer_lock_cloneable()
    constants.PARALLELISM = constants.Parallelism.Threading
    install_safe_https_context()
    install_symbol_downloader()
    install_pdb_download_gate()
    return configure_symbol_paths(resolved)


def pdb_download_allowed() -> bool:
    return bool(getattr(_tls, "allow_pdb_download", False))


def set_pdb_download_allowed(value: bool) -> None:
    _tls.allow_pdb_download = bool(value)


def last_needed_kernel() -> dict[str, Any] | None:
    needed = getattr(_tls, "needed_kernel", None)
    return dict(needed) if isinstance(needed, dict) else None


def clear_needed_kernel() -> None:
    _tls.needed_kernel = None


def record_needed_kernel(pdb_name: str, guid: str, age: int) -> dict[str, Any]:
    payload = {
        "pdb_name": Path(str(pdb_name).strip() or "ntkrnlmp.pdb").name,
        "guid": str(guid).upper(),
        "age": int(age),
    }
    _tls.needed_kernel = payload
    return payload


def install_pdb_download_gate() -> None:
    """Do not fetch Microsoft PDBs until the user consents for this build."""
    global _pdb_gate_installed
    if _pdb_gate_installed:
        return
    from volatility3.framework.symbols.windows.pdbutil import PDBUtility

    original = PDBUtility.download_pdb_isf

    def gated(
        cls: Any,
        context: Any,
        guid: str,
        age: int,
        pdb_name: str,
        progress_callback: Any = None,
    ) -> None:
        record_needed_kernel(str(pdb_name), str(guid), int(age))
        if not pdb_download_allowed():
            log.info(
                "kernel PDB download waiting for user consent",
                extra={"channel": "tool"},
            )
            return None
        return original.__func__(
            cls, context, guid, age, pdb_name, progress_callback
        )

    PDBUtility.download_pdb_isf = classmethod(gated)  # type: ignore[method-assign]
    _pdb_gate_installed = True


def install_symbol_downloader() -> None:
    """Point PDB retrieval at HTTPS with a User-Agent Microsoft will accept."""
    global _urlopen_wrapped
    from volatility3.framework import constants

    constants.SYMBOL_SERVER_URL = SYMBOL_SERVER_HTTPS
    if _urlopen_wrapped:
        return
    urllib.request.urlopen = _symbol_urlopen  # type: ignore[method-assign]
    _urlopen_wrapped = True


def _as_request(url: Any) -> Any:
    if isinstance(url, urllib.request.Request):
        if not url.has_header("User-agent"):
            url.add_header("User-Agent", SYMBOL_USER_AGENT)
        return url
    if isinstance(url, str) and url.startswith(("http://", "https://")):
        return urllib.request.Request(
            url, headers={"User-Agent": SYMBOL_USER_AGENT}
        )
    return url


def _symbol_urlopen(
    url: Any,
    data: Any = None,
    timeout: float | None = None,
    *,
    context: ssl.SSLContext | None = None,
) -> Any:
    req = _as_request(url)
    target = req.full_url if isinstance(req, urllib.request.Request) else str(url)
    kwargs: dict[str, Any] = {}
    if timeout is not None:
        kwargs["timeout"] = timeout
    is_http = target.startswith(("http://", "https://"))
    if context is None and target.startswith("https://"):
        context = safe_https_context()
    if context is not None and is_http:
        kwargs["context"] = context
    try:
        return _orig_urlopen(req, data, **kwargs)
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        log.warning(
            "symbol download failed: %s",
            exc,
            extra={"channel": "tool"},
        )
        raise


def install_safe_https_context() -> bool:
    """Prefer the stdlib HTTPS context; only fall back if Windows CAs are unreadable."""
    if ssl._create_default_https_context is not safe_https_context:
        ssl._create_default_https_context = safe_https_context
    return True


def safe_https_context(*args: Any, **kwargs: Any) -> ssl.SSLContext:
    try:
        return _stdlib_https_context(*args, **kwargs)
    except ssl.SSLError:
        pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    cafile = kwargs.get("cafile")
    capath = kwargs.get("capath")
    cadata = kwargs.get("cadata")
    if cafile or capath or cadata:
        ctx.load_verify_locations(cafile=cafile, capath=capath, cadata=cadata)
        return ctx
    load_windows_ca_certs(ctx)
    if ctx.cert_store_stats().get("x509_ca", 0) == 0:
        try:
            ctx.set_default_verify_paths()
        except ssl.SSLError:
            pass
    return ctx


def load_windows_ca_certs(
    ctx: ssl.SSLContext,
    purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
) -> int:
    """Load Windows store CAs one-by-one so a bad encoding cannot abort TLS."""
    loaded = 0
    enum_certificates = getattr(ssl, "enum_certificates", None)
    if enum_certificates is None:
        return loaded
    purpose_oid = getattr(purpose, "oid", None)
    for storename in ("CA", "ROOT"):
        try:
            entries = enum_certificates(storename)
        except (ssl.SSLError, OSError, PermissionError):
            continue
        for item in entries:
            try:
                cert, encoding, trust = item
            except (TypeError, ValueError):
                continue
            if encoding != "x509_asn":
                continue
            if trust is not True and purpose_oid not in (trust or ()):
                continue
            try:
                ctx.load_verify_locations(cadata=cert)
            except ssl.SSLError:
                continue
            loaded += 1
    return loaded


def configure_symbol_paths(paths: AppPaths) -> dict[str, str]:
    """Prefer writable user-data symbol dirs over Program Files package paths."""
    from volatility3 import symbols
    from volatility3.framework import constants

    cache = str(paths.volatility_cache)
    user_symbols = str(paths.symbols)
    download_symbols = str(paths.volatility_cache / "symbols")
    constants.CACHE_PATH = cache
    Path(cache).mkdir(parents=True, exist_ok=True)
    Path(download_symbols).mkdir(parents=True, exist_ok=True)
    Path(user_symbols).mkdir(parents=True, exist_ok=True)

    preferred = [user_symbols, download_symbols]
    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in preferred + list(constants.SYMBOL_BASEPATHS):
        key = str(Path(candidate))
        lowered = key.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(candidate)
    constants.SYMBOL_BASEPATHS[:] = ordered
    symbols.__path__ = constants.SYMBOL_BASEPATHS
    return {
        "cache_path": cache,
        "user_symbols": user_symbols,
        "download_symbols": download_symbols,
    }


def symbol_hint_dir(paths: AppPaths | None = None) -> str:
    """Portable location shown to users. Never a resolved C:\\Users\\... path."""
    del paths
    return rf"%LOCALAPPDATA%\{APP_NAME}\symbols"


def unsatisfied_looks_like_symbols(unsatisfied: list[Any]) -> bool:
    blob = " ".join(str(x) for x in unsatisfied).lower()
    keys = ("kernel", "symbol", "ntkrnl", "linux", "darwin", "mac")
    return any(key in blob for key in keys)
