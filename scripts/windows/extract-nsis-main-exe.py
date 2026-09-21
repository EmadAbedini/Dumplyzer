# Extract the main Dumplyzer PE from a Tauri NSIS installer overlay.
# Uses only the Python 3.12 stdlib (lzma). Does not patch bytes.

from __future__ import annotations

import hashlib
import lzma
import struct
import sys
from pathlib import Path


def _pe_raw_size(data: bytes, mz_off: int) -> int | None:
    if mz_off + 64 > len(data):
        return None
    e_lfanew = struct.unpack_from("<I", data, mz_off + 0x3C)[0]
    pe = mz_off + e_lfanew
    if e_lfanew < 0x40 or pe + 24 > len(data) or data[pe : pe + 4] != b"PE\x00\x00":
        return None
    _machine, nsec, _td, _p, _s, optsz, _ch = struct.unpack_from("<HHIIIHH", data, pe + 4)
    sec = pe + 4 + 20 + optsz
    max_end = 0
    for i in range(min(nsec, 16)):
        off = sec + i * 40
        if off + 40 > len(data):
            return None
        _vsize, _va, rsize, raw = struct.unpack_from("<IIII", data, off + 8)
        max_end = max(max_end, raw + rsize)
    if max_end < 1_000_000:
        return None
    return max_end


def extract_main_exe(installer: Path, dest: Path) -> str:
    blob = installer.read_bytes()
    idx = blob.find(b"NullsoftInst")
    if idx < 0:
        raise SystemExit(f"not an NSIS installer (missing NullsoftInst): {installer}")
    compressed = blob[idx + 20 :]
    # NSIS LZMA: 5-byte properties, no uncompressed-size field.
    lzma_blob = compressed[:5] + b"\xff" * 8 + compressed[5:]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    uncompressed = dec.decompress(lzma_blob)
    marker = uncompressed.find(b"BUNDLE_TYPE_VAR_NSS")
    if marker < 0:
        raise SystemExit("NSIS payload does not contain BUNDLE_TYPE_VAR_NSS dumplyzer.exe")
    mz = uncompressed.rfind(b"MZ", 0, marker)
    while mz >= 0:
        size = _pe_raw_size(uncompressed, mz)
        if size and mz + size <= len(uncompressed) and mz <= marker < mz + size:
            exe = uncompressed[mz : mz + size]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(exe)
            return hashlib.sha256(exe).hexdigest()
        mz = uncompressed.rfind(b"MZ", 0, mz)
    raise SystemExit("could not locate dumplyzer.exe PE covering BUNDLE_TYPE_VAR_NSS")


def main(argv: list[str]) -> None:
    if len(argv) != 3:
        raise SystemExit(f"usage: {argv[0]} <nsis-setup.exe> <out-dumplyzer.exe>")
    digest = extract_main_exe(Path(argv[1]), Path(argv[2]))
    sys.stdout.write(digest + "\n")


if __name__ == "__main__":
    main(sys.argv)
