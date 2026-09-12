"""PCAP reconstruction from synthetic packet records (no malware samples)."""

from __future__ import annotations

import struct
from pathlib import Path
from uuid import uuid4

import pytest

from memscope_engine.analysis.pcap_carve import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    PCAP_MAGIC,
    carve_buffer,
    carve_image,
    ipv4_header_checksum,
    overall_status,
    parse_ipv4,
    read_pcap,
    write_pcap,
    write_pcap_pair,
)
from memscope_engine.analysis.pcap_reconstruction import (
    LIMITATIONS,
    run_pcap_reconstruction_job,
    validate_import_pcap,
)
from memscope_engine.analysis.workflows import import_evidence
from memscope_engine.errors import AppError
from memscope_engine.paths import AppPaths
from memscope_engine.storage import Database


def _checksum(header: bytes) -> int:
    padded = header if len(header) % 2 == 0 else header + b"\x00"
    return ipv4_header_checksum(padded)


def _ipv4_header(src: str, dst: str, proto: int, total: int) -> bytes:
    s = bytes(int(p) for p in src.split("."))
    d = bytes(int(p) for p in dst.split("."))
    hdr = bytearray(20)
    hdr[0] = 0x45
    hdr[1] = 0
    hdr[2:4] = total.to_bytes(2, "big")
    hdr[8] = 64
    hdr[9] = proto
    hdr[12:16] = s
    hdr[16:20] = d
    csum = _checksum(bytes(hdr))
    hdr[10:12] = csum.to_bytes(2, "big")
    return bytes(hdr)


def _tcp_header(sport: int, dport: int) -> bytes:
    hdr = bytearray(20)
    hdr[0:2] = sport.to_bytes(2, "big")
    hdr[2:4] = dport.to_bytes(2, "big")
    hdr[12] = 5 << 4
    hdr[13] = 0x02  # SYN
    hdr[14:16] = (8192).to_bytes(2, "big")
    return bytes(hdr)


def _udp_header(sport: int, dport: int, payload_len: int) -> bytes:
    hdr = bytearray(8)
    hdr[0:2] = sport.to_bytes(2, "big")
    hdr[2:4] = dport.to_bytes(2, "big")
    hdr[4:6] = (8 + payload_len).to_bytes(2, "big")
    return bytes(hdr)


def ethernet_ipv4_tcp(
    *,
    src="10.0.0.1",
    dst="8.8.8.8",
    sport=49152,
    dport=443,
    payload=b"GET / HTTP/1.1\r\n\r\n",
) -> bytes:
    tcp = _tcp_header(sport, dport) + payload
    ip = _ipv4_header(src, dst, 6, 20 + len(tcp)) + tcp
    eth = bytes.fromhex("001122334455") + bytes.fromhex("aabbccddeeff") + b"\x08\x00"
    return eth + ip


def raw_ipv4_udp(
    *,
    src="192.0.2.10",
    dst="192.0.2.20",
    sport=53,
    dport=53,
    payload=b"\x12\x34" + b"\x00" * 10,
) -> bytes:
    udp = _udp_header(sport, dport, len(payload)) + payload
    return _ipv4_header(src, dst, 17, 20 + len(udp)) + udp


def ipv6_udp() -> bytes:
    payload = b"\x00" * 12
    pkt = bytearray(40 + 8 + len(payload))
    pkt[0] = 0x60
    pkt[4:6] = (8 + len(payload)).to_bytes(2, "big")
    pkt[6] = 17
    pkt[7] = 64
    pkt[8:24] = bytes.fromhex("20010db8000000000000000000000001")
    pkt[24:40] = bytes.fromhex("20010db8000000000000000000000002")
    pkt[40:42] = (12345).to_bytes(2, "big")
    pkt[42:44] = (53).to_bytes(2, "big")
    pkt[44:46] = (8 + len(payload)).to_bytes(2, "big")
    pkt[48:] = payload
    return bytes(pkt)


def test_ipv4_checksum_rejects_corrupt_header() -> None:
    pkt = raw_ipv4_udp()
    assert parse_ipv4(pkt, 0) is not None
    bad = bytearray(pkt)
    bad[10] ^= 0xFF
    assert parse_ipv4(bytes(bad), 0) is None


def test_carve_ethernet_tcp_and_raw_udp() -> None:
    eth = ethernet_ipv4_tcp()
    raw = raw_ipv4_udp()
    blob = b"\x00" * 32 + eth + b"\x11" * 16 + raw
    packets, _skipped, _ = carve_buffer(blob)
    assert any(p.linktype == LINKTYPE_ETHERNET and p.protocol == "tcp" for p in packets)
    assert any(p.linktype == LINKTYPE_RAW and p.protocol == "udp" for p in packets)
    tcp = next(p for p in packets if p.protocol == "tcp")
    assert tcp.src_ip == "10.0.0.1"
    assert tcp.dst_port == 443
    assert eth in blob
    assert tcp.data.startswith(eth[:14])
    assert not tcp.truncated


def test_carve_ipv6_udp() -> None:
    pkt = ipv6_udp()
    packets, _, _ = carve_buffer(pkt)
    v6 = [p for p in packets if p.ip_version == 6]
    assert v6
    assert v6[0].protocol == "udp"
    assert "2001:db8" in (v6[0].src_ip or "")


def test_truncated_packet_is_partial() -> None:
    full = ethernet_ipv4_tcp(payload=b"A" * 200)
    truncated = full[:40]
    packets, _, _ = carve_buffer(truncated + b"\x00" * 8)
    assert packets
    assert any(p.truncated for p in packets)
    assert overall_status(packets) == "partially_reconstructed"


def test_no_packets_in_noise() -> None:
    packets, _, _ = carve_buffer(b"\xff" * 512)
    assert packets == []
    assert overall_status(packets) == "unavailable"


def test_write_and_read_pcap_roundtrip(tmp_path: Path) -> None:
    eth = ethernet_ipv4_tcp()
    packets, _, _ = carve_buffer(eth)
    path = tmp_path / "out.pcap"
    write_pcap(path, packets, linktype=LINKTYPE_ETHERNET)
    data = path.read_bytes()
    magic = struct.unpack_from("<I", data, 0)[0]
    assert magic == PCAP_MAGIC
    network = struct.unpack_from("<I", data, 20)[0]
    assert network == LINKTYPE_ETHERNET
    loaded = read_pcap(path)
    assert loaded
    assert loaded[0].src_ip == "10.0.0.1"
    assert loaded[0].dst_port == 443


def test_write_pcap_pair_splits_linktypes(tmp_path: Path) -> None:
    blob = ethernet_ipv4_tcp() + raw_ipv4_udp()
    packets, _, _ = carve_buffer(blob)
    written = write_pcap_pair(tmp_path, packets)
    names = {f["name"] for f in written["files"]}
    assert "reconstructed.pcap" in names
    assert "reconstructed-rawip.pcap" in names


def test_job_writes_pcap_outside_evidence(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    image = evidence_dir / "memory.raw"
    before = ethernet_ipv4_tcp() + b"\x00" * 64
    image.write_bytes(before)
    ev = import_evidence(db, str(image))
    mtime = image.stat().st_mtime_ns
    size = image.stat().st_size

    def progress(_msg: str, _extra=None) -> None:
        return None

    result = run_pcap_reconstruction_job(
        db,
        {"evidence_id": ev["id"]},
        lambda: False,
        progress,
        paths=paths,
    )
    recon = result["reconstruction"]
    assert recon["packet_count"] >= 1
    assert recon["reconstruction_status"] in {"packets_recovered", "partially_reconstructed"}
    assert recon["pcap_embedded"] is False
    out = Path(recon["output_path"])
    assert out.is_file()
    assert out.read_bytes()[:4] == struct.pack("<I", PCAP_MAGIC)
    assert out.resolve().is_relative_to(paths.analysis.resolve())
    assert not out.resolve().is_relative_to(evidence_dir.resolve())
    assert image.read_bytes() == before
    assert image.stat().st_mtime_ns == mtime
    assert image.stat().st_size == size
    assert LIMITATIONS[0] in recon["limitations"]
    db.close()


def test_job_unavailable_on_empty_image(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    image = tmp_path / "empty.raw"
    image.write_bytes(b"\x00" * 256)
    ev = import_evidence(db, str(image))
    result = run_pcap_reconstruction_job(
        db,
        {"evidence_id": ev["id"]},
        lambda: False,
        lambda *a, **k: None,
        paths=paths,
    )
    recon = result["reconstruction"]
    assert recon["reconstruction_status"] == "unavailable"
    assert recon["packet_count"] == 0
    assert recon["output_path"] is None
    db.close()


def test_job_requires_evidence(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    with pytest.raises(AppError) as err:
        run_pcap_reconstruction_job(db, {}, lambda: False, lambda *a, **k: None, paths=paths)
    assert err.value.code == "evidence_required"
    db.close()


def test_carve_image_progress_and_cancel(tmp_path: Path) -> None:
    image = tmp_path / "mem.raw"
    image.write_bytes(ethernet_ipv4_tcp() + b"\x00" * 1024)
    seen: list[float] = []
    result = carve_image(image, progress=lambda frac, _m: seen.append(frac))
    assert result.packets
    assert seen
    cancelled = carve_image(image, cancelled=lambda: True)
    assert cancelled.cancelled


def test_timestamps_are_unset(tmp_path: Path) -> None:
    packets, _, _ = carve_buffer(ethernet_ipv4_tcp())
    path = tmp_path / "ts.pcap"
    write_pcap(path, packets, linktype=LINKTYPE_ETHERNET)
    ts_sec, ts_usec = struct.unpack_from("<II", path.read_bytes(), 24)
    assert ts_sec == 0
    assert ts_usec == 0


def _write_big_endian_pcap(path: Path, frames: list[bytes]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack(">IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for frame in frames:
            fh.write(struct.pack(">IIII", 0, 0, len(frame), len(frame)))
            fh.write(frame)


def test_read_pcap_big_endian(tmp_path: Path) -> None:
    path = tmp_path / "be.pcap"
    _write_big_endian_pcap(path, [ethernet_ipv4_tcp()])
    loaded = read_pcap(path)
    assert len(loaded) == 1
    assert loaded[0].src_ip == "10.0.0.1"
    assert loaded[0].dst_port == 443


def test_job_imports_external_pcap(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    image = tmp_path / "memory.raw"
    image.write_bytes(b"\x00" * 512)
    ev = import_evidence(db, str(image))

    external = tmp_path / "packets.pcap"
    packets, _, _ = carve_buffer(ethernet_ipv4_tcp())
    write_pcap(external, packets, linktype=LINKTYPE_ETHERNET)

    result = run_pcap_reconstruction_job(
        db,
        {"evidence_id": ev["id"], "import_pcap_path": str(external)},
        lambda: False,
        lambda *a, **k: None,
        paths=paths,
    )
    recon = result["reconstruction"]
    assert recon["packet_count"] == 1
    assert recon["ethernet_count"] == 1
    assert recon["observed"]["imported_pcap_packets"] == 1
    assert recon["observed"]["imported_pcap_path"] == str(external.resolve())
    out = Path(recon["output_path"])
    assert out.is_file()
    loaded = read_pcap(out)
    assert loaded[0].src_ip == "10.0.0.1"
    assert external.read_bytes()[:4] == struct.pack("<I", PCAP_MAGIC)
    db.close()


def test_job_without_import_ignores_param(tmp_path: Path) -> None:
    paths = AppPaths(tmp_path / "data").ensure()
    db = Database(paths.db_path)
    image = tmp_path / "memory.raw"
    image.write_bytes(ethernet_ipv4_tcp() + b"\x00" * 64)
    ev = import_evidence(db, str(image))
    result = run_pcap_reconstruction_job(
        db,
        {"evidence_id": ev["id"], "import_pcap_path": None},
        lambda: False,
        lambda *a, **k: None,
        paths=paths,
    )
    assert result["reconstruction"]["observed"]["imported_pcap_path"] is None
    db.close()


def test_import_pcap_missing_file(tmp_path: Path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(b"\x00" * 64)
    with pytest.raises(AppError) as err:
        validate_import_pcap(str(tmp_path / "nope.pcap"), evidence_path=image)
    assert err.value.code == "pcap_import_missing"


def test_import_pcap_rejects_evidence_itself(tmp_path: Path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(struct.pack("<I", PCAP_MAGIC) + b"\x00" * 64)
    with pytest.raises(AppError) as err:
        validate_import_pcap(str(image), evidence_path=image)
    assert err.value.code == "pcap_import_denied"


def test_import_pcap_rejects_pcapng(tmp_path: Path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(b"\x00" * 64)
    ng = tmp_path / "capture.pcapng"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 64)
    with pytest.raises(AppError) as err:
        validate_import_pcap(str(ng), evidence_path=image)
    assert err.value.code == "pcap_import_unsupported"


def test_import_pcap_rejects_non_pcap(tmp_path: Path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(b"\x00" * 64)
    other = tmp_path / "random.bin"
    other.write_bytes(b"\x7fELF" + b"\x00" * 64)
    with pytest.raises(AppError) as err:
        validate_import_pcap(str(other), evidence_path=image)
    assert err.value.code == "pcap_import_invalid"
