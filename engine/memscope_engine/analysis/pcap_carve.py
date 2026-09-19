"""Carve Ethernet/IP packet records from a memory image and write classic PCAP.

This recovers bytes that already look like packets (NIC buffers, NDIS, raw IP).
It does not invent headers, payloads, MAC addresses, or capture timestamps.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Iterable

PCAP_MAGIC = 0xA1B2C3D4
# Same magic bytes (a1 b2 c3 d4) read as a little-endian uint32 → big-endian file.
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101  # LINKTYPE_RAW in savefiles (IPv4 or IPv6)

CHUNK_SIZE = 8 * 1024 * 1024
CHUNK_OVERLAP = 64 * 1024
MAX_PACKETS = 20_000
MAX_PACKET_LEN = 65535
MIN_IPV4_LEN = 20
MIN_IPV6_LEN = 40
# Reject jumbo claims that are usually false positives in RAM.
MAX_PLAUSIBLE_LEN = 9000

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
_IP_PROTOS = {PROTO_ICMP, PROTO_TCP, PROTO_UDP}
_IP6_NEXT = {PROTO_TCP, PROTO_UDP, PROTO_ICMPV6, 0, 43, 44, 51, 60}

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD


@dataclass(frozen=True)
class CarvedPacket:
    offset: int
    linktype: int
    data: bytes
    orig_len: int
    truncated: bool
    ip_version: int
    protocol: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    source: str = "packet_carve"

    @property
    def incl_len(self) -> int:
        return len(self.data)

    def five_tuple(self) -> tuple[str, int, str, int, str] | None:
        if not self.src_ip or not self.dst_ip or not self.protocol:
            return None
        if self.src_port is None or self.dst_port is None:
            return None
        proto = self.protocol.lower()
        if proto not in ("tcp", "udp"):
            return None
        return (self.src_ip, int(self.src_port), self.dst_ip, int(self.dst_port), proto)


@dataclass
class CarveResult:
    packets: list[CarvedPacket] = field(default_factory=list)
    bytes_scanned: int = 0
    image_size: int = 0
    skipped_invalid: int = 0
    truncated_count: int = 0
    ethernet_count: int = 0
    raw_ip_count: int = 0
    cancelled: bool = False


def ipv4_header_checksum(header: bytes) -> int:
    if len(header) < 20 or len(header) % 2:
        return -1
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _u16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _fmt_ipv4(data: bytes, offset: int) -> str:
    return str(ipaddress.IPv4Address(data[offset : offset + 4]))


def _fmt_ipv6(data: bytes, offset: int) -> str:
    return str(ipaddress.IPv6Address(data[offset : offset + 16]))


def _transport(
    packet: bytes, ip_off: int, ihl: int, proto: int, total_len: int
) -> tuple[str | None, int | None, int | None]:
    name = {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp", PROTO_ICMPV6: "icmpv6"}.get(proto)
    if name in (None, "icmp", "icmpv6"):
        return name, None, None
    start = ip_off + ihl
    if start + 4 > len(packet) or start + 4 > total_len:
        return name, None, None
    sport = _u16(packet, start)
    dport = _u16(packet, start + 2)
    if name == "tcp":
        # Minimum TCP header is 20 bytes. Incomplete headers are truncated, not invalid.
        if start + 20 > len(packet):
            return name, sport, dport
        data_off = (packet[start + 12] >> 4) * 4
        if data_off < 20:
            return None, None, None
    elif name == "udp":
        if start + 8 > len(packet):
            return name, sport, dport
        udp_len = _u16(packet, start + 4)
        if udp_len < 8:
            return None, None, None
    return name, sport, dport


def parse_ipv4(buffer: bytes, offset: int) -> dict[str, Any] | None:
    if offset + MIN_IPV4_LEN > len(buffer):
        return None
    vihl = buffer[offset]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or ihl > 60 or offset + ihl > len(buffer):
        return None
    total_len = _u16(buffer, offset + 2)
    if total_len < ihl or total_len > MAX_PACKET_LEN:
        return None
    if total_len > MAX_PLAUSIBLE_LEN:
        return None
    proto = buffer[offset + 9]
    if proto not in _IP_PROTOS:
        return None
    ttl = buffer[offset + 8]
    if ttl == 0:
        return None
    header = bytearray(buffer[offset : offset + ihl])
    header[10] = 0
    header[11] = 0
    check = ipv4_header_checksum(bytes(header))
    claimed = _u16(buffer, offset + 10)
    if check != claimed:
        return None
    try:
        src = _fmt_ipv4(buffer, offset + 12)
        dst = _fmt_ipv4(buffer, offset + 16)
    except (ValueError, ipaddress.AddressValueError):
        return None
    available = len(buffer) - offset
    truncated = available < total_len
    take = min(available, total_len)
    if take < ihl:
        return None
    payload = bytes(buffer[offset : offset + take])
    proto_name, sport, dport = _transport(payload, 0, ihl, proto, total_len)
    if proto_name is None and proto in (PROTO_TCP, PROTO_UDP):
        return None
    return {
        "total_len": total_len,
        "ihl": ihl,
        "protocol": proto_name or str(proto),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "ip_version": 4,
        "data": payload,
        "truncated": truncated,
        "orig_len": total_len,
    }


def parse_ipv6(buffer: bytes, offset: int) -> dict[str, Any] | None:
    if offset + MIN_IPV6_LEN > len(buffer):
        return None
    if (buffer[offset] >> 4) != 6:
        return None
    payload_len = _u16(buffer, offset + 4)
    if payload_len < 0 or payload_len > MAX_PLAUSIBLE_LEN - MIN_IPV6_LEN:
        return None
    next_hdr = buffer[offset + 6]
    if next_hdr not in _IP6_NEXT:
        return None
    hop = buffer[offset + 7]
    if hop == 0:
        return None
    total_len = MIN_IPV6_LEN + payload_len
    if total_len < MIN_IPV6_LEN + 8 and next_hdr in (PROTO_TCP, PROTO_UDP):
        return None
    try:
        src = _fmt_ipv6(buffer, offset + 8)
        dst = _fmt_ipv6(buffer, offset + 24)
    except (ValueError, ipaddress.AddressValueError):
        return None
    if src == "::" and dst == "::":
        return None
    available = len(buffer) - offset
    truncated = available < total_len
    take = min(available, total_len)
    if take < MIN_IPV6_LEN:
        return None
    payload = bytes(buffer[offset : offset + take])
    proto_name, sport, dport = _transport(payload, 0, MIN_IPV6_LEN, next_hdr, total_len)
    if next_hdr in (PROTO_TCP, PROTO_UDP) and proto_name is None:
        return None
    return {
        "total_len": total_len,
        "ihl": MIN_IPV6_LEN,
        "protocol": proto_name or str(next_hdr),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "ip_version": 6,
        "data": payload,
        "truncated": truncated,
        "orig_len": total_len,
    }


def parse_ethernet(buffer: bytes, offset: int) -> dict[str, Any] | None:
    if offset + 14 + MIN_IPV4_LEN > len(buffer):
        return None
    ethertype = _u16(buffer, offset + 12)
    inner_off = offset + 14
    parsed: dict[str, Any] | None = None
    if ethertype == ETHERTYPE_IPV4:
        parsed = parse_ipv4(buffer, inner_off)
    elif ethertype == ETHERTYPE_IPV6:
        parsed = parse_ipv6(buffer, inner_off)
    if not parsed:
        return None
    frame_len = 14 + int(parsed["orig_len"])
    available = len(buffer) - offset
    truncated = parsed["truncated"] or available < frame_len
    take = min(available, frame_len, MAX_PACKET_LEN)
    if take < 14 + parsed["ihl"]:
        return None
    data = bytes(buffer[offset : offset + take])
    return {
        **parsed,
        "data": data,
        "truncated": truncated,
        "orig_len": frame_len,
        "linktype": LINKTYPE_ETHERNET,
        "inner_ip_offset": inner_off,
    }


def _candidate_indexes(chunk: bytes, needle: bytes) -> Iterable[int]:
    start = 0
    while True:
        idx = chunk.find(needle, start)
        if idx < 0:
            return
        yield idx
        start = idx + 1


def _ip_version_indexes(chunk: bytes, version: int) -> Iterable[int]:
    """Byte offsets whose high nibble is the IP version (IHL / traffic class still varies)."""
    lo = version << 4
    # IPv4 IHL 5–15 → 0x45–0x4F. IPv6: 0x60–0x6F (traffic class in low nibble).
    start = lo + 5 if version == 4 else lo
    for value in range(start, lo + 16):
        yield from _candidate_indexes(chunk, bytes((value,)))


def carve_buffer(
    buffer: bytes,
    *,
    base_offset: int = 0,
    consumed: set[int] | None = None,
    max_packets: int = MAX_PACKETS,
    existing: int = 0,
    include_raw_ip: bool = True,
    include_ipv6: bool = True,
) -> tuple[list[CarvedPacket], int, set[int]]:
    """Carve packets from a buffer.

    `consumed` holds absolute start offsets plus Ethernet inner-IP offsets so the
    same frame is not stored twice (Ethernet + raw IP).
    """
    found: list[CarvedPacket] = []
    skipped = 0
    covered = consumed if consumed is not None else set()
    budget = max(0, max_packets - existing)

    def _accept(pkt: CarvedPacket, inner_ip_offset: int | None = None) -> bool:
        nonlocal skipped
        if len(found) >= budget:
            return False
        if pkt.offset in covered:
            skipped += 1
            return True
        found.append(pkt)
        covered.add(pkt.offset)
        if inner_ip_offset is not None:
            covered.add(inner_ip_offset)
        return True

    # Ethernet frames first so inner IP is not also stored as raw IP.
    needles = [b"\x08\x00"]
    if include_ipv6:
        needles.append(b"\x86\xdd")
    for needle in needles:
        for rel in _candidate_indexes(buffer, needle):
            if len(found) >= budget:
                break
            if rel < 12:
                continue
            start = rel - 12
            abs_off = base_offset + start
            if abs_off in covered:
                continue
            parsed = parse_ethernet(buffer, start)
            if not parsed:
                skipped += 1
                continue
            if not include_ipv6 and int(parsed.get("ip_version") or 0) == 6:
                skipped += 1
                continue
            pkt = _packet_from_parsed(parsed, abs_off, LINKTYPE_ETHERNET)
            inner = parsed.get("inner_ip_offset")
            inner_abs = (base_offset + int(inner)) if inner is not None else None
            if not _accept(pkt, inner_abs):
                break

    if include_raw_ip:
        parsers: list[tuple[int, Any]] = [(4, parse_ipv4)]
        if include_ipv6:
            parsers.append((6, parse_ipv6))
        for version, parse in parsers:
            if len(found) >= budget:
                break
            for rel in _ip_version_indexes(buffer, version):
                if len(found) >= budget:
                    break
                abs_off = base_offset + rel
                if abs_off in covered:
                    continue
                parsed = parse(buffer, rel)
                if not parsed:
                    skipped += 1
                    continue
                pkt = _packet_from_parsed(parsed, abs_off, LINKTYPE_RAW)
                if not _accept(pkt):
                    break

    return found, skipped, covered


def _packet_from_parsed(parsed: dict[str, Any], offset: int, linktype: int) -> CarvedPacket:
    return CarvedPacket(
        offset=offset,
        linktype=int(parsed.get("linktype") or linktype),
        data=parsed["data"],
        orig_len=int(parsed["orig_len"]),
        truncated=bool(parsed["truncated"]),
        ip_version=int(parsed["ip_version"]),
        protocol=parsed.get("protocol"),
        src_ip=parsed.get("src_ip"),
        dst_ip=parsed.get("dst_ip"),
        src_port=parsed.get("src_port"),
        dst_port=parsed.get("dst_port"),
    )


def carve_image(
    path: Path,
    *,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[float, str | None], None] | None = None,
    max_packets: int = MAX_PACKETS,
    include_raw_ip: bool = True,
    include_ipv6: bool = True,
) -> CarveResult:
    result = CarveResult()
    image = Path(path)
    size = image.stat().st_size
    result.image_size = size
    if size <= 0:
        return result
    covered: set[int] = set()
    offset = 0
    with image.open("rb") as fh:
        while offset < size:
            if cancelled and cancelled():
                result.cancelled = True
                break
            fh.seek(offset)
            take = min(CHUNK_SIZE + CHUNK_OVERLAP, size - offset)
            chunk = fh.read(take)
            if not chunk:
                break
            packets, skipped, covered = carve_buffer(
                chunk,
                base_offset=offset,
                consumed=covered,
                max_packets=max_packets,
                existing=len(result.packets),
                include_raw_ip=include_raw_ip,
                include_ipv6=include_ipv6,
            )
            result.packets.extend(packets)
            result.skipped_invalid += skipped
            scanned_end = offset + max(0, len(chunk) - CHUNK_OVERLAP if offset + take < size else len(chunk))
            result.bytes_scanned = min(size, scanned_end)
            if progress:
                frac = result.bytes_scanned / size if size else 1.0
                progress(frac, f"Scanning memory image for packet records ({result.bytes_scanned}/{size})")
            if len(result.packets) >= max_packets:
                break
            if offset + take >= size:
                result.bytes_scanned = size
                break
            offset += CHUNK_SIZE
    result.packets.sort(key=lambda p: p.offset)
    result.truncated_count = sum(1 for p in result.packets if p.truncated)
    result.ethernet_count = sum(1 for p in result.packets if p.linktype == LINKTYPE_ETHERNET)
    result.raw_ip_count = sum(1 for p in result.packets if p.linktype == LINKTYPE_RAW)
    return result


def write_pcap(path: Path, packets: list[CarvedPacket], *, linktype: int) -> int:
    """Write a classic libpcap file. Only packets matching `linktype` are included."""
    path.parent.mkdir(parents=True, exist_ok=True)
    matching = [p for p in packets if p.linktype == linktype]
    with path.open("wb") as fh:
        fh.write(
            struct.pack(
                "<IHHIIII",
                PCAP_MAGIC,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,
                0,
                MAX_PACKET_LEN,
                linktype,
            )
        )
        for pkt in matching:
            data = pkt.data[:MAX_PACKET_LEN]
            orig = min(pkt.orig_len, MAX_PACKET_LEN)
            incl = len(data)
            # Capture timestamps are not present on carved memory-resident packets.
            fh.write(struct.pack("<IIII", 0, 0, incl, orig))
            fh.write(data)
    return path.stat().st_size


def read_pcap(path: Path, *, source: str = "pcap_file") -> list[CarvedPacket]:
    """Parse a classic PCAP (little- or big-endian). Used to reuse bulk_extractor packets.pcap."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le == PCAP_MAGIC:
        endian = "<"
    elif magic_le == PCAP_MAGIC_BE:
        endian = ">"
    else:
        return []
    _magic, major, minor, _zone, _sig, _snap, network = struct.unpack_from(f"{endian}IHHIIII", data, 0)
    if major != PCAP_VERSION_MAJOR:
        return []
    packets: list[CarvedPacket] = []
    offset = 24
    while offset + 16 <= len(data) and len(packets) < MAX_PACKETS:
        _ts, _tu, incl, orig = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if incl > MAX_PACKET_LEN or offset + incl > len(data):
            break
        raw = data[offset : offset + incl]
        offset += incl
        parsed = _describe_frame(raw, network)
        packets.append(
            CarvedPacket(
                offset=offset - incl,
                linktype=network if network in (LINKTYPE_ETHERNET, LINKTYPE_RAW) else LINKTYPE_RAW,
                data=raw,
                orig_len=orig or incl,
                truncated=incl < orig,
                ip_version=parsed.get("ip_version") or 0,
                protocol=parsed.get("protocol"),
                src_ip=parsed.get("src_ip"),
                dst_ip=parsed.get("dst_ip"),
                src_port=parsed.get("src_port"),
                dst_port=parsed.get("dst_port"),
                source=source,
            )
        )
    return packets


def _describe_frame(raw: bytes, network: int) -> dict[str, Any]:
    if network == LINKTYPE_ETHERNET:
        parsed = parse_ethernet(raw + b"\x00" * 64, 0)
        return parsed or {}
    parsed = parse_ipv4(raw + b"\x00" * 40, 0) or parse_ipv6(raw + b"\x00" * 40, 0)
    return parsed or {}


def canonical_ip(value: str | None) -> str:
    """Normalize IPv4-mapped IPv6 (::ffff:a.b.c.d) to dotted IPv4."""
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return str(addr)


def flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> tuple[Any, ...]:
    proto = protocol.lower().replace("ipv4", "").replace("ipv6", "").replace("v4", "").replace("v6", "")
    proto = proto.strip() or protocol.lower()
    if proto.startswith("tcp"):
        proto = "tcp"
    elif proto.startswith("udp"):
        proto = "udp"
    src = canonical_ip(src_ip) or src_ip
    dst = canonical_ip(dst_ip) or dst_ip
    a = (src, int(src_port), dst, int(dst_port))
    b = (dst, int(dst_port), src, int(src_port))
    ends = a if a <= b else b
    return (proto, ends)


def packet_matches_flow(pkt: CarvedPacket, key: tuple[Any, ...]) -> bool:
    tup = pkt.five_tuple()
    if not tup:
        return False
    return flow_key(*tup) == key


def write_pcap_pair(
    out_dir: Path,
    packets: list[CarvedPacket],
    *,
    stem: str = "packets",
) -> dict[str, Any]:
    """Write one or two classic PCAPs so Ethernet and raw IP are never mixed."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ethernet = [p for p in packets if p.linktype == LINKTYPE_ETHERNET]
    raw_ip = [p for p in packets if p.linktype == LINKTYPE_RAW]
    files: list[dict[str, Any]] = []
    primary: Path | None = None
    if ethernet:
        path = out_dir / f"{stem}.pcap"
        size = write_pcap(path, ethernet, linktype=LINKTYPE_ETHERNET)
        rec = {"name": path.name, "kind": "pcap_ethernet", "linktype": LINKTYPE_ETHERNET, "packet_count": len(ethernet), "size_bytes": size, "path": str(path)}
        files.append(rec)
        primary = path
    if raw_ip:
        name = f"{stem}.pcap" if not ethernet else f"{stem}-rawip.pcap"
        path = out_dir / name
        size = write_pcap(path, raw_ip, linktype=LINKTYPE_RAW)
        rec = {"name": path.name, "kind": "pcap_raw_ip", "linktype": LINKTYPE_RAW, "packet_count": len(raw_ip), "size_bytes": size, "path": str(path)}
        files.append(rec)
        if primary is None:
            primary = path
    return {
        "files": files,
        "primary_path": str(primary) if primary else None,
        "packet_count": len(packets),
        "ethernet_count": len(ethernet),
        "raw_ip_count": len(raw_ip),
    }


def filter_packets_for_flow(packets: list[CarvedPacket], key: tuple[Any, ...]) -> list[CarvedPacket]:
    return [p for p in packets if packet_matches_flow(p, key)]


def write_flow_pcap(path: Path, packets: list[CarvedPacket]) -> int:
    if not packets:
        return 0
    ethernet = [p for p in packets if p.linktype == LINKTYPE_ETHERNET]
    chosen = ethernet or packets
    linktype = chosen[0].linktype
    return write_pcap(path, chosen, linktype=linktype)


def overall_status(packets: list[CarvedPacket]) -> str:
    if not packets:
        return "unavailable"
    if any(p.truncated for p in packets):
        return "partially_reconstructed"
    return "packets_recovered"


# Keep a reference so type checkers accept BinaryIO usage in tests.
_ = BinaryIO
