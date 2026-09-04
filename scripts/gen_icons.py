import struct
import zlib
import pathlib

out = pathlib.Path(r"C:\Users\Stanly\Desktop\MemScope\app\desktop\icons")
out.mkdir(parents=True, exist_ok=True)


def write_png(size: int, path: pathlib.Path) -> None:
    raw = b"".join(b"\x00" + bytes([26, 58, 110, 255]) * size for _ in range(size))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    data = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(data)


def write_ico(sizes: list[int], path: pathlib.Path) -> None:
    images: list[tuple[int, bytes]] = []
    for s in sizes:
        p = out / f"_{s}.png"
        write_png(s, p)
        images.append((s, p.read_bytes()))
        p.unlink()
    num = len(images)
    offset = 6 + 16 * num
    dir_entries = []
    payloads = b""
    for s, data in images:
        w = 0 if s >= 256 else s
        h = 0 if s >= 256 else s
        dir_entries.append(struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
        payloads += data
    header = struct.pack("<HHH", 0, 1, num)
    path.write_bytes(header + b"".join(dir_entries) + payloads)


write_png(32, out / "32x32.png")
write_png(128, out / "128x128.png")
write_png(256, out / "128x128@2x.png")
write_ico([16, 32, 48, 256], out / "icon.ico")
png_bytes = (out / "128x128.png").read_bytes()
body = b"ic07" + struct.pack(">I", len(png_bytes) + 8) + png_bytes
(out / "icon.icns").write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)
print("icons ok", sorted(p.name for p in out.iterdir()))
