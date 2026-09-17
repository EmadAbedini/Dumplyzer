"""Generate Tauri / Windows icon assets from the Dumplyzer source PNG.

The official artwork is ``app/desktop/icons/Dumplyzer.png``. This generator does not invent a background
tile. It converts the source to 32bpp, scales it to fill each canvas, applies a
moderate rounded-rect mask (12% of the canvas — enough to soften corners like a
modern Windows app icon, not a squircle or pill), and writes Windows-safe ICO frames:

* Every size below 256: 32bpp BMP + 1bpp AND mask (Explorer/shortcut-safe)
* 256: PNG-in-ICO (high-quality source for Taskbar / Alt+Tab downscale)

The 256 PNG frame is written first. Tauri's codegen uses ``entries()[0]`` as the
live window icon (ICON_SMALL). Putting 16px first made the Taskbar stretch a
16×16 bitmap. Windows still size-matches later directory entries for shortcuts.
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT / "app" / "desktop" / "icons"
SOURCE = ICONS / "Dumplyzer.png"
CANONICAL_1024 = ICONS / "icon-source-1024.png"

CS_HELPER = r"""
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

public static class DumplyzerIconPipeline {
  // 12% of the canvas. Windows 11 plated icons are closer to 16–20% (squircle);
  // this only softens the square so the silhouette stays a rounded rectangle.
  const float CornerRadiusRatio = 0.12f;

  static GraphicsPath RoundedRect(float x, float y, float w, float h, float r) {
    var path = new GraphicsPath();
    if (r < 0.5f) {
      path.AddRectangle(new RectangleF(x, y, w, h));
      return path;
    }
    if (r > w / 2f) r = w / 2f;
    if (r > h / 2f) r = h / 2f;
    float d = r * 2f;
    path.AddArc(x, y, d, d, 180, 90);
    path.AddArc(x + w - d, y, d, d, 270, 90);
    path.AddArc(x + w - d, y + h - d, d, d, 0, 90);
    path.AddArc(x, y + h - d, d, d, 90, 90);
    path.CloseFigure();
    return path;
  }

  static void ApplyRoundedCorners(Bitmap bmp, float radius) {
    int w = bmp.Width, h = bmp.Height;
    using (var mask = new Bitmap(w, h, PixelFormat.Format32bppArgb)) {
      using (var g = Graphics.FromImage(mask)) {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.CompositingQuality = CompositingQuality.HighQuality;
        g.Clear(Color.Transparent);
        using (var path = RoundedRect(0, 0, w, h, radius))
        using (var br = new SolidBrush(Color.White)) {
          g.FillPath(br, path);
        }
      }
      for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
          Color c = bmp.GetPixel(x, y);
          Color m = mask.GetPixel(x, y);
          int a = (c.A * m.A) / 255;
          bmp.SetPixel(x, y, Color.FromArgb(a, c));
        }
      }
    }
  }

  public static void Prepare(string srcPath, string destPath) {
    using (var srcImg = new Bitmap(srcPath)) {
      int w = 1024, h = 1024;
      var canvas = new Bitmap(w, h, PixelFormat.Format32bppArgb);
      using (var g = Graphics.FromImage(canvas)) {
        g.CompositingMode = CompositingMode.SourceCopy;
        g.CompositingQuality = CompositingQuality.HighQuality;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.SmoothingMode = SmoothingMode.HighQuality;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.Clear(Color.Transparent);
        g.CompositingMode = CompositingMode.SourceOver;
        g.DrawImage(srcImg, 0, 0, w, h);
      }
      ApplyRoundedCorners(canvas, w * CornerRadiusRatio);
      canvas.Save(destPath, ImageFormat.Png);
      canvas.Dispose();
    }
  }

  static byte[] EncodeBmpFrame(Bitmap bmp) {
    int w = bmp.Width, h = bmp.Height;
    int xorStride = w * 4;
    int andStride = ((w + 31) / 32) * 4;
    byte[] xor = new byte[xorStride * h];
    byte[] and = new byte[andStride * h];
    for (int y = 0; y < h; y++) {
      int destY = h - 1 - y;
      for (int x = 0; x < w; x++) {
        Color c = bmp.GetPixel(x, y);
        int i = destY * xorStride + x * 4;
        xor[i] = c.B;
        xor[i + 1] = c.G;
        xor[i + 2] = c.R;
        xor[i + 3] = c.A;
        if (c.A < 128) {
          and[destY * andStride + (x / 8)] |= (byte)(0x80 >> (x % 8));
        }
      }
    }
    using (var ms = new MemoryStream())
    using (var bw = new BinaryWriter(ms)) {
      bw.Write(40);
      bw.Write(w);
      bw.Write(h * 2);
      bw.Write((short)1);
      bw.Write((short)32);
      bw.Write(0);
      bw.Write(xor.Length + and.Length);
      bw.Write(0);
      bw.Write(0);
      bw.Write(0);
      bw.Write(0);
      bw.Write(xor);
      bw.Write(and);
      return ms.ToArray();
    }
  }

  public static void WriteIco(string destPath, string pngList) {
    string[] pngPaths = pngList.Split('|');
    var frames = new List<byte[]>();
    var sizes = new List<int>();
    foreach (string pngPath in pngPaths) {
      using (var bmp = new Bitmap(pngPath)) {
        sizes.Add(bmp.Width);
        if (bmp.Width >= 256) frames.Add(File.ReadAllBytes(pngPath));
        else frames.Add(EncodeBmpFrame(bmp));
      }
    }
    int n = frames.Count;
    int offset = 6 + 16 * n;
    using (var ms = new MemoryStream())
    using (var bw = new BinaryWriter(ms)) {
      bw.Write((short)0);
      bw.Write((short)1);
      bw.Write((short)n);
      for (int i = 0; i < n; i++) {
        int size = sizes[i];
        bw.Write((byte)(size >= 256 ? 0 : size));
        bw.Write((byte)(size >= 256 ? 0 : size));
        bw.Write((byte)0);
        bw.Write((byte)0);
        bw.Write((short)1);
        bw.Write((short)32);
        bw.Write(frames[i].Length);
        bw.Write(offset);
        offset += frames[i].Length;
      }
      for (int i = 0; i < n; i++) bw.Write(frames[i]);
      File.WriteAllBytes(destPath, ms.ToArray());
    }
  }

  public static void ResizePng(string srcPath, string destPath, int size) {
    using (var src = new Bitmap(srcPath)) {
      var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
      using (var g = Graphics.FromImage(bmp)) {
        g.CompositingMode = CompositingMode.SourceOver;
        g.CompositingQuality = CompositingQuality.HighQuality;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.SmoothingMode = SmoothingMode.HighQuality;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.Clear(Color.Transparent);
        g.DrawImage(src, 0, 0, size, size);
      }
      bmp.Save(destPath, ImageFormat.Png);
      bmp.Dispose();
    }
  }
}
"""


def _run_csharp(script: str) -> None:
    cs_path = ICONS / "_icon_pipeline.cs"
    ps1 = ICONS / "_icon_pipeline.ps1"
    cs_path.write_text(CS_HELPER, encoding="utf-8")
    ps1.write_text(
        "Add-Type -AssemblyName System.Drawing\n"
        f"Add-Type -TypeDefinition (Get-Content -Raw -LiteralPath '{cs_path}') "
        "-ReferencedAssemblies System.Drawing\n"
        f"{script}\n",
        encoding="utf-8",
    )
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ps1),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr or proc.stdout or "icon pipeline failed")
        if proc.stdout:
            print(proc.stdout.strip())
    finally:
        cs_path.unlink(missing_ok=True)
        ps1.unlink(missing_ok=True)


def write_icns(png_256: bytes, dest: Path) -> None:
    inner = b"ic08" + struct.pack(">I", len(png_256) + 8) + png_256
    dest.write_bytes(b"icns" + struct.pack(">I", len(inner) + 8) + inner)


# Order matters: 256 is first so Tauri embeds a high-res live window icon.
# Remaining sizes cover 100–200% DPI Taskbar, pinned shortcuts, and Explorer.
ICO_SIZES = (256, 128, 64, 48, 40, 32, 24, 20, 16)


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"missing source icon: {SOURCE}")
    ICONS.mkdir(parents=True, exist_ok=True)
    prepared = ICONS / "_icon-prepared.png"
    png32 = ICONS / "32x32.png"
    png128 = ICONS / "128x128.png"
    png256 = ICONS / "128x128@2x.png"
    temps: dict[int, Path] = {}
    for size in ICO_SIZES:
        if size == 32:
            temps[size] = png32
        elif size == 128:
            temps[size] = png128
        elif size == 256:
            temps[size] = png256
        else:
            temps[size] = ICONS / f"_{size}.png"
    ico = ICONS / "icon.ico"
    try:
        lines = [f"[DumplyzerIconPipeline]::Prepare('{SOURCE}', '{prepared}')"]
        for size in ICO_SIZES:
            lines.append(
                f"[DumplyzerIconPipeline]::ResizePng('{prepared}', '{temps[size]}', {size})"
            )
        ico_list = "|".join(str(temps[size]) for size in ICO_SIZES)
        lines.append(f"[DumplyzerIconPipeline]::WriteIco('{ico}', '{ico_list}')")
        _run_csharp("\n".join(lines) + "\n")
        write_icns(png256.read_bytes(), ICONS / "icon.icns")
        prepared.replace(CANONICAL_1024)
    finally:
        for size, path in temps.items():
            if size not in (32, 128, 256):
                path.unlink(missing_ok=True)
        prepared.unlink(missing_ok=True)
    print("icons ok", sorted(p.name for p in ICONS.iterdir() if p.is_file()))


if __name__ == "__main__":
    sys.exit(main())
