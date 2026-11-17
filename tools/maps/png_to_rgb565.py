#!/usr/bin/env python3
"""Convert map tiles into the T-Deck's raw RGB565 format for the SD card.

Input: a folder laid out as <zoom>/<x>/<y>.png (or .jpg), each image 256x256 pixels.
Output: the same layout with .bin files of 256*256 little-endian RGB565 values.

Copy the output folder to the SD card as /maps, so the device finds /maps/<z>/<x>/<y>.bin.

Usage:
    pip install pillow
    python3 png_to_rgb565.py tiles_in/ sd_card/maps/
"""
import argparse
import os
import struct

from PIL import Image

TILE = 256
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg")


def to_rgb565(path):
    img = Image.open(path).convert("RGB")
    if img.size != (TILE, TILE):
        img = img.resize((TILE, TILE))
    raw = img.tobytes()
    out = bytearray(TILE * TILE * 2)
    for i in range(TILE * TILE):
        r = raw[3 * i]
        g = raw[3 * i + 1]
        b = raw[3 * i + 2]
        value = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
        struct.pack_into("<H", out, 2 * i, value)
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("src", help="folder with <zoom>/<x>/<y>.png tiles")
    parser.add_argument("dst", help="output folder, usually sd_card/maps")
    args = parser.parse_args()

    converted = 0
    for root, _, files in os.walk(args.src):
        for name in files:
            base, ext = os.path.splitext(name)
            if ext.lower() not in IMAGE_EXTENSIONS:
                continue
            rel = os.path.relpath(os.path.join(root, name), args.src)
            parts = rel.split(os.sep)
            if len(parts) != 3 or not all(p.isdigit() for p in parts[0:2]) or not base.isdigit():
                print(f"skipped {rel}: expected <zoom>/<x>/<y>.png")
                continue
            out_dir = os.path.join(args.dst, parts[0], parts[1])
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, base + ".bin"), "wb") as f:
                f.write(to_rgb565(os.path.join(root, name)))
            converted += 1

    print(f"converted {converted} tiles into {args.dst}")


if __name__ == "__main__":
    main()
