"""Generate CyberSuite's Windows .ico using only Python's standard library."""
from __future__ import annotations

import math
import struct
from pathlib import Path

SIZE = 64
OUT = Path(__file__).resolve().parents[1] / "assets" / "cybersuite.ico"


def inside_polygon(x: float, y: float, points: list[tuple[float, float]]) -> bool:
    inside = False
    j = len(points) - 1
    for i, (xi, yi) in enumerate(points):
        xj, yj = points[j]
        if ((yi > y) != (yj > y)) and x < (xj - xi) * (y - yi) / ((yj - yi) or 1e-9) + xi:
            inside = not inside
        j = i
    return inside


def segment_distance(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    dx, dy = bx - ax, by - ay
    if dx == dy == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def make_icon() -> bytes:
    shield = [(32, 5), (53, 13), (52, 32), (48, 44), (40, 54), (32, 60),
              (24, 54), (16, 44), (12, 32), (11, 13)]
    circuit = [((32, 18), (32, 28)), ((32, 28), (23, 36)),
               ((32, 28), (41, 36)), ((23, 36), (23, 45)),
               ((41, 36), (41, 45)), ((27, 49), (37, 49))]
    pixels = bytearray()
    for y in range(SIZE - 1, -1, -1):
        for x in range(SIZE):
            cx, cy = x + 0.5, y + 0.5
            inside = inside_polygon(cx, cy, shield)
            if inside:
                # Deep green shield with a bright mint border.
                edge = min(segment_distance(cx, cy, *shield[i], *shield[(i + 1) % len(shield)]) for i in range(len(shield)))
                color = (18, 38, 25, 255) if edge > 2.0 else (110, 239, 137, 255)
                for (a, b) in circuit:
                    if segment_distance(cx, cy, *a, *b) < 1.8:
                        color = (145, 255, 112, 255)
                for nx, ny in ((32, 18), (23, 45), (41, 45)):
                    if math.hypot(cx - nx, cy - ny) < 3.0:
                        color = (190, 255, 132, 255)
            else:
                color = (8, 13, 10, 255)
            r, g, b, a = color
            pixels.extend((b, g, r, a))

    # A 32-bit icon DIB stores a doubled height: XOR bitmap + AND mask.
    mask = bytes(((SIZE + 31) // 32) * 4 * SIZE)
    header = struct.pack("<IIIHHIIIIII", 40, SIZE, SIZE * 2, 1, 32, 0,
                         len(pixels), 0, 0, 0, 0)
    image = header + pixels + mask
    directory = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", SIZE, SIZE, 0, 0, 1, 32, len(image), 22)
    return directory + entry + image


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(make_icon())
    print(f"Generated {OUT}")
