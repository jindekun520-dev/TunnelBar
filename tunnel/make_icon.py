#!/usr/bin/env python3
"""生成 TunnelClient 应用图标 (.icns)"""
import os
from PIL import Image, ImageDraw, ImageFilter

SIZES = [16, 32, 64, 128, 256, 512]
OUT_DIR = os.path.join(os.path.dirname(__file__), "TunnelClient.app", "Contents", "Resources", "icons.iconset")
ICNS = os.path.join(os.path.dirname(__file__), "TunnelClient.app", "Contents", "Resources", "app.icns")
os.makedirs(OUT_DIR, exist_ok=True)


def round_rect(draw, box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def draw_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 背景圆角矩形（深蓝渐变感，用两层近似）
    pad = int(size * 0.06)
    round_rect(d, [pad, pad, size - pad, size - pad], int(size * 0.22), (24, 38, 64, 255))

    # 中心发光的连接节点（圆）
    cx, cy = size * 0.5, size * 0.5
    r = size * 0.10
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(56, 189, 248, 255))

    # 两侧节点
    r2 = size * 0.07
    left = (size * 0.26, size * 0.5)
    right = (size * 0.74, size * 0.5)
    for (x, y) in (left, right):
        d.ellipse([x - r2, y - r2, x + r2, y + r2], fill=(148, 163, 184, 255))

    # 连接线（隧道）
    lw = max(2, int(size * 0.022))
    d.line([left, (cx, cy)], fill=(56, 189, 248, 200), width=lw)
    d.line([(cx, cy), right], fill=(56, 189, 248, 200), width=lw)

    # 上行箭头（表示从本地打到家里）
    aw = max(3, int(size * 0.05))
    ax, ay = right
    d.line([(ax - size * 0.12, ay + size * 0.12), (ax, ay)], fill=(34, 197, 94, 255), width=aw)
    d.line([(ax, ay), (ax - size * 0.02, ay - size * 0.12)], fill=(34, 197, 94, 255), width=aw)
    d.line([(ax, ay), (ax - size * 0.13, ay - size * 0.04)], fill=(34, 197, 94, 255), width=aw)

    # 轻微外发光
    img = img.filter(ImageFilter.GaussianBlur(radius=max(0.5, size * 0.004)))
    return img


for s in SIZES:
    im = draw_icon(s)
    im.save(os.path.join(OUT_DIR, f"icon_{s}x{s}.png"))
    # @2x 版本
    im2 = draw_icon(s * 2)
    im2.save(os.path.join(OUT_DIR, f"icon_{s}x{s}@2x.png"))

print("iconset 生成完毕:", OUT_DIR)
