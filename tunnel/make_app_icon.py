#!/usr/bin/env python3
"""生成 TunnelBar 应用图标（.icns）。

设计要点：
  * 遵循 macOS Big Sur 之后的图标栅格：1024 画布中圆角方块占 824（80.5%），
    圆角半径 ≈ 边长 × 0.2237，四周留出投影空间；
  * 主体为蓝→深蓝渐变底 + 白色盾牌（安全隧道），盾内挖出隧道拱洞，
    拱洞里留一颗"隧道尽头的光"，32px 下仍能分辨出"盾 + 暗洞 + 亮点"三层；
  * 每个尺寸都按 4 倍超采样绘制后 LANCZOS 缩小，避免小图标边缘发毛。

用法：
  python3 make_app_icon.py            # 生成 app.icns 到 tunnel/app/
  python3 make_app_icon.py --preview  # 额外输出各尺寸预览 PNG，便于肉眼检查
"""
import os
import subprocess
import sys

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "app")
ICONSET = os.path.join(OUT_DIR, "app.iconset")
ICNS = os.path.join(OUT_DIR, "app.icns")
PREVIEW = os.path.join(OUT_DIR, "icon-preview")

# 渐变：顶部亮蓝 → 底部深靛蓝
TOP = (74, 141, 255)
MID = (44, 91, 224)
BOT = (18, 34, 78)

SUPERSAMPLE = 4


def _lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def _gradient(size):
    """竖直双段渐变（顶亮 → 中亮 → 底深）。"""
    img = Image.new("RGB", (1, size))
    px = img.load()
    half = size / 2
    for y in range(size):
        if y < half:
            px[0, y] = _lerp(TOP, MID, y / half)
        else:
            px[0, y] = _lerp(MID, BOT, (y - half) / (half - 1 if half > 1 else 1))
    return img.resize((size, size), Image.BILINEAR)


def _squircle_mask(size):
    """Apple 圆角方块遮罩（超采样下用 rounded_rectangle 近似连续曲率）。"""
    body = size * 0.8047
    off = (size - body) / 2
    radius = body * 0.2237
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([off, off, off + body, off + body], radius=radius, fill=255)
    return mask, off, body


def _quad(p0, p1, p2, steps):
    """二次贝塞尔采样（含首尾）。"""
    pts = []
    for i in range(steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]
        pts.append((x, y))
    return pts


def _shield_polygon(cx, cy, w, h):
    """盾牌轮廓：平顶带小圆肩 → 直边 → 下半段收成尖角。"""
    x0, x1 = cx - w / 2, cx + w / 2
    top = cy - h / 2
    r = w * 0.15
    shoulder = top + h * 0.56

    pts = [(x0 + r, top)]
    pts += _quad((x0 + r, top), (x0, top), (x0, top + r), 8)[1:]          # 左上圆肩
    pts.append((x0, shoulder))                                            # 左边直下
    pts += _quad((x0, shoulder), (x0, top + h * 0.90), (cx, top + h), 26)[1:]  # 左下半弧 → 底尖
    pts += _quad((cx, top + h), (x1, top + h * 0.90), (x1, shoulder), 26)[1:]  # 右下半弧
    pts.append((x1, top + r))                                             # 右边直上
    pts += _quad((x1, top + r), (x1, top), (x1 - r, top), 8)[1:]          # 右上圆肩
    return pts


def draw(size):
    """按目标输出尺寸绘制（内部 4 倍超采样）。"""
    s = size * SUPERSAMPLE
    mask, off, body = _squircle_mask(s)

    # 1) 渐变底 + 圆角遮罩
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(_gradient(s), (0, 0), mask)

    # 2) 顶部一层极淡的高光，让方块看起来有玻璃感
    sheen = Image.new("L", (s, s), 0)
    sd = ImageDraw.Draw(sheen)
    for i in range(int(body * 0.45)):
        a = int(26 * (1 - i / (body * 0.45)) ** 2)
        sd.line([(0, off + i), (s, off + i)], fill=a)
    sheen = Image.composite(sheen, Image.new("L", (s, s), 0), mask)
    img.paste(Image.new("RGBA", (s, s), (255, 255, 255, 255)), (0, 0), sheen)

    # 3) 内描边：1.5px 白，模拟系统图标的边缘反射
    edge = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ed = ImageDraw.Draw(edge)
    inset = max(1, s * 0.004)
    ed.rounded_rectangle(
        [off + inset, off + inset, off + body - inset, off + body - inset],
        radius=body * 0.2237 - inset, outline=(255, 255, 255, 46),
        width=max(2, int(s * 0.0035)),
    )
    img.alpha_composite(edge)

    # 记下"纯底"（渐变+高光+描边），后面挖洞时用它回填，才真的透出背景
    bg = img.copy()

    # 4) 盾牌：白色实心
    cx, cy = s / 2, s / 2 - body * 0.005
    sw, sh = body * 0.50, body * 0.60
    shield = Image.new("L", (s, s), 0)
    ImageDraw.Draw(shield).polygon(_shield_polygon(cx, cy, sw, sh), fill=255)
    img.paste(Image.new("RGBA", (s, s), (255, 255, 255, 255)), (0, 0), shield)

    # 5) 盾牌里镂出一支向右的箭头（走隧道的流量），用纯底回填 = 真的挖穿。
    top = cy - sh / 2
    arrow = Image.new("L", (s, s), 0)
    ad = ImageDraw.Draw(arrow)
    ay = top + sh * 0.44                    # 箭头中线
    skew = sh * 0.055                       # 箭杆半高
    shaft_l = cx - sw * 0.30
    shaft_r = cx + sw * 0.06
    head_r = cx + sw * 0.32
    head_h = sh * 0.155
    ad.rounded_rectangle([shaft_l, ay - skew, shaft_r, ay + skew],
                         radius=skew, fill=255)
    ad.polygon([(shaft_r - skew * 0.4, ay - head_h),
                (head_r, ay),
                (shaft_r - skew * 0.4, ay + head_h)], fill=255)
    arrow = Image.composite(arrow, Image.new("L", (s, s), 0), shield)
    img.paste(bg, (0, 0), arrow)

    return img.resize((size, size), Image.LANCZOS)


def main():
    os.makedirs(ICONSET, exist_ok=True)
    # macOS iconset 需要的 10 个条目（含 @2x）
    entries = [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1),
               (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)]
    cache = {}
    for base, scale in entries:
        px = base * scale
        if px not in cache:
            cache[px] = draw(px)
        name = f"icon_{base}x{base}{'@2x' if scale == 2 else ''}.png"
        cache[px].save(os.path.join(ICONSET, name))

    if os.path.exists(ICNS):
        os.remove(ICNS)
    subprocess.run(["iconutil", "-c", "icns", ICONSET, "-o", ICNS], check=True)
    print("生成:", ICNS, os.path.getsize(ICNS), "bytes")

    if "--preview" in sys.argv:
        os.makedirs(PREVIEW, exist_ok=True)
        for px in (1024, 256, 128, 64, 32, 16):
            draw(px).save(os.path.join(PREVIEW, f"icon-{px}.png"))
        print("预览:", PREVIEW)


if __name__ == "__main__":
    main()
