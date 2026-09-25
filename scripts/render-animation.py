#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["playwright==1.55.0"]
# ///

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Render the docs/example-workflow.md animation to docs/diagrams/workflow.gif.

The animation is an HTML page (docs/diagrams/animation/) whose state is a pure
function of time: window.anim.seek(t). This script steps headless Chrome
through time at a fixed frame rate, screenshots each frame, collapses runs of
identical frames into a single longer frame, and encodes with ffmpeg: a GIF
with one global palette, or (--mp4) an H.264 video.

Requirements: uv, ffmpeg, and Google Chrome (or `uv run --with playwright
playwright install chromium` and --browser chromium). Fonts load from jsDelivr
at render time, so a network connection is needed. gifsicle is optional but
recommended (brew install gifsicle): it makes the GIF roughly 25% smaller.

The MP4 is written to the git-ignored build directory by default: GitHub does
not play repository video files inline in Markdown. To embed it, drag the file
into GitHub's Markdown editor, which uploads it as an attachment.

Usage:
  scripts/render-animation.py                 # render docs/diagrams/workflow.gif
  scripts/render-animation.py --mp4           # 1920x1080 30 fps H.264, ends on the end card
  scripts/render-animation.py --stills 12,40  # just PNGs of those seconds (for review)
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import math
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from playwright.async_api import Browser, Page, async_playwright

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "docs" / "diagrams" / "animation"
BUILD = SRC / "build"  # git-ignored
OUT_GIF = REPO / "docs" / "diagrams" / "workflow.gif"
OUT_MP4 = BUILD / "workflow.mp4"

WIDTH, HEIGHT = 960, 540  # CSS px; the stage in index.html


async def open_page(browser: Browser, scale: float) -> tuple[Page, dict]:
    """Load the animation; returns the page and its timing info (duration, loopTail)."""
    page = await browser.new_page(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=scale)
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    await page.goto((SRC / "index.html").as_uri() + "?render")
    try:
        info = await page.evaluate("window.anim.ready")
    except Exception as exc:  # surface JS errors from the page, not a bare timeout
        raise SystemExit(f"animation failed to initialise: {exc}\n{chr(10).join(errors)}") from exc
    if errors:
        raise SystemExit("page errors:\n" + "\n".join(errors))
    return page, info


async def shoot(page, t: float) -> bytes:
    await page.evaluate("t => window.anim.seek(t)", t)
    return await page.screenshot(clip={"x": 0, "y": 0, "width": WIDTH, "height": HEIGHT}, type="png")


# Software rasterization: with the GPU path, parallel pages render the same
# instant with slightly different pixels, which defeats identical-frame
# collapsing (and bloats the GIF). With it off, every worker agrees exactly.
CHROME_ARGS = ["--disable-gpu"]


async def launch(pw, which: str) -> Browser:
    if which == "chrome":
        try:
            return await pw.chromium.launch(channel="chrome", args=CHROME_ARGS)
        except Exception as exc:
            raise SystemExit(
                f"could not launch Google Chrome ({exc}).\n"
                "Install Chrome, or run `uv run --with playwright==1.55.0 playwright install chromium` "
                "and pass --browser chromium."
            ) from exc
    return await pw.chromium.launch(args=CHROME_ARGS)


async def render_stills(args) -> None:
    out = BUILD / "stills"
    out.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as pw:
        browser = await launch(pw, args.browser)
        page, info = await open_page(browser, args.scale)
        for t in args.stills:
            path = out / f"t{t:06.2f}.png"
            path.write_bytes(await shoot(page, t))
            print(f"{path.relative_to(REPO)}")
        await browser.close()
    print(f"duration {info['duration']:.2f} s")


async def render_frames(args) -> tuple[list[Path], list[int], float]:
    frames_dir = BUILD / "frames"
    if frames_dir.exists():
        shutil.rmtree(frames_dir)
    frames_dir.mkdir(parents=True)

    async with async_playwright() as pw:
        browser = await launch(pw, args.browser)
        pages = []
        info: dict = {}
        for _ in range(args.jobs):
            page, info = await open_page(browser, args.scale)
            pages.append(page)

        # The animation ends by cross-fading back into its title card so the
        # GIF loops seamlessly. A video plays once, so it stops on the end card.
        end = info["duration"] - (info["loopTail"] if args.mp4 else 0)
        n = math.ceil(round(end * args.fps, 6))
        digests: list[str | None] = [None] * n
        done = 0
        started = time.monotonic()

        async def worker(w: int) -> None:
            nonlocal done
            for i in range(w, n, args.jobs):
                png = await shoot(pages[w], i / args.fps)
                digests[i] = hashlib.sha1(png).hexdigest()
                (frames_dir / f"{i:05d}.png").write_bytes(png)
                done += 1
                if done % 200 == 0:
                    print(f"  {done}/{n} frames ({time.monotonic() - started:.0f} s)", flush=True)

        await asyncio.gather(*(worker(w) for w in range(args.jobs)))
        await browser.close()

    # Collapse runs of identical frames: keep the first, extend its duration.
    keep: list[Path] = []
    counts: list[int] = []
    prev = None
    for i, d in enumerate(digests):
        if d == prev:
            counts[-1] += 1
            (frames_dir / f"{i:05d}.png").unlink()
        else:
            keep.append(frames_dir / f"{i:05d}.png")
            counts.append(1)
            prev = d
    return keep, counts, end


def write_concat(keep: list[Path], counts: list[int], fps: int) -> Path:
    """List the unique frames with their durations, for ffmpeg's concat demuxer."""
    # Paths inside an ffconcat file resolve relative to the file itself. Each
    # PNG is opened by the image2 demuxer, whose default 25 fps timebase would
    # quantise every delay to 4 or 8 cs (visible judder); `option framerate`
    # keeps the timestamps on the render grid so durations come out exact.
    concat = BUILD / "frames.ffconcat"
    lines = ["ffconcat version 1.0"]
    for path, count in zip(keep, counts):
        lines += [f"file 'frames/{path.name}'", f"option framerate {fps}", f"duration {count / fps:.6f}"]
    if counts[-1] > 1:
        # The concat demuxer drops the final entry's duration; a trailing
        # repeat of the frame makes it stick (at the cost of one extra frame).
        lines += [f"file 'frames/{keep[-1].name}'", f"option framerate {fps}"]
    concat.write_text("\n".join(lines) + "\n")
    return concat


def encode_mp4(concat: Path, fps: int, out: Path) -> None:
    # H.264 + yuv420p plays everywhere, Safari and iOS included. The frames are
    # sRGB, so tag Rec.709 primaries and matrix with the sRGB transfer curve;
    # tagging plain bt709 makes colour-managed players show it washed out. The
    # tags go on the frames (setparams): ffmpeg lets frame properties override
    # -color_* encoder flags. stillimage tuning keeps deblocking off text edges.
    tags = "setparams=color_primaries=bt709:color_trc=iec61966-2-1:colorspace=bt709:range=tv"
    subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat),
            "-vf",
            f"scale=out_color_matrix=bt709:out_range=tv,format=yuv420p,{tags}",
            "-fps_mode",
            "cfr",
            "-r",
            str(fps),
            "-c:v",
            "libx264",
            "-preset",
            "slow",
            "-crf",
            "20",
            "-tune",
            "stillimage",
            "-movflags",
            "+faststart",
            "-an",
            str(out),
        ],
        check=True,
    )


def encode_gif(concat: Path, out: Path, dither: str, gifsicle: str | None, lossy: int) -> None:
    # Flat UI colours: no dithering is both crisper and smaller than bayer.
    use = {"none": "dither=none", "bayer": "dither=bayer:bayer_scale=4"}[dither]
    graph = (
        "split[a][b];"
        "[a]palettegen=max_colors=256:stats_mode=full:reserve_transparent=1[p];"
        f"[b][p]paletteuse={use}:diff_mode=rectangle"
    )
    tmp = out.with_suffix(".tmp.gif")
    subprocess.run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat),
            "-lavfi",
            graph,
            "-fps_mode",
            "vfr",
            "-loop",
            "0",
            str(tmp),
        ],
        check=True,
    )
    if gifsicle:
        cmd = [gifsicle, "-O3", "--batch", str(tmp)]
        if lossy:
            cmd.insert(2, f"--lossy={lossy}")
        subprocess.run(cmd, check=True)
    else:
        print("note: gifsicle not found; the GIF is unoptimised (brew install gifsicle)")
    os.replace(tmp, out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mp4", action="store_true", help="render an H.264 video instead of the GIF")
    ap.add_argument("--fps", type=int, help="frame rate (default: GIF 20, MP4 30); a GIF's must divide 100")
    ap.add_argument("--scale", type=float, help="device pixel ratio: output is 960x540 times this (GIF 1.5, MP4 2)")
    ap.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1), help="parallel browser pages")
    ap.add_argument("--dither", choices=["none", "bayer"], default="none")
    ap.add_argument(
        "--gifsicle",
        default=os.environ.get("GIFSICLE") or shutil.which("gifsicle"),
        help="gifsicle binary (default: $GIFSICLE, then PATH)",
    )
    ap.add_argument("--lossy", type=int, default=30, help="gifsicle --lossy level; 0 = lossless")
    ap.add_argument("--browser", choices=["chrome", "chromium"], default="chrome")
    ap.add_argument("--out", type=Path, help="output file (default: docs/diagrams/workflow.gif, or build/ for MP4)")
    ap.add_argument(
        "--stills", type=lambda s: [float(x) for x in s.split(",")], help="render PNGs at these seconds only"
    )
    args = ap.parse_args()
    args.fps = args.fps or (30 if args.mp4 else 20)
    args.scale = args.scale or (2.0 if args.mp4 else 1.5)
    args.out = (args.out or (OUT_MP4 if args.mp4 else OUT_GIF)).resolve()

    if args.stills:
        asyncio.run(render_stills(args))
        return
    if not args.mp4 and 100 % args.fps:
        sys.exit("--fps must divide 100 for a GIF (frame delays are whole centiseconds)")
    if not shutil.which("ffmpeg"):
        sys.exit("error: ffmpeg not found (brew install ffmpeg)")

    t0 = time.monotonic()
    keep, counts, length = asyncio.run(render_frames(args))
    print(f"captured {sum(counts)} frames, {len(keep)} unique, {length:.1f} s")
    concat = write_concat(keep, counts, args.fps)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.mp4:
        encode_mp4(concat, args.fps, args.out)
    else:
        encode_gif(concat, args.out, args.dither, args.gifsicle, args.lossy)
    size = args.out.stat().st_size
    shown = args.out.relative_to(REPO) if args.out.is_relative_to(REPO) else args.out
    print(
        f"wrote {shown}: {size / 1e6:.2f} MB, "
        f"{int(WIDTH * args.scale)}x{int(HEIGHT * args.scale)}, {time.monotonic() - t0:.0f} s"
    )


if __name__ == "__main__":
    main()
