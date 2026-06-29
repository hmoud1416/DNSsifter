#!/usr/bin/env python3
"""
plot_cdri.py - Render the CDRI-by-category figure as a self-contained SVG.

Reads the aggregated dimension scores, computes the CDRI (same logic as
cdri_score.py), and writes a horizontal bar chart to an SVG file. SVG renders
natively on GitHub, so the figure can be embedded directly in the README.

Dependency-free (Python 3 standard library only).

Usage:
    python3 Scripts/plot_cdri.py \
        --input Data/cdri_dimension_scores.csv \
        --out Figures/cdri_by_category.svg
"""
import argparse
import csv

WEIGHTS = [0.20, 0.15, 0.10, 0.15, 0.10, 0.20, 0.10]
DIMS = ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]


def load(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    rows = []
    for r in csv.DictReader(lines):
        s = [float(r[d]) for d in DIMS]
        cdri = sum(w * v for w, v in zip(WEIGHTS, s))
        rows.append((r["category"].strip(), cdri))
    rows.sort(key=lambda x: x[1], reverse=True)
    return rows


def color_for(value):
    # Red (low) -> amber (mid) -> green (high), simple 3-stop ramp.
    if value < 0.35:
        return "#d64545"
    if value < 0.50:
        return "#e0a44a"
    return "#4a9d5b"


def render(rows, out):
    bar_h, gap, top, left, plot_w = 26, 12, 70, 90, 460
    height = top + len(rows) * (bar_h + gap) + 50
    width = left + plot_w + 70
    parts = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" '
        f'font-family="Segoe UI, Arial, sans-serif">')
    parts.append(f'<rect width="{width}" height="{height}" fill="#ffffff"/>')
    parts.append(f'<text x="{left}" y="30" font-size="18" font-weight="700" '
                 f'fill="#1a1a1a">Composite DNS Resilience Index (CDRI) by Category</text>')
    parts.append(f'<text x="{left}" y="50" font-size="12" fill="#666">'
                 f'Higher is better. Source: Table 8 (Alharbi et al.).</text>')

    # X gridlines at 0, 0.25, 0.5, 0.75, 1.0
    for gx in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = left + gx * plot_w
        parts.append(f'<line x1="{x:.1f}" y1="{top-8}" x2="{x:.1f}" '
                     f'y2="{height-40}" stroke="#e6e6e6" stroke-width="1"/>')
        parts.append(f'<text x="{x:.1f}" y="{height-22}" font-size="11" '
                     f'fill="#888" text-anchor="middle">{gx:.2f}</text>')

    y = top
    for cat, cdri in rows:
        w = cdri * plot_w
        parts.append(f'<text x="{left-8}" y="{y+bar_h*0.68:.1f}" font-size="13" '
                     f'fill="#222" text-anchor="end">{cat}</text>')
        parts.append(f'<rect x="{left}" y="{y}" width="{w:.1f}" height="{bar_h}" '
                     f'rx="3" fill="{color_for(cdri)}"/>')
        parts.append(f'<text x="{left+w+6:.1f}" y="{y+bar_h*0.68:.1f}" '
                     f'font-size="12" font-weight="600" fill="#333">{cdri:.3f}</text>')
        y += bar_h + gap

    parts.append('</svg>')
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
    print(f"Wrote {out} ({len(rows)} categories)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="Data/cdri_dimension_scores.csv")
    ap.add_argument("--out", default="Figures/cdri_by_category.svg")
    args = ap.parse_args()
    render(load(args.input), args.out)


if __name__ == "__main__":
    main()
