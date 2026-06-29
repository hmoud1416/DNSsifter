#!/usr/bin/env python3
"""
plot_benchmark.py - Turn a benchmark_enumeration.py report into a Markdown table
and an SVG figure (recall / precision per tool), ready for the paper and GitHub.

Dependency-free (Python 3 standard library only).

Usage:
    python3 Scripts/plot_benchmark.py \
        --input results/benchmark_sample.json \
        --table results/benchmark_table.md \
        --figure Figures/benchmark_comparison.svg
"""
import argparse
import json

BAR_COLORS = {"recall": "#2a78d6", "precision": "#1baf7a"}  # blue, aqua


def make_table(report):
    rows = report["tools"]
    lines = [
        f"Benchmark seed set: {report['seed']} | "
        f"validated ground-truth size: {report['ground_truth_size']}",
        "",
        "| Tool | Reported | Validated | Recall | Precision | Runtime (s) | Max depth |",
        "|------|---------:|----------:|-------:|----------:|------------:|----------:|",
    ]
    for t in rows:
        avail = "" if t.get("available", True) else " _(not available)_"
        rt = f"{t['runtime_s']:.1f}" if t.get("runtime_s") is not None else "n/a"
        lines.append(
            f"| {t['tool']}{avail} | {t['reported']} | {t['validated']} | "
            f"{t['recall']:.3f} | {t['precision']:.3f} | {rt} | {t['max_depth']} |")
    return "\n".join(lines) + "\n"


def make_figure(report):
    tools = report["tools"]
    n = len(tools)
    left, top, group_w, plot_h = 110, 80, 90, 240
    width = left + n * group_w + 40
    height = top + plot_h + 80
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'viewBox="0 0 {width} {height}" font-family="Segoe UI, Arial, sans-serif">',
         f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
         f'<text x="20" y="30" font-size="17" font-weight="700" fill="#1a1a1a">'
         f'Subdomain enumeration: recall vs precision by tool</text>',
         f'<text x="20" y="50" font-size="12" fill="#666">Validated against trusted '
         f'resolvers. Seed set: {report["seed"]}.</text>']
    base = top + plot_h
    # y gridlines 0..1
    for g in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = base - g * plot_h
        p.append(f'<line x1="{left-6}" y1="{y:.1f}" x2="{width-20}" y2="{y:.1f}" '
                 f'stroke="#e6e6e6"/>')
        p.append(f'<text x="{left-10}" y="{y+4:.1f}" font-size="11" fill="#888" '
                 f'text-anchor="end">{g:.2f}</text>')
    # legend
    lx = left
    for i, (k, c) in enumerate(BAR_COLORS.items()):
        p.append(f'<rect x="{lx+i*100}" y="60" width="11" height="11" fill="{c}"/>')
        p.append(f'<text x="{lx+i*100+16}" y="70" font-size="12" fill="#333">{k}</text>')
    # bars
    bw = 26
    for j, t in enumerate(tools):
        gx = left + j * group_w
        for i, key in enumerate(("recall", "precision")):
            v = t[key]
            x = gx + 10 + i * (bw + 6)
            h = v * plot_h
            p.append(f'<rect x="{x}" y="{base-h:.1f}" width="{bw}" height="{h:.1f}" '
                     f'rx="3" fill="{BAR_COLORS[key]}"/>')
            p.append(f'<text x="{x+bw/2:.1f}" y="{base-h-4:.1f}" font-size="10" '
                     f'fill="#333" text-anchor="middle">{v:.2f}</text>')
        p.append(f'<text x="{gx+group_w/2:.1f}" y="{base+18:.1f}" font-size="12" '
                 f'fill="#222" text-anchor="middle">{t["tool"]}</text>')
    p.append('</svg>')
    return "\n".join(p)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="benchmark report JSON.")
    ap.add_argument("--table", default="benchmark_table.md")
    ap.add_argument("--figure", default="Figures/benchmark_comparison.svg")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        report = json.load(fh)

    with open(args.table, "w", encoding="utf-8") as fh:
        fh.write(make_table(report))
    with open(args.figure, "w", encoding="utf-8") as fh:
        fh.write(make_figure(report))
    print(f"Wrote table  -> {args.table}")
    print(f"Wrote figure -> {args.figure}")


if __name__ == "__main__":
    main()
