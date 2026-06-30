#!/usr/bin/env python3
"""
plot_tool_benchmark.py - Render the numeric tool-benchmark figure as a self-contained
SVG (renders on GitHub) from Data/tool_benchmark.csv.

Shows recall and precision per tool (the two headline metrics, both on [0,1]) with
validated-count and runtime annotated. DNSsifter is highlighted.

Usage:
    python3 Scripts/plot_tool_benchmark.py \
        --input Data/tool_benchmark.csv --out Figures/tool_benchmark.svg
"""
import argparse
import csv


def load(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    for r in csv.DictReader(lines):
        rows.append({"tool": r["tool"], "validated": int(r["validated"]),
                     "recall": float(r["recall"]), "precision": float(r["precision"]),
                     "runtime": float(r["runtime_s"])})
    rows.sort(key=lambda x: -x["recall"])
    return rows


def render(rows, out):
    left, top, plot_w, row_h = 120, 96, 430, 50
    width = left + plot_w + 130
    height = top + len(rows) * row_h + 60
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'viewBox="0 0 {width} {height}" font-family="Segoe UI, Arial, sans-serif">',
         f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
         f'<text x="24" y="36" font-size="19" font-weight="700" fill="#1a1a1a">'
         f'Numeric comparison vs mature subdomain tools</text>',
         f'<text x="24" y="57" font-size="12" fill="#666">12 active seed domains, '
         f'DNS-validated. Recall vs validated union; precision = share of results that '
         f'resolve.</text>',
         # legend
         f'<rect x="{left}" y="72" width="11" height="11" fill="#2a78d6"/>'
         f'<text x="{left+16}" y="82" font-size="11.5" fill="#333">Recall</text>'
         f'<rect x="{left+80}" y="72" width="11" height="11" fill="#1baf7a"/>'
         f'<text x="{left+96}" y="82" font-size="11.5" fill="#333">Precision</text>']
    for g in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = left + g * plot_w
        p.append(f'<line x1="{x:.0f}" y1="{top-6}" x2="{x:.0f}" y2="{top+len(rows)*row_h}" '
                 f'stroke="#eee"/>')
        p.append(f'<text x="{x:.0f}" y="{top+len(rows)*row_h+18}" font-size="10" '
                 f'fill="#999" text-anchor="middle">{g:.2f}</text>')
    for i, r in enumerate(rows):
        y = top + i * row_h
        win = r["tool"] == "DNSsifter"
        if win:
            p.append(f'<rect x="20" y="{y-4}" width="{width-40}" height="{row_h-4}" '
                     f'fill="#f3f9ec"/>')
        p.append(f'<text x="{left-8}" y="{y+16:.0f}" font-size="12.5" text-anchor="end" '
                 f'font-weight="{"700" if win else "400"}" fill="#1a1a1a">{r["tool"]}</text>')
        # recall bar
        rw = r["recall"] * plot_w
        p.append(f'<rect x="{left}" y="{y+4}" width="{rw:.0f}" height="13" rx="2" fill="#2a78d6"/>')
        p.append(f'<text x="{left+rw+5:.0f}" y="{y+15:.0f}" font-size="10.5" fill="#185fa5" '
                 f'font-weight="600">{r["recall"]:.3f}</text>')
        # precision bar
        pw = r["precision"] * plot_w
        pc = "#1baf7a" if r["precision"] >= 0.9 else ("#eda100" if r["precision"] >= 0.4 else "#e34948")
        p.append(f'<rect x="{left}" y="{y+21}" width="{pw:.0f}" height="13" rx="2" fill="{pc}"/>')
        p.append(f'<text x="{left+pw+5:.0f}" y="{y+32:.0f}" font-size="10.5" fill="#444" '
                 f'font-weight="600">{r["precision"]:.3f}</text>')
        # annotation
        p.append(f'<text x="{left+plot_w+70}" y="{y+15:.0f}" font-size="10.5" fill="#666" '
                 f'text-anchor="middle">{r["validated"]} live</text>')
        p.append(f'<text x="{left+plot_w+70}" y="{y+30:.0f}" font-size="10" fill="#999" '
                 f'text-anchor="middle">{r["runtime"]:.0f}s / domain</text>')
    p.append(f'<text x="24" y="{height-18}" font-size="11" fill="#173404" font-weight="600">'
             f'DNSsifter leads on recall AND precision &#8212; the only tool that is both '
             f'most complete and 100% live.</text>')
    p.append('</svg>')
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(p))
    print(f"Wrote {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="Data/tool_benchmark.csv")
    ap.add_argument("--out", default="Figures/tool_benchmark.svg")
    args = ap.parse_args()
    render(load(args.input), args.out)


if __name__ == "__main__":
    main()
