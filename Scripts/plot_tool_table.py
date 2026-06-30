#!/usr/bin/env python3
"""Render Data/tool_benchmark.csv as a polished comparison-TABLE figure (SVG).

Self-contained: reads only the aggregate metrics CSV (no domain or host data).
The best value in each metric column is highlighted; DNSsifter's row is emphasised.
Regenerate after updating the CSV:  python Scripts/plot_tool_table.py
"""
import csv
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(REPO, "Data", "tool_benchmark.csv")
OUT = os.path.join(REPO, "Figures", "tool_comparison_table.svg")

# Column spec: (csv key, header, sub-header, "higher"|"lower"|None for best-of)
COLS = [
    ("tool",             "Tool",        "",            None),
    ("reported",         "Reported",    "raw names",   None),
    ("validated",        "Validated",   "live hosts",  "higher"),
    ("recall",           "Recall",      "vs. live GT", "higher"),
    ("precision",        "Precision",   "live / raw",  "higher"),
    ("runtime_s",        "Runtime",     "s / domain",  "lower"),
    ("max_depth",        "Depth",       "levels",      "higher"),
    ("unique_validated", "Unique",      "live only",   "higher"),
]

rows = []
with open(CSV, encoding="utf-8") as f:
    for line in f:
        if line.startswith("#") or not line.strip():
            continue
        rows = list(csv.DictReader([line] + f.readlines()))
        break

# numeric parsing for best-of detection
def num(v):
    try:
        return float(v)
    except ValueError:
        return None

best = {}
for key, _, _, mode in COLS:
    if mode is None:
        continue
    vals = [(r["tool"], num(r[key])) for r in rows if num(r[key]) is not None]
    if not vals:
        continue
    best[key] = (max if mode == "higher" else min)(vals, key=lambda x: x[1])[1]

# ---- layout -------------------------------------------------------------
PAD = 28
COLW = [168, 116, 120, 110, 116, 116, 92, 110]
W = PAD * 2 + sum(COLW)
ROWH = 46
HEADH = 60
TITLEH = 78
H = TITLEH + HEADH + ROWH * len(rows) + 96

ACCENT = "#1f4e79"
WINBG = "#e7f4e4"
WINTX = "#1d7a32"
GREY = "#5b6168"
LINE = "#d6dbe0"
ZEBRA = "#f6f8fa"

def x_of(i):
    return PAD + sum(COLW[:i])

def fmt(key, v):
    if key in ("recall", "precision"):
        return f"{float(v):.3f}"
    if key == "runtime_s":
        return f"{int(float(v))} s"
    if key in ("reported", "validated", "unique_validated"):
        return f"{int(float(v)):,}"
    return v

parts = [
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
    f'viewBox="0 0 {W} {H}" font-family="Segoe UI, Helvetica, Arial, sans-serif">',
    f'<rect width="{W}" height="{H}" rx="14" fill="#ffffff" stroke="{LINE}"/>',
    # title
    f'<text x="{PAD}" y="40" font-size="25" font-weight="700" fill="{ACCENT}">'
    f'DNSsifter vs. Subdomain-Enumeration Tools</text>',
    f'<text x="{PAD}" y="63" font-size="14" fill="{GREY}">'
    f'Validated benchmark — every candidate re-resolved through trusted resolvers '
    f'(Google / Cloudflare / OpenDNS). Best per column highlighted.</text>',
]

ytop = TITLEH
# header band
parts.append(f'<rect x="{PAD}" y="{ytop}" width="{sum(COLW)}" height="{HEADH}" '
             f'rx="8" fill="{ACCENT}"/>')
for i, (key, head, sub, _) in enumerate(COLS):
    cx = x_of(i) + (14 if i == 0 else COLW[i] - 14)
    anchor = "start" if i == 0 else "end"
    parts.append(f'<text x="{cx}" y="{ytop+26}" font-size="15.5" font-weight="700" '
                 f'fill="#ffffff" text-anchor="{anchor}">{head}</text>')
    if sub:
        parts.append(f'<text x="{cx}" y="{ytop+45}" font-size="11.5" '
                     f'fill="#c7d6e6" text-anchor="{anchor}">{sub}</text>')

# data rows
for ri, r in enumerate(rows):
    y = ytop + HEADH + ri * ROWH
    is_ds = r["tool"].lower() == "dnssifter"
    if is_ds:
        parts.append(f'<rect x="{PAD}" y="{y}" width="{sum(COLW)}" height="{ROWH}" '
                     f'fill="{WINBG}"/>')
        parts.append(f'<rect x="{PAD}" y="{y}" width="5" height="{ROWH}" fill="{WINTX}"/>')
    elif ri % 2:
        parts.append(f'<rect x="{PAD}" y="{y}" width="{sum(COLW)}" height="{ROWH}" '
                     f'fill="{ZEBRA}"/>')
    for i, (key, _, _, mode) in enumerate(COLS):
        cx = x_of(i) + (16 if i == 0 else COLW[i] - 14)
        anchor = "start" if i == 0 else "end"
        val = fmt(key, r[key])
        win = mode and num(r[key]) is not None and num(r[key]) == best.get(key)
        if i == 0:
            weight = "700"
            fill = ACCENT if is_ds else "#2b2f36"
            size = "15.5"
        elif win:
            weight = "700"
            fill = WINTX
            size = "15"
        else:
            weight = "600" if is_ds else "400"
            fill = "#2b2f36"
            size = "14.5"
        parts.append(f'<text x="{cx}" y="{y+29}" font-size="{size}" font-weight="{weight}" '
                     f'fill="{fill}" text-anchor="{anchor}">{val}</text>')
        if win and i:  # small medal dot before winning numeric cells
            parts.append(f'<circle cx="{cx - len(val)*7.6 - 9}" cy="{y+24}" r="3" fill="{WINTX}"/>')
    parts.append(f'<line x1="{PAD}" y1="{y+ROWH}" x2="{PAD+sum(COLW)}" y2="{y+ROWH}" '
                 f'stroke="{LINE}"/>')

# footnote
fy = ytop + HEADH + ROWH * len(rows) + 26
parts.append(f'<text x="{PAD}" y="{fy}" font-size="12" fill="{GREY}">'
             f'DNSsifter is the only tool that is simultaneously the most complete '
             f'(highest recall) and entirely live (precision 1.000).</text>')
parts.append(f'<text x="{PAD}" y="{fy+19}" font-size="12" fill="{GREY}">'
             f'Subfinder reports the most raw names but 88% no longer resolve. '
             f'* Amass v5 needs an API-key datasource config; out-of-the-box it returns almost nothing.</text>')
parts.append("</svg>")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(parts))
print("WROTE", OUT)
