#!/usr/bin/env python3
"""
plot_tool_matrix.py - Render the capability-comparison matrix as a self-contained
SVG (no external data, renders on GitHub).

Compares DNSsifter against the most popular subdomain-enumeration tools across the
capabilities that determine real-world coverage and result quality. Capability
ratings reflect each tool's documented, out-of-the-box behaviour:
    2 = full / built-in     1 = partial / optional / plugin     0 = none

Sources for the ratings: each tool's official docs/README (OWASP Amass, ProjectDiscovery
Subfinder, Sublist3r, Assetfinder, Findomain, Knockpy, Gobuster, theHarvester, BBOT).

Usage:
    python3 Scripts/plot_tool_matrix.py --out Figures/tool_comparison_matrix.svg
"""
import argparse

CAPS = ["Passive|sources", "Active|brute-force", "Recursive|multi-level",
        "Liveness|validation", "Arabic /|Arabizi", "Wildcard|handling"]

# (tool, [ratings per capability]); DNSsifter first, then by capability strength.
TOOLS = [
    ("DNSsifter (ours)", [2, 2, 2, 2, 2, 2]),
    ("OWASP Amass",      [2, 2, 2, 2, 0, 2]),
    ("BBOT",             [2, 2, 2, 2, 0, 2]),
    ("Knockpy",          [1, 2, 2, 2, 0, 2]),
    ("Gobuster (DNS)",   [0, 2, 0, 2, 0, 2]),
    ("Subfinder",        [2, 0, 0, 0, 0, 1]),
    ("Findomain",        [2, 0, 0, 1, 0, 0]),
    ("Sublist3r",        [2, 1, 0, 1, 0, 0]),
    ("Assetfinder",      [2, 0, 0, 0, 0, 0]),
    ("theHarvester",     [2, 0, 0, 0, 0, 0]),
]

FILL = {2: "#eaf3de", 1: "#fef4e2", 0: "#f4f3ee"}
MARK = {2: "#2e7d32", 1: "#b9770e", 0: "#bdbdb6"}
SYM = {2: "✓", 1: "◐", 0: "–"}  # check, half-circle, dash


def render(out):
    name_w, cap_w, row_h = 168, 92, 34
    top, left = 96, 24
    width = left + name_w + len(CAPS) * cap_w + 24
    height = top + len(TOOLS) * row_h + 70
    arabic_x = left + name_w + 4 * cap_w  # highlight the unique column
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'viewBox="0 0 {width} {height}" font-family="Segoe UI, Arial, sans-serif">',
         f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
         f'<text x="{left}" y="36" font-size="20" font-weight="700" fill="#1a1a1a">'
         f'Capability comparison vs popular subdomain tools</text>',
         f'<text x="{left}" y="58" font-size="12.5" fill="#666">'
         f'&#10003; full &#160;&#160; &#9680; partial / optional &#160;&#160; &#8211; none. '
         f'Ratings from each tool&#8217;s official documentation.</text>']
    # highlight the Arabic/Arabizi column band
    p.append(f'<rect x="{arabic_x}" y="{top-26}" width="{cap_w}" '
             f'height="{len(TOOLS)*row_h+26}" fill="#f3f7ec"/>')
    # capability headers (two lines)
    for i, cap in enumerate(CAPS):
        cx = left + name_w + i * cap_w + cap_w / 2
        l1, l2 = cap.split("|")
        p.append(f'<text x="{cx:.0f}" y="{top-28}" font-size="11.5" font-weight="600" '
                 f'fill="#333" text-anchor="middle">{l1}</text>')
        p.append(f'<text x="{cx:.0f}" y="{top-14}" font-size="11.5" font-weight="600" '
                 f'fill="#333" text-anchor="middle">{l2}</text>')
    # rows
    for r, (tool, caps) in enumerate(TOOLS):
        y = top + r * row_h
        if r == 0:
            p.append(f'<rect x="{left}" y="{y}" width="{name_w + len(CAPS)*cap_w}" '
                     f'height="{row_h}" fill="#eef6e3"/>')
        weight = "700" if r == 0 else "400"
        p.append(f'<text x="{left+6}" y="{y+row_h/2+4:.0f}" font-size="12.5" '
                 f'font-weight="{weight}" fill="#1a1a1a">{tool}</text>')
        for i, v in enumerate(caps):
            cx = left + name_w + i * cap_w + cap_w / 2
            cy = y + row_h / 2
            p.append(f'<circle cx="{cx:.0f}" cy="{cy:.0f}" r="11" fill="{FILL[v]}"/>')
            p.append(f'<text x="{cx:.0f}" y="{cy+4:.0f}" font-size="14" '
                     f'font-weight="700" fill="{MARK[v]}" text-anchor="middle">{SYM[v]}</text>')
        p.append(f'<line x1="{left}" y1="{y+row_h}" x2="{left+name_w+len(CAPS)*cap_w}" '
                 f'y2="{y+row_h}" stroke="#eee"/>')
    # callout
    cy = top + len(TOOLS) * row_h + 30
    p.append(f'<text x="{left}" y="{cy}" font-size="12.5" fill="#173404" font-weight="600">'
             f'DNSsifter is the only tool combining all six — and the only one with '
             f'Arabic / Arabizi wordlists,</text>')
    p.append(f'<text x="{left}" y="{cy+18}" font-size="12.5" fill="#173404" font-weight="600">'
             f'the capability that matters most for Arabic-region domain discovery.</text>')
    p.append('</svg>')
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(p))
    print(f"Wrote {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="Figures/tool_comparison_matrix.svg")
    render(ap.parse_args().out)


if __name__ == "__main__":
    main()
