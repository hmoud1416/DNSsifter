#!/usr/bin/env python3
"""
sample_domains.py - Extract Saudi seed domains from the dataset spreadsheets and
build a reproducible, stratified sample for the tool-comparison benchmark.

It reads the per-category sheets, writes one plain-text list per category
(domains/<category>.txt) plus the full union (domains/all_domains.txt), and draws
a deterministic stratified sample (proportional to category size, with a floor per
category so small sectors are represented) into domains/benchmark_sample.txt.

Deterministic: uses a fixed RNG seed so the sample is identical on every run.

Usage:
    python3 Scripts/sample_domains.py \
        --xlsx "main_domains (1).xlsx" "دومينات السعودية.xlsx" \
        --size 300 --out-dir domains
"""
import argparse
import os
import random

import openpyxl

# Map spreadsheet sheet titles to the SLD/ccTLD category label.
SHEET_TO_CATEGORY = {
    "SA": ".sa",
    "Organizations": ".org.sa",
    "Schools": ".sch.sa",
    "Education": ".edu.sa",
    "Medical": ".med.sa",
    "Commercial": ".com.sa",
    "Publications": ".pub.sa",
    "Networks": ".net.sa",
    "Government": ".gov.sa",
}
# Any sheet not in the map (e.g. the Arabic IDN sheet) is bucketed here.
IDN_CATEGORY = ".idn.sa"
SEED = 1416  # fixed for reproducibility


def extract(xlsx_paths):
    """Return {category: sorted_unique_domains}."""
    buckets = {}
    for path in xlsx_paths:
        wb = openpyxl.load_workbook(path, read_only=True)
        for ws in wb.worksheets:
            cat = SHEET_TO_CATEGORY.get(ws.title, IDN_CATEGORY)
            for i, row in enumerate(ws.iter_rows(values_only=True)):
                if i == 0 or not row or not row[0]:
                    continue
                dom = str(row[0]).strip().lower().rstrip(".")
                if dom and "." in dom:
                    buckets.setdefault(cat, set()).add(dom)
        wb.close()
    return {c: sorted(v) for c, v in buckets.items()}


def stratified_sample(buckets, size, floor=5):
    """Proportional sample across categories with a per-category floor."""
    rng = random.Random(SEED)
    total = sum(len(v) for v in buckets.values())
    sample = {}
    for cat, doms in buckets.items():
        quota = max(floor, round(size * len(doms) / total))
        quota = min(quota, len(doms))
        sample[cat] = rng.sample(doms, quota)
    return sample


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--xlsx", nargs="+", required=True,
                    help="One or more dataset spreadsheets.")
    ap.add_argument("--size", type=int, default=300,
                    help="Target sample size (approximate; floors may raise it).")
    ap.add_argument("--floor", type=int, default=5,
                    help="Minimum domains sampled per category.")
    ap.add_argument("--out-dir", default="domains")
    args = ap.parse_args()

    buckets = extract(args.xlsx)
    os.makedirs(args.out_dir, exist_ok=True)

    # Per-category full lists + union.
    all_doms = []
    for cat, doms in sorted(buckets.items()):
        fn = os.path.join(args.out_dir, f"all_{cat.strip('.').replace('.', '_')}.txt")
        with open(fn, "w", encoding="utf-8") as fh:
            fh.write("\n".join(doms) + "\n")
        all_doms.extend(doms)
    with open(os.path.join(args.out_dir, "all_domains.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(sorted(all_doms)) + "\n")

    # Stratified sample.
    sample = stratified_sample(buckets, args.size, args.floor)
    flat = [d for doms in sample.values() for d in doms]
    with open(os.path.join(args.out_dir, "benchmark_sample.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(flat) + "\n")

    print(f"Categories: {len(buckets)} | total domains: {len(all_doms)}")
    for cat in sorted(buckets):
        print(f"  {cat:<10} full={len(buckets[cat]):>6}  sampled={len(sample[cat])}")
    print(f"\nStratified sample: {len(flat)} domains -> "
          f"{os.path.join(args.out_dir, 'benchmark_sample.txt')}")


if __name__ == "__main__":
    main()
