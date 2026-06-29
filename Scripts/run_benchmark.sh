#!/usr/bin/env bash
#
# run_benchmark.sh - Turnkey tool-comparison benchmark for DNSsifter.
#
# Run this on an UNRESTRICTED network (e.g. the Riyadh measurement server), NOT
# behind an SSL-intercepting proxy: Amass/Subfinder/Sublist3r are passive tools
# that depend on HTTPS sources (crt.sh, Censys, VirusTotal, search engines). If
# those sources are blocked, the passive tools return little/nothing and the
# comparison becomes invalid.
#
# It (1) installs dependencies + the three reference tools, (2) runs all four
# tools across the stratified sample in parallel and validates hits via trusted
# resolvers, and (3) emits a Markdown table + SVG figure for the paper.
#
# Usage:
#   bash Scripts/run_benchmark.sh [SAMPLE_FILE] [WORKERS]
# Defaults: SAMPLE_FILE=domains/benchmark_sample.txt  WORKERS=8
set -euo pipefail

SAMPLE="${1:-domains/benchmark_sample.txt}"
WORKERS="${2:-8}"
WORDLIST="Wordlists/English_Wordlist_Subdomain.txt"
OUT="results"
mkdir -p "$OUT"

echo "==> [1/4] Python dependencies"
python3 -m pip install -r requirements.txt

echo "==> [2/4] Reference tools (skip any already installed)"
# Sublist3r (pure Python)
command -v sublist3r >/dev/null 2>&1 || python3 -m pip install sublist3r
# Subfinder (Go) - https://github.com/projectdiscovery/subfinder
command -v subfinder >/dev/null 2>&1 || \
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || \
  echo "[!] Install subfinder manually (Go binary) and re-run."
# Amass (Go) - https://github.com/owasp-amass/amass
command -v amass >/dev/null 2>&1 || \
  go install -v github.com/owasp-amass/amass/v4/...@master || \
  echo "[!] Install amass manually (Go binary) and re-run."

echo "==> [3/4] Running benchmark across $(wc -l < "$SAMPLE") domains (parallel=$WORKERS)"
python3 Scripts/benchmark_enumeration.py \
    --domain-list "$SAMPLE" \
    --wordlist "$WORDLIST" \
    --workers "$WORKERS" \
    --validate \
    --out-dir "$OUT/raw" \
    --out "$OUT/benchmark_sample.json"

echo "==> [4/4] Building table + figure"
python3 Scripts/plot_benchmark.py \
    --input "$OUT/benchmark_sample.json" \
    --table "$OUT/benchmark_table.md" \
    --figure "Figures/benchmark_comparison.svg"

echo
echo "Done. Deliverables:"
echo "  - $OUT/benchmark_sample.json   (raw metrics)"
echo "  - $OUT/benchmark_table.md      (paste into the paper)"
echo "  - Figures/benchmark_comparison.svg (renders on GitHub)"
echo
echo "Send benchmark_sample.json back and the table/figure can be regenerated anywhere."
