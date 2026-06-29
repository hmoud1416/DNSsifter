#!/usr/bin/env python3
"""
benchmark_enumeration.py - Reproducible comparison of DNSsifter against mature
subdomain-enumeration tools (Amass, Subfinder, Sublist3r).

Motivation
----------
Reviewers asked for a rigorous comparison of DNSsifter against established tools
in terms of recall, precision, runtime, and depth. This script runs each tool on
the same seed domain(s), validates the union of discovered names against live DNS,
and reports the standard metrics so the comparison is transparent and repeatable.

Definitions (per seed domain, against a validated ground-truth set G)
---------------------------------------------------------------------
    G  = the set of names that resolve (A/AAAA) when re-checked through the
         trusted resolver set; this is the validated ground truth used as the
         denominator. By default G is the union of all tools' validated results;
         pass --ground-truth FILE to use an external authoritative list instead.
    T  = the set a tool reports
    TP = |T_validated intersect G|   (reported names that are real)
    recall    = TP / |G|
    precision = TP / |T| (over the tool's *raw* reported names)
    runtime   = wall-clock seconds for the tool's run
    depth     = max number of subdomain labels below the seed among validated hits
                (e.g. a.b.example.com -> depth 2)

Usage
-----
    # Live benchmark (requires amass/subfinder/sublist3r on PATH + DNSsifter)
    python3 Scripts/benchmark_enumeration.py \
        --domain example.com \
        --wordlist Wordlists/English_Wordlist_Subdomain.txt \
        --out results/benchmark_example.json

    # Offline scoring from pre-collected tool outputs (one name per line),
    # e.g. to reproduce the table in the paper without re-running the tools:
    python3 Scripts/benchmark_enumeration.py --score-only \
        --result DNSsifter=out/dnssifter.txt \
        --result Amass=out/amass.txt \
        --result Subfinder=out/subfinder.txt \
        --result Sublist3r=out/sublist3r.txt \
        --validate --out results/benchmark_example.json

Notes
-----
* Validation re-resolves candidate names through the same trusted resolver set
  DNSsifter uses (Google/Cloudflare/OpenDNS) to keep the ground truth consistent
  across tools and to avoid counting wildcard/poisoned answers as real.
* The external tools are invoked via subprocess; adjust the command templates in
  TOOL_COMMANDS if your local versions use different flags.
"""
import argparse
import json
import os
import shutil
import subprocess
import time
from typing import Dict, List, Set

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover - dnspython optional for --score-only w/o validate
    _HAVE_DNS = False

# Trusted resolver set kept identical to DNSsifter's double-resolution step.
TRUSTED_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222"]

# Command templates per tool. {domain}/{wordlist}/{out} are substituted.
# Edit these to match the flags of your locally installed versions.
TOOL_COMMANDS = {
    "Amass":     "amass enum -passive -d {domain} -o {out}",
    "Subfinder": "subfinder -silent -d {domain} -o {out}",
    "Sublist3r": "sublist3r -d {domain} -o {out}",
    "DNSsifter": "python3 {script_dir}/DNSsifter-emumerate.py "
                 "-d {domain} -w {wordlist} -o {out}",
}


def run_tool(name: str, domain: str, wordlist: str, out_dir: str) -> Dict:
    """Run one tool and return its raw reported names plus runtime."""
    template = TOOL_COMMANDS[name]
    out_file = os.path.join(out_dir, f"{name.lower()}_{domain}.txt")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cmd = template.format(domain=domain, wordlist=wordlist, out=out_file,
                          script_dir=script_dir)
    binary = cmd.split()[0]
    if binary not in ("python3", "python") and shutil.which(binary) is None:
        return {"tool": name, "available": False, "names": [], "runtime_s": None}

    start = time.time()
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=3600)
    except subprocess.TimeoutExpired:
        pass
    runtime = time.time() - start
    names = read_names(out_file) if os.path.exists(out_file) else set()
    return {"tool": name, "available": True, "names": sorted(names),
            "runtime_s": round(runtime, 2)}


def read_names(path: str) -> Set[str]:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return {ln.strip().lstrip("*.").lower()
                for ln in fh if ln.strip() and "." in ln}


def validate(names: Set[str]) -> Set[str]:
    """Return the subset of names that resolve (A/AAAA) via trusted resolvers."""
    if not _HAVE_DNS:
        raise RuntimeError("dnspython is required for --validate "
                           "(pip install dnspython)")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = TRUSTED_RESOLVERS
    resolver.timeout, resolver.lifetime = 5, 5
    live = set()
    for n in names:
        for rtype in ("A", "AAAA"):
            try:
                if resolver.resolve(n, rtype):
                    live.add(n)
                    break
            except Exception:
                continue
    return live


def depth_of(name: str, seed: str) -> int:
    """Number of labels of `name` below the seed domain."""
    if not name.endswith(seed):
        return 0
    prefix = name[: -len(seed)].rstrip(".")
    return len([p for p in prefix.split(".") if p]) if prefix else 0


def score(results: List[Dict], seed: str, do_validate: bool,
          ground_truth: Set[str]) -> Dict:
    """Compute recall/precision/runtime/depth for each tool."""
    validated = {}
    for r in results:
        names = set(r["names"])
        validated[r["tool"]] = validate(names) if do_validate else names

    if not ground_truth:
        ground_truth = set().union(*validated.values()) if validated else set()
    G = len(ground_truth) or 1

    report = {"seed": seed, "ground_truth_size": len(ground_truth), "tools": []}
    for r in results:
        raw = set(r["names"])
        val = validated[r["tool"]]
        tp = len(val & ground_truth)
        report["tools"].append({
            "tool": r["tool"],
            "available": r.get("available", True),
            "reported": len(raw),
            "validated": len(val),
            "true_positives": tp,
            "recall": round(tp / G, 4),
            "precision": round(tp / (len(raw) or 1), 4),
            "runtime_s": r.get("runtime_s"),
            "max_depth": max((depth_of(n, seed) for n in val), default=0),
        })
    report["tools"].sort(key=lambda t: t["recall"], reverse=True)
    return report


def print_report(report: Dict) -> None:
    print(f"\nSeed: {report['seed']}   "
          f"Ground-truth (validated) size: {report['ground_truth_size']}")
    print(f"{'Tool':<11}{'Reported':>9}{'Valid':>7}{'Recall':>8}"
          f"{'Prec.':>8}{'Runtime':>9}{'Depth':>7}")
    print("-" * 59)
    for t in report["tools"]:
        rt = f"{t['runtime_s']:.1f}s" if t["runtime_s"] is not None else "n/a"
        print(f"{t['tool']:<11}{t['reported']:>9}{t['validated']:>7}"
              f"{t['recall']:>8.3f}{t['precision']:>8.3f}{rt:>9}{t['max_depth']:>7}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", help="Seed domain to benchmark (live mode).")
    ap.add_argument("--wordlist", help="Wordlist for DNSsifter (live mode).")
    ap.add_argument("--out", default="benchmark_results.json")
    ap.add_argument("--out-dir", default="benchmark_runs",
                    help="Where per-tool raw outputs are written (live mode).")
    ap.add_argument("--score-only", action="store_true",
                    help="Skip running tools; score pre-collected outputs.")
    ap.add_argument("--result", action="append", default=[],
                    metavar="TOOL=FILE",
                    help="Tool=outputfile pair for --score-only (repeatable).")
    ap.add_argument("--ground-truth", help="Optional authoritative name list; "
                    "used as the recall denominator instead of the tool union.")
    ap.add_argument("--validate", action="store_true",
                    help="Re-resolve candidate names through trusted resolvers.")
    args = ap.parse_args()

    seed = args.domain or ""
    if args.score_only:
        results = []
        for pair in args.result:
            tool, _, path = pair.partition("=")
            results.append({"tool": tool, "available": True,
                            "names": sorted(read_names(path)), "runtime_s": None})
            if not seed:
                # infer seed from the most common suffix-ish: use the shortest name
                some = next(iter(read_names(path)), "")
                seed = ".".join(some.split(".")[-2:]) if some else seed
    else:
        if not (args.domain and args.wordlist):
            ap.error("--domain and --wordlist are required unless --score-only")
        os.makedirs(args.out_dir, exist_ok=True)
        results = [run_tool(name, args.domain, args.wordlist, args.out_dir)
                   for name in TOOL_COMMANDS]

    gt = read_names(args.ground_truth) if args.ground_truth else set()
    report = score(results, seed, args.validate or bool(gt), gt)
    print_report(report)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nFull report written to {args.out}")


if __name__ == "__main__":
    main()
