#!/usr/bin/env python3
"""
passive_sources.py - Aggregated passive subdomain discovery for DNSsifter.

DNSsifter historically used a single passive source (crt.sh). Mature tools such
as Subfinder owe their high recall to *aggregating many* passive sources. This
module brings DNSsifter to parity-and-beyond on passive discovery by querying a
broad set of free, no-API-key sources concurrently and returning their union.
Combined with DNSsifter's active brute-force + recursive enumeration + trusted-
resolver validation, the result is a superset of what any single tool finds, at
high precision.

Free sources queried (no API key required):
    crt.sh, Certspotter, HackerTarget, RapidDNS, URLScan, Wayback/CommonCrawl,
    AlienVault OTX, AnubisDB (jldc), Digitorus/certificatedetails, BufferOver.

Each source is fetched with retries and a generous timeout, concurrently, so a
slow/unavailable source never blocks the others. All names are lower-cased,
wildcard-stripped, and filtered to the target domain. Validation is the caller's
job (DNSsifter re-resolves every candidate through trusted resolvers).

Usage (standalone):
    python3 Scripts/passive_sources.py example.com [--insecure] [--timeout 90]
"""
import argparse
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

UA = {"User-Agent": "Mozilla/5.0 (compatible; DNSsifter/2.0; +passive-recon)"}

# Optional API keys lift free-tier caps and unlock high-yield sources. They are
# read from the environment (NEVER hard-coded) so secrets stay out of the repo:
#   export VT_API_KEY=...          (VirusTotal)
#   export CERTSPOTTER_API_KEY=... (Certspotter, removes the anonymous result cap)
VT_API_KEY = os.environ.get("VT_API_KEY", "")
CERTSPOTTER_API_KEY = os.environ.get("CERTSPOTTER_API_KEY", "")


def _session(insecure: bool) -> requests.Session:
    s = requests.Session()
    s.headers.update(UA)
    if insecure:
        urllib3.disable_warnings()
        s.verify = False
    return s


def _get(s, url, timeout, retries=3, backoff=4):
    last = None
    for i in range(retries):
        try:
            return s.get(url, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - we retry on any transport error
            last = e
            time.sleep(backoff * (i + 1))
    raise last


def src_crtsh(s, d, t):
    # crt.sh is the highest-yield source but prone to 502/503 (it times out
    # server-side on domains with very large certificate histories). We retry
    # aggressively, and on persistent failure fall back to excluding expired certs,
    # which returns a much smaller payload that crt.sh can serve without 502-ing.
    out = set()
    urls = [f"https://crt.sh/?q=%.{d}&output=json",
            f"https://crt.sh/?q=%.{d}&output=json&exclude=expired"]
    for i in range(8):
        url = urls[0] if i < 5 else urls[1]
        try:
            r = s.get(url, timeout=max(t, 120))
            if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                for e in r.json():
                    for n in str(e.get("name_value", "")).splitlines():
                        out.add(n)
                if out:
                    return out
        except Exception:  # noqa: BLE001
            pass
        time.sleep(5 * (i + 1))
    return out


def src_commoncrawl(s, d, t):
    # CommonCrawl's CDX index holds URLs crawled across the web; extracting hosts
    # yields many subdomains, and it handles large domains without crt.sh's limits.
    out = set()
    try:
        colls = s.get("https://index.commoncrawl.org/collinfo.json",
                      timeout=t).json()
    except Exception:  # noqa: BLE001
        return out
    for coll in colls[:2]:  # two most recent indexes
        api = coll.get("cdx-api")
        if not api:
            continue
        try:
            r = s.get(f"{api}?url=*.{d}&output=json&fl=url&limit=20000",
                      timeout=max(t, 90))
            for line in r.text.splitlines():
                m = re.search(r"https?://([\w.\-]+)", line)
                if m:
                    out.add(m.group(1))
        except Exception:  # noqa: BLE001
            continue
    return out


def src_certspotter(s, d, t):
    # Certspotter paginates via an `after` cursor (the last issuance id). The
    # anonymous tier caps results; an API key (Authorization: Bearer) lifts the cap
    # and returns the full CT history, which is what matters for large domains.
    headers = {"Authorization": f"Bearer {CERTSPOTTER_API_KEY}"} if CERTSPOTTER_API_KEY else {}
    pages = 200 if CERTSPOTTER_API_KEY else 20
    out, after = set(), ""
    for _ in range(pages):
        try:
            r = s.get(f"https://api.certspotter.com/v1/issuances?domain={d}"
                      f"&include_subdomains=true&expand=dns_names&after={after}",
                      headers=headers, timeout=t)
            j = r.json()
        except Exception:  # noqa: BLE001
            break
        if not isinstance(j, list) or not j:
            break
        for e in j:
            out.update(e.get("dns_names", []))
        after = j[-1].get("id", "")
        if not after:
            break
    return out


def src_virustotal(s, d, t):
    # VirusTotal's domain/subdomains relationship is a very high-yield source.
    # Requires a (free) API key; paginates via links.next.
    if not VT_API_KEY:
        return set()
    out = set()
    # VT caps page size at 40; paginate via links.next. Stop on rate-limit (429)
    # rather than hammering the free-tier quota (4 req/min, 500/day).
    url = f"https://www.virustotal.com/api/v3/domains/{d}/subdomains?limit=40"
    for _ in range(40):
        try:
            r = s.get(url, headers={"x-apikey": VT_API_KEY}, timeout=t)
            if r.status_code == 429:
                time.sleep(16)
                continue
            if r.status_code != 200:
                break
            j = r.json()
        except Exception:  # noqa: BLE001
            break
        for e in j.get("data", []):
            out.add(e.get("id", ""))
        url = j.get("links", {}).get("next")
        if not url:
            break
    return out


def src_hackertarget(s, d, t):
    r = _get(s, f"https://api.hackertarget.com/hostsearch/?q={d}", t)
    return {ln.split(",")[0] for ln in r.text.splitlines() if "," in ln}


def src_rapiddns(s, d, t):
    r = _get(s, f"https://rapiddns.io/subdomain/{d}?full=1", t)
    return set(re.findall(r"<td>([\w.\-]+\.%s)</td>" % re.escape(d), r.text, re.I))


def src_urlscan(s, d, t):
    r = _get(s, f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=10000", t)
    out = set()
    for e in r.json().get("results", []):
        for k in ("domain",):
            v = e.get("page", {}).get(k, "")
            if v:
                out.add(v)
    return out


def src_wayback(s, d, t):
    r = _get(s, f"https://web.archive.org/cdx/search/cdx?url=*.{d}&output=json"
                f"&fl=original&collapse=urlkey&limit=50000", max(t, 90), retries=4)
    out = set()
    try:
        rows = r.json()
    except Exception:  # noqa: BLE001
        return out
    for row in rows[1:]:
        m = re.search(r"https?://([\w.\-]+)", row[0])
        if m:
            out.add(m.group(1))
    return out


def src_alienvault(s, d, t):
    r = _get(s, f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns", t)
    return {e.get("hostname", "") for e in r.json().get("passive_dns", [])}


def src_anubis(s, d, t):
    r = _get(s, f"https://jldc.me/anubis/subdomains/{d}", t)
    try:
        return set(r.json())
    except Exception:
        return set()


def src_digitorus(s, d, t):
    r = _get(s, f"https://certificatedetails.com/api/list/{d}", t)
    return set(re.findall(r"[\w.\-]+\.%s" % re.escape(d), r.text, re.I))


def src_bufferover(s, d, t):
    r = _get(s, f"https://dns.bufferover.run/dns?q=.{d}", t)
    out = set()
    try:
        j = r.json()
        for key in ("FDNS_A", "RDNS"):
            for rec in (j.get(key) or []):
                out.update(rec.split(","))
    except Exception:
        pass
    return out


# alienvault now requires authentication (HTTP 429 for anonymous) and bufferover is
# offline; both are kept as functions but excluded from the default set.
SOURCES = {
    "crtsh": src_crtsh, "certspotter": src_certspotter, "hackertarget": src_hackertarget,
    "rapiddns": src_rapiddns, "urlscan": src_urlscan, "wayback": src_wayback,
    "anubis": src_anubis, "digitorus": src_digitorus, "commoncrawl": src_commoncrawl,
    "virustotal": src_virustotal,
}


def clean(names, domain):
    out = set()
    for n in names:
        n = str(n).strip().lstrip("*.").lower().rstrip(".")
        if n and " " not in n and n.endswith("." + domain) or n == domain:
            if n != domain:
                out.add(n)
    return out


# crt.sh is the highest-yield source but aggressively rate-limits repeated/parallel
# hits from one IP. We therefore fetch it on its own, patiently, OUTSIDE the
# concurrent pool so it is not competing with the other requests.
PATIENT = {"crtsh"}


def gather(domain, timeout=45, insecure=False, workers=6, verbose=False):
    """Query all sources; return (union_set, per_source_counts). crt.sh is fetched
    on its own with patience; the remaining sources run concurrently."""
    s = _session(insecure)
    results, counts = set(), {}

    for name in PATIENT:
        try:
            got = clean(SOURCES[name](s, domain, max(timeout, 120)), domain)
        except Exception:  # noqa: BLE001
            got = set()
        counts[name] = len(got)
        results |= got
        if verbose:
            print(f"  [{name}] {len(got)}", file=sys.stderr)

    concurrent = {n: fn for n, fn in SOURCES.items() if n not in PATIENT}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fut = {pool.submit(fn, s, domain, timeout): n for n, fn in concurrent.items()}
        for f in as_completed(fut):
            name = fut[f]
            try:
                got = clean(f.result(), domain)
            except Exception as e:  # noqa: BLE001
                got = set()
                if verbose:
                    print(f"  [{name}] failed: {type(e).__name__}", file=sys.stderr)
            counts[name] = len(got)
            results |= got
            if verbose:
                print(f"  [{name}] {len(got)}", file=sys.stderr)
    return results, counts


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domain")
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--insecure", action="store_true",
                    help="Skip TLS verification (use only if the local Python CA "
                         "bundle is stale; sources are public and results are "
                         "re-validated via DNS).")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()
    names, counts = gather(args.domain, args.timeout, args.insecure, verbose=True)
    print(f"\nTOTAL unique passive names: {len(names)}", file=sys.stderr)
    print("per-source:", counts, file=sys.stderr)
    text = "\n".join(sorted(names))
    if args.output:
        open(args.output, "w", encoding="utf-8").write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
