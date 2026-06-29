#!/usr/bin/env python3
"""
DNSsifter - asynchronous, multithreaded DNS enumeration with wildcard control.

This is the active-enumeration component described in:
    "A Longitudinal Assessment of DNS Resilience and Robustness in Saudi Arabia"
    (Alharbi et al.), Section 4.2.

It combines passive discovery (Certificate Transparency logs) with multithreaded
active brute-forcing of a wordlist, and enumerates recursively across subdomain
levels until a level yields no new active names. To keep results reproducible and
to avoid overloading DNS infrastructure, the tool implements the exact safeguards
and parameters reported in the paper:

    * Rate limit         : 10 DNS queries / second / seed domain   (--rate)
    * Wildcard handling  : detect wildcard zones and cap probing at
                           1000 subdomains per such domain          (--wildcard-cap)
    * Double-resolution  : confirm every candidate against a set of
                           trusted recursive resolvers to drop
                           false positives / poisoned answers       (--resolvers)
    * Recursion depth    : enumerate level-by-level until no new
                           active names are found                   (--max-depth)
    * Record types       : A and AAAA only (no malformed payloads)

All thresholds are exposed as CLI flags so a reviewer can reproduce, or vary, the
measurement configuration. See REPRODUCIBILITY.md for the full parameter table.

Dependencies: requests, dnspython
    pip install requests dnspython
"""
import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    import dns.resolver
except ImportError:
    sys.exit("[!] dnspython is required: pip install dnspython")

# Default trusted recursive resolvers used for the double-resolution confirmation
# step (Section 4.2). Google, Cloudflare, OpenDNS.
DEFAULT_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1",
                     "208.67.222.222", "208.67.220.220"]

# Paper defaults (Section 3.1.1 / 4.2 / 4.5).
DEFAULT_RATE = 10            # queries per second per seed domain
DEFAULT_WILDCARD_CAP = 1000  # max probes for a wildcard-enabled domain
DEFAULT_THREADS = 20
DEFAULT_MAX_DEPTH = 5
DEFAULT_TIMEOUT = 5


class RateLimiter:
    """Simple thread-safe token-bucket: at most `rate` acquisitions per second."""

    def __init__(self, rate: int):
        self.min_interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
            self._next = max(now, self._next) + self.min_interval


def make_resolver(resolvers, timeout):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = resolvers
    r.timeout = timeout
    r.lifetime = timeout
    return r


def resolves(name, resolver, limiter) -> bool:
    """True if `name` has an A or AAAA record (with rate limiting)."""
    for rtype in ("A", "AAAA"):
        limiter.acquire()
        try:
            if resolver.resolve(name, rtype):
                return True
        except Exception:
            continue
    return False


def double_confirm(name, resolvers, timeout, limiter) -> bool:
    """Confirm a hit independently on each trusted resolver to drop false
    positives / poisoned records. Requires agreement from a majority."""
    agree = 0
    for ns in resolvers:
        r = make_resolver([ns], timeout)
        if resolves(name, r, limiter):
            agree += 1
    return agree >= (len(resolvers) // 2 + 1)


def detect_wildcard(seed_domain, resolver, limiter) -> bool:
    """A zone is wildcard-enabled if random, almost-certainly-nonexistent labels
    still resolve. We test several random labels to reduce flukes."""
    probes = [f"wildcard-probe-{tag}.{seed_domain}"
              for tag in ("zzq9x1", "qq7v2k", "x0p3mm")]
    hits = sum(1 for p in probes if resolves(p, resolver, limiter))
    return hits >= 2


def passive_discovery(seed_domain, timeout) -> set:
    """Fetch known subdomains from Certificate Transparency (crt.sh)."""
    found = set()
    try:
        url = f"https://crt.sh/?q=%.{seed_domain}&output=json"
        resp = requests.get(url, timeout=timeout * 2)
        if resp.status_code == 200:
            for entry in resp.json():
                for nm in entry.get("name_value", "").splitlines():
                    nm = nm.strip().lstrip("*.").lower()
                    if nm.endswith(seed_domain):
                        found.add(nm)
    except Exception as e:
        print(f"[!] CT-log lookup failed: {e}")
    return found


def load_words(path) -> list:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [ln.strip() for ln in fh if ln.strip()]


def enumerate_level(parents, words, resolver, resolvers, limiter, cfg) -> set:
    """Brute-force one level: prepend each word to each parent, validate, and
    (when the parent is a wildcard zone) cap the number of probes."""
    active = set()
    for parent in parents:
        wildcard = detect_wildcard(parent, resolver, limiter)
        level_words = words[: cfg.wildcard_cap] if wildcard else words
        if wildcard:
            print(f"[~] Wildcard detected on {parent}: "
                  f"capping at {cfg.wildcard_cap} probes")

        candidates = [f"{w}.{parent}" for w in level_words]

        def check(name):
            if resolves(name, resolver, limiter):
                if double_confirm(name, resolvers, cfg.timeout, limiter):
                    return name
            return None

        with ThreadPoolExecutor(max_workers=cfg.threads) as pool:
            for fut in as_completed(pool.submit(check, c) for c in candidates):
                hit = fut.result()
                if hit:
                    print(f"[+] {hit}")
                    active.add(hit)
    return active


def enumerate_domain(seed_domain, words, cfg) -> set:
    resolver = make_resolver(cfg.resolvers, cfg.timeout)
    limiter = RateLimiter(cfg.rate)
    discovered = set()

    print(f"[+] Passive discovery (CT logs) for {seed_domain} ...")
    for name in passive_discovery(seed_domain, cfg.timeout):
        if resolves(name, resolver, limiter):
            discovered.add(name)
    print(f"[+] Passive stage found {len(discovered)} live names")

    print(f"[+] Active recursive enumeration (max depth {cfg.max_depth}) ...")
    current_level = {seed_domain}
    for depth in range(cfg.max_depth):
        new_active = enumerate_level(current_level, words, resolver,
                                     cfg.resolvers, limiter, cfg)
        new_active -= discovered
        if not new_active:
            print(f"[+] Level {depth + 1}: no new active names; stopping.")
            break
        print(f"[+] Level {depth + 1}: {len(new_active)} new active names")
        discovered |= new_active
        current_level = new_active
    return discovered


def main() -> None:
    ap = argparse.ArgumentParser(
        description="DNSsifter: multithreaded recursive DNS enumeration with "
                    "wildcard control and trusted-resolver confirmation.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domain", required=True,
                    help="Seed domain to enumerate (e.g. example.com).")
    ap.add_argument("-w", "--wordlist", required=True, help="Path to wordlist.")
    ap.add_argument("-o", "--output", help="File to save confirmed names.")
    ap.add_argument("--resolvers", nargs="+", default=DEFAULT_RESOLVERS,
                    help="Trusted recursive resolvers for confirmation.")
    ap.add_argument("--rate", type=int, default=DEFAULT_RATE,
                    help="Max DNS queries per second per seed domain.")
    ap.add_argument("--wildcard-cap", type=int, default=DEFAULT_WILDCARD_CAP,
                    help="Max probes for a wildcard-enabled domain.")
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                    help="Concurrent resolution workers.")
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
                    help="Maximum subdomain recursion depth.")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="Per-query DNS timeout (seconds).")
    cfg = ap.parse_args()

    words = load_words(cfg.wordlist)
    print(f"[+] Loaded {len(words)} wordlist entries")
    print(f"[+] Parameters: rate={cfg.rate} q/s, threads={cfg.threads}, "
          f"wildcard_cap={cfg.wildcard_cap}, max_depth={cfg.max_depth}, "
          f"resolvers={cfg.resolvers}")

    results = enumerate_domain(cfg.domain, words, cfg)
    print(f"\n[+] Enumeration complete: {len(results)} confirmed active names")

    if cfg.output:
        with open(cfg.output, "w", encoding="utf-8") as fh:
            for name in sorted(results):
                fh.write(name + "\n")
        print(f"[+] Results saved to {cfg.output}")


if __name__ == "__main__":
    main()
