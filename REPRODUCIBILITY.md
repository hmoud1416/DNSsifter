# Reproducibility Appendix

This document is the reproducibility appendix for the study
**"A Longitudinal Assessment of DNS Resilience and Robustness in Saudi Arabia"**
(Alharbi et al.). It specifies the exact measurement configuration, parameters,
filtering thresholds, resolvers, and all metric/index equations with complete
variable definitions, so that the enumeration and scoring pipeline can be
independently replicated.

> Scope note: passive historical sources (1994–2024) are used for **domain
> discovery** only. All **DNS resilience metrics** are computed from the dedicated
> **active measurement campaign of 2024**. The two should not be conflated.

---

## 1. Measurement campaign and query schedule

| Item | Value |
|------|-------|
| Active measurement window | **2024-09-04 to 2024-12-30** |
| Measurement rounds | Multiple rounds; **per-metric values are averaged** across rounds to absorb transient/caching effects |
| Vantage point | Single research server under our administrative control, **Riyadh, Saudi Arabia** (see limitation in §7) |
| Query rate limit | **10 DNS queries / second / seed domain** across all stages |
| Record types queried | **A, AAAA, NS, MX, DS, DNSKEY** only (no malformed payloads, no zone manipulation) |
| Seed domains | 25,811 Saudi seed domains (~35.2% of SaudiNIC-registered domains) |
| Discovered subdomains | > 37 million (passive + active) |
| Passive discovery window | 1994–2024 (CT logs and historical sources) — **discovery only** |

## 2. Resolvers

| Purpose | Resolvers |
|---------|-----------|
| Double-resolution confirmation (drop false positives / poisoned answers) | Google `8.8.8.8`, `8.8.4.4`; OpenDNS `208.67.222.222`, `208.67.220.220`; Cloudflare `1.1.1.1` |
| DNSSEC validation | Google `8.8.8.8` (validating resolver) plus `delv +yaml` for chain-of-trust verification |

A candidate name is accepted only if it is confirmed by a **majority** of the
trusted resolvers (see `double_confirm()` in `Scripts/DNSsifter-emumerate.py`).
The single-resolver dependency for DNSSEC validation and its bias implications are
discussed in §7.

## 3. Wildcard handling rules

Wildcard zones inflate enumeration because arbitrary labels resolve. The mitigation,
implemented in `DNSsifter-emumerate.py` (`detect_wildcard()` / `--wildcard-cap`):

1. Before brute-forcing a (sub)domain, probe **3 random, almost-certainly-nonexistent
   labels**. If **>= 2** resolve, the zone is flagged wildcard-enabled.
2. For a wildcard-enabled domain, enumeration is **hard-capped at 1,000 subdomain
   probes** for that domain.
3. Repeated keyword counts that exceed this behaviour in the results are attributed
   to wildcard configuration and are **not** counted as independently configured
   subdomains (Section 4.2.1 / Table 3 of the paper).

## 4. Filtering thresholds

| Threshold | Value | Used by |
|-----------|-------|---------|
| Wildcard probe cap | 1,000 subdomains/domain | enumeration |
| Wildcard detection | >= 2 of 3 random labels resolve | enumeration |
| Double-resolution agreement | majority of trusted resolvers | enumeration |
| Stale NS / defective-delegation observation window | **7 days** (aligned with max TTL of common resolvers) | delegation analysis |
| Per-query DNS timeout | 5 s | enumeration / measurement |

## 5. Anycast inference

| Parameter | Value |
|-----------|-------|
| Tool | iGreedy (great-circle-distance method) |
| Vantage probes | **500 globally distributed RIPE Atlas probes** |
| Probe spacing | >= 100 km apart |
| Detection criterion | speed-of-light constraint violations in RTT measurements |
| Decision | a domain is Anycast-enabled if >= 1 of its nameservers is detected as Anycast |

False-positive/false-negative considerations: latency anomalies (congestion,
routing detours) can cause false positives; sparse probe coverage near an instance
can cause false negatives. Results are therefore reported as **inferred** Anycast
adoption.

## 6. DNSsifter parameters (CLI defaults)

All parameters are exposed as flags in `Scripts/DNSsifter-emumerate.py`:

| Flag | Default | Meaning |
|------|---------|---------|
| `--rate` | 10 | DNS queries/second/seed domain |
| `--wildcard-cap` | 1000 | max probes for a wildcard-enabled domain |
| `--threads` | 20 | concurrent resolution workers |
| `--max-depth` | 5 | max subdomain recursion depth |
| `--timeout` | 5 | per-query DNS timeout (s) |
| `--resolvers` | Google/Cloudflare/OpenDNS set | trusted confirmation resolvers |

---

## 7. Known limitations (single vantage point and resolver choice)

* **Single vantage point (Riyadh).** Active measurements originate from one
  location. DNS behaviour can vary by resolver, geography, routing, caching state,
  and time of day. Anycast detection and caching-latency figures are most sensitive
  to this. Multi-vantage replication (e.g. additional RIPE Atlas/cloud vantage
  points) is recommended for cross-validation.
* **Single validating resolver for DNSSEC.** DNSSEC validation success uses Google
  `8.8.8.8`. A different validating resolver (e.g. Cloudflare or a local Saudi ISP
  resolver) could yield slightly different validation success rates.
* **Coverage.** The dataset covers the *observable* Saudi DNS ecosystem (~35.2% of
  registered domains), not a complete census; unobserved domains may differ
  systematically.

---

## 8. Metric definitions (complete equations and variables)

Notation: `D` = number of domains analysed; `1(.)` = indicator function (1 if the
condition holds, else 0). `NS^d_D` = set of authoritative nameservers of domain `d`.

**Eq. 1 — Authoritative nameserver redundancy**
```
R_Auth = (1/D) * sum_{d=1..D} |NS^d_D|
```
`|NS^d_D|` = number of distinct authoritative nameservers for domain `d`.
Higher = more redundant.

**Eq. 2 — Nameserver AS diversity**
```
AS_Diversity = (1/D) * sum_{d=1..D} |AS(NS^d_D)|
```
`AS(NS^d_D)` = set of unique ASes hosting the nameservers of `d`. Higher = better
network diversity.

**Eq. 3 — Full defective delegation**
```
R_full_Defective = ( sum_{d=1..D} 1(NS^d_D subset_of B) ) / D
```
`B` = set of non-functional (defective) nameservers. A domain is fully defective if
*all* its nameservers are in `B`.

**Eq. 4 — Partial defective delegation**
```
R_partial_Defective = ( sum_{d=1..D} 1( 0 < |NS^d_D intersect B| < |NS^d_D| ) ) / D
```
At least one, but not all, nameservers non-functional. Note: full and partial
categories are **not mutually exclusive** with other defect types; the paper's
"Total Defects" is the share of domains with **>= 1** defect, not the sum of columns.

**Eq. 5 — Parent-child inconsistency (PCI)**
```
PCI = ( sum_{d=1..D} 1( NS^d_P != NS^d_C ) ) / D
```
`NS^d_P` = nameserver set at the parent (TLD) level; `NS^d_C` = nameserver set at the
child (domain) level. Counts domains whose delegations disagree.

**Eq. 6 — Anycast adoption**
```
R_Anycast = ( sum_{d=1..D} 1( NS^d_D in A ) ) / D
```
`A` = set of nameservers identified as Anycast (see §5). Domain counts if >= 1 of
its nameservers is Anycast-enabled.

**Eq. 7 — DNSSEC adoption rate**
```
R_adopt_DNSSEC = (1/D) * sum_{d=1..D} 1( DS_d > 0 AND DNSKEY_d > 0 )
```
`DS_d`, `DNSKEY_d` = number of DS and DNSKEY records in the answer for domain `d`.

**Eq. 8 — DNSSEC validation success rate**
```
R_success_DNSSEC = (1/D) * sum_{d=1..D} 1( status_d == "success" )
```
`status_d` = result of the validating-resolver DNSSEC check for `d`. A high adoption
with low validation success indicates broken chains of trust.

**Caching — hit rate and TTL.** Caching efficiency is derived from the TTL values of
resolved NS/A/AAAA records and the observed cache-hit behaviour across repeated
rounds (Table 7). Higher TTL within recommended bounds and higher hit rate = better.

---

## 9. Composite DNS Resilience Index (CDRI)

**Dimensions (S1..S7), all health-oriented (higher = better):**

| Dim | Meaning | Direction of raw metric |
|-----|---------|-------------------------|
| S1 | NS redundancy + AS diversity | positive |
| S2 | Delegation correctness | risk (inverted) |
| S3 | Third-party provider independence | risk (inverted) |
| S4 | Parent-child consistency | risk (inverted) |
| S5 | Anycast adoption | positive |
| S6 | DNSSEC health (adoption + validation) | positive |
| S7 | Caching efficiency | positive |

**Eq. 9 — Min-max normalization across categories**
```
S_{i,c} = ( x_{i,c} - min_c' x_{i,c'} ) / ( max_c' x_{i,c'} - min_c' x_{i,c'} )
```
Risk-oriented dimensions are inverted **before** normalization so higher always
means stronger resilience.

**Weighting scheme (Section 3.1.5), sums to 1.0:**

| w1 | w2 | w3 | w4 | w5 | w6 | w7 |
|----|----|----|----|----|----|----|
| 0.20 | 0.15 | 0.10 | 0.15 | 0.10 | 0.20 | 0.10 |

Rationale: structural redundancy (`w1`) and cryptographic assurance (`w6`) are
weighted highest as foundational properties; deployment-optimization and
ecosystem-exposure dimensions (`w3`, `w5`, `w7`) are secondary risk layers.

**Eq. 10 — CDRI (weighted additive index)**
```
CDRI_c = sum_{i=1..7} w_i * S_{i,c}        ,  CDRI_c in [0, 1]
```

> Note: the index is **additive** (weighted sum), not geometric. Earlier wording
> describing it as a "weighted geometric model" has been corrected to "weighted
> index" throughout (Reviewer 1, Concern 6).

**Reproducing the published CDRI ranking and a sensitivity analysis:**
```bash
# Reproduces .sa = 0.623 ... .med.sa = 0.097 (paper Table 8 / Figure 6)
python3 Scripts/cdri_score.py --input Data/cdri_dimension_scores.csv

# Weight-robustness check (Monte-Carlo, deterministic/reproducible)
python3 Scripts/cdri_score.py --input Data/cdri_dimension_scores.csv \
        --sensitivity --trials 10000 --jitter 0.05
```

The normalized dimension scores `S1..S7` for all ten SLD/ccTLD categories are
released in [`Data/cdri_dimension_scores.csv`](Data/cdri_dimension_scores.csv).

---

## 10. Data availability

* **Aggregated, anonymized CDRI dimension scores** for every SLD/ccTLD:
  [`Data/cdri_dimension_scores.csv`](Data/cdri_dimension_scores.csv).
* **Scoring code:** [`Scripts/cdri_score.py`](Scripts/cdri_score.py) (stdlib only).
* **Enumeration code + parameters:**
  [`Scripts/DNSsifter-emumerate.py`](Scripts/DNSsifter-emumerate.py).
* **Tool comparison:** [`Scripts/benchmark_enumeration.py`](Scripts/benchmark_enumeration.py)
  (recall / precision / runtime / depth vs Amass, Subfinder, Sublist3r).

Raw per-domain measurement records contain potentially sensitive operational
detail about third-party domains and are available from the corresponding author on
reasonable request, subject to responsible-disclosure constraints. The aggregated,
anonymized data above is sufficient to reproduce all CDRI results in the paper.
