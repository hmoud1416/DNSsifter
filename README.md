
![Tool Screenshot](Figures/DNSsifter.jpg)



# DNSsifter

DNSsifter is an automated multithreaded bruteforcer to discover seed domain names, subdomain names, and hostnames by systematically generating and querying a large number of possible combinations against targeted DNS servers. Since a d can have multiple levels of subdomains, DNSsifter enumerates deeply on all subdomain levels staring from the seed level until it reaches the last level subdomain. For instance, `test3.test2.test1.example.com` has three levels of subdomains. A subdomain may comprise up to 255 characters, counting the dots. However, if the subdomain contains multiple levels, each level can only consist of a maximum of 63 characters. 


DNSsifter is a high-performance, asynchronous tool built for DNS brute-forcing and fuzzing. Designed with speed and simplicity in mind, it caters to penetration testers, ethical hackers, and cybersecurity professionals focused on active reconnaissance. It aids in uncovering hidden subdomains and detecting potential vulnerabilities within a target's DNS infrastructure.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Convert English Wordlist to Arabic](#1-convert-english-wordlist-to-arabic)
  - [2. Convert Arabic Wordlist to ASCII](#2-convert-arabic-wordlist-to-ascii)
  - [3. Convert Arabic Wordlist to English Phonetics](#3-convert-arabic-wordlist-to-english-phonetics)
  - [4. DNS Vulnerability Scanner](#4-dns-vulnerability-scanner)
  - [5. DNS Enumeration](#5-dns-enumration)
  - [6. DNS Explorer (Measurements)](#6-dns-explorer-measurements)
- [Directory Structure](#directory-structure)
- [Contributing](#contributing)

---

## Features


### 1. Wordlist Generation:
Creates customized wordlists in English, Arabic, and Arabizi.
#### What we do here:
DNSsifter utilizes curated wordlists—collections of commonly used domain-related terms—for generating potential seed domains and subdomains during active enumeration and reconnaissance. These wordlists include general vocabulary, industry-specific keywords, brand names, and popular phrases that are likely to appear in real-world domain names. They are essential for security researchers, penetration testers, and administrators in evaluating the exposure of DNS infrastructure.

To make the domain identification process more comprehensive and inclusive of regional variations, we developed specialized scripts to create wordlists aligned with Arabic-speaking regions. Specifically, DNSsifter includes instrumented scripts to:

1. **Translate** commonly used English words and technical terms into Arabic to reflect linguistic relevance in domain names.
2. **Generate Arabizi wordlists**—transliterated Arabic written using Latin characters, often used informally online.
3. **Create ASCII-compatible versions** of Arabic domain-related terms to support DNS environments that require ASCII-only inputs.

These multilingual wordlists expand the effectiveness of DNS brute-forcing and enhance the discovery of culturally and linguistically relevant domain assets.


### 2. DNS Enumeration:
Actively discovers hidden seed domains and subdomains through asynchronous brute-forcing techniques. 
#### What we do here:
At each level, DNSsifter requires three input lists for each Top-Level Domain (TLD) or Second-Level Domain (SLD) for enumeration:

1. A list of all domain names registered with the target TLD/SLD, acquired through passive DNS enumeration. This list contains either the set of seed domains or the i-th level subdomains for each seed domain.
2. A list consisting of publicly accessible seed domains or subdomains registered with the target TLD/SLD.
3. A list obtained by performing active DNS enumeration where the wordlists are prepended to the target TLD/SLD.  
   - For example, if the target SLD is `.com.sa` and the wordlist contains `site1`, `site2`, and `site3`, DNSsifter generates:  
     - `site1.com.sa`  
     - `site2.com.sa`  
     - `site3.com.sa`

Next, DNSsifter performs DNS resolution in search of active seed domains or subdomains. To reduce false positives, DNSsifter re-runs the resolution process on the collected results using trusted resolvers like:

- Google DNS: `8.8.8.8`, `8.8.4.4`  
- OpenDNS: `208.67.222.222`, `208.67.220.220`  
- Cloudflare DNS: `1.1.1.1`

This double-resolution step helps eliminate invalid or poisoned records. The final output is a list of confirmed active domains and subdomains, which then serves as input for the next enumeration level. DNSsifter continues recursively until reaching a level with no active subdomains — marking the end of enumeration.


### 3. DNS Measurments:
Performs DNS configuration and performance analysis for security insights.

![Tool Screenshot](Figures/measurments.jpg)

#### What we do here:
After identifying DNS seed domains and subdomains, DNSsifter conducts a series of DNS measurements to assess configuration quality, security posture, and infrastructure resilience. For each domain in the seed set, the tool performs the following steps:

- **Step 1: Querying Name Servers**  
  DNSsifter queries both the parent and child authoritative name servers to determine the authoritative NS set for each domain.

- **Step 2: Collecting IP Addresses**  
  The tool retrieves IPv4 (`A`) and IPv6 (`AAAA`) records for each nameserver. It detects round-robin configurations where one NS returns multiple IPs to balance traffic and enhance redundancy.

- **Step 3: Testing Configuration**  
  DNSsifter sends:
  - `A` and `AAAA` queries to validate nameserver configuration and detect lame delegations.
  - `MX` queries to retrieve mail exchanger records for the domain.

- **Step 4: Verifying MX Server Configuration**  
  The tool queries the `A` records of MX servers to verify their nameserver configurations and check for misconfigurations.

- **Step 5: DNSSEC Testing**  
  DNSsifter checks for DNSSEC deployment by retrieving `DS` and `DNSKEY` records. It then validates them using trusted resolvers like Google’s `8.8.8.8` to confirm the authenticity and integrity of the domain’s DNS data.

- **Step 6: Robustness & Redundancy Evaluation**  
  The tool evaluates DNS robustness using:
  - MaxMind’s GeoIP2 ASN database to identify the number of unique /24 prefixes and ASNs associated with the nameserver IPs.
  - iGreedy-based RTT measurements via 500 globally distributed RIPE Atlas probes to detect IP anycast adoption and validate infrastructure diversity.

 
### 4. DNS Vulnerability Assessment:
Scans for critical DNS security vulnerabilities and misconfigurations.

#### What we do here:
DNSsifter includes an automated script designed to perform a comprehensive evaluation of common DNS vulnerabilities. This feature helps identify both active and passive threats, as well as misconfigurations that may expose DNS infrastructure to exploitation or service disruption.

The tool scans for five key DNS security issues, categorized by their activity type (active vs. passive) and their impact level. This allows users to understand the nature of each issue—whether it’s a direct security vulnerability or a configuration oversight—and prioritize mitigation accordingly.

The following table summarizes the vulnerabilities DNSsifter checks for:

| **Vulnerability**                  | **Activity Type** | **Security Impact**                        |
|-----------------------------------|-------------------|--------------------------------------------|
| AXFR Zone Transfer                | Active            | High (Serious misconfiguration)            |
| DNS Cache Poisoning               | Passive           | High (Exploitable in weak DNS servers)     |
| Subdomain Takeover (Wildcard DNS) | Passive           | High (If misconfigured)                    |
| NXDOMAIN Flooding (DNS Amplification) | Active        | Moderate (Used in DDoS attacks)           |
| Stale NS Record Detection         | Passive           | High (If NS records are hijackable)        |


---

## Installation

### Prerequisites

- Python 3.x
- Bash
- Required Python packages:
  ```bash
  pip install geoip2 argparse tqdm colorama
  ```
- MaxMind GeoIP databases (place in `data/` directory):
  - GeoLite2-City.mmdb
  - GeoLite2-Country.mmdb
  - GeoLite2-ASN.mmdb

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/DNS-Sifter.git
   cd DNS-Sifter
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Make scripts executable:
   ```bash
   chmod +x Scripts/*.sh
   ```

---

## Usage

### 1. Convert English Wordlist to Arabic

This script converts Arabic words to their ASCII-compatible Punycode representation.

#### Command:
```bash
python3 Scripts/translate_word_to_arabic.py [-h] -l WORDLIST -o OUTPUT [-k APIKEY]
```

### 2. Convert Arabic Wordlist to ASCII

This script converts Arabic words to their ASCII-compatible Punycode representation.

#### Command:
```bash
python3 Scripts/Convert_ArabicWordlist_To_Ascii.py -l input_arabic.txt -o output_ascii.txt
```

#### Arguments:
- `-l/--list`: Path to the input file containing Arabic words (one per line).
- `-o/--output`: Path to the output file to save the Punycode results.

#### Example:
Input (`input_arabic.txt`):
```
فاطمة
حمود
أحمد
```

Output (`output_ascii.txt`):
```
xn--mgbe5bybw
xn--sgbe9dm
xn--igbug1g
```

---

### 3. Convert Arabic Wordlist to English Phonetics

This script translates Arabic words into multiple possible English phonetic representations.

#### Command:
```bash
python3 Scripts/Convert_ArabicWordlist_To_EnglishPhonetics.py -l input_arabic.txt -o output_phonetics.txt
```

#### Arguments:
- `-l/--list`: Path to the input file containing Arabic words.
- `-o/--output`: Path to the output file to save unique phonetic words.

#### Example:
Input (`input_arabic.txt`):
```
فاطمة
حمود
أحمد
```

Output (`output_phonetics.txt`):
```
Fatima
Hamoud
Ahmed
```

---

### 4. DNS Vulnerability Scanner

This script scans domains for common DNS vulnerabilities.

#### Command:
```bash
./Scripts/DNS_Vulnerability_Scanner.sh -d domains.txt -o results.json
```

#### Arguments:
- `-d/--domains`: Path to the input file containing domains (one per line).
- `-o/--output`: Path to the output file to save scan results.

#### Example:
Input (`domains.txt`):
```
example.com
google.com
```

Output (`results.json`):
```json
[
    {
        "domain": "example.com",
        "vulnerabilities": [
            {"vulnerability": "AXFR Open Zone Transfer", "server": "ns1.example.com"}
        ]
    }
]
```

---

### 5. DNS Enumeration

This script converts Arabic words to their ASCII-compatible Punycode representation.

#### Command:
```bash
python3 Scripts/DNSsifter-emumerate.py -d DOMAIN -w WORDLIST [-o OUTPUT]
```


### 6. DNS Explorer (Measurements)

The `Measurements` folder contains a comprehensive DNS analysis tool.

#### Directory Structure:
```
Measurements/
├── dns_explorer/
│   ├── __init__.py                     # Package initialization
│   ├── dns_utils.py                    # Main DNS utility functions
│   ├── geoip_utils.py                  # GeoIP lookup utilities
│   ├── main.py                         # Entry point for DNS Explorer
│   ├── output_utils.py                 # Output handling utilities
│   └── tests/                          # Unit tests
├── setup.py                            # Setup script for installation
```

##### **dns_utils.py**
- Contains core functions for DNS analysis:
  - Fetches NS, A, AAAA, and MX records.
  - Performs GeoIP lookups using MaxMind databases.
  - Validates DNSSEC configurations.
  - Supports concurrent domain processing with progress tracking.

##### **geoip_utils.py**
- Provides utilities for GeoIP lookups:
  - Uses MaxMind GeoLite2 databases for city, country, and ASN lookups.
  - Handles invalid IP addresses gracefully.

##### **main.py**
- Entry point for the DNS Explorer tool:
  - Accepts a list of domains as input.
  - Processes domains concurrently if threading is enabled.

##### **setup.py**
- Installation script for the DNS Explorer tool:
  - Installs required dependencies (`geoip2`, `argparse`).
  - Creates a command-line tool alias (`dnsexplorer`).

##### **tests/**
- Contains unit tests for DNS and GeoIP utilities.

#### Installation:
To install the DNS Explorer tool:
```bash
cd Scripts/Measurements
pip install .
```

#### Usage:
```bash
dnsexplorer --domains example.com google.com --threads
```

#### Features:
- Fetches NS, A, AAAA, and MX records.
- Performs GeoIP lookups.
- Validates DNSSEC configurations.
- Saves results in JSON format.

---



## Directory Structure

```
DNS-Sifter/
├── Scripts/
│   ├── Convert_ArabicWordlist_To_Ascii.py       # Converts Arabic to ASCII
│   ├── Convert_ArabicWordlist_To_EnglishPhonetics.py  # Converts Arabic to phonetics
│   ├── DNS_Vulnerability_Scanner.sh            # Scans DNS vulnerabilities
│   └── Measurements/                           # DNS analysis module
│       ├── dns_explorer/                       # DNS analysis utilities
│       │   ├── __init__.py
│       │   ├── dns_utils.py                    # Main DNS utility functions
│       │   ├── geoip_utils.py                  # GeoIP lookup utilities
│       │   ├── main.py                         # Entry point for DNS Explorer
│       │   ├── output_utils.py                 # Output handling utilities
│       │   └── tests/                          # Unit tests
│       └── setup.py                            # Setup script
└── README.md                                   # This file
```

---

## Contributing

We welcome contributions! To contribute:

1. Fork this repository.
2. Create a new branch (`git checkout -b feature/YourFeatureName`).
3. Commit your changes (`git commit -m "Add some feature"`).
4. Push to the branch (`git push origin feature/YourFeatureName`).
5. Open a pull request.



