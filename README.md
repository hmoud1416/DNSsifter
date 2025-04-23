
---

![alt text](https://i.postimg.cc/yYp3Qn1q/DNSsifter.jpg)


# DNSsifter

DNSsifter is an automated multithreaded bruteforcer to discover seed domain names, subdomain names, and hostnames by systematically generating and querying a large number of possible combinations against targeted DNS servers. Since a d can have multiple levels of subdomains, DNSsifter enumerates deeply on all subdomain levels staring from the seed level until it reaches the last level subdomain. For instance, test3.test2.test1.example.com has three levels of subdomains. A subdomain may comprise up to 255 characters, counting the dots. However, if the subdomain contains multiple levels, each level can only consist of a maximum of 63 characters. 


DNSsifter is a high-performance, asynchronous tool built for DNS brute-forcing and fuzzing. Designed with speed and simplicity in mind, it caters to penetration testers, ethical hackers, and cybersecurity professionals focused on active reconnaissance. It aids in uncovering hidden subdomains and detecting potential vulnerabilities within a target's DNS infrastructure.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Convert Arabic Wordlist to ASCII](#1-convert-arabic-wordlist-to-ascii)
  - [2. Convert Arabic Wordlist to English Phonetics](#2-convert-arabic-wordlist-to-english-phonetics)
  - [3. DNS Vulnerability Scanner](#3-dns-vulnerability-scanner)
  - [4. DNS Explorer (Measurements)](#4-dns-explorer-measurements)
- [Directory Structure](#directory-structure)
- [Contributing](#contributing)

---

## Features

### 1. DNS Enumeration:
Actively discover hidden seed domains and subdomains through asynchronous brute-forcing techniques. 
#### What we do here:
At each level, DNSsifter requires three lists as input for each Top-Level-domain/Second-Level-Domain (TLD/SLD) for each enumeration level: 

\begin{enumerate}
    \item A list of all domain names registered with the target ccTLD\allowbreak /SLD acquired through passive DNS enumeration. This list contains either the set \(D_{seed}\) or the \(i^{th}\) level \(D_{sub}\) for each \(d \in D_{seed}\).
    \item A list consisting of publicly accessible \(D_{seed}\) or \(D_{sub}\) registered with the target ccTLD/SLD.
    \item A list obtained by performing active DNS enumeration where the wordlists are prepended to the target ccTLD\allowbreak /SLD\allowbreak. For example, considering (\texttt{.com.sa}) as our target SLD with a wordlist contains site1, site2, and site3, then the prepended potential are (\texttt{site1.com.sa}, \texttt{site2.com.sa}, and \texttt{site3.\allowbreak com.\allowbreak sa}), respectively. 
\end{enumerate}

Next, DNSsifter performs DNS resolution in hope to find acive and alive \(D_{seed}\) or \(D_{sub}\). To be more  certain, DNSsifter re-iterates the DNS resolution procedure on the gathered sets to eliminate false-positives. The crucial aspect lies in utilizing trusted DNS resolvers such as Google DNS (\texttt{8.8.8.8}, \texttt{8.8.4.4}), OpenDNS (\texttt{208.67.222.\allowbreak 222}, \texttt{208.67.220.220}) and Cloudflare (\texttt{1.1.1.1}) during this resolution process to validate the results for a final time. This double-resolution approach aids in discarding erroneous results. Leveraging trusted DNS resolvers offers a significant advantage by mitigating risks associated with DNS poisoning or other discrepancies commonly encountered with standard resolvers. The output is a list of Active seed domains and subdomains which is the input of the next enumeration level. The tool keeps digging deeply until it reaches the $n^{th}$ level (i.e., the last one), which outputs no active subdomain. 

### 1. Convert Arabic Wordlist to ASCII
- Converts Arabic wordlists to their ASCII-compatible Punycode representation.
- Useful for handling Arabic domain names in systems that only support ASCII.

### 2. Convert Arabic Wordlist to English Phonetics
- Translates Arabic words into multiple possible English phonetic representations.
- Supports alternative patterns for each Arabic character.

### 3. DNS Vulnerability Scanner
- Scans domains for common DNS vulnerabilities, including:
  - Open Zone Transfer (AXFR)
  - DNS Cache Poisoning
  - Subdomain Takeover (Wildcard DNS)
  - CNAME Misconfigurations
  - NXDOMAIN Flooding
  - DNSSEC Misconfigurations
  - Stale NS Records

### 4. DNS Explorer (Measurements)
- A comprehensive DNS analysis tool with the following features:
  - Fetches NS, A, AAAA, and MX records.
  - Performs GeoIP lookups using MaxMind databases.
  - Validates DNSSEC configurations.
  - Supports concurrent domain processing with progress tracking.

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

### 1. Convert Arabic Wordlist to ASCII

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

### 2. Convert Arabic Wordlist to English Phonetics

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

### 3. DNS Vulnerability Scanner

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

### 4. DNS Explorer (Measurements)

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



