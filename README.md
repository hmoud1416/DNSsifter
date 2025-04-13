
# DNSInspector

**DNSInspector** is a Python-based tool for analyzing DNS records, performing GeoIP lookups, and validating DNSSEC. It processes single or multiple domains, fetches relevant DNS details, and saves the results in JSON format.

## Features

- Fetch **NS**, **A**, and **AAAA** records for domains.
- Perform **GeoIP lookups** for IP addresses (City and Country).
- Check **DNSSEC** using `delv`.
- Save results in a structured JSON format.
- Supports **concurrent processing** with multithreading for faster results.

---

## Project Structure

```
DNSInspector/
├── dns_explorer/
│   ├── __init__.py               # Defines the package
│   ├── main.py                   # Entry point for the project
│   ├── dns_utils.py              # Functions related to DNS queries
│   ├── geoip_utils.py            # Functions related to GeoIP lookups
│   ├── output_utils.py           # Functions for saving and logging output
├── data/
│   ├── GeoLite2-City.mmdb        # GeoIP database for city lookups
│   ├── GeoLite2-Country.mmdb     # GeoIP database for country lookups
├── tests/
│   ├── test_dns_utils.py         # Unit tests for DNS functions
│   ├── test_geoip_utils.py       # Unit tests for GeoIP functions
├── examples/
│   ├── example_domains.txt       # Example list of domains for testing
│   ├── example_output.json       # Example output file
├── docs/
│   ├── README.md                 # Documentation for the project
│   ├── USAGE.md                  # Detailed usage instructions
│   ├── CONTRIBUTING.md           # Guidelines for contributors
├── requirements.txt              # Dependencies required for the project
├── setup.py                      # Installation setup for the project
├── LICENSE                       # Project license (e.g., MIT)
└── .gitignore                    # Excludes unnecessary files from Git
```

---

## Installation

### Prerequisites

1. Python 3.7 or newer installed on your system.
2. `pip` for installing Python packages.

### Steps

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/your-username/DNSInspector.git
   cd DNSInspector
   ```

2. **Create a Virtual Environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate        # On Linux/Mac
   .venv\Scripts\activate         # On Windows
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Add GeoIP Database Files:**
   Download the following GeoIP database files from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data):
   - `GeoLite2-City.mmdb`
   - `GeoLite2-Country.mmdb`

   Place them in the `data/` directory.

---

## Usage

1. **Process a Single Domain:**

   ```bash
   python -m dns_explorer.main --domains example.com
   ```

2. **Process Multiple Domains:**

   ```bash
   python -m dns_explorer.main --domains example.com example.net another.org
   ```

3. **Enable Concurrent Processing:**

   Use the `--threads` flag for faster processing:

   ```bash
   python -m dns_explorer.main --domains example.com example.net --threads
   ```

---

## Output

Results are saved in the `output/` directory under subfolders organized by TLD and date. For example:

```
output/
├── com/
│   ├── 2025_01_21/
│       ├── example.com.json
├── net/
│   ├── 2025_01_21/
│       ├── example.net.json
```

Each JSON file contains details like:

```json
{
    "domain": "example.com",
    "tld": "com",
    "ns_records": ["ns1.example.com", "ns2.example.com"],
    "ns_details": [
        {
            "NS_Server": "ns1.example.com",
            "authority": [...],
            "answer": [...]
        }
    ],
    "ip_records": [
        {
            "NS": "ns1.example.com",
            "A_record": ["192.168.1.1"],
            "AAAA_record": ["2001:0db8:85a3::8a2e:0370:7334"]
        }
    ],
    "geoip_info": [
        {
            "IP": "192.168.1.1",
            "City": "San Francisco",
            "Country": "United States"
        }
    ],
    "mx_records": [...],
    "dnssec_info": {...}
}
```

---

## Running Tests

To ensure everything is working correctly, run the tests:

```bash
pytest tests/
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add feature name"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a Pull Request.

---


