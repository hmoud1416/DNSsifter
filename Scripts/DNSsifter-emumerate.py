import argparse
import requests
import dns.resolver

# Passive Discovery: Fetch subdomains from public sources
def passive_discovery(seed_domain):
    subdomains = set()
    
    # Example: Fetch subdomains from Certificate Transparency Logs (CT Logs)
    try:
        ct_logs_url = f"https://crt.sh/?q=%.{seed_domain}&output=json"
        response = requests.get(ct_logs_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomains.add(entry['name_value'].lower())
    except Exception as e:
        print(f"[!] Error fetching CT logs: {e}")
    
    return subdomains

# Perform DNS resolution to validate subdomain existence
def dns_query(subdomain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(subdomain, "A")  # Resolve A record
        return True if answers else False
    except Exception:
        return False

# Perform HTTP request to check if the subdomain is active
def http_check(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        return response.status_code == 200
    except Exception:
        return False

# Validate subdomain by performing DNS and HTTP checks
def validate_subdomain(subdomain):
    if dns_query(subdomain):
        if http_check(subdomain):
            print(f"[+] Found Active Subdomain: {subdomain}")
            return True
    return False

# Brute-force subdomains using a wordlist
def brute_force(seed_domain, wordlist):
    subdomains = []
    with open(wordlist, "r") as file:
        words = file.read().splitlines()
    for word in words:
        subdomains.append(f"{word}.{seed_domain}")
    return subdomains

# Recursive brute-force to discover nested subdomains
def recursive_brute_force(subdomain, wordlist):
    subdomains = []
    with open(wordlist, "r") as file:
        words = file.read().splitlines()
    for word in words:
        subdomains.append(f"{word}.{subdomain}")
    return subdomains

# Main function for subdomain enumeration
def subdomain_enumeration(seed_domain, wordlist, output_file):
    discovered_subdomains = set()

    # Step 1: Passive Enumeration
    print("[+] Starting passive enumeration...")
    passive_subdomains = passive_discovery(seed_domain)
    for subdomain in passive_subdomains:
        if validate_subdomain(subdomain):
            discovered_subdomains.add(subdomain)

    # Step 2: Active Brute-Force Enumeration
    print("[+] Starting active brute-force enumeration...")
    for subdomain in brute_force(seed_domain, wordlist):
        if validate_subdomain(subdomain):
            discovered_subdomains.add(subdomain)

    # Step 3: Recursive Enumeration
    print("[+] Starting recursive brute-force enumeration...")
    for subdomain in list(discovered_subdomains):
        for r_subdomain in recursive_brute_force(subdomain, wordlist):
            if validate_subdomain(r_subdomain):
                discovered_subdomains.add(r_subdomain)

    print("\n[+] Subdomain Enumeration Complete!")

    # Save results to output file
    if output_file:
        with open(output_file, "w") as file:
            for subdomain in discovered_subdomains:
                file.write(f"{subdomain}\n")
        print(f"[+] Results saved to {output_file}")

# Entry Point
if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="SubEnumPro: A tool for subdomain enumeration.")
    parser.add_argument("-d", "--domain", required=True, help="Seed domain to enumerate (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-o", "--output", help="Output file to save results (optional)")

    # Parse arguments
    args = parser.parse_args()

    # Run subdomain enumeration
    subdomain_enumeration(args.domain, args.wordlist, args.output)
