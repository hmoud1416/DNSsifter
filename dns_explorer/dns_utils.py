import subprocess
from datetime import datetime
import os
import json
import geoip2.database
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, Style, init
import time

# Initialize colorama
init(autoreset=True)

# Helper function to execute a shell command
def run_dig_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip().split('\n')
    except Exception as e:
        return f"Error executing command {command}: {str(e)}"

# Log errors to a file
def log_error(tld, domain, error_message):
    date_part = datetime.now().strftime("%Y_%m_%d")
    error_log_file = os.path.join("output", tld, date_part, "error_log.txt")
    os.makedirs(os.path.dirname(error_log_file), exist_ok=True)
    with open(error_log_file, 'a') as file:
        file.write(f"[{datetime.now()}] Domain: {domain} - Error: {error_message}\n")
    print(f"{Fore.RED}Error logged for domain {domain}: {error_message}")

# Fetch NS records for a TLD
def get_ns_records(tld):
    command = f"dig NS {tld} +short"
    return run_dig_command(command)

# Fetch NS details for a domain
def get_ns_details(domain, ns_server):
    authority_command = f"dig NS {domain} @{ns_server} +nocmd +noall +authority"
    answer_command = f"dig NS {domain} @{ns_server} +nocmd +noall +answer"
    return {
        "NS_Server": ns_server,
        "authority": run_dig_command(authority_command),
        "answer": run_dig_command(answer_command)
    }

# Fetch A and AAAA records
def get_ip_records(ns_list):
    results = []
    for ns in ns_list:
        a_command = f"dig A {ns} +short"
        aaaa_command = f"dig AAAA {ns} +short"
        results.append({
            "NS": ns,
            "A_record": run_dig_command(a_command),
            "AAAA_record": run_dig_command(aaaa_command)
        })
    return results

# Perform GeoIP lookups
def get_geoip_info(ip_list):
    geoip_ans_reader = geoip2.database.Reader('data/GeoLite2-ASN.mmdb')
    geoip_city_reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')
    geoip_country_reader = geoip2.database.Reader('data/GeoLite2-Country.mmdb')
    results = []
    for ip in ip_list:
        try:
            if ipaddress.ip_address(ip):
                city = geoip_city_reader.city(ip).city.name or "null"
                country = geoip_country_reader.country(ip).country.name or "null"
                asn = geoip_ans_reader.asn(ip).autonomous_system_organization or "null"
                results.append({"IP": ip, "City": city, "Country": country, "ASN": asn})
        except (geoip2.errors.AddressNotFoundError, ValueError):
            results.append({"IP": ip, "City": "null", "Country": "null", "ASN": "null"})
    geoip_ans_reader.close()
    geoip_city_reader.close()
    geoip_country_reader.close()
    return results

# Fetch MX, A, and AAAA records
def get_mx_records(domain, ip_list):
    results = []
    for ip in ip_list:
        mx_command = f"dig MX {domain} @{ip} +noall +answer"
        a_command = f"dig A {domain} @{ip} +noall +answer"
        aaaa_command = f"dig AAAA {domain} @{ip} +noall +answer"
        results.append({
            "IP": ip,
            "MX_record": run_dig_command(mx_command),
            "A_record": run_dig_command(a_command),
            "AAAA_record": run_dig_command(aaaa_command)
        })
    return results

# Check DNSSEC using `delv`
def check_dnssec(domain):
    command = f"delv +yaml {domain}"
    output = run_dig_command(command)
    return {"command": command, "output": output}

# Save output to JSON file
def save_output(tld, domain, output_data):
    date_part = datetime.now().strftime("%Y_%m_%d")
    output_dir = os.path.join("output", tld, date_part)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{domain}.json")

    # Clean the output by replacing tabs with commas
    def clean_output(data):
        if isinstance(data, str):
            return data.replace("\t", ", ")
        if isinstance(data, list):
            return [clean_output(item) for item in data]
        if isinstance(data, dict):
            return {key: clean_output(value) for key, value in data.items()}
        return data

    cleaned_data = clean_output(output_data)

    with open(output_file, 'w') as file:
        json.dump(cleaned_data, file, indent=4)
    print(f"{Fore.GREEN}Saved output for {domain} to {output_file}")

# Display progress animation
def show_spinner(message, duration=3):
    spinner = ['|', '/', '-', '\\']
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"{Fore.CYAN}\r{message} {spinner[i % len(spinner)]}", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r{message}... Done!{Style.RESET_ALL}")

# Process a single domain
def process_domain(domain):
    try:
        print(f"{Fore.YELLOW}Processing domain: {domain}...")
        tld = domain.split('.')[-2] + '.' + domain.split('.')[-1]
        show_spinner(f"Fetching NS records for {domain}")
        ns_records = get_ns_records(tld)
        if not ns_records:
            log_error(tld, domain, "No NS records found")
            return

        show_spinner(f"Fetching NS details for {domain}")
        ns_details = [get_ns_details(domain, ns) for ns in ns_records]
        show_spinner(f"Fetching IP records for {domain}")
        ip_records = get_ip_records([ns['NS_Server'] for ns in ns_details])
        show_spinner(f"Performing GeoIP lookups for {domain}")
        geoip_info = get_geoip_info([ip['A_record'][0] for ip in ip_records if ip['A_record']])
        show_spinner(f"Fetching MX records for {domain}")
        mx_records = get_mx_records(domain, [ip['A_record'][0] for ip in ip_records if ip['A_record']])
        show_spinner(f"Checking DNSSEC for {domain}")
        dnssec_info = check_dnssec(domain)

        output_data = {
            "domain": domain,
            "tld": tld,
            "ns_records": ns_records,
            "ns_details": ns_details,
            "ip_records": ip_records,
            "geoip_info": geoip_info,
            "mx_records": mx_records,
            "dnssec_info": dnssec_info
        }
        save_output(tld, domain, output_data)
        print(f"{Fore.GREEN}Finished processing {domain}")
    except Exception as e:
        log_error("unknown", domain, str(e))

# Process a list of domains with progress bar
def process_domains(domains, use_threads=True):
    if use_threads:
        with ThreadPoolExecutor(max_workers=10) as executor:
            with tqdm(total=len(domains), desc=f"{Fore.MAGENTA}Processing Domains", unit="domain") as pbar:
                futures = [executor.submit(process_domain, domain) for domain in domains]
                for future in futures:
                    future.add_done_callback(lambda p: pbar.update(1))
    else:
        with tqdm(domains, desc=f"{Fore.MAGENTA}Processing Domains", unit="domain") as pbar:
            for domain in pbar:
                process_domain(domain)

# Example usage
if __name__ == "__main__":
    domains = ["example.com", "google.com"]  # Replace with your domain list
    process_domains(domains)
