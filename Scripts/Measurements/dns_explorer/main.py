import argparse
from dns_explorer.dns_utils import process_domains

def main():
    parser = argparse.ArgumentParser(description="Process domains and extract DNS information.")
    parser.add_argument("--domains", required=True, nargs='+', help="List of domains to process (space-separated).")
    parser.add_argument("--threads", action="store_true", help="Use threads for concurrent processing.")
    args = parser.parse_args()
    process_domains(args.domains, args.threads)

if __name__ == "__main__":
    main()
