import sys
import requests
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent

# List of CDN providers to check in HTTP headers and DNS results
CDN_PROVIDERS = ["akamai", "imperva", "cloudflare", "fastly", "verizon", "stackpath", "incapsula"]

# Random user-agent generator
ua = UserAgent()

def random_headers():
    """Generate random HTTP headers including a random User-Agent."""
    return {"User-Agent": ua.random}

def check_http(domain, verbose=False):
    """Check if the domain is behind a CDN by analyzing HTTP headers."""
    try:
        response = requests.get(f"http://{domain}", headers=random_headers(), timeout=5)
        headers = response.headers
        for provider in CDN_PROVIDERS:
            if provider in headers.get("server", "").lower() or provider in headers.get("x-cdn", "").lower():
                if verbose:
                    print(f"{domain} (CDN detected via HTTP: {provider.capitalize()})")
                return None
        return domain
    except requests.exceptions.RequestException:
        return None

def check_dns(domain, verbose=False):
    """Check DNS resolution using both 'host' and 'dig' commands for CDN detection."""
    try:
        # Run 'host' command to get DNS resolution
        result_host = subprocess.run(['host', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output_host = result_host.stdout.decode()

        # Check 'host' output for CDN providers
        for provider in CDN_PROVIDERS:
            if provider in output_host.lower():
                if verbose:
                    print(f"{domain} (CDN detected via DNS 'host': {provider.capitalize()})")
                return None

        # Run 'dig' command to check DNS resolution for CDN providers
        result_dig = subprocess.run(['dig', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output_dig = result_dig.stdout.decode()

        for provider in CDN_PROVIDERS:
            if provider in output_dig.lower():
                if verbose:
                    print(f"{domain} (CDN detected via DNS 'dig': {provider.capitalize()})")
                return None

        return domain
    except subprocess.SubprocessError:
        return None

def process_domain(domain, verbose=False):
    """Process a single domain by checking both DNS and HTTP for CDN presence."""
    # Remove the ":port" part if it exists
    if ':' in domain:
        domain = domain.split(':')[0]

    # First check via DNS resolution using 'host' and 'dig'
    domain_check = check_dns(domain, verbose)
    if domain_check:
        # If DNS is clear, check via HTTP headers
        return check_http(domain, verbose)
    return None

def main():
    """Main function to parse arguments and execute CDN detection."""
    parser = argparse.ArgumentParser(description="Vanish: Filter domains behind CDN (Akamai, Imperva, Cloudflare, etc.)")
    parser.add_argument("-l", "--list", help="File containing the list of domains")
    parser.add_argument("-t", "--target", help="Check a single domain")
    parser.add_argument("-c", "--concurrence", type=int, default=10, help="Number of threads for parallel execution")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode to show CDN detections")
    args = parser.parse_args()

    domains = []

    if args.list:
        # Read domains from a file
        with open(args.list, 'r') as file:
            domains = [line.strip() for line in file.readlines()]
    elif args.target:
        # Single domain via argument
        domains = [args.target]
    else:
        # Read domains from stdin
        domains = [line.strip() for line in sys.stdin.readlines()]

    # Run checks in parallel using the specified number of threads
    with ThreadPoolExecutor(max_workers=args.concurrence) as executor:
        futures = {executor.submit(process_domain, domain, args.verbose): domain for domain in domains}

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)

if __name__ == "__main__":
    main()
